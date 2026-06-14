"""
BENSEC - Web Application Security Scanner & WAF
Main Flask application entry point — Production Local Build.
"""

import os
import sys
import threading
import logging
import time
import json
import sqlite3
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify, send_file, Response
from flask_cors import CORS

# ── Silence Insecure Request Warnings ─────────────────────────────────────────
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(__file__))

# Safe fallback imports validation wrapper block
try:
    from database.models import (
        init_db, add_target, get_all_targets, get_target,
        update_target_status, get_vulnerabilities, get_vuln_stats,
        get_waf_logs, get_waf_stats, get_request_logs,
        get_blacklist, blacklist_ip, remove_from_blacklist,
    )
except ImportError as err:
    print(f"\n[CRITICAL ERROR] Failed importing database dependencies: {err}")
    print("Please confirm your 'database/models.py' file matches your exact structural schemas.\n")
    sys.exit(1)

from scanner.crawler import WebCrawler
from scanner.xss_scanner import XSSScanner
from scanner.sqli_scanner import SQLiScanner
from scanner.dir_bruteforce import DirectoryBruteforcer
from scanner.header_checker import HeaderChecker
from waf.request_filter import register_waf
from reports.report_generator import generate_report

# ── Logging ───────────────────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/bensec.log"),
    ]
)
logger = logging.getLogger(__name__)

# ── App ───────────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})
app.secret_key = os.environ.get("SECRET_KEY", "bensec-dev-key-change-in-prod")

# Register WAF middleware
register_waf(app)

# Initialize database
with app.app_context():
    try:
        init_db()
    except Exception as db_err:
        print(f"\n[DATABASE SCHEMA ERROR] Failed initializing database layout: {db_err}\n")
        sys.exit(1)

# ── Anti-Cache Header Hooks ───────────────────────────────────────────────────
@app.after_request
def add_header(response):
    """Purges browser disk cache states to ensure dynamic operations update instantly."""
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# ── Progress Tracking ─────────────────────────────────────────────────────────
scan_progress: dict = {}
_progress_lock = threading.Lock()

def _set_progress(target_id: int, step: str, pct: int, findings: int = 0,
                  done: bool = False, error: bool = False):
    with _progress_lock:
        scan_progress[target_id] = {
            "step": step, "pct": pct, "findings": findings,
            "done": done, "error": error,
        }

# ── Helpers ───────────────────────────────────────────────────────────────────
SEVERITY_SCORES = {"Critical": 95, "High": 80, "Medium": 55, "Low": 20}

def compute_risk_score(vulns):
    if not vulns:
        return 0
    weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    total = sum(weights.get(v["severity"], 1) for v in vulns)
    max_possible = len(vulns) * 4
    return min(100, int((total / max_possible) * 100))

def run_scan(target_id: int, target_url: str):
    logger.info(f"[SCAN] Starting scan for target {target_id}: {target_url}")
    update_target_status(target_id, "scanning")
    all_vulns = []

    try:
        # 1. Crawl
        _set_progress(target_id, "🕷  Crawling pages…", 5)
        crawler = WebCrawler(target_url, max_pages=30)
        crawl_result = crawler.crawl()
        pages = crawl_result["pages"]
        forms = crawl_result["forms"]
        _set_progress(target_id, f"🕷  Crawled {len(pages)} pages", 15)

        # 2. XSS scan
        _set_progress(target_id, "🔍 Running XSS scan…", 20, findings=len(all_vulns))
        xss_live_counter = [0]
        def xss_callback():
            xss_live_counter[0] += 1
            current_total = len(all_vulns) + xss_live_counter[0]
            _set_progress(target_id, "🔍 Running XSS scan…", 20, findings=current_total)

        xss = XSSScanner()
        xss_findings = xss.scan(pages, forms, on_find=xss_callback)
        all_vulns.extend(xss_findings)
        _set_progress(target_id, f"🔍 XSS done — {len(xss_findings)} findings", 40, findings=len(all_vulns))

        # 3. SQLi scan
        _set_progress(target_id, "💉 Running SQLi scan…", 42, findings=len(all_vulns))
        sqli_live_counter = [0]
        def sqli_callback():
            sqli_live_counter[0] += 1
            current_total = len(all_vulns) + sqli_live_counter[0]
            _set_progress(target_id, "💉 Running SQLi scan…", 42, findings=current_total)

        sqli = SQLiScanner()
        sqli_findings = sqli.scan(pages, forms, on_find=sqli_callback)
        all_vulns.extend(sqli_findings)
        _set_progress(target_id, f"💉 SQLi done — {len(sqli_findings)} findings", 60, findings=len(all_vulns))

        # 4. Directory enumeration
        _set_progress(target_id, "📂 Directory bruteforce…", 62, findings=len(all_vulns))
        dirbuster = DirectoryBruteforcer(target_url)
        dir_findings = dirbuster.scan()
        all_vulns.extend(dir_findings)
        _set_progress(target_id, f"📂 Dir scan done — {len(dir_findings)} findings", 78, findings=len(all_vulns))

        # 5. Header analysis
        _set_progress(target_id, "🔒 Checking security headers…", 80, findings=len(all_vulns))
        header_checker = HeaderChecker()
        header_findings = header_checker.scan(target_url)
        all_vulns.extend(header_findings)
        _set_progress(target_id, f"🔒 Headers done — {len(header_findings)} findings", 90, findings=len(all_vulns))

        # 6. Save findings to DB
        _set_progress(target_id, "💾 Saving findings to database…", 93, findings=len(all_vulns))
        from database.models import add_vulnerability
        for v in all_vulns:
            add_vulnerability(
                target_id=target_id,
                vuln_type=v["vuln_type"],
                severity=v["severity"],
                affected_url=v["affected_url"],
                parameter=v.get("parameter"),
                payload=v.get("payload"),
                description=v.get("description"),
            )

        risk_score = compute_risk_score(all_vulns)
        update_target_status(target_id, "completed", risk_score)
        _set_progress(target_id, f"✅ Scan complete — {len(all_vulns)} total findings", 100, findings=len(all_vulns), done=True)

    except Exception as e:
        logger.error(f"[SCAN] Error scanning target {target_id}: {e}", exc_info=True)
        update_target_status(target_id, "error")
        _set_progress(target_id, f"❌ Error: {e}", 0, error=True)

# ── Dashboard Routes ──────────────────────────────────────────────────────────
@app.route("/")
def index():
    targets = get_all_targets()
    vuln_stats = get_vuln_stats()
    waf_stats = get_waf_stats()
    return render_template("dashboard.html", targets=targets, vuln_stats=vuln_stats, waf_stats=waf_stats)

# ── Target API ────────────────────────────────────────────────────────────────
@app.route("/api/targets", methods=["GET"])
def api_targets():
    return jsonify([dict(t) for t in get_all_targets()])

@app.route("/api/targets", methods=["POST"])
def api_add_target():
    data = request.json or {}
    url = data.get("url", "").strip()
    if not url or not url.startswith(("http://", "https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    target = add_target(url)
    if not target:
        return jsonify({"error": "Failed to add target"}), 500
    return jsonify(dict(target)), 201

@app.route("/api/targets/<int:target_id>/scan", methods=["POST"])
def api_start_scan(target_id):
    target = get_target(target_id)
    if not target:
        return jsonify({"error": "Target not found"}), 404

    thread = threading.Thread(target=run_scan, args=(target_id, target["url"]), daemon=True)
    thread.start()
    return jsonify({"message": f"Scan started for {target['url']}"}), 202

@app.route("/api/targets/<int:target_id>", methods=["GET"])
def api_target_detail(target_id):
    target = get_target(target_id)
    if not target:
        return jsonify({"error": "Target not found"}), 404
    return jsonify({
        "target": dict(target),
        "vulnerabilities": [dict(v) for v in get_vulnerabilities(target_id)],
    })

@app.route("/api/targets/<int:target_id>", methods=["DELETE"])
def api_delete_target(target_id):
    try:
        import database.models
        if hasattr(database.models, 'delete_target_and_history'):
            if database.models.delete_target_and_history(target_id):
                return jsonify({"message": f"Target {target_id} permanently deleted."}), 200
        return jsonify({"error": "Failed to run deletion layout cycles."}), 500
    except Exception as err:
        return jsonify({"error": str(err)}), 500

@app.route("/api/targets/<int:target_id>/progress", methods=["GET"])
def api_scan_progress(target_id):
    def generate():
        while True:
            with _progress_lock:
                state = scan_progress.get(target_id)
            if state is None:
                target = get_target(target_id)
                status = target.get("scan_status", "unknown") if target else "unknown"
                if status == "scanning":
                    payload = json.dumps({"step": "⏳ Queuing crawler tasks...", "pct": 4, "findings": 0, "done": False, "error": False})
                elif status == "completed":
                    payload = json.dumps({"step": "✅ Already completed", "pct": 100, "findings": 0, "done": True, "error": False})
                else:
                    payload = json.dumps({"step": "—", "pct": 0, "findings": 0, "done": False, "error": False})
                yield f"data: {payload}\n\n"
            else:
                yield f"data: {json.dumps(state)}\n\n"
                if state.get("done") or state.get("error"):
                    break
            time.sleep(1)
    return Response(generate(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ── Vulnerability API ─────────────────────────────────────────────────────────
@app.route("/api/vulnerabilities", methods=["GET"])
def api_vulnerabilities():
    return jsonify([dict(v) for v in get_vulnerabilities(request.args.get("target_id", type=int))])

# ── WAF API ───────────────────────────────────────────────────────────────────
@app.route("/api/waf/logs", methods=["GET"])
def api_waf_logs():
    return jsonify([dict(l) for l in get_waf_logs(request.args.get("limit", 100, type=int))])

@app.route("/api/waf/stats", methods=["GET"])
def api_waf_stats():
    stats = get_waf_stats()
    return jsonify({
        "total": stats["total"],
        "by_type": [dict(r) for r in stats["by_type"]],
        "top_ips": [dict(r) for r in stats["top_ips"]],
    })

# ── IP Blacklist API ──────────────────────────────────────────────────────────
@app.route("/api/blacklist", methods=["GET"])
def api_get_blacklist():
    return jsonify([dict(r) for r in get_blacklist()])

@app.route("/api/blacklist", methods=["POST"])
def api_add_blacklist():
    data = request.json or {}
    ip = data.get("ip_address", "").strip()
    if not ip: return jsonify({"error": "ip_address required"}), 400
    blacklist_ip(ip_address=ip, attack_type=data.get("attack_type", "Manual"), block_reason=data.get("reason", "Manually blocked"))
    return jsonify({"message": f"{ip} blacklisted"}), 201

@app.route("/api/blacklist/<ip>", methods=["DELETE"])
def api_remove_blacklist(ip):
    remove_from_blacklist(ip)
    return jsonify({"message": f"{ip} removed from blacklist"})

# ── Request Logs API ──────────────────────────────────────────────────────────
@app.route("/api/requests", methods=["GET"])
def api_request_logs():
    return jsonify([dict(l) for l in get_request_logs(request.args.get("limit", 200, type=int))])

# ── Reports API ───────────────────────────────────────────────────────────────
@app.route("/api/report/<int:target_id>", methods=["POST"])
def api_generate_report(target_id):
    data = request.json or {}
    report_type = data.get("type", "technical")

    target = get_target(target_id)
    if not target: return jsonify({"error": "Target not found"}), 404

    # Extract clean domain name dynamically from the target URL string
    parsed_url = urlparse(target["url"])
    domain_name = parsed_url.netloc if parsed_url.netloc else parsed_url.path
    domain_name = domain_name.replace(":", "_").replace("/", "_")

    vulns = [dict(v) for v in get_vulnerabilities(target_id)]
    waf_stats = get_waf_stats()
    waf_stats_clean = {
        "total": waf_stats["total"],
        "by_type": [dict(r) for r in waf_stats["by_type"]],
        "top_ips": [dict(r) for r in waf_stats["top_ips"]],
    }

    filepath = generate_report(
        target_url=target["url"],
        vulnerabilities=vulns,
        waf_stats=waf_stats_clean,
        report_type=report_type,
    )

    return send_file(filepath, as_attachment=True,
                     download_name=f"BENSEC-Audit-Report-{domain_name}.pdf",
                     mimetype="application/pdf")

# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="192.168.1.3", port=80, debug=True)
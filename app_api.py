"""
BENSEC - Web Application Security Scanner & WAF
Decoupled Flask API backend engine — Production Local Build.
"""

import os
import sys
import threading
import logging
import time
import json
import sqlite3
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(__file__))

# Safe fallback database layouts verification mapping
try:
    from database.models import (
        init_db, add_target, get_all_targets, get_target,
        update_target_status, get_vulnerabilities, get_vuln_stats,
        get_waf_logs, get_waf_stats, get_request_logs,
        get_blacklist, blacklist_ip, remove_from_blacklist,
    )
except ImportError as err:
    print(f"\n[CRITICAL ERROR] Failed importing database dependencies: {err}")
    sys.exit(1)

from scanner.crawler import WebCrawler
from scanner.xss_scanner import XSSScanner
from scanner.sqli_scanner import SQLiScanner
from scanner.dir_bruteforce import DirectoryBruteforcer
from scanner.header_checker import HeaderChecker
from waf.request_filter import register_waf
from reports.report_generator import generate_report

os.makedirs("logs", exist_ok=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Complete wildcard origin coverage allows local testing via React servers securely
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

register_waf(app)

with app.app_context():
    init_db()

scan_progress = {}
_progress_lock = threading.Lock()

def _set_progress(target_id, step, pct, findings=0, done=False, error=False):
    with _progress_lock:
        scan_progress[target_id] = {"step": step, "pct": pct, "findings": findings, "done": done, "error": error}

def compute_risk_score(vulns):
    if not vulns: return 0
    weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    total = sum(weights.get(v["severity"], 1) for v in vulns)
    return min(100, int((total / (len(vulns) * 4)) * 100))

def run_scan(target_id, target_url):
    update_target_status(target_id, "scanning")
    all_vulns = []
    try:
        _set_progress(target_id, "🕷  Crawling pages…", 5)
        crawler = WebCrawler(target_url, max_pages=30)
        crawl_res = crawler.crawl()
        pages, forms = crawl_res["pages"], crawl_res["forms"]
        
        _set_progress(target_id, "🔍 Running XSS modules…", 25, findings=len(all_vulns))
        all_vulns.extend(XSSScanner().scan(pages, forms))
        
        _set_progress(target_id, "💉 Launching injection checks…", 50, findings=len(all_vulns))
        all_vulns.extend(SQLiScanner().scan(pages, forms))
        
        _set_progress(target_id, "📂 Bruteforcing directory endpoints…", 75, findings=len(all_vulns))
        all_vulns.extend(DirectoryBruteforcer(target_url).scan())

        _set_progress(target_id, "💾 Synchronizing database findings…", 90, findings=len(all_vulns))
        from database.models import add_vulnerability
        for v in all_vulns:
            add_vulnerability(target_id=target_id, vuln_type=v["vuln_type"], severity=v["severity"], affected_url=v["affected_url"])

        risk = compute_risk_score(all_vulns)
        update_target_status(target_id, "completed", risk)
        _set_progress(target_id, f"✅ Audit finished successfully", 100, findings=len(all_vulns), done=True)
    except Exception as e:
        update_target_status(target_id, "error")
        _set_progress(target_id, f"❌ Engine failure: {e}", 0, error=True)

# ── API ENDPOINTS ─────────────────────────────────────────────────────────────

@app.route("/api/targets", methods=["GET"])
def api_targets():
    return jsonify([dict(t) for t in get_all_targets()])

@app.route("/api/targets", methods=["POST"])
def api_add_target():
    url = (request.json or {}).get("url", "").strip()
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "Invalid protocol specification"}), 400
    return jsonify(dict(add_target(url))), 201

@app.route("/api/targets/<int:target_id>/scan", methods=["POST"])
def api_start_scan(target_id):
    target = get_target(target_id)
    threading.Thread(target=run_scan, args=(target_id, target["url"]), daemon=True).start()
    return jsonify({"message": "Background scanning loop spawned successfully"}), 202

@app.route("/api/targets/<int:target_id>/progress", methods=["GET"])
def api_scan_progress(target_id):
    def generate():
        while True:
            with _progress_lock: state = scan_progress.get(target_id)
            if state is None:
                target = get_target(target_id)
                status = target.get("scan_status", "unknown") if target else "unknown"
                payload = {"step": "✅ Already completed" if status == "completed" else "—", "pct": 100 if status == "completed" else 0, "findings": 0, "done": status == "completed", "error": status == "error"}
                yield f"data: {json.dumps(payload)}\n\n"
            else:
                yield f"data: {json.dumps(state)}\n\n"
                if state.get("done") or state.get("error"): break
            time.sleep(1)
    return Response(generate(), mimetype="text/event-stream")

@app.route("/api/targets/<int:target_id>", methods=["DELETE"])
def api_delete_target(target_id):
    import database.models
    if hasattr(database.models, 'delete_target_and_history') and database.models.delete_target_and_history(target_id):
        return jsonify({"message": "Data purged successfully"}), 200
    return jsonify({"error": "Deletion sync failed"}), 500

@app.route("/api/waf/stats", methods=["GET"])
def api_waf_stats():
    return jsonify({"total": get_waf_stats()["total"]})

@app.route("/api/report/<int:target_id>", methods=["POST"])
def api_generate_report(target_id):
    target = get_target(target_id)
    domain = urlparse(target["url"]).netloc or urlparse(target["url"]).path
    domain = domain.replace(":", "_").replace("/", "_")
    
    filepath = generate_report(target_url=target["url"], vulnerabilities=[dict(v) for v in get_vulnerabilities(target_id)], waf_stats={"total": 0, "by_type": [], "top_ips": []}, report_type="technical")
    return send_file(filepath, as_attachment=True, download_name=f"BENSEC-Audit-Report-{domain}.pdf", mimetype="application/pdf")
    
@app.route("/", methods=["GET"])
def api_root_check():
    return jsonify({
        "status": "online",
        "engine": "BENSEC Security Daemon",
        "message": "Cloud API gateway initialized successfully."
    }), 200
if __name__ == "__main__":
    # Render assigns ports dynamically via the PORT environment variable
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

from flask import request, jsonify, g
from waf.waf_engine import inspect_request
from waf.rate_limiter import check_rate_limit
from waf.ip_blacklist import is_blocked, block_ip
from database.models import add_request_log
import logging

logger = logging.getLogger(__name__)


def register_waf(app):
    """
    Attach WAF middleware to a Flask app.
    Call once after creating the Flask app instance.
    """

    @app.before_request
    def waf_filter():
        ip = request.remote_addr or "unknown"

        # 1. IP blacklist check
        if is_blocked(ip):
            logger.warning(f"[WAF] Blacklisted IP attempted request: {ip}")
            return jsonify({"error": "Access denied", "reason": "IP blacklisted"}), 403

        # 2. Rate limit check
        allowed, reason = check_rate_limit(ip)
        if not allowed:
            return jsonify({"error": "Too many requests", "reason": reason}), 429

        # 3. Signature-based attack detection
        body = ""
        try:
            body = request.get_data(as_text=True) or ""
        except Exception:
            pass

        is_malicious, attack_type, payload = inspect_request(
            source_ip=ip,
            method=request.method,
            url=request.path,
            body=body,
            query_string=request.query_string.decode("utf-8", errors="replace"),
        )

        if is_malicious:
            # Auto-block repeat offenders — tracked inside waf_engine via DB
            return jsonify({
                "error": "Request blocked by WAF",
                "attack_type": attack_type,
            }), 403

    @app.after_request
    def log_request(response):
        ip = request.remote_addr or "unknown"
        add_request_log(
            request_url=request.path,
            method=request.method,
            response_code=response.status_code,
            source_ip=ip,
        )
        return response

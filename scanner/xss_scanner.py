"""
Mahisec - Web Application Security Scanner
XSS Scanner Module with strict runtime type-assertion safeguards.
"""

import logging
import requests
from urllib.parse import urlparse, urlunparse, parse_qs

logger = logging.getLogger(__name__)

class XSSScanner:
    def __init__(self):
        self.payloads = [
            "<img src=x onerror=alert(1)>",
            "'\"><script>alert(1)</script>",
            "javascript:alert(1)//",
            "<svg onerror=alert(1)>"
        ]

    def _extract_url_string(self, item) -> str:
        """Surgically extracts raw text URLs from any data type structure."""
        if not item:
            return ""
        if isinstance(item, str):
            return item.strip()
        if isinstance(item, dict):
            return str(item.get("url") or item.get("link") or item.get("action") or "")
        if isinstance(item, (list, tuple, set)) and len(item) > 0:
            return self._extract_url_string(list(item)[0])
        return str(item).strip()

    def _clean_url(self, url) -> str:
        """Cleans and extracts core components of a target endpoint."""
        try:
            url_str = self._extract_url_string(url)
            if not url_str or not url_str.startswith(("http://", "https://")):
                return ""
            parsed = urlparse(url_str)
            return urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                '' # Drops fragment tags securely
            ))
        except Exception:
            return ""

    def scan(self, pages: list, forms: list, on_find=None) -> list:
        findings = []
        tested_vectors = set()

        logger.info(f"[XSS] Launching scanner pipeline across elements...")

        # ── Step A: Analyze Forms ─────────────────────────────────────────────
        if isinstance(forms, list):
            for form in forms:
                if not isinstance(form, dict):
                    continue

                action_url = self._clean_url(form.get("action"))
                method = self._extract_url_string(form.get("method") or "get").lower()
                inputs = form.get("inputs") or []

                if not action_url or not isinstance(inputs, list):
                    continue

                for inp in inputs:
                    if not isinstance(inp, dict):
                        continue
                        
                    param_name = self._extract_url_string(inp.get("name"))
                    inp_type = self._extract_url_string(inp.get("type") or "text")

                    if not param_name or inp_type in ["submit", "hidden", "file"]:
                        continue

                    vector_key = f"{method}|{action_url}|{param_name}"
                    if vector_key in tested_vectors:
                        continue
                    tested_vectors.add(vector_key)

                    for payload in self.payloads:
                        data = {}
                        for field in inputs:
                            if isinstance(field, dict):
                                name = field.get("name")
                                if name:
                                    data[name] = payload if name == param_name else "test"

                        try:
                            if method == "post":
                                res = requests.post(action_url, data=data, timeout=5, verify=False)
                            else:
                                res = requests.get(action_url, params=data, timeout=5, verify=False)

                            if payload in res.text:
                                logger.warning(f"[XSS] FOUND at {action_url} | param={param_name} payload={payload}")
                                
                                findings.append({
                                    "vuln_type": "Cross-Site Scripting (XSS)",
                                    "severity": "High",
                                    "affected_url": action_url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "description": f"Reflected XSS validation bypass detected on input parameter '{param_name}'."
                                })

                                if on_find:
                                    on_find()
                                break

                        except requests.RequestException:
                            continue

        # ── Step B: Analyze Query Parameters ──────────────────────────────────
        if isinstance(pages, list):
            for page_element in pages:
                # 1. Pull the URL out safely
                raw_url = self._extract_url_string(page_element)
                
                # 2. Process stripping logic safely
                cleaned_page = self._clean_url(raw_url)
                
                # CRITICAL GUARD: Ensure cleaned_page is absolutely a valid string before urlparse
                if not cleaned_page or not isinstance(cleaned_page, str) or not cleaned_page.startswith(("http://", "https://")):
                    continue

                try:
                    parsed_url = urlparse(cleaned_page)
                    if not parsed_url.query:
                        continue

                    params = parse_qs(parsed_url.query)

                    for param_name in params.keys():
                        vector_key = f"get|{parsed_url.path}|{param_name}"
                        if vector_key in tested_vectors:
                            continue
                        tested_vectors.add(vector_key)

                        for payload in self.payloads:
                            test_params = {k: (payload if k == param_name else v[0]) for k, v in params.items()}
                            base_target = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', '', ''))

                            try:
                                res = requests.get(base_target, params=test_params, timeout=5, verify=False)
                                if payload in res.text:
                                    logger.warning(f"[XSS] FOUND at {base_target} | param={param_name} payload={payload}")
                                    
                                    findings.append({
                                        "vuln_type": "Cross-Site Scripting (XSS)",
                                        "severity": "High",
                                        "affected_url": base_target,
                                        "parameter": param_name,
                                        "payload": payload,
                                        "description": f"Reflected XSS validation bypass inside request query variable '{param_name}'."
                                    })

                                    if on_find:
                                        on_find()
                                    break

                            except requests.RequestException:
                                continue
                except Exception:
                    continue

        return findings
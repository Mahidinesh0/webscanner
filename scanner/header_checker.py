import requests
import logging

logger = logging.getLogger(__name__)

HEADERS = {"User-Agent": "Mahisec-Scanner/1.0"}

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "description": "Missing Content-Security-Policy header. Increases XSS risk.",
    },
    "Strict-Transport-Security": {
        "severity": "High",
        "description": "Missing HSTS header. Allows downgrade attacks.",
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "Missing X-Frame-Options. Site may be vulnerable to clickjacking.",
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "description": "Missing X-Content-Type-Options. MIME-type sniffing possible.",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Missing Referrer-Policy. May leak sensitive URL data.",
    },
    "Permissions-Policy": {
        "severity": "Low",
        "description": "Missing Permissions-Policy. Browser features not restricted.",
    },
    "X-XSS-Protection": {
        "severity": "Low",
        "description": "Missing X-XSS-Protection (legacy but still checked).",
    },
}


class HeaderChecker:
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.findings = []

    def scan(self, url):
        logger.info(f"[HEADERS] Checking security headers for {url}")
        try:
            resp = requests.get(url, headers=HEADERS, timeout=self.timeout,
                                verify=False, allow_redirects=True)
        except Exception as e:
            logger.error(f"[HEADERS] Could not reach {url}: {e}")
            return []

        present = []
        missing = []

        for header, meta in SECURITY_HEADERS.items():
            if header.lower() in {k.lower() for k in resp.headers}:
                present.append(header)
                logger.info(f"[HEADERS] Present: {header}")
            else:
                missing.append(header)
                finding = {
                    "vuln_type": "Missing Security Header",
                    "severity": meta["severity"],
                    "affected_url": url,
                    "parameter": header,
                    "payload": None,
                    "description": meta["description"],
                }
                self.findings.append(finding)
                logger.warning(f"[HEADERS] MISSING: {header}")

        # Extra informational checks
        server = resp.headers.get("Server", "")
        if server:
            self.findings.append({
                "vuln_type": "Information Disclosure",
                "severity": "Low",
                "affected_url": url,
                "parameter": "Server",
                "payload": None,
                "description": f"Server header exposes version info: {server}",
            })

        x_powered = resp.headers.get("X-Powered-By", "")
        if x_powered:
            self.findings.append({
                "vuln_type": "Information Disclosure",
                "severity": "Low",
                "affected_url": url,
                "parameter": "X-Powered-By",
                "payload": None,
                "description": f"X-Powered-By exposes technology stack: {x_powered}",
            })

        logger.info(f"[HEADERS] Done. Present: {len(present)} | Missing: {len(missing)}")
        return self.findings

    def get_score(self):
        """Return a 0-100 security score based on headers."""
        total = len(SECURITY_HEADERS)
        missing_count = sum(
            1 for f in self.findings if f["vuln_type"] == "Missing Security Header"
        )
        return max(0, int(((total - missing_count) / total) * 100))

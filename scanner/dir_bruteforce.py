import requests
import logging
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

HEADERS = {"User-Agent": "Mahisec-Scanner/1.0"}

DEFAULT_WORDLIST = [
    "admin", "administrator", "login", "wp-admin", "dashboard",
    "backup", "backup.zip", "backup.tar.gz", "db.sql", "database.sql",
    "uploads", "upload", "files", "images", "img",
    "config", "config.php", "config.yml", "config.json", ".env",
    "api", "api/v1", "api/v2", "swagger", "swagger-ui",
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "robots.txt", "sitemap.xml", ".git", ".svn", ".htaccess",
    "wp-content", "wp-includes", "wp-login.php",
    "phpmyadmin", "pma", "mysql", "adminer.php",
    "console", "shell", "cmd", "webshell",
    "cgi-bin", "old", "temp", "tmp", "bak",
    "server-status", "server-info",
    ".DS_Store", "thumbs.db",
    "include", "includes", "lib", "libs", "vendor",
    "install", "setup", "setup.php", "install.php",
]


class DirectoryBruteforcer:
    def __init__(self, base_url, wordlist=None, timeout=8, threads=10):
        self.base_url = base_url.rstrip("/")
        self.wordlist = wordlist or DEFAULT_WORDLIST
        self.timeout = timeout
        self.findings = []

    def scan(self):
        logger.info(f"[DIR] Starting directory enumeration on {self.base_url}")
        for path in self.wordlist:
            self._check_path(path)
        logger.info(f"[DIR] Done. Discovered: {len(self.findings)}")
        return self.findings

    def _check_path(self, path):
        url = f"{self.base_url}/{path}"
        try:
            resp = requests.get(url, headers=HEADERS, timeout=self.timeout,
                                verify=False, allow_redirects=False)

            if resp.status_code == 200:
                severity = self._assess_severity(path)
                finding = {
                    "vuln_type": "Directory Exposure",
                    "severity": severity,
                    "affected_url": url,
                    "parameter": None,
                    "payload": None,
                    "description": f"Accessible path discovered: /{path} [HTTP 200]",
                }
                self.findings.append(finding)
                logger.warning(f"[DIR] FOUND 200: {url}")

            elif resp.status_code == 403:
                finding = {
                    "vuln_type": "Forbidden Directory",
                    "severity": "Low",
                    "affected_url": url,
                    "parameter": None,
                    "payload": None,
                    "description": f"Forbidden directory detected: /{path} [HTTP 403]",
                }
                self.findings.append(finding)
                logger.info(f"[DIR] FOUND 403: {url}")

        except Exception as e:
            logger.debug(f"[DIR] Error checking {url}: {e}")

    def _assess_severity(self, path):
        critical_paths = [".env", "config.php", "db.sql", "database.sql",
                          "backup.zip", ".git", "adminer.php", "phpinfo.php",
                          "webshell", "shell", "cmd"]
        high_paths = ["admin", "administrator", "phpmyadmin", "wp-admin",
                      "wp-login.php", "console", "install.php", "setup.php"]

        path_lower = path.lower()
        if any(c in path_lower for c in critical_paths):
            return "Critical"
        if any(h in path_lower for h in high_paths):
            return "High"
        return "Medium"

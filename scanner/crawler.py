import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

HEADERS = {
    "User-Agent": "Mahisec-Scanner/1.0 (Security Research)"
}


class WebCrawler:
    def __init__(self, base_url, max_pages=50, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.base_domain = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.timeout = timeout
        self.visited = set()
        self.pages = []
        self.forms = []
        self.parameters = {}

    def crawl(self):
        logger.info(f"[CRAWLER] Starting crawl: {self.base_url}")
        self._crawl_page(self.base_url)
        logger.info(f"[CRAWLER] Done. Pages: {len(self.pages)} | Forms: {len(self.forms)}")
        return {
            "pages": self.pages,
            "forms": self.forms,
            "parameters": self.parameters,
        }

    def _crawl_page(self, url):
        if url in self.visited or len(self.visited) >= self.max_pages:
            return
        self.visited.add(url)

        try:
            resp = requests.get(url, headers=HEADERS, timeout=self.timeout, verify=False)
            resp.raise_for_status()
        except Exception as e:
            logger.warning(f"[CRAWLER] Failed {url}: {e}")
            return

        page_info = {
            "url": url,
            "status_code": resp.status_code,
            "content_type": resp.headers.get("Content-Type", ""),
        }
        self.pages.append(page_info)
        logger.info(f"[CRAWLER] Crawled: {url} [{resp.status_code}]")

        soup = BeautifulSoup(resp.text, "html.parser")
        self._extract_forms(soup, url)
        self._extract_get_params(url)
        self._extract_links(soup, url)

    def _extract_links(self, soup, current_url):
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            full_url = urljoin(current_url, href)
            parsed = urlparse(full_url)
            if parsed.netloc == self.base_domain and full_url not in self.visited:
                self._crawl_page(full_url)

    def _extract_forms(self, soup, page_url):
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            full_action = urljoin(page_url, action) if action else page_url

            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })

            form_info = {
                "page_url": page_url,
                "action": full_action,
                "method": method,
                "inputs": inputs,
            }
            self.forms.append(form_info)
            logger.info(f"[CRAWLER] Form found on {page_url}: {method} → {full_action}")

    def _extract_get_params(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if params:
            self.parameters[url] = list(params.keys())
            logger.info(f"[CRAWLER] GET params at {url}: {list(params.keys())}")

import re
import logging
from database.models import add_waf_log, blacklist_ip

logger = logging.getLogger(__name__)

# ── Attack Signatures ─────────────────────────────────────────────────────────

SQLI_PATTERNS = [
    r"(\bUNION\b.*\bSELECT\b)",
    r"(\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1)",
    r"(\bDROP\b\s+\bTABLE\b)",
    r"(\bINSERT\b\s+\bINTO\b)",
    r"(\bDELETE\b\s+\bFROM\b)",
    r"(--\s*$)",
    r"(\bSLEEP\s*\()",
    r"(\bWAITFOR\s+DELAY\b)",
    r"(\bEXEC\b\s*\()",
    r"(xp_cmdshell)",
    r"(\bAND\b\s+\d+\s*=\s*\d+)",
    r"(admin\s*'?\s*--)",
]

XSS_PATTERNS = [
    r"(<script[\s>])",
    r"(</script>)",
    r"(javascript\s*:)",
    r"(onerror\s*=)",
    r"(onload\s*=)",
    r"(onclick\s*=)",
    r"(onmouseover\s*=)",
    r"(<iframe[\s>])",
    r"(<svg[\s>])",
    r"(document\.cookie)",
    r"(eval\s*\()",
    r"(alert\s*\()",
]

PATH_TRAVERSAL_PATTERNS = [
    r"(\.\./){2,}",
    r"(\.\.\\){2,}",
    r"(%2e%2e%2f)",
    r"(%2e%2e/)",
    r"(\.\.%2f)",
    r"(/etc/passwd)",
    r"(/etc/shadow)",
    r"(c:\\windows\\)",
]

CMD_INJECTION_PATTERNS = [
    r"(;\s*\bls\b)",
    r"(;\s*\bcat\b)",
    r"(;\s*\bwhoami\b)",
    r"(;\s*\bid\b\s)",
    r"(`[^`]+`)",
    r"(\$\([^)]+\))",
    r"(\|\s*\bsh\b)",
    r"(\|\s*\bbash\b)",
    r"(&&\s*\bcat\b)",
    r"(&&\s*\bls\b)",
]

_COMPILED = {
    "SQL Injection": [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS],
    "XSS": [re.compile(p, re.IGNORECASE) for p in XSS_PATTERNS],
    "Path Traversal": [re.compile(p, re.IGNORECASE) for p in PATH_TRAVERSAL_PATTERNS],
    "Command Injection": [re.compile(p, re.IGNORECASE) for p in CMD_INJECTION_PATTERNS],
}


def inspect_request(source_ip, method, url, body="", query_string=""):
    """
    Inspect an incoming request for attack patterns.
    Returns (is_malicious: bool, attack_type: str | None, matched_payload: str | None)
    """
    combined = f"{url} {query_string} {body}"

    for attack_type, patterns in _COMPILED.items():
        for pattern in patterns:
            match = pattern.search(combined)
            if match:
                payload = match.group(0)
                logger.warning(
                    f"[WAF] {attack_type} detected from {source_ip} | "
                    f"URL: {url} | Payload: {payload}"
                )
                add_waf_log(
                    source_ip=source_ip,
                    attack_type=attack_type,
                    request_url=url,
                    method=method,
                    payload=payload,
                    action="blocked",
                )
                return True, attack_type, payload

    return False, None, None

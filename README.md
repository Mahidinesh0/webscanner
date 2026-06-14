# Mahisec — Web Application Security Scanner & WAF

**Mahisec** is a combined offensive + defensive web security platform.
Scan targets for XSS, SQLi, directory exposure, and missing security headers,
while running a Flask-based WAF that blocks malicious requests in real time.

---

## Project Structure

```
WebApp-Security-Scanner/
├── app.py                      # Flask app + all API routes
├── requirements.txt
├── scanner/
│   ├── crawler.py              # Web crawler (URLs, forms, params)
│   ├── xss_scanner.py          # XSS detection engine
│   ├── sqli_scanner.py         # SQL injection detection engine
│   ├── dir_bruteforce.py       # Directory enumeration
│   └── header_checker.py       # Security header analysis
├── waf/
│   ├── waf_engine.py           # Regex-based attack signature detection
│   ├── rate_limiter.py         # Per-IP rate limiting + auto-blacklist
│   ├── ip_blacklist.py         # IP blacklist manager
│   └── request_filter.py       # Flask middleware (before_request hook)
├── reports/
│   └── report_generator.py     # PDF report generation (ReportLab)
├── database/
│   └── models.py               # SQLite schema + all DB helpers
├── templates/
│   └── dashboard.html          # Web dashboard UI
├── logs/                       # Runtime logs (auto-created)
└── reports_output/             # Generated PDFs (auto-created)
```

---

## Setup

```bash
# 1. Clone / enter the project
cd WebApp-Security-Scanner

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
python app.py
```

Open **http://localhost:5000** in your browser.

---

## API Reference

### Targets
| Method | Route | Description |
|--------|-------|-------------|
| GET  | `/api/targets` | List all targets |
| POST | `/api/targets` | Add target `{"url": "https://..."}` |
| GET  | `/api/targets/<id>` | Target + its vulnerabilities |
| POST | `/api/targets/<id>/scan` | Start async scan |

### Vulnerabilities
| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/vulnerabilities?target_id=<id>` | List findings |

### WAF
| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/waf/logs` | Recent blocked requests |
| GET | `/api/waf/stats` | Attack type breakdown |

### Blacklist
| Method | Route | Description |
|--------|-------|-------------|
| GET    | `/api/blacklist` | All blocked IPs |
| POST   | `/api/blacklist` | Block IP `{"ip_address":"x.x.x.x","reason":"..."}` |
| DELETE | `/api/blacklist/<ip>` | Unblock IP |

### Reports
| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/report/<target_id>` | Generate PDF `{"type":"technical"}` |

Report types: `technical`, `executive`, `waf`

---

## Ethical Use Notice

> This tool is for **authorized security testing only**.
> Only scan targets you own or have explicit written permission to test.
> Unauthorized scanning is illegal in most jurisdictions.

---

*Built by Mahi | Mahisec Security Research*

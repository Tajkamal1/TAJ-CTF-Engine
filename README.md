# TAJ-CTF-Engine v2.0
### Aggressive Web Exploitation Automation — by Taj | CSYClub IIITK

> **For use only on CTF competition challenges and systems you own or have explicit permission to test.**

---

## What's New in v2.0

| Feature | Description |
|---|---|
| **14 Modules** | +4 new: DirBrute, Headers/Auth-Bypass, Open Redirect, Type Juggling |
| **Auto-Crawler** | Crawls entire target before scanning — discovers hidden endpoints, forms, JS secrets |
| **⚡ Quick Flag Hunt** | One-click rapid scan of response + 8 common paths |
| **Flag Modal Popup** | Instant visual alert + clipboard copy when a flag is found |
| **50+ CTF Platforms** | Flag hunter recognises picoCTF, HTB, THM, DUCTF, angstromCTF, corCTF + 45 more |
| **Base64 Flag Decode** | Automatically decodes base64-encoded flags in responses |
| **Header Flags** | Hunts flags in HTTP response headers and cookies, not just body |
| **JS Secret Scanner** | Extracts flag values from inline JavaScript variable assignments |
| **HTML Comment Scanner** | Finds flags hidden in `<!-- -->` comments |

---

## Quick Start

```bash
pip install -r requirements.txt
python app.py
# Open http://localhost:5000
```

---

## 14 Attack Modules

| Module | What It Tests |
|---|---|
| `dirbrute` | 100+ CTF-specific paths — `/flag`, `/api/flag`, `/.env`, `/admin`, etc. |
| `sqli` | Error-based, Union (MySQL/PostgreSQL/SQLite/MSSQL), Boolean, Time-based |
| `ssti` | Jinja2, Twig, FreeMarker, Smarty template injection → RCE → flag read |
| `cmdi` | OS command injection (Linux + Windows), filter bypasses |
| `lfi` | Path traversal, PHP wrappers (`php://filter`, `expect://`), proc leaks |
| `xss` | Reflected, DOM, stored detection + JS variable flag hunting |
| `headers` | X-Forwarded-For bypass, X-Admin/Role overrides, Werkzeug debug RCE |
| `open_redirect` | Redirect chain following, file:// leaks, redirect param bruteforce |
| `ssrf` | Internal services, AWS/GCP metadata, Redis/Gopher, bypass encodings |
| `jwt` | None-alg bypass, weak secret brute-force, RS256→HS256 confusion |
| `nosql` | MongoDB `$gt/$ne/$regex` injection on JSON + form endpoints |
| `idor` | ID parameter brute-force (0, 1, 1337, admin, UUID) + path probing |
| `xxe` | External entities, SYSTEM file reads, XXE-OOB hints |
| `typejuggle` | PHP loose comparison, mass assignment, JSON prototype pollution |

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `POST /api/scan` | POST | Full scan — crawler + all selected modules |
| `POST /api/scan_module` | POST | Single module scan |
| `POST /api/quick_flag` | POST | Lightning fast — GET + 8 common paths |
| `POST /api/crawl` | POST | Crawler only — map the target site |
| `GET  /api/modules` | GET | List all available modules |
| `GET  /api/payloads/<module>` | GET | Get payloads for a module |

### Example: Quick Flag Hunt via curl
```bash
curl -X POST http://localhost:5000/api/quick_flag \
  -H "Content-Type: application/json" \
  -d '{"url":"http://challenge.ctf.com:8080/"}'
```

---

## Project Structure

```
TAJ-CTF-Engine/
├── app.py                        # Flask server — 14 modules registered
├── requirements.txt
├── backend/
│   ├── core/
│   │   ├── crawler.py            # NEW: site mapper + JS/comment secret extractor
│   │   ├── flag_hunter.py        # 50+ platform patterns + base64 + HTML comment
│   │   ├── requester.py          # HTTP session with retry, proxy, cookie support
│   │   ├── parser.py             # HTML form/link/error extractor
│   │   └── base_module.py        # Base class for all modules
│   ├── modules/
│   │   ├── sqli.py               # SQL Injection (MySQL/PostgreSQL/SQLite/MSSQL)
│   │   ├── ssti.py               # Server-Side Template Injection
│   │   ├── cmdi.py               # OS Command Injection
│   │   ├── lfi.py                # Local File Inclusion + PHP Wrappers
│   │   ├── xss.py                # XSS + JS variable hunting
│   │   ├── ssrf.py               # SSRF + metadata endpoints
│   │   ├── jwt.py                # JWT attacks
│   │   ├── idor.py               # Insecure Direct Object Reference
│   │   ├── xxe.py                # XML External Entity
│   │   ├── nosql.py              # NoSQL Injection
│   │   ├── dirbrute.py           # NEW: directory/endpoint brute-force
│   │   ├── headers.py            # NEW: header injection + auth bypass
│   │   ├── open_redirect.py      # NEW: redirect chain exploitation
│   │   └── typejuggle.py         # NEW: type juggling + mass assignment
│   └── payloads/                 # JSON payload files per module
├── frontend/
│   ├── index.html                # Main UI
│   ├── css/style.css
│   └── js/app.js                 # Live terminal, flag modal, module status grid
└── README.md
```

---

*TAJ-CTF-Engine is for authorised security research and CTF competitions only.*

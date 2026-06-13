# >\_ OSINTBox

> A modular OSINT reconnaissance toolkit. Run from your own machine. No third-party APIs required.

![OSINTBox Screenshot](screenshot.png)

---

## What it does

OSINTBox is a self-hosted OSINT platform with five recon modules, a dark terminal UI, and local SQLite storage. Everything runs on your machine — no data leaves your device.

| Module           | What it does                               |
| ---------------- | ------------------------------------------ |
| Username Search  | Find accounts across platforms by username |
| IP / Host Lookup | Resolve IPs, reverse DNS, geolocation      |
| Domain Recon     | WHOIS, DNS records, subdomains             |
| Email Analysis   | Validate, breach check, header analysis    |
| Phone Parsing    | Carrier lookup, region, line type          |

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone https://github.com/cookiesn1ffer/osintbox.git
cd osintbox
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # Linux
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000 in your browser.

---

## Stack

- **Flask** — lightweight web server
- **SQLite** — local job storage
- **Python** — all recon modules pure Python, no heavy dependencies

---

## License

Copyright (c) 2026 Aarush (cookiesn1ffer). All rights reserved.
This software is proprietary. See LICENSE for details.

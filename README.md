# BUGHUNTR

> Unified bug bounty hunting platform. 11 scanners. Real-time output. Auto H1 reports.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)
![React](https://img.shields.io/badge/React-TypeScript-61DAFB?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-SSE-black?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## The Problem

Bug bounty hunting requires juggling subfinder, assetfinder, nuclei, dig, curl, and five browser tabs — then manually writing a report in H1's format. Most findings get closed as Informative because the PoC is weak or the report structure is wrong.

BUGHUNTR fixes that.

---

## What It Does

Single platform. Paste a target. Get findings with ready-to-submit H1 reports.

| Module | What It Catches |
|---|---|
| Subdomain Takeover | Dangling CNAMEs across 27 providers |
| S3 / Blob Buckets | Public AWS S3 and Azure Blob exposure |
| CORS | Origin reflection, credential flag misconfig |
| Sensitive Files | .env, .git/config, credentials.json, 30+ paths |
| API Key Leak | AWS, Stripe, GitHub, Slack, JWT in JS files |
| Open Redirect | 17 parameter fuzzing with external-location check |
| Clickjacking | X-Frame-Options + CSP frame-ancestors |
| DNS Zone Transfer | AXFR across all nameservers |
| SPF / DMARC | Email spoofing misconfiguration |
| Rate Limit | Request flooding with 429 detection |
| Nuclei | Full nuclei v3+ integration with JSONL parsing |

---

## What's Actually Novel

**Guided takeover pipeline** — enumerate → DNS triage → provider fingerprint → double-pass NXDOMAIN verify → confidence score. Not just "CNAME points somewhere."

**Pre-submission validation gate** — every finding is checked for valid URL, concrete PoC, severity threshold, and vulnerable object before it hits the database. Weak findings get dropped automatically.

**Real-time SSE streaming** — scan output streams live to the dashboard. No polling. No waiting for completion.

*Patent pending.*

---

## Stack

```
Frontend   React + TypeScript + Vite
Backend    Python + Flask + SQLAlchemy
Database   SQLite (local) / PostgreSQL (prod)
Streaming  Server-Sent Events (SSE)
Scanners   subfinder, assetfinder, amass, nuclei, dnspython, requests
```

---

## Setup

**Requirements:** Node 18+, Python 3.10+

### Windows

```bash
# Clone
git clone https://github.com/medhu0505/BUGHUNTR
cd BUGHUNTR

# Run everything
start.bat
```

### Linux / macOS

```bash
git clone https://github.com/medhu0505/BUGHUNTR
cd BUGHUNTR
chmod +x start.sh && ./start.sh
```

### Manual

```bash
# Backend
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux/macOS
pip install -r requirements.txt
python app.py                # → http://localhost:5000

# Frontend (separate terminal)
cd ..
npm install
npm run dev                  # → http://localhost:5173
```

---

## Environment

```env
# backend/.env
FLASK_ENV=development
DATABASE_URL=sqlite:///bbh.db

# .env.local (frontend)
VITE_API_BASE_URL=http://localhost:5000/api
```

---

## External Tools (Optional but Recommended)

BUGHUNTR works without these but subdomain enumeration is significantly better with them installed and in PATH.

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/owasp-amass/amass/v4/...@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

---

## Built By

**Medhansh Sharma** — student, bug bounty hunter ([HackerOne: stickybugger](https://hackerone.com/stickybugger))

Built out of frustration with the current toolchain. Every H1 closure marked Informative because the PoC wasn't good enough was motivation.

---

## License

MIT — use it, fork it, don't resell it as-is.

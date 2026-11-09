# TrustShield™ (ASPD-TrustShield)
### Intelligent Website Trust & Safety Platform

[![Live Demo](https://img.shields.io/badge/Live%20Demo-aspd--trust--shield.vercel.app-00dfa2?style=for-the-badge&logo=vercel)](https://aspd-trust-shield.vercel.app)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/Frontend-React%20%2B%20Vite-61DAFB?style=for-the-badge&logo=react)](https://react.dev/)
[![TailwindCSS](https://img.shields.io/badge/Styling-Tailwind%20CSS-38B2AC?style=for-the-badge&logo=tailwind-css)](https://tailwindcss.com/)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)](LICENSE)

> 🌐 **Live Web Application:** [https://aspd-trust-shield.vercel.app](https://aspd-trust-shield.vercel.app)  
> 🛡️ **Deep Scan Console:** [https://aspd-trust-shield.vercel.app/scan](https://aspd-trust-shield.vercel.app/scan)

---

## 📌 Project Overview

**TrustShield™** is an enterprise-grade, automated website trust and safety intelligence platform designed to detect credential harvesters, brand impersonations, deceptive homoglyph attacks, weaponized redirect chains, zero-day phishing portals, and weak TLS configurations.

Unlike traditional static blocklists that fail against fast-flux domains and short-lived infrastructure, TrustShield executes an end-to-end, multi-stage passive forensic analysis pipeline that synthesizes **8 distinct telemetry layers** into an **explainable 0–100 trust score**.

---

## 🚀 Key Features

- **⚡ Deep URL Forensics Console:** Interactive cyber command deck featuring real-time diagnostic terminal streaming, preset attack vectors, and an interactive 3D perspective security layer HUD.
- **🧠 Explainable Trust Score Engine:** Multi-signal risk synthesis with transparent weighted ceilings:
  - *URL & Domain Infrastructure* (Max 35 pts)
  - *Phishing DOM Content & Credential Forms* (Max 30 pts)
  - *Threat Intelligence Consensus* (Max 25 pts)
  - *SSL/TLS Certificate & CA Trust* (Max 15 pts)
  - *Web Security Headers & Configurations* (Max 10 pts)
- **🤖 Embedded ML URL Classifier:** High-speed (<5ms) scikit-learn classifier trained on lexical entropy, structural token distribution, and domain age indicators with transparent feature attribution.
- **🛡️ Pluggable Threat Intelligence Architecture:** Multi-feed adapter framework integrating **Google Safe Browsing (v4)**, **URLhaus (abuse.ch)**, **PhishTank**, **OpenPhish**, and **VirusTotal (v3)** with circuit-breaker fault isolation and exponential backoff.
- **🔒 Passive SSL/TLS & CA Trust Audit:** Full X.509 certificate chain inspection, SAN validation, short-lived domain-validated cert detection, CT log verification, and distrusted CA root monitoring.
- **🕵️ DOM Phishing Detection:** Scans HTML structure for deceptive password/OTP inputs, external form submission targets, known logo lures, and social engineering banners.
- **👥 Crowdsourced Community Reporting & Watchlists:** Community voting, domain reporting, and personal security watchlists with automated alerting.

---

## 🏗️ 7-Stage Security Inspection Pipeline

| Stage | Inspection Focus | Signals Analyzed |
| :--- | :--- | :--- |
| **1. URL & SSRF Gate** | Pre-flight syntax & anti-pivot defense | RFC 3986 compliance, private RFC 1918 / loopback rejection, Punycode/homoglyph detection, TLD reputation. |
| **2. DNS & Domain Infrastructure** | Authoritative DNS resolution | A/AAAA records, MX mail servers, TXT (SPF/DKIM/DMARC), NS delegation, SOA records, and domain registration age. |
| **3. Cryptographic Audit** | TLS/SSL integrity & CA trust | Certificate validity windows, SAN matching, issuer reputation, revocation checks (OCSP), and weak cipher suites. |
| **4. Web Security Assessment** | Browser security headers | HSTS preload/max-age, Content-Security-Policy (CSP), X-Frame-Options (Clickjacking), and cookie flags. |
| **5. Content & DOM Analysis** | Phishing heuristic scanning | Password fields, OTP collectors, cross-origin form action endpoints, brand logos, and urgent lure text. |
| **6. ML URL Classification** | Statistical ML inference | Shannon entropy, digit ratios, keyword densities, and decision-tree feature attributions. |
| **7. Threat Intelligence Feeds** | IOC reputation matching | Multi-feed consensus from Google Safe Browsing, URLhaus, PhishTank, OpenPhish, and VirusTotal. |

---

## 💻 Tech Stack

### Frontend
- **Framework:** React 19 + Vite 8
- **Routing:** React Router v7
- **Styling:** Tailwind CSS v4, Lucide Icons, Framer Motion
- **State & Data Fetching:** TanStack Query v5 (React Query)
- **Visualizations:** Recharts, Custom Cyberpunk 3D Layer Stacks, SVG Gauges

### Backend & ML
- **Framework:** FastAPI (Python 3.11+)
- **ASGI Server:** Uvicorn (uvloop & httptools)
- **Database ORM:** SQLAlchemy 2.0 (PostgreSQL async engine + local SQLite dev resilience)
- **Machine Learning:** Scikit-Learn, Joblib, NumPy
- **Security & Cryptography:** PyJWT, Cryptography (X.509 parsing), Bcrypt
- **Network & Parsing:** HTTPX, BeautifulSoup4, DNSPython

---

## 🛠️ Quickstart / Local Development

### Prerequisites
- Node.js 18+ & npm
- Python 3.11+
- Git

### 1. Clone Repository
```bash
git clone https://github.com/artlinger2331/ASPD-TrustShield.git
cd ASPD-TrustShield
```

### 2. Backend Setup
```powershell
# Set Python path to backend directory
$env:PYTHONPATH="backend"

# Install dependencies
pip install -r backend/requirements.txt

# Start backend development server (Port 8000)
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
> API interactive documentation will be live at `http://127.0.0.1:8000/docs`.

### 3. Frontend Setup
```bash
cd frontend

# Install packages
npm install

# Start Vite frontend (Port 5173)
npm run dev
```
> Open your browser at `http://localhost:5173/scan`.

---

## 🧪 Automated Test Suite

TrustShield includes unit and integration tests covering the risk engine, ML classifier, threat intel providers, and asynchronous scan pipelines:

```powershell
python -m pytest backend/tests/ -v
```

---

## 🌐 Production Deployment

- **Frontend:** Hosted on [Vercel](https://aspd-trust-shield.vercel.app) with global edge delivery and automated SPA rewrites.
- **Backend:** Hosted on [Render](https://render.com) using the included [render.yaml](render.yaml) blueprint.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

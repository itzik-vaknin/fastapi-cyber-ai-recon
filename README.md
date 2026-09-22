# FastAPI Cyber AI Recon Agent 🛡️🧠

A secure, modular, and high-performance network reconnaissance tool built with **FastAPI** and **Python**. This system automates infrastructure port scanning and integrates a cloud-hosted **Groq AI Agent** (Llama-3-8b) to process technical exposure metrics and instantly generate professional risk analyst summaries.

⚠️ **Legal Notice:** This tool is intended strictly for authorized security testing, lab environments, and systems you legally own or have explicit, written permission to assess.

---

## 📐 System Architecture

```text
             ┌──────────────┐
             │    Client    │
             └──────┬───────┘
                    │
              Bearer Token
                    │
             ┌──────▼───────┐
             │   FastAPI    │
             └──────┬───────┘
                    │
            ┌───────▼────────┐
            │ Target Validator│
            │  SSRF Defense   │
            └───────┬────────┘
                    │
             ┌──────▼───────┐
             │ Port Scanner │
             └──────┬───────┘
                    │
          ┌─────────┴─────────┐
          │                   │
    ┌─────▼─────┐      ┌──────▼──────┐
    │  SQLite   │      │  Groq AI    │
    │  History  │      │   Analysis  │
    └───────────┘      └─────────────┘
```

---

## 📸 Core Interface Evaluation

### 🔒 1. Secure Access Gateway (OAuth2 Framework)
The entire application routing infrastructure is tightly gated using token validation constraints.
![Secure Gateway Authentication](01_auth.png)

### 📐 2. Input Configuration & SSRF Firewall Shield
Application inputs are thoroughly sanitized against Server-Side Request Forgery (SSRF) vulnerabilities to shield local assets.
![Port Scanner Parameters Setup](02_request.png)

### 💾 3. Live Server Response & Automated AI Analysis Reports
Socket data is automatically pushed into relational tables and sent to the Groq Cloud runner for immediate threat indexing.
![Server Response and AI Analytics Report](03_response.png)

---

## 🔒 Security Architecture & Applied Controls

* **Modular Framework Design:** Complete separation of concerns mapping into clear architectural layers (`core/`, `database/`, `ai/`).
* **Token Gate Filter:** Critical scanner API components are blocked using an **OAuth2 Bearer Token** security middleware.
* **SSRF Prevention Core:** Validates target endpoints via low-level DNS resolution checks to block internal loops (`127.0.0.1`, private IP blocks).
* **Automated Engineering Tests:** Backed by an automated unit testing architecture (**Pytest** environment validation engine).

---

## 🚀 Quick Start Guide

### Installation Tree
```bash
git clone https://github.com
cd fastapi-cyber-ai-recon
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Environment Variable Profile Setup
Create a local `.env` configuration file mapping your secret access token key:
```text
GROQ_API_KEY=your_secret_groq_api_token_here
```

### Launch Environment Run Profile
```bash
./venv/bin/uvicorn main:app --reload
```

### Running Automated Framework Validation Tests
To trigger the automated SSRF firewall testing matrix infrastructure natively:
```bash
pytest
```

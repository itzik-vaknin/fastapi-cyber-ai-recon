# FastAPI Cyber AI Recon Agent 🛡️🧠

A modular network reconnaissance tool built with **FastAPI** and **Python**. The system automates infrastructure port scanning and integrates a cloud-hosted **Groq AI** model to analyze technical exposure data and generate risk analyst summaries.

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
            │  SSRF Mitigation│
            └───────┬────────┘
                    │
             ┌──────▼───────┐
             │ Port Scanner │
             └──────┬───────┘
                    │
          ┌─────────┴─────────┐
          │                   │
    ┌─────▼─────┐      ┌──────▼──────┐
    │  SQLite   │      │   Groq AI   │
    │  History  │      │   Analysis  │
    └───────────┘      └─────────────┘
```

---

## 📸 Core Features

### 🔒 1. Secure Access Gateway — Bearer Token Authentication

The scanner API is protected using Bearer Token authentication.

![Secure Gateway Authentication](01_auth.png)

### 🛡️ 2. Input Validation & SSRF Mitigation

Target inputs are validated using DNS resolution checks to help prevent access to loopback and private network addresses.

![Port Scanner Parameters Setup](02_request.png)

### 🤖 3. Server Response & AI Analysis

Scan results are stored in SQLite and sent to the Groq AI model for analysis.

![Server Response and AI Analytics Report](03_response.png)

---

## 🔒 Security Architecture & Applied Controls

* **Modular Framework Design:** Separation of concerns across clear architectural layers (`core/`, `database/`, `ai/`).
* **Bearer Token Authentication:** Scanner API endpoints are protected using Bearer Token authentication.
* **SSRF Mitigation:** Target endpoints are resolved and checked against loopback and private IP addresses.
* **Fault-Tolerant AI Engine:** Includes a **Local Fallback Engine** in `ai/groq_agent.py` to provide graceful degradation when the external AI service is unavailable.
* **Automated Testing:** Includes automated tests using **Pytest** for application security controls.
* **Environment-Based Configuration:** Sensitive credentials are loaded from environment variables instead of being stored directly in the source code.

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/itzik-vaknin/fastapi-cyber-ai-recon.git
cd fastapi-cyber-ai-recon

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

### Environment Variables

Create a local `.env` file:

```text
GROQ_API_KEY=your_groq_api_key
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_strong_password
API_BEARER_TOKEN=your_long_random_token
```

**Do not commit the `.env` file to Git.**

### Run the Application

```bash
./venv/bin/uvicorn main:app --reload
```

### Run Automated Tests

```bash
pytest
```

---

## 🧰 Technologies

* Python
* FastAPI
* SQLAlchemy
* SQLite
* Groq AI
* Pytest
* AsyncIO

---

## 🎯 Project Goal

The goal of this project was to combine cybersecurity and backend development into a practical application.

The project demonstrates how reconnaissance, API development, authentication, SSRF mitigation, database storage, automated testing, and AI-assisted analysis can be integrated into a single modular application.

---

## ⚠️ Responsible Use

Use this project only for authorized security testing, personal labs, and systems where you have explicit permission to perform security assessments.


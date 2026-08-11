# CyberSentinel — AI-Powered Automated SOC Alert Triage & Threat Monitoring

# Problem Statement

1. Vast Amount of False Positive Alerts

  Modern SIEM systems generate thousands of security alerts every day. A large portion of these alerts may be legitimate activity, expected administrative behavior, automated scanners, or low-risk events.

As a result, SOC analysts spend valuable time manually investigating alerts that ultimately require no action.

2. Fighting Automated Threats with Manual Operations

  Although attacks are increasingly automated, L1 SOC investigation is still heavily manual.
  
  For every suspicious alert, analysts may need to:
  
  Review logs → Check IP reputation → Investigate context → Compare historical incidents → Decide → Document → Escalate
  
  Doing this repeatedly across hundreds or thousands of alerts creates a major operational bottleneck.


## Impact

This leads to:

Alert Fatigue — Analysts become overwhelmed by repetitive alerts.
Delayed Response — Time spent investigating false positives means less time for genuine threats.
Missed Threats — Critical alerts can be buried among large volumes of noise.
High Operational Cost — More analyst time is required to maintain continuous SOC operations.

The real problem isn't that SOCs lack alerts — it's that analysts lack the time to investigate all of them effectively.

---

# The Solution

Agentic workflow
Dashboard
Email

**The goal isn't to replace the SOC analyst.
It's to make sure the analyst spends their time on the alerts that actually deserve attention.**

<img width="1692" height="537" alt="image" src="https://github.com/user-attachments/assets/f995c466-f048-4f5b-9f6a-9febe1b4af9a" />


## Cyber Attack Detection & Automated Response Pipeline

```text
Postman → n8n Webhook → ingest.py (INSERT) → PostgreSQL
                                                   │
                              n8n Enrichment ◄─────┘
        (AbuseIPDB + VirusTotal + AlienVault OTX)
                                                   │
                                                   ▼
                                    api.py + Pydantic AI Agent
                                    (RAG via ChromaDB)
                                                   │
                                                   ▼
                                          PostgreSQL (verdict)
                                          │              │
                                   TP/Needs Review    False Positive
                                          │              │
                                    Email SOC Team    No Action
                                          │
                                          ▼
                                  Grafana Dashboard
```
# Features:
* why chroma db
* why x llm
* why grafana
* why pydantic
* why pydantic ai
 Tech Stack 
 LLM , RA & Vector DBs, API
- LLM
- LM Studio
- FastAPI
- Webhook
- POSTMAN
- n8n
- vs code
- Vector Database
- RAG
- chromadb
- uvicorn
- aistudio.google
- Postman
---
Example

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/de6e98f5-f19b-4037-bdca-fd4fb8ece748" />

---
how to use

---
Security
1 local LLM - LM Studio 
2 Local Embedding 
3 local grafana dashboard

---
optimization
1 Just suspecious arrived to llm and correlated
2 calling tools just if neccessarfy  otherwise automation
3 شو بدخل لل LLM

## Project Directory Structure

```text
SOC_AGENT/
│
├── app/                        # Main application package
│   ├── __init__.py
│   │
│   ├── agent/                  # AI Core (The brains of the system)
│   │   ├── __init__.py
│   │   ├── pydantic_agent.py   # Agent definition, system prompts, and LLM setup
│   │   └── schemas.py          # Pydantic models for structured JSON outputs
│   │
│   ├── core/                   # System configuration and security controls
│   │   ├── __init__.py
│   │   ├── config.py           # Environment variables, LM Studio URLs, and API keys
│   │   └── sanitization.py     # Log scrubbing and input sanitization (Regex pipeline)
│   │
│   ├── database/               # Semantic memory and retrieval
│   │   ├── __init__.py
│   │   └── vector_db.py        # ChromaDB logic (RAG integration & context retrieval)
│   │
│   └── main.py                 # FastAPI server application entrypoint & API routing
│
├── data/                       # Directory for offline evaluation data
│   └── raw_logs_samples.json   # Simulated or downloaded log datasets (Kaggle/GitHub)
│
├── tests/                      # Simulation scripts and operational testing
│   └── mock_attacker.py        # Python script to simulate real-time cyber attacks (Postman alternative)
│
├── .gitignore                  # Prevents committing venv, cache, and DB storage to GitHub
├── README.md                   # Comprehensive project documentation
└── requirements.txt            # Project dependencies and package versions
```

---
# Author
**GhaydA' Alqudah**

**Computer Engineer | AI & Cyber Security Enthusiast**

V DB, ترتيب الكود ولملمتهو اوتلوت ا llm ,  شو السيناريوهات يلي بكون فيها  FP  بالعادة


# Upload 
- db
- vs code
- n8n 
- dashboard

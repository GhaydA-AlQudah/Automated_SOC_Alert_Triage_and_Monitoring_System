# CyberSentinel-An-Autonomous-AI-Driven-SOC-L1-Analyst-using-RAG-and-n8n.


# Problem Statement

Modern Security Operations Centers (SOCs) are overwhelmed by an exponential volume of security logs and alerts generated across enterprise networks. Human analysts spend a massive amount of time triaging low-level alerts, leading to critical operational bottlenecks.

### What happens without this solution? (The Consequences)
* **Alert Fatigue & Missed Breaches:** Analysts get buried under thousands of daily alerts, allowing actual, sophisticated cyber attacks to slip through unnoticed.
* **Delayed Incident Response Time (MTTR):** Manually investigating raw, unstructured logs takes hours, giving attackers ample time to move laterally and compromise critical assets.
* **High Operational Costs:** Scaling a 24/7 SOC team to handle Tier-1 (L1) log triaging requires massive human capital and constant resource draining.
* **Data Privacy Risks:** Forwarding raw security logs directly to public cloud AI models (like OpenAI API) exposes sensitive internal corporate data (PII, internal IPs, and architecture secrets) to third-party leakage.
---
# Cyber Attack Detection & Automated Response Pipeline

```text
┌────────────────────────────────────────────────────────┐
│                   Postman (Simulator)                  │
│  - Simulates the cyber attack                          │
│  - Sends raw log payload via HTTP POST                 │
└──────────────────────────┬─────────────────────────────┘
                           │
                           │ HTTP POST Request (Raw Log)
                           ▼
┌────────────────────────────────────────────────────────┐
│                 n8n Webhook Node (Listener)            │
│  - Triggers the workflow instantly upon receiving log  │
│  - Forwards the payload to the FastAPI backend         │
└──────────────────────────┬─────────────────────────────┘
                           │
                           │ HTTP POST Request
                           │ (Sanitized Payload)
                           ▼
┌────────────────────────────────────────────────────────┐
│                 FastAPI Server (Python)                │
│  - Data Sanitization (Masking PII/Sensitive Data)      │
│  - Executes RAG using ChromaDB Vector Database         │
│  - Pydantic AI Agent analyzes context & decides        │
└──────────────────────────┬─────────────────────────────┘
                           │
                           │ JSON Response
                           │ (is_attack, risk_level, summary)
                           ▼
┌────────────────────────────────────────────────────────┐
│           n8n Automation Pipeline (Orchestrator)       │
│  - Routes decision via Conditional Logic               │
│  - If attack detected → triggers response actions      │
└──────────────────────────┬─────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
┌──────────────────────────┐ ┌──────────────────────────┐
│     Incident Dashboard   │ │  Automated Mitigation    │
│  - Alerts SOC Analyst    │ │  - Blocks Malicious IP   │
│  - Human-in-the-Loop UI  │ │  - Isolates Compromised  │
│    for approval          │ │    Host via Firewall API │
└──────────────────────────┘ └──────────────────────────┘
```


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

# Tech Stack 
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

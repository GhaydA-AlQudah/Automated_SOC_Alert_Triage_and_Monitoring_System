# CyberSentinel-An-Autonomous-AI-Driven-SOC-L1-Analyst-using-RAG-and-n8n.
model, prompt, threat intelligence, V DB, ترتيب الكود ولملمتهو اوتلوت ا llm ,  clean code, loggers, docs, comments, error handling
شو الي بندخله لل LLM ما تكرري وما تدخلي اشي ماله داعي 
# Problem Statement

1 vast amount of false positive alerts
Modern Security Information and Event Management (SIEM) systems generate thousands of security alerts every day. Although these alerts are essential for detecting potential cyber threats, a significant percentage of them are false positives, duplicated events, or low-priority notifications. As a result, SOC analysts spend a considerable amount of time manually investigating alerts that do not require immediate action.

🚨 The Problem: Fighting Automated Threats with Manual Operations


### What happens without this solution? (The Consequences)
missing the essential true positive 
* **Alert Fatigue & Missed Breaches:** Analysts get buried under thousands of daily alerts, allowing actual, sophisticated cyber attacks to slip through unnoticed.
* **Delayed Incident Response Time (MTTR):** Manually investigating raw, unstructured logs takes hours, giving attackers ample time to move laterally and compromise critical assets.
* **High Operational Costs:** Scaling a 24/7 SOC team to handle Tier-1 (L1) log triaging requires massive human capital and constant resource draining.
* **Data Privacy Risks:** Forwarding raw security logs directly to public cloud AI models (like OpenAI API) exposes sensitive internal corporate data (PII, internal IPs, and architecture secrets) to third-party leakage.
---

# The Solution

<img width="1715" height="632" alt="image" src="https://github.com/user-attachments/assets/8373ec21-c241-4775-bc13-cd871ae882ee" />


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

* why chroma db
* why x llm
* why grafana
* why pydantic
* why pydantic ai
# Architecture 
- Race Condition
- - Bottleneck

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
- Postman
----
🧠 Why Vector Database? (Agentic RAG Architecture)While Large Language Models (LLMs) are excellent at recognizing generic attack patterns, they operate in isolation—lacking context about internal infrastructure, evolving zero-day threats, and historical organizational triage.Integrating a Vector Database provides the SOC Agent with a Long-term Cyber Memory through Retrieval-Augmented Generation (RAG):1. Organizational Context & False Positive ReductionWhitelisting: Stores internal system contexts, trusted administrative IP spaces, and scheduled vulnerability scanners.Internal Policies: Feeds localized security compliance baselines (e.g., flagging off-hour authentications from external regions as critical) directly into the agent's prompt context.2. Live Threat Intelligence (Beyond Static Weights)Dynamic Knowledge Updates: Constantly ingests updated threat feeds, newly published CVEs, and evolving frameworks like MITRE ATT&CK or OWASP Top 10.Zero-Day Pattern Matching: Allows the agent to query raw log behaviors against newly uncovered advanced persistent threat (APT) tactics without requiring model retraining.3. Historical Incident Case-Base (Few-Shot Security Triage)Similarity Search ($Cosine\ Similarity$): When a complex, obfuscated log pattern emerges, the database surfaces historically archived incidents handled by human analysts.Contextual Learning: Employs Few-Shot Learning by supplying past mitigation playbooks (e.g., "We saw this pattern last month; the response was to block port X") to the LLM to guarantee optimized, consistent incident response.

---
why this llm?

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
---
Example

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/de6e98f5-f19b-4037-bdca-fd4fb8ece748" />

---
how to use
---
# Author
**GhaydA' Alqudah**

**Computer Engineer | AI & Cyber Security Enthusiast**

# CyberSentinel — AI-Powered Automated SOC Alert Triage & Threat Monitoring
> **The goal isn't to replace the SOC analyst.**
> 
> **It's to make sure the analyst spends their time on the alerts that actually deserve attention.**

# Problem Statement

### 1. Vast Amount of False Positive Alerts

- Modern SIEM systems generate thousands of security alerts every day.
- A large portion of these alerts may be:
  - Legitimate activity
  - Expected administrative behavior
  - Automated scanners
  - Low-risk events

- As a result:
  - SOC analysts spend valuable time manually investigating alerts.
  - Many investigated alerts ultimately require no action.

### 2. Fighting Automated Threats with Manual Operations

- Although attacks are increasingly automated, L1 SOC investigation is still heavily manual.
- For every suspicious alert, analysts may need to:
  - Review logs
  - Check IP reputation
  - Investigate context
  - Compare historical incidents
  - Decide
  - Document
  - Escalate

- Doing this repeatedly across hundreds or thousands of alerts creates a major operational bottleneck.
## Impact

This leads to:

Alert Fatigue — Analysts become overwhelmed by repetitive alerts.
Delayed Response — Time spent investigating false positives means less time for genuine threats.
Missed Threats — Critical alerts can be buried among large volumes of noise.
High Operational Cost — More analyst time is required to maintain continuous SOC operations.

The real problem isn't that SOCs lack alerts — it's that analysts lack the time to investigate all of them effectively.

---

# Solution Overview

The system provides an **automated SOC workflow** that continuously processes, enriches, investigates, and triages security alerts with minimal manual intervention.

### 📥 Automated Alert Ingestion

- The workflow **periodically retrieves new alerts** received through **POSTMAN**.
- As soon as a new alert arrives, it is **stored in PostgreSQL** to ensure reliable persistence and tracking.
- The alert is then processed through the automated investigation workflow.

### 🤖 AI-Powered Alert Investigation

- The **AI Agent** analyzes the enriched alert and performs the required investigation.
- When additional historical context is needed, the agent can query the **Vector Database** using **RAG (Retrieval-Augmented Generation)**.
- RAG allows the agent to retrieve and analyze **historical incidents** that may be relevant to the current alert.
- After the investigation, the alert's **status is updated in PostgreSQL** based on the agent's decision.

### 🎯 Automated Triage & Response

- After gathering the necessary context, the agent **triages the alert** and determines the appropriate case classification.
- The workflow automatically updates the alert's **status and case information** in PostgreSQL.
- **Emails are sent automatically** according to the case and its outcome.

### 🔄 Reliability & Recovery

- The workflow is managed through a defined **execution lifecycle** to prevent processes from remaining stuck indefinitely.
- If an execution fails or becomes stuck, the workflow can **automatically recover or retry** based on the configured recovery mechanism.
- This ensures that alerts remain trackable and are not lost due to temporary failures.

### 📊 Real-Time Security Dashboard

- A **real-time Grafana dashboard** provides continuous visibility into the security environment.
- The dashboard can be used to:
  - Monitor **recent alerts**
  - Track **detected threats**
  - Identify **threat patterns**
  - Observe **alert statuses and investigation activity**

> **Automate whenever possible, use the LLM when needed, and call tools only when necessary.**

### 🚀 End-to-End Workflow

**POSTMAN Alerts**  
↓  
**Store New Alert in PostgreSQL**  
↓  
**Threat Intelligence Enrichment**  
↓  
**AI Agent Investigation**  
↓  
**RAG → Vector DB → Historical Incidents (if needed)**  
↓  
**Update Alert Status in PostgreSQL**  
↓  
**Alert Triage & Case Classification**  
↓  
**Automated Case-Based Email Notification**  
↓  
**Real-Time Monitoring via Grafana**

**↻ Recovery / Retry mechanism handles failed or stuck executions**
---
# Security

The system is designed with a **local-first and controlled architecture** to improve security, privacy, and predictability.

- **Local-first infrastructure:** Local LLM via **LM Studio**, local embedding model, and a **local Grafana dashboard**, keeping AI processing, embeddings, and monitoring within the local environment.

- The **LLM has no direct access to the alerts database**; it only receives relevant data as input and produces output within a **deterministic workflow**.
- SQL injection
- kman wahdeh
- Prompt Injection
- sanitization

- i didnt use locally models due to commputation limits on my labtop
---

# Optimization

The system is optimized to reduce **LLM usage, latency, and unnecessary tool calls**.

### Only the **relevant alert information** is provided to the LLM as input.
- Unnecessary data is filtered out before reaching the model.
- This reduces:
  - Token usage
  - Processing time
  - Noise in the LLM's context
 
--- 
# Example

<img width="1501" height="741" alt="image" src="https://github.com/user-attachments/assets/c8a03357-7226-4a03-acf1-191d3821db66" />

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/95937a76-ec26-4edf-af98-26836bcfa268" />

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/de7f8f71-474e-4b5b-ab6e-8cbd0d4b6a0e" />

## run
## result
---
# Author
**GhaydA' Alqudah**

**Computer Engineer | AI & Cyber Security Enthusiast**

---

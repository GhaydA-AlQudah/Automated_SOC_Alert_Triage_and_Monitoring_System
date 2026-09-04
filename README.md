# CyberSentinel — AI-Powered Automated SOC Alert Triage & Threat Monitoring
> **The goal isn't to replace the SOC analyst.**
> 
> **It's to make sure the analyst spends their time on the alerts that actually deserve attention.**

# Problem Statement

**Alert Fatigue** — Analysts become **overwhelmed**, creating an operational **bottleneck**:

they lack the time to investigate everything, and **end up spending valuable time manually investigating** alerts that **ultimately require no action.** 

— while alerts that are genuinely **critical inestigation** get buried and **delayed.**

#### 1. Vast Amount of False Positive Alerts

#### 2. Fighting Automated Threats with Manual Operations
---

# Solution Overview

The system provides an **automated SOC workflow** that continuously processes, enriches, investigates, and triages security alerts with minimal manual intervention.

## n8n Workflow

<img width="1871" height="922" alt="image" src="https://github.com/user-attachments/assets/a427e6c8-8ed3-4da3-aee4-e72197e3d86a" />

---
## Email Alert

<img width="1487" height="636" alt="image" src="https://github.com/user-attachments/assets/c037b9fc-452b-4f02-96cf-dd844c15878c" />

---
## Monitoring Dashboard

<img width="1852" height="767" alt="image" src="https://github.com/user-attachments/assets/3ea2d417-bf81-450c-8961-0aa17ecd2b72" />

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

---
# Security

- Local LLM via **LM Studio**, local embedding model, and a **local Grafana dashboard**, keeping AI processing, embeddings, and monitoring within the local environment.
- The **LLM has no direct access to the alerts database**; it only receives relevant data as input and produces output within a **deterministic workflow**.
- SQL injection and Prompt Injection Protection.
- **NOTE: I didnt use locally models due to commputation limits on my labtop.**

---

# Optimization

- Only the **relevant alert information** is provided to the LLM as input.
- This reduces:
  - Token usage
  - Processing time
  - Noise in the LLM's context
---
# Author
**GhaydA' Alqudah**

**Computer Engineer | AI & Cyber Security Enthusiast**

# app/core/ingest_knowledge.py
import uuid
from app.core.vector_db import soc_vdb
from logger import logger

def run_ingestion():
    """
    Executes the comprehensive data ingestion pipeline for the SOC Vector DB.
    
    This script populates the ChromaDB collection with the foundational 
    cybersecurity knowledge base required by the AI Agent to perform RAG-driven 
    analysis. It structures and injects data across 4 core dimensions:
    1. Enterprise Policies
    2. Incident Playbooks
    3. Network & Asset Context
    4. Historical Incident Summaries
    """
    logger.info("🎬 Starting comprehensive SOC Knowledge Base and Incident Ingestion...")

    # =====================================================================
    # 1. CORE KNOWLEDGE BASE DATA (Policies, Playbooks, Network Context)
    # =====================================================================
    knowledge_base_items = [
        # --- Category 1: Enterprise Policies ---
        {
            "text": "Enterprise Firewall Policy: Any external IP address initiating more than 20 failed login attempts within a 60-second window via SSH (Port 22) or RDP (Port 3389) must be classified as an active Brute-Force attack. Enforcement Action: Immediate perimeter IP Blacklisting.",
            "metadata": {"knowledge_type": "enterprise_policy", "target": "Brute-Force", "severity": "High"}
        },
        {
            "text": "Web Application Firewall (WAF) Policy: Strict validation bounds on incoming HTTP POST bodies. Detection of aggressive SQL payload patterns including 'UNION SELECT', 'OR 1=1', or comment boundaries '--' triggers a violation. Enforcement Action: Drop request connection and flag infrastructure state.",
            "metadata": {"knowledge_type": "enterprise_policy", "target": "SQLi", "severity": "Critical"}
        },
        
        # --- Category 2: Incident Playbooks ---
        {
            "text": "SQL Injection (SQLi) Remediation Playbook: Upon detection of a validated SQLi attempt, the automated system must: 1. Isolate and blacklist the attacker's Source IP at the firewall level. 2. Terminate active database sessions tied to the transaction. 3. Dispatch a high-priority webhook alert to the Senior SOC Analyst team.",
            "metadata": {"knowledge_type": "incident_playbook", "target": "SQLi", "severity": "Critical"}
        },
        {
            "text": "Cross-Site Scripting (XSS) Mitigation Playbook: When browser payload injection or '<script>' string anomalies are flagged: 1. Sanitize the malformed input parameters. 2. Inject security headers (X-XSS-Protection) into the current response block. 3. Log user-agent metadata for persistence profiling.",
            "metadata": {"knowledge_type": "incident_playbook", "target": "XSS", "severity": "Medium"}
        },
        
        # --- Category 3: Network & Asset Context ---
        {
            "text": "Core Asset Infrastructure Context: Server 10.0.0.5 is designated as the primary Production Database Instance storing customer financial records. It is classified as a Crown-Jewel Asset. Direct inbound ingress traffic from external subnets or unsegmented corporate WiFi pools is explicitly prohibited.",
            "metadata": {"knowledge_type": "network_context", "target": "Database_Server", "severity": "Critical"}
        },
        {
            "text": "Network Topology Segmentation Rule: The Active Directory Domain Controller resides exclusively on the management subnet (10.0.0.2). Internal corporate workstations (172.16.x.x) should never exhibit raw outbound RPC or lateral SMB connections toward this zone outside verified administrative contexts.",
            "metadata": {"knowledge_type": "network_context", "target": "Active_Directory", "severity": "High"}
        }
    ]

    # Ingesting General Knowledge Base Components (Policies, Playbooks, Context)
    logger.info("📚 Ingesting corporate policies, playbooks, and network topology context...")
    for item in knowledge_base_items:
        doc_id = f"kb_{uuid.uuid4().hex[:8]}"
        soc_vdb.add_security_knowledge(
            doc_id=doc_id,
            document_text=item["text"],
            metadata=item["metadata"]
        )

    # =====================================================================
    # 2. HISTORICAL INCIDENT DATA (Behavioral Summaries)
    # =====================================================================
    historical_incidents = [
        {
            "text": "Historical Incident Summary (Q1 2025): An attacker compromised an unpatched HR portal endpoint using a Directory Traversal technique ('../../etc/passwd'). The system automatically intercepted the exfiltration attempt, blocked the offending external proxy server IP, and initiated a system patch workflow.",
            "metadata": {"attack_type": "Directory-Traversal", "mitigation_action": "Block IP & Patch", "year": "2025"}
        },
        {
            "text": "Historical Incident Summary (Jan 2026): A credential stuffing event targeted internal VPN entry nodes. Over 5,000 automated login permutations were detected from varying rotating VPN endpoints. The event was contained by enforcing global Multi-Factor Authentication (MFA) step-up constraints.",
            "metadata": {"attack_type": "Credential-Stuffing", "mitigation_action": "Enforce MFA", "year": "2026"}
        }
    ]

    # Ingesting Historical Incident Narratives via the dedicated method
    logger.info("🗃️ Ingesting historical incident case studies and narratives...")
    for incident in historical_incidents:
        incident_id = f"inc_{uuid.uuid4().hex[:8]}"
        soc_vdb.add_incident_summary(
            incident_id=incident_id,
            summary_text=incident["text"],
            metadata=incident["metadata"]
        )

    # =====================================================================
    # 3. COLLECTION VALIDATION & METRICS
    # =====================================================================
    print("-" * 60)
    total_docs = soc_vdb.get_total_documents()
    logger.info(f"🎉 SOC Data Ingestion Pipeline executed successfully!")
    logger.info(f"📦 Database State: Total persistent records securely stored in Vector DB: {total_docs}")
    print("-" * 60)

if __name__ == "__main__":
    run_ingestion()
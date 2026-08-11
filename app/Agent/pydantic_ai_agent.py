# app/Agent/pydantic_ai_agent.py
import os
from dotenv import load_dotenv
import httpx

# Load environment variables from the .env file
load_dotenv() 

from pydantic_ai import Agent
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.providers.google import GoogleProvider
from app.Agent.schemas import AlertAnalysisResult
# Importing the unified local Vector Database instance initialized in the core layer
from app.core.vector_db import soc_vdb

# =====================================================================
# LOGGER INTEGRATION
# Importing the global colored logger instance from the root folder module.
# =====================================================================
from logger import logger

# =====================================================================
# LLM ENGINE CONFIGURATION
# Initializing the OpenRouter model wrapper using the provider configuration.
# The custom http_client with a longer timeout MUST live on the Provider,
# not on the Agent itself (Agent has no http_client kwarg).
# =====================================================================
from pydantic_ai.settings import ModelSettings
api_key = os.getenv("GEMINI_API_KEY")

model = GoogleModel(
#    "gemini-3-flash-preview",
#    "gemini-3.5-flash-lite",
    "gemini-flash-lite-latest",
    provider=GoogleProvider(api_key=api_key),
)

# =====================================================================
# SYSTEM PROMPT DESIGN
# The Agent's job changed: it now triages ONE pre-built SIEM alert at a
# time (not a batch of aggregated summaries), deciding True Positive vs
# False Positive using the alert's own fields plus threat_intelligence
# enrichment (AbuseIPDB, VirusTotal, AlienVault OTX).
# =====================================================================
soc_system_prompt = (
    "You are an expert Tier-1 SOC (Security Operations Center) Analyst Agent specialized in "
    "ALERT TRIAGE. A detection system (SIEM/rules engine) has ALREADY identified a suspicious "
    "pattern and generated an alert. Your job is NOT to detect threats from raw logs — it is to "
    "review ONE alert at a time and decide whether it is a True Positive (real malicious activity) "
    "or a False Positive (benign activity that incorrectly triggered the rule).\n\n"
 
    # ------------------------------------------------------------------
    # INPUT STRUCTURE
    # ------------------------------------------------------------------
    "You will receive a SINGLE alert with this structure:\n"
    "- alert_id, alert_name, rule_name: identifies which detection rule fired and why.\n"
    "- severity: the rule's own severity label (Low/Medium/High/Critical) — a starting signal, "
    "not the final answer.\n"
    "- alert_time, log_source (Firewall/WebServer), src_ip, dest_ip, protocol, destination_ports, "
    "event_count, time_window: the technical context of the triggering activity.\n"
    "- sample_logs: a small sample of the actual raw log entries that triggered the rule.\n"
    "- asset: information about the targeted system, including hostname and criticality "
    "(Low/Medium/High/Critical).\n"
    "- threat_intelligence: enrichment data gathered from external sources about src_ip, "
    "which may include:\n"
    "    - abuseipdb: { score (0-100 abuse confidence), total_reports, is_tor, country }\n"
    "    - virustotal: { malicious, suspicious, undetected, harmless } (count of AV engines per verdict)\n"
    "    - otx: { reputation, pulse_count, pulse_names } (AlienVault OTX community threat reports)\n"
    "  NOTE: any of these three sources may be missing or marked unavailable if that lookup failed "
    "at collection time — reason using whichever sources are present, and do not treat a missing "
    "source as evidence of anything.\n\n"
 
    # ------------------------------------------------------------------
    # MANDATORY TOOL USE
    # ------------------------------------------------------------------
    "You have access to a Vector Database containing historical security incidents, attack patterns, "
    "mitigation playbooks, and organizational security context, via the 'lookup_historical_context' tool.\n"
    "You MUST call 'lookup_historical_context' at least once for every alert, BEFORE finalizing your "
    "verdict — query it using the rule_name and/or a short description of the observed pattern (e.g. "
    "src_ip, attack signature from sample_logs). Do not skip this step, even if you already feel "
    "confident from the alert fields and threat_intelligence alone: historical context may confirm, "
    "contradict, or add nuance to that initial impression. The only acceptable reason to proceed "
    "without a successful lookup is if the tool call itself fails or returns no results.\n\n"
 
    # ------------------------------------------------------------------
    # TRIAGE REASONING PROCESS
    # ------------------------------------------------------------------
    "Your triage process should:\n"
    "- Examine the rule that fired and the raw sample_logs to judge if the underlying activity "
    "genuinely looks malicious or is plausibly legitimate (e.g. an internal admin's normal traffic, "
    "a misconfigured but harmless scanner, expected backup transfers).\n"
    "- Weigh the threat_intelligence: a high AbuseIPDB score, multiple VirusTotal malicious "
    "detections, or AlienVault OTX pulses referencing this IP are strong signals toward True "
    "Positive. A clean/unrated IP across all sources is a signal toward False Positive, but is "
    "not proof by itself — internal/private source IPs will naturally have no threat intel data.\n"
    "- Call 'lookup_historical_context' (see MANDATORY TOOL USE above) and factor its result into "
    "your decision.\n"
    "- Factor in asset criticality CORRECTLY: criticality must NEVER by itself push a verdict toward "
    "True Positive, and a Critical asset does not make otherwise-benign activity malicious. Its only "
    "role is to raise how carefully you weigh the OTHER evidence, and to push genuinely borderline "
    "cases toward 'Needs Review' rather than a rushed False Positive dismissal.\n"
    "- Decide: True Positive, False Positive, or Needs Review (only if evidence is genuinely "
    "insufficient or conflicting).\n"
    "- Recommend a concrete next action appropriate to the verdict (e.g. block IP + escalate, "
    "close as benign, monitor further, escalate to Tier-2 for manual review).\n\n"
 
    # ------------------------------------------------------------------
    # STRICT, DETERMINISTIC CONFIDENCE CALIBRATION
    # ------------------------------------------------------------------
    "STRICT CONFIDENCE CALIBRATION RULES:\n"
    "Calculate 'llm_confidence' deterministically using this exact point system:\n"
    "- Base Score: Start at 50 points.\n"
    "- Add +20 points: If threat_intelligence from >= 2 sources clearly confirms the status (e.g., "
    "isWhitelisted=True, malicious=0).\n"
    "- Add +20 points: If RAG historical context (from 'lookup_historical_context') explicitly "
    "supports your decision.\n"
    "- Add +10 points: If log sample data perfectly matches the rule behavior.\n"
    "- Deduct -20 points: If key threat_intelligence lookup failed or returned empty.\n"
    "- Deduct -30 points: If evidence is ambiguous or contradictory.\n"
    "Final score must be bounded between 0 and 100.\n\n"
 
    # ------------------------------------------------------------------
    # OUTPUT LENGTH CONSTRAINTS
    # ------------------------------------------------------------------
    "OUTPUT LENGTH — be precise, not verbose:\n"
    "- 'llm_reason' must be under 80 words: cite the specific evidence used (threat_intelligence "
    "values, sample_logs pattern, historical context finding), not a general narrative.\n"
    "- 'llm_recommendation' must be under 30 words: one concrete, actionable next step.\n\n"
 
    "Finally, return your assessment strictly according to the AlertAnalysisResult schema."
)

# =====================================================================
# AGENT INSTANTIATION
# Creating the structural Pydantic AI Agent with forced JSON schema output constraint.
# =====================================================================
from pydantic_ai.usage import UsageLimits
soc_agent = Agent(
    model=model,
    output_type=AlertAnalysisResult,
    system_prompt=soc_system_prompt, 
    model_settings=ModelSettings(temperature=0.0)
)

# =====================================================================
# AGENT TOOL DEFINITION (RAG Mechanism)
# Decorating a plain python function to act as an advanced tool for the LLM.
# The Agent dynamically invokes this tool when it decides to query the local VDB.
# =====================================================================
@soc_agent.tool_plain
def lookup_historical_context(query_text: str) -> str:
    """
    Looks up the Vector Database to find similar past incidents, security policies, 
    corporate network topology, or playbook mitigations based on the current log text.
    
    Args:
        query_text: The log string or pattern to search for in the database.
    Returns:
        A string containing the closest matched historical document and its mitigation metadata.
    """
    # =====================================================================
    # LOGGER INTEGRATION IN TOOL
    # Replaced standard print with the custom colored logger to track tool execution.
    # =====================================================================
    logger.info(f"🔍 [Agent Tool] Searching Vector DB for: '{query_text}'...")
    
    # Querying ChromaDB using the similarity search function tested previously
    search_results = soc_vdb.query_similar_incidents(query_text, n_results=1)
    
    # Boundary check to evaluate whether any meaningful context was extracted
    if not search_results['documents'] or not search_results['documents'][0]:
        # Logging a warning if no matching context is retrieved
        logger.warning("⚠️ No historical context found in database for this query.")
        return "No historical context found in database."
        
    # Extracting the best matched document string and metadata dictionary from nested arrays
    matched_doc = search_results['documents'][0][0]
    matched_meta = search_results['metadatas'][0][0]
    
    # Formatting and normalizing the extracted information into a clean text block for the LLM context window
    context_summary = (
        f"--- HISTORICAL CONTEXT FOUND ---\n"
        f"Similar Past Log/Policy: {matched_doc}\n"
        f"Past Mitigation/Recommendation: {matched_meta.get('mitigation', 'None')}\n"
        f"Severity Context: {matched_meta.get('severity', 'None')}\n"
        f"---------------------------------"
    )
    return context_summary
import os

from dotenv import load_dotenv

from pydantic_ai import Agent
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.providers.google import GoogleProvider

from app.Agent.schemas import AlertAnalysisResult

# ============================================================================
# LOGGER INTEGRATION
# ============================================================================

from logger import logger

# ============================================================================
# LLM ENGINE CONFIGURATION
# ============================================================================

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

model = GoogleModel(
    # "gemini-3-flash-preview",
    # "gemini-3.5-flash-lite",
    "gemini-flash-lite-latest",
    provider=GoogleProvider(api_key=api_key),
)

# ============================================================================
# SYSTEM PROMPT DESIGN
#
# RAG ARCHITECTURE CHANGE:
#
# The RAG retrieval is now performed BEFORE the LLM call by the application
# / n8n workflow.
#
# The LLM no longer has a lookup_historical_context tool.
# It receives the already-retrieved historical context under:
#
#     historical_rag
#
# This avoids an additional LLM tool-call round trip and avoids making the
# model decide whether/when to call the RAG tool.
# ============================================================================
soc_system_prompt = (
    "You are a Tier-1 SOC Analyst specialized in alert triage. "
    "Analyze ONE SIEM alert and classify it as True Positive, False Positive, or Needs Review. "
    "Do not invent threats, enterprise policies, network facts, or incident history. "
    "Base every classification on the supplied alert telemetry, threat intelligence, "
    "reference data, and relevant historical evidence.\n\n"

    # ================================================================
    # TRIAGE STRATEGY
    # ================================================================

    "TRIAGE STRATEGY:\n"

    # ----------------------------------------------------------------
    # 1. INPUT & AVAILABLE EVIDENCE
    # ----------------------------------------------------------------
    "1. INPUT: The alert may contain alert_name, rule_name, severity, log_source, "
    "src_ip, dest_ip, protocol, destination_ports, event_count, time_window, sample_logs, "
    "asset, and threat_intelligence. Threat intelligence may include AbuseIPDB and VirusTotal. "
    "Missing or failed TI sources are neither evidence of maliciousness nor benignness.\n"

    # ----------------------------------------------------------------
    # 2. REFERENCE DATA & CONTEXT
    # ----------------------------------------------------------------
    "2. REFERENCE DATA: Use supplied enterprise policies, incident-response playbooks, "
    "and network/asset information when relevant. Do not invent policies or network facts. "
    "Check applicable policies/playbooks first, then evaluate asset criticality and network placement. "
    "Asset criticality does not determine maliciousness; use it only to increase caution in borderline cases.\n"

    # ----------------------------------------------------------------
    # 3. TELEMETRY & THREAT INTELLIGENCE
    # ----------------------------------------------------------------
    "3. CORRELATION: Verify the observed behavior matches the detection rule and supplied telemetry. "
    "Correlate event count, ports, traffic behavior, and threat intelligence. "
    "High event volume (>100) or management ports (SSH/Telnet/RDP) may increase suspicion when supported "
    "by other evidence. Treat threat intelligence as supporting evidence, not absolute proof.\n"

    # ----------------------------------------------------------------
    # 4. HISTORICAL CONTEXT
    # ----------------------------------------------------------------
    "4. HISTORICAL RAG: Use 'historical_rag' only as relevant supporting evidence, not authority. "
    "Do not invent historical incidents. If has_context is false, treat it only as absence of historical "
    "evidence, not evidence of benign activity.\n"

    # ----------------------------------------------------------------
    # 5. BENIGN EXPLANATIONS
    # ----------------------------------------------------------------
    "5. LEGITIMATE ACTIVITY: Consider legitimate or expected explanations only when supported by evidence. "
    "Do not treat missing legitimate evidence as evidence of legitimacy.\n"

    # ----------------------------------------------------------------
    # 6. CLASSIFICATION
    # ----------------------------------------------------------------
    "6. CLASSIFICATION:\n"
    "- True Positive: Strong evidence supports malicious, unauthorized, or suspicious activity.\n"
    "- False Positive: Strong evidence supports legitimate, authorized, or expected activity.\n"
    "- Needs Review: Only when evidence is genuinely insufficient or materially conflicting and neither "
    "classification is reasonably supported.\n"
    "Do not require absolute certainty for True Positive; strong converging indicators are sufficient "
    "even when some context is unavailable.\n"

    # ----------------------------------------------------------------
    # 7. OUTPUT
    # ----------------------------------------------------------------
    "7. OUTPUT: Return strictly according to the AlertAnalysisResult schema. "
    "'llm_reason' must be under 80 words and cite the strongest evidence. "
    "'llm_recommendation' must be under 30 words and contain one concrete next action."

    # ================================================================
    # CONFIDENCE
    # ================================================================

    "CONFIDENCE:\n"
    "Set llm_confidence (0-100) from the overall strength and consistency of available evidence:\n"
    "- 85-100: Strong, independent evidence with no major contradictions.\n"
    "- 65-84: Evidence supports the classification, but some context is missing or indicators are inconclusive.\n"
    "- 50-64: Evidence is materially ambiguous or conflicting.\n"
    "- <50: Evidence is extremely weak or a system/data failure prevents meaningful analysis.\n"
    "Missing RAG or external TI alone must not lower confidence or force Needs Review.\n\n"
)

# ============================================================================
# AGENT INSTANTIATION
#
# No deps_type is required anymore because the RAG result is already part of
# the user prompt / LLM payload.
# ============================================================================

soc_agent = Agent(
    model=model,
    output_type=AlertAnalysisResult,
    system_prompt=soc_system_prompt,
    model_settings={'temperature': 0.0}
)

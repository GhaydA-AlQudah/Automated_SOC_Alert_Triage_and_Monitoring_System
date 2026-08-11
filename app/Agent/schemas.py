# app/Agent/schemas.py
from pydantic import BaseModel, Field


class AlertAnalysisResult(BaseModel):
    """
    Final structured output returned by the SOC Agent for a SINGLE alert.
    This maps 1:1 onto the LLM-related columns of the `alerts` table:
    llm_classification, llm_confidence, llm_reason, llm_recommendation.

    Deliberately flat (no nested models / lists of objects) to avoid
    $defs/$ref in the generated JSON Schema, which some OpenRouter free
    models (grammar-constrained decoding) cannot resolve.
    """

    llm_classification: str = Field(
        description=(
            "The triage verdict for this alert. Must be exactly one of: "
            "'True Positive', 'False Positive', 'Needs Review'. "
            "Use 'Needs Review' only when the available evidence is genuinely "
            "insufficient or contradictory to confidently decide TP or FP."
        )
    )

    llm_confidence: float = Field(
        description=(
            "Confidence in the classification, as a number from 0 to 100 "
            "(e.g. 92.5). Higher values mean stronger certainty."
        )
    )

    llm_reason: str = Field(
        description=(
            "A concise technical explanation justifying the classification. "
            "Must reference specific evidence from the alert fields (severity, "
            "event_count, destination_ports, sample_logs, asset criticality) "
            "and/or the threat_intelligence data (AbuseIPDB score, VirusTotal "
            "detections, AlienVault OTX reputation/pulses) that support the verdict."
        )
    )

    llm_recommendation: str = Field(
        description=(
            "The concrete recommended action for a SOC analyst to take next "
            "(e.g. 'Block source IP and escalate to Tier-2', 'No action required, "
            "close as benign', 'Monitor source IP for repeated activity')."
        )
    )
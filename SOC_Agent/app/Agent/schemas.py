# app/Agent/schemas.py
from pydantic import BaseModel, Field

class AlertAnalysisResult(BaseModel):
    llm_classification: str = Field(
        ...,
        description=(
            "The triage verdict. Must be exactly one of: 'True Positive', 'False Positive', 'Needs Review'. "
            "Use 'Needs Review' only if evidence is insufficient or contradictory."
        )
    )

    llm_confidence: float = Field(
        ...,
        description="Confidence score between 0.0 and 100.0 based on evidence strength."
    )

    llm_reason: str = Field(
        ...,
        description=(
            "A concise technical explanation justifying the verdict by referencing key evidence "
            "(e.g., threat intelligence, logs, asset criticality). "
            "STRICT LIMIT: Maximum 2 short sentences, under 35 words."
        )
    )

    llm_recommendation: str = Field(
        ...,
        description=(
            "The concrete next step for a SOC analyst. "
            "STRICT LIMIT: Maximum 1 short sentence, under 15 words."
        )
    )
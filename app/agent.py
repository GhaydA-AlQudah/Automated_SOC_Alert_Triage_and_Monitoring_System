import uvicorn
import httpx

from typing import Optional, Any, Dict
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.Agent.pydantic_ai_agent import soc_agent
from app.Agent.schemas import AlertAnalysisResult
from pydantic_ai.usage import UsageLimits
from logger import logger


# ============================================================================
# APPLICATION CONFIGURATION
# ============================================================================

app = FastAPI(
    title="Automated SOC Analyst Agent API",
    description=(
        "Real-time AI-powered SOC alert triage API "
        "(True Positive / False Positive / Needs Review)"
    ),
    version="3.0.0",
)

INGEST_BASE_URL = "http://127.0.0.1:8000"


# ============================================================================
# REQUEST SCHEMA — Dynamic Alert Payload
# ============================================================================

class AlertPayload(BaseModel):
    """
    Tolerates both direct payloads (where alert_id is at the root)
    and wrapped payloads (where data arrives under an 'alert' key).
    """
    alert_id: Optional[str] = None
    alert: Optional[Dict[str, Any]] = None  # Supports wrapped payload from n8n
    alert_name: Optional[str] = None
    rule_name: Optional[str] = None
    severity: Optional[str] = None
    alert_time: Optional[str] = None
    log_source: Optional[str] = None
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    protocol: Optional[str] = None
    destination_ports: Optional[list] = None
    event_count: Optional[int] = None
    time_window: Optional[str] = None
    sample_logs: Optional[list] = None
    asset: Optional[dict] = None
    threat_intelligence: Optional[dict] = None

    class Config:
        extra = "ignore"


# ============================================================================
# LLM INPUT BUILDER
# ============================================================================

def build_llm_alert_payload(alert: dict) -> dict:
    """Extracts only security-relevant fields for LLM processing, explicitly excluding alert_id."""
    payload = {
        "alert_name": alert.get("alert_name"),
        "rule_name": alert.get("rule_name"),
        "severity": alert.get("severity"),
        "alert_time": alert.get("alert_time"),
        "log_source": alert.get("log_source"),
        "src_ip": alert.get("src_ip"),
        "dest_ip": alert.get("dest_ip"),
        "protocol": alert.get("protocol"),
        "destination_ports": alert.get("destination_ports"),
        "event_count": alert.get("event_count"),
        "time_window": alert.get("time_window"),
        "sample_logs": alert.get("sample_logs"),
        "asset": alert.get("asset"),
        "threat_intelligence": alert.get("threat_intelligence"),
    }
    # Ensure alert_id is completely stripped out from LLM input
    payload.pop("alert_id", None)
    return payload


# ============================================================================
# MAIN ALERT TRIAGE ENDPOINT
# ============================================================================

@app.post("/api/v1/analyze")
async def analyze_alert(payload: AlertPayload):
    """
    Triage a single SOC alert, handling direct or wrapped n8n JSON inputs.
    """
    alert_dict = payload.model_dump()

    # Unwrap nested "alert" key if n8n passed the outer object wrapper
    if alert_dict.get("alert") and isinstance(alert_dict["alert"], dict):
        inner_alert = alert_dict["alert"]
        for key, val in inner_alert.items():
            if alert_dict.get(key) is None:
                alert_dict[key] = val

    alert_id = alert_dict.get("alert_id")

    if not alert_id:
        logger.error("❌ [TRIAGE] Request rejected: missing alert_id.")
        raise HTTPException(
            status_code=400,
            detail="Missing required field: alert_id"
        )

    logger.info("🔎 [TRIAGE] Received alert for triage: %s", alert_id)

    # STEP 1 — BUILD MINIMAL LLM PAYLOAD (WITHOUT ALERT_ID)
    llm_alert = build_llm_alert_payload(alert_dict)

    logger.info("🧹 [TRIAGE] Reduced alert %s to security-relevant fields.", alert_id)

    # STEP 2 — SEND TO SOC AGENT
    logger.info("🧠 [TRIAGE] Sending alert %s to SOC Agent...", alert_id)

    try:
        response = await soc_agent.run(
            user_prompt=(
                "Triage the following SOC alert.\n\n"
                "The alert has already been enriched with threat "
                "intelligence under the 'threat_intelligence' field.\n\n"
                f"{llm_alert}"
            )
        )

        result: AlertAnalysisResult = response.output

        logger.info("🆔 [TRIAGE] Alert ID: %s", alert_id)
        logger.info("🏷️ [TRIAGE] Classification: %s", result.llm_classification)
        logger.info("📊 [TRIAGE] Confidence: %.2f", result.llm_confidence)

    except Exception as e:
        logger.exception("❌ [TRIAGE] SOC Agent execution failed for alert %s.", alert_id)
        raise HTTPException(
            status_code=500,
            detail=f"Internal agent execution error: {str(e)}"
        )

    # STEP 3 — PERSIST LLM RESULT TO INGEST SERVICE
    logger.info("💾 [TRIAGE] Persisting analysis result for alert %s...", alert_id)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            update_response = await client.post(
                f"{INGEST_BASE_URL}/api/v1/update_analysis_result",
                json={
                    "alert_id": alert_id,
                    "llm_classification": result.llm_classification,
                    "llm_confidence": result.llm_confidence,
                    "llm_reason": result.llm_reason,
                    "llm_recommendation": result.llm_recommendation,
                },
            )

            update_response.raise_for_status()
            update_data = update_response.json()

        if update_data.get("status") != "success":
            raise HTTPException(
                status_code=502,
                detail=f"Failed to persist analysis result: {update_data.get('message')}"
            )

        logger.info("✅ [TRIAGE] Alert %s fully processed and persisted.", alert_id)

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("❌ [TRIAGE] Database persistence failed for alert %s.", alert_id)
        raise HTTPException(
            status_code=502,
            detail=f"Failed to persist analysis result: {str(e)}"
        )

    return {
        "status": "success",
        "alert_id": alert_id,
        "analysis": result.model_dump(),
    }


# ============================================================================
# HEALTH CHECK
# ============================================================================

@app.get("/health")
async def health_check():
    return {"status": "healthy"}


if __name__ == "__main__":
    logger.info("🚀 Starting SOC Agent API...")
    uvicorn.run("app.agent:app", host="127.0.0.1", port=8001, reload=True)
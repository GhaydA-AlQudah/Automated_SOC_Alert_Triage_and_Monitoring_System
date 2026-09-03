import uvicorn
import httpx
import traceback
import json

from typing import Optional, Any, Dict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.Agent.pydantic_ai_agent import soc_agent
from app.Agent.schemas import AlertAnalysisResult
from logger import logger

from app.database import Database


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
# DATABASE
# ============================================================================

# Lazy database connection.
db = Database()


async def get_all_security_reference_data() -> dict:
    """
    Fetch all organizational security reference data from PostgreSQL.

    This data is later attached to the alert payload and provided
    to the LLM as trusted application reference data.
    """

    query = """
        SELECT reference_type, data
        FROM public.security_reference_data;
    """

    rows = await db.execute(
        query,
        params=None,
        fetch=True,
        commit=False,
    )

    if not rows:
        return {}

    return {
        row[0]: row[1]
        for row in rows
    }


# ============================================================================
# REQUEST SCHEMAS
# ============================================================================

class RAGContextPayload(BaseModel):
    """
    Pre-LLM RAG result coming from the n8n RAG node.

    RAG is intentionally NOT a Pydantic AI tool anymore.
    n8n calls the RAG endpoint first and then sends its result together
    with the enriched alert to this endpoint.
    """

    has_context: bool = False
    context_block: Optional[str] = None

    class Config:
        extra = "ignore"


class AlertPayload(BaseModel):
    """
    Accepts the enriched alert plus the pre-retrieved RAG result.

    Supported n8n shapes:

    1) Wrapped:
        {
            "alert": {...},
            "rag": {
                "has_context": true,
                "context_block": "..."
            }
        }

    2) Direct:
        {
            "alert_id": "...",
            ...
            "rag": {...}
        }

    3) Direct RAG fields:
        {
            "alert": {...},
            "has_context": true,
            "context_block": "...",
        }
    """

    # Alert can arrive wrapped by n8n.
    alert_id: Optional[str] = None
    alert: Optional[Dict[str, Any]] = None

    # Alert fields.
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

    # Pre-LLM RAG result.
    rag: Optional[RAGContextPayload] = None

    # Also tolerate RAG fields directly on the request.
    has_context: Optional[bool] = None
    context_block: Optional[str] = None

    class Config:
        extra = "ignore"


# ============================================================================
# RAG NORMALIZATION
# ============================================================================

def extract_rag_context(request_data: dict) -> dict:
    """
    Extract the pre-LLM RAG result from the n8n request.

    Preferred shape:
        request_data["rag"]

    For compatibility, direct RAG fields are also accepted.
    """

    rag_value = request_data.get("rag")

    if isinstance(rag_value, RAGContextPayload):
        rag = rag_value.model_dump()
    elif isinstance(rag_value, dict):
        rag = dict(rag_value)
    else:
        rag = {}

    # Compatibility with direct RAG fields.
    for key in (
        "has_context",
        "context_block",
    ):
        if rag.get(key) is None and request_data.get(key) is not None:
            rag[key] = request_data.get(key)

    return {
        "has_context": bool(rag.get("has_context", False)),
        "context_block": rag.get("context_block") or "",
    }


# ============================================================================
# PROMPT FORMATTER (DYNAMIC STRUCTURAL FORMATTING)
# ============================================================================

def format_structured_user_prompt(llm_alert: dict) -> str:
    """
    Formats the raw LLM alert payload into a clean, human-readable text prompt
    without raw dictionary brackets '{', '}', or tuple formatting.
    """

    lines = [
        "Triage the following Security Operations Center (SOC) alert carefully.",
        "The alert has been enriched with threat intelligence, historical RAG evidence, and organizational reference data.",
        "\n--- ALERT CORE DETAILS ---"
    ]

    for key, value in llm_alert.items():
        if key in (
            "threat_intelligence",
            "historical_rag",
            "organizational_reference_data",
            "sample_logs",
            "asset"
        ):
            continue

        lines.append(
            f"- {key.replace('_', ' ').title()}: {value}"
        )

    if llm_alert.get("asset"):
        lines.append("\n--- TARGET ASSET INFORMATION ---")

        asset = llm_alert["asset"]

        if isinstance(asset, dict):
            for k, v in asset.items():
                lines.append(
                    f"- {k.replace('_', ' ').title()}: {v}"
                )
        else:
            lines.append(str(asset))

    if llm_alert.get("threat_intelligence"):
        lines.append("\n--- THREAT INTELLIGENCE ENRICHMENT ---")

        ti = llm_alert["threat_intelligence"]

        if isinstance(ti, dict):
            for k, v in ti.items():
                lines.append(
                    f"- {k.replace('_', ' ').title()}: {v}"
                )
        else:
            lines.append(str(ti))

    if llm_alert.get("sample_logs"):
        lines.append("\n--- SAMPLE LOGS ---")

        logs = llm_alert["sample_logs"]

        if isinstance(logs, list):
            for idx, log in enumerate(logs, start=1):
                lines.append(
                    f"Log #{idx}: {log}"
                )
        else:
            lines.append(str(logs))

    if llm_alert.get("historical_rag"):
        lines.append("\n--- HISTORICAL RAG CONTEXT ---")

        rag = llm_alert["historical_rag"]

        if isinstance(rag, dict):

            lines.append(
                f"- Has Context: {rag.get('has_context')}"
            )

            lines.append(
                f"- Context Block:\n{rag.get('context_block')}"
            )

        else:
            lines.append(str(rag))

    if llm_alert.get("organizational_reference_data"):
        lines.append("\n--- ORGANIZATIONAL REFERENCE DATA ---")

        ref_data = llm_alert["organizational_reference_data"]

        if isinstance(ref_data, dict):

            for k, v in ref_data.items():
                lines.append(
                    f"[{k.upper()}]"
                )

                lines.append(
                    f"{v}\n"
                )

        else:
            lines.append(str(ref_data))

    lines.append(
        "\nPerform a thorough analysis based on all the provided data above "
        "and return the final triage classification."
    )

    return "\n".join(lines)


# ============================================================================
# LLM INPUT BUILDER
# ============================================================================

async def build_llm_alert_payload(
    alert: dict,
    rag_context: dict,
) -> dict:
    """
    Build the security-relevant payload sent to the LLM.

    RAG has already been retrieved before the LLM call.
    No RAG tool is called by the agent.
    """

    # ------------------------------------------------------------------------
    # 1. Load organizational reference data
    # ------------------------------------------------------------------------

    full_reference = await get_all_security_reference_data()

    # ------------------------------------------------------------------------
    # 2. Build LLM payload
    # ------------------------------------------------------------------------

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

        # Threat intelligence is the enrichment result.
        "threat_intelligence": alert.get(
            "threat_intelligence"
        ),

        # RAG is historical evidence retrieved before the LLM call.
        "historical_rag": rag_context,

        # Trusted organizational reference data.
        "organizational_reference_data": full_reference,
    }

    # Absolute hygiene:
    # Never send alert_id to the LLM.
    payload.pop("alert_id", None)

    return payload


# ============================================================================
# PERSISTENCE HELPER
# ============================================================================

async def persist_analysis_result(
    alert_id: str,
    llm_classification: str,
    llm_confidence: float,
    llm_reason: str,
    llm_recommendation: str,
    triage_status: str,
) -> Dict[str, Any]:
    """
    Persist the LLM triage result to the ingest service.
    """

    async with httpx.AsyncClient(
        timeout=30.0
    ) as client:

        update_response = await client.post(
            f"{INGEST_BASE_URL}/api/v1/update_analysis_result",

            json={
                "alert_id": alert_id,

                "llm_classification":
                    llm_classification,

                "llm_confidence":
                    llm_confidence,

                "llm_reason":
                    llm_reason,

                "llm_recommendation":
                    llm_recommendation,

                "triage_status":
                    triage_status,
            },
        )

        update_response.raise_for_status()

        return update_response.json()


# ============================================================================
# MAIN ALERT TRIAGE ENDPOINT
# ============================================================================

@app.post("/api/v1/analyze")
async def analyze_alert(
    payload: AlertPayload,
):
    """
    Triage a single SOC alert.

    n8n should call the RAG endpoint BEFORE this endpoint and then send:

        {
            "alert": <enriched alert>,
            "rag": <RAG response>
        }

    The LLM receives both as evidence in one call.
    No RAG tool call is performed by Pydantic AI.
    """

    # =========================================================================
    # STEP 0 — NORMALIZE REQUEST
    # =========================================================================

    request_dict = payload.model_dump()

    # -------------------------------------------------------------------------
    # Unwrap nested alert object if present.
    # -------------------------------------------------------------------------

    alert_dict = {}

    if (
        request_dict.get("alert")
        and isinstance(
            request_dict["alert"],
            dict,
        )
    ):
        alert_dict.update(
            request_dict["alert"]
        )

    # Direct alert fields override missing values only.
    for key in (
        "alert_id",
        "alert_name",
        "rule_name",
        "severity",
        "alert_time",
        "log_source",
        "src_ip",
        "dest_ip",
        "protocol",
        "destination_ports",
        "event_count",
        "time_window",
        "sample_logs",
        "asset",
        "threat_intelligence",
    ):
        value = request_dict.get(key)

        if value is not None:
            alert_dict[key] = value

    # -------------------------------------------------------------------------
    # Extract alert ID.
    # -------------------------------------------------------------------------

    alert_id = alert_dict.get("alert_id")

    if not alert_id:

        logger.error(
            "❌ [TRIAGE] Request rejected: missing alert_id."
        )

        raise HTTPException(
            status_code=400,
            detail="Missing required field: alert_id",
        )

    logger.info(
        "🔎 [TRIAGE] Received alert for triage: %s",
        alert_id,
    )

    # =========================================================================
    # STEP 0.1 — EXTRACT PRE-LLM RAG
    # =========================================================================

    rag_context = extract_rag_context(
        request_dict
    )

    logger.info(
        "📚 [RAG] Pre-LLM RAG received for alert %s | "
        "has_context=%s",
        alert_id,
        rag_context["has_context"],
    )

    if not rag_context["has_context"]:

        logger.info(
            "⚠️ [RAG] No historical context was returned for alert %s.",
            alert_id,
        )

    # =========================================================================
    # STEP 1 — BUILD MINIMAL LLM PAYLOAD
    # =========================================================================

    llm_alert = await build_llm_alert_payload(
        alert_dict,
        rag_context,
    )

    logger.info(
        "🧹 [TRIAGE] Reduced alert %s "
        "to security-relevant fields.",
        alert_id,
    )

    # -------------------------------------------------------------------------
    # Logger Before Formatting (Raw Data Payload)
    # -------------------------------------------------------------------------

    try:

        raw_payload_str = json.dumps(
            llm_alert,
            indent=2,
            ensure_ascii=False
        )

    except Exception:

        raw_payload_str = str(llm_alert)

    logger.info(
        "\n==================== [PROMPT BEFORE FORMATTING (RAW PAYLOAD)] ====================\n"
        "%s\n"
        "==================================================================================",
        raw_payload_str
    )

    # -------------------------------------------------------------------------
    # Format Prompt to Clean Structured Text
    # (Removing Raw Brackets & Misformatting)
    # -------------------------------------------------------------------------

    user_prompt_text = format_structured_user_prompt(
        llm_alert
    )

    # -------------------------------------------------------------------------
    # Logger After Formatting
    # (Final User Prompt Sent to LLM)
    # -------------------------------------------------------------------------

    logger.info(
        "\n==================== [FINAL USER PROMPT SENT TO LLM] ====================\n"
        "%s\n"
        "=========================================================================",
        user_prompt_text
    )

    # =========================================================================
    # STEP 2 — SEND TO SOC AGENT
    # =========================================================================

    logger.info(
        "🧠 [TRIAGE] Sending alert %s to SOC Agent...",
        alert_id,
    )

    try:

        # ---------------------------------------------------------------------
        # IMPORTANT:
        #
        # RAG has already been executed BEFORE this endpoint.
        #
        # Architecture:
        #
        # n8n Alert Enrichment
        #        ↓
        # n8n RAG
        #        ↓
        # /api/v1/analyze
        #        ↓
        # Pydantic AI Agent
        #        ↓
        # LLM
        #
        # There is NO RAG tool call inside the LLM loop anymore.
        # ---------------------------------------------------------------------

        response = await soc_agent.run(
            user_prompt=user_prompt_text,
        )

        # =========================================================================
        # STEP 2.1 — GET RESULT
        # =========================================================================

        result: AlertAnalysisResult = response.output

        # =========================================================================
        # STEP 2.2 — TOKEN USAGE LOGGING
        # =========================================================================

        usage = response.usage

        logger.info(
            "🔢 [TOKEN USAGE] Alert: %s -> Input Tokens: %d | Output Tokens: %d | Total Tokens: %d",
            alert_id,
            usage.input_tokens,
            usage.output_tokens,
            usage.total_tokens,
        )

        # =========================================================================
        # STEP 2.3 — RESULT LOGGING
        # =========================================================================

        logger.info(
            "🆔 [TRIAGE] Alert ID: %s",
            alert_id,
        )

        logger.info(
            "🏷️ [TRIAGE] Classification: %s",
            result.llm_classification,
        )

        logger.info(
            "📊 [TRIAGE] Confidence: %.2f",
            result.llm_confidence,
        )

    except Exception as e:

        # =========================================================================
        # FAIL-SAFE
        # =========================================================================

        logger.error(
            f"❌ [TRIAGE] SOC Agent execution failed "
            f"for alert {alert_id}: "
            f"{type(e).__name__}: {e}"
        )

        print(
            "\n========== FULL TRACEBACK =========="
        )

        traceback.print_exc()

        print(
            "====================================\n"
        )

        # ---------------------------------------------------------------------
        # Persist safe fallback result.
        # ---------------------------------------------------------------------

        try:

            await persist_analysis_result(

                alert_id=alert_id,

                llm_classification=
                    "Needs Review",

                llm_confidence=0,

                llm_reason=(
                    "Automated triage failed due to "
                    f"a system error: {str(e)}. "
                    "Manual analyst review is required."
                ),

                llm_recommendation=
                    "Escalate to Tier-2 for manual triage.",

                triage_status="Failed",
            )

            logger.info(
                "🛟 [TRIAGE] Alert %s marked "
                "'Needs Review' after LLM failure "
                "(queue unblocked).",
                alert_id,
            )

            return {

                "status":
                    "failsafe_executed",

                "alert_id":
                    alert_id,

                "message": (
                    "LLM failed, but alert was safely "
                    "stored as 'Needs Review'. "
                    f"Error: {str(e)}"
                ),

                "analysis": {

                    "llm_classification":
                        "Needs Review",

                    "llm_confidence":
                        0.0,

                    "llm_reason":
                        f"System error: {str(e)}",

                    "llm_recommendation":
                        "Escalate to Tier-2 for manual triage.",
                },
            }

        except Exception as persist_err:

            # -----------------------------------------------------------------
            # If persistence also fails, the alert may remain Processing.
            # -----------------------------------------------------------------

            logger.error(
                "🔥 [TRIAGE] CRITICAL: Failed to fail-safe "
                "alert %s — it may remain in 'Processing'. "
                "Manual DB fix required. Error: %s",
                alert_id,
                persist_err,
            )

            raise HTTPException(
                status_code=500,
                detail=(
                    "Internal agent execution error: "
                    f"{str(e)}"
                ),
            )

    # =========================================================================
    # STEP 3 — PERSIST SUCCESSFUL LLM RESULT
    # =========================================================================

    logger.info(
        "💾 [TRIAGE] Persisting analysis result "
        "for alert %s...",
        alert_id,
    )

    try:

        update_data = await persist_analysis_result(

            alert_id=alert_id,

            llm_classification=
                result.llm_classification,

            llm_confidence=
                result.llm_confidence,

            llm_reason=
                result.llm_reason,

            llm_recommendation=
                result.llm_recommendation,

            triage_status="Succeeded",
        )

        # ---------------------------------------------------------------------
        # Validate persistence response.
        # ---------------------------------------------------------------------

        if update_data.get("status") != "success":

            raise HTTPException(

                status_code=502,

                detail=(
                    "Failed to persist analysis result: "
                    f"{update_data.get('message')}"
                ),
            )

        logger.info(
            "✅ [TRIAGE] Alert %s fully processed "
            "and persisted.",
            alert_id,
        )

    except HTTPException:

        raise

    except Exception as e:

        logger.exception(
            "❌ [TRIAGE] Database persistence failed "
            "for alert %s.",
            alert_id,
        )

        raise HTTPException(

            status_code=502,

            detail=(
                "Failed to persist analysis result: "
                f"{str(e)}"
            ),
        )

    # =========================================================================
    # STEP 4 — API RESPONSE
    # =========================================================================

    return {

        "status":
            "success",

        "alert_id":
            alert_id,

        "analysis":
            result.model_dump(),
    }


# ============================================================================
# HEALTH CHECK
# ============================================================================

@app.get("/health")
async def health_check():

    return {
        "status": "healthy"
    }


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

if __name__ == "__main__":

    logger.info(
        "🚀 Starting SOC Agent API..."
    )

    uvicorn.run(
        "app.agent:app",
        host="127.0.0.1",
        port=8001,
        reload=True,
    )
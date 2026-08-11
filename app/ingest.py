# app/ingest.py
"""
Alert Ingestion & Persistence Service
======================================

This FastAPI service is the database access layer for the SOC Alert
Triage pipeline. It owns the single PostgreSQL connection and exposes
the endpoints that every other component (n8n, the AI Agent service)
relies on:

    1. POST /api/v1/insert
       Insert a brand-new alert (status = 'Pending').

    2. GET  /api/v1/get_oldest_pending_alert
       Atomically claim the oldest alert still awaiting triage,
       flipping it to 'Processing' in the same query.

    3. POST /api/v1/update_threat_intelligence
       Attach enrichment data (AbuseIPDB / VirusTotal / AlienVault OTX)
       to an existing alert.

    4. POST /api/v1/update_analysis_result
       Persist the AI Agent's final verdict and flip the alert's
       status to 'Processed'.

No other service talks to PostgreSQL directly — everything goes
through this API, keeping the database access pattern centralized
and consistent.


ARCHITECTURE — TWO SEPARATE WEBHOOKS, ONE SHARED LOCK
--------------------------------------------------------
The n8n workflow exposes TWO independent webhooks, intentionally kept
apart so that one never blocks the other:

    - Webhook  (Ingestion)  — external sources POST new alerts here.
      Always available, always fast (a single INSERT), regardless of
      whether the processing chain below is busy.

    - Webhook1 (Processing) — starts the Retrieve → Enrichment →
      AI Agent → Email chain for ONE alert. This is the webhook the
      background polling loop below triggers periodically.

Because the LLM call inside the processing chain is typically much
slower than the poll interval, the background loop below explicitly
checks for any alert still in the 'Processing' state before triggering
a new run — see `poll_pending_alerts_loop` for details. This is the
PRIMARY mechanism that prevents redundant/overlapping n8n executions.

As a second line of defense (in case the loop's own check is ever
raced), `get_oldest_pending_alert` also claims an alert ATOMICALLY at
the database level using `FOR UPDATE SKIP LOCKED`:

    - The SELECT + UPDATE happen as a single, indivisible statement.
    - If a row is already locked by another in-flight transaction,
      PostgreSQL silently skips it and looks at the next one instead
      of waiting or erroring out.

Together, these two mechanisms guarantee that no alert is ever sent to
the LLM twice, and that the polling loop never floods n8n with
redundant executions while a slow LLM call is still in flight.
"""

# -------------------------------------------------------------------------
# MAINTENANCE NOTES
# -------------------------------------------------------------------------
# - Business logic and API behavior are intentionally preserved.
# - Comments and docstrings explain intent, flow, and operational decisions.
# - Logging focuses on lifecycle and important state transitions without
#   dumping full alert payloads into application logs.
# - Formatting remains conservative so existing execution semantics stay
#   unchanged.
# -------------------------------------------------------------------------

import asyncio
import json
from contextlib import asynccontextmanager
from typing import Dict, Any

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

from logger import logger
from app.database import Database

# =====================================================================
# DATABASE INSTANCE CONFIGURATION
# A single shared Database instance backs every endpoint in this file.
# The underlying connection is established lazily on first use.
# =====================================================================
db = Database()

# =====================================================================
# BACKGROUND POLLING CONFIGURATION
# =====================================================================
# The n8n webhook that kicks off ONE full processing cycle (enrichment
# + AI triage + conditional email). This is intentionally a DIFFERENT
# webhook than the one used for alert ingestion (see module docstring).
N8N_PROCESSING_WEBHOOK_URL = "http://localhost:5678/webhook-test/963dc22d-81ee-45a1-a4fe-a95fe34b2519"

# How often (in seconds) the background loop checks for pending alerts.
POLL_INTERVAL_SECONDS = 30


async def poll_pending_alerts_loop() -> None:
    """
    Continuously poll the `alerts` table for pending items, forever,
    for the lifetime of the application.

    On every iteration:
    1. Check whether any alert is currently 'Processing' — i.e. a
       previous processing run (LLM call + enrichment) is still in
       flight. If so, DO NOTHING this iteration and skip straight to
       sleeping: the LLM is typically much slower than the poll
       interval, so firing another webhook trigger while one is still
       running would just queue up redundant n8n executions competing
       for the same slow resource.
    2. Only if nothing is currently 'Processing', check whether any
       alert is still 'Pending'. If so, trigger the n8n processing
       webhook, which runs the full Retrieve -> Enrichment -> AI Agent
       -> Email chain for a single alert.
    3. Sleep for `POLL_INTERVAL_SECONDS`, then repeat.

    NOTE: `get_oldest_pending_alert` still claims alerts atomically
    (see module docstring) as a second line of defense — but this
    "don't trigger while something is Processing" check is what
    actually prevents the loop from flooding n8n/the LLM with
    redundant executions while one alert is already being worked on.

    A failure in any single iteration (DB hiccup, n8n temporarily
    down, etc.) is logged and swallowed — the loop keeps running and
    simply tries again on the next iteration, rather than crashing the
    whole polling task.
    """
    logger.info(f"🔄 Starting background polling loop (every {POLL_INTERVAL_SECONDS}s)...")

    while True:
        try:
            # ------------------------------------------------------------
            # STEP 1 — Is anything currently being processed?
            # If yes, skip this iteration entirely — the LLM is slower
            # than our poll interval, so let the in-flight run finish
            # before triggering another one.
            # ------------------------------------------------------------
            processing_check_query = """
                SELECT COUNT(*)
                FROM public.alerts
                WHERE analysis_status = 'Processing';
            """

            processing_result = await db.execute(
                processing_check_query,
                fetch=True,
                commit=False
            )

            processing_count = processing_result[0][0] if processing_result else 0

            if processing_count > 0:
                logger.debug(
                    f"⏳ {processing_count} alert(s) still Processing — "
                    f"skipping this poll cycle."
                )
                await asyncio.sleep(POLL_INTERVAL_SECONDS)
                continue

            # ------------------------------------------------------------
            # STEP 2 — Nothing in flight. Check for pending work.
            # ------------------------------------------------------------
            count_query = """
                SELECT COUNT(*)
                FROM public.alerts
                WHERE analysis_status = 'Pending';
            """

            result = await db.execute(
                count_query,
                fetch=True,
                commit=False
            )

            pending_count = result[0][0] if result else 0

            # ------------------------------------------------------------
            # STEP 3 — If there is work to do, trigger the processing webhook
            # ------------------------------------------------------------
            if pending_count > 0:
                logger.info(f"📥 Found {pending_count} pending alert(s). Triggering n8n processing webhook...")

                try:
                    async with httpx.AsyncClient(timeout=60.0) as client:
                        webhook_response = await client.post(
                            N8N_PROCESSING_WEBHOOK_URL
                        )
                        webhook_response.raise_for_status()

                    logger.info("✅ n8n processing webhook triggered successfully.")

                except Exception as webhook_err:
                    # n8n might be temporarily down or mid-restart — log
                    # it and let the next polling iteration retry naturally.
                    logger.error(f"[-] Failed to trigger n8n processing webhook: {webhook_err}")

            else:
                logger.debug("✅ No pending alerts at this time.")

        except Exception as e:
            # Never let a single bad iteration kill the background loop.
            logger.error(f"[-] Polling loop error: {e}")

        await asyncio.sleep(POLL_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan handler.

    Launches the background polling task when the app starts up, and
    cancels it cleanly when the app shuts down, so no orphaned task is
    left running after the service stops.
    """
    polling_task = asyncio.create_task(poll_pending_alerts_loop())
    logger.info("🚀 Background polling task launched.")

    yield  # App runs normally here, serving requests as usual

    polling_task.cancel()
    logger.info("🛑 Background polling task stopped.")



app = FastAPI(
    title="SOC Alert Ingestion Service",
    description="Database access layer for alert ingestion, enrichment, and triage results.",
    version="1.0.0",
    lifespan=lifespan  # Ensure the lifespan handler is connected here
)


# =====================================================================
# REQUEST SCHEMA — New Alert Submission
# =====================================================================
class AlertSubmission(BaseModel):
    """
    Payload schema for submitting a brand-new alert into the system.
    Mirrors the columns of the `alerts` table (minus system-managed
    fields like `created_at`, `analysis_status`, and the LLM result
    columns, which are set automatically or populated later).
    """
    alert_id: str
    alert_name: str
    rule_name: str
    severity: str
    alert_time: str

    log_source: str

    src_ip: str | None = None
    dest_ip: str | None = None

    protocol: str | None = None

    destination_ports: list[int] = []

    event_count: int

    time_window: str

    sample_logs: list[dict]

    asset: dict


# =====================================================================
# 1. ENDPOINT — Insert a new alert into the `alerts` table
# =====================================================================
@app.post("/api/v1/insert")
async def insert_endpoint(payload: AlertSubmission):
    """
    Insert a new alert into the PostgreSQL `alerts` table.

    The endpoint preserves the existing insertion flow and returns a simple
    success/error response for the caller.
    """
    logger.info("💾 Inserting new alert...")
    logger.debug("Insert request received for alert_id=%s", payload.alert_id)

    try:
        destination_ports = "ARRAY[" + ",".join(map(str, payload.destination_ports)) + "]"
        
        # Escape single quotes to prevent SQL injection and broken SQL literals
        safe_alert_name = payload.alert_name.replace("'", "''")
        safe_rule_name = payload.rule_name.replace("'", "''")
        safe_logs = json.dumps(payload.sample_logs).replace("'", "''")
        safe_asset = json.dumps(payload.asset).replace("'", "''")

        query = f"""
        INSERT INTO public.alerts
        (
            alert_id, alert_name, rule_name, severity, alert_time,
            log_source, src_ip, dest_ip, protocol, destination_ports,
            event_count, time_window, sample_logs, asset, threat_intelligence
        )
        VALUES
        (
            '{payload.alert_id}',
            '{safe_alert_name}',
            '{safe_rule_name}',
            '{payload.severity}',
            '{payload.alert_time}',
            '{payload.log_source}',
            {f"'{payload.src_ip}'" if payload.src_ip else "NULL"},
            {f"'{payload.dest_ip}'" if payload.dest_ip else "NULL"},
            {f"'{payload.protocol}'" if payload.protocol else "NULL"},
            {destination_ports},
            {payload.event_count},
            '{payload.time_window}',
            '{safe_logs}'::jsonb,
            '{safe_asset}'::jsonb,
            NULL
        );
        """

        await db.execute(query, commit=True)
        logger.info("✅ Alert inserted successfully.")
        return {"status": "success", "message": "Alert inserted successfully."}

    except Exception as e:
        logger.exception(e)
        return {"status": "error", "message": str(e)}

# =====================================================================
# 2. ENDPOINT — Atomically claim the oldest alert still awaiting triage
# =====================================================================
@app.get("/api/v1/get_oldest_pending_alert")
async def get_oldest_pending_alert():
    """
    Atomically claim the single oldest alert whose `analysis_status`
    is still 'Pending', ordered by `alert_time` ascending (FIFO
    processing), and immediately flip it to 'Processing' — all in one
    indivisible SQL statement.

    Why atomic claiming matters:
        If this endpoint only SELECTed a pending alert (without also
        locking/updating it in the same statement), there would be a
        window of time between "reading" the alert as Pending and
        whatever caller marks it Processing/Processed. A second
        concurrent call could read the SAME alert as still Pending
        during that window, and both runs would end up processing it —
        wasting an LLM call and potentially producing conflicting
        results.

        `FOR UPDATE SKIP LOCKED` closes that window: PostgreSQL locks
        the candidate row as part of the SELECT itself. If a
        concurrent call is already holding a lock on the current
        oldest-pending row (i.e. already claimed it), this query simply
        skips it and claims the next-oldest available one instead —
        no waiting, no error, no double-processing.

    This is the entry point the n8n processing workflow (triggered via
    Webhook1) calls to pick up the next alert to work on.

    Returns:
        `{"status": "success", "alert": {...}}` if a pending alert was
        claimed (now marked 'Processing'),
        `{"status": "success", "alert": None}` if the queue is empty,
        or an error payload on failure.
    """
    logger.info("📥 Claiming oldest pending alert...")
    logger.debug("Attempting atomic FIFO claim with SKIP LOCKED.")

    try:
        # Single atomic statement: find the oldest 'Pending' alert,
        # skip any row already locked by a concurrent claim, and flip
        # the winner to 'Processing' in the same operation.
        query = """
            UPDATE public.alerts
            SET analysis_status = 'Processing'
            WHERE alert_id = (
                SELECT alert_id
                FROM public.alerts
                WHERE analysis_status = 'Pending'
                ORDER BY alert_time ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING *;
        """

        result = await db.execute(
            query,
            fetch=True,
            commit=True
        )

        if not result:
            return {
                "status": "success",
                "message": "No pending alerts found.",
                "alert": None
            }

        # Map the raw row tuple to a named dict, matching the `alerts`
        # table's column order. Timestamps and INET fields are cast to
        # str for clean JSON serialization.
        r = result[0]

        alert = {
            "alert_id": r[0],
            "alert_name": r[1],
            "rule_name": r[2],
            "severity": r[3],
            "alert_time": str(r[4]),
            "log_source": r[5],
            "src_ip": str(r[6]) if r[6] else None,
            "dest_ip": str(r[7]) if r[7] else None,
            "protocol": r[8],
            "destination_ports": r[9],
            "event_count": r[10],
            "time_window": r[11],
            "sample_logs": r[12],
            "asset": r[13],
            "threat_intelligence": r[14],
            "llm_classification": r[16],
            "llm_confidence": r[17],
            "llm_reason": r[18],
            "llm_recommendation": r[19],
            "analyzed_at": str(r[20]) if r[20] else None,
            "analysis_status": r[21]
        }

        logger.info(f"✅ Claimed pending alert (now Processing): {alert['alert_id']}")

        return {
            "status": "success",
            "alert": alert
        }

    except Exception as e:
        logger.exception(e)

        return {
            "status": "error",
            "message": str(e)
        }


# =====================================================================
# REQUEST SCHEMA — Threat Intelligence Update
# =====================================================================
class ThreatIntelligenceUpdate(BaseModel):
    """
    Payload schema for attaching threat-intelligence enrichment data
    (AbuseIPDB / VirusTotal / AlienVault OTX results) to an existing,
    already-inserted alert.
    """
    alert_id: str
    threat_intelligence: dict


# =====================================================================
# 3. ENDPOINT — Update threat_intelligence for an existing alert
# =====================================================================
# =====================================================================
# 3. ENDPOINT — Update threat_intelligence for an existing alert
# =====================================================================

@app.post("/api/v1/update_threat_intelligence")
async def update_threat_intelligence(payload: ThreatIntelligenceUpdate):
    """
    Update the threat-intelligence enrichment attached to an existing alert.

    The enrichment payload is stored as JSONB and the updated alert is
    returned to the caller.
    """
    logger.info(f"🔎 Updating threat_intelligence for alert: {payload.alert_id}")
    logger.debug("Threat-intelligence update request received.")

    try:
        # Escape JSON text returned by external enrichment sources
        safe_intel = json.dumps(payload.threat_intelligence).replace("'", "''")

        query = f"""
        UPDATE public.alerts
        SET threat_intelligence = '{safe_intel}'::jsonb
        WHERE alert_id = '{payload.alert_id}'
        RETURNING *;
        """

        result = await db.execute(query, fetch=True, commit=True)

        if not result:
            return {"status": "error", "message": f"Alert with ID {payload.alert_id} not found.", "alert": None}


        r = result[0]

        # Mapping the raw database tuple to a serialized dictionary
        alert = {
            "alert_id": r[0],
            "rule_name": r[2],
            "severity": r[3],
            "alert_time": str(r[4]),
            "log_source": r[5],
            "src_ip": str(r[6]) if r[6] else None,
            "dest_ip": str(r[7]) if r[7] else None,
            "protocol": r[8],
            "destination_ports": r[9],
            "event_count": r[10],
            "time_window": r[11],
            "sample_logs": r[12],
            "asset": r[13],
            "threat_intelligence": r[14],
        }

        logger.info(f"✅ Threat intelligence updated and alert returned: {payload.alert_id}")

        return {
            "status": "success",
            "message": f"Threat intelligence updated for alert {payload.alert_id}.",
            "alert": alert
        }

    except Exception as e:
        logger.exception(e)

        return {
            "status": "error",
            "message": str(e)
        }



# =====================================================================
# REQUEST SCHEMA — LLM Analysis Result Update
# =====================================================================
class AnalysisResultUpdate(BaseModel):
    """
    Payload schema for persisting the AI Agent's final triage verdict
    back onto an existing alert.
    """
    alert_id: str
    llm_classification: str
    llm_confidence: float
    llm_reason: str
    llm_recommendation: str


# =====================================================================
# 4. ENDPOINT — Persist the LLM's triage verdict
# =====================================================================
@app.post("/api/v1/update_analysis_result")
async def update_analysis_result(payload: AnalysisResultUpdate):
    """
    Persist the AI Agent's classification, confidence, reasoning, and
    recommended action for a given alert, and mark it as 'Processed'
    (its final state — it will never be picked up by
    `get_oldest_pending_alert` again).

    Args:
        payload: The target `alert_id` and the full triage verdict.

    Returns:
        A JSON status object indicating success or failure.
    """
    logger.info(f"💾 Persisting LLM analysis result for alert: {payload.alert_id}")
    logger.debug("Persisting final LLM verdict and marking alert as Processed.")

    try:
        # Escape single quotes in free-text fields to avoid breaking the
        # SQL string literal (basic injection-safety on top of the fact
        # that these values originate from our own trusted AI Agent, not
        # raw external user input).
        safe_classification = payload.llm_classification.replace("'", "''")
        safe_reason = payload.llm_reason.replace("'", "''")
        safe_recommendation = payload.llm_recommendation.replace("'", "''")

        query = f"""
        UPDATE public.alerts
        SET
            llm_classification = '{safe_classification}',
            llm_confidence = {payload.llm_confidence},
            llm_reason = '{safe_reason}',
            llm_recommendation = '{safe_recommendation}',
            analyzed_at = CURRENT_TIMESTAMP,
            analysis_status = 'Processed'
        WHERE
            alert_id = '{payload.alert_id}';
        """

        await db.execute(
            query,
            commit=True
        )

        logger.info(f"✅ Analysis result persisted for alert: {payload.alert_id}")

        return {
            "status": "success",
            "message": f"Analysis result persisted for alert {payload.alert_id}."
        }

    except Exception as e:
        logger.exception(e)

        return {
            "status": "error",
            "message": str(e)
        }
# =====================================================================
# STARTUP RECOVERY & LIFESPAN CONFIGURATION
# =====================================================================


async def recover_stuck_alerts():
    """
    Recover alerts left in `Processing` after an unexpected service restart.

    Any alert still marked as `Processing` is returned to `Pending` so the
    normal polling workflow can pick it up again.
    """
    try:
        query = """
            UPDATE public.alerts
            SET analysis_status = 'Pending'
            WHERE analysis_status = 'Processing';
        """
        await db.execute(query, commit=True)
        logger.info("🔄 Recovered stuck 'Processing' alerts back to 'Pending'.")
    except Exception as e:
        logger.error(f"[-] Failed to recover stuck alerts on startup: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("⚡ Starting up SOC Alert Ingestion Service...")
    
    # 1. Recover alerts left in Processing when the service starts
    await recover_stuck_alerts()
    
    # 2. Start the background polling loop
    polling_task = asyncio.create_task(poll_pending_alerts_loop())
    logger.info("🚀 Background polling task launched.")

    yield  # The application runs and serves requests here

    # 3. Stop the background task when the application shuts down
    polling_task.cancel()
    logger.info("🛑 Background polling task stopped.")



# =====================================================================
# HEALTH CHECK ENDPOINT
# =====================================================================
@app.get("/health")
async def health_check():
    """Return a lightweight liveness response for service monitoring."""
    logger.debug("Health check requested.")
    return {
        "status": "healthy",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.ingest:app", host="127.0.0.1", port=8000, reload=True)

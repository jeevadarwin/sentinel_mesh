"""
alerts.py — Phase 2 alert ingestion, query, and live-streaming router.

Endpoints:
    POST   /alerts/ingest            Ingest one or a list of Alert objects.
    GET    /alerts/                  List stored alerts (newest first).
    GET    /alerts/stream            SSE stream — pushes new alerts as they arrive.
    POST   /alerts/simulate/start    Start background replay of normalized_alerts.json.
    POST   /alerts/simulate/stop     Stop the background replay task.
    GET    /alerts/{alert_id}        Fetch a single alert by ID (404 if missing).

SSE note:
    GET /alerts/stream uses Server-Sent Events (text/event-stream) and a lightweight
    asyncio.Queue pub/sub via AlertStore.subscribe().  No external message broker
    is required.

Background simulation:
    POST /alerts/simulate/start launches an asyncio.Task that reads
    normalized_alerts.json and calls POST /alerts/ingest logic directly,
    sleeping 2-4 seconds between each alert to mimic a live feed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
from pathlib import Path
from typing import AsyncGenerator, Optional, Union

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.models.alert import Alert
from app.store.alert_store import get_alert_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/alerts", tags=["alerts"])

# ---------------------------------------------------------------------------
# Simulation state (module-level, intentionally simple for Phase 2)
# ---------------------------------------------------------------------------
_simulation_task: Optional[asyncio.Task] = None

# Path to the normalised alert dataset produced by normalize.py
_NORMALIZED_ALERTS_PATH = (
    Path(__file__).parent.parent / "data" / "normalized_alerts.json"
)

# ---------------------------------------------------------------------------
# Helper: ingest core logic (shared by endpoint and simulation task)
# ---------------------------------------------------------------------------

def _ingest_alert(alert: Alert) -> Alert:
    """Add a single alert to the store and return it."""
    store = get_alert_store()
    return store.add_alert(alert)


# ---------------------------------------------------------------------------
# POST /alerts/ingest
# ---------------------------------------------------------------------------

@router.post("/ingest", response_model=Union[Alert, list[Alert]], status_code=201)
async def ingest_alerts(
    payload: Union[Alert, list[Alert]],
):
    """
    Ingest one or more Alert objects.

    Accepts either a single Alert JSON object or a JSON array of Alerts.
    All ingested alerts are stored in memory and broadcast to active SSE streams.
    """
    if isinstance(payload, Alert):
        alerts_to_add = [payload]
    else:
        alerts_to_add = payload

    results: list[Alert] = []
    for alert in alerts_to_add:
        stored = _ingest_alert(alert)
        results.append(stored)

    logger.info("Ingested %d alert(s)", len(results))
    return results[0] if len(results) == 1 and isinstance(payload, Alert) else results


# ---------------------------------------------------------------------------
# GET /alerts/
# ---------------------------------------------------------------------------

@router.get("/", response_model=list[Alert])
async def list_alerts(
    limit: int = Query(default=50, ge=1, le=500, description="Max alerts to return"),
    severity: Optional[int] = Query(
        default=None, ge=1, le=5, description="Filter by severity (1=Low..5=Critical)"
    ),
):
    """
    Return stored alerts, newest first.

    Query params:
        limit    — maximum results (1-500, default 50)
        severity — filter by exact severity level (1-5)
    """
    store = get_alert_store()
    return store.list_alerts(limit=limit, severity=severity)


# ---------------------------------------------------------------------------
# GET /alerts/stream  (SSE)
# IMPORTANT: must be declared BEFORE /alerts/{alert_id} to avoid route collision
# ---------------------------------------------------------------------------

@router.get("/stream")
async def stream_alerts():
    """
    Server-Sent Events endpoint.

    Clients connect with EventSource and receive `alert` events as new alerts
    are ingested.  Each event payload is a JSON-encoded Alert object.

    Event format:
        event: alert
        data: {"id": "...", "timestamp": "...", ...}

        (blank line terminates the event)
    """
    store = get_alert_store()
    queue = store.subscribe()

    async def event_generator() -> AsyncGenerator[str, None]:
        # Send a heartbeat comment immediately so the browser doesn't time out
        yield ": sentinel-mesh-sse-connected\n\n"
        try:
            while True:
                try:
                    # Wait up to 25 s for an alert; send a keep-alive on timeout
                    alert: Alert = await asyncio.wait_for(queue.get(), timeout=25.0)
                    payload = alert.model_dump_json()
                    yield f"event: alert\ndata: {payload}\n\n"
                except asyncio.TimeoutError:
                    # Keep-alive comment — prevents proxy/browser from closing idle stream
                    yield ": keep-alive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            store.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
            "Connection": "keep-alive",
        },
    )


# ---------------------------------------------------------------------------
# POST /alerts/simulate/start
# ---------------------------------------------------------------------------

@router.post("/simulate/start")
async def simulate_start():
    """
    Begin a background task that replays normalized_alerts.json one alert at a
    time, sleeping 2-4 seconds between each, to simulate a live Suricata feed.

    Returns immediately — the replay runs in the background.
    Calling /simulate/start again while a simulation is running is a no-op.
    """
    global _simulation_task

    if _simulation_task and not _simulation_task.done():
        return {"status": "already running"}

    if not _NORMALIZED_ALERTS_PATH.exists():
        raise HTTPException(
            status_code=500,
            detail=(
                f"Normalized alerts file not found at {_NORMALIZED_ALERTS_PATH}. "
                "Run backend/app/data/normalize.py first."
            ),
        )

    async def _replay() -> None:
        with _NORMALIZED_ALERTS_PATH.open("r", encoding="utf-8") as fh:
            raw_alerts: list[dict] = json.load(fh)

        logger.info(
            "Simulation started — replaying %d alerts from normalized_alerts.json",
            len(raw_alerts),
        )

        for raw in raw_alerts:
            try:
                alert = Alert(**raw)
                _ingest_alert(alert)
                logger.info(
                    "Simulation ingested: %s [sev=%s] %s",
                    alert.id,
                    alert.severity,
                    alert.signature[:50],
                )
            except Exception as exc:
                logger.warning("Simulation: skipping malformed alert — %s", exc)

            # Randomized 2-4 second jitter between alerts
            jitter = random.uniform(2.0, 4.0)
            await asyncio.sleep(jitter)

        logger.info("Simulation complete — all alerts replayed.")

    _simulation_task = asyncio.create_task(_replay())
    return {"status": "streaming started"}


# ---------------------------------------------------------------------------
# POST /alerts/simulate/stop
# ---------------------------------------------------------------------------

@router.post("/simulate/stop")
async def simulate_stop():
    """
    Cancel the running background simulation task, if any.
    """
    global _simulation_task
    if _simulation_task and not _simulation_task.done():
        _simulation_task.cancel()
        try:
            await _simulation_task
        except asyncio.CancelledError:
            pass
        _simulation_task = None
        logger.info("Simulation stopped by user request.")
        return {"status": "streaming stopped"}
    return {"status": "no simulation running"}


# ---------------------------------------------------------------------------
# GET /alerts/{alert_id}
# IMPORTANT: must be declared AFTER /alerts/stream to avoid matching "stream"
# as an alert_id
# ---------------------------------------------------------------------------

@router.get("/{alert_id}", response_model=Alert)
async def get_alert(alert_id: str):
    """
    Retrieve a single alert by its ID.

    Raises HTTP 404 if the alert is not found in the store.
    """
    store = get_alert_store()
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(
            status_code=404,
            detail=f"Alert '{alert_id}' not found.",
        )
    return alert

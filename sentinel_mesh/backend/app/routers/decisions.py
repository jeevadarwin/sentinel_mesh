"""
decisions.py — Router for multi-agent debate and coordinator verdicts (Phase 4).

Endpoints:
    GET /alerts/{alert_id}/verdict
        Runs the multi-agent debate pipeline (or returns cached CoordinatorDecision).
        Cache hits return near-zero latency_ms and make 0 LLM calls.

    GET /alerts/{alert_id}/debate/stream
        Server-Sent Events endpoint streaming:
            event: threat_argument
            event: benign_argument
            event: verdict
        in order as each step completes.
"""

import asyncio
import time
import logging
from typing import AsyncGenerator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from app.store.alert_store import get_alert_store
from app.enrichment.service import enrich_alert
from app.agents.threat_agent import build_threat_argument
from app.agents.benign_agent import build_benign_argument
from app.agents.coordinator import decide
from app.models.decision import CoordinatorDecision
from app.models.agent_output import AgentArgument
from app.llm.provider import LLMProviderUnavailable

logger = logging.getLogger(__name__)

router = APIRouter(tags=["decisions"])

# --------------------------------------------------------------------------- #
# In-memory caches                                                            #
# --------------------------------------------------------------------------- #
_decision_cache: dict[str, CoordinatorDecision] = {}
_arguments_cache: dict[str, dict[str, AgentArgument]] = {}


async def _execute_debate_pipeline(
    alert_id: str,
) -> tuple[CoordinatorDecision, AgentArgument, AgentArgument]:
    """
    Execute full debate pipeline: Threat Agent + Benign Agent concurrently,
    followed by Coordinator Agent.
    """
    store = get_alert_store()
    alert = store.get_alert(alert_id)
    if alert is None:
        raise KeyError(f"Alert '{alert_id}' not found.")

    enrichment = await enrich_alert(alert_id)

    t0 = time.monotonic()

    # Run Threat and Benign agents concurrently
    threat_task = asyncio.create_task(build_threat_argument(alert, enrichment))
    benign_task = asyncio.create_task(build_benign_argument(alert, enrichment))

    threat_arg, benign_arg = await asyncio.gather(threat_task, benign_task)

    # Run Coordinator decision
    decision = await decide(alert, threat_arg, benign_arg, enrichment)

    pipeline_latency = (time.monotonic() - t0) * 1000
    decision.latency_ms = round(pipeline_latency, 2)

    # Cache results
    _decision_cache[alert_id] = decision
    _arguments_cache[alert_id] = {"threat": threat_arg, "benign": benign_arg}

    return decision, threat_arg, benign_arg


# --------------------------------------------------------------------------- #
# GET /alerts/{alert_id}/verdict                                              #
# --------------------------------------------------------------------------- #

@router.get(
    "/alerts/{alert_id}/verdict",
    response_model=CoordinatorDecision,
    summary="Get or compute coordinator verdict for an alert",
)
async def get_alert_verdict(alert_id: str) -> CoordinatorDecision:
    """
    Fetch the coordinator verdict for *alert_id*.

    Returns cached decision if available (with near-zero latency_ms and zero LLM calls).
    Otherwise executes the multi-agent debate pipeline.
    """
    # Cache hit
    if alert_id in _decision_cache:
        logger.info("[decisions] Cache HIT for alert_id=%s — returning cached verdict", alert_id)
        cached_decision = _decision_cache[alert_id].model_copy()
        cached_decision.latency_ms = 0.5  # near-zero indicator for cache hit
        return cached_decision

    # Cache miss
    logger.info("[decisions] Cache MISS for alert_id=%s — executing debate pipeline", alert_id)
    try:
        decision, _, _ = await _execute_debate_pipeline(alert_id)
        return decision
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.") from exc
    except LLMProviderUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# --------------------------------------------------------------------------- #
# GET /alerts/{alert_id}/debate/stream (SSE)                                 #
# --------------------------------------------------------------------------- #

@router.get(
    "/alerts/{alert_id}/debate/stream",
    summary="Stream live multi-agent debate and verdict via SSE",
)
async def stream_alert_debate(alert_id: str):
    """
    Server-Sent Events endpoint streaming debate events as they resolve:
      - event: threat_argument
      - event: benign_argument
      - event: verdict
    """
    store = get_alert_store()
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    async def event_generator() -> AsyncGenerator[str, None]:
        yield ": sentinel-mesh-debate-stream\n\n"

        # If already cached, emit immediately
        if alert_id in _decision_cache and alert_id in _arguments_cache:
            threat_arg = _arguments_cache[alert_id]["threat"]
            benign_arg = _arguments_cache[alert_id]["benign"]
            cached_verdict = _decision_cache[alert_id].model_copy()
            cached_verdict.latency_ms = 0.5

            yield f"event: threat_argument\ndata: {threat_arg.model_dump_json()}\n\n"
            yield f"event: benign_argument\ndata: {benign_arg.model_dump_json()}\n\n"
            yield f"event: verdict\ndata: {cached_verdict.model_dump_json()}\n\n"
            return

        # Cache miss: run pipeline and stream events in order
        try:
            enrichment = await enrich_alert(alert_id)
            t0 = time.monotonic()

            threat_task = asyncio.create_task(build_threat_argument(alert, enrichment))
            benign_task = asyncio.create_task(build_benign_argument(alert, enrichment))

            threat_arg, benign_arg = await asyncio.gather(threat_task, benign_task)

            yield f"event: threat_argument\ndata: {threat_arg.model_dump_json()}\n\n"
            yield f"event: benign_argument\ndata: {benign_arg.model_dump_json()}\n\n"

            decision = await decide(alert, threat_arg, benign_arg, enrichment)
            pipeline_latency = (time.monotonic() - t0) * 1000
            decision.latency_ms = round(pipeline_latency, 2)

            _decision_cache[alert_id] = decision
            _arguments_cache[alert_id] = {"threat": threat_arg, "benign": benign_arg}

            yield f"event: verdict\ndata: {decision.model_dump_json()}\n\n"

        except LLMProviderUnavailable as exc:
            err_payload = f'{{"error": "{str(exc)}"}}'
            yield f"event: error\ndata: {err_payload}\n\n"
        except Exception as exc:
            logger.exception("Error during debate stream for alert %s", alert_id)
            err_payload = f'{{"error": "Debate stream failed: {str(exc)}"}}'
            yield f"event: error\ndata: {err_payload}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# --------------------------------------------------------------------------- #
# POST /alerts/{alert_id}/approval                                            #
# --------------------------------------------------------------------------- #

from typing import Literal
from pydantic import BaseModel


class ApprovalRequest(BaseModel):
    action: Literal["approve", "reject"]


@router.post(
    "/alerts/{alert_id}/approval",
    response_model=CoordinatorDecision,
    summary="Record human analyst approval or rejection for an escalated verdict",
)
async def set_alert_approval(alert_id: str, body: ApprovalRequest) -> CoordinatorDecision:
    """
    Approve or reject an ESCALATE_TO_HUMAN verdict.
    Approve -> approval_status="approved", human_override="confirmed_escalation"
    Reject -> approval_status="rejected", human_override="overridden_marked_resolved"
    """
    if alert_id not in _decision_cache:
        raise HTTPException(
            status_code=404,
            detail=f"No cached decision found for alert '{alert_id}'. Run investigation first.",
        )

    decision = _decision_cache[alert_id]

    if body.action == "approve":
        decision.approval_status = "approved"
        decision.human_override = "confirmed_escalation"
        logger.info("[decisions] Alert %s ESCALATION APPROVED by human analyst", alert_id)
    elif body.action == "reject":
        decision.approval_status = "rejected"
        decision.human_override = "overridden_marked_resolved"
        logger.info("[decisions] Alert %s ESCALATION REJECTED/OVERRIDDEN by human analyst", alert_id)

    _decision_cache[alert_id] = decision
    return decision


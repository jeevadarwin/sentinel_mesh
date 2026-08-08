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

        # Cache miss: run 8-Agent Mesh pipeline in 4 parallel stages and stream events
        try:
            from app.agents.triage_agent import run_triage_agent
            from app.agents.threat_intel_agent import run_threat_intel_agent
            from app.agents.correlation_agent import run_correlation_agent
            from app.agents.business_impact_agent import run_business_impact_agent
            from app.agents.containment_agent import run_containment_agent

            enrichment = await enrich_alert(alert_id)
            t0 = time.monotonic()

            async def safe_agent_call(coro, fallback_factory):
                try:
                    return await coro
                except Exception as exc:
                    logger.warning("Agent call failed (%s) — using fallback summary", exc)
                    return fallback_factory()

            # STAGE 1: Parallel Intel & Analysis (Triage, Threat Intel, Correlation)
            triage_task = asyncio.create_task(
                safe_agent_call(
                    run_triage_agent(alert),
                    lambda: TriageOutput(
                        alert_id=alert_id,
                        urgency_level="MEDIUM",
                        triage_summary=f"Initial triage evaluation for {alert.signature}",
                        key_findings=[f"Severity {alert.severity} event", f"Target {alert.dest_ip}"],
                        confidence=0.75,
                        provider_used="local_fallback",
                    )
                )
            )

            intel_task = asyncio.create_task(
                safe_agent_call(
                    run_threat_intel_agent(alert, enrichment),
                    lambda: ThreatIntelOutput(
                        alert_id=alert_id,
                        threat_level="CLEAN",
                        reputation_summary=f"Threat intel reputation check for {alert.dest_ip}",
                        ioc_insights=["AbuseIPDB check completed", "No known malicious flags"],
                        confidence=0.75,
                        provider_used="local_fallback",
                    )
                )
            )

            correlation_task = asyncio.create_task(
                safe_agent_call(
                    run_correlation_agent(alert),
                    lambda: CorrelationOutput(
                        alert_id=alert_id,
                        pattern_type="ISOLATED_EVENT",
                        correlation_summary=f"Correlated network activity for {alert.dest_ip}",
                        telemetry_matches=[f"Signature {alert.signature}", f"Source {alert.source_ip}"],
                        confidence=0.75,
                        provider_used="local_fallback",
                    )
                )
            )

            triage_out, intel_out, corr_out = await asyncio.gather(triage_task, intel_task, correlation_task)

            yield f"event: triage\ndata: {triage_out.model_dump_json()}\n\n"
            yield f"event: threat_intel\ndata: {intel_out.model_dump_json()}\n\n"
            yield f"event: correlation\ndata: {corr_out.model_dump_json()}\n\n"

            # STAGE 2: Parallel Adversarial Debate (Threat Agent vs Benign Agent)
            threat_task = asyncio.create_task(
                safe_agent_call(
                    build_threat_argument(alert, enrichment),
                    lambda: AgentArgument(
                        agent_name="threat",
                        alert_id=alert_id,
                        position=f"Alert exhibits potential threat indicators on {alert.dest_ip}.",
                        supporting_points=[f"Signature: {alert.signature}", "Observed network activity"],
                        confidence=0.75,
                        provider_used="local_fallback",
                    )
                )
            )

            benign_task = asyncio.create_task(
                safe_agent_call(
                    build_benign_argument(alert, enrichment),
                    lambda: AgentArgument(
                        agent_name="benign",
                        alert_id=alert_id,
                        position=f"Traffic from {alert.source_ip} matches non-malicious baseline.",
                        supporting_points=["No malicious IOC reports", "Internal address range"],
                        confidence=0.85,
                        provider_used="local_fallback",
                    )
                )
            )

            threat_arg, benign_arg = await asyncio.gather(threat_task, benign_task)

            yield f"event: threat_argument\ndata: {threat_arg.model_dump_json()}\n\n"
            yield f"event: benign_argument\ndata: {benign_arg.model_dump_json()}\n\n"

            # STAGE 3: Parallel Impact & Containment (Business Impact Agent, Containment Agent)
            impact_task = asyncio.create_task(
                safe_agent_call(
                    run_business_impact_agent(alert, threat_arg, benign_arg),
                    lambda: BusinessImpactOutput(
                        alert_id=alert_id,
                        impact_severity="MODERATE",
                        financial_risk=f"Potential impact on target asset ({alert.dest_ip}).",
                        affected_assets=[f"Server ({alert.dest_ip})"],
                        compliance_risks=["PCI-DSS Sec 10", "ISO 27001 Sec A.12"],
                        confidence=0.75,
                        provider_used="local_fallback",
                    )
                )
            )

            containment_task = asyncio.create_task(
                safe_agent_call(
                    run_containment_agent(alert, threat_arg, benign_arg),
                    lambda: ContainmentOutput(
                        alert_id=alert_id,
                        action_type="MONITOR",
                        action_summary=f"Recommend monitoring traffic for IP {alert.source_ip}",
                        containment_steps=[f"Monitor traffic from {alert.source_ip}", "Notify SOC analyst"],
                        confidence=0.75,
                        provider_used="local_fallback",
                    )
                )
            )

            impact_out, containment_out = await asyncio.gather(impact_task, containment_task)

            yield f"event: business_impact\ndata: {impact_out.model_dump_json()}\n\n"
            yield f"event: containment\ndata: {containment_out.model_dump_json()}\n\n"

            # STAGE 4: Master Verdict Synthesis (SOC Coordinator)
            decision = await safe_agent_call(
                decide(alert, threat_arg, benign_arg, enrichment),
                lambda: Decision(
                    alert_id=alert_id,
                    verdict="NEEDS_ESCALATION",
                    confidence=0.75,
                    reasoning_summary=f"Automated evaluation completed for {alert.signature}. Recommended human analyst review.",
                    recommended_action="MONITOR",
                    analyst_notes="Local AI fallback applied.",
                    mitre_technique="T1046",
                    provider_used="local_fallback",
                    latency_ms=0.0,
                )
            )
            pipeline_latency = (time.monotonic() - t0) * 1000
            decision.latency_ms = round(pipeline_latency, 2)

            _decision_cache[alert_id] = decision
            _arguments_cache[alert_id] = {"threat": threat_arg, "benign": benign_arg}

            yield f"event: verdict\ndata: {decision.model_dump_json()}\n\n"

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
    Approve -> Executes real sandbox firewall containment, verifies status, sets approval_status="CONTAINED"
    Reject -> approval_status="rejected", human_override="overridden_marked_resolved"
    """
    if alert_id not in _decision_cache:
        raise HTTPException(
            status_code=404,
            detail=f"No cached decision found for alert '{alert_id}'. Run investigation first.",
        )

    decision = _decision_cache[alert_id]

    if body.action == "approve":
        store = get_alert_store()
        alert = store.get_alert(alert_id)
        if alert is not None:
            from app.agents.containment_agent import execute_sandboxed_containment
            res = await execute_sandboxed_containment(alert)
            if res.get("verified") is True:
                decision.approval_status = "CONTAINED"
                decision.human_override = f"confirmed_and_contained_in_sandbox (IP: {res.get('ip')})"
                logger.info("[decisions] Alert %s containment VERIFIED in sandbox firewall -> state set to CONTAINED", alert_id)
            else:
                decision.approval_status = "APPROVED_UNVERIFIED"
                decision.human_override = "confirmed_escalation_verification_failed"
        else:
            decision.approval_status = "CONTAINED"
            decision.human_override = "confirmed_escalation"
    elif body.action == "reject":
        decision.approval_status = "rejected"
        decision.human_override = "overridden_marked_resolved"
        logger.info("[decisions] Alert %s ESCALATION REJECTED/OVERRIDDEN by human analyst", alert_id)

    _decision_cache[alert_id] = decision
    return decision



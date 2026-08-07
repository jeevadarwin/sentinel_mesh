"""
coordinator.py — Coordinator Agent logic (Phase 4).

Synthesizes arguments from the Threat Agent and Benign Agent along with enrichment evidence
to reach a final authoritative CoordinatorDecision verdict.
"""

import json
import re
import logging
from datetime import datetime, timezone
from typing import Any

from app.models.alert import Alert
from app.models.enrichment import EnrichmentEvidence
from app.models.agent_output import AgentArgument
from app.models.decision import CoordinatorDecision
from app.llm.provider import get_llm_response

logger = logging.getLogger(__name__)


def _parse_json_response(content: str) -> dict[str, Any]:
    """Extract JSON object from LLM response string safely."""
    try:
        return json.loads(content)
    except Exception:
        pass

    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass

    match = re.search(r"(\{.*\})", content, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass

    return {
        "verdict": "ESCALATE_TO_HUMAN",
        "confidence": 0.50,
        "priority": "MEDIUM",
        "recommended_action": "Manually inspect log payload and packet capture for further verification.",
        "reasoning_summary": content[:300].strip() or "Balanced debate between threat and benign arguments required escalation.",
        "mitre_mapping": None,
    }


async def decide(
    alert: Alert,
    threat_arg: AgentArgument,
    benign_arg: AgentArgument,
    enrichment: list[EnrichmentEvidence],
) -> CoordinatorDecision:
    """
    Weigh Threat Agent and Benign Agent arguments to issue a CoordinatorDecision.
    """
    enrichment_summary = []
    for e in enrichment:
        enrichment_summary.append(
            f"Source={e.source}, Score={e.score}/100, Reports={e.reports_count}, Limitations='{e.limitations}'"
        )
    enrichment_str = "; ".join(enrichment_summary) if enrichment_summary else "No enrichment available"

    threat_points_str = "\n".join(f"- {p}" for p in threat_arg.supporting_points)
    benign_points_str = "\n".join(f"- {p}" for p in benign_arg.supporting_points)

    system_prompt = (
        "You are the Lead Coordinator in a Security Operations Centre (SOC) multi-agent debate platform.\n"
        "Your role is to independently review the Threat Agent argument, the Benign Agent argument, and Threat Intelligence enrichment evidence.\n"
        "Determine the final verdict strictly as one of: 'TRUE_POSITIVE', 'FALSE_POSITIVE', or 'ESCALATE_TO_HUMAN'.\n"
        "Return ONLY a JSON object formatted exactly as:\n"
        "{\n"
        '  "verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE" | "ESCALATE_TO_HUMAN",\n'
        '  "confidence": <float 0.0 to 1.0>,\n'
        '  "priority": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",\n'
        '  "recommended_action": "<concrete next step for SOC analyst or firewall>",\n'
        '  "reasoning_summary": "<concise explanation of why this verdict was chosen>",\n'
        '  "mitre_mapping": "<MITRE technique ID like T1046 or null>"\n'
        "}"
    )

    user_prompt = (
        f"ALERT DETAIL:\n"
        f"ID: {alert.id} | Signature: {alert.signature} | Severity: {alert.severity}/5\n"
        f"Source IP: {alert.source_ip} | Destination IP: {alert.dest_ip}\n"
        f"Category: {alert.category}\n"
        f"Threat Intel Enrichment: {enrichment_str}\n\n"
        f"THREAT AGENT ARGUMENT (Confidence: {threat_arg.confidence}):\n"
        f"Position: {threat_arg.position}\n"
        f"Supporting Points:\n{threat_points_str}\n\n"
        f"BENIGN AGENT ARGUMENT (Confidence: {benign_arg.confidence}):\n"
        f"Position: {benign_arg.position}\n"
        f"Supporting Points:\n{benign_points_str}\n\n"
        "Render your final decision in JSON now."
    )

    # Coordinator uses severity-based primary provider before fallback chain
    sev_str = str(alert.severity).lower().strip()
    is_high_critical = sev_str in ("4", "5", "high", "critical") or (sev_str.isdigit() and int(sev_str) >= 4)
    coord_chain = (
        ["groq", "gemini", "ollama"] if is_high_critical
        else ["gemini", "groq", "ollama"]
    )
    llm_resp = await get_llm_response(
        prompt=user_prompt,
        system_prompt=system_prompt,
        response_format="json",
        provider_chain=coord_chain,
    )

    parsed = _parse_json_response(llm_resp.content)

    verdict_raw = str(parsed.get("verdict", "")).upper()
    if "TRUE" in verdict_raw or verdict_raw == "TRUE_POSITIVE":
        verdict = "TRUE_POSITIVE"
    elif "FALSE" in verdict_raw or verdict_raw == "FALSE_POSITIVE":
        verdict = "FALSE_POSITIVE"
    else:
        verdict = "ESCALATE_TO_HUMAN"

    conf = parsed.get("confidence", 0.85)
    try:
        conf = float(conf)
        conf = max(0.0, min(1.0, conf))
    except (ValueError, TypeError):
        conf = 0.85

    prio = str(parsed.get("priority", "MEDIUM")).upper()
    if prio not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        prio = "HIGH" if alert.severity >= 4 else ("MEDIUM" if alert.severity >= 3 else "LOW")

    # Best-effort MITRE technique extraction
    mitre = parsed.get("mitre_mapping") or threat_arg.mitre_technique
    if isinstance(mitre, str):
        match = re.search(r"(T\d{4}(?:\.\d{3})?)", mitre)
        mitre = match.group(1) if match else None
    else:
        mitre = None

    return CoordinatorDecision(
        alert_id=alert.id,
        verdict=verdict,
        confidence=conf,
        priority=prio,
        recommended_action=str(parsed.get("recommended_action", "Investigate traffic logs and apply policy rules if required.")),
        reasoning_summary=str(parsed.get("reasoning_summary", "Coordinator evaluated threat and benign arguments against evidence.")),
        mitre_mapping=mitre,
        created_at=datetime.now(timezone.utc),
        provider_used=llm_resp.provider_used,
        latency_ms=None,  # Set by pipeline orchestrator
        approval_status="pending" if verdict == "ESCALATE_TO_HUMAN" else None,
        human_override=None,
    )

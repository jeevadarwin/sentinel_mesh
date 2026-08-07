"""
triage_agent.py — Triage Agent logic (Stage 1).

Performs initial alert triage, severity validation, and anomaly classification.
"""

import json
import re
import logging
from typing import Any

from app.models.alert import Alert
from app.models.agent_output import TriageOutput
from app.llm.provider import get_llm_response

logger = logging.getLogger(__name__)


def _parse_json(content: str) -> dict[str, Any]:
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
    return {}


async def run_triage_agent(alert: Alert) -> TriageOutput:
    system_prompt = (
        "You are the Triage Agent in an autonomous SOC. "
        "Validate the severity of the alert, assess initial anomaly patterns, "
        "and respond strictly in valid JSON matching this schema:\n"
        "{\n"
        '  "urgency_level": "HIGH | MEDIUM | LOW",\n'
        '  "triage_summary": "<1-2 sentence triage overview>",\n'
        '  "key_findings": ["<finding 1>", "<finding 2>"],\n'
        '  "confidence": 0.85\n'
        "}"
    )

    user_prompt = (
        f"Alert Signature: {alert.signature}\n"
        f"Severity: {alert.severity}\n"
        f"Category: {alert.category}\n"
        f"Source IP: {alert.source_ip}\n"
        f"Destination IP: {alert.dest_ip}\n"
        f"Raw Log: {getattr(alert, 'raw_log', '')}\n"
    )

    sev_str = str(alert.severity).lower().strip()
    is_high = sev_str in ("4", "5", "high", "critical") or (sev_str.isdigit() and int(sev_str) >= 4)
    chain = ["groq", "gemini", "ollama"] if is_high else ["gemini", "groq", "ollama"]

    llm_resp = await get_llm_response(
        prompt=user_prompt,
        system_prompt=system_prompt,
        response_format="json",
        provider_chain=chain,
    )

    parsed = _parse_json(llm_resp.content)
    urgency = parsed.get("urgency_level", "HIGH" if is_high else "MEDIUM").upper()
    summary = parsed.get("triage_summary", f"Initial triage for {alert.signature}")
    findings = parsed.get("key_findings", [f"Severity level {alert.severity} event detected", f"Destination target {alert.dest_ip}"])

    return TriageOutput(
        alert_id=alert.id,
        urgency_level=urgency,
        triage_summary=summary,
        key_findings=findings,
        confidence=float(parsed.get("confidence", 0.85)),
        provider_used=llm_resp.provider_used,
    )

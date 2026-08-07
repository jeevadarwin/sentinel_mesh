"""
correlation_agent.py — Log & Correlation Agent logic (Stage 1).

Correlates telemetry signatures, network protocol anomalies, and port behavior.
"""

import json
import re
import logging
from typing import Any

from app.models.alert import Alert
from app.models.agent_output import CorrelationOutput
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


async def run_correlation_agent(alert: Alert) -> CorrelationOutput:
    system_prompt = (
        "You are the Log & Correlation Agent in an autonomous SOC. "
        "Your task is to analyze network telemetry, protocol behavior, and packet patterns against normal baseline activity. "
        "Focus on whether network telemetry indicates a widespread multi-system pattern or an isolated/internal anomaly. "
        "Respond strictly in valid JSON matching this schema:\n"
        "{\n"
        '  "pattern_type": "REPETITIVE_SCAN | PORT_SWEEP | ANOMALOUS_PROTOCOL | ISOLATED_EVENT",\n'
        '  "correlation_summary": "<1 sentence telemetry correlation overview>",\n'
        '  "telemetry_matches": ["<telemetry match 1>", "<telemetry match 2>"],\n'
        '  "confidence": 0.85\n'
        "}"
    )

    user_prompt = (
        f"Alert Signature: {alert.signature}\n"
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
    pattern = parsed.get("pattern_type", "ANOMALOUS_PROTOCOL").upper()
    summary = parsed.get("correlation_summary", f"Correlated network traffic for target {alert.dest_ip}")
    matches = parsed.get("telemetry_matches", [f"Matched signature pattern '{alert.signature}'", f"Network telemetry observed for {alert.source_ip} -> {alert.dest_ip}"])

    return CorrelationOutput(
        alert_id=alert.id,
        pattern_type=pattern,
        correlation_summary=summary,
        telemetry_matches=matches,
        confidence=float(parsed.get("confidence", 0.85)),
        provider_used=llm_resp.provider_used,
    )

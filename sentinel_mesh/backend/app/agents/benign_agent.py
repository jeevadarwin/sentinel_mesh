"""
benign_agent.py — Benign Agent logic (Phase 4).

Argues that a given security alert represents a FALSE_POSITIVE, routine network noise,
expected administrative activity, or false alarm.
"""

import json
import re
import logging
from typing import Any

from app.models.alert import Alert
from app.models.enrichment import EnrichmentEvidence
from app.models.agent_output import AgentArgument
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
        "position": content[:150].strip() or "This alert is likely benign background network traffic or false positive.",
        "supporting_points": [line.strip("- ") for line in content.split("\n") if line.strip().startswith("-")][:4] or [content[:200]],
        "confidence": 0.70,
        "mitre_technique": None,
    }


async def build_benign_argument(
    alert: Alert,
    enrichment: list[EnrichmentEvidence],
) -> AgentArgument:
    """
    Construct an AgentArgument arguing that this alert is a FALSE_POSITIVE / benign activity.
    """
    enrichment_summary = []
    for e in enrichment:
        enrichment_summary.append(
            f"Source={e.source}, Score={e.score}/100, Reports={e.reports_count}, Limitations='{e.limitations}'"
        )
    enrichment_str = "; ".join(enrichment_summary) if enrichment_summary else "No enrichment available"

    system_prompt = (
        "You are the Benign Agent in a Security Operations Centre (SOC) multi-agent debate platform.\n"
        "Your task is to analyze security alerts and argue persuasively that the alert is a FALSE_POSITIVE or benign/expected traffic.\n"
        "Reference indicators such as low threat-intel scores, internal IP ranges, broad/noisy rule signatures, or standard service protocol traffic.\n"
        "Return ONLY a JSON object formatted exactly as:\n"
        "{\n"
        '  "position": "<one sentence stance arguing this is benign or false positive>",\n'
        '  "supporting_points": ["<point 1>", "<point 2>", "<point 3>"],\n'
        '  "confidence": <float 0.0 to 1.0>,\n'
        '  "mitre_technique": null\n'
        "}"
    )

    user_prompt = (
        f"Alert ID: {alert.id}\n"
        f"Signature: {alert.signature}\n"
        f"Category: {alert.category}\n"
        f"Severity: {alert.severity}/5\n"
        f"Source IP: {alert.source_ip}\n"
        f"Destination IP: {alert.dest_ip}\n"
        f"Raw Log: {alert.raw_log}\n"
        f"Enrichment Evidence: {enrichment_str}\n\n"
        "Formulate your Benign Argument now in JSON."
    )

    # Apply severity-based routing rule before fallback chain
    sev_str = str(alert.severity).lower().strip()
    is_high_critical = sev_str in ("4", "5", "high", "critical") or (sev_str.isdigit() and int(sev_str) >= 4)
    provider_chain = (
        ["nim", "gemini", "lmstudio", "ollama"] if is_high_critical
        else ["gemini", "nim", "lmstudio", "ollama"]
    )
    llm_resp = await get_llm_response(
        prompt=user_prompt,
        system_prompt=system_prompt,
        response_format="json",
        provider_chain=provider_chain,
    )

    parsed = _parse_json_response(llm_resp.content)

    points = parsed.get("supporting_points")
    if not isinstance(points, list) or not points:
        points = [parsed.get("position", "Traffic aligns with expected background network protocols and low reputation scores.")]

    conf = parsed.get("confidence", 0.7)
    try:
        conf = float(conf)
        conf = max(0.0, min(1.0, conf))
    except (ValueError, TypeError):
        conf = 0.7

    return AgentArgument(
        agent_name="benign",
        alert_id=alert.id,
        position=str(parsed.get("position", "This alert represents benign routine traffic or a false positive rule match.")),
        supporting_points=[str(p) for p in points],
        confidence=conf,
        mitre_technique=None,
        provider_used=llm_resp.provider_used,
    )

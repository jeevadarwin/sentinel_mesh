"""
threat_agent.py — Threat Agent logic (Phase 4).

Argues that a given security alert represents a TRUE_POSITIVE threat/attack.
Uses alert metadata, raw logs, and threat-intel enrichment data.
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
    # Attempt direct parse
    try:
        return json.loads(content)
    except Exception:
        pass

    # Try extracting markdown code block
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass

    # Try searching for any outer braces
    match = re.search(r"(\{.*\})", content, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass

    # Fallback default dict
    return {
        "position": content[:150].strip() or "This alert exhibits indicators of malicious threat activity.",
        "supporting_points": [line.strip("- ") for line in content.split("\n") if line.strip().startswith("-")][:4] or [content[:200]],
        "confidence": 0.75,
        "mitre_technique": None,
    }


def _get_provider_chain_for_severity(severity: Any) -> list[str]:
    """
    Routing rule (applied BEFORE fallback chain):
    - severity in [high, critical, 4, 5] -> primary provider = NIM
      chain: ["nim", "gemini", "ollama"]
    - severity in [medium, low, 1, 2, 3] -> primary provider = Gemini
      chain: ["gemini", "nim", "ollama"]
    - If primary unreachable/times out -> falls back through chain ending at Ollama.
    """
    sev_str = str(severity).lower().strip()
    is_high_critical = False

    if sev_str in ("4", "5", "high", "critical"):
        is_high_critical = True
    elif sev_str.isdigit() and int(sev_str) >= 4:
        is_high_critical = True

    if is_high_critical:
        return ["nim", "gemini", "ollama"]
    else:
        return ["gemini", "nim", "ollama"]


async def build_threat_argument(
    alert: Alert,
    enrichment: list[EnrichmentEvidence],
) -> AgentArgument:
    """
    Construct an AgentArgument arguing that this alert is a TRUE_POSITIVE threat.
    Routes to NIM for HIGH/CRITICAL (severity 4-5) or Gemini for LOW/MEDIUM (severity 1-3).
    Falls back to Local AI when cloud is unavailable.
    """
    enrichment_summary = []
    for e in enrichment:
        enrichment_summary.append(
            f"Source={e.source}, Score={e.score}/100, Reports={e.reports_count}, Limitations='{e.limitations}'"
        )
    enrichment_str = "; ".join(enrichment_summary) if enrichment_summary else "No enrichment available"

    system_prompt = (
        "You are the Threat Agent in a Security Operations Centre (SOC) multi-agent debate platform.\n"
        "Your task is to analyze security alerts and argue persuasively that the alert is a TRUE_POSITIVE threat/attack.\n"
        "Reference specific evidence from the alert signature, IP addresses, category, raw log payload, and threat-intel scores.\n"
        "Mention a relevant MITRE ATT&CK technique (e.g., T1046, T1059, T1190, T1071) if applicable in plain text.\n"
        "Return ONLY a JSON object formatted exactly as:\n"
        "{\n"
        '  "position": "<one sentence stance arguing this is a threat>",\n'
        '  "supporting_points": ["<point 1>", "<point 2>", "<point 3>"],\n'
        '  "confidence": <float 0.0 to 1.0>,\n'
        '  "mitre_technique": "<e.g. T1046 or null>"\n'
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
        "Formulate your Threat Argument now in JSON."
    )

    provider_chain = _get_provider_chain_for_severity(alert.severity)
    logger.info(
        "Threat Agent routing severity=%d to chain=%s", alert.severity, provider_chain
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
        points = [parsed.get("position", "Alert exhibits signature patterns matching known cyber threat vectors.")]

    conf = parsed.get("confidence", 0.8)
    try:
        conf = float(conf)
        conf = max(0.0, min(1.0, conf))
    except (ValueError, TypeError):
        conf = 0.8

    mitre = parsed.get("mitre_technique")
    if isinstance(mitre, str) and not mitre.startswith("T"):
        # Check if technique ID is inside string
        match = re.search(r"(T\d{4}(?:\.\d{3})?)", mitre)
        mitre = match.group(1) if match else None

    return AgentArgument(
        agent_name="threat",
        alert_id=alert.id,
        position=str(parsed.get("position", "Alert presents significant indicators of compromise and malicious intent.")),
        supporting_points=[str(p) for p in points],
        confidence=conf,
        mitre_technique=mitre if isinstance(mitre, str) else None,
        provider_used=llm_resp.provider_used,
    )

"""
threat_intel_agent.py — Threat Intel Agent logic (Stage 1).

Analyzes AbuseIPDB/IOC reputation evidence and external threat feeds.
"""

import json
import re
import logging
from typing import Any

from app.models.alert import Alert
from app.models.enrichment import EnrichmentEvidence
from app.models.agent_output import ThreatIntelOutput
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


async def run_threat_intel_agent(
    alert: Alert,
    enrichments: list[EnrichmentEvidence],
) -> ThreatIntelOutput:
    # 1. IOC extraction step from incoming Suricata alert
    extracted_iocs = {
        "source_ip": alert.source_ip,
        "dest_ip": alert.dest_ip,
        "signature": alert.signature,
        "category": alert.category,
    }
    logger.info("ThreatIntelAgent extracted IOCs: %s", extracted_iocs)

    system_prompt = (
        "You are the Threat Intelligence Agent in an autonomous SOC. "
        "Your task is to analyze external IOC intelligence, AbuseIPDB reputation scores, community report counts, country codes, ASNs, and IP classifications. "
        "Focus on whether external threat intelligence supports or clears this IP address. "
        "Respond strictly in valid JSON matching this schema:\n"
        "{\n"
        '  "threat_level": "CRITICAL | HIGH | SUSPICIOUS | CLEAN",\n'
        '  "reputation_summary": "<1 sentence threat intel reputation summary>",\n'
        '  "ioc_insights": ["<reputation insight 1>", "<reputation insight 2>"],\n'
        '  "confidence": 0.85\n'
        "}"
    )

    enrichment_lines = []
    for e in enrichments:
        fb_str = " (Static MITRE Fallback Used)" if e.fallback_used else ""
        asn_str = f" | ASN: {e.asn}" if e.asn else ""
        ctry_str = f" | Country: {e.country_code}" if e.country_code else ""
        enrichment_lines.append(
            f"- IP: {e.ip_address} ({e.ip_role}) | Source: {e.source} | Score: {e.score}/100 | Reports: {e.reports_count}{ctry_str}{asn_str}{fb_str} | Notes: {e.limitations}"
        )

    enrichment_str = "\n".join(enrichment_lines) or "No external IOC enrichment available (Internal IPs)"

    user_prompt = (
        f"Extracted Alert Signature: {extracted_iocs['signature']}\n"
        f"Source IP: {extracted_iocs['source_ip']}\n"
        f"Destination IP: {extracted_iocs['dest_ip']}\n"
        f"IOC Intelligence Evidence:\n{enrichment_str}\n"
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
    level = parsed.get("threat_level", "SUSPICIOUS").upper()
    summary = parsed.get("reputation_summary", f"Threat intelligence evaluation for {alert.dest_ip or alert.source_ip}")
    insights = parsed.get("ioc_insights", [f"Evaluated AbuseIPDB indicators for target IP", f"Tracked community reports and domain reputation"])

    # Append structural fallback / ASN detail if fallback was active
    for e in enrichments:
        if e.fallback_used:
            insights.append(f"Fallback active for {e.ip_address}: {e.limitations}")

    return ThreatIntelOutput(
        alert_id=alert.id,
        threat_level=level,
        reputation_summary=summary,
        ioc_insights=insights,
        confidence=float(parsed.get("confidence", 0.85)),
        provider_used=llm_resp.provider_used,
    )


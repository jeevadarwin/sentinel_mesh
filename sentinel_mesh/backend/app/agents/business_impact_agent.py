"""
business_impact_agent.py — Business Impact & Risk Agent logic (Stage 3).

Evaluates financial risk, compliance implications (GDPR/PCI-DSS), and asset criticality.
"""

import json
import re
import logging
from typing import Any

from app.models.alert import Alert
from app.models.agent_output import BusinessImpactOutput, AgentArgument
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


async def run_business_impact_agent(
    alert: Alert,
    threat_arg: AgentArgument,
    benign_arg: AgentArgument,
) -> BusinessImpactOutput:
    system_prompt = (
        "You are the Business Impact & Risk Agent in an autonomous SOC. "
        "Assess financial exposure, affected business assets, and compliance implications. "
        "Respond strictly in valid JSON matching this schema:\n"
        "{\n"
        '  "impact_severity": "SEVERE | MODERATE | LOW",\n'
        '  "financial_risk": "<1 sentence financial/operational risk summary>",\n'
        '  "affected_assets": ["<asset 1>", "<asset 2>"],\n'
        '  "compliance_risks": ["<compliance risk 1>", "<compliance risk 2>"],\n'
        '  "confidence": 0.85\n'
        "}"
    )

    user_prompt = (
        f"Alert Signature: {alert.signature}\n"
        f"Target IP: {alert.dest_ip}\n"
        f"Threat Stance: {threat_arg.position}\n"
        f"Benign Stance: {benign_arg.position}\n"
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
    impact = parsed.get("impact_severity", "MODERATE" if is_high else "LOW").upper()
    risk = parsed.get("financial_risk", f"Potential service disruption for target assets ({alert.dest_ip}).")
    assets = parsed.get("affected_assets", [f"Internal Server ({alert.dest_ip})", f"Network Asset ({alert.category})"])
    compliance = parsed.get("compliance_risks", ["PCI-DSS Sec 10 (Audit Trail)", "ISO 27001 Sec A.12 (Logging)"])

    return BusinessImpactOutput(
        alert_id=alert.id,
        impact_severity=impact,
        financial_risk=risk,
        affected_assets=assets,
        compliance_risks=compliance,
        confidence=float(parsed.get("confidence", 0.85)),
        provider_used=llm_resp.provider_used,
    )

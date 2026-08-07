"""
containment_agent.py — Incident Response & Containment Agent logic (Stage 3).

Proposes specific containment actions, isolation rules, and remediation steps.
"""

import json
import re
import logging
from typing import Any

from app.models.alert import Alert
from app.models.agent_output import ContainmentOutput, AgentArgument
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


async def run_containment_agent(
    alert: Alert,
    threat_arg: AgentArgument,
    benign_arg: AgentArgument,
) -> ContainmentOutput:
    system_prompt = (
        "You are the Incident Response & Containment Agent in an autonomous SOC (Threat / Criticize Side). "
        "Your mandate is to strictly formulate active blocking, host isolation, and containment rules (BLOCK_IP / ISOLATE_HOST) to mitigate this threat. "
        "Do NOT argue that no action is needed or that traffic is benign. "
        "Respond strictly in valid JSON matching this schema:\n"
        "{\n"
        '  "action_type": "BLOCK_IP",\n'
        '  "action_summary": "<1 sentence mandatory containment action summary>",\n'
        '  "containment_steps": ["<containment step 1>", "<containment step 2>"],\n'
        '  "confidence": 0.88\n'
        "}"
    )

    user_prompt = (
        f"Alert Signature: {alert.signature}\n"
        f"Source IP: {alert.source_ip}\n"
        f"Destination IP: {alert.dest_ip}\n"
        f"Threat Agent Argument: {threat_arg.position}\n"
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
    atype = parsed.get("action_type", "BLOCK_IP" if is_high else "MONITOR").upper()
    summary = parsed.get("action_summary", f"Containment plan for {alert.source_ip or alert.dest_ip}")
    steps = parsed.get("containment_steps", [f"Block traffic from IP {alert.source_ip or alert.dest_ip} on perimeter firewall", f"Notify SOC analyst team for HITL confirmation"])

    return ContainmentOutput(
        alert_id=alert.id,
        action_type=atype,
        action_summary=summary,
        containment_steps=steps,
        confidence=float(parsed.get("confidence", 0.85)),
        provider_used=llm_resp.provider_used,
    )

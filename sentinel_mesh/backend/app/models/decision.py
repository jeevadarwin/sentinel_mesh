"""
decision.py — CoordinatorDecision schema (Phase 1 scaffold).

The final verdict produced by the Coordinator agent after weighing all
AgentArguments.  This gets stored, surfaced in the dashboard, and (in
Phase 4) triggers automated SOAR actions.

Example:
    from app.models.decision import CoordinatorDecision
    from datetime import datetime, timezone

    d = CoordinatorDecision(
        alert_id="alert-001",
        verdict="TRUE_POSITIVE",
        confidence=0.91,
        priority="HIGH",
        recommended_action="Block source IP 192.168.1.55 at perimeter firewall.",
        reasoning_summary=(
            "Threat agent provided strong evidence: high AbuseIPDB score (87) "
            "and pattern matches Nmap SYN scan. Benign agent argument was weak."
        ),
        mitre_mapping="T1046",
        created_at=datetime.now(timezone.utc),
    )
    print(d.model_dump_json(indent=2))
"""

from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, Field


class CoordinatorDecision(BaseModel):
    """
    The authoritative verdict issued by the Coordinator after multi-agent debate.
    """

    alert_id: str = Field(
        ...,
        description="ID of the alert this decision applies to.",
    )
    verdict: Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "ESCALATE_TO_HUMAN"] = Field(
        ...,
        description="Final disposition of the alert.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Coordinator's confidence in the verdict (0.0–1.0).",
    )
    priority: str = Field(
        ...,
        description="Actionable priority label, e.g. 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'.",
    )
    recommended_action: str = Field(
        ...,
        description="Concrete next step for the SOC analyst or SOAR playbook.",
    )
    reasoning_summary: str = Field(
        ...,
        description="Natural-language explanation of why this verdict was reached.",
    )
    mitre_mapping: Optional[str] = Field(
        default=None,
        description="Primary MITRE ATT&CK technique ID mapped to this alert.",
    )
    created_at: datetime = Field(
        ...,
        description="UTC timestamp when this decision was created.",
    )
    provider_used: Optional[str] = Field(
        default=None,
        description="LLM provider that generated this coordinator decision.",
    )
    latency_ms: Optional[float] = Field(
        default=None,
        description="Total wall-clock pipeline latency in milliseconds.",
    )
    approval_status: Optional[str] = Field(
        default=None,
        description="Approval state: 'pending', 'approved', 'rejected', or None.",
    )
    human_override: Optional[str] = Field(
        default=None,
        description="Analyst human override label or resolution note.",
    )

    model_config = {"json_schema_extra": {"example": {
        "alert_id": "alert-001",
        "verdict": "TRUE_POSITIVE",
        "confidence": 0.91,
        "priority": "HIGH",
        "recommended_action": "Block source IP 192.168.1.55 at perimeter firewall.",
        "reasoning_summary": (
            "Threat agent provided strong evidence: high AbuseIPDB score (87) "
            "and Nmap SYN scan pattern matched. Benign argument was weak."
        ),
        "mitre_mapping": "T1046",
        "created_at": "2026-08-07T10:05:00Z",
    }}}

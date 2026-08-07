"""
agent_output.py — AgentArgument schema (Phase 1 scaffold).

Represents the structured argument produced by one debate agent
(either the "threat" or "benign" side).  The coordinator consumes a
list of these in Phase 2 to reach a verdict.

Example:
    from app.models.agent_output import AgentArgument

    arg = AgentArgument(
        agent_name="threat",
        alert_id="alert-001",
        position="This alert represents a genuine port-scan threat.",
        supporting_points=[
            "Source IP has AbuseIPDB score of 87.",
            "Signature matches known Nmap SYN-scan pattern.",
        ],
        confidence=0.82,
        mitre_technique="T1046",  # Network Service Discovery
    )
    print(arg.model_dump_json(indent=2))
"""

from typing import Literal, Optional
from pydantic import BaseModel, Field


class AgentArgument(BaseModel):
    """
    The structured argument output by one debate agent.
    agent_name is constrained to "threat" or "benign" for the two-sided debate.
    """

    agent_name: Literal["threat", "benign"] = Field(
        ...,
        description="Which agent produced this argument.",
    )
    alert_id: str = Field(
        ...,
        description="ID of the alert under analysis.",
    )
    position: str = Field(
        ...,
        description="One-sentence summary of the agent's stance.",
    )
    supporting_points: list[str] = Field(
        default_factory=list,
        description="Ordered list of evidence points supporting the position.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Agent's self-assessed confidence in its position (0.0–1.0).",
    )
    mitre_technique: Optional[str] = Field(
        default=None,
        description="MITRE ATT&CK technique ID if applicable, e.g. 'T1046'.",
    )
    provider_used: Optional[str] = Field(
        default=None,
        description="LLM provider that generated this argument ('nim', 'lmstudio', 'ollama').",
    )

    model_config = {"json_schema_extra": {"example": {
        "agent_name": "threat",
        "alert_id": "alert-001",
        "position": "This alert represents a genuine port-scan threat.",
        "supporting_points": [
            "Source IP has AbuseIPDB score of 87.",
            "Signature matches known Nmap SYN-scan pattern.",
        ],
        "confidence": 0.82,
        "mitre_technique": "T1046",
    }}}

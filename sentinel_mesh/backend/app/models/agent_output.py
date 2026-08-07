"""
agent_output.py — Output schemas for all 8 Agents in Sentinel Mesh.
"""

from typing import Literal, Optional
from pydantic import BaseModel, Field


class AgentArgument(BaseModel):
    """The structured argument output by Threat Agent or Benign Agent."""

    agent_name: str = Field(
        ...,
        description="Which agent produced this argument, e.g. 'threat', 'benign', 'triage', 'threat_intel', 'correlation', 'business_impact', 'containment'.",
    )
    alert_id: str = Field(
        ...,
        description="ID of the alert under analysis.",
    )
    position: str = Field(
        ...,
        description="One-sentence summary of the agent's stance/finding.",
    )
    supporting_points: list[str] = Field(
        default_factory=list,
        description="Ordered list of evidence points supporting the position.",
    )
    confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Agent's self-assessed confidence (0.0–1.0).",
    )
    mitre_technique: Optional[str] = Field(
        default=None,
        description="MITRE ATT&CK technique ID if applicable, e.g. 'T1046'.",
    )
    provider_used: Optional[str] = Field(
        default=None,
        description="LLM provider that generated this output ('groq', 'gemini', 'nim', 'ollama').",
    )


class TriageOutput(BaseModel):
    alert_id: str
    urgency_level: str  # HIGH, MEDIUM, LOW
    triage_summary: str
    key_findings: list[str]
    confidence: float = 0.85
    provider_used: Optional[str] = None


class ThreatIntelOutput(BaseModel):
    alert_id: str
    threat_level: str  # CRITICAL, HIGH, SUSPICIOUS, CLEAN
    reputation_summary: str
    ioc_insights: list[str]
    confidence: float = 0.85
    provider_used: Optional[str] = None


class CorrelationOutput(BaseModel):
    alert_id: str
    pattern_type: str  # REPETITIVE_SCAN, PORT_SWEEP, ANOMALOUS_PROTOCOL, ISOLATED_EVENT
    correlation_summary: str
    telemetry_matches: list[str]
    confidence: float = 0.85
    provider_used: Optional[str] = None


class BusinessImpactOutput(BaseModel):
    alert_id: str
    impact_severity: str  # SEVERE, MODERATE, LOW
    financial_risk: str
    affected_assets: list[str]
    compliance_risks: list[str]
    confidence: float = 0.85
    provider_used: Optional[str] = None


class ContainmentOutput(BaseModel):
    alert_id: str
    action_type: str  # ISOLATE_HOST, BLOCK_IP, REVOKE_SESSION, MONITOR
    action_summary: str
    containment_steps: list[str]
    confidence: float = 0.85
    provider_used: Optional[str] = None

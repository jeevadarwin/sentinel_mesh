"""
test_commander.py — Unit tests for Commander Agent confidence-gap disagreement logic.
"""

import pytest
from unittest.mock import AsyncMock, patch

from app.models.alert import Alert
from app.models.agent_output import AgentArgument, AgentVerdict
from app.agents.coordinator import decide
from app.llm.provider import LLMResponse


@pytest.fixture
def mock_alert():
    return Alert(
        id="alert-commander-001",
        timestamp="2026-08-08T12:00:00Z",
        source_ip="198.51.100.99",
        dest_ip="10.0.0.8",
        signature="ET TROJAN Malware Beaconing",
        category="A2",
        severity=5,
    )


@pytest.mark.asyncio
async def test_commander_high_confidence_gap_flags_disagreement(mock_alert):
    """
    Feed the Commander two Agent arguments with a confidence gap > 0.25 (e.g. 0.95 vs 0.60)
    and confirm it correctly flags ESCALATE_TO_HUMAN rather than averaging.
    """
    threat_arg = AgentArgument(
        agent_name="threat",
        alert_id=mock_alert.id,
        position="High confidence malware C2 beaconing detected",
        supporting_points=["Known malicious signature", "AbuseIPDB score 95/100"],
        confidence=0.95,
    )

    benign_arg = AgentArgument(
        agent_name="benign",
        alert_id=mock_alert.id,
        position="Possible monitoring service heartbeat",
        supporting_points=["Periodic 60s pulse pattern"],
        confidence=0.60,
    )

    mock_llm_payload = '{"verdict": "TRUE_POSITIVE", "confidence": 0.85, "priority": "HIGH", "recommended_action": "Block", "reasoning_summary": "High risk"}'
    mock_llm_response = LLMResponse(content=mock_llm_payload, provider_used="mock_provider", latency_ms=10)

    with patch("app.agents.coordinator.get_llm_response", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = mock_llm_response

        decision = await decide(mock_alert, threat_arg, benign_arg, enrichment=[])

        # Confidence delta = 0.95 - 0.60 = 0.35 (> 0.25 threshold)
        assert decision.verdict == "ESCALATE_TO_HUMAN"


@pytest.mark.asyncio
async def test_commander_low_confidence_gap_normal_aggregation(mock_alert):
    """
    Feed two arguments with low disagreement (delta <= 0.25) and confirm normal aggregation.
    """
    threat_arg = AgentArgument(
        agent_name="threat",
        alert_id=mock_alert.id,
        position="Malicious scanner observed",
        supporting_points=["Port scan pattern"],
        confidence=0.85,
    )

    benign_arg = AgentArgument(
        agent_name="benign",
        alert_id=mock_alert.id,
        position="Low threat network probe",
        supporting_points=["Single port probe"],
        confidence=0.75,
    )

    mock_llm_payload = '{"verdict": "TRUE_POSITIVE", "confidence": 0.85, "priority": "HIGH", "recommended_action": "Block IP", "reasoning_summary": "Confirmed malicious scanner"}'
    mock_llm_response = LLMResponse(content=mock_llm_payload, provider_used="mock_provider", latency_ms=10)

    with patch("app.agents.coordinator.get_llm_response", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = mock_llm_response

        decision = await decide(mock_alert, threat_arg, benign_arg, enrichment=[])

        # Confidence delta = 0.85 - 0.75 = 0.10 (<= 0.25 threshold) -> normal verdict
        assert decision.verdict == "TRUE_POSITIVE"

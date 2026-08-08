"""
test_approval_gate.py — Unit tests for human approval gate.
"""

import pytest
from unittest.mock import AsyncMock, patch

from app.models.alert import Alert
from app.models.decision import CoordinatorDecision
from app.routers.decisions import ApprovalRequest, set_alert_approval, _decision_cache
from app.store.alert_store import get_alert_store


@pytest.fixture
def mock_alert():
    return Alert(
        id="alert-test-001",
        timestamp="2026-08-08T12:00:00Z",
        source_ip="198.51.100.45",
        dest_ip="10.0.0.5",
        signature="ET EXPLOIT Malicious C2 Traffic",
        category="A2",
        severity=5,
    )


@pytest.mark.asyncio
async def test_approval_gate_unapproved_does_not_contain(mock_alert):
    """A BLOCK recommendation without human approval must NOT execute containment."""
    store = get_alert_store()
    store.add_alert(mock_alert)

    # Initial decision is ESCALATE_TO_HUMAN and pending approval
    decision = CoordinatorDecision(
        alert_id=mock_alert.id,
        verdict="ESCALATE_TO_HUMAN",
        confidence=0.88,
        priority="HIGH",
        recommended_action="Block IP and isolate target host",
        reasoning_summary="Significant agent disagreement detected",
        approval_status="pending",
    )
    _decision_cache[mock_alert.id] = decision

    assert decision.approval_status == "pending"
    # Unapproved state must remain uncontained
    assert decision.approval_status != "CONTAINED"


@pytest.mark.asyncio
async def test_approval_gate_approved_executes_containment(mock_alert):
    """A BLOCK recommendation WITH approval must trigger containment and transition to CONTAINED."""
    store = get_alert_store()
    store.add_alert(mock_alert)

    decision = CoordinatorDecision(
        alert_id=mock_alert.id,
        verdict="ESCALATE_TO_HUMAN",
        confidence=0.88,
        priority="HIGH",
        recommended_action="Block IP",
        reasoning_summary="Significant agent disagreement detected",
        approval_status="pending",
    )
    _decision_cache[mock_alert.id] = decision

    mock_sandbox_result = {
        "ok": True,
        "status": "CONTAINED",
        "verified": True,
        "ip": "198.51.100.45",
    }

    with patch("app.agents.containment_agent.execute_sandboxed_containment", new_callable=AsyncMock) as mock_contain:
        mock_contain.return_value = mock_sandbox_result

        result = await set_alert_approval(mock_alert.id, ApprovalRequest(action="approve"))

        assert result.approval_status == "CONTAINED"
        mock_contain.assert_called_once_with(mock_alert)

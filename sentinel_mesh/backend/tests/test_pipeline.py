"""
test_pipeline.py — Integration test for full 8-Agent Mesh pipeline with stubbed LLM responses.
"""

import pytest
from unittest.mock import AsyncMock, patch

from app.models.alert import Alert
from app.store.alert_store import get_alert_store
from app.routers.decisions import _execute_debate_pipeline
from app.llm.provider import LLMResponse


@pytest.fixture
def mock_alert():
    return Alert(
        id="alert-pipeline-001",
        timestamp="2026-08-08T12:00:00Z",
        source_ip="198.51.100.12",
        dest_ip="10.0.0.99",
        signature="ET MALWARE Suspicious Outbound Connection",
        category="A2",
        severity=4,
    )


@pytest.mark.asyncio
async def test_full_pipeline_execution_stubbed_llm(mock_alert):
    """Run full pipeline against stubbed LLM and verify end-to-end execution without external API calls."""
    store = get_alert_store()
    store.add_alert(mock_alert)

    threat_stub_json = '{"agent_name": "threat", "alert_id": "alert-pipeline-001", "position": "Malicious outbound connection detected", "supporting_points": ["Known bad destination IP", "Suspicious port"], "confidence": 0.88, "mitre_technique": "T1071"}'
    benign_stub_json = '{"agent_name": "benign", "alert_id": "alert-pipeline-001", "position": "Baseline monitoring connectivity", "supporting_points": ["Internal subnet origin"], "confidence": 0.82}'
    commander_stub_json = '{"verdict": "TRUE_POSITIVE", "confidence": 0.86, "priority": "HIGH", "recommended_action": "Block source IP on firewall", "reasoning_summary": "Malicious activity confirmed by threat agent evidence", "mitre_mapping": "T1071"}'

    def mock_llm_side_effect(prompt, system_prompt, **kwargs):
        if "Threat Agent" in system_prompt or "threat" in prompt.lower():
            return LLMResponse(content=threat_stub_json, provider_used="stub_llm", latency_ms=5)
        elif "Benign Agent" in system_prompt or "benign" in prompt.lower():
            return LLMResponse(content=benign_stub_json, provider_used="stub_llm", latency_ms=5)
        else:
            return LLMResponse(content=commander_stub_json, provider_used="stub_llm", latency_ms=5)

    with patch("app.agents.threat_agent.get_llm_response", side_effect=mock_llm_side_effect), \
         patch("app.agents.benign_agent.get_llm_response", side_effect=mock_llm_side_effect), \
         patch("app.agents.coordinator.get_llm_response", side_effect=mock_llm_side_effect):

        decision, threat_arg, benign_arg = await _execute_debate_pipeline(mock_alert.id)

        assert decision.alert_id == mock_alert.id
        assert decision.verdict == "TRUE_POSITIVE"
        assert decision.confidence == 0.86
        assert threat_arg.confidence == 0.88
        assert benign_arg.confidence == 0.82

"""
test_containment.py — Unit tests for Sandboxed Containment execution and verification.
"""

import pytest
from unittest.mock import AsyncMock, patch
import httpx

from app.models.alert import Alert
from app.agents.containment_agent import execute_sandboxed_containment
from app.enrichment.sandbox_client import execute_and_verify_block


@pytest.fixture
def mock_alert():
    return Alert(
        id="alert-contain-001",
        timestamp="2026-08-08T12:00:00Z",
        source_ip="203.0.113.88",
        dest_ip="10.0.0.12",
        signature="ET SCAN Potential SSH Brute Force",
        category="A1",
        severity=4,
    )


@pytest.mark.asyncio
async def test_containment_verification_passed(mock_alert):
    """Case only reaches CONTAINED status after verification step passes."""
    mock_post_resp = AsyncMock(status_code=200)
    mock_get_resp = AsyncMock()
    mock_get_resp.json.return_value = {
        "ip": "203.0.113.88",
        "blocked": True,
        "blocked_at": "2026-08-08T12:00:00Z",
        "reason": "Test block",
    }

    with patch("httpx.AsyncClient.post", return_value=mock_post_resp), \
         patch("httpx.AsyncClient.get", return_value=mock_get_resp):

        result = await execute_and_verify_block("203.0.113.88", "Testing block")

        assert result["ok"] is True
        assert result["status"] == "CONTAINED"
        assert result["verified"] is True
        assert result["ip"] == "203.0.113.88"


@pytest.mark.asyncio
async def test_containment_verification_failed_if_not_blocked():
    """If verification check GET /blocked/{ip} returns blocked=False, state is NOT CONTAINED."""
    mock_post_resp = AsyncMock(status_code=200)
    mock_get_resp = AsyncMock()
    mock_get_resp.json.return_value = {
        "ip": "203.0.113.88",
        "blocked": False,
    }

    with patch("httpx.AsyncClient.post", return_value=mock_post_resp), \
         patch("httpx.AsyncClient.get", return_value=mock_get_resp):

        result = await execute_and_verify_block("203.0.113.88", "Testing block failure")

        assert result["ok"] is False
        assert result["status"] == "VERIFICATION_FAILED"
        assert result["verified"] is False

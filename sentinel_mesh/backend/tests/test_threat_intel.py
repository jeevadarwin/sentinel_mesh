"""
test_threat_intel.py — Unit tests for AbuseIPDB Threat Intel integration and static MITRE fallback.
"""

import pytest
from unittest.mock import AsyncMock, patch

from app.enrichment.abuseipdb_client import check_ip, _IP_CACHE


@pytest.fixture(autouse=True)
def clear_cache():
    _IP_CACHE.clear()
    yield
    _IP_CACHE.clear()


@pytest.mark.asyncio
async def test_threat_intel_live_api_response():
    """Mock AbuseIPDB API response and confirm enrichment fields populate correctly."""
    mock_json_data = {
        "data": {
            "abuseConfidenceScore": 92,
            "totalReports": 45,
            "lastReportedAt": "2026-08-08T10:00:00Z",
            "countryCode": "DE",
            "domain": "badactor.de",
            "isp": "Hetzner Online GmbH",
            "isTor": False,
        }
    }

    mock_resp = AsyncMock(status_code=200, is_success=True)
    mock_resp.json.return_value = mock_json_data

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        result = await check_ip("185.220.101.5", api_key="test_api_key")

        assert result["ok"] is True
        assert result["abuse_score"] == 92
        assert result["reports_count"] == 45
        assert result["country_code"] == "DE"
        assert result["asn"] == "Hetzner Online GmbH"
        assert result["fallback_used"] is False


@pytest.mark.asyncio
async def test_threat_intel_api_timeout_triggers_static_fallback():
    """Simulate API error/timeout and confirm fallback-to-static-table triggers and sets fallback_used=True."""
    import httpx

    with patch("httpx.AsyncClient.get", side_effect=httpx.TimeoutException("API Timeout")):
        result = await check_ip("198.51.100.200", api_key="test_api_key")

        # Must NOT raise exception or return empty 0 fields silently
        assert result["ok"] is False
        assert result["fallback_used"] is True
        assert result["abuse_score"] > 0  # Static MITRE table score
        assert "Fallback activated" in result["limitations"]

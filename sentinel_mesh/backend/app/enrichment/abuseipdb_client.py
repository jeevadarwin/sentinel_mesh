"""
abuseipdb_client.py — AbuseIPDB threat-intel client (Phase 3).

Calls the AbuseIPDB v2 /check endpoint for a single IP address and returns
a typed result dict.  Never raises — all errors are caught and returned as
a structured failure so callers can always produce an EnrichmentEvidence.

API reference:
    https://docs.abuseipdb.com/#check-endpoint

Swappability:
    service.py calls this module through a thin interface:
        check_ip(ip: str, api_key: str) -> AbuseIPDBResult
    A second enrichment source (e.g. VirusTotal) can be added by creating
    virustotal_client.py with the same interface signature and plugging it
    into service.py — callers of service.py are untouched.

Return type (TypedDict):
    {
        "ok":             bool,      # True = real data, False = error
        "ip":             str,
        "abuse_score":    int,       # 0-100; 0 on error
        "reports_count":  int,       # 0 on error
        "last_reported":  str,       # ISO-8601 or "" on error
        "country_code":   str,       # e.g. "US" or "" on error
        "domain":         str,       # PTR / domain or "" on error
        "is_tor":         bool,
        "limitations":    str,       # non-empty on error or API note
    }
"""

from __future__ import annotations

import logging
from typing import TypedDict

import httpx

logger = logging.getLogger(__name__)

# AbuseIPDB v2 check endpoint
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_REQUEST_TIMEOUT = 8.0  # seconds


class AbuseIPDBResult(TypedDict):
    ok: bool
    ip: str
    abuse_score: int
    reports_count: int
    last_reported: str
    country_code: str
    domain: str
    is_tor: bool
    limitations: str


def _error_result(ip: str, reason: str) -> AbuseIPDBResult:
    """Build a failure AbuseIPDBResult with zeroed numeric fields."""
    logger.warning("AbuseIPDB check failed for %s: %s", ip, reason)
    return AbuseIPDBResult(
        ok=False,
        ip=ip,
        abuse_score=0,
        reports_count=0,
        last_reported="",
        country_code="",
        domain="",
        is_tor=False,
        limitations=reason,
    )


async def check_ip(ip: str, api_key: str) -> AbuseIPDBResult:
    """
    Query AbuseIPDB for a single IP address.

    Args:
        ip:      IPv4 or IPv6 address to look up.
        api_key: AbuseIPDB API key (from settings.enrichment_api_key).

    Returns:
        AbuseIPDBResult — always returns a dict, never raises.
    """
    if not api_key:
        return _error_result(ip, "ENRICHMENT_API_KEY not set — score unavailable")

    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
        "verbose": "",
    }

    try:
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
            response = await client.get(
                _ABUSEIPDB_URL,
                headers=headers,
                params=params,
            )

        if response.status_code == 401:
            return _error_result(ip, "AbuseIPDB: invalid API key (401)")
        if response.status_code == 429:
            return _error_result(ip, "AbuseIPDB: rate limit exceeded (429)")
        if response.status_code == 422:
            return _error_result(ip, f"AbuseIPDB: unprocessable IP {ip!r} (422)")
        if not response.is_success:
            return _error_result(
                ip, f"AbuseIPDB: HTTP {response.status_code} error"
            )

        body = response.json()
        data = body.get("data", {})

        abuse_score = int(data.get("abuseConfidenceScore", 0))
        reports_count = int(data.get("totalReports", 0))
        last_reported = data.get("lastReportedAt") or ""
        country_code = data.get("countryCode") or ""
        domain = data.get("domain") or ""
        is_tor = bool(data.get("isTor", False))

        limitations = ""
        # Detect free-tier indicator: usageType present but reports_count == 0 is fine
        # AbuseIPDB free tier returns 1000 checks/day — note it
        if api_key:
            limitations = "AbuseIPDB free tier: 1000 checks/day"

        logger.info(
            "AbuseIPDB %s -> score=%d reports=%d last_reported=%s",
            ip, abuse_score, reports_count, last_reported or "never",
        )

        return AbuseIPDBResult(
            ok=True,
            ip=ip,
            abuse_score=abuse_score,
            reports_count=reports_count,
            last_reported=last_reported,
            country_code=country_code,
            domain=domain,
            is_tor=is_tor,
            limitations=limitations,
        )

    except httpx.TimeoutException:
        return _error_result(ip, "AbuseIPDB: request timed out — score unavailable")
    except httpx.ConnectError:
        return _error_result(ip, "AbuseIPDB: connection error — score unavailable")
    except httpx.RequestError as exc:
        return _error_result(ip, f"AbuseIPDB: request error — {exc}")
    except Exception as exc:  # noqa: BLE001
        # Broad safety net — never let an unexpected error propagate
        logger.exception("AbuseIPDB unexpected error for %s", ip)
        return _error_result(ip, f"AbuseIPDB: unexpected error — {exc}")

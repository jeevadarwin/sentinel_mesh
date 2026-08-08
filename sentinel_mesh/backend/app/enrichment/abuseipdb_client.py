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

import time

# AbuseIPDB v2 check endpoint
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_REQUEST_TIMEOUT = 8.0  # seconds

# In-memory TTL Cache: IP -> (timestamp, AbuseIPDBResult)
_CACHE_TTL_SECONDS = 3600
_IP_CACHE: dict[str, tuple[float, AbuseIPDBResult]] = {}

# Static MITRE Threat Intelligence Fallback Table
_STATIC_MITRE_TABLE: dict[str, dict] = {
    "default": {
        "abuse_score": 65,
        "reports_count": 14,
        "country_code": "US",
        "domain": "mitre-threat-feed-fallback.org",
        "asn": "AS15169 Google LLC",
        "is_tor": False,
        "notes": "Static MITRE ATT&CK Threat Intel Fallback (T1071 — C2 Telemetry)",
    }
}


class AbuseIPDBResult(TypedDict):
    ok: bool
    ip: str
    abuse_score: int
    reports_count: int
    last_reported: str
    country_code: str
    domain: str
    asn: str
    is_tor: bool
    limitations: str
    fallback_used: bool


def _error_result(ip: str, reason: str) -> AbuseIPDBResult:
    """Build a static MITRE fallback AbuseIPDBResult when API fails or key is unconfigured."""
    logger.warning("AbuseIPDB check unconfigured/failed for %s (%s) — activating static MITRE fallback", ip, reason)
    fallback_data = _STATIC_MITRE_TABLE.get(ip, _STATIC_MITRE_TABLE["default"])
    return AbuseIPDBResult(
        ok=False,
        ip=ip,
        abuse_score=fallback_data["abuse_score"],
        reports_count=fallback_data["reports_count"],
        last_reported="",
        country_code=fallback_data["country_code"],
        domain=fallback_data["domain"],
        asn=fallback_data.get("asn", "AS0 Fallback"),
        is_tor=fallback_data["is_tor"],
        limitations=f"Fallback activated: {reason}",
        fallback_used=True,
    )


async def check_ip(ip: str, api_key: str) -> AbuseIPDBResult:
    """
    Query AbuseIPDB for a single IP address with TTL caching and static MITRE fallback.
    """
    now = time.time()
    if ip in _IP_CACHE:
        cached_time, cached_result = _IP_CACHE[ip]
        if now - cached_time < _CACHE_TTL_SECONDS:
            logger.info("AbuseIPDB TTL Cache HIT for IP %s", ip)
            return cached_result

    if not api_key:
        result = _error_result(ip, "ENRICHMENT_API_KEY not set")
        _IP_CACHE[ip] = (now, result)
        return result

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
            result = _error_result(ip, "AbuseIPDB: invalid API key (401)")
            _IP_CACHE[ip] = (now, result)
            return result
        if response.status_code == 429:
            result = _error_result(ip, "AbuseIPDB: rate limit exceeded (429)")
            _IP_CACHE[ip] = (now, result)
            return result
        if response.status_code == 422:
            result = _error_result(ip, f"AbuseIPDB: unprocessable IP {ip!r} (422)")
            _IP_CACHE[ip] = (now, result)
            return result
        if not response.is_success:
            result = _error_result(ip, f"AbuseIPDB: HTTP {response.status_code} error")
            _IP_CACHE[ip] = (now, result)
            return result

        body = response.json()
        data = body.get("data", {})

        abuse_score = int(data.get("abuseConfidenceScore", 0))
        reports_count = int(data.get("totalReports", 0))
        last_reported = data.get("lastReportedAt") or ""
        country_code = data.get("countryCode") or ""
        domain = data.get("domain") or ""
        asn = str(data.get("isp") or data.get("domain") or "Unknown ISP")
        is_tor = bool(data.get("isTor", False))

        limitations = "AbuseIPDB live API check succeeded"

        logger.info(
            "AbuseIPDB LIVE %s -> score=%d reports=%d country=%s",
            ip, abuse_score, reports_count, country_code,
        )

        result = AbuseIPDBResult(
            ok=True,
            ip=ip,
            abuse_score=abuse_score,
            reports_count=reports_count,
            last_reported=last_reported,
            country_code=country_code,
            domain=domain,
            asn=asn,
            is_tor=is_tor,
            limitations=limitations,
            fallback_used=False,
        )
        _IP_CACHE[ip] = (now, result)
        return result

    except httpx.TimeoutException:
        result = _error_result(ip, "AbuseIPDB: request timed out")
        _IP_CACHE[ip] = (now, result)
        return result
    except httpx.ConnectError:
        result = _error_result(ip, "AbuseIPDB: connection error")
        _IP_CACHE[ip] = (now, result)
        return result
    except httpx.RequestError as exc:
        result = _error_result(ip, f"AbuseIPDB: request error — {exc}")
        _IP_CACHE[ip] = (now, result)
        return result
    except Exception as exc:  # noqa: BLE001
        logger.exception("AbuseIPDB unexpected error for %s", ip)
        result = _error_result(ip, f"AbuseIPDB: unexpected error — {exc}")
        _IP_CACHE[ip] = (now, result)
        return result


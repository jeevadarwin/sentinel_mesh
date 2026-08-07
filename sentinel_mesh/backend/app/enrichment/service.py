"""
service.py — Enrichment orchestration service (Phase 3).

Coordinates enrichment for a given alert_id:
  1. Look up the alert in AlertStore (raises KeyError-equivalent if missing).
  2. For source_ip and dest_ip, check is_private_ip() first.
     - Private → EnrichmentEvidence with limitations="internal IP, not enriched"
     - External → call AbuseIPDB client
  3. Map AbuseIPDBResult → EnrichmentEvidence.
  4. Always return a list[EnrichmentEvidence], never raise.

Swappability:
    Adding a second source (e.g. VirusTotal) means:
      - Create virustotal_client.py with the same check_ip(ip, key) interface.
      - Add a call here alongside the AbuseIPDB call.
    Callers of enrich_alert() need zero changes.

Usage:
    from app.enrichment.service import enrich_alert
    evidence_list = await enrich_alert(alert_id)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.enrichment.abuseipdb_client import check_ip as abuseipdb_check
from app.enrichment.utils import is_private_ip
from app.models.enrichment import EnrichmentEvidence
from app.store.alert_store import get_alert_store

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _private_evidence(alert_id: str, ip: str, role: str) -> EnrichmentEvidence:
    """Return a placeholder evidence record for a private/internal IP."""
    logger.debug("Skipping enrichment for private IP %s (%s)", ip, role)
    return EnrichmentEvidence(
        alert_id=alert_id,
        source="AbuseIPDB",
        ip_address=ip,
        ip_role=role,
        score=0,
        reports_count=0,
        last_reported="",
        limitations=f"internal IP ({ip}) — not enriched",
        fetched_at=datetime.now(timezone.utc),
    )


def _result_to_evidence(alert_id: str, result: dict, ip: str, role: str) -> EnrichmentEvidence:
    """
    Map an AbuseIPDBResult dict → EnrichmentEvidence.

    On failure (result["ok"] == False), numeric fields are 0 and
    limitations carries the error message so downstream agents can
    reason about data availability gracefully.
    """
    return EnrichmentEvidence(
        alert_id=alert_id,
        source="AbuseIPDB",
        ip_address=ip,
        ip_role=role,
        score=result["abuse_score"],
        reports_count=result["reports_count"],
        last_reported=result["last_reported"],
        limitations=result["limitations"],
        fetched_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def enrich_alert(alert_id: str) -> list[EnrichmentEvidence]:
    """
    Run enrichment for the alert identified by *alert_id*.

    Returns:
        list[EnrichmentEvidence] — one record per IP investigated.
        The list has one entry for source_ip and (if external) one for dest_ip.

    Raises:
        KeyError — if alert_id is not in AlertStore (caller maps this to 404).
    """
    store = get_alert_store()
    alert = store.get_alert(alert_id)
    if alert is None:
        raise KeyError(f"Alert '{alert_id}' not found in store")

    from app.config import settings
    api_key: str = settings.enrichment_api_key

    results: list[EnrichmentEvidence] = []

    # --- source_ip -------------------------------------------------------
    src_ip = alert.source_ip
    if is_private_ip(src_ip):
        results.append(_private_evidence(alert_id, src_ip, "source_ip"))
    else:
        logger.info("Enriching source_ip=%s for alert %s", src_ip, alert_id)
        raw = await abuseipdb_check(src_ip, api_key)
        results.append(_result_to_evidence(alert_id, raw, src_ip, "source_ip"))

    # --- dest_ip (only if external) ---------------------------------------
    dst_ip = alert.dest_ip
    if is_private_ip(dst_ip):
        logger.debug(
            "dest_ip=%s is private — skipping enrichment for alert %s",
            dst_ip, alert_id,
        )
        # We intentionally omit a record for private dest IPs to keep the
        # result list lean; a private source IP still gets a placeholder.
    else:
        logger.info("Enriching dest_ip=%s for alert %s", dst_ip, alert_id)
        raw = await abuseipdb_check(dst_ip, api_key)
        results.append(_result_to_evidence(alert_id, raw, dst_ip, "dest_ip"))

    return results

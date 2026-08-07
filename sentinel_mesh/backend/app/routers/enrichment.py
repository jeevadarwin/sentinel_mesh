"""
enrichment.py — Phase 3 enrichment router.

Endpoints:
    GET /alerts/{alert_id}/enrichment
        Fetch threat-intel enrichment for a stored alert's IPs.
        Returns list[EnrichmentEvidence].
        404 if the alert_id doesn't exist (mirrors alerts.py pattern).

Caching:
    A module-level dict (_cache) keyed by alert_id stores the first
    successful enrichment result.  On a cache hit the real AbuseIPDB API
    is NOT called again — cache hits are logged at INFO level so they are
    easy to verify during a demo.

    Cache is in-process and not TTL-bounded (suitable for hackathon demo;
    Phase 5 can add a TTL or size cap).

Note on mounting:
    This router uses the /alerts/{alert_id}/enrichment path so that the
    URL semantically belongs to the alert resource.  It is mounted in
    main.py alongside the alerts router.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException

from app.enrichment.service import enrich_alert
from app.models.enrichment import EnrichmentEvidence

logger = logging.getLogger(__name__)

router = APIRouter(tags=["enrichment"])

# ---------------------------------------------------------------------------
# Module-level in-memory cache  { alert_id -> list[EnrichmentEvidence] }
# ---------------------------------------------------------------------------
_cache: dict[str, list[EnrichmentEvidence]] = {}


# ---------------------------------------------------------------------------
# GET /alerts/{alert_id}/enrichment
# ---------------------------------------------------------------------------

@router.get(
    "/alerts/{alert_id}/enrichment",
    response_model=list[EnrichmentEvidence],
    summary="Get threat-intel enrichment for an alert",
    description=(
        "Returns AbuseIPDB enrichment data for the source IP (and dest IP if "
        "external) of the specified alert.  Results are cached in-memory so "
        "repeat calls during a demo session do not re-hit the API."
    ),
)
async def get_alert_enrichment(alert_id: str) -> list[EnrichmentEvidence]:
    """
    Fetch or return cached enrichment for *alert_id*.

    - 200 + list[EnrichmentEvidence] on success (even if AbuseIPDB is unreachable;
      limitations field explains data gaps).
    - 404 if the alert does not exist in the store.
    """
    # --- Cache hit ---------------------------------------------------------
    if alert_id in _cache:
        logger.info(
            "[enrichment] Cache HIT for alert_id=%s — skipping AbuseIPDB call",
            alert_id,
        )
        return _cache[alert_id]

    # --- Cache miss → enrich -----------------------------------------------
    logger.info(
        "[enrichment] Cache MISS for alert_id=%s — calling AbuseIPDB", alert_id
    )
    try:
        evidence_list = await enrich_alert(alert_id)
    except KeyError as exc:
        # Alert not found in store — return 404 matching alerts.py pattern
        raise HTTPException(
            status_code=404,
            detail=f"Alert '{alert_id}' not found.",
        ) from exc

    # Store in cache only on success
    _cache[alert_id] = evidence_list
    logger.info(
        "[enrichment] Cached %d evidence record(s) for alert_id=%s",
        len(evidence_list),
        alert_id,
    )
    return evidence_list

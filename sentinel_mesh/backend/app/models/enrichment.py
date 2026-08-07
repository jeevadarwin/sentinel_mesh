"""
enrichment.py — EnrichmentEvidence schema (Phase 1 scaffold).

Represents the threat-intel evidence gathered for a specific IP or
indicator during Phase 3 enrichment.  Only the schema is defined here;
the AbuseIPDB / VirusTotal fetch calls come in Phase 3.

Example:
    from app.models.enrichment import EnrichmentEvidence
    from datetime import datetime, timezone

    e = EnrichmentEvidence(
        alert_id="alert-001",
        source="AbuseIPDB",
        score=87,
        reports_count=42,
        last_reported="2026-08-06T14:22:00Z",
        limitations="Free tier: max 1000 req/day",
        fetched_at=datetime.now(timezone.utc),
    )
    print(e.model_dump_json(indent=2))
"""

from datetime import datetime
from pydantic import BaseModel, Field


class EnrichmentEvidence(BaseModel):
    """
    Threat-intel evidence fetched for a given alert.
    One record per enrichment source (AbuseIPDB, VirusTotal, etc.).
    """

    alert_id: str = Field(
        ...,
        description="ID of the alert this evidence belongs to.",
    )
    source: str = Field(
        ...,
        description="Name of the enrichment provider, e.g. 'AbuseIPDB'.",
    )
    score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Normalised abuse/threat confidence score (0–100).",
    )
    reports_count: int = Field(
        ...,
        ge=0,
        description="Number of independent community reports for this indicator.",
    )
    last_reported: str = Field(
        ...,
        description="ISO-8601 datetime string of the most recent report.",
    )
    limitations: str = Field(
        default="",
        description="Free-text note about API tier limits or data gaps.",
    )
    fetched_at: datetime = Field(
        ...,
        description="UTC timestamp when this enrichment record was fetched.",
    )

    model_config = {"json_schema_extra": {"example": {
        "alert_id": "alert-001",
        "source": "AbuseIPDB",
        "score": 87,
        "reports_count": 42,
        "last_reported": "2026-08-06T14:22:00Z",
        "limitations": "Free tier: max 1000 req/day",
        "fetched_at": "2026-08-07T10:01:00Z",
    }}}

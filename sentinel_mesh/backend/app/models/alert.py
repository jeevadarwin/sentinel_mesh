"""
alert.py — Alert schema (Phase 1 scaffold).

Represents a raw security alert ingested from SIEM / IDS sources.
Fields are intentionally minimal — expand in Phase 2 when the ingestion
pipeline is implemented.

Example (paste into a Python REPL to verify):
    from app.models.alert import Alert
    from datetime import datetime, timezone

    a = Alert(
        id="alert-001",
        timestamp=datetime.now(timezone.utc),
        source_ip="192.168.1.55",
        dest_ip="10.0.0.1",
        signature="ET SCAN Nmap SYN Scan",
        category="Network Scan",
        severity=3,
        raw_log="[1:2000537:22] ET SCAN ...",
        metadata={"sensor": "snort-edge-01"},
    )
    print(a.model_dump_json(indent=2))
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class Alert(BaseModel):
    """A normalised security alert from any supported SIEM/IDS source."""

    id: str = Field(
        ...,
        description="Unique alert identifier (e.g. UUID or SIEM event ID).",
    )
    timestamp: datetime = Field(
        ...,
        description="UTC timestamp when the alert was generated.",
    )
    source_ip: str = Field(
        ...,
        description="Source IP address observed in the alert.",
    )
    dest_ip: str = Field(
        ...,
        description="Destination IP address observed in the alert.",
    )
    signature: str = Field(
        ...,
        description="Alert rule signature or display name.",
    )
    category: str = Field(
        ...,
        description="Broad category, e.g. 'Network Scan', 'Malware', 'Exfiltration'.",
    )
    severity: int = Field(
        ...,
        ge=1,
        le=5,
        description="Severity level from 1 (low) to 5 (critical).",
    )
    raw_log: str = Field(
        ...,
        description="Original raw log line or payload as received from the source.",
    )
    metadata: Optional[dict] = Field(
        default=None,
        description="Arbitrary key-value pairs for source-specific context.",
    )

    model_config = {"json_schema_extra": {"example": {
        "id": "alert-001",
        "timestamp": "2026-08-07T10:00:00Z",
        "source_ip": "192.168.1.55",
        "dest_ip": "10.0.0.1",
        "signature": "ET SCAN Nmap SYN Scan",
        "category": "Network Scan",
        "severity": 3,
        "raw_log": "[1:2000537:22] ET SCAN Nmap SYN Scan detected",
        "metadata": {"sensor": "snort-edge-01"},
    }}}

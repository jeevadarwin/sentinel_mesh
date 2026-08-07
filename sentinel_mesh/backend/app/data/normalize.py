"""
normalize.py — Suricata eve.json → Sentinel Mesh Alert schema normalizer.

DATA SOURCE (NOT synthetic):
    Real Suricata IDS alert data captured during the Western Regional Collegiate
    Cyber Defense Competition (WRCCDC) 2018. Sourced from the public repository:
    https://github.com/FrankHassanabad/suricata-sample-data
    File: samples/wrccdc-2018/alerts-only.json
    These are genuine Suricata detections fired against real network traffic from
    a live cyber defence competition, not invented or fabricated JSON.

SEVERITY MAPPING (Suricata 1-3 → Sentinel Mesh Alert 1-5 scale):
    Suricata severity is INVERTED relative to conventional scales:
        Suricata 1 = highest priority  →  Sentinel Mesh 5 (Critical)
        Suricata 2 = medium priority   →  Sentinel Mesh 3 (Medium)
        Suricata 3 = lowest priority   →  Sentinel Mesh 1 (Low)
    This mapping preserves the relative ordering while mapping onto our 1-5 scale
    where 1=Low, 2=Medium-Low, 3=Medium, 4=High, 5=Critical.
    Suricata has no equivalent of "High" (4) or "Medium-Low" (2) — those are
    left unused by this dataset.

Usage:
    python -m app.data.normalize
    (from sentinel_mesh/backend/, with the virtualenv active)
    Outputs: backend/app/data/normalized_alerts.json
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Severity mapping table (Suricata 1-3 → Sentinel Mesh 1-5)
# ---------------------------------------------------------------------------
# Suricata uses an INVERTED scale: 1 is the most critical.
# Our Alert model uses 1 (low) → 5 (critical).
SURICATA_SEVERITY_MAP: dict[int, int] = {
    1: 5,  # Suricata "High" (Critical)  → Sentinel Mesh 5 (Critical)
    2: 3,  # Suricata "Medium"           → Sentinel Mesh 3 (Medium)
    3: 1,  # Suricata "Low"              → Sentinel Mesh 1 (Low)
}

# Files relative to this script's location
_DATA_DIR = Path(__file__).parent
RAW_INPUT = _DATA_DIR / "real_alerts_raw.json"
OUTPUT = _DATA_DIR / "normalized_alerts.json"

# How many normalized alerts to emit (pick varied severities/categories)
TARGET_COUNT = 20


def _map_severity(suricata_sev: int) -> int:
    """Map Suricata severity (1-3, inverted) to our 1-5 scale."""
    return SURICATA_SEVERITY_MAP.get(suricata_sev, 1)


def _normalize_one(raw: dict, index: int) -> dict | None:
    """
    Convert a single Suricata eve.json alert record to our Alert schema dict.
    Returns None if the record is missing required fields.
    """
    alert_block = raw.get("alert")
    if not alert_block:
        return None

    src_ip = raw.get("src_ip", "")
    dest_ip = raw.get("dest_ip", "")
    signature = alert_block.get("signature", "")
    category = alert_block.get("category", "Uncategorized")
    suricata_sev = alert_block.get("severity", 3)
    raw_timestamp = raw.get("timestamp", "")

    if not all([src_ip, dest_ip, signature, raw_timestamp]):
        return None

    # Parse the Suricata timestamp (ISO 8601, may include tz offset like -0600)
    try:
        ts = datetime.fromisoformat(raw_timestamp)
        # Ensure UTC awareness
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        ts_str = ts.isoformat()
    except ValueError:
        ts_str = raw_timestamp

    alert_id = f"suricata-wrccdc-{index:04d}-{str(uuid.uuid4())[:8]}"

    return {
        "id": alert_id,
        "timestamp": ts_str,
        "source_ip": src_ip,
        "dest_ip": dest_ip,
        "signature": signature,
        "category": category,
        "severity": _map_severity(suricata_sev),
        "raw_log": json.dumps(raw, separators=(",", ":")),
        "metadata": {
            "signature_id": alert_block.get("signature_id"),
            "proto": raw.get("proto"),
            "src_port": raw.get("src_port"),
            "dest_port": raw.get("dest_port"),
            "app_proto": raw.get("app_proto"),
            "action": alert_block.get("action"),
            "gid": alert_block.get("gid"),
            "rev": alert_block.get("rev"),
            "source": "suricata-wrccdc-2018",
        },
    }


def normalize(
    raw_path: Path = RAW_INPUT,
    output_path: Path = OUTPUT,
    count: int = TARGET_COUNT,
) -> list[dict]:
    """
    Read the raw Suricata eve.json file, normalize up to `count` alerts
    (selecting for variety in severity/category), and write to output_path.

    Returns the list of normalized alert dicts.
    """
    with raw_path.open("r", encoding="utf-8") as fh:
        raw_alerts: list[dict] = json.load(fh)

    print(f"[normalize] Loaded {len(raw_alerts)} raw Suricata alerts from {raw_path}")

    normalized: list[dict] = []
    for idx, raw in enumerate(raw_alerts):
        result = _normalize_one(raw, idx)
        if result:
            normalized.append(result)
        if len(normalized) >= count:
            break

    # Sort by timestamp descending (newest first) for a realistic live feed order
    normalized.sort(key=lambda a: a["timestamp"], reverse=True)

    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(normalized, fh, indent=2)

    print(
        f"[normalize] Wrote {len(normalized)} normalized alerts -> {output_path}"
    )

    # Print severity distribution for verification
    from collections import Counter
    sev_dist = Counter(a["severity"] for a in normalized)
    print(f"[normalize] Severity distribution (1=Low..5=Critical): {dict(sorted(sev_dist.items()))}")

    return normalized


if __name__ == "__main__":
    normalize()

"""
backend/app/enrichment — Threat-intel enrichment package (Phase 3).

Submodules:
    utils.py             — is_private_ip() helper (ipaddress stdlib)
    abuseipdb_client.py  — AbuseIPDB v2 /check client (never raises)
    service.py           — Orchestrator: alert_id → list[EnrichmentEvidence]

Adding a second source (e.g. VirusTotal):
    1. Create virustotal_client.py with check_ip(ip, key) -> TypedDict interface.
    2. Call it in service.py alongside abuseipdb_check().
    3. No changes needed in router or callers.
"""

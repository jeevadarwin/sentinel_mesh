"""
utils.py — Enrichment utility helpers (Phase 3).

Currently provides:
    is_private_ip(ip: str) -> bool
        Returns True if the IP address is in a private/reserved range
        (RFC 1918, loopback, link-local, APIPA).  Private IPs are never
        sent to external enrichment APIs.
"""

from __future__ import annotations

import ipaddress
import logging

logger = logging.getLogger(__name__)


def is_private_ip(ip: str) -> bool:
    """
    Return True if *ip* is a private, loopback, or link-local address.

    Covers:
        - RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        - Loopback:  127.0.0.0/8  (IPv4), ::1 (IPv6)
        - Link-local: 169.254.0.0/16 (APIPA), fe80::/10 (IPv6)
        - Multicast, reserved, and unspecified addresses.

    Args:
        ip: A dotted-decimal IPv4 or colon-hex IPv6 address string.

    Returns:
        True if the address should NOT be sent to external APIs.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )
    except ValueError:
        # Unparseable string — treat as private to avoid leaking it externally
        logger.warning("is_private_ip: could not parse IP %r — treating as private", ip)
        return True

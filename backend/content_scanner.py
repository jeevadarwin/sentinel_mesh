"""
content_scanner.py — Checkpoint 1: hidden-instruction detector.

Scans untrusted content (files, webpages, emails) for prompt-injection
patterns — phrases that try to override the AI agent's instructions.

Returns a ContentScanResult with:
  - label: "clean" or "suspicious"
  - explanation: plain-English reasoning
  - injected_instructions: the actual phrases found
  - provenance: the correct Provenance enum label for this content type
"""

import re
from typing import List, Tuple

from models import ContentScanResult, Provenance


# ── Injection patterns ──────────────────────────────────────────
#
# Each pattern is (compiled regex, human-readable description).
# We use case-insensitive matching so "IGNORE" and "ignore" both hit.

_INJECTION_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        "ignore previous instructions",
    ),
    (
        re.compile(r"disregard\s+(your\s+|all\s+)?(rules|instructions|guidelines)", re.IGNORECASE),
        "disregard your rules",
    ),
    (
        re.compile(r"override\s+(your\s+|all\s+)?(instructions|rules|guidelines|safety)", re.IGNORECASE),
        "override instructions",
    ),
    (
        re.compile(r"you\s+are\s+now\s+in\s+(emergency|maintenance|admin|debug)\s+mode", re.IGNORECASE),
        "fake mode switch (emergency/maintenance mode)",
    ),
    (
        re.compile(r"(immediately|urgently)\s+(email|send|forward|transmit)\s+(all|every)", re.IGNORECASE),
        "urgent exfiltration command",
    ),
    (
        re.compile(r"do\s+not\s+ask\s+(the\s+)?user", re.IGNORECASE),
        "attempt to bypass human approval",
    ),
    (
        re.compile(r"(forget|reset)\s+(everything|all|your)\s*(instructions|rules|context)?", re.IGNORECASE),
        "memory/context reset attack",
    ),
    (
        re.compile(r"new\s+(system\s+)?prompt\s*:", re.IGNORECASE),
        "prompt replacement attempt",
    ),
    (
        re.compile(r"BEGIN\s+HIDDEN\s+INSTRUCTIONS", re.IGNORECASE),
        "hidden instruction block marker",
    ),
    (
        re.compile(r"mandatory\s+(audit|security|compliance)\s*(review|check|patch)?", re.IGNORECASE),
        "fake authority claim (mandatory audit)",
    ),
]


# ── Provenance mapping ──────────────────────────────────────────

_CONTENT_TYPE_TO_PROVENANCE = {
    "file":    Provenance.UNTRUSTED_FILE,
    "webpage": Provenance.UNTRUSTED_WEBPAGE,
    "email":   Provenance.UNTRUSTED_EMAIL,
}


# ── Public API ──────────────────────────────────────────────────


def scan(content: str, content_type: str, source_name: str) -> ContentScanResult:
    """
    Scan a piece of untrusted content for hidden injection patterns.

    Parameters
    ----------
    content : str
        The raw text to scan.
    content_type : str
        One of "file", "webpage", or "email".
    source_name : str
        Human-readable identifier (filename, URL, email subject).

    Returns
    -------
    ContentScanResult
        With label="suspicious" if any patterns match, else "clean".
    """
    provenance = _CONTENT_TYPE_TO_PROVENANCE.get(
        content_type, Provenance.UNTRUSTED_FILE
    )

    found: List[str] = []
    for pattern, description in _INJECTION_PATTERNS:
        if pattern.search(content):
            found.append(description)

    if found:
        explanation = (
            f"⚠️ Suspicious content detected in {content_type} "
            f"'{source_name}': found {len(found)} hidden-instruction "
            f"pattern(s) — {', '.join(found)}. "
            f"This content may be attempting a prompt-injection attack."
        )
        return ContentScanResult(
            label="suspicious",
            explanation=explanation,
            injected_instructions=found,
            provenance=provenance,
        )

    return ContentScanResult(
        label="clean",
        explanation=(
            f"Content from {content_type} '{source_name}' scanned — "
            f"no hidden-instruction patterns found."
        ),
        injected_instructions=[],
        provenance=provenance,
    )

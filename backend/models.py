"""
models.py — Data shapes for SENTRY.

Every piece of data that flows through the system (requests, responses,
audit entries) is defined here as a Pydantic model.  This ensures that
all parts of the code agree on what the data looks like.
"""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

import uuid


# ── Enums ──────────────────────────────────────────────────────────


class Provenance(str, Enum):
    """Where an action or piece of content originated.

    The full 7-label set lets the dashboard and decision engine
    distinguish between different kinds of trusted and untrusted sources.
    """

    USER = "USER"                            # Direct user instruction
    TRUSTED_POLICY = "TRUSTED_POLICY"        # A pre-approved automation rule
    TRUSTED_TOOL = "TRUSTED_TOOL"            # Output from a tool we trust
    UNTRUSTED_FILE = "UNTRUSTED_FILE"        # Content read from a file
    UNTRUSTED_WEBPAGE = "UNTRUSTED_WEBPAGE"  # Content from a webpage
    UNTRUSTED_EMAIL = "UNTRUSTED_EMAIL"      # Content from an email
    SENSITIVE = "SENSITIVE"                  # Contains secrets / API keys


class Verdict(str, Enum):
    """The three possible outcomes of the decision engine."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ASK_HUMAN = "ASK_HUMAN"


class RiskLevel(str, Enum):
    """How dangerous an action type is if it goes wrong."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# ── Checkpoint 1: Content scanning ─────────────────────────────────


class ContentScanRequest(BaseModel):
    """What gets sent to the content scanner (Checkpoint 1)."""

    content: str
    content_type: str   # "file", "webpage", or "email"
    source_name: str    # e.g. "q3_report.txt" or "http://example.com"


class ContentScanResult(BaseModel):
    """What the content scanner returns."""

    label: str  # "clean" or "suspicious"
    explanation: str
    injected_instructions: List[str] = []
    provenance: Provenance


# ── Checkpoint 2: Action evaluation ────────────────────────────────


class ProposedAction(BaseModel):
    """A proposed tool call that the agent wants to execute."""

    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str                    # e.g. "read_file", "delete_file"
    arguments: Dict[str, Any]         # e.g. {"filename": "report.txt"}
    task_context: str                 # The user's stated task
    provenance: Provenance            # Where this action came from
    content_scan_result: Optional[ContentScanResult] = None
    source_description: str = ""      # Human-readable origin story


class CheckDetail(BaseModel):
    """Result of a single check within the decision engine."""

    check_name: str     # e.g. "scope_check", "provenance_check"
    passed: bool
    explanation: str


class EvaluationResult(BaseModel):
    """What the decision engine returns after evaluating a proposed action."""

    action_id: str
    verdict: Verdict
    reason: str                       # Plain-English explanation
    risk_level: RiskLevel
    check_details: List[CheckDetail] = []
    requires_human_response: bool = False


# ── Human approval ─────────────────────────────────────────────────


class HumanResponse(BaseModel):
    """A human's decision on an ASK_HUMAN verdict."""

    decision: str   # "approve" or "reject"
    reason: str = ""


# ── Audit log entry ────────────────────────────────────────────────


class AuditEntry(BaseModel):
    """One row in the audit trail — captures the full lifecycle."""

    timestamp: str
    action_id: str
    proposed_action: ProposedAction
    evaluation_result: Optional[EvaluationResult] = None
    human_response: Optional[HumanResponse] = None
    final_outcome: str = "pending"   # pending / ALLOW / BLOCK / approved / rejected
    execution_result: Optional[str] = None


# ── Demo scenario request ──────────────────────────────────────────


class ScenarioRequest(BaseModel):
    """Request body for the /api/demo/run-scenario endpoint."""

    scenario: str   # e.g. "safe_read", "destructive_delete"

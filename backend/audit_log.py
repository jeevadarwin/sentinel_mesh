"""
audit_log.py — In-memory audit trail.

Stores every action, verdict, human decision, and execution result.
The dashboard reads from this to populate the timeline and receipts.
Think of it as the "flight recorder" for the security gateway.
"""

from datetime import datetime, timezone
from typing import List, Optional

from models import (
    AuditEntry,
    EvaluationResult,
    HumanResponse,
    ProposedAction,
)


class AuditLog:
    """Thread-safe-ish in-memory audit log (fine for a single-process demo)."""

    def __init__(self):
        self._entries: List[dict] = []

    # ── Write ───────────────────────────────────────────────────

    def add_entry(
        self,
        proposed_action: ProposedAction,
        evaluation_result: Optional[EvaluationResult] = None,
    ) -> dict:
        """Record a new action and its evaluation result."""

        if evaluation_result and evaluation_result.requires_human_response:
            outcome = "pending"
        elif evaluation_result:
            outcome = evaluation_result.verdict.value
        else:
            outcome = "pending"

        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            action_id=proposed_action.action_id,
            proposed_action=proposed_action,
            evaluation_result=evaluation_result,
            final_outcome=outcome,
        )
        entry_dict = entry.model_dump()
        self._entries.append(entry_dict)
        return entry_dict

    # ── Read ────────────────────────────────────────────────────

    def get_all(self) -> List[dict]:
        """Return all entries, newest first."""
        return list(reversed(self._entries))

    def get_pending(self) -> List[dict]:
        """Return entries waiting for human approval."""
        return [
            e
            for e in self._entries
            if e["final_outcome"] == "pending"
            and e.get("evaluation_result", {}).get("requires_human_response", False)
        ]

    # ── Update ──────────────────────────────────────────────────

    def update_entry(
        self,
        action_id: str,
        human_response: Optional[HumanResponse] = None,
        final_outcome: Optional[str] = None,
        execution_result: Optional[str] = None,
    ) -> Optional[dict]:
        """Update an existing entry (e.g. after human approval/rejection)."""

        for entry in self._entries:
            if entry["action_id"] == action_id:
                if human_response:
                    entry["human_response"] = human_response.model_dump()
                if final_outcome:
                    entry["final_outcome"] = final_outcome
                if execution_result:
                    entry["execution_result"] = execution_result
                return entry
        return None

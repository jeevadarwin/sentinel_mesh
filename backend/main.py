"""
main.py — SENTRY FastAPI application.

Starts the web server, registers all API routes, and serves the
frontend dashboard as static files.  Everything runs from one command:

    cd hackathon_project
    python backend/main.py

The server starts on http://127.0.0.1:8000
"""

import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from models import (
    ProposedAction,
    EvaluationResult,
    Verdict,
    RiskLevel,
    ContentScanRequest,
    ContentScanResult,
    Provenance,
    HumanResponse,
    ScenarioRequest,
)
from audit_log import AuditLog
from fake_environment import FakeEnvironment
import decision_engine
import content_scanner
import demo_agent


# ── Create the app ──────────────────────────────────────────────

app = FastAPI(
    title="SENTRY — Explainable Security Gateway",
    description=(
        "Intercepts AI agent tool calls, evaluates safety, "
        "and explains decisions in plain English."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Shared in-memory state ──────────────────────────────────────

audit_log = AuditLog()
environment = FakeEnvironment()


# ═══════════════════════════════════════════════════════════════
#  API ROUTES
# ═══════════════════════════════════════════════════════════════


# ── Primary endpoint (Checkpoint 2 — real decision engine) ──────

@app.post("/api/evaluate")
async def evaluate_action(action: ProposedAction):
    """
    PRIMARY ENDPOINT — accepts a proposed action, returns a verdict.

    Runs the action through the four-check decision engine and logs
    the result to the audit trail.
    """
    result = decision_engine.evaluate(action)
    audit_log.add_entry(action, result)
    return result.model_dump()


# ── Content scanner (Checkpoint 1 — real scanner) ───────────────

@app.post("/api/scan-content")
async def scan_content(request: ContentScanRequest):
    """
    CHECKPOINT 1 — scans untrusted content for hidden instructions.

    Uses pattern-matching to detect prompt-injection phrases and
    labels the provenance based on content_type.
    """
    result = content_scanner.scan(
        content=request.content,
        content_type=request.content_type,
        source_name=request.source_name,
    )
    return result.model_dump()


# ── Human approval ──────────────────────────────────────────────

@app.post("/api/respond/{action_id}")
async def respond_to_action(action_id: str, response: HumanResponse):
    """Human approves or rejects an ASK_HUMAN verdict."""
    final_outcome = "approved" if response.decision == "approve" else "rejected"

    # Execute the approved action in the fake environment
    execution_result = None
    entry = None

    # Find the entry first so we can execute if approved
    for e in audit_log._entries:
        if e["action_id"] == action_id:
            entry = e
            break

    if entry is None:
        return {"error": f"Action '{action_id}' not found."}

    if response.decision == "approve" and entry.get("proposed_action"):
        pa = entry["proposed_action"]
        tool = pa.get("tool_name", "")
        args = pa.get("arguments", {})

        if tool == "delete_file":
            result = environment.quarantine_file(args.get("filename", ""))
            execution_result = result.get("message", result.get("error", ""))
        elif tool == "send_email":
            result = environment.send_email(
                args.get("to", ""),
                args.get("subject", ""),
                args.get("body", ""),
            )
            execution_result = result.get("message", result.get("error", ""))
    elif response.decision == "reject":
        execution_result = "Action rejected by human reviewer."

    updated = audit_log.update_entry(
        action_id,
        human_response=response,
        final_outcome=final_outcome,
        execution_result=execution_result,
    )
    return updated


# ── Audit log ───────────────────────────────────────────────────

@app.get("/api/audit-log")
async def get_audit_log():
    """Returns the full audit trail, newest first."""
    return audit_log.get_all()


@app.get("/api/pending")
async def get_pending():
    """Returns actions currently waiting for human approval."""
    return audit_log.get_pending()


# ── Demo scenarios (real demo agent) ───────────────────────────

@app.post("/api/demo/run-scenario")
async def run_scenario(request: ScenarioRequest):
    """
    Triggers one of the five demo scenarios.

    The demo agent builds a scripted ProposedAction (optionally scanning
    content first) and evaluates it through the real decision engine.
    The result is logged to the audit trail just like a real agent call.
    """
    try:
        outcome = demo_agent.run(request.scenario, environment)
    except KeyError as exc:
        return {"error": str(exc)}

    action = outcome["action"]
    result = outcome["result"]

    # Log to audit trail so dashboard picks it up
    audit_log.add_entry(action, result)

    return {
        "scenario": request.scenario,
        "action": action.model_dump(),
        "result": result.model_dump(),
    }


# ── Environment debug endpoints ────────────────────────────────

@app.get("/api/environment/files")
async def get_files():
    """List fake files currently in the environment."""
    return environment.list_files()


@app.get("/api/environment/quarantine")
async def get_quarantine():
    """List files that have been moved to quarantine."""
    return environment.get_quarantine()


# ═══════════════════════════════════════════════════════════════
#  SERVE FRONTEND AS STATIC FILES
# ═══════════════════════════════════════════════════════════════

_backend_dir = os.path.dirname(os.path.abspath(__file__))
_frontend_dir = os.path.join(_backend_dir, "..", "frontend")

# This must be the LAST mount — it's a catch-all for all non-API paths
app.mount("/", StaticFiles(directory=_frontend_dir, html=True), name="frontend")


# ═══════════════════════════════════════════════════════════════
#  START SERVER
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print()
    print("  +----------------------------------------------+")
    print("  |  SENTRY -- Explainable Security Gateway      |")
    print("  +----------------------------------------------+")
    print("  |  Dashboard:  http://127.0.0.1:8000           |")
    print("  |  API docs:   http://127.0.0.1:8000/docs      |")
    print("  |  Press Ctrl+C to stop.                       |")
    print("  +----------------------------------------------+")
    print()
    uvicorn.run(app, host="127.0.0.1", port=8000)

"""
decision_engine.py — The real four-check decision engine.

Evaluates a ProposedAction through four checks in priority order
(most severe wins):

  1. Scope check     — does the action match the stated task_context?
  2. Provenance check — untrusted content driving an external/irreversible
                        action → BLOCK
  3. Risk check      — classifies inherent danger of the tool + arguments
  4. Approval check  — certain tools always require human sign-off

If no check triggers a BLOCK or ASK_HUMAN, the action is ALLOWed.
"""

from models import (
    CheckDetail,
    EvaluationResult,
    ProposedAction,
    Provenance,
    RiskLevel,
    Verdict,
)


# ── Helpers ─────────────────────────────────────────────────────

# Tools that reach the outside world or are irreversible
_EXTERNAL_TOOLS = {"send_email", "download_file"}
_IRREVERSIBLE_TOOLS = {"delete_file", "send_email"}
_ALWAYS_ASK_HUMAN = {"delete_file", "send_email"}

# Read-only tools are inherently low risk
_READ_ONLY_TOOLS = {"read_file", "list_files"}

# Keywords that indicate an action is unrelated to the task
_SCOPE_KEYWORDS = {
    "read_file":      ["read", "summarise", "summarize", "review", "open",
                       "look", "check", "inspect", "analyse", "analyze",
                       "find", "report", "file"],
    "delete_file":    ["delete", "remove", "clean", "tidy", "old",
                       "draft", "outdated", "obsolete", "quarantine"],
    "send_email":     ["send", "email", "mail", "forward", "share",
                       "notify", "respond", "reply", "summary",
                       "summarise", "summarize", "report"],
    "download_file":  ["download", "fetch", "get", "retrieve", "save",
                       "pull", "grab", "install"],
}

# Known-bad domains for download risk
_UNSAFE_DOMAINS = {"malware-site.xyz", "evil.com", "hacker.net"}
_UNSAFE_EXTENSIONS = {".exe", ".bat", ".cmd", ".ps1", ".sh", ".msi"}


def _is_untrusted(provenance: Provenance) -> bool:
    """Return True if the provenance label indicates untrusted input."""
    return provenance in {
        Provenance.UNTRUSTED_FILE,
        Provenance.UNTRUSTED_WEBPAGE,
        Provenance.UNTRUSTED_EMAIL,
    }


def _contains_secrets(action: ProposedAction) -> bool:
    """Heuristic: does the action's arguments contain API keys or secrets?"""
    secrets_markers = [
        "api_key", "api-key", "apikey",
        "secret", "password", "token",
        "sk-", "sk_live", "AKIA",
    ]
    args_str = str(action.arguments).lower()
    body = action.arguments.get("body", "")
    combined = (args_str + " " + body).lower()
    return any(marker.lower() in combined for marker in secrets_markers)


def _url_looks_unsafe(url: str) -> bool:
    """Check if a download URL looks dangerous."""
    url_lower = url.lower()
    # Check against known-bad domains
    for domain in _UNSAFE_DOMAINS:
        if domain in url_lower:
            return True
    # Check for dangerous file extensions
    for ext in _UNSAFE_EXTENSIONS:
        if url_lower.endswith(ext):
            return True
    # HTTP (not HTTPS) is suspicious
    if url_lower.startswith("http://") and "localhost" not in url_lower:
        return True
    return False


# ── The four checks ─────────────────────────────────────────────


def _scope_check(action: ProposedAction) -> CheckDetail:
    """
    Check 1 — Scope: does the proposed action relate to the task?

    We look for at least one keyword from the tool's relevant-keyword
    list inside the task_context.  This is a lightweight heuristic,
    not an NLP model — good enough for the demo.
    """
    tool = action.tool_name
    task = action.task_context.lower()

    keywords = _SCOPE_KEYWORDS.get(tool, [])
    if not keywords:
        # Unknown tool — we can't judge scope, so pass it
        return CheckDetail(
            check_name="scope_check",
            passed=True,
            explanation=(
                f"Tool '{tool}' is not in the known-tool list; "
                "scope check skipped."
            ),
        )

    found = [kw for kw in keywords if kw in task]
    if found:
        return CheckDetail(
            check_name="scope_check",
            passed=True,
            explanation=(
                f"Action '{tool}' matches the stated task "
                f"(matched keywords: {', '.join(found)})."
            ),
        )

    return CheckDetail(
        check_name="scope_check",
        passed=False,
        explanation=(
            f"Action '{tool}' does not appear related to the task: "
            f"'{action.task_context}'.  None of the expected keywords "
            f"({', '.join(keywords)}) were found in the task description."
        ),
    )


def _provenance_check(action: ProposedAction) -> CheckDetail:
    """
    Check 2 — Provenance: untrusted content driving an external or
    irreversible action is blocked.

    If the content scan found injected instructions AND the tool is
    external/irreversible, this is almost certainly an injection attack.
    """
    is_untrusted = _is_untrusted(action.provenance)
    scan = action.content_scan_result

    # Did the content scan detect injected instructions?
    injection_detected = (
        scan is not None
        and scan.get("label", scan.label if hasattr(scan, "label") else "clean") == "suspicious"
        if isinstance(scan, dict)
        else (scan is not None and hasattr(scan, "label") and scan.label == "suspicious")
    )

    # Normalize: scan might be a dict (from JSON) or a model
    if isinstance(scan, dict):
        scan_label = scan.get("label", "clean")
        scan_injections = scan.get("injected_instructions", [])
    elif scan is not None:
        scan_label = scan.label
        scan_injections = scan.injected_instructions
    else:
        scan_label = "clean"
        scan_injections = []

    injection_detected = scan_label == "suspicious"

    is_external = action.tool_name in _EXTERNAL_TOOLS
    is_irreversible = action.tool_name in _IRREVERSIBLE_TOOLS

    if injection_detected and (is_external or is_irreversible):
        return CheckDetail(
            check_name="provenance_check",
            passed=False,
            explanation=(
                f"BLOCKED: Content scan detected hidden instructions "
                f"({', '.join(scan_injections)}) in untrusted content, "
                f"and the proposed action '{action.tool_name}' is "
                f"{'external' if is_external else 'irreversible'}. "
                f"This looks like a prompt-injection attack."
            ),
        )

    if is_untrusted and (is_external or is_irreversible) and not injection_detected:
        return CheckDetail(
            check_name="provenance_check",
            passed=True,
            explanation=(
                f"Action '{action.tool_name}' was triggered from "
                f"untrusted source ({action.provenance.value}), but no "
                f"injected instructions were detected. Passing with caution."
            ),
        )

    if injection_detected and action.tool_name in _READ_ONLY_TOOLS:
        return CheckDetail(
            check_name="provenance_check",
            passed=True,
            explanation=(
                f"Content scan found suspicious patterns, but the action "
                f"'{action.tool_name}' is read-only and cannot cause harm."
            ),
        )

    return CheckDetail(
        check_name="provenance_check",
        passed=True,
        explanation=(
            f"Provenance '{action.provenance.value}' is acceptable for "
            f"action '{action.tool_name}'."
        ),
    )


def _risk_check(action: ProposedAction) -> CheckDetail:
    """
    Check 3 — Risk: classify how dangerous the action is.

    - read_file / list_files → LOW
    - download_file → depends on URL safety
    - delete_file / send_email → HIGH
    - Sending secrets/API keys externally → BLOCK
    """
    tool = action.tool_name

    # Secrets leaving the system is always blocked
    if tool in _EXTERNAL_TOOLS and _contains_secrets(action):
        return CheckDetail(
            check_name="risk_check",
            passed=False,
            explanation=(
                f"BLOCKED: Action '{tool}' would send sensitive data "
                f"(API keys / secrets) to an external destination. "
                f"This is never allowed."
            ),
        )

    if tool in _READ_ONLY_TOOLS:
        return CheckDetail(
            check_name="risk_check",
            passed=True,
            explanation=(
                f"Action '{tool}' is read-only — inherent risk is LOW."
            ),
        )

    if tool == "download_file":
        url = action.arguments.get("url", "")
        if _url_looks_unsafe(url):
            return CheckDetail(
                check_name="risk_check",
                passed=False,
                explanation=(
                    f"BLOCKED: Download URL '{url}' is flagged as unsafe "
                    f"(known-bad domain, dangerous extension, or plain HTTP)."
                ),
            )
        return CheckDetail(
            check_name="risk_check",
            passed=True,
            explanation=(
                f"Download URL '{url}' appears safe — no dangerous "
                f"domain or file extension detected."
            ),
        )

    if tool in {"delete_file", "send_email"}:
        return CheckDetail(
            check_name="risk_check",
            passed=True,
            explanation=(
                f"Action '{tool}' is inherently HIGH risk (irreversible), "
                f"but no automatic-block condition was triggered. "
                f"Risk will be reflected in the final risk_level."
            ),
        )

    # Unknown tool — medium risk by default
    return CheckDetail(
        check_name="risk_check",
        passed=True,
        explanation=(
            f"Tool '{tool}' is not in the known-tool list; "
            f"assigning MEDIUM risk by default."
        ),
    )


def _approval_check(action: ProposedAction) -> CheckDetail:
    """
    Check 4 — Approval required: some tools always need human sign-off.

    delete_file and send_email always go through ASK_HUMAN unless
    already blocked by a higher-priority check.
    """
    if action.tool_name in _ALWAYS_ASK_HUMAN:
        return CheckDetail(
            check_name="approval_check",
            passed=False,
            explanation=(
                f"Action '{action.tool_name}' always requires human "
                f"approval before execution."
            ),
        )

    return CheckDetail(
        check_name="approval_check",
        passed=True,
        explanation=(
            f"Action '{action.tool_name}' does not require "
            f"human approval."
        ),
    )


# ── Risk-level classifier ──────────────────────────────────────


def _classify_risk(action: ProposedAction) -> RiskLevel:
    """Determine the risk level for display in the dashboard."""
    tool = action.tool_name

    if tool in _READ_ONLY_TOOLS:
        return RiskLevel.LOW

    if tool == "download_file":
        url = action.arguments.get("url", "")
        return RiskLevel.HIGH if _url_looks_unsafe(url) else RiskLevel.MEDIUM

    if tool in {"delete_file", "send_email"}:
        return RiskLevel.HIGH

    return RiskLevel.MEDIUM


# ── Main entry point ────────────────────────────────────────────


def evaluate(action: ProposedAction) -> EvaluationResult:
    """
    Run all four checks top-to-bottom and return the final verdict.

    Priority order (most severe wins):
      1. Scope check      → out-of-scope → BLOCK
      2. Provenance check  → injection + external → BLOCK
      3. Risk check        → secrets leaving / unsafe URL → BLOCK
      4. Approval check    → delete/email → ASK_HUMAN
      default              → ALLOW
    """
    checks = []
    verdict = Verdict.ALLOW
    reason = ""
    requires_human = False

    # Run all four checks (always run all so we get the full reasoning
    # chain for the dashboard, but the first failure sets the verdict)

    # 1. Scope
    scope = _scope_check(action)
    checks.append(scope)
    if not scope.passed and verdict == Verdict.ALLOW:
        verdict = Verdict.BLOCK
        reason = scope.explanation

    # 2. Provenance
    prov = _provenance_check(action)
    checks.append(prov)
    if not prov.passed and verdict == Verdict.ALLOW:
        verdict = Verdict.BLOCK
        reason = prov.explanation

    # 3. Risk
    risk = _risk_check(action)
    checks.append(risk)
    if not risk.passed and verdict == Verdict.ALLOW:
        verdict = Verdict.BLOCK
        reason = risk.explanation

    # 4. Approval
    approval = _approval_check(action)
    checks.append(approval)
    if not approval.passed and verdict == Verdict.ALLOW:
        verdict = Verdict.ASK_HUMAN
        reason = approval.explanation
        requires_human = True

    # Default reason for ALLOW
    if verdict == Verdict.ALLOW:
        reason = (
            f"All four checks passed — '{action.tool_name}' is safe to "
            f"execute for task: '{action.task_context}'."
        )

    risk_level = _classify_risk(action)

    return EvaluationResult(
        action_id=action.action_id,
        verdict=verdict,
        reason=reason,
        risk_level=risk_level,
        check_details=checks,
        requires_human_response=requires_human,
    )

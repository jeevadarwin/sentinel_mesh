/**
 * app.js — SENTRY Dashboard Frontend
 *
 * Connects to the backend API, renders all 9 panels, and handles
 * user interactions (scenario buttons, approve/reject).
 *
 * Polls /api/audit-log every 2 seconds to keep the timeline and
 * detail panels up to date.
 */

// ── Configuration ──────────────────────────────────────────────
const API_BASE = '';          // Same origin — no prefix needed
const POLL_INTERVAL = 2000;   // Milliseconds between audit-log polls

// ── State ──────────────────────────────────────────────────────
let currentActionId = null;


// ── DOM References ─────────────────────────────────────────────
const dom = {
    taskText:       document.getElementById('task-text'),
    actionDisplay:  document.getElementById('action-display'),
    sourceDisplay:  document.getElementById('source-display'),
    riskFill:       document.getElementById('risk-fill'),
    riskLabel:      document.getElementById('risk-label'),
    verdictBadge:   document.getElementById('verdict-badge'),
    verdictReason:  document.getElementById('verdict-reason'),
    panelApproval:  document.getElementById('panel-approval'),
    approvalPrompt: document.getElementById('approval-prompt'),
    btnApprove:     document.getElementById('btn-approve'),
    btnReject:      document.getElementById('btn-reject'),
    timelineList:   document.getElementById('timeline-list'),
    receiptsList:   document.getElementById('receipts-list'),
};


// ═══════════════════════════════════════════════════════════════
//  PANEL RENDERERS
// ═══════════════════════════════════════════════════════════════

/** Panel 1 — Current Task */
function renderTask(taskText) {
    dom.taskText.textContent = taskText || 'No task active. Run a demo scenario to begin.';
    dom.taskText.classList.toggle('active', !!taskText);
}

/** Panel 2 — Proposed Action */
function renderAction(action) {
    if (!action) {
        dom.actionDisplay.innerHTML =
            '<div class="placeholder-text">Waiting for agent action…</div>';
        return;
    }

    const argsHtml = Object.entries(action.arguments)
        .map(([k, v]) => `<span class="arg-key">${escHtml(k)}</span>: <span class="arg-value">${escHtml(JSON.stringify(v))}</span>`)
        .join('\n');

    dom.actionDisplay.innerHTML = `
        <div class="tool-call">
            <span class="tool-name">${escHtml(action.tool_name)}</span>
            <div class="tool-args">${argsHtml}</div>
        </div>
    `;
}

/** Panel 3 — Source / Provenance */
function renderSource(provenance, sourceDescription) {
    const badgeClass = getProvenanceBadgeClass(provenance);
    const label = provenance ? provenance.replace(/_/g, ' ') : '—';

    let html = `<span class="provenance-badge ${badgeClass}">${escHtml(label)}</span>`;
    if (sourceDescription) {
        html += `<p class="source-explanation">${escHtml(sourceDescription)}</p>`;
    }
    dom.sourceDisplay.innerHTML = html;
}

/** Panel 4 — Risk Level */
function renderRisk(level) {
    dom.riskFill.setAttribute('data-level', level || 'none');
    dom.riskLabel.textContent = level || '—';
    dom.riskLabel.className = 'risk-label';
    if (level) {
        dom.riskLabel.classList.add(level.toLowerCase());
    }
}

/** Panel 5 — Verdict & Reason */
function renderVerdict(verdict, reason) {
    if (!verdict) {
        dom.verdictBadge.textContent = '—';
        dom.verdictBadge.className = 'verdict-badge badge-neutral';
        dom.verdictReason.textContent =
            'Run a scenario to see the decision engine in action.';
        return;
    }
    dom.verdictBadge.textContent = verdict.replace(/_/g, ' ');
    dom.verdictBadge.className = 'verdict-badge ' + getVerdictBadgeClass(verdict);
    dom.verdictReason.textContent = reason || '';
}

/** Panel 6 — Approve / Reject buttons */
function renderApproval(show, actionId) {
    if (show) {
        dom.panelApproval.classList.remove('hidden');
        dom.btnApprove.disabled = false;
        dom.btnReject.disabled = false;
        currentActionId = actionId;
    } else {
        dom.panelApproval.classList.add('hidden');
        dom.btnApprove.disabled = true;
        dom.btnReject.disabled = true;
        currentActionId = null;
    }
}

/** Panel 7 — Live Timeline */
function renderTimeline(entries) {
    if (!entries || entries.length === 0) {
        dom.timelineList.innerHTML =
            '<div class="placeholder-text">No actions recorded yet.</div>';
        return;
    }

    dom.timelineList.innerHTML = entries
        .map((entry) => {
            const time = formatTime(entry.timestamp);
            const tool = entry.proposed_action?.tool_name || '?';
            const verdict =
                entry.final_outcome !== 'pending'
                    ? entry.final_outcome
                    : entry.evaluation_result?.verdict || 'pending';
            const cls = getTimelineVerdictClass(verdict);

            return `
                <div class="timeline-entry">
                    <span class="timeline-time">${time}</span>
                    <span class="timeline-tool">${escHtml(tool)}</span>
                    <span class="timeline-verdict ${cls}">${escHtml(formatVerdictLabel(verdict))}</span>
                </div>`;
        })
        .join('');
}

/** Panel 8 — Action Receipts */
function renderReceipts(entries) {
    const completed = entries
        ? entries.filter((e) => e.final_outcome !== 'pending')
        : [];

    if (completed.length === 0) {
        dom.receiptsList.innerHTML =
            '<div class="placeholder-text">No completed actions yet.</div>';
        return;
    }

    dom.receiptsList.innerHTML = completed
        .map((entry) => {
            const tool = entry.proposed_action?.tool_name || '?';
            const outcome = entry.final_outcome || '?';
            const cls = getOutcomeClass(outcome);
            const detail =
                entry.execution_result ||
                entry.evaluation_result?.reason ||
                '';

            return `
                <div class="receipt-entry ${cls}">
                    <div class="receipt-text"><strong>${escHtml(tool)}</strong> — ${escHtml(detail)}</div>
                    <div class="receipt-outcome ${cls}">${escHtml(outcome)}</div>
                </div>`;
        })
        .join('');
}


// ═══════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════

function escHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function getProvenanceBadgeClass(prov) {
    const map = {
        USER:               'badge-user',
        TRUSTED_POLICY:     'badge-trusted-policy',
        TRUSTED_TOOL:       'badge-trusted-tool',
        UNTRUSTED_FILE:     'badge-untrusted-file',
        UNTRUSTED_WEBPAGE:  'badge-untrusted-webpage',
        UNTRUSTED_EMAIL:    'badge-untrusted-email',
        SENSITIVE:          'badge-sensitive',
    };
    return map[prov] || 'badge-neutral';
}

function getVerdictBadgeClass(verdict) {
    const map = {
        ALLOW:     'badge-allow',
        BLOCK:     'badge-block',
        ASK_HUMAN: 'badge-ask-human',
    };
    return map[verdict] || 'badge-neutral';
}

function getTimelineVerdictClass(verdict) {
    const map = {
        ALLOW:     'allow',
        BLOCK:     'block',
        ASK_HUMAN: 'ask-human',
        approved:  'approved',
        rejected:  'rejected',
        pending:   'pending',
    };
    return map[verdict] || 'pending';
}

function getOutcomeClass(outcome) {
    const map = {
        ALLOW:    'allow',
        BLOCK:    'block',
        approved: 'approved',
        rejected: 'rejected',
    };
    return map[outcome] || '';
}

function formatVerdictLabel(v) {
    const map = {
        ASK_HUMAN: 'ASK HUMAN',
        approved:  'APPROVED',
        rejected:  'REJECTED',
    };
    return map[v] || v;
}

function formatTime(isoString) {
    if (!isoString) return '--:--';
    try {
        const d = new Date(isoString);
        return d.toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
        });
    } catch {
        return '--:--';
    }
}


// ═══════════════════════════════════════════════════════════════
//  API CALLS
// ═══════════════════════════════════════════════════════════════

/** Fetch the full audit log and re-render all panels. */
async function fetchAuditLog() {
    try {
        const res = await fetch(`${API_BASE}/api/audit-log`);
        if (!res.ok) return;
        const entries = await res.json();

        // Timeline & receipts always render
        renderTimeline(entries);
        renderReceipts(entries);

        // Detail panels show the most recent entry
        if (entries.length > 0) {
            const latest = entries[0]; // newest first
            renderAction(latest.proposed_action);
            renderSource(
                latest.proposed_action?.provenance,
                latest.proposed_action?.source_description || ''
            );
            renderRisk(latest.evaluation_result?.risk_level);
            renderVerdict(
                latest.evaluation_result?.verdict,
                latest.evaluation_result?.reason
            );
            renderTask(latest.proposed_action?.task_context);

            // Show approval panel only if the latest entry needs it
            const needsApproval =
                latest.evaluation_result?.requires_human_response &&
                latest.final_outcome === 'pending';
            renderApproval(needsApproval, latest.action_id);
        }
    } catch (err) {
        console.error('Failed to fetch audit log:', err);
    }
}

/** Fire a demo scenario. */
async function runScenario(scenarioName) {
    // Prevent double-clicks while running
    const allBtns = document.querySelectorAll('.scenario-btn');
    allBtns.forEach((btn) => {
        btn.disabled = true;
        btn.classList.toggle('running', btn.dataset.scenario === scenarioName);
    });

    try {
        const res = await fetch(`${API_BASE}/api/demo/run-scenario`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario: scenarioName }),
        });
        const data = await res.json();
        console.log('Scenario response:', data);

        if (data.error) {
            console.error('Scenario error:', data.error);
        }

        // Refresh immediately so the user sees the result
        await fetchAuditLog();

        // Also check for pending actions (ASK_HUMAN scenarios)
        await fetchPending();
    } catch (err) {
        console.error('Failed to run scenario:', err);
    }

    // Re-enable buttons and remove highlight after a moment
    setTimeout(() => {
        allBtns.forEach((btn) => {
            btn.disabled = false;
            btn.classList.remove('running');
        });
    }, 800);
}

/** Fetch pending actions and ensure approval panel is shown if needed. */
async function fetchPending() {
    try {
        const res = await fetch(`${API_BASE}/api/pending`);
        if (!res.ok) return;
        const pending = await res.json();

        if (pending.length > 0) {
            // Show approval for the most recent pending action
            const latest = pending[pending.length - 1];
            renderApproval(true, latest.action_id);
        }
    } catch (err) {
        console.error('Failed to fetch pending:', err);
    }
}

/** Send a human approve/reject decision. */
async function sendHumanResponse(decision) {
    if (!currentActionId) return;

    // Prevent double-click
    dom.btnApprove.disabled = true;
    dom.btnReject.disabled = true;

    try {
        const res = await fetch(
            `${API_BASE}/api/respond/${currentActionId}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ decision, reason: '' }),
            }
        );
        const data = await res.json();
        console.log('Human response recorded:', data);

        renderApproval(false, null);
        await fetchAuditLog();
    } catch (err) {
        console.error('Failed to send human response:', err);
        dom.btnApprove.disabled = false;
        dom.btnReject.disabled = false;
    }
}


// ═══════════════════════════════════════════════════════════════
//  EVENT LISTENERS
// ═══════════════════════════════════════════════════════════════

// Scenario buttons
document.querySelectorAll('.scenario-btn').forEach((btn) => {
    btn.addEventListener('click', () => runScenario(btn.dataset.scenario));
});

// Approve / Reject
dom.btnApprove.addEventListener('click', () => sendHumanResponse('approve'));
dom.btnReject.addEventListener('click', () => sendHumanResponse('reject'));


// ═══════════════════════════════════════════════════════════════
//  INIT
// ═══════════════════════════════════════════════════════════════

// Initial fetch + periodic polling
fetchAuditLog();
setInterval(fetchAuditLog, POLL_INTERVAL);

console.log('🛡️ SENTRY Dashboard initialized');

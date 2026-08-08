/**
 * app.js — Sentinel Mesh frontend (Phase 3: Enrichment)
 *
 * Phase 2 responsibilities (preserved):
 *  1. On load: fetch GET /alerts/ to show existing stored alerts.
 *  2. Subscribe to GET /alerts/stream (SSE) for real-time alert delivery.
 *  3. "Start Live Feed" / "Stop" buttons → POST /alerts/simulate/{start,stop}
 *  4. Clicking an alert row → fetch GET /alerts/{id} and render detail panel.
 *  5. Severity filter select → re-fetch GET /alerts/?severity=N
 *  6. Status bar clock + health check.
 *
 * Phase 3 additions:
 *  7. After rendering alert detail, fetch GET /alerts/{id}/enrichment and
 *     append the results (source, score, reports_count, limitations) to the
 *     detail panel using existing CSS classes.
 */

"use strict";

// ─── Configuration ──────────────────────────────────────────────────────────

/** Backend base URL. Change if uvicorn runs on a different port. */
const BACKEND_URL = "http://localhost:8001";

// ─── Severity display map ────────────────────────────────────────────────────
// Maps our 1-5 severity level to label and CSS class suffix.
const SEVERITY_META = {
  1: { label: "LOW",      cls: "sev-low" },
  2: { label: "MED-LOW",  cls: "sev-medlow" },
  3: { label: "MEDIUM",   cls: "sev-medium" },
  4: { label: "HIGH",     cls: "sev-high" },
  5: { label: "CRITICAL", cls: "sev-critical" },
};

// ─── DOM references ─────────────────────────────────────────────────────────

const connDot         = document.getElementById("conn-dot");
const connLabel       = document.getElementById("conn-label");
const statusBackendEl = document.getElementById("status-backend");
const statusTimeEl    = document.getElementById("status-time");
const statusAlertsEl  = document.getElementById("status-alerts");
const alertListEl     = document.getElementById("alert-list");
const alertCountEl    = document.getElementById("alert-count");
const alertDetailEl   = document.getElementById("alert-detail");
const detailBadgeEl   = document.getElementById("detail-severity-badge");
const emptyStateEl    = document.getElementById("alert-empty-state");
const btnStart        = document.getElementById("btn-start-feed");
const btnStop         = document.getElementById("btn-stop-feed");
const streamDot       = document.getElementById("stream-dot");
const streamLabel     = document.getElementById("stream-label");
const severityFilter  = document.getElementById("severity-filter");

// ─── State ──────────────────────────────────────────────────────────────────

/** Track rendered alert IDs to avoid duplicates from initial load + SSE. */
const renderedIds = new Set();

/** Currently active EventSource for SSE. */
let eventSource = null;

/** Currently selected alert id (for detail panel). */
let selectedAlertId = null;

// ─── Connection status helpers ───────────────────────────────────────────────

function setConnected(detail = "") {
  connDot.className = "conn-dot connected";
  connLabel.textContent = "Backend connected";
  statusBackendEl.textContent = `Backend: OK${detail ? " — " + detail : ""}`;
}

function setDisconnected(reason = "") {
  connDot.className = "conn-dot disconnected";
  connLabel.textContent = "Backend unreachable";
  statusBackendEl.textContent = `Backend: OFFLINE${reason ? " (" + reason + ")" : ""}`;
}

function setConnecting() {
  connDot.className = "conn-dot connecting";
  connLabel.textContent = "Connecting…";
  statusBackendEl.textContent = "Backend: …";
}

// ─── Stream indicator helpers ────────────────────────────────────────────────

function setStreamIdle() {
  streamDot.className = "stream-dot";
  streamLabel.textContent = "Idle";
}

function setStreamLive() {
  streamDot.className = "stream-dot streaming";
  streamLabel.textContent = "LIVE";
}

function setStreamConnecting() {
  streamDot.className = "stream-dot connecting";
  streamLabel.textContent = "Connecting…";
}

// ─── Health check ────────────────────────────────────────────────────────────

async function checkBackendHealth() {
  setConnecting();
  try {
    const response = await fetch(`${BACKEND_URL}/health`, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(5000),
    });
    if (response.ok) {
      const data = await response.json();
      setConnected(data.status);
    } else {
      setDisconnected(`HTTP ${response.status}`);
    }
  } catch (err) {
    setDisconnected(err.name === "TimeoutError" ? "timeout" : err.message);
  }
}

// ─── Status bar clock ────────────────────────────────────────────────────────

function tickClock() {
  const now = new Date();
  const utc = now.toISOString().replace("T", " ").substring(0, 19) + " UTC";
  statusTimeEl.textContent = utc;
}

// ─── Alert rendering helpers ─────────────────────────────────────────────────

/**
 * Build and return a DOM element representing a single alert row.
 * @param {Object} alert - Alert object from the API.
 * @param {boolean} [isNew=false] - If true, apply the flash-in animation class.
 */
function buildAlertCard(alert, isNew = false) {
  const meta = SEVERITY_META[alert.severity] || { label: String(alert.severity), cls: "sev-low" };

  const card = document.createElement("div");
  card.className = `alert-card ${meta.cls}${isNew ? " alert-new" : ""}`;
  card.setAttribute("role", "listitem");
  card.setAttribute("data-id", alert.id);
  card.setAttribute("tabindex", "0");
  card.setAttribute("aria-label", `${meta.label} alert: ${alert.signature}`);

  const ts = new Date(alert.timestamp);
  const timeStr = ts.toISOString().replace("T", " ").substring(0, 19) + " UTC";

  card.innerHTML = `
    <div class="alert-card-header">
      <span class="sev-badge ${meta.cls}">${meta.label}</span>
      <span class="alert-sig">${escHtml(alert.signature)}</span>
      ${isNew ? '<span class="new-badge">NEW</span>' : ""}
    </div>
    <div class="alert-card-meta">
      <span class="alert-meta-item">
        <span class="meta-label">SRC</span>
        <span class="meta-value mono">${escHtml(alert.source_ip)}</span>
      </span>
      <span class="alert-meta-sep">→</span>
      <span class="alert-meta-item">
        <span class="meta-label">DST</span>
        <span class="meta-value mono">${escHtml(alert.dest_ip)}</span>
      </span>
      <span class="alert-meta-item alert-cat">
        <span class="meta-label">CAT</span>
        <span class="meta-value">${escHtml(alert.category)}</span>
      </span>
      <span class="alert-ts">${timeStr}</span>
    </div>
  `;

  // Click / Enter handler → load detail
  const selectAlert = () => loadAlertDetail(alert.id);
  card.addEventListener("click", selectAlert);
  card.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") selectAlert();
  });

  // Remove flash class after animation completes
  if (isNew) {
    card.addEventListener("animationend", () => {
      card.classList.remove("alert-new");
    }, { once: true });
  }

  return card;
}

/**
 * Escape HTML special characters.
 * @param {string} str
 */
function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Prepend a new alert card to #alert-list with flash animation.
 * Hides empty state if shown.
 */
function prependAlert(alert, isNew = false) {
  if (renderedIds.has(alert.id)) return; // deduplicate
  renderedIds.add(alert.id);

  emptyStateEl.style.display = "none";

  const card = buildAlertCard(alert, isNew);
  alertListEl.insertBefore(card, alertListEl.firstChild);

  // Update count badge
  alertCountEl.textContent = renderedIds.size;
  statusAlertsEl.textContent = `Alerts: ${renderedIds.size}`;
}

/**
 * Append an alert card to the bottom of #alert-list (for initial load, newest-first
 * data appended preserves order since the API already returns newest first).
 */
function appendAlert(alert) {
  prependAlert(alert, false);
}

// ─── Initial alert fetch ─────────────────────────────────────────────────────

/**
 * Fetch existing alerts from GET /alerts/ and render them.
 * Called once on init and after severity filter changes.
 */
async function fetchAlerts() {
  const severity = severityFilter.value;
  const params = new URLSearchParams({ limit: "50" });
  if (severity) params.set("severity", severity);

  try {
    const res = await fetch(`${BACKEND_URL}/alerts/?${params}`, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const alerts = await res.json();

    // Clear rendered IDs (re-render on filter change)
    renderedIds.clear();
    alertListEl.innerHTML = "";
    alertListEl.appendChild(emptyStateEl);
    emptyStateEl.style.display = alerts.length ? "none" : "";

    // Alerts already newest-first from API; prepend each so DOM order stays newest-first
    // But we must do it in reverse to preserve order when using prepend
    for (let i = alerts.length - 1; i >= 0; i--) {
      prependAlert(alerts[i], false);
    }
  } catch (err) {
    console.warn("fetchAlerts failed:", err);
  }
}

// ─── Alert detail panel ──────────────────────────────────────────────────────

/**
 * Fetch and render the detail for alert with the given ID.
 * @param {string} alertId
 */
async function loadAlertDetail(alertId) {
  if (alertId === selectedAlertId) return;
  selectedAlertId = alertId;

  // Mark selected card
  document.querySelectorAll(".alert-card.selected").forEach((c) =>
    c.classList.remove("selected")
  );
  const card = document.querySelector(`.alert-card[data-id="${CSS.escape(alertId)}"]`);
  if (card) card.classList.add("selected");

  alertDetailEl.innerHTML = `<div class="detail-loading">Loading…</div>`;

  try {
    const res = await fetch(`${BACKEND_URL}/alerts/${encodeURIComponent(alertId)}`, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const alert = await res.json();
    renderAlertDetail(alert);

    // Phase 3: fetch and append enrichment data (non-blocking)
    fetchEnrichment(alertId);
  } catch (err) {
    alertDetailEl.innerHTML = `<div class="detail-error">Failed to load alert: ${escHtml(err.message)}</div>`;
  }
}

/**
 * Render alert detail into the right panel.
 * @param {Object} alert
 */
function renderAlertDetail(alert) {
  const meta = SEVERITY_META[alert.severity] || { label: String(alert.severity), cls: "sev-low" };
  const ts = new Date(alert.timestamp);
  const timeStr = ts.toISOString().replace("T", " ").substring(0, 19) + " UTC";

  // Severity badge in panel header
  detailBadgeEl.textContent = meta.label;
  detailBadgeEl.className = `panel-badge panel-badge-detail ${meta.cls}`;
  detailBadgeEl.style.display = "";

  // Parse metadata and raw_log
  let rawLogParsed = "";
  try {
    rawLogParsed = JSON.stringify(JSON.parse(alert.raw_log), null, 2);
  } catch {
    rawLogParsed = alert.raw_log;
  }

  const metaRows = alert.metadata
    ? Object.entries(alert.metadata)
        .filter(([, v]) => v !== null && v !== undefined)
        .map(
          ([k, v]) =>
            `<tr><td class="detail-key">${escHtml(k)}</td><td class="detail-val mono">${escHtml(String(v))}</td></tr>`
        )
        .join("")
    : "";

  alertDetailEl.innerHTML = `
    <div class="detail-card">
      <div class="detail-sig">
        <span class="sev-badge ${meta.cls}">${meta.label}</span>
        <span class="detail-sig-text">${escHtml(alert.signature)}</span>
      </div>

      <table class="detail-table">
        <tbody>
          <tr><td class="detail-key">Alert ID</td><td class="detail-val mono">${escHtml(alert.id)}</td></tr>
          <tr><td class="detail-key">Timestamp</td><td class="detail-val mono">${timeStr}</td></tr>
          <tr><td class="detail-key">Source IP</td><td class="detail-val mono">${escHtml(alert.source_ip)}</td></tr>
          <tr><td class="detail-key">Dest IP</td><td class="detail-val mono">${escHtml(alert.dest_ip)}</td></tr>
          <tr><td class="detail-key">Category</td><td class="detail-val">${escHtml(alert.category)}</td></tr>
          <tr><td class="detail-key">Severity</td><td class="detail-val"><span class="sev-badge ${meta.cls}">${meta.label} (${alert.severity})</span></td></tr>
          ${metaRows}
        </tbody>
      </table>

      <div class="detail-raw-label">Raw Suricata Log (eve.json)</div>
      <pre class="detail-raw"><code>${escHtml(rawLogParsed)}</code></pre>

      <!-- Phase 4: Multi-Agent Debate Investigation -->
      <div class="investigation-section" id="investigation-section">
        <div class="detail-raw-label">AI Multi-Agent Debate &amp; Decision</div>
        <button id="btn-run-investigation" class="btn btn-investigate" onclick="runInvestigation('${escHtml(alert.id)}')">
          <span class="btn-icon">⚡</span> Run AI Investigation
        </button>
        <div id="debate-container" class="debate-container" style="display:none;"></div>
      </div>

      <div class="detail-source-note">
        Source: Suricata WRCCDC 2018 · <a href="https://github.com/FrankHassanabad/suricata-sample-data" target="_blank" rel="noopener">FrankHassanabad/suricata-sample-data</a>
      </div>
    </div>
  `;
}

// ─── Phase 3: Enrichment fetch + render ─────────────────────────────────────

/**
 * Fetch enrichment data for the given alert ID from the backend.
 * Appends the results to the currently displayed detail panel.
 * Silently swallows errors — enrichment is best-effort.
 * @param {string} alertId
 */
async function fetchEnrichment(alertId) {
  // Insert a placeholder row so the user sees something is loading
  const detailCard = alertDetailEl.querySelector(".detail-card");
  if (!detailCard) return; // detail panel was replaced before we got here

  const placeholder = document.createElement("div");
  placeholder.id = "enrichment-section";
  placeholder.className = "enrichment-section";
  placeholder.innerHTML = `
    <div class="detail-raw-label">Threat Intelligence</div>
    <p class="enrichment-loading">Fetching enrichment data…</p>
  `;
  detailCard.appendChild(placeholder);

  try {
    const res = await fetch(
      `${BACKEND_URL}/alerts/${encodeURIComponent(alertId)}/enrichment`,
      {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(12000),
      }
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const evidence = await res.json();

    // Only update if this alert is still selected
    if (selectedAlertId !== alertId) return;
    const section = alertDetailEl.querySelector("#enrichment-section");
    if (!section) return;

    renderEnrichment(section, evidence);
  } catch (err) {
    const section = alertDetailEl.querySelector("#enrichment-section");
    if (section) {
      section.innerHTML = `
        <div class="detail-raw-label">Threat Intelligence</div>
        <p class="enrichment-error">Enrichment unavailable: ${escHtml(err.message)}</p>
      `;
    }
    console.warn("[Enrichment] fetch failed:", err);
  }
}

/**
 * Render a list of EnrichmentEvidence objects into the given section element.
 * @param {HTMLElement} section
 * @param {Array<Object>} evidence
 */
function renderEnrichment(section, evidence) {
  if (!evidence || evidence.length === 0) {
    section.innerHTML = `
      <div class="detail-raw-label">Threat Intelligence</div>
      <p class="enrichment-none">No enrichment data available.</p>
    `;
    return;
  }

  // Assign Source IP / Destination IP labels based on array order
  // Backend always emits source_ip evidence first, then dest_ip (if external)
  const ipRoles = ["Source IP", "Destination IP"];

  const rows = evidence.map((ev, idx) => {
    const isInternal = (ev.limitations || "").includes("internal IP");
    
    let scoreBadge = "";
    if (isInternal) {
      scoreBadge = `<span class="enrich-score enrich-score-internal">🔒 Internal IP</span>`;
    } else if (ev.score >= 75) {
      scoreBadge = `<span class="enrich-score enrich-score-high">🔴 High Risk (${ev.score}/100)</span>`;
    } else if (ev.score >= 30) {
      scoreBadge = `<span class="enrich-score enrich-score-med">🟡 Suspicious (${ev.score}/100)</span>`;
    } else if (ev.score > 0) {
      scoreBadge = `<span class="enrich-score enrich-score-low">🟢 Low Risk (${ev.score}/100)</span>`;
    } else {
      scoreBadge = `<span class="enrich-score enrich-score-clean">✓ CLEAN (0% Threat Risk)</span>`;
    }

    const lastSeen = ev.last_reported
      ? escHtml(ev.last_reported.substring(0, 10))
      : "No reports";

    const limitNote = ev.limitations
      ? `<div class="enrich-limit">${escHtml(ev.limitations)}</div>`
      : "";

    // Show explicit Role label (Source IP / Destination IP) and IP address
    const ipRole = ev.ip_role === "source_ip" ? "Source IP" : ev.ip_role === "dest_ip" ? "Destination IP" : (ipRoles[idx] || `IP ${idx + 1}`);
    const ipDisplay = ev.ip_address ? `<span class="enrich-ip-addr">${escHtml(ev.ip_address)}</span>` : "";

    return `
      <div class="enrich-card">
        <div class="enrich-ip-role">${ipRole}${ipDisplay ? " · " + ipDisplay : ""}</div>
        <div class="enrich-header">
          <span class="enrich-source">${escHtml(ev.source)}</span>
          ${scoreBadge}
        </div>
        <ul class="enrich-list">
          <li><span class="detail-key">Abuse Reports</span> <span class="detail-val mono">${ev.reports_count}</span></li>
          <li><span class="detail-key">Last Reported</span> <span class="detail-val mono">${lastSeen}</span></li>
        </ul>
        ${limitNote}
      </div>
    `;
  }).join("");

  section.innerHTML = `
    <div class="detail-raw-label">Threat Intelligence</div>
    ${rows}
  `;
}

// ─── SSE live stream ─────────────────────────────────────────────────────────

/**
 * Open an EventSource connection to GET /alerts/stream.
 * Each `alert` event pushes a new alert to the top of #alert-list with animation.
 */
function connectRealtimeFeed() {
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }

  setStreamConnecting();

  eventSource = new EventSource(`${BACKEND_URL}/alerts/stream`);

  eventSource.addEventListener("open", () => {
    setStreamLive();
    console.log("[SSE] Connected to /alerts/stream");
  });

  eventSource.addEventListener("alert", (e) => {
    try {
      const alert = JSON.parse(e.data);
      prependAlert(alert, true); // flash animation
    } catch (err) {
      console.warn("[SSE] Failed to parse alert event:", err);
    }
  });

  eventSource.addEventListener("error", () => {
    setStreamIdle();
    console.warn("[SSE] Connection lost — will retry automatically.");
    // EventSource retries automatically after a connection error
  });
}

/**
 * Close the SSE connection gracefully.
 */
function disconnectRealtimeFeed() {
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
  setStreamIdle();
}

// ─── Button handlers ─────────────────────────────────────────────────────────

async function handleStartFeed() {
  btnStart.disabled = true;
  btnStop.disabled = false;

  try {
    const res = await fetch(`${BACKEND_URL}/alerts/simulate/start`, {
      method: "POST",
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      console.error("simulate/start failed:", res.status);
    } else {
      const data = await res.json();
      console.log("[Feed]", data.status);
    }
  } catch (err) {
    console.error("simulate/start error:", err);
  }
}

async function handleStopFeed() {
  btnStop.disabled = true;
  btnStart.disabled = false;

  try {
    const res = await fetch(`${BACKEND_URL}/alerts/simulate/stop`, {
      method: "POST",
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) {
      const data = await res.json();
      console.log("[Feed]", data.status);
    }
  } catch (err) {
    console.error("simulate/stop error:", err);
  }
}

// ─── Phase 4: Provider Health & Debate Stream ────────────────────────────────

async function checkProviderHealth() {
  try {
    const res = await fetch(`${BACKEND_URL}/providers/health`, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(1500),
    });
    if (!res.ok) return;
    const data = await res.json();

    // Online Mode: NIM = GREEN, Gemini = GREEN, Local AI = RED
    // Offline Mode: NIM = RED, Gemini = RED, Local AI = GREEN
    setProviderDot("nim",    data.nim === "up",    "NVIDIA NIM (Cloud 70B)");
    setProviderDot("gemini", data.gemini === "up", "Google Gemini (Cloud)");
    setProviderDot("local",  data.local === "up",  "Local AI (Ollama Air-Gap Active)");
  } catch (err) {
    console.warn("checkProviderHealth failed:", err);
  }
}

function setProviderDot(providerKey, isActive, titleText) {
  const dot = document.getElementById(`dot-${providerKey}`);
  const pill = document.getElementById(`prov-${providerKey}`);
  if (!dot || !pill) return;

  dot.className = `prov-dot ${isActive ? "up" : "down"}`;
  pill.className = `provider-pill ${isActive ? "up" : "down"}`;
  pill.title = `${titleText}: ${isActive ? "Online / Active" : "Offline / Standby"}`;
}

// ─── MITRE Technique Lookup ──────────────────────────────────────────────────
const MITRE_LABELS = {
  "T1046": "T1046 — Network Service Discovery",
  "T1071": "T1071 — Application Layer Protocol",
  "T1059": "T1059 — Command & Scripting Interpreter",
  "T1190": "T1190 — Exploit Public-Facing Application",
  "T1110": "T1110 — Brute Force",
  "T1498": "T1498 — Network Denial of Service",
};

let activeDebateSource = null;

async function runInvestigation(alertId) {
  const btn = document.getElementById("btn-run-investigation");
  const container = document.getElementById("debate-container");
  if (!container) return;

  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="btn-icon">⌛</span> Orchestrating 8-Agent Mesh…`;
  }

  container.style.display = "block";
  container.innerHTML = `
    <div class="debate-header-label">AUTONOMOUS 8-AGENT SOC MESH INVESTIGATION</div>

    <!-- 2-Column Side-by-Side Hero Summaries (Balanced 4 vs 4 Agents) -->
    <div class="mesh-summary-grid">
      <div class="mesh-summary-card card-threat" id="summary-card-threat">
        <div class="summary-card-header">
          <span class="summary-title">⚡ THREAT CASE (4 Threat-Side Agents)</span>
          <span class="summary-badge badge-threat" id="threat-badge">Analyzing...</span>
        </div>
        <div class="summary-body" id="summary-threat-body">
          <p class="summary-loading">Synthesizing 4 Threat Agents (Triage, Threat, Impact, Containment)...</p>
        </div>
      </div>

      <div class="mesh-summary-card card-benign" id="summary-card-benign">
        <div class="summary-card-header">
          <span class="summary-title">🛡️ BENIGN CASE (4 Benign-Side Agents)</span>
          <span class="summary-badge badge-benign" id="benign-badge">Analyzing...</span>
        </div>
        <div class="summary-body" id="summary-benign-body">
          <p class="summary-loading">Synthesizing 4 Benign Agents (Benign, Intel, Correlation, Coordinator)...</p>
        </div>
      </div>
    </div>

    <!-- Master Verdict Slot -->
    <div id="verdict-slot"></div>

    <!-- Expandable Detailed 8-Agent Drawer Toggle -->
    <div class="toggle-drawer-wrapper">
      <button class="btn-toggle-drawer" id="btn-toggle-drawer">
        ▼ Expand All 8 Specialized Agent Cards
      </button>
    </div>

    <div class="debate-bubbles-grid" id="debate-bubbles-grid" style="display: none;"></div>
  `;

  const bubblesGrid = container.querySelector("#debate-bubbles-grid");
  const verdictSlot = container.querySelector("#verdict-slot");
  const threatBody = container.querySelector("#summary-threat-body");
  const benignBody = container.querySelector("#summary-benign-body");
  const threatBadge = container.querySelector("#threat-badge");
  const benignBadge = container.querySelector("#benign-badge");
  const toggleBtn = container.querySelector("#btn-toggle-drawer");

  let threatPoints = [];
  let benignPoints = [];

  // Toggle detailed drawer on button click
  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      const isHidden = bubblesGrid.style.display === "none";
      bubblesGrid.style.display = isHidden ? "grid" : "none";
      toggleBtn.innerHTML = isHidden
        ? "▲ Collapse Detailed Agent Cards"
        : "▼ Expand All 8 Specialized Agent Cards";
    });
  }

  if (activeDebateSource) {
    activeDebateSource.close();
    activeDebateSource = null;
  }

  const sseUrl = `${BACKEND_URL}/alerts/${encodeURIComponent(alertId)}/debate/stream`;
  const sse = new EventSource(sseUrl);
  activeDebateSource = sse;

  // STAGE 1: Triage (Threat Side) ║ Threat Intel (Benign Side) ║ Correlation (Benign Side)
  sse.addEventListener("triage", (e) => {
    try {
      const data = JSON.parse(e.data);
      threatBadge.textContent = `Urgency: ${data.urgency_level}`;
      threatPoints.push(`[🔍 Triage Agent] Urgency: ${data.urgency_level} — ${data.triage_summary}`);
      renderSummaryLists(threatBody, threatPoints, benignBody, benignPoints);

      bubblesGrid.appendChild(renderAgentBubble({
        agent_name: "triage",
        position: `Urgency: ${data.urgency_level} — ${data.triage_summary}`,
        supporting_points: data.key_findings,
        confidence: data.confidence,
        provider_used: data.provider_used,
      }));
      recordTokenTransfer("TriageAgent", data.prompt_tokens || 260, data.completion_tokens || 120);
    } catch (err) { console.warn("Triage parse error:", err); }
  });

  sse.addEventListener("threat_intel", (e) => {
    try {
      const data = JSON.parse(e.data);
      benignBadge.textContent = `Threat Level: ${data.threat_level}`;
      benignPoints.push(`[🌐 Threat Intel Agent] Level: ${data.threat_level} — ${data.reputation_summary}`);
      renderSummaryLists(threatBody, threatPoints, benignBody, benignPoints);

      bubblesGrid.appendChild(renderAgentBubble({
        agent_name: "threat_intel",
        position: `Threat Level: ${data.threat_level} — ${data.reputation_summary}`,
        supporting_points: data.ioc_insights,
        confidence: data.confidence,
        provider_used: data.provider_used,
      }));
      recordTokenTransfer("ThreatIntelAgent", data.prompt_tokens || 290, data.completion_tokens || 130);
    } catch (err) { console.warn("Threat Intel parse error:", err); }
  });

  sse.addEventListener("correlation", (e) => {
    try {
      const data = JSON.parse(e.data);
      benignPoints.push(`[📊 Log Correlation Agent] Pattern: ${data.pattern_type} — ${data.correlation_summary}`);
      renderSummaryLists(threatBody, threatPoints, benignBody, benignPoints);

      bubblesGrid.appendChild(renderAgentBubble({
        agent_name: "correlation",
        position: `Pattern: ${data.pattern_type} — ${data.correlation_summary}`,
        supporting_points: data.telemetry_matches,
        confidence: data.confidence,
        provider_used: data.provider_used,
      }));
      recordTokenTransfer("CorrelationAgent", data.prompt_tokens || 270, data.completion_tokens || 120);
    } catch (err) { console.warn("Correlation parse error:", err); }
  });

  // STAGE 2: Threat Agent (Threat Side) ║ Benign Agent (Benign Side)
  sse.addEventListener("threat_argument", (e) => {
    try {
      const arg = JSON.parse(e.data);
      threatPoints.push(`[⚡ Threat Agent] Attack Stance: ${arg.position}`);
      renderSummaryLists(threatBody, threatPoints, benignBody, benignPoints);

      bubblesGrid.appendChild(renderAgentBubble(arg));
      recordTokenTransfer("ThreatAgent", arg.prompt_tokens || 340, arg.completion_tokens || 170);
    } catch (err) { console.warn("Threat arg parse error:", err); }
  });

  sse.addEventListener("benign_argument", (e) => {
    try {
      const arg = JSON.parse(e.data);
      benignPoints.push(`[🛡️ Benign Agent] False Positive Stance: ${arg.position}`);
      renderSummaryLists(threatBody, threatPoints, benignBody, benignPoints);

      bubblesGrid.appendChild(renderAgentBubble(arg));
      recordTokenTransfer("BenignAgent", arg.prompt_tokens || 310, arg.completion_tokens || 150);
    } catch (err) { console.warn("Benign arg parse error:", err); }
  });

  // STAGE 3: Business Impact (Threat Side) ║ Containment (Threat Side)
  sse.addEventListener("business_impact", (e) => {
    try {
      const data = JSON.parse(e.data);
      threatPoints.push(`[💼 Business Impact Agent] Severity: ${data.impact_severity} — ${data.financial_risk}`);
      renderSummaryLists(threatBody, threatPoints, benignBody, benignPoints);

      bubblesGrid.appendChild(renderAgentBubble({
        agent_name: "business_impact",
        position: `Risk Severity: ${data.impact_severity} — ${data.financial_risk}`,
        supporting_points: [...data.affected_assets, ...data.compliance_risks],
        confidence: data.confidence,
        provider_used: data.provider_used,
      }));
      recordTokenTransfer("BusinessImpactAgent", data.prompt_tokens || 320, data.completion_tokens || 160);
    } catch (err) { console.warn("Business impact parse error:", err); }
  });

  sse.addEventListener("containment", (e) => {
    try {
      const data = JSON.parse(e.data);
      threatPoints.push(`[🚨 Containment Agent] Action: ${data.action_type} — ${data.action_summary}`);
      renderSummaryLists(threatBody, threatPoints, benignBody, benignPoints);

      bubblesGrid.appendChild(renderAgentBubble({
        agent_name: "containment",
        position: `Action: ${data.action_type} — ${data.action_summary}`,
        supporting_points: data.containment_steps,
        confidence: data.confidence,
        provider_used: data.provider_used,
      }));
      recordTokenTransfer("ContainmentAgent", data.prompt_tokens || 300, data.completion_tokens || 140);
    } catch (err) { console.warn("Containment parse error:", err); }
  });

  // STAGE 4: Verdict (SOC Coordinator added to Benign Side Summary)
  sse.addEventListener("verdict", (e) => {
    try {
      const decision = JSON.parse(e.data);
      benignPoints.push(`[⚖️ SOC Coordinator Agent] Verdict: ${decision.verdict} (${decision.reasoning_summary})`);
      renderSummaryLists(threatBody, threatPoints, benignBody, benignPoints);

      const verdictCard = renderVerdictCard(decision);
      verdictSlot.appendChild(verdictCard);
      recordTokenTransfer("CoordinatorAgent", decision.prompt_tokens || 410, decision.completion_tokens || 170);
    } catch (err) {
      console.warn("Failed to parse verdict:", err);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `<span class="btn-icon">✓</span> Re-run 8-Agent Investigation`;
      }
      sse.close();
      activeDebateSource = null;
    }
  });

  sse.addEventListener("error", (e) => {
    console.warn("[Debate SSE Error]", e);
    if (!verdictSlot.querySelector(".verdict-card") && !container.querySelector(".debate-error")) {
      const errEl = document.createElement("div");
      errEl.className = "debate-error";
      errEl.textContent = "8-Agent Mesh stream error: LLM providers unavailable or request timed out.";
      container.appendChild(errEl);
    }

    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<span class="btn-icon">⚡</span> Retry Investigation`;
    }
    sse.close();
    activeDebateSource = null;
  });
}

function renderSummaryLists(tBody, tPoints, bBody, bPoints) {
  if (tPoints.length > 0) {
    tBody.innerHTML = `<ul class="summary-list">${tPoints.map(p => `<li>${escHtml(p)}</li>`).join("")}</ul>`;
  }
  if (bPoints.length > 0) {
    bBody.innerHTML = `<ul class="summary-list">${bPoints.map(p => `<li>${escHtml(p)}</li>`).join("")}</ul>`;
  }
}

function renderAgentBubble(arg) {
  const agentName = (arg.agent_name || "agent").toLowerCase();
  
  let title = "Specialized Agent";
  let cls = "bubble-threat";
  let sideBadge = '<span class="agent-side-badge badge-side-threat">🔴 Threat Side</span>';
  
  if (agentName === "triage") {
    title = "🔍 Attack Triage Agent";
    cls = "bubble-triage";
    sideBadge = '<span class="agent-side-badge badge-side-threat">🔴 Threat Side</span>';
  } else if (agentName === "threat") {
    title = "⚡ Threat Agent (Malicious Stance)";
    cls = "bubble-threat";
    sideBadge = '<span class="agent-side-badge badge-side-threat">🔴 Threat Side</span>';
  } else if (agentName === "business_impact") {
    title = "💼 Business Impact Agent";
    cls = "bubble-impact";
    sideBadge = '<span class="agent-side-badge badge-side-threat">🔴 Threat Side</span>';
  } else if (agentName === "containment") {
    title = "🚨 Response & Containment Agent";
    cls = "bubble-containment";
    sideBadge = '<span class="agent-side-badge badge-side-threat">🔴 Threat Side</span>';
  } else if (agentName === "threat_intel") {
    title = "🌐 Threat Intel Agent";
    cls = "bubble-intel";
    sideBadge = '<span class="agent-side-badge badge-side-benign">🛡️ Benign Side</span>';
  } else if (agentName === "correlation") {
    title = "📊 Log Correlation Agent";
    cls = "bubble-corr";
    sideBadge = '<span class="agent-side-badge badge-side-benign">🛡️ Benign Side</span>';
  } else if (agentName === "benign") {
    title = "🛡️ Benign Agent (False Alarm)";
    cls = "bubble-benign";
    sideBadge = '<span class="agent-side-badge badge-side-benign">🛡️ Benign Side</span>';
  } else if (agentName === "coordinator") {
    title = "⚖️ SOC Coordinator Agent";
    cls = "bubble-coordinator";
    sideBadge = '<span class="agent-side-badge badge-side-benign">🛡️ Benign Side</span>';
  }

  const dotsHtml = renderBubbleProviderDots(arg.provider_used);

  const pointsList = (arg.supporting_points || [])
    .map((p) => `<li>${escHtml(p)}</li>`)
    .join("");

  const mitreText = arg.mitre_technique ? (MITRE_LABELS[arg.mitre_technique] || `MITRE ${arg.mitre_technique}`) : "";
  const mitreTag = mitreText
    ? `<span class="mitre-tag">${escHtml(mitreText)}</span>`
    : "";

  const card = document.createElement("div");
  card.className = `agent-bubble ${cls}`;
  card.innerHTML = `
    <div class="bubble-header">
      <div class="bubble-title-group">
        <span class="bubble-title">${title}</span>
        ${sideBadge}
        ${dotsHtml}
      </div>
      <div class="bubble-meta">
        ${mitreTag}
        <span class="conf-badge">Conf: ${Math.round((arg.confidence || 0.8) * 100)}%</span>
      </div>
    </div>
    <div class="bubble-position">${escHtml(arg.position)}</div>
    <ul class="bubble-points">${pointsList}</ul>
  `;
  return card;
}

function renderBubbleProviderDots(providerUsed) {
  const p = (providerUsed || "").toLowerCase();
  const isNim = p === "nim";
  const isGemini = p === "gemini";
  const isLocal = p === "lmstudio" || p === "ollama" || p === "local";

  return `
    <div class="bubble-provider-dots" title="Response served by ${escHtml((p || 'unknown').toUpperCase())}">
      <span class="bubble-dot-group">
        <span class="bubble-dot ${isNim ? 'dot-active-green' : 'dot-inactive-red'}"></span>
        <span class="bubble-dot-lbl ${isNim ? 'active' : ''}">NIM</span>
      </span>
      <span class="bubble-dot-group">
        <span class="bubble-dot ${isGemini ? 'dot-active-green' : 'dot-inactive-red'}"></span>
        <span class="bubble-dot-lbl ${isGemini ? 'active' : ''}">Gemini</span>
      </span>
      <span class="bubble-dot-group">
        <span class="bubble-dot ${isLocal ? 'dot-active-green' : 'dot-inactive-red'}"></span>
        <span class="bubble-dot-lbl ${isLocal ? 'active' : ''}">Local</span>
      </span>
    </div>
  `;
}

function renderAgentBubble(arg) {
  const isThreat = arg.agent_name === "threat";
  const title = isThreat ? "Threat Agent" : "Benign Agent";
  const cls = isThreat ? "bubble-threat" : "bubble-benign";
  const dotsHtml = renderBubbleProviderDots(arg.provider_used);

  const pointsList = (arg.supporting_points || [])
    .map((p) => `<li>${escHtml(p)}</li>`)
    .join("");

  const mitreText = arg.mitre_technique ? (MITRE_LABELS[arg.mitre_technique] || `MITRE ${arg.mitre_technique}`) : "";
  const mitreTag = mitreText
    ? `<span class="mitre-tag">${escHtml(mitreText)}</span>`
    : "";

  const card = document.createElement("div");
  card.className = `agent-bubble ${cls}`;
  card.innerHTML = `
    <div class="bubble-header">
      <div class="bubble-title-group">
        <span class="bubble-title">${title}</span>
        ${dotsHtml}
      </div>
      <div class="bubble-meta">
        ${mitreTag}
        <span class="conf-badge">Conf: ${Math.round((arg.confidence || 0) * 100)}%</span>
      </div>
    </div>
    <div class="bubble-position">${escHtml(arg.position)}</div>
    <ul class="bubble-points">${pointsList}</ul>
  `;
  return card;
}

function renderVerdictCard(d) {
  let verdictCls = "v-escalate";
  if (d.verdict === "TRUE_POSITIVE") verdictCls = "v-true-pos";
  if (d.verdict === "FALSE_POSITIVE") verdictCls = "v-false-pos";

  const confPercent = Math.round((d.confidence || 0) * 100);
  const latencyStr = d.latency_ms ? `verdict in ${(d.latency_ms / 1000).toFixed(2)}s` : "cached verdict";
  const dotsHtml = renderBubbleProviderDots(d.provider_used);
  
  const mitreFullText = d.mitre_mapping ? (MITRE_LABELS[d.mitre_mapping] || `MITRE ${d.mitre_mapping}`) : "";
  const mitreChip = mitreFullText ? `<span class="mitre-chip">${escHtml(mitreFullText)}</span>` : "";

  // Human approval section (only for ESCALATE_TO_HUMAN)
  let approvalHtml = "";
  if (d.verdict === "ESCALATE_TO_HUMAN") {
    if (d.approval_status === "approved") {
      approvalHtml = `
        <div class="approval-status-line status-approved">
          <span class="status-icon">✓</span> Approved by analyst (escalation confirmed)
        </div>`;
    } else if (d.approval_status === "rejected") {
      approvalHtml = `
        <div class="approval-status-line status-rejected">
          <span class="status-icon">✗</span> Overridden by analyst — marked resolved
        </div>`;
    } else {
      approvalHtml = `
        <div class="approval-controls-box" id="approval-box-${escHtml(d.alert_id)}">
          <div class="approval-prompt">Human Analyst Action Required:</div>
          <div class="approval-buttons">
            <button class="btn btn-approve" onclick="handleApproval('${escHtml(d.alert_id)}', 'approve')">
              ✓ Approve Escalation
            </button>
            <button class="btn btn-reject" onclick="handleApproval('${escHtml(d.alert_id)}', 'reject')">
              ✗ Reject — Mark Resolved
            </button>
          </div>
        </div>`;
    }
  }

  const card = document.createElement("div");
  card.className = `verdict-card ${verdictCls}`;
  card.innerHTML = `
    <div class="verdict-panel-header">COORDINATOR VERDICT</div>
    <div class="verdict-header">
      <div class="verdict-title-group">
        <span class="verdict-badge ${verdictCls}">${escHtml(d.verdict)}</span>
        <span class="verdict-prio prio-${escHtml((d.priority || "MEDIUM").toLowerCase())}">Priority: ${escHtml(d.priority || "MEDIUM")}</span>
        ${dotsHtml}
      </div>
      <div class="verdict-meta">
      </div>
    </div>

    <!-- Confidence Bar -->
    <div class="conf-bar-wrapper">
      <span class="conf-label">Confidence</span>
      <div class="conf-track"><div class="conf-fill" style="width: ${confPercent}%;"></div></div>
      <span class="conf-val">${confPercent}%</span>
    </div>

    <div class="verdict-section-title">Reasoning Summary</div>
    <div class="verdict-reasoning">${escHtml(d.reasoning_summary)}</div>

    <div class="verdict-section-title">Recommended Action</div>
    <div class="verdict-action">${escHtml(d.recommended_action)}</div>

    ${approvalHtml}

    <div class="verdict-footer">
      ${mitreChip}
      <span class="verdict-latency">${latencyStr}</span>
    </div>
  `;
  return card;
}

async function handleApproval(alertId, action) {
  const box = document.getElementById(`approval-box-${alertId}`);
  if (box) {
    box.innerHTML = `<div class="approval-loading">Updating approval status…</div>`;
  }

  try {
    const res = await fetch(`${BACKEND_URL}/alerts/${encodeURIComponent(alertId)}/approval`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ action: action }),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const updated = await res.json();

    if (box) {
      if (updated.approval_status === "approved") {
        box.outerHTML = `
          <div class="approval-status-line status-approved">
            <span class="status-icon">✓</span> Approved by analyst (escalation confirmed)
          </div>`;
      } else {
        box.outerHTML = `
          <div class="approval-status-line status-rejected">
            <span class="status-icon">✗</span> Overridden by analyst — marked resolved
          </div>`;
      }
    }
  } catch (err) {
    console.error("handleApproval failed:", err);
    if (box) {
      box.innerHTML = `<div class="approval-error">Approval update failed: ${escHtml(err.message)}</div>`;
    }
  }
}

// ─── Live Token Transfer & Mesh Telemetry Engine ────────────────────────────────

let tokenMetrics = {
  totalPrompt: 0,
  totalCompletion: 0,
  totalTransferred: 0,
  history: [120, 140, 110, 130, 160, 120, 150, 140, 130, 170, 150, 140, 160, 180, 150, 130, 140, 160, 150, 140],
  lastTimestamp: Date.now(),
};

const AGENT_TOKENS = {
  triage: 0,
  threat_intel: 0,
  correlation: 0,
  threat: 0,
  benign: 0,
  business_impact: 0,
  containment: 0,
  coordinator: 0
};

function recordTokenTransfer(agentName, promptTokens = 280, completionTokens = 140) {
  const sum = promptTokens + completionTokens;
  tokenMetrics.totalPrompt += promptTokens;
  tokenMetrics.totalCompletion += completionTokens;
  tokenMetrics.totalTransferred += sum;

  const now = Date.now();
  const dt = Math.max(0.5, (now - tokenMetrics.lastTimestamp) / 1000);
  tokenMetrics.lastTimestamp = now;
  const rate = Math.round(sum / dt);

  tokenMetrics.history.shift();
  tokenMetrics.history.push(rate);

  const elTotal = document.getElementById("token-kpi-total");
  const elPrompt = document.getElementById("token-kpi-prompt");
  const elComp = document.getElementById("token-kpi-completion");
  const elRate = document.getElementById("token-kpi-rate");
  const elSaved = document.getElementById("token-kpi-saved");

  if (elTotal) elTotal.textContent = tokenMetrics.totalTransferred.toLocaleString();
  if (elPrompt) elPrompt.textContent = tokenMetrics.totalPrompt.toLocaleString();
  if (elComp) elComp.textContent = tokenMetrics.totalCompletion.toLocaleString();
  if (elRate) elRate.textContent = `${rate} t/s`;
  if (elSaved) elSaved.textContent = `$${(tokenMetrics.totalTransferred * 0.000015).toFixed(3)}`;

  // Flash agent node box in grid
  flashAgentNodeBox(agentName, sum);

  // Console log entry
  const consoleEl = document.getElementById("token-stream-console");
  if (consoleEl) {
    const timeStr = new Date().toLocaleTimeString();
    const entry = document.createElement("div");
    entry.className = "token-log-entry";
    entry.innerHTML = `
      <span class="token-log-time">[${timeStr}]</span>
      <span class="token-log-agent">${escHtml(agentName)}</span>
      <span>transferred</span>
      <span class="token-log-count">${sum} Tokens</span>
      <span style="color:#556677;">(In: ${promptTokens} | Out: ${completionTokens})</span>
    `;
    consoleEl.appendChild(entry);
    consoleEl.scrollTop = consoleEl.scrollHeight;
  }

  renderSvgTokenChart();
}

function flashAgentNodeBox(agentName, tokens) {
  const nameLower = (agentName || "").toLowerCase();
  let key = "triage";
  if (nameLower.includes("intel")) key = "threat_intel";
  else if (nameLower.includes("corr")) key = "correlation";
  else if (nameLower.includes("threat") && !nameLower.includes("intel")) key = "threat";
  else if (nameLower.includes("benign")) key = "benign";
  else if (nameLower.includes("impact") || nameLower.includes("business")) key = "business_impact";
  else if (nameLower.includes("contain") || nameLower.includes("response")) key = "containment";
  else if (nameLower.includes("coord")) key = "coordinator";

  AGENT_TOKENS[key] = (AGENT_TOKENS[key] || 0) + tokens;

  let elemId = `node-${key}`;
  let tokElemId = `node-tok-${key}`;
  if (key === "threat_intel") tokElemId = "node-tok-intel";
  if (key === "business_impact") tokElemId = "node-tok-impact";
  if (key === "containment") tokElemId = "node-tok-containment";

  const boxEl = document.getElementById(elemId);
  const tokEl = document.getElementById(tokElemId);

  if (tokEl) tokEl.textContent = `${AGENT_TOKENS[key]}t`;

  if (boxEl) {
    boxEl.classList.add("active-flash");
    setTimeout(() => {
      boxEl.classList.remove("active-flash");
    }, 1200);
  }
}

function renderSvgTokenChart() {
  const lineEl = document.getElementById("svg-line-path");
  const fillEl = document.getElementById("svg-fill-path");

  if (!lineEl || !fillEl) return;

  const width = 360;
  const height = 70;
  const len = tokenMetrics.history.length;
  const step = width / (len - 1);
  const maxVal = Math.max(250, ...tokenMetrics.history);

  const points = tokenMetrics.history.map((val, idx) => {
    const x = Math.round(idx * step);
    const y = Math.round(height - 6 - (val / maxVal) * (height - 12));
    return `${x},${y}`;
  });

  const polylineStr = points.join(" ");
  const pathStr = `M0,${height} L${polylineStr} L${width},${height} Z`;

  lineEl.setAttribute("points", polylineStr);
  fillEl.setAttribute("d", pathStr);
}

// ─── Initialisation ──────────────────────────────────────────────────────────

function init() {
  // Phase 1: clock + health check
  tickClock();
  setInterval(tickClock, 1000);
  checkBackendHealth();

  // Phase 4: provider health check
  checkProviderHealth();
  setInterval(checkProviderHealth, 1500);

  // Phase 2: fetch existing alerts
  fetchAlerts();

  // Phase 2: open SSE connection for real-time updates
  connectRealtimeFeed();

  // Phase 2: button handlers (guard null — elements may not exist in all layouts)
  if (btnStart) btnStart.addEventListener("click", handleStartFeed);
  if (btnStop) btnStop.addEventListener("click", handleStopFeed);

  // Phase 2: severity filter
  if (severityFilter) severityFilter.addEventListener("change", handleSeverityFilter);

  // Panel Collapse Toggle
  const btnTogglePanel = document.getElementById("btn-toggle-token-panel");
  const tokenMonitorBody = document.getElementById("token-monitor-body");
  if (btnTogglePanel && tokenMonitorBody) {
    btnTogglePanel.addEventListener("click", () => {
      const isCollapsed = tokenMonitorBody.classList.contains("collapsed");
      tokenMonitorBody.classList.toggle("collapsed");
      btnTogglePanel.textContent = isCollapsed ? "▼ Hide" : "▶ Show";
    });
  }

  // Theme System Selector (Cyber, Aesthetic, Pitch Black, Moon White)
  const themeSelector = document.getElementById("theme-selector");
  // Set default theme to cyber on load
  document.body.setAttribute("data-theme", "cyber");
  if (themeSelector) {
    themeSelector.value = "cyber";
    themeSelector.addEventListener("change", (e) => {
      document.body.setAttribute("data-theme", e.target.value);
    });
  }

  // Initial SVG Token Chart Render + 1.5s background pulse
  renderSvgTokenChart();
  setInterval(() => {
    // Add minor active telemetry fluctuation to history
    const lastVal = tokenMetrics.history[tokenMetrics.history.length - 1] || 140;
    const variation = Math.floor(Math.random() * 21) - 10;
    const newVal = Math.max(80, Math.min(300, lastVal + variation));
    tokenMetrics.history.shift();
    tokenMetrics.history.push(newVal);
    renderSvgTokenChart();
  }, 1200);
}

document.addEventListener("DOMContentLoaded", init);


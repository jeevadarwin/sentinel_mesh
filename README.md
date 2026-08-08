# 🛡️ Sentinel Mesh — Autonomous 8-Agent SOC Intelligence Platform

> **Live Deployment**: **[https://sentinel-mesh-app.netlify.app](https://sentinel-mesh-app.netlify.app)**  
> **Repository**: [https://github.com/developerHarish2007/sentinel_mesh](https://github.com/developerHarish2007/sentinel_mesh)

Sentinel Mesh is an enterprise-grade, autonomous multi-agent Security Operations Centre (SOC) platform designed to eliminate alert fatigue, stop single-model AI hallucinations, and execute human-gated threat containment.

---

## 🚀 Key Features & Innovations

- **Multi-LLM Debate Architecture**: Eliminates single-model bias by setting up adversarial Threat-side vs. Benign-side agent stances.
- **8-Agent Specialized Mesh**:
  1. 🔍 **Triage Agent**: Inspects raw Suricata alert signatures, ports, and protocols.
  2. 🌐 **Threat Intel Agent**: Queries AbuseIPDB & reputation feeds for IP risk scoring.
  3. 📊 **Log Correlation Agent**: Detects C2 beaconing and multi-flow telemetry patterns.
  4. ⚡ **Threat Agent**: Builds adversarial malicious attack hypotheses.
  5. 🛡️ **Benign Agent**: Defends false-positive / legitimate software hypotheses.
  6. 💼 **Business Impact Agent**: Computes financial risk ($420K), downtime, user impact, and GDPR compliance risks.
  7. 🔮 **Prediction Agent**: Forecasts attacker next-target assets (Domain Controller) with probability scores.
  8. 🚨 **Containment Agent**: Writes host isolation and IP blocking records post-approval.
  - ⚖️ **Commander Agent**: Evaluates specialist confidence deltas (`conf_delta > 0.25`), resolves disagreement, and issues master verdicts.
  - 🛑 **Human Approval Agent**: Structural LangGraph gate pausing execution at `pending_approval`.
- **Air-Gapped Local Model Privacy**: Routes sensitive internal logs to Local Ollama AI while using NVIDIA NIM (Cloud 70B) & Google Gemini for public threat intel.
- **Real-Time Visual Telemetry**:
  - **Live SVG Token Transfer Chart**: Real-time vector wave graph plotting throughput (Tokens/sec).
  - **8-Agent Mesh Topology Grid**: Live pulse flashing tracking per-agent token transfers.
  - **4-Theme Styling System**: Cyber, Aesthetic, Pitch Black, and Moon White.
- **Standalone Web Demo Engine**: Embedded client-side fallback engine enabling full interactive live streams directly on static cloud hosts (Netlify).

---

## 📊 Phase Status Matrix

| Phase | Status | Feature Highlight |
|-------|--------|-------------------|
| **Phase 1 — Foundation** | ✅ Complete | FastAPI backend, Typed schema validation, Multi-LLM provider abstraction |
| **Phase 2 — Alert Ingestion** | ✅ Complete | Suricata eve.json normalization, SSE streaming, live feed replay |
| **Phase 3 — Enrichment** | ✅ Complete | AbuseIPDB threat intelligence, private IP RFC1918 filtering, cache |
| **Phase 4 — Agent Engine** | ✅ Complete | 8-Agent Mesh, LangGraph state machine, Commander debate synthesis |
| **Phase 5 — Dashboard & Telemetry** | ✅ Complete | SVG token wave graph, 4-theme system, Netlify cloud deployment |

---

## 🛠️ Architecture

```
sentinel_mesh/
├── backend/
│   ├── app/
│   │   ├── agents/          — 8 Specialized Agents + BaseAgent + Commander
│   │   ├── api/             — REST Routes (/alerts, /approval, /providers) + /ws/trace WebSocket
│   │   ├── db/              — SQLAlchemy Session & Models (Case, AgentMessageRecord, etc.)
│   │   ├── llm/             — Fault-tolerant LLM router (NIM, Gemini, Ollama)
│   │   ├── orchestrator/    — LangGraph StateGraph pipeline execution
│   │   └── main.py          — FastAPI Application entrypoint
├── frontend/
│   ├── index.html           — Main SOC Dashboard + Standalone Demo Engine
│   ├── styles.css           — Vanilla CSS design system (4 themes: Cyber, Aesthetic, Pitch Black, Moon White)
│   └── app.js               — Live SSE, WebSocket client, SVG token telemetry & fallback engine
└── sentinel_mesh_complete_project_context.txt — Full technical context documentation
```

---

## 🚦 Quickstart (Local Development)

### 1. Backend Setup
```bash
cd sentinel_mesh/backend
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --port 8001
```
*API Swagger Docs*: `http://localhost:8001/docs`

### 2. Frontend Setup
```bash
python -m http.server 3000 --directory sentinel_mesh/frontend
```
*Frontend URL*: `http://localhost:3000`

---

## ☁️ Live Cloud Demo

View the live interactive application directly in your browser:  
🔗 **[https://sentinel-mesh-app.netlify.app](https://sentinel-mesh-app.netlify.app)**

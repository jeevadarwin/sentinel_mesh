# Sentinel Mesh — Autonomous Multi-Agent SOC Intelligence Platform

> **Hackathon project · Phase 1: Foundation**

Sentinel Mesh is an AI-powered Security Operations Centre (SOC) platform that uses a **multi-agent debate architecture** to autonomously triage security alerts. Two opposing LLM agents argue the threat vs. benign case; a coordinator agent weighs the debate and issues a structured verdict with MITRE ATT&CK mapping and a recommended action.

---

## Project Status

| Phase | Status | Description |
|-------|--------|-------------|
| **Phase 1 — Foundation** | ✅ Complete | Scaffolding, schemas, LLM provider abstraction, health endpoints |
| **Phase 2 — Alert Ingestion** | ✅ Complete | Alert store, SSE streaming, simulation replay, SOC dashboard |
| **Phase 3 — Enrichment** | ✅ Complete | AbuseIPDB enrichment, private-IP filtering, in-memory cache |
| Phase 4 — Agent Engine | 🔲 Planned | Multi-LLM debate (threat/benign agents) + coordinator verdict |
| Phase 5 — Dashboard Polish | 🔲 Planned | Verdict timeline, MITRE chip, confidence bar, SOAR actions |

---

## Architecture Overview

```
frontend/               — Plain HTML/CSS/JS SOC dashboard
backend/
  app/
    config.py           — Pydantic-settings typed config (reads .env)
    main.py             — FastAPI entrypoint + CORS
    models/             — Pydantic v2 schemas (Alert, Evidence, Agent, Decision)
    llm/
      provider.py       — NIM → Ollama fault-tolerant LLM router
      nim_client.py     — NVIDIA NIM API client
      ollama_client.py  — Local Ollama API client
    enrichment/
      utils.py          — is_private_ip() (ipaddress stdlib, RFC1918/loopback)
      abuseipdb_client.py — AbuseIPDB v2 /check client (never raises)
      service.py        — Orchestrator: alert_id → list[EnrichmentEvidence]
    routers/
      health.py         — /health, /health/ollama-models, /health/llm
      alerts.py         — /alerts/* (ingest, list, stream, simulate)
      enrichment.py     — /alerts/{id}/enrichment (with in-memory cache)
```

---

## Quickstart

### 1. Set up environment

```bash
cd sentinel_mesh/backend
cp .env.example .env
# Edit .env — fill in NIM_API_KEY, NIM_BASE_URL, NIM_MODEL at minimum.
```

### 2. Install dependencies

```bash
# Create and activate a virtual environment (recommended)
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Run the backend

```bash
# From the sentinel_mesh/backend/ directory:
uvicorn app.main:app --reload
```

The API will be available at `http://localhost:8000`.  
Interactive docs: `http://localhost:8000/docs`

### 4. Run the frontend

Open `sentinel_mesh/frontend/index.html` directly in your browser, **or** serve it with a simple static server to avoid browser CORS restrictions on `file://` origins:

```bash
# Using Python (no install needed):
python -m http.server 3000 --directory sentinel_mesh/frontend

# Then open:  http://localhost:3000
```

---

## Verification Endpoints (Phase 3 Acceptance Tests)

### Phase 1 — Health

| Endpoint | Expected response |
|----------|------------------|
| `GET /health` | `{"status": "ok"}` |
| `GET /health/llm` | `{"provider_used": "nim" or "ollama", "latency_ms": ..., "content_preview": "OK"}` |

### Phase 3 — Enrichment

| Endpoint | Expected response |
|----------|------------------|
| `GET /alerts/{id}/enrichment` | `list[EnrichmentEvidence]` — 200 even if AbuseIPDB unreachable |
| `GET /alerts/bad-id/enrichment` | `404 Not Found` |
| Second call to same `{id}` | Cache HIT in logs, no outbound API call |

---

## Environment Variables

Copy `.env.example` to `.env` and fill in:

| Variable | Default | Description |
|----------|---------|-------------|
| `NIM_API_KEY` | *(required)* | NVIDIA NIM API key |
| `NIM_BASE_URL` | *(required)* | NIM OpenAI-compatible base URL |
| `NIM_MODEL` | *(required)* | NIM model identifier |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Local Ollama server URL |
| `OLLAMA_MODEL` | `gemma4:latest` | Ollama fallback model tag |
| `ENRICHMENT_API_KEY` | *(empty)* | **AbuseIPDB API key** — get a free key at [abuseipdb.com](https://www.abuseipdb.com/register). If empty, enrichment still returns 200 with a `limitations` note. |
| `ENVIRONMENT` | `dev` | `dev` or `prod` |

---

## Ollama Setup (for local fallback)

```bash
# Install Ollama from https://ollama.ai, then:
ollama pull gemma4:latest
# Verify:
ollama list
```

---

## Schema Quick Reference

All Pydantic v2 models live in `backend/app/models/`. Each file has an
inline usage example in its module docstring.

| Model | File | Purpose |
|-------|------|---------|
| `Alert` | `alert.py` | Raw security alert from SIEM/IDS |
| `EnrichmentEvidence` | `enrichment.py` | Threat-intel evidence per indicator |
| `AgentArgument` | `agent_output.py` | Structured argument from one debate agent |
| `CoordinatorDecision` | `decision.py` | Final verdict from the coordinator |

---

## Tech Stack

- **Backend**: Python 3.11+, FastAPI, Pydantic v2, httpx
- **LLM providers**: NVIDIA NIM (primary), Ollama (local fallback)
- **Frontend**: Vanilla HTML/CSS/JS (no framework)
- **Config**: pydantic-settings + python-dotenv

---

*Built for hackathon — Phase 1 scaffolding only. No auth, no database, no Docker yet.*

"""
main.py — FastAPI application entrypoint for Sentinel Mesh backend.

Run with:
    cd sentinel_mesh/backend
    uvicorn app.main:app --reload

Phase 1: /health
Phase 2: /alerts  (ingestion, SSE streaming, simulation)
Phase 3: /alerts/{alert_id}/enrichment  (AbuseIPDB threat-intel)
Future phases will register:
    - /agents    (Phase 4 — agent debate)
    - /decisions (Phase 4 — coordinator verdicts)
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import health as health_router
from app.routers import alerts as alerts_router
from app.routers import enrichment as enrichment_router
from app.routers import providers as providers_router
from app.routers import decisions as decisions_router

# --------------------------------------------------------------------------- #
# Logging setup                                                                #
# --------------------------------------------------------------------------- #
# Configure at the application root — per-module loggers inherit this.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# FastAPI application                                                          #
# --------------------------------------------------------------------------- #

app = FastAPI(
    title="Sentinel Mesh — SOC Intelligence Platform",
    description=(
        "Autonomous Multi-Agent Security Operations Centre (SOC) platform. "
        "Uses a multi-LLM debate architecture to triage security alerts, "
        "enrich indicators with threat-intel, and issue actionable verdicts."
    ),
    version="0.4.0-phase4",
    docs_url="/docs",       # Swagger UI
    redoc_url="/redoc",     # ReDoc UI
)

# --------------------------------------------------------------------------- #
# CORS — allow the local frontend (any localhost port) during development      #
# --------------------------------------------------------------------------- #
# In production (ENVIRONMENT=prod) this list should be restricted to the
# specific origin(s) serving the frontend.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://localhost(:\d+)?",  # matches any localhost port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------------------------------- #
# Routers                                                                      #
# --------------------------------------------------------------------------- #
# Phase 1: health.
app.include_router(health_router.router)

# Phase 2: alert ingestion, in-memory store, SSE live feed.
app.include_router(alerts_router.router)

# Phase 3: threat-intel enrichment (GET /alerts/{alert_id}/enrichment)
app.include_router(enrichment_router.router)

# Phase 4: providers health and multi-agent debate decisions
app.include_router(providers_router.router)
app.include_router(decisions_router.router)


# --------------------------------------------------------------------------- #
# Startup / shutdown lifecycle hooks (stubs for later phases)                 #
# --------------------------------------------------------------------------- #

@app.on_event("startup")
async def on_startup() -> None:
    """
    Called once when the server starts.
    """
    logger.info("Sentinel Mesh backend starting up — Phase 4 (Multi-Agent Debate).")


@app.on_event("shutdown")
async def on_shutdown() -> None:
    """
    Called once when the server shuts down.
    """
    logger.info("Sentinel Mesh backend shutting down — Phase 4.")


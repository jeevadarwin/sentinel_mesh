"""
health.py — Health and readiness endpoints.

Routes
------
GET /health              — Basic liveness check (returns {"status": "ok"}).
GET /health/ollama-models — Lists installed Ollama model names.
GET /health/llm          — Verification endpoint: fires a trivial LLM call
                           and shows which provider (NIM or Ollama) responded.

These endpoints are the primary acceptance-test surface for Phase 1.
No authentication required — these are internal/ops endpoints.
"""

import logging

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.config import settings
from app.llm.provider import get_llm_response, LLMProviderUnavailable

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["Health"])


# --------------------------------------------------------------------------- #
# Response schemas (local to this router — not in models/ intentionally)      #
# --------------------------------------------------------------------------- #

class HealthResponse(BaseModel):
    status: str


class OllamaModelsResponse(BaseModel):
    models: list[str]


class LLMHealthResponse(BaseModel):
    provider_used: str
    latency_ms: float
    content_preview: str  # first 80 chars of the reply — enough for a smoke test


# --------------------------------------------------------------------------- #
# Endpoints                                                                    #
# --------------------------------------------------------------------------- #

@router.get(
    "",
    response_model=HealthResponse,
    summary="Basic liveness check",
)
async def health_check() -> HealthResponse:
    """Returns 200 OK when the server is running."""
    return HealthResponse(status="ok")


@router.get(
    "/ollama-models",
    response_model=OllamaModelsResponse,
    summary="List installed Ollama models",
)
async def ollama_models() -> OllamaModelsResponse:
    """
    Calls the local Ollama API (GET /api/tags) and returns the list of
    installed model names.

    Raises 503 if Ollama is not reachable.
    """
    url = f"{settings.ollama_base_url.rstrip('/')}/api/tags"

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url)
            response.raise_for_status()
    except (httpx.RequestError, httpx.HTTPStatusError) as exc:
        logger.error("Could not reach Ollama at %s: %s", url, exc)
        raise HTTPException(
            status_code=503,
            detail=f"Ollama unreachable at {settings.ollama_base_url}: {exc}",
        )

    data = response.json()

    # Ollama /api/tags response shape:
    # { "models": [ { "name": "gemma4:latest", ... }, ... ] }
    model_names: list[str] = [m["name"] for m in data.get("models", [])]

    return OllamaModelsResponse(models=model_names)


@router.get(
    "/llm",
    response_model=LLMHealthResponse,
    summary="LLM provider smoke test",
)
async def llm_health() -> LLMHealthResponse:
    """
    Fires a trivial prompt ('Say OK') through get_llm_response and returns:
      - which provider responded (nim / ollama)
      - round-trip latency in milliseconds
      - first 80 chars of the reply

    Use a bad NIM_BASE_URL in .env to force the Ollama fallback path and
    verify fault-tolerance is working correctly.
    """
    try:
        resp = await get_llm_response(
            prompt="Say OK",
            system_prompt="You are a health-check assistant. Reply with exactly the word OK.",
        )
    except LLMProviderUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    return LLMHealthResponse(
        provider_used=resp.provider_used,
        latency_ms=round(resp.latency_ms, 2),
        content_preview=resp.content[:80],
    )

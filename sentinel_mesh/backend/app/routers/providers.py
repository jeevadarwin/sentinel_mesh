"""
providers.py — Router for LLM provider health checks.

Provides:
    GET /providers/health — pings NIM, LM Studio, and Ollama independently
    and returns "up" or "down" for each.
"""

import asyncio
import logging
import httpx
from fastapi import APIRouter
from pydantic import BaseModel

from app.config import settings
from app.llm.nim_client import call_nim
from app.llm.gemini_client import call_gemini
from app.llm.lmstudio_client import call_lmstudio
from app.llm.ollama_client import call_ollama

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/providers", tags=["providers"])


class ProvidersHealthResponse(BaseModel):
    nim: str       # "up" or "down"
    gemini: str    # "up" or "down"
    lmstudio: str  # "up" or "down"
    ollama: str    # "up" or "down"


async def _check_nim() -> str:
    try:
        await asyncio.wait_for(call_nim(prompt="hi"), timeout=8.0)
        return "up"
    except Exception as exc:
        logger.debug("NIM health check down: %s", exc)
        return "down"


async def _check_gemini() -> str:
    try:
        await asyncio.wait_for(call_gemini(prompt="hi"), timeout=3.0)
        return "up"
    except Exception as exc:
        logger.debug("Gemini health check down: %s", exc)
        return "down"


async def _check_lmstudio() -> str:
    try:
        await asyncio.wait_for(call_lmstudio(prompt="hi"), timeout=3.0)
        return "up"
    except Exception as exc:
        logger.debug("LM Studio health check down: %s", exc)
        return "down"


async def _check_ollama() -> str:
    try:
        url = f"{settings.ollama_base_url.rstrip('/')}/api/tags"
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
        return "up"
    except Exception as exc:
        logger.debug("Ollama health check down: %s", exc)
        return "down"


@router.get("/health", response_model=ProvidersHealthResponse)
async def get_providers_health() -> ProvidersHealthResponse:
    """
    Pings all four providers (NIM, Gemini, LM Studio, Ollama) and returns up/down status.
    """
    nim_status, gemini_status, lmstudio_status, ollama_status = await asyncio.gather(
        _check_nim(),
        _check_gemini(),
        _check_lmstudio(),
        _check_ollama(),
    )

    return ProvidersHealthResponse(
        nim=nim_status,
        gemini=gemini_status,
        lmstudio=lmstudio_status,
        ollama=ollama_status,
    )

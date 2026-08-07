"""
provider.py — LLM provider abstraction (fault-tolerant orchestrator).

This is the single entry-point for all LLM calls in Sentinel Mesh.

Strategy
--------
1. Try NIM first (low latency, high quality).
2. On timeout / connection error / non-2xx from NIM → log a warning and
   fall back to the local Ollama server.
3. If both fail → raise LLMProviderUnavailable (never return empty content).

The NIM-specific and Ollama-specific HTTP logic live in their own modules;
this file only orchestrates the try/fallback flow.

Usage
-----
    from app.llm.provider import get_llm_response

    response = await get_llm_response(
        prompt="Classify this alert as benign or malicious.",
        system_prompt="You are a SOC analyst...",
    )
    print(response.content, response.provider_used, response.latency_ms)
"""

import logging
from dataclasses import dataclass

import httpx

from app.llm.nim_client import call_nim
from app.llm.gemini_client import call_gemini
from app.llm.groq_client import call_groq
from app.llm.ollama_client import call_ollama

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Response model                                                               #
# --------------------------------------------------------------------------- #

@dataclass
class LLMResponse:
    """
    Normalised response returned by get_llm_response regardless of which
    provider actually handled the request.
    """

    content: str
    """The text reply from the model."""

    provider_used: str
    """Which provider answered: 'nim', 'gemini', 'groq', or 'ollama'."""

    latency_ms: float
    """End-to-end round-trip time in milliseconds."""

    error: str | None = None


# --------------------------------------------------------------------------- #
# Custom exception                                                             #
# --------------------------------------------------------------------------- #

class LLMProviderUnavailable(Exception):
    """
    Raised when all LLM providers in the fallback chain fail to produce a response.
    Callers should surface this as a 503 Service Unavailable.
    """


# --------------------------------------------------------------------------- #
# Public interface                                                             #
# --------------------------------------------------------------------------- #

async def get_llm_response(
    prompt: str,
    system_prompt: str | None = None,
    response_format: str = "text",
    provider_chain: list[str] | None = None,
) -> LLMResponse:
    """
    Get an LLM response with configurable fallback chain.
    High/Critical chain: NIM → Groq → Ollama.
    Low/Medium chain: Gemini → Groq → Ollama.

    Retry policy: NO automatic retries per provider — each is a single
    attempt. On any exception (timeout, 429, connection error) the chain
    immediately advances to the next provider. This prevents silent quota
    exhaustion from repeated retries.
    """
    chain = provider_chain or ["nim", "groq", "ollama"]

    for provider in chain:
        p = provider.lower().strip()
        if p == "nim":
            try:
                result = await call_nim(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    response_format=response_format,
                )
                return LLMResponse(
                    content=result["content"],
                    provider_used="nim",
                    latency_ms=result["latency_ms"],
                )
            except Exception as exc:
                logger.warning("NIM call failed (%s) — trying next provider in chain.", exc)

        elif p == "gemini":
            try:
                result = await call_gemini(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    response_format=response_format,
                )
                return LLMResponse(
                    content=result["content"],
                    provider_used="gemini",
                    latency_ms=result["latency_ms"],
                )
            except Exception as exc:
                logger.warning("Gemini call failed (%s) — trying next provider in chain.", exc)

        elif p == "groq":
            try:
                result = await call_groq(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    response_format=response_format,
                )
                return LLMResponse(
                    content=result["content"],
                    provider_used="groq",
                    latency_ms=result["latency_ms"],
                )
            except Exception as exc:
                logger.warning("Groq call failed (%s) — trying next provider in chain.", exc)

        elif p in ("ollama", "lmstudio", "local"):
            try:
                result = await call_ollama(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    response_format=response_format,
                )
                return LLMResponse(
                    content=result["content"],
                    provider_used="ollama",
                    latency_ms=result["latency_ms"],
                )
            except Exception as exc:
                logger.warning("Ollama local AI call failed (%s) — trying next provider in chain.", exc)

    raise LLMProviderUnavailable(
        f"All LLM providers in chain {chain} are unavailable."
    )


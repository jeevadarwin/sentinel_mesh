"""
ollama_client.py — Local Ollama LLM client (fallback provider).

Encapsulates all Ollama-specific HTTP logic.
Ollama exposes a slightly different API shape than OpenAI, so we normalise
the response here before returning it to provider.py.

Phase 1: structure + docstrings.  Streaming support can be added in Phase 2.
"""

import time
import logging

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# Ollama can be slow on local generation when processing queued requests.
OLLAMA_TIMEOUT_SECONDS = 120.0


async def call_ollama(
    prompt: str,
    system_prompt: str | None = None,
    response_format: str = "text",
) -> dict:
    """
    Send a chat request to the local Ollama /api/chat endpoint.

    Returns a dict with keys:
        content       (str)   — model reply text
        latency_ms    (float) — round-trip time in milliseconds

    Raises:
        httpx.TimeoutException  — if Ollama doesn't respond in time
        httpx.RequestError      — on connection failures (e.g. Ollama not running)
        httpx.HTTPStatusError   — on 4xx / 5xx

    The caller (provider.py) handles exceptions and raises LLMProviderUnavailable
    if both providers fail.
    """
    messages = []

    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})

    messages.append({"role": "user", "content": prompt})

    payload: dict = {
        "model": settings.ollama_model,
        "messages": messages,
        "stream": False,  # disable streaming for now; Phase 2 can enable it
    }

    # Ollama chat endpoint
    url = f"{settings.ollama_base_url.rstrip('/')}/api/chat"

    logger.debug("Calling Ollama at %s with model=%s", url, settings.ollama_model)

    t0 = time.monotonic()

    async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT_SECONDS) as client:
        response = await client.post(url, json=payload)
        response.raise_for_status()

    latency_ms = (time.monotonic() - t0) * 1000

    data = response.json()

    # Ollama /api/chat non-streaming response shape:
    # { "message": { "role": "assistant", "content": "..." }, ... }
    content = data["message"]["content"]

    logger.info("Ollama responded in %.1f ms", latency_ms)

    return {"content": content, "latency_ms": latency_ms}

"""
nim_client.py — NVIDIA NIM LLM client.

Encapsulates all NIM-specific HTTP request/response logic.
The provider.py orchestrator calls `call_nim(...)` and receives a plain
dict that maps to LLMResponse fields, keeping provider.py thin.

Phase 1: structure + docstrings only.  Actual prompt templating and
         structured-output parsing are added in Phase 2.
"""

import time
import logging

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# NIM timeout in seconds — short so fallback triggers quickly.
NIM_TIMEOUT_SECONDS = 10.0


async def call_nim(
    prompt: str,
    system_prompt: str | None = None,
    response_format: str = "text",
) -> dict:
    """
    Send a chat-completion request to the NIM endpoint.

    Returns a dict with keys:
        content       (str)   — model reply text
        latency_ms    (float) — round-trip time in milliseconds

    Raises:
        httpx.TimeoutException   — if NIM doesn't respond within NIM_TIMEOUT_SECONDS
        httpx.HTTPStatusError    — on 4xx / 5xx (caller inspects for rate-limit)
        httpx.RequestError       — on connection failures

    The caller (provider.py) is responsible for deciding whether to fall back.
    """
    messages = []

    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})

    messages.append({"role": "user", "content": prompt})

    payload: dict = {
        "model": settings.nim_model,
        "messages": messages,
        # Phase 2 will populate "response_format" for JSON-mode outputs.
    }

    headers = {
        "Authorization": f"Bearer {settings.nim_api_key}",
        "Content-Type": "application/json",
    }

    # Construct the chat completions URL from the configured base URL.
    url = f"{settings.nim_base_url.rstrip('/')}/chat/completions"

    logger.debug("Calling NIM at %s with model=%s", url, settings.nim_model)

    t0 = time.monotonic()

    async with httpx.AsyncClient(timeout=NIM_TIMEOUT_SECONDS) as client:
        response = await client.post(url, json=payload, headers=headers)
        response.raise_for_status()  # propagate 4xx/5xx to caller

    latency_ms = (time.monotonic() - t0) * 1000

    data = response.json()

    # OpenAI-compatible response: choices[0].message.content
    content = data["choices"][0]["message"]["content"]

    logger.info("NIM responded in %.1f ms", latency_ms)

    return {"content": content, "latency_ms": latency_ms}

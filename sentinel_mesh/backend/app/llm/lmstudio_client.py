"""
lmstudio_client.py — LM Studio LLM client (middle fallback provider).

Encapsulates all LM Studio HTTP request/response logic.
LM Studio exposes an OpenAI-compatible endpoint at /v1/chat/completions.
The provider.py orchestrator calls `call_lmstudio(...)` and receives a dict
matching LLMResponse requirements.
"""

import time
import logging
import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# LM Studio timeout in seconds — short so fallback to Ollama triggers quickly if not running.
LMSTUDIO_TIMEOUT_SECONDS = 3.0


async def call_lmstudio(
    prompt: str,
    system_prompt: str | None = None,
    response_format: str = "text",
) -> dict:
    """
    Send a chat-completion request to the local LM Studio OpenAI-compatible endpoint.

    Returns a dict with keys:
        content       (str)   — model reply text
        latency_ms    (float) — round-trip time in milliseconds

    Raises:
        httpx.TimeoutException  — if LM Studio doesn't respond in time
        httpx.RequestError      — on connection failures (e.g. LM Studio not running)
        httpx.HTTPStatusError   — on 4xx / 5xx
    """
    messages = []

    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})

    messages.append({"role": "user", "content": prompt})

    payload: dict = {
        "model": settings.lmstudio_model,
        "messages": messages,
        "temperature": 0.2,
    }

    base_url = settings.lmstudio_base_url.rstrip("/")
    url = f"{base_url}/chat/completions"

    headers = {
        "Content-Type": "application/json",
    }

    logger.debug("Calling LM Studio at %s with model=%s", url, settings.lmstudio_model)

    t0 = time.monotonic()

    async with httpx.AsyncClient(timeout=LMSTUDIO_TIMEOUT_SECONDS) as client:
        response = await client.post(url, json=payload, headers=headers)
        response.raise_for_status()

    latency_ms = (time.monotonic() - t0) * 1000

    data = response.json()

    # OpenAI-compatible response: choices[0].message.content
    content = data["choices"][0]["message"]["content"]

    logger.info("LM Studio responded in %.1f ms", latency_ms)

    return {"content": content, "latency_ms": latency_ms}

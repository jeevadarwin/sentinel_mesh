"""
groq_client.py — Groq Cloud LLM client.

Groq exposes an OpenAI-compatible /chat/completions endpoint, so this
client is structurally identical to nim_client.py.

Endpoint: https://api.groq.com/openai/v1/chat/completions
Model:    llama-3.3-70b-versatile  (free tier, very fast)

The provider.py orchestrator calls `call_groq(...)` and receives a plain
dict identical in shape to what NIM and Gemini return.
"""

import time
import logging

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# Groq is very fast (hardware-accelerated inference) — keep timeout tight.
GROQ_TIMEOUT_SECONDS = 8.0

GROQ_BASE_URL = "https://api.groq.com/openai/v1"


async def call_groq(
    prompt: str,
    system_prompt: str | None = None,
    response_format: str = "text",
) -> dict:
    """
    Send a chat-completion request to the Groq API.

    Returns a dict with keys:
        content       (str)   — model reply text
        latency_ms    (float) — round-trip time in milliseconds

    Raises:
        httpx.TimeoutException   — if Groq doesn't respond within GROQ_TIMEOUT_SECONDS
        httpx.HTTPStatusError    — on 4xx / 5xx (e.g. 429 rate-limit)
        httpx.RequestError       — on connection failures or missing API key
    """
    if not settings.groq_api_key:
        raise httpx.RequestError("GROQ_API_KEY not configured in .env")

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    payload: dict = {
        "model": settings.groq_model,
        "messages": messages,
    }

    # Groq supports JSON mode via response_format (OpenAI-compatible)
    if response_format == "json":
        payload["response_format"] = {"type": "json_object"}

    headers = {
        "Authorization": f"Bearer {settings.groq_api_key}",
        "Content-Type": "application/json",
    }

    url = f"{GROQ_BASE_URL}/chat/completions"

    logger.debug("Calling Groq at %s with model=%s", url, settings.groq_model)

    t0 = time.monotonic()

    async with httpx.AsyncClient(timeout=GROQ_TIMEOUT_SECONDS) as client:
        response = await client.post(url, json=payload, headers=headers)
        response.raise_for_status()

    latency_ms = (time.monotonic() - t0) * 1000

    data = response.json()

    # OpenAI-compatible response: choices[0].message.content
    content = data["choices"][0]["message"]["content"]

    logger.info("Groq responded in %.1f ms", latency_ms)

    return {"content": content, "latency_ms": latency_ms}

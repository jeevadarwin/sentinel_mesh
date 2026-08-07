"""
gemini_client.py — Google Gemini LLM client.

Encapsulates all Gemini REST API request/response logic using httpx.
Endpoint: https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent
"""

import time
import logging
import httpx

from app.config import settings

logger = logging.getLogger(__name__)

GEMINI_TIMEOUT_SECONDS = 15.0


async def call_gemini(
    prompt: str,
    system_prompt: str | None = None,
    response_format: str = "text",
) -> dict:
    """
    Send a generateContent request to Google Gemini API.

    Returns a dict with keys:
        content       (str)   — model reply text
        latency_ms    (float) — round-trip time in milliseconds

    Raises:
        httpx.TimeoutException  — if Gemini doesn't respond in time
        httpx.RequestError      — on connection failures
        httpx.HTTPStatusError   — on 4xx / 5xx
    """
    if not settings.gemini_api_key:
        raise httpx.RequestError("GEMINI_API_KEY not configured in .env")

    model_name = settings.gemini_model or "gemini-1.5-flash"
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={settings.gemini_api_key}"

    contents = [
        {
            "role": "user",
            "parts": [{"text": prompt}],
        }
    ]

    payload: dict = {"contents": contents}

    if system_prompt:
        payload["systemInstruction"] = {
            "parts": [{"text": system_prompt}]
        }

    if response_format == "json":
        payload["generationConfig"] = {
            "responseMimeType": "application/json"
        }

    headers = {
        "Content-Type": "application/json",
    }

    logger.debug("Calling Gemini API at model=%s", model_name)

    t0 = time.monotonic()

    async with httpx.AsyncClient(timeout=GEMINI_TIMEOUT_SECONDS) as client:
        response = await client.post(url, json=payload, headers=headers)
        response.raise_for_status()

    latency_ms = (time.monotonic() - t0) * 1000

    data = response.json()

    # Response shape: candidates[0].content.parts[0].text
    try:
        content = data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError) as exc:
        raise httpx.RequestError(f"Unexpected response structure from Gemini API: {data}") from exc

    logger.info("Gemini responded in %.1f ms", latency_ms)

    return {"content": content, "latency_ms": latency_ms}

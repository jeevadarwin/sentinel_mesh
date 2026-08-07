import socket
import asyncio
import logging
import httpx
from fastapi import APIRouter
from pydantic import BaseModel

from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/providers", tags=["providers"])


class ProvidersHealthResponse(BaseModel):
    nim: str          # "up" or "down"
    gemini: str       # "up" or "down"
    local: str        # "up" or "down"
    active_cloud: str # "online" | "airgap"


def _is_online() -> bool:
    """Instant 0.8s socket check for active internet connectivity."""
    try:
        sock = socket.create_connection(("1.1.1.1", 53), timeout=0.8)
        sock.close()
        return True
    except OSError:
        pass
    try:
        sock = socket.create_connection(("8.8.8.8", 53), timeout=0.8)
        sock.close()
        return True
    except OSError:
        return False


async def _check_ollama() -> str:
    try:
        url = f"{settings.ollama_base_url.rstrip('/')}/api/tags"
        async with httpx.AsyncClient(timeout=1.5) as client:
            resp = await client.get(url)
            resp.raise_for_status()
        return "up"
    except Exception:
        return "down"


@router.get("/health", response_model=ProvidersHealthResponse)
async def get_providers_health() -> ProvidersHealthResponse:
    """
    Returns instant provider health:
    - Online mode: NIM=up (GREEN), Gemini=up (GREEN), Local=down (RED)
    - Offline mode: NIM=down (RED), Gemini=down (RED), Local=up (GREEN)
    """
    online = await asyncio.to_thread(_is_online)
    ollama_up = await _check_ollama()

    if online and bool(settings.nim_api_key):
        nim_status = "up"
        gemini_status = "up"
        local_status = "down"
        active_cloud = "online"
    else:
        nim_status = "down"
        gemini_status = "down"
        local_status = "up" if ollama_up == "up" else "down"
        active_cloud = "airgap"

    return ProvidersHealthResponse(
        nim=nim_status,
        gemini=gemini_status,
        local=local_status,
        active_cloud=active_cloud,
    )

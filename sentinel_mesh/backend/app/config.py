"""
config.py — Centralised settings for Sentinel Mesh backend.

All configuration is read from environment variables (or a .env file at
project root).  Pydantic-settings validates and type-checks every value at
startup, so misconfiguration fails loudly instead of silently at runtime.

Usage:
    from app.config import settings
    print(settings.nim_model)
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    """
    Typed, validated application settings.
    Reads from environment variables and .env file automatically.
    """

    # ------------------------------------------------------------------ #
    # NIM (NVIDIA Inference Microservices) — primary LLM provider          #
    # ------------------------------------------------------------------ #
    nim_api_key: str = Field(
        ...,
        description="NVIDIA NIM API key.  Required for primary LLM provider.",
    )
    nim_base_url: str = Field(
        ...,
        description="Base URL for the NIM OpenAI-compatible endpoint.",
    )
    nim_model: str = Field(
        ...,
        description="NIM model identifier, e.g. meta/llama-3.1-70b-instruct.",
    )

    # ------------------------------------------------------------------ #
    # Google Gemini — cloud LLM provider                                  #
    # ------------------------------------------------------------------ #
    gemini_api_key: str = Field(
        default="",
        description="Google Gemini API key.",
    )
    gemini_model: str = Field(
        default="gemini-1.5-flash",
        description="Gemini model tag.",
    )

    # ------------------------------------------------------------------ #
    # Ollama — local fallback LLM provider                                #
    # ------------------------------------------------------------------ #
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Base URL for the local Ollama server.",
    )
    ollama_model: str = Field(
        default="gemma4:latest",
        description="Ollama model tag to use as fallback.",
    )

    # ------------------------------------------------------------------ #
    # LM Studio — middle fallback LLM provider                           #
    # ------------------------------------------------------------------ #
    lmstudio_base_url: str = Field(
        default="http://localhost:1234/v1",
        description="Base URL for the local LM Studio server.",
    )
    lmstudio_model: str = Field(
        default="local-model",
        description="LM Studio model identifier.",
    )

    # ------------------------------------------------------------------ #
    # Enrichment — placeholder; populated in Phase 3                      #
    # ------------------------------------------------------------------ #
    enrichment_api_key: str = Field(
        default="",
        description="API key for threat-intel enrichment provider (Phase 3).",
    )

    # ------------------------------------------------------------------ #
    # General                                                             #
    # ------------------------------------------------------------------ #
    environment: str = Field(
        default="dev",
        description="Deployment environment: 'dev' or 'prod'.",
    )

    # Tell pydantic-settings to load from a .env file in the CWD.
    # The `env_file` path is relative to where the process is started from
    # (typically the backend/ directory when running uvicorn).
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,  # NIM_API_KEY and nim_api_key both work
        extra="ignore",        # silently ignore unknown env vars
    )


# Module-level singleton — import and use `settings` everywhere.
settings = Settings()

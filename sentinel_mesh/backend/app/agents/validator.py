"""
validator.py — Schema validation and retry helper for Sentinel Mesh agent verdicts.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Awaitable, Callable

from pydantic import ValidationError
from app.models.agent_output import AgentVerdict

logger = logging.getLogger(__name__)


def extract_json_dict(text: str) -> dict:
    """Extract dict from raw string, codeblock, or regex match."""
    try:
        return json.loads(text)
    except Exception:
        pass
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    m = re.search(r"(\{.*\})", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    return {}


async def parse_and_validate_verdict(
    content: str,
    retry_fn: Callable[[str], Awaitable[str]] | None = None,
) -> AgentVerdict:
    """
    Parse content into AgentVerdict model.
    If validation fails and retry_fn is given, retries once with an explicit
    correction message before falling back to manual review flag.
    """
    raw_dict = extract_json_dict(content)
    try:
        return AgentVerdict.model_validate(raw_dict)
    except (ValidationError, Exception) as exc:
        logger.warning("AgentVerdict validation failed on initial attempt: %s", exc)
        if retry_fn is not None:
            logger.info("Retrying LLM call once with schema correction message...")
            correction_prompt = (
                f"Your last output didn't match the required schema error: {exc}. "
                "Please respond ONLY with valid JSON matching:\n"
                '{\n'
                '  "verdict": "malicious" | "benign" | "uncertain",\n'
                '  "confidence": <float between 0.0 and 1.0>,\n'
                '  "evidence": ["point 1", "point 2"],\n'
                '  "recommended_action": "block" | "isolate" | "monitor" | "none"\n'
                '}'
            )
            try:
                new_content = await retry_fn(correction_prompt)
                new_dict = extract_json_dict(new_content)
                return AgentVerdict.model_validate(new_dict)
            except Exception as retry_exc:
                logger.error("Retry LLM output also failed schema validation: %s", retry_exc)

        return AgentVerdict(
            verdict="uncertain",
            confidence=0.5,
            evidence=["Output failed schema validation — flagged for manual review"],
            recommended_action="none",
        )

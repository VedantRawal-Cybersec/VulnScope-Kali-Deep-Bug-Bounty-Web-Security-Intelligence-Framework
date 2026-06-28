from __future__ import annotations

import re
from typing import Any

SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"sk-proj-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"sk-or-v1-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"gsk_[A-Za-z0-9_\-]{20,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),
    re.compile(r"AQ\.[A-Za-z0-9_\-\.]{20,}"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password|authorization)\s*[:=]\s*['\"]?[^\s'\"]+"),
]

BLOCKED_AI_ACTIONS = [
    "generate exploit chain",
    "bypass rate limits",
    "credential capture",
    "database dump",
    "brute force",
    "stealth scanning",
    "out of scope scanning",
    "auto exploit",
]


def redact_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: redact_secrets(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, str):
        redacted = value
        for pattern in SECRET_PATTERNS:
            redacted = pattern.sub("[REDACTED_SECRET]", redacted)
        return redacted
    return value


def build_ai_safety_instruction() -> str:
    return """
You are the AI Analyst Engine inside VulnScope-Kali.
Operate only as a defensive, authorized security analyst.
Do not generate exploit chains, stealth instructions, brute force logic, credential capture steps, database dumping instructions, or out-of-scope scanning guidance.
Analyze only the provided evidence.
Classify findings as confirmed observation, manual validation required, weak signal, likely false positive, or report-ready only when the evidence is strong.
Always prefer safe manual validation steps and professional remediation.
Return compact JSON only.
""".strip()


def ai_action_allowed(action_text: str) -> bool:
    lowered = action_text.lower()
    return not any(blocked in lowered for blocked in BLOCKED_AI_ACTIONS)

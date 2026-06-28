from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class FirewallResult:
    allowed: bool
    reason: str
    redacted_text: str
    flags: list[str]


SECRET_PATTERNS = [
    ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9._\-]{20,}", re.I)),
    ("api_key", re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9._\-]{12,}")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----")),
    ("cookie", re.compile(r"(?i)(cookie|set-cookie)\s*[:=].{10,}")),
]

INJECTION_PATTERNS = [
    re.compile(r"ignore (all )?(previous|above) instructions", re.I),
    re.compile(r"reveal (system|developer|hidden) (prompt|instructions)", re.I),
    re.compile(r"disable (safety|guardrails|filters)", re.I),
    re.compile(r"exfiltrate|steal|dump secrets|bypass mfa|bypass captcha", re.I),
]


def inspect_text(text: str) -> FirewallResult:
    flags: list[str] = []
    redacted = text
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(redacted):
            flags.append(name)
            redacted = pattern.sub(f"<{name.upper()}_REDACTED>", redacted)
    for pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            flags.append("prompt_injection_like_text")
    allowed = "prompt_injection_like_text" not in flags
    reason = "allowed with redaction" if allowed else "blocked prompt-injection-like content"
    return FirewallResult(allowed=allowed, reason=reason, redacted_text=redacted, flags=flags)


def sanitize_evidence_for_ai(data: Any) -> Any:
    if isinstance(data, str):
        return inspect_text(data).redacted_text
    if isinstance(data, list):
        return [sanitize_evidence_for_ai(item) for item in data]
    if isinstance(data, dict):
        clean = {}
        for key, value in data.items():
            if str(key).lower() in {"password", "token", "secret", "authorization", "cookie", "set-cookie"}:
                clean[key] = "<REDACTED>"
            else:
                clean[key] = sanitize_evidence_for_ai(value)
        return clean
    return data

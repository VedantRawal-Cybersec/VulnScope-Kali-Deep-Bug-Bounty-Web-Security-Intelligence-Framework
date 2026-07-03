#!/usr/bin/env python3
from __future__ import annotations

import base64
import html
import re
from dataclasses import asdict, dataclass
from typing import Any

SECRET_RE = re.compile(r"(?i)(authorization|cookie|set-cookie|api[_-]?key|token|secret|password|passwd|bearer)\s*[:=]\s*([^\s;,&]+)")
LONG_B64_RE = re.compile(r"(?i)(?:[A-Z0-9+/]{80,}={0,2})")
SCRIPT_RE = re.compile(r"(?is)<script\b[^>]*>.*?</script>")
STYLE_RE = re.compile(r"(?is)<style\b[^>]*>.*?</style>")
TAG_RE = re.compile(r"(?s)<[^>]+>")
PROMPT_INJECTION_HINTS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "system prompt",
    "developer message",
    "you are chatgpt",
    "reveal your instructions",
    "exfiltrate",
    "send this secret",
    "run command",
    "tool call",
]


@dataclass
class SanitizedEvidence:
    original_chars: int
    sanitized_chars: int
    redacted: bool
    prompt_injection_suspected: bool
    observations: list[str]
    text: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def mask_secrets(text: str) -> tuple[str, bool]:
    redacted = False

    def repl(match: re.Match[str]) -> str:
        nonlocal redacted
        redacted = True
        return f"{match.group(1)}=<redacted>"

    text = SECRET_RE.sub(repl, text or "")
    if LONG_B64_RE.search(text):
        redacted = True
        text = LONG_B64_RE.sub("<redacted-base64-blob>", text)
    return text, redacted


def strip_html(raw: str) -> str:
    text = SCRIPT_RE.sub(" ", raw or "")
    text = STYLE_RE.sub(" ", text)
    text = TAG_RE.sub(" ", text)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def detect_prompt_injection(text: str) -> bool:
    low = (text or "").lower()
    return any(hint in low for hint in PROMPT_INJECTION_HINTS)


def sanitize_for_llm(value: Any, *, max_chars: int = 5000) -> SanitizedEvidence:
    raw = value if isinstance(value, str) else repr(value)
    original_len = len(raw)
    cleaned = strip_html(raw)
    cleaned, redacted = mask_secrets(cleaned)
    suspected = detect_prompt_injection(cleaned)
    observations: list[str] = []
    if redacted:
        observations.append("sensitive-looking values were redacted")
    if suspected:
        observations.append("prompt-injection-like text was detected and treated as untrusted page content")
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars] + "…"
        observations.append(f"content truncated to {max_chars} chars")
    if not observations:
        observations.append("content sanitized")
    return SanitizedEvidence(original_chars=original_len, sanitized_chars=len(cleaned), redacted=redacted, prompt_injection_suspected=suspected, observations=observations, text=cleaned)


def sanitize_evidence_object(evidence: dict[str, Any], *, max_chars: int = 5000) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in evidence.items():
        if key.lower() in {"body", "html", "response_text", "request_headers", "response_headers", "cookie", "authorization"}:
            safe[key] = sanitize_for_llm(value, max_chars=max_chars).to_dict()
        else:
            if isinstance(value, str):
                safe[key] = mask_secrets(value[:max_chars])[0]
            else:
                safe[key] = value
    return safe

#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable
from urllib.parse import urlparse, urlunparse

import requests

from core.prompt_injection_guard import sanitize_evidence_object, sanitize_for_llm


@dataclass
class LLMHealth:
    ok: bool
    provider: str
    base_url: str
    chat_url: str
    tags_url: str
    fast_model: str
    deep_model: str
    report_model: str
    transport_ok: bool = False
    model_available: bool = False
    generation_ok: bool = False
    transport_status: str = "unknown"
    model_status: str = "unknown"
    generation_status: str = "unknown"
    mode: str = "deterministic_fallback"
    latency_ms: int = 0
    generation_latency_ms: int = 0
    error: str = ""
    fallback: str = "deterministic"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LLMResponse:
    ok: bool
    source: str
    model: str
    content: str = ""
    parsed: dict[str, Any] | None = None
    public_reasoning: list[str] | None = None
    latency_ms: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _base_from_url(url: str) -> str:
    raw = url or os.getenv("VULNSCOPE_OLLAMA_BASE", "http://localhost:11434")
    parsed = urlparse(raw)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc or parsed.path.split("/")[0]
    return urlunparse((scheme, netloc, "", "", "", "")).rstrip("/")


def _extract_json(text: str) -> dict[str, Any]:
    text = (text or "").strip()
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            parsed = json.loads(text[start : end + 1])
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


class LLMGateway:
    """Single Ollama entry point for planning, public reasoning, validation, and reports."""

    def __init__(self, *, ollama_url: str | None = None, fast_model: str | None = None, deep_model: str | None = None, report_model: str | None = None, timeout: int | None = None, health_mode: str | None = None) -> None:
        env_url = ollama_url or os.getenv("VULNSCOPE_OLLAMA_URL") or os.getenv("VULNSCOPE_OLLAMA_BASE") or "http://localhost:11434/api/chat"
        self.base_url = _base_from_url(env_url)
        self.chat_url = self.base_url + "/api/chat"
        self.generate_url = self.base_url + "/api/generate"
        self.tags_url = self.base_url + "/api/tags"
        default_model = os.getenv("VULNSCOPE_OLLAMA_MODEL", "qwen2.5:3b")
        self.fast_model = fast_model or os.getenv("VULNSCOPE_FAST_MODEL", default_model)
        self.deep_model = deep_model or os.getenv("VULNSCOPE_DEEP_MODEL", self.fast_model)
        self.report_model = report_model or os.getenv("VULNSCOPE_REPORT_MODEL", self.fast_model)
        self.timeout = max(3, int(timeout or os.getenv("VULNSCOPE_OLLAMA_TIMEOUT", "60")))
        self.health_mode = (health_mode or os.getenv("VULNSCOPE_LLM_HEALTH_MODE", "tags-only")).strip().lower()
        if self.health_mode not in {"tags-only", "full", "disabled"}:
            self.health_mode = "tags-only"
        self.session = requests.Session()
        self._health_cache: LLMHealth | None = None

    def health_check(self, *, force: bool = False) -> LLMHealth:
        if self._health_cache is not None and not force:
            return self._health_cache
        started = time.time()
        health = LLMHealth(False, "ollama", self.base_url, self.chat_url, self.tags_url, self.fast_model, self.deep_model, self.report_model)
        if self.health_mode == "disabled":
            health.transport_status = "skipped"
            health.model_status = "skipped"
            health.generation_status = "disabled"
            health.mode = "deterministic_fallback"
            health.error = "LLM health check disabled"
            self._health_cache = health
            return health
        try:
            response = self.session.get(self.tags_url, timeout=min(self.timeout, 10))
            health.latency_ms = int((time.time() - started) * 1000)
            if response.status_code != 200:
                health.transport_status = f"http_{response.status_code}"
                health.error = f"tags HTTP {response.status_code}"
                self._health_cache = health
                return health
            health.transport_ok = True
            health.transport_status = "ok"
            payload = response.json()
            names = {str(item.get("name") or item.get("model") or "") for item in payload.get("models", [])}
            health.model_available = self.fast_model in names or any(name.startswith(self.fast_model + ":") for name in names)
            health.model_status = "available" if health.model_available else "missing"
            if not health.model_available:
                health.error = f"model `{self.fast_model}` not found"
                self._health_cache = health
                return health
            if self.health_mode == "tags-only":
                health.ok = True
                health.generation_status = "skipped"
                health.mode = "llm_available_tags_only"
                self._health_cache = health
                return health
            gen_started = time.time()
            quick = self.chat_json(messages=[{"role": "user", "content": "Return JSON only: {\"ok\": true}"}], model_role="fast", timeout=self.timeout, force_no_health=True)
            health.generation_latency_ms = int((time.time() - gen_started) * 1000)
            health.generation_ok = quick.ok and bool((quick.parsed or {}).get("ok", True))
            health.generation_status = "ok" if health.generation_ok else "timeout_or_invalid"
            health.ok = bool(health.transport_ok and health.model_available and health.generation_ok)
            health.mode = "llm_generation_ready" if health.ok else "deterministic_fallback"
            if not health.ok:
                health.error = quick.error or "quick JSON prompt failed"
            self._health_cache = health
            return health
        except Exception as exc:
            health.latency_ms = int((time.time() - started) * 1000)
            health.transport_status = "error"
            health.error = str(exc)[:500]
            self._health_cache = health
            return health

    def _model_for_role(self, model_role: str) -> str:
        if model_role == "deep":
            return self.deep_model
        if model_role == "report":
            return self.report_model
        return self.fast_model

    def _generation_allowed(self, health: LLMHealth) -> tuple[bool, str]:
        if not (health.transport_ok and health.model_available):
            return False, health.error or "Ollama unavailable"
        if self.health_mode == "tags-only" and health.generation_status == "skipped":
            return False, "generation skipped by tags-only health mode"
        if self.health_mode == "disabled":
            return False, "LLM disabled"
        return True, "generation allowed"

    def chat_json(self, *, messages: list[dict[str, str]], model_role: str = "fast", timeout: int | None = None, force_no_health: bool = False) -> LLMResponse:
        if not force_no_health:
            health = self.health_check()
            allowed, reason = self._generation_allowed(health)
            if not allowed:
                return LLMResponse(False, "fallback", self._model_for_role(model_role), error=reason)
        model = self._model_for_role(model_role)
        started = time.time()
        try:
            response = self.session.post(self.chat_url, json={"model": model, "messages": messages, "stream": False, "format": "json", "options": {"temperature": 0.1}}, timeout=timeout or self.timeout)
            latency = int((time.time() - started) * 1000)
            if response.status_code != 200:
                return LLMResponse(False, "ollama", model, latency_ms=latency, error=f"chat HTTP {response.status_code}")
            payload = response.json()
            content = str((payload.get("message") or {}).get("content") or payload.get("response") or "")
            parsed = _extract_json(content)
            return LLMResponse(bool(parsed), "ollama", model, content=content, parsed=parsed, public_reasoning=list(map(str, parsed.get("public_reasoning", []))) if isinstance(parsed.get("public_reasoning"), list) else [], latency_ms=latency, error="" if parsed else "model did not return valid JSON")
        except Exception as exc:
            return LLMResponse(False, "fallback", model, latency_ms=int((time.time() - started) * 1000), error=str(exc)[:500])

    def stream_public_reasoning(self, *, messages: list[dict[str, str]], model_role: str = "fast", on_chunk: Callable[[str], None] | None = None, timeout: int | None = None) -> LLMResponse:
        health = self.health_check()
        model = self._model_for_role(model_role)
        allowed, reason = self._generation_allowed(health)
        if not allowed:
            return LLMResponse(False, "fallback", model, error=reason)
        started = time.time()
        collected: list[str] = []
        try:
            response = self.session.post(self.chat_url, json={"model": model, "messages": messages, "stream": True, "options": {"temperature": 0.1}}, stream=True, timeout=timeout or self.timeout)
            if response.status_code != 200:
                return LLMResponse(False, "ollama", model, error=f"chat stream HTTP {response.status_code}")
            buffer = ""
            for line in response.iter_lines(decode_unicode=True):
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except Exception:
                    continue
                piece = str((item.get("message") or {}).get("content") or item.get("response") or "")
                if not piece:
                    continue
                buffer += piece
                if "\n" in buffer or len(buffer) > 180:
                    safe_piece = sanitize_for_llm(buffer, max_chars=500).text
                    collected.append(safe_piece)
                    if on_chunk:
                        on_chunk(safe_piece)
                    buffer = ""
                if item.get("done"):
                    break
            if buffer.strip():
                safe_piece = sanitize_for_llm(buffer, max_chars=500).text
                collected.append(safe_piece)
                if on_chunk:
                    on_chunk(safe_piece)
            return LLMResponse(True, "ollama", model, content="\n".join(collected), public_reasoning=collected, latency_ms=int((time.time() - started) * 1000))
        except Exception as exc:
            return LLMResponse(False, "fallback", model, content="\n".join(collected), public_reasoning=collected, latency_ms=int((time.time() - started) * 1000), error=str(exc)[:500])

    def plan_actions(self, context: dict[str, Any], *, model_role: str = "fast") -> LLMResponse:
        health = self.health_check()
        if health.transport_ok and health.model_available and health.generation_status == "skipped":
            reasoning = ["Ollama transport and model are available, but generation is skipped by health policy; deterministic scan planning remains active."]
            return LLMResponse(True, "fallback", self._model_for_role(model_role), parsed={"public_reasoning": reasoning, "actions": []}, public_reasoning=reasoning)
        safe_context = sanitize_evidence_object(context, max_chars=5000)
        system = "You are VulnScope's defensive planning assistant. Return JSON only. Never propose exploit payloads, credential attacks, destructive methods, stealth, WAF bypass, internal network probing, or data modification. Use concise public_reasoning, not hidden chain-of-thought."
        user = {"task": "Choose up to five safe next actions for an authorized defensive web assessment.", "allowed_actions": ["crawl", "review_scripts", "test_parameter", "validate_evidence", "write_reports", "stop"], "allowed_tests": ["reflection_canary", "classification_review", "passive_review"], "context": safe_context, "required_json_schema": {"public_reasoning": ["brief rationale"], "actions": [{"action": "test_parameter", "test": "reflection_canary", "url": "", "parameter": "", "reason": ""}]}}
        return self.chat_json(messages=[{"role": "system", "content": system}, {"role": "user", "content": json.dumps(user, ensure_ascii=False)}], model_role=model_role)

    def validate_evidence(self, finding: dict[str, Any]) -> LLMResponse:
        safe_finding = sanitize_evidence_object(finding, max_chars=6000)
        system = "You validate defensive security evidence. Return JSON only with status, confidence, reason, and public_reasoning. Do not overclaim. Reflection is not automatically XSS."
        user = {"finding": safe_finding, "allowed_status": ["Confirmed", "Potential", "Informational", "Rejected"]}
        return self.chat_json(messages=[{"role": "system", "content": system}, {"role": "user", "content": json.dumps(user, ensure_ascii=False)}], model_role="deep")

    def report_summary(self, report_context: dict[str, Any]) -> LLMResponse:
        safe_context = sanitize_evidence_object(report_context, max_chars=8000)
        system = "You write concise professional security report summaries. Return JSON only with executive_summary, technical_summary, and remediation_focus."
        return self.chat_json(messages=[{"role": "system", "content": system}, {"role": "user", "content": json.dumps(safe_context, ensure_ascii=False)}], model_role="report")

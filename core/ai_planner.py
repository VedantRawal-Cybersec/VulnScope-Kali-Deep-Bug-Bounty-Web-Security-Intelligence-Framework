#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any

import requests

from core.parameter_inventory import dedupe_by_cluster
from core.scan_state import ParamRecord, ScanState

ALLOWED_ACTIONS = {"crawl", "review_scripts", "test_parameter", "write_reports", "stop"}
ALLOWED_TESTS = {"baseline", "reflection_canary", "error_behavior", "redirect_review", "classification_review"}


@dataclass
class PlannerDecision:
    action: str
    reason: str
    url: str = ""
    parameter: str = ""
    test_name: str = ""
    confidence: int = 50
    source: str = "deterministic"

    def safe(self) -> "PlannerDecision":
        if self.action not in ALLOWED_ACTIONS:
            return PlannerDecision(action="stop", reason="planner returned unsupported action", confidence=0, source=self.source)
        if self.test_name and self.test_name not in ALLOWED_TESTS:
            self.test_name = "classification_review"
        self.confidence = max(0, min(100, int(self.confidence)))
        return self


class AIPlanner:
    """Fallback-first planner.

    Ollama is advisory only. The scan never depends on model output, and model calls are
    skipped unless explicitly enabled with VULNSCOPE_USE_OLLAMA_PLANNER=1.
    """

    def __init__(self, *, ollama_url: str | None = None, model: str | None = None, timeout: int = 6) -> None:
        self.ollama_url = ollama_url or os.getenv("VULNSCOPE_OLLAMA_URL", "http://localhost:11434/api/generate")
        self.model = model or os.getenv("VULNSCOPE_OLLAMA_MODEL", "qwen2.5:3b")
        self.timeout = max(2, int(timeout))
        self.use_ollama = os.getenv("VULNSCOPE_USE_OLLAMA_PLANNER", "0") == "1"
        self.last_call_at = 0.0
        self.min_interval = float(os.getenv("VULNSCOPE_OLLAMA_MIN_INTERVAL", "15"))

    def fallback(self, state: ScanState) -> PlannerDecision:
        cov = state.coverage()
        queued_urls = state.queued_urls(limit=5)
        if queued_urls and cov["urls_done"] < max(1, min(cov["urls_total"], int(state.stats.get("max_pages", 120)))):
            return PlannerDecision(action="crawl", reason=f"{len(queued_urls)} queued URL(s) remain", confidence=85)
        if int(state.stats.get("javascript_routes", 0)) == 0 and int(state.stats.get("scripts", 0)) > 0:
            return PlannerDecision(action="review_scripts", reason="scripts discovered but external JavaScript route review has not run", confidence=80)
        candidates = dedupe_by_cluster(state.queued_params(limit=100), max_per_cluster=2)
        for item in candidates:
            if item.status == "queued" and "reflection_canary" not in item.tested:
                return PlannerDecision(action="test_parameter", url=item.url, parameter=item.name, test_name="reflection_canary", reason=f"safe queued parameter {item.name} kind={item.kind}", confidence=90)
            if "classification_review" not in item.tested:
                return PlannerDecision(action="test_parameter", url=item.url, parameter=item.name, test_name="classification_review", reason=f"classification review for {item.kind} parameter", confidence=75)
        return PlannerDecision(action="write_reports", reason="crawl and parameter queues are exhausted", confidence=90)

    def _should_call_ollama(self, fallback: PlannerDecision, state: ScanState) -> bool:
        if not self.use_ollama:
            return False
        if fallback.action in {"crawl", "review_scripts", "write_reports", "stop"}:
            return False
        if len(state.params) < 5:
            return False
        if time.time() - self.last_call_at < self.min_interval:
            return False
        return True

    def decide(self, state: ScanState) -> PlannerDecision:
        fallback = self.fallback(state).safe()
        if not self._should_call_ollama(fallback, state):
            return fallback
        self.last_call_at = time.time()
        context = {
            "target": state.target,
            "coverage": state.coverage(),
            "top_parameters": [
                {"url": p.url, "name": p.name, "kind": p.kind, "risk_score": p.risk_score, "tested": p.tested}
                for p in dedupe_by_cluster(list(state.params.values()), max_per_cluster=1)[:25]
            ],
            "allowed_actions": sorted(ALLOWED_ACTIONS),
            "allowed_tests": sorted(ALLOWED_TESTS),
            "fallback": fallback.__dict__,
            "rules": [
                "Return JSON only.",
                "Do not invent URLs or parameters.",
                "Choose only allowed actions and tests.",
                "Prefer deterministic fallback unless there is clear evidence to reprioritize.",
            ],
        }
        try:
            response = requests.post(
                self.ollama_url,
                json={
                    "model": self.model,
                    "prompt": "Return compact JSON: {action, reason, url, parameter, test_name, confidence}.\n" + json.dumps(context, ensure_ascii=False),
                    "stream": False,
                    "options": {"temperature": 0.1},
                },
                timeout=self.timeout,
            )
            if response.status_code != 200:
                return fallback
            text = str(response.json().get("response", ""))
            start = text.find("{")
            end = text.rfind("}")
            if start < 0 or end <= start:
                return fallback
            data = json.loads(text[start : end + 1])
            decision = PlannerDecision(
                action=str(data.get("action") or fallback.action),
                reason=str(data.get("reason") or fallback.reason),
                url=str(data.get("url") or fallback.url),
                parameter=str(data.get("parameter") or fallback.parameter),
                test_name=str(data.get("test_name") or fallback.test_name),
                confidence=int(data.get("confidence") or fallback.confidence),
                source="ollama",
            ).safe()
            if decision.action == "test_parameter" and not self.find_param(state, decision.url, decision.parameter):
                return fallback
            return decision
        except Exception:
            return fallback

    @staticmethod
    def find_param(state: ScanState, url: str, parameter: str) -> ParamRecord | None:
        for item in state.params.values():
            if item.url == url and item.name == parameter:
                return item
        return None

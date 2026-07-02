#!/usr/bin/env python3
from __future__ import annotations

import json
import os
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

    def safe(self) -> "PlannerDecision":
        if self.action not in ALLOWED_ACTIONS:
            return PlannerDecision(action="stop", reason="planner returned unsupported action", confidence=0)
        if self.test_name and self.test_name not in ALLOWED_TESTS:
            self.test_name = "classification_review"
        self.confidence = max(0, min(100, int(self.confidence)))
        return self


class AIPlanner:
    """Ollama-guided planner with deterministic fallback and strict action allowlist."""

    def __init__(self, *, ollama_url: str | None = None, model: str | None = None, timeout: int = 20) -> None:
        self.ollama_url = ollama_url or os.getenv("VULNSCOPE_OLLAMA_URL", "http://localhost:11434/api/generate")
        self.model = model or os.getenv("VULNSCOPE_OLLAMA_MODEL", "qwen2.5:3b")
        self.timeout = max(3, int(timeout))

    def fallback(self, state: ScanState) -> PlannerDecision:
        cov = state.coverage()
        if cov["urls_done"] < min(cov["urls_total"], 20):
            return PlannerDecision(action="crawl", reason="queued URLs remain and crawl coverage is incomplete", confidence=80)
        if int(state.stats.get("javascript_routes", 0)) == 0 and cov["urls_done"] > 0:
            return PlannerDecision(action="review_scripts", reason="HTML crawl completed enough to review script route hints", confidence=70)
        candidates = dedupe_by_cluster(state.queued_params(limit=50), max_per_cluster=2)
        for item in candidates:
            if "reflection_canary" not in item.tested:
                return PlannerDecision(action="test_parameter", url=item.url, parameter=item.name, test_name="reflection_canary", reason=f"high-priority parameter {item.name} kind={item.kind}", confidence=85)
            if "classification_review" not in item.tested:
                return PlannerDecision(action="test_parameter", url=item.url, parameter=item.name, test_name="classification_review", reason=f"classification lead needed for {item.kind} parameter", confidence=75)
        return PlannerDecision(action="write_reports", reason="crawl and parameter queues are exhausted", confidence=90)

    def decide(self, state: ScanState) -> PlannerDecision:
        fallback = self.fallback(state)
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
                "Choose only allowed actions and tests.",
                "Prefer evidence quality, bounded scope, and request budget control.",
                "Do not request credential checks, destructive actions, or hidden routing.",
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
            return PlannerDecision(
                action=str(data.get("action") or fallback.action),
                reason=str(data.get("reason") or fallback.reason),
                url=str(data.get("url") or fallback.url),
                parameter=str(data.get("parameter") or fallback.parameter),
                test_name=str(data.get("test_name") or fallback.test_name),
                confidence=int(data.get("confidence") or fallback.confidence),
            ).safe()
        except Exception:
            return fallback

    @staticmethod
    def find_param(state: ScanState, url: str, parameter: str) -> ParamRecord | None:
        for item in state.params.values():
            if item.url == url and item.name == parameter:
                return item
        return None

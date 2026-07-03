#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from core.llm_gateway import LLMGateway
from core.scan_state import ScanState, TestRecord

ALLOWED_ACTIONS = {"run_test", "continue", "report", "stop"}
ALLOWED_TESTS = {"classification_review", "reflection_canary", "redirect_review", "baseline", "error_behavior"}
NETWORK_TESTS = {"reflection_canary", "redirect_review", "baseline", "error_behavior"}


@dataclass
class ReactDecision:
    """Public ReAct decision object used by dashboard, trace, and executor."""

    turn: int
    source: str
    action: str
    tool: str
    test_id: str = ""
    url: str = ""
    parameter: str = ""
    public_reasoning: str = ""
    message: str = ""
    confidence: int = 0
    safety: str = "same-scope safe tool policy"
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CAIReActController:
    """Think -> Act -> Observe controller for VulnScope.

    The model can select only from explicit safe actions and existing safe test
    functions. Invalid model output is ignored and deterministic routing is used.
    """

    def __init__(self, *, llm: LLMGateway, scan_mode: str = "passive", enabled: bool | None = None) -> None:
        self.llm = llm
        self.scan_mode = scan_mode if scan_mode in {"passive", "safe-active", "lab"} else "passive"
        self.enabled = (os.getenv("VULNSCOPE_LLM_ENABLED", "1") != "0") if enabled is None else bool(enabled)
        self.full_llm = os.getenv("VULNSCOPE_FULL_LLM_BEHAVIOR", "0") == "1"
        self.history: list[dict[str, Any]] = []

    def _summarize_tests(self, tests: list[TestRecord], limit: int = 20) -> list[dict[str, Any]]:
        return [
            {"test_id": test.test_id, "url": test.url, "parameter": test.parameter, "test_name": test.test_name, "status": test.status}
            for test in tests[:limit]
        ]

    def _first_safe_test(self, tests: list[TestRecord], *, budget_remaining: int) -> TestRecord | None:
        for test in tests:
            if test.status != "queued" or test.test_name not in ALLOWED_TESTS:
                continue
            if self.scan_mode == "passive" and test.test_name in NETWORK_TESTS:
                continue
            if test.test_name in NETWORK_TESTS and budget_remaining <= 0:
                continue
            return test
        return None

    def _deterministic(self, *, tests: list[TestRecord], turn: int, budget_remaining: int, reason: str) -> ReactDecision:
        selected = self._first_safe_test(tests, budget_remaining=budget_remaining)
        if selected is None:
            return ReactDecision(turn=turn, source="deterministic", action="report", tool="report_generator", public_reasoning="No eligible queued safe tests remain.", message=reason, confidence=75)
        return ReactDecision(
            turn=turn,
            source="deterministic",
            action="run_test",
            tool=selected.test_name,
            test_id=selected.test_id,
            url=selected.url,
            parameter=selected.parameter or "",
            public_reasoning=f"Selected next eligible safe test `{selected.test_name}` for `{selected.parameter or 'N/A'}`.",
            message=reason,
            confidence=80,
        )

    def _system_prompt(self) -> str:
        return (
            "You are VulnScope's defensive ReAct controller. Return JSON only. "
            "Use concise public_reasoning summaries, not private reasoning. "
            "Choose only allowed safe actions and safe tests from the context. "
            "Do not propose credential attempts, destructive methods, high-volume traffic, scope changes, or target data modification."
        )

    def decide(self, *, state: ScanState, tests: list[TestRecord], turn: int, max_turns: int, budget_remaining: int) -> ReactDecision:
        queued = [test for test in tests if test.status == "queued"]
        if not self.enabled or not self.full_llm:
            decision = self._deterministic(tests=queued, turn=turn, budget_remaining=budget_remaining, reason="Model ReAct generation disabled; deterministic controller active.")
            self.history.append(decision.to_dict())
            return decision

        context = {
            "turn": turn,
            "max_turns": max_turns,
            "scan_mode": self.scan_mode,
            "coverage": state.coverage(),
            "budget_remaining": budget_remaining,
            "allowed_actions": sorted(ALLOWED_ACTIONS),
            "allowed_tests": sorted(ALLOWED_TESTS if self.scan_mode != "passive" else (ALLOWED_TESTS - NETWORK_TESTS)),
            "queued_tests": self._summarize_tests(queued),
            "recent_observations": self.history[-8:],
            "required_json_schema": {
                "public_reasoning": "one concise sentence explaining the safe decision",
                "action": "run_test|continue|report|stop",
                "tool": "classification_review|reflection_canary|redirect_review|baseline|error_behavior|report_generator",
                "test_id": "exact queued test_id when action is run_test",
                "confidence": 0,
                "message": "brief operational note",
            },
        }
        response = self.llm.chat_json(
            messages=[{"role": "system", "content": self._system_prompt()}, {"role": "user", "content": json.dumps(context, ensure_ascii=False)}],
            model_role="fast",
        )
        if not response.ok or not response.parsed:
            decision = self._deterministic(tests=queued, turn=turn, budget_remaining=budget_remaining, reason=response.error or "Model response unavailable; deterministic fallback.")
            decision.source = "fallback"
            self.history.append(decision.to_dict())
            return decision

        parsed = response.parsed
        action = str(parsed.get("action") or "run_test")
        tool = str(parsed.get("tool") or parsed.get("test_name") or "classification_review")
        test_id = str(parsed.get("test_id") or "")
        if action not in ALLOWED_ACTIONS:
            action = "run_test"
        if tool not in ALLOWED_TESTS and tool != "report_generator":
            tool = "classification_review"
        if self.scan_mode == "passive" and tool in NETWORK_TESTS:
            tool = "classification_review"
        selected = next((item for item in queued if item.test_id == test_id), None)
        if action == "run_test" and selected is None:
            selected = self._first_safe_test(queued, budget_remaining=budget_remaining)
        if action == "run_test" and selected is None:
            action = "report"
            tool = "report_generator"
        if selected is not None:
            tool = selected.test_name
            test_id = selected.test_id
        decision = ReactDecision(
            turn=turn,
            source="ollama",
            action=action,
            tool=tool,
            test_id=test_id,
            url=selected.url if selected else "",
            parameter=(selected.parameter or "") if selected else "",
            public_reasoning=str(parsed.get("public_reasoning") or "Model selected the next safe ReAct action.")[:600],
            message=str(parsed.get("message") or "safe ReAct decision accepted")[:300],
            confidence=max(0, min(100, int(parsed.get("confidence") or 70))),
        )
        self.history.append(decision.to_dict())
        return decision

    def observe(self, decision: ReactDecision, *, status: str, output: str = "", evidence_id: str = "") -> dict[str, Any]:
        observation = {"turn": decision.turn, "action": decision.action, "tool": decision.tool, "status": status, "output": str(output)[:700], "evidence_id": evidence_id, "time": time.time()}
        self.history.append({"observation": observation})
        return observation

    def write_state(self, state: ScanState) -> None:
        state.stats["cai_react_controller"] = {"enabled": self.enabled, "full_llm": self.full_llm, "turns": self.history[-100:]}
        state.save()

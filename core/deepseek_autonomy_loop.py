#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from core.ai_brain import AIBrain
from core.autonomous_planner import AutonomousPlanner


class DeepSeekAutonomyLoop:
    """DeepSeek-controlled ReAct loop over VulnScope's existing safe engines.

    The model proposes actions, but the controller enforces forward progress.
    It cannot finish while safe deterministic work is still pending.
    """

    ACTIONS = ["crawl_more", "review_javascript", "baseline", "reflection_canary", "redirect_review", "classification_review", "dynamic_tools", "report", "finish"]
    TEST_ACTIONS = {"baseline", "reflection_canary", "redirect_review", "classification_review"}
    REQUIRED_TESTS = ["baseline", "reflection_canary", "classification_review"]

    def __init__(self, *, target: str, state: Any, crawler: Any, tester: Any, dashboard: Any | None = None, dynamic_scheduler: Any | None = None, brain: AIBrain | None = None, planner: AutonomousPlanner | None = None, max_turns: int = 80, max_params: int = 250, scan_mode: str = "safe-active") -> None:
        self.target = target
        self.state = state
        self.crawler = crawler
        self.tester = tester
        self.dashboard = dashboard
        self.dynamic_scheduler = dynamic_scheduler
        self.brain = brain or AIBrain()
        self.planner = planner or AutonomousPlanner()
        self.max_turns = max(1, int(max_turns))
        self.max_params = max(1, int(max_params))
        self.scan_mode = scan_mode
        self.turns: list[dict[str, Any]] = []
        self.dynamic_ran = False
        self.started_at = time.time()
        self.no_progress_turns = 0

    def _params(self) -> list[Any]:
        params = list(getattr(self.state, "params", {}).values())
        params.sort(key=lambda item: int(getattr(item, "risk_score", 0) or 0), reverse=True)
        return params[: self.max_params]

    def _required_tests_for(self, param: Any) -> list[str]:
        tests = list(self.REQUIRED_TESTS)
        if getattr(param, "kind", "") in {"route-like", "reference-like"}:
            tests.insert(2, "redirect_review")
        return tests

    def _pending_work(self) -> list[dict[str, Any]]:
        work: list[dict[str, Any]] = []
        for index, param in enumerate(self._params()):
            tested = set(getattr(param, "tested", []) or [])
            for test_name in self._required_tests_for(param):
                if test_name not in tested:
                    work.append({"parameter_index": index, "action": test_name, "parameter": getattr(param, "name", ""), "url": getattr(param, "url", ""), "risk_score": int(getattr(param, "risk_score", 0) or 0)})
                    break
        return work

    def _dynamic_ready_count(self) -> int:
        registry = getattr(self.dynamic_scheduler, "registry", None)
        if registry is None:
            return 0
        try:
            return sum(1 for tool in registry.list(enabled_only=True) if bool(getattr(tool, "approved_for_run", False)) and bool(getattr(tool, "run", [])))
        except Exception:
            return 0

    def _surface(self) -> dict[str, Any]:
        coverage = self.state.coverage() if hasattr(self.state, "coverage") else {}
        return {"urls": len(getattr(self.state, "urls", {}) or {}), "params": len(getattr(self.state, "params", {}) or {}), "pending_work": len(self._pending_work()), "tests": len(getattr(self.state, "tests", {}) or {}), "findings": len(getattr(self.state, "findings", []) or []), "requests": int((getattr(self.state, "stats", {}) or {}).get("requests", 0) or 0), "dynamic_ready": self._dynamic_ready_count(), "coverage": coverage}

    def context(self) -> dict[str, Any]:
        params = []
        for index, param in enumerate(self._params()[:80]):
            tested = list(getattr(param, "tested", []) or [])
            missing = [name for name in self._required_tests_for(param) if name not in set(tested)]
            params.append({"index": index, "url": getattr(param, "url", ""), "name": getattr(param, "name", ""), "kind": getattr(param, "kind", "generic"), "risk_score": int(getattr(param, "risk_score", 0) or 0), "tested": tested, "missing_tests": missing, "status": getattr(param, "status", "")})
        return {"target": self.target, "mode": self.scan_mode, "turn": len(self.turns) + 1, "max_turns": self.max_turns, "allowlist": self.ACTIONS, "surface": self._surface(), "parameters": params, "next_required_work": self._pending_work()[:20], "recent_turns": self.turns[-8:], "dynamic_tools_available": self._dynamic_ready_count() > 0, "dynamic_tools_ran": self.dynamic_ran}

    def _json_from_text(self, text: str) -> dict[str, Any]:
        try:
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                data = json.loads(text[start : end + 1])
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
        return {}

    def fallback_decision(self) -> dict[str, Any]:
        work = self._pending_work()
        if work:
            item = work[0]
            return {"action": item["action"], "parameter_index": item["parameter_index"], "reason": "deterministic next required test"}
        if self._surface()["params"] == 0 and self.no_progress_turns < 2:
            return {"action": "crawl_more", "parameter_index": None, "reason": "no parameters discovered yet"}
        if not self.dynamic_ran and self._dynamic_ready_count() > 0:
            return {"action": "dynamic_tools", "parameter_index": None, "reason": "safe internal review complete and ready dynamic tools exist"}
        return {"action": "report", "parameter_index": None, "reason": "all deterministic work exhausted"}

    def normalize_decision(self, decision: dict[str, Any]) -> dict[str, Any]:
        action = str(decision.get("action", "")).strip()
        if action not in self.ACTIONS:
            fixed = self.fallback_decision()
            fixed["reason"] = f"model returned invalid action `{action}`; " + fixed["reason"]
            return fixed
        work = self._pending_work()
        if action in {"report", "finish"} and work:
            item = work[0]
            return {"action": item["action"], "parameter_index": item["parameter_index"], "reason": "blocked early finish; pending deterministic parameter work remains"}
        if action == "dynamic_tools" and self._dynamic_ready_count() == 0:
            fixed = self.fallback_decision()
            fixed["reason"] = "dynamic tools requested but no ready approved tool exists; " + fixed["reason"]
            return fixed
        if action in self.TEST_ACTIONS:
            idx = decision.get("parameter_index")
            if not isinstance(idx, int) or idx < 0 or idx >= len(self._params()):
                fixed = self.fallback_decision()
                fixed["reason"] = "invalid parameter index; " + fixed["reason"]
                return fixed
            param = self._params()[idx]
            if action in set(getattr(param, "tested", []) or []):
                fixed = self.fallback_decision()
                fixed["reason"] = "model selected already-tested action; " + fixed["reason"]
                return fixed
        return decision

    def think(self) -> dict[str, Any]:
        ctx = self.context()
        memory = self.brain.retrieve_similar(json.dumps(ctx, ensure_ascii=False), top_k=5)
        prompt = (
            "You are the planner for VulnScope's safe autonomous loop. Return one JSON object only. "
            "Choose exactly one action from allowlist. Do not choose report/finish while next_required_work is non-empty.\n"
            "Schema: {\"action\":\"baseline|reflection_canary|redirect_review|classification_review|crawl_more|review_javascript|dynamic_tools|report|finish\",\"parameter_index\":0,\"reason\":\"short reason\"}\n"
            "Context:\n" + json.dumps(ctx, indent=2, ensure_ascii=False) + "\nMemory:\n" + json.dumps(memory, indent=2, ensure_ascii=False)
        )
        data = self._json_from_text(self.brain.ask_ollama(prompt))
        try:
            parameter_index = data.get("parameter_index", None)
            if parameter_index is not None:
                parameter_index = int(parameter_index)
        except Exception:
            parameter_index = None
        decision = {"action": str(data.get("action", "")).strip(), "parameter_index": parameter_index, "reason": str(data.get("reason", "ai decision"))[:500]}
        return self.normalize_decision(decision)

    def _dashboard(self, decision: dict[str, Any], observation: str, *, progress: int = 0) -> None:
        if self.dashboard is None or not hasattr(self.dashboard, "update"):
            return
        action = str(decision.get("action") or "")
        param_label = ""
        idx = decision.get("parameter_index")
        params = self._params()
        if isinstance(idx, int) and 0 <= idx < len(params):
            param = params[idx]
            param_label = f"{getattr(param, 'name', '')} on {getattr(param, 'url', '')}"
        self.dashboard.update(phase="DeepSeek Autonomous ReAct", phase_progress=progress, current_agent="DeepSeekPlannerAgent", current_tool=action, decision=str(decision.get("reason") or ""), action=f"{action} {param_label}".strip(), evidence=observation[:1000], requests=(getattr(self.state, "stats", {}) or {}).get("requests", 0), findings=len(getattr(self.state, "findings", []) or []), safety_status="authorized scope • deterministic progress guard • approval-gated external tools")
        if hasattr(self.dashboard, "event"):
            self.dashboard.event("AI", f"DeepSeek chose {action}: {decision.get('reason', '')}")

    def execute(self, decision: dict[str, Any]) -> dict[str, Any]:
        action = str(decision.get("action") or "")
        idx = decision.get("parameter_index")
        params = self._params()
        before = self._surface()
        started = time.time()
        if action == "crawl_more":
            result = self.crawler.crawl().__dict__
        elif action == "review_javascript":
            result = {"routes_added": self.crawler.analyze_scripts(limit=160)}
        elif action in self.TEST_ACTIONS:
            if not isinstance(idx, int) or idx < 0 or idx >= len(params):
                return {"ok": False, "action": action, "error": "invalid parameter_index"}
            outcome = self.tester.run_test(params[idx], action)
            result = {"ok": outcome.status in {"done", "finding"}, "status": outcome.status, "confidence": outcome.confidence, "message": outcome.message, "finding": bool(outcome.finding), "parameter": getattr(params[idx], "name", ""), "url": getattr(params[idx], "url", "")}
        elif action == "dynamic_tools":
            if self.dynamic_scheduler is None:
                result = {"ok": False, "error": "dynamic scheduler unavailable"}
            elif self.dynamic_ran:
                result = {"ok": True, "skipped": True, "reason": "dynamic tools already ran"}
            elif self._dynamic_ready_count() == 0:
                result = {"ok": True, "skipped": True, "reason": "no ready approved dynamic tools"}
                self.dynamic_ran = True
            else:
                result = self.dynamic_scheduler.run_all(target=self.target, confirm=True, timeout=240)
                self.dynamic_ran = True
        elif action in {"report", "finish"}:
            result = {"ok": True, "stop": True, "reason": action}
        else:
            result = {"ok": False, "error": "unknown action"}
        result["elapsed_ms"] = int((time.time() - started) * 1000)
        after = self._surface()
        progress_delta = (after["tests"] - before["tests"]) + (after["findings"] - before["findings"]) + (after["urls"] - before["urls"]) + (after["params"] - before["params"])
        result["progress_delta"] = progress_delta
        self.no_progress_turns = self.no_progress_turns + 1 if progress_delta <= 0 and action not in {"report", "finish"} else 0
        return result

    def run(self) -> dict[str, Any]:
        summary_path = Path(getattr(self.state, "out_dir", "reports/output")) / "deepseek-autonomy-summary.json"
        for turn in range(1, self.max_turns + 1):
            decision = self.think()
            progress = min(92, 60 + int((turn / max(1, self.max_turns)) * 30))
            self._dashboard(decision, "thinking", progress=progress)
            observation = self.execute(decision)
            turn_record = {"turn": turn, "decision": decision, "observation": observation, "surface": self._surface(), "time": time.time()}
            self.turns.append(turn_record)
            self.state.add_event("AI", "deepseek react turn", **turn_record)
            self.brain.store_decision(json.dumps(self.context(), ensure_ascii=False), json.dumps(decision, ensure_ascii=False), json.dumps(observation, ensure_ascii=False), metadata={"mode": self.scan_mode, "turn": turn})
            self._dashboard(decision, json.dumps(observation, ensure_ascii=False), progress=progress)
            self.state.save()
            if observation.get("stop") or decision.get("action") in {"report", "finish"}:
                break
            if not self._pending_work() and (self.dynamic_ran or self._dynamic_ready_count() == 0):
                break
            if self.no_progress_turns >= 4 and not self._pending_work():
                break
        payload = {"ok": True, "target": self.target, "mode": self.scan_mode, "turns": self.turns, "surface": self._surface(), "elapsed_ms": int((time.time() - self.started_at) * 1000), "progress_guard": {"no_progress_turns": self.no_progress_turns, "dynamic_ready": self._dynamic_ready_count(), "pending_work": len(self._pending_work())}}
        summary_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        md_path = summary_path.with_suffix(".md")
        lines = ["# DeepSeek Autonomous ReAct Summary", "", f"Target: `{self.target}`", f"Turns: `{len(self.turns)}`", f"Pending work at end: `{len(self._pending_work())}`", f"Ready dynamic tools: `{self._dynamic_ready_count()}`", "", "## Turns"]
        for item in self.turns:
            lines.append(f"- Turn `{item['turn']}` action=`{item['decision'].get('action')}` reason=`{item['decision'].get('reason')}` progress_delta=`{item['observation'].get('progress_delta')}` observation=`{str(item['observation'])[:300]}`")
        md_path.write_text("\n".join(lines), encoding="utf-8")
        payload["summary_path"] = str(summary_path)
        payload["markdown_path"] = str(md_path)
        return payload

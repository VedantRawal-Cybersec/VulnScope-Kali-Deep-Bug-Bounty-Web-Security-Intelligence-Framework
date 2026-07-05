#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.ai_brain import AIBrain
from core.autonomous_planner import AutonomousPlanner


class DeepSeekAutonomyLoop:
    """DeepSeek-controlled ReAct loop over VulnScope's existing safe engines.

    This is intentionally wired to existing low-impact internal components:
    crawler, JavaScript route review, parameter inventory, safe TestEngine, and
    approval-gated dynamic tools. It does not invent raw probes; it selects among
    already-implemented safe actions and records every turn.
    """

    ACTIONS = [
        "crawl_more",
        "review_javascript",
        "baseline",
        "reflection_canary",
        "redirect_review",
        "classification_review",
        "dynamic_tools",
        "report",
        "finish",
    ]

    TEST_ACTIONS = {"baseline", "reflection_canary", "redirect_review", "classification_review"}

    def __init__(
        self,
        *,
        target: str,
        state: Any,
        crawler: Any,
        tester: Any,
        dashboard: Any | None = None,
        dynamic_scheduler: Any | None = None,
        brain: AIBrain | None = None,
        planner: AutonomousPlanner | None = None,
        max_turns: int = 80,
        max_params: int = 250,
        scan_mode: str = "safe-active",
    ) -> None:
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

    def _params(self) -> list[Any]:
        params = list(getattr(self.state, "params", {}).values())
        params.sort(key=lambda item: int(getattr(item, "risk_score", 0) or 0), reverse=True)
        return params[: self.max_params]

    def _pending_params(self) -> list[Any]:
        pending = []
        for param in self._params():
            tested = set(getattr(param, "tested", []) or [])
            if not {"reflection_canary", "classification_review"}.issubset(tested):
                pending.append(param)
        return pending

    def _surface(self) -> dict[str, Any]:
        coverage = self.state.coverage() if hasattr(self.state, "coverage") else {}
        return {
            "urls": len(getattr(self.state, "urls", {}) or {}),
            "params": len(getattr(self.state, "params", {}) or {}),
            "pending_params": len(self._pending_params()),
            "tests": len(getattr(self.state, "tests", {}) or {}),
            "findings": len(getattr(self.state, "findings", []) or []),
            "requests": int((getattr(self.state, "stats", {}) or {}).get("requests", 0) or 0),
            "coverage": coverage,
        }

    def context(self) -> dict[str, Any]:
        params = []
        for index, param in enumerate(self._params()[:80]):
            params.append(
                {
                    "index": index,
                    "url": getattr(param, "url", ""),
                    "name": getattr(param, "name", ""),
                    "kind": getattr(param, "kind", "generic"),
                    "risk_score": int(getattr(param, "risk_score", 0) or 0),
                    "tested": list(getattr(param, "tested", []) or []),
                    "status": getattr(param, "status", ""),
                }
            )
        return {
            "target": self.target,
            "mode": self.scan_mode,
            "turn": len(self.turns) + 1,
            "max_turns": self.max_turns,
            "actions": self.ACTIONS,
            "surface": self._surface(),
            "parameters": params,
            "recent_turns": self.turns[-8:],
            "dynamic_tools_available": bool(self.dynamic_scheduler is not None),
            "dynamic_tools_ran": self.dynamic_ran,
        }

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
        params = self._params()
        if not params:
            if self._surface()["urls"] < 5:
                return {"action": "crawl_more", "parameter_index": None, "reason": "no parameters discovered yet"}
            return {"action": "report", "parameter_index": None, "reason": "no parameters available after discovery"}
        for index, param in enumerate(params):
            tested = set(getattr(param, "tested", []) or [])
            if "reflection_canary" not in tested:
                return {"action": "reflection_canary", "parameter_index": index, "reason": "next untested high-risk parameter"}
            if "classification_review" not in tested:
                return {"action": "classification_review", "parameter_index": index, "reason": "classify reviewed parameter"}
            if getattr(param, "kind", "") in {"route-like", "reference-like"} and "redirect_review" not in tested:
                return {"action": "redirect_review", "parameter_index": index, "reason": "route/reference parameter needs redirect review"}
        if not self.dynamic_ran and self.dynamic_scheduler is not None:
            return {"action": "dynamic_tools", "parameter_index": None, "reason": "internal parameter review is complete"}
        return {"action": "report", "parameter_index": None, "reason": "review budget complete"}

    def think(self) -> dict[str, Any]:
        ctx = self.context()
        memory = self.brain.retrieve_similar(json.dumps(ctx, ensure_ascii=False), top_k=5)
        prompt = (
            "You control VulnScope's safe autonomous loop. Choose exactly one action from the allowlist. "
            "Return JSON only: {\"action\":\"...\",\"parameter_index\":0,\"reason\":\"...\"}.\n"
            "Prefer high-risk untested parameters. Choose report/finish only when useful work is done.\n"
            "Context:\n"
            + json.dumps(ctx, indent=2, ensure_ascii=False)
            + "\nMemory:\n"
            + json.dumps(memory, indent=2, ensure_ascii=False)
        )
        data = self._json_from_text(self.brain.ask_ollama(prompt))
        action = str(data.get("action", "")).strip()
        if action not in self.ACTIONS:
            return self.fallback_decision()
        try:
            parameter_index = data.get("parameter_index", None)
            if parameter_index is not None:
                parameter_index = int(parameter_index)
        except Exception:
            parameter_index = None
        return {"action": action, "parameter_index": parameter_index, "reason": str(data.get("reason", "ai decision"))[:500]}

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
        self.dashboard.update(
            phase="DeepSeek Autonomous ReAct",
            phase_progress=progress,
            current_agent="DeepSeekPlannerAgent",
            current_tool=action,
            decision=str(decision.get("reason") or ""),
            action=f"{action} {param_label}".strip(),
            evidence=observation[:1000],
            requests=(getattr(self.state, "stats", {}) or {}).get("requests", 0),
            findings=len(getattr(self.state, "findings", []) or []),
            safety_status="authorized scope • low-impact internal actions • approval-gated external tools",
        )
        if hasattr(self.dashboard, "event"):
            self.dashboard.event("AI", f"DeepSeek chose {action}: {decision.get('reason', '')}")

    def execute(self, decision: dict[str, Any]) -> dict[str, Any]:
        action = str(decision.get("action") or "")
        idx = decision.get("parameter_index")
        params = self._params()
        started = time.time()
        if action == "crawl_more":
            result = self.crawler.crawl().__dict__
        elif action == "review_javascript":
            result = {"routes_added": self.crawler.analyze_scripts(limit=160)}
        elif action in self.TEST_ACTIONS:
            if not isinstance(idx, int) or idx < 0 or idx >= len(params):
                return {"ok": False, "action": action, "error": "invalid parameter_index"}
            outcome = self.tester.run_test(params[idx], action)
            result = {
                "ok": outcome.status in {"done", "finding"},
                "status": outcome.status,
                "confidence": outcome.confidence,
                "message": outcome.message,
                "finding": bool(outcome.finding),
                "parameter": getattr(params[idx], "name", ""),
                "url": getattr(params[idx], "url", ""),
            }
        elif action == "dynamic_tools":
            if self.dynamic_scheduler is None:
                result = {"ok": False, "error": "dynamic scheduler unavailable"}
            elif self.dynamic_ran:
                result = {"ok": True, "skipped": True, "reason": "dynamic tools already ran"}
            else:
                result = self.dynamic_scheduler.run_all(target=self.target, confirm=True, timeout=240)
                self.dynamic_ran = True
        elif action in {"report", "finish"}:
            result = {"ok": True, "stop": True, "reason": action}
        else:
            result = {"ok": False, "error": "unknown action"}
        result["elapsed_ms"] = int((time.time() - started) * 1000)
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
            if self._surface()["pending_params"] == 0 and self.dynamic_ran:
                break
        payload = {
            "ok": True,
            "target": self.target,
            "mode": self.scan_mode,
            "turns": self.turns,
            "surface": self._surface(),
            "elapsed_ms": int((time.time() - self.started_at) * 1000),
        }
        summary_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        md_path = summary_path.with_suffix(".md")
        lines = ["# DeepSeek Autonomous ReAct Summary", "", f"Target: `{self.target}`", f"Turns: `{len(self.turns)}`", "", "## Turns"]
        for item in self.turns:
            lines.append(f"- Turn `{item['turn']}` action=`{item['decision'].get('action')}` reason=`{item['decision'].get('reason')}` observation=`{str(item['observation'])[:300]}`")
        md_path.write_text("\n".join(lines), encoding="utf-8")
        payload["summary_path"] = str(summary_path)
        payload["markdown_path"] = str(md_path)
        return payload

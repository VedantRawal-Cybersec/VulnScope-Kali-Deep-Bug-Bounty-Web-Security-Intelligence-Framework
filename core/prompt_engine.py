#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from core.ai_brain import AIBrain
from core.context_store import ContextStore
from core.orchestrator import Orchestrator
from core.tool_manager import ToolManager


class PromptEngine:
    """Natural-language plan parser and executor for VulnScope."""

    DEFAULT_PHASES = ["recon", "discovery", "validation", "reporting"]

    def __init__(self, tool_manager: ToolManager, brain: AIBrain, context: ContextStore) -> None:
        self.tool_manager = tool_manager
        self.brain = brain
        self.context = context
        self.conversation_history: list[tuple[dict[str, Any], dict[str, Any]]] = []

    def parse_prompt(self, user_prompt: str) -> dict[str, Any]:
        available = self._available_tool_names()
        prompt = (
            "Convert this user request into JSON only with keys: target, scope, tools, phases, mode, options. "
            "Allowed phases are recon, discovery, validation, reporting. Mode is lab or bugbounty. "
            "Use tools='auto' unless a listed tool is explicitly requested. "
            f"Available tools: {available}. User request: {user_prompt!r}"
        )
        raw = self.brain.chat(prompt)
        raw = re.sub(r"^```json\s*", "", raw or "", flags=re.I).strip()
        raw = re.sub(r"\s*```$", "", raw).strip()
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return self._normalize_plan(parsed, user_prompt)
        except Exception:
            pass
        return self._fallback_plan(user_prompt)

    def execute_plan(self, plan: dict[str, Any], *, assume_authorized: bool = False) -> dict[str, Any]:
        target = str(plan.get("target") or "").strip()
        if not target:
            return {"error": "No target specified", "plan": plan}
        if plan.get("mode") == "bugbounty" and not assume_authorized:
            confirm = input(f"Do you have written authorization to test {target}? (y/N): ").strip().lower()
            if confirm != "y":
                return {"error": "Authorization denied", "plan": plan}
        if plan.get("tools") in (None, "auto", []):
            selected = self._select_tools(plan.get("phases") or self.DEFAULT_PHASES, target)
            plan["tools"] = selected or "auto"
        runner = Orchestrator(target, plan.get("scope"), plan.get("mode", "bugbounty"), dashboard=None, plan=plan)
        result = runner.run()
        findings = result.get("findings") or []
        summary = self.brain.analyze_findings(findings if isinstance(findings, list) else [])
        output = {"plan": plan, "findings": findings, "summary": summary, "reports": result.get("engine", {}).get("reports", {}), "raw_result_path": "reports/output/prompt-engine/orchestrator_result.json"}
        self.conversation_history.append((plan, output))
        self.brain.store_decision(json.dumps(plan, sort_keys=True), "plan: " + json.dumps(plan, sort_keys=True), f"found {len(findings)} findings")
        Path("last_scan_results.json").write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
        return output

    def answer_followup(self, user_prompt: str) -> dict[str, Any]:
        if not self.conversation_history:
            return {"error": "No previous context exists."}
        _, last = self.conversation_history[-1]
        findings = last.get("findings") or []
        lower = user_prompt.lower()
        if "critical" in lower or "high" in lower:
            findings = [item for item in findings if str(item.get("severity", "")).upper() in {"CRITICAL", "HIGH"}]
        return {"findings": findings, "summary": self.brain.analyze_findings(findings)}

    def _available_tool_names(self) -> list[str]:
        try:
            self.tool_manager.reconcile_installed_tools(approve_known=True, enable=True)
            return sorted({tool.name for tool in self.tool_manager.registry.list(enabled_only=True)})
        except Exception:
            return []

    def _extract_target(self, prompt: str) -> str:
        match = re.search(r"(https?://[^\s]+|[a-zA-Z0-9_.-]+\.[a-zA-Z]{2,})", prompt)
        return match.group(1).rstrip(".,)") if match else ""

    def _fallback_plan(self, prompt: str) -> dict[str, Any]:
        lower = prompt.lower()
        mode = "lab" if any(word in lower for word in ["lab", "ctf", "localhost", "127.0.0.1"]) else "bugbounty"
        phases = list(self.DEFAULT_PHASES)
        if "recon" in lower:
            phases = ["recon", "discovery", "reporting"]
        if "validate" in lower or "check" in lower:
            phases = ["discovery", "validation", "reporting"]
        requested_tools = [name for name in self._available_tool_names() if name.lower() in lower]
        return {"target": self._extract_target(prompt), "scope": None, "tools": requested_tools or "auto", "phases": phases, "mode": mode, "options": {}}

    def _normalize_plan(self, plan: dict[str, Any], original_prompt: str) -> dict[str, Any]:
        normalized = dict(plan)
        normalized["target"] = str(normalized.get("target") or self._extract_target(original_prompt)).strip()
        normalized["scope"] = normalized.get("scope") or None
        normalized["mode"] = "lab" if str(normalized.get("mode") or "bugbounty").lower() == "lab" else "bugbounty"
        phases = normalized.get("phases") or list(self.DEFAULT_PHASES)
        if isinstance(phases, str):
            phases = [phases]
        fixed = []
        for phase in phases:
            phase = "validation" if str(phase).lower() == "exploitation" else str(phase).lower()
            if phase in self.DEFAULT_PHASES:
                fixed.append(phase)
        normalized["phases"] = fixed or list(self.DEFAULT_PHASES)
        tools = normalized.get("tools") or "auto"
        normalized["tools"] = tools if tools == "auto" or isinstance(tools, list) else [str(tools)]
        options = normalized.get("options") or {}
        normalized["options"] = options if isinstance(options, dict) else {}
        return normalized

    def _select_tools(self, phases: list[str], target: str) -> list[str]:
        candidates: list[str] = []
        try:
            self.tool_manager.reconcile_installed_tools(approve_known=True, enable=True)
            for phase in phases:
                candidates.extend([tool.name for tool in self.tool_manager.registry.list(enabled_only=True, phase=phase)])
        except Exception:
            pass
        candidates = sorted(set(candidates))
        if not candidates:
            return []
        choice = self.brain.decide_next_action({"target": target, "phases": phases}, candidates)
        return ([choice] if choice in candidates else []) + [name for name in candidates if name != choice][:4]

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_core.activity_log import log_event
from agent_core.agent_registry import registry_markdown
from agent_core.model_router import choose_model, provider_status
from agent_core.task_model import AgentObservation, AgentTask
from agent_core.tool_router import build_tool_plan, run_tool_plan
from agent_core.workflow_memory import remember_target
from review_agents.base_agent import load_json
from review_agents.specialists import SPECIALIST_AGENTS

OUT_DIR = Path("reports/output/agent_core")


class AgentCoreController:
    def __init__(self, target: str, mode: str = "bounty", auto_yes: bool = False, dry_run: bool = False) -> None:
        self.target = target
        self.mode = mode
        self.auto_yes = auto_yes
        self.dry_run = dry_run
        OUT_DIR.mkdir(parents=True, exist_ok=True)

    def run(self) -> dict[str, Any]:
        log_event("controller_start", {"target": self.target, "mode": self.mode})
        (OUT_DIR / "agent-registry.md").write_text(registry_markdown(), encoding="utf-8")
        model_route = choose_model("deep_review")
        tool_results = self.run_tool_stage()
        agent_results = self.run_agent_stage()
        summary = {
            "target": self.target,
            "mode": self.mode,
            "model_route": model_route.__dict__,
            "providers": provider_status(),
            "tool_results": tool_results,
            "agent_results": agent_results,
            "policy": "Evidence-first review. Candidates are not confirmed until validated on authorized assets.",
        }
        (OUT_DIR / "agent-core-summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        remember_target(self.target, {"mode": self.mode, "agent_count": len(agent_results), "tool_count": len(tool_results)})
        log_event("controller_complete", {"target": self.target, "agent_count": len(agent_results)})
        return summary

    def run_tool_stage(self) -> list[dict[str, Any]]:
        actions = ["domain_expansion", "ai_discovery", "mythic_validation"]
        if self.mode in {"pentest", "comprehensive"}:
            actions.append("auto_mode")
        results = []
        for action in actions:
            plan = build_tool_plan(action, self.target, self.mode)
            if not plan:
                continue
            task = AgentTask(task_id=f"tool-{action}", agent="ToolRouter", goal=f"Run {action}", inputs={"target": self.target}, risk_level=plan.risk_level, requires_human=plan.requires_confirmation)
            log_event("task_created", task.to_dict())
            result = run_tool_plan(plan, auto_yes=self.auto_yes, dry_run=self.dry_run)
            log_event("tool_result", result)
            results.append(result)
        return results

    def run_agent_stage(self) -> list[dict[str, Any]]:
        evidence = self._load_evidence()
        results = []
        out = OUT_DIR / "specialist-results"
        out.mkdir(parents=True, exist_ok=True)
        for agent in SPECIALIST_AGENTS:
            task = AgentTask(task_id=f"agent-{agent.name}", agent=agent.name, goal="Review collected evidence and produce validation candidates")
            log_event("task_created", task.to_dict())
            result = agent.run(evidence).to_dict()
            observation = AgentObservation(
                task_id=task.task_id,
                agent=agent.name,
                summary=f"{len(result.get('candidates', []))} candidates produced",
                candidates=result.get("candidates", []),
                confidence=float(result.get("confidence", 0.0) or 0.0),
            )
            log_event("agent_observation", observation.to_dict())
            (out / f"{agent.name}.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
            results.append(result)
        return results

    def _load_evidence(self) -> dict[str, Any]:
        sources = ["reports/output/recon/domain-expansion.json", "reports/output/evidence.json", "reports/output/auth/account-comparison.json"]
        merged: dict[str, Any] = {"sources": []}
        for source in sources:
            data = load_json(source)
            if not data:
                continue
            merged["sources"].append(source)
            for key, value in data.items():
                if isinstance(value, list):
                    merged.setdefault(key, []).extend(value)
                else:
                    merged.setdefault(key, value)
        return merged

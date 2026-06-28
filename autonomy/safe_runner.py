from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from agent_core.controller import AgentCoreController
from autonomy.autonomous_planner import build_plan, plan_to_markdown
from autonomy.autonomy_policy import load_autonomy_policy
from findings.quality import load_findings_from_reports, reduce_low_quality
from importers.har_importer import save_import
from reports.report_v2 import build_report_v2
from safe_discovery.non_exploit_discovery import SafeDiscoveryRunner
from scope.policy import load_scope_policy
from workflow.assessment_state import AssessmentState
from workflow.checkpoint_store import load_checkpoint, save_checkpoint
from workflow.phase_runner import PhaseRunner

OUT_DIR = Path("reports/output/autonomy")


class SafeAutonomyRunner:
    def __init__(self, target: str, mode: str = "bounty", autonomy_policy_path: str = "autonomy_policy.yaml", scope_policy_path: str = "scope_policy.yaml", har_path: str | None = None, provider: str | None = None, auto_yes: bool = False, dry_run: bool = False) -> None:
        self.target = target
        self.mode = mode
        self.policy = load_autonomy_policy(autonomy_policy_path)
        self.scope_policy = load_scope_policy(scope_policy_path)
        self.har_path = har_path
        self.provider = provider
        self.auto_yes = auto_yes
        self.dry_run = dry_run
        OUT_DIR.mkdir(parents=True, exist_ok=True)

    def run(self) -> dict[str, Any]:
        started = time.time()
        scope_decision = self.scope_policy.check(self.target)
        plan = build_plan(self.target, self.policy, has_har=bool(self.har_path))
        (OUT_DIR / "autonomy-plan.md").write_text(plan_to_markdown(self.target, self.policy, plan), encoding="utf-8")
        if not scope_decision.allowed and self.policy.stop_on_scope_block:
            result = self._result(started, scope_decision.to_dict(), [s.to_dict() for s in plan], {"stopped": True, "reason": scope_decision.reason})
            self._save(result)
            return result
        if self.dry_run:
            result = self._result(started, scope_decision.to_dict(), [s.to_dict() for s in plan], {"dry_run": True})
            self._save(result)
            return result
        artifacts: dict[str, Any] = {}
        if self.har_path and self.policy.allow_har_import:
            artifacts["har_import"] = str(save_import(self.har_path))
        if self.policy.allow_safe_discovery_probes and self.policy.allows_stage("safe_discovery"):
            safe_result = SafeDiscoveryRunner(self.target).run()
            artifacts["safe_discovery"] = {
                "json": "reports/output/safe-discovery/safe-discovery.json",
                "markdown": "reports/output/safe-discovery/safe-discovery.md",
                "findings": safe_result.get("summary", {}).get("findings", 0),
            }
        state = load_checkpoint(self.target) or AssessmentState(target=self.target, mode=self.mode)
        save_checkpoint(state)
        PhaseRunner(state).run_all()
        artifacts["phase_report"] = "reports/output/workflow/vulnscope-assessment-report.md"
        council = self.policy.allow_model_council and self.policy.level >= 2
        AgentCoreController(target=self.target, mode=self.mode, auto_yes=self.auto_yes, dry_run=False, provider=self.provider, council=council).run()
        artifacts["agent_core"] = "reports/output/agent_core/agent-core-summary.json"
        items = load_findings_from_reports([
            "reports/output/safe-discovery/safe-discovery.json",
            "reports/output/agent_core/agent-core-summary.json",
            "reports/output/workflow/reportability-scores.json",
            "reports/output/imports/har-import.json",
        ])
        quality = reduce_low_quality(items, threshold=self.policy.min_quality_threshold)
        q_path = Path("reports/output/finding-quality.json")
        q_path.parent.mkdir(parents=True, exist_ok=True)
        q_path.write_text(json.dumps(quality, indent=2, ensure_ascii=False), encoding="utf-8")
        artifacts["quality"] = str(q_path)
        if self.policy.allow_report_generation:
            report_paths = build_report_v2(self.target)
            artifacts["report_v2"] = {k: str(v) for k, v in report_paths.items()}
        result = self._result(started, scope_decision.to_dict(), [s.to_dict() for s in plan], {"artifacts": artifacts})
        self._save(result)
        return result

    def _result(self, started: float, scope: dict[str, Any], plan: list[dict[str, Any]], extra: dict[str, Any]) -> dict[str, Any]:
        return {"target": self.target, "mode": self.mode, "autonomy_policy": self.policy.to_dict(), "scope_decision": scope, "plan": plan, "started_at": started, "ended_at": time.time(), "extra": extra}

    def _save(self, result: dict[str, Any]) -> None:
        (OUT_DIR / "autonomy-run.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

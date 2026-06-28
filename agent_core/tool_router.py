from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_core.human_gate import classify_risk, require_confirmation


@dataclass
class ToolPlan:
    name: str
    command: list[str]
    output_hint: str
    risk_level: str = "review-only"
    requires_confirmation: bool = False


def build_tool_plan(action: str, target: str, mode: str = "bounty") -> ToolPlan | None:
    py = sys.executable or "python3"
    if action == "domain_expansion":
        return ToolPlan("domain_expansion", [py, "domain_recon_cli.py", "--target", target], "reports/output/recon/domain-expansion.json", "passive", False)
    if action == "auto_mode":
        return ToolPlan("auto_mode", [py, "auto_mode.py", "--url", target, "--profile", "bug-bounty-safe", "--full"], "reports/output/auto-mode-summary.json", "approval-required", True)
    if action == "ai_discovery":
        return ToolPlan("ai_discovery", [py, "ai_discovery_cli.py", "--input", "reports/output/recon/domain-expansion.json"], "reports/output/ai-discovery/ai-discovery-report.md", "review-only", False)
    if action == "mythic_validation":
        return ToolPlan("mythic_validation", [py, "mythic_hunter_cli.py", "--input", "reports/output/recon/domain-expansion.json", "--depth", "DEEP_HUNTER_MODE"], "reports/output/mythic/mythic-report.md", "review-only", False)
    return None


def run_tool_plan(plan: ToolPlan, auto_yes: bool = False, dry_run: bool = False) -> dict[str, Any]:
    risk = classify_risk(" ".join(plan.command)) if plan.risk_level == "approval-required" else plan.risk_level
    if plan.requires_confirmation:
        decision = require_confirmation(f"Run tool plan: {plan.name}\nRisk: {risk}\nCommand: {' '.join(plan.command)}", auto_yes=auto_yes)
        if not decision.allowed:
            return {"name": plan.name, "ok": False, "reason": decision.reason, "risk": risk}
    if dry_run:
        return {"name": plan.name, "ok": True, "dry_run": True, "command": plan.command, "risk": risk}
    code = subprocess.call(plan.command)
    return {"name": plan.name, "ok": code == 0, "exit_code": code, "output_hint": plan.output_hint, "risk": risk}

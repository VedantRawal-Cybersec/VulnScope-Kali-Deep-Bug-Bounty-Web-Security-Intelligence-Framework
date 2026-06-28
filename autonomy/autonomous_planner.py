from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

from autonomy.autonomy_policy import AutonomyPolicy


@dataclass
class AutonomousStep:
    name: str
    stage: str
    reason: str
    command_hint: str
    required: bool = True
    status: str = "pending"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_plan(target: str, policy: AutonomyPolicy, has_har: bool = False) -> list[AutonomousStep]:
    steps: list[AutonomousStep] = [
        AutonomousStep("scope_check", "scope", "Confirm target is allowed by scope_policy.yaml", "scope.policy.check"),
        AutonomousStep("safe_discovery", "safe_discovery", "Find real misconfigurations and review candidates using low-impact evidence collection", "safe_discovery_cli.py"),
        AutonomousStep("phase_workflow", "passive_recon", "Run phase workflow, passive recon, app profile, validation task creation", "PhaseRunner.run_all"),
        AutonomousStep("agent_core", "agent_review", "Run specialist agents over collected evidence", "AgentCoreController.run"),
        AutonomousStep("finding_quality", "quality", "Dedupe candidates and reduce low-quality findings", "finding_quality_cli.py"),
    ]
    if has_har and policy.allows_stage("agent_review"):
        steps.insert(1, AutonomousStep("har_import", "agent_review", "Import HAR traffic for richer API/auth surface review", "har_import_cli.py", required=False))
    if policy.allows_stage("model_council"):
        steps.append(AutonomousStep("model_council", "model_council", "Ask multiple configured models and build consensus", "--model-council", required=False))
    if policy.allows_stage("active_tools"):
        steps.append(AutonomousStep("controlled_active_tools", "active_tools", "Run controlled active tools with rate limits and scope policy", "auto_mode.py", required=False))
    if policy.allows_stage("authenticated_review"):
        steps.append(AutonomousStep("owned_account_review", "authenticated_review", "Use owned Account A/B sessions for access-control validation", "auth_mode.py", required=False))
    if policy.allows_stage("report"):
        steps.append(AutonomousStep("report_v2", "report", "Generate executive and technical report artifacts", "report_v2_cli.py"))
    return steps


def plan_to_markdown(target: str, policy: AutonomyPolicy, steps: list[AutonomousStep]) -> str:
    lines = [f"# VulnScope Autonomous Plan — {target}", "", f"Autonomy level: `{policy.level}`", "", "## Steps"]
    for idx, step in enumerate(steps, 1):
        lines += [
            f"{idx}. **{step.name}**",
            f"   - Stage: `{step.stage}`",
            f"   - Required: `{step.required}`",
            f"   - Reason: {step.reason}",
            f"   - Status: `{step.status}`",
            "",
        ]
    lines += ["## Policy", "", "```json", str(policy.to_dict()).replace("'", '"'), "```"]
    return "\n".join(lines)

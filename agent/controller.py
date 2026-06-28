from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from agent.approval_gate import ask_user_approval
from agent.decision_engine import build_next_action_plan
from agent.run_history import log_event
from storage.sqlite_store import add_artifact, add_decision, create_run


@dataclass
class ControllerConfig:
    target_url: str
    mode: str = "passive"
    max_pages: int = 5
    timeout: int = 45
    delay: float = 1.0
    retries: int = 3
    providers: str = ""
    yes: bool = False
    dry_run: bool = False
    run_ai: bool = True
    run_validation: bool = True
    run_uplift: bool = True
    export_reports: bool = True


class AgenticController:
    def __init__(self, config: ControllerConfig) -> None:
        self.config = config
        self.python = sys.executable or "python3"
        self.run_id = create_run(config.target_url, config.mode, "agentic-controller")

    def run(self) -> int:
        log_event("controller_start", self.config.__dict__)
        scan_code = self._run_step(
            "Core VulnScope Scan",
            [
                self.python,
                "vulnscope.py",
                "--url",
                self.config.target_url,
                "--mode",
                self.config.mode,
                "--max-pages",
                str(self.config.max_pages),
                "--timeout",
                str(self.config.timeout),
                "--delay",
                str(self.config.delay),
                "--retries",
                str(self.config.retries),
            ],
            "controlled-active" if self.config.mode == "safe-active" else "passive",
            required=True,
        )
        if scan_code != 0:
            return scan_code

        add_artifact(self.run_id, "evidence", "reports/output/evidence.json", "Core scanner evidence")
        plan = build_next_action_plan("reports/output/evidence.json")
        add_decision(self.run_id, "next_action_plan", plan)
        self._write_plan(plan)

        if self.config.run_ai:
            command = [self.python, "ai_discovery_cli.py", "--input", "reports/output/evidence.json"]
            if self.config.providers:
                command += ["--providers", self.config.providers]
            self._run_step("AI Discovery", command, "internal", required=False)
            add_artifact(self.run_id, "ai-discovery", "reports/output/ai-discovery/ai-discovery-report.md", "AI discovery report")

        if self.config.run_validation:
            self._run_step("Mythic Validation", [self.python, "mythic_hunter_cli.py", "--input", "reports/output/evidence.json", "--depth", "DEEP_HUNTER_MODE"], "internal", required=False)
            add_artifact(self.run_id, "mythic", "reports/output/mythic/mythic-report.md", "Mythic validation report")

        if self.config.run_uplift:
            self._run_step("Uplift Analysis", [self.python, "mythic_uplift_cli.py", "--input", "reports/output/evidence.json"], "internal", required=False)
            add_artifact(self.run_id, "uplift", "reports/output/uplift/uplift-report.md", "Advanced uplift report")

        if self.config.export_reports:
            self._run_step("Report Export", [self.python, "export_reports.py"], "internal", required=False)
            add_artifact(self.run_id, "export", "~/Downloads/vulnscope-report-pack-*.zip", "Report ZIP export")

        log_event("controller_complete", {"run_id": self.run_id})
        return 0

    def _run_step(self, name: str, command: list[str], risk: str, required: bool) -> int:
        log_event("step_planned", {"name": name, "command": command, "risk": risk, "required": required})
        print(f"\n[+] {name}")
        print("    " + " ".join(command))
        if self.config.dry_run:
            return 0
        if not ask_user_approval(name, command, risk, auto_yes=self.config.yes):
            log_event("step_skipped", {"name": name, "reason": "not approved"})
            return 1 if required else 0
        code = subprocess.call(command)
        log_event("step_finished", {"name": name, "exit_code": code})
        if code != 0 and required:
            print(f"[!] Required step failed: {name}")
        return code

    def _write_plan(self, plan: dict) -> None:
        out = Path("reports/output/agentic")
        out.mkdir(parents=True, exist_ok=True)
        (out / "next-action-plan.json").write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
        lines = ["# Agentic Next Action Plan", "", f"Target: `{self.config.target_url}`", "", "## Summary", ""]
        for key, value in plan.get("summary", {}).items():
            if key != "registered_tools":
                lines.append(f"- **{key}:** {value}")
        lines += ["", "## Recommended Actions", ""]
        for idx, action in enumerate(plan.get("recommended_actions", []), start=1):
            lines.append(f"### {idx}. {action.get('name')}")
            lines.append(f"- Risk: {action.get('risk')}")
            lines.append(f"- Approval required: {action.get('approval_required')}")
            lines.append(f"- Why: {action.get('why')}")
            lines.append(f"- Command: `{action.get('command')}`")
            lines.append("")
        (out / "next-action-plan.md").write_text("\n".join(lines), encoding="utf-8")
        add_artifact(self.run_id, "plan", str(out / "next-action-plan.md"), "Agentic next action plan")

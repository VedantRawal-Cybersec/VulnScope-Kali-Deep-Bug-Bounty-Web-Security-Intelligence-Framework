from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

OUT_DIR = Path("reports/output/autonomy")

INPUTS = {
    "healthcheck": "reports/output/arsenal/healthcheck.json",
    "maintenance": "reports/output/maintenance/daily-update-state.json",
    "safe_discovery": "reports/output/safe-discovery/safe-discovery.json",
    "category_suite": "reports/output/category-suite/category-suite.json",
    "comprehensive_suite": "reports/output/comprehensive-suite/comprehensive-suite.json",
    "coverage_matrix": "reports/output/tool-matrix/tool-matrix.json",
    "google_context": "reports/output/auth/google-context/google-context-review.json",
    "auth_compare": "reports/output/auth/account-comparison.json",
    "quality": "reports/output/finding-quality.json",
    "report_v2": "reports/output/report-v2/executive-report-v2.json",
}

@dataclass
class Decision:
    priority: int
    stage: str
    action: str
    reason: str
    command: str
    safety_gate: str = "authorized_scope_required"
    status: str = "recommended"
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

class AutonomousDecisionEngine:
    """Safe planner that decides what VulnScope should do next."""
    def __init__(self, target: str, provider: str | None = None, mode: str = "comprehensive") -> None:
        self.target = target
        self.provider = provider
        self.mode = mode
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        self.data = {name: self._load(path) for name, path in INPUTS.items()}

    def decide(self) -> dict[str, Any]:
        started = time.time()
        decisions: list[Decision] = []
        health = self.data.get("healthcheck") or {}
        maintenance = self.data.get("maintenance") or {}
        safe = self.data.get("safe_discovery") or {}
        comp = self.data.get("comprehensive_suite") or {}
        matrix = self.data.get("coverage_matrix") or {}
        google = self.data.get("google_context") or {}
        quality = self.data.get("quality") or {}

        if not matrix:
            decisions.append(Decision(5, "coverage", "build_module_coverage_matrix", "No module coverage matrix exists yet.", "python3 coverage_matrix.py"))
        elif matrix.get("minimum_modules_per_category", 0) < 5:
            decisions.append(Decision(6, "coverage", "repair_module_coverage", "Coverage matrix is below the required five modules per category.", "python3 coverage_matrix.py"))

        if not maintenance:
            decisions.append(Decision(10, "maintenance", "run_daily_update", "No daily maintenance result found.", "python3 daily_update_cli.py --profile bug-bounty-safe --yes"))
        elif (health.get("missing_count") or 0) > 0:
            decisions.append(Decision(11, "maintenance", "repair_missing_tools", f"Healthcheck still shows {health.get('missing_count')} missing tools.", "python3 daily_update_cli.py --profile bug-bounty-safe --force --yes"))

        if not safe:
            decisions.append(Decision(20, "discovery", "run_safe_discovery", "No safe-discovery evidence exists yet.", f"python3 autopilot_cli.py --target {self.target} --mode {self.mode} --yes"))
        elif safe.get("summary", {}).get("findings", 0):
            decisions.append(Decision(35, "review", "review_safe_discovery", "Safe Discovery produced candidates that should be reviewed and correlated.", "cat reports/output/safe-discovery/safe-discovery.md"))

        if not comp:
            decisions.append(Decision(25, "category_review", "run_comprehensive_suite", "No comprehensive category suite output exists yet.", f"python3 comprehensive_suite_cli.py --target {self.target} --yes"))
        else:
            summary = comp.get("summary", {})
            if summary.get("candidates", 0):
                decisions.append(Decision(36, "category_review", "triage_comprehensive_candidates", f"Comprehensive suite found {summary.get('candidates')} review candidates across {summary.get('categories')} categories.", "cat reports/output/comprehensive-suite/comprehensive-suite.md"))

        if not google:
            decisions.append(Decision(30, "auth_context", "run_google_context_review", "No Google authenticated-context review output exists yet.", "python3 google_context_cli.py"))
        elif google.get("summary", {}).get("candidates", 0):
            decisions.append(Decision(37, "auth_context", "review_google_context", "Google/OAuth context produced session or authorization review candidates.", "cat reports/output/auth/google-context/google-context-review.md"))

        if not quality:
            decisions.append(Decision(50, "quality", "run_quality_report", "No finding-quality output found.", f"python3 report_v2_cli.py --target {self.target}"))
        else:
            accepted = len(quality.get("accepted", []))
            review = len(quality.get("needs_review", []))
            if accepted or review:
                decisions.append(Decision(60, "report", "generate_final_report", f"Quality engine has {accepted} accepted and {review} review items.", f"python3 report_v2_cli.py --target {self.target}"))
            else:
                decisions.append(Decision(70, "coverage", "increase_evidence", "No accepted/review findings yet. More evidence is needed before reporting.", f"python3 auto_mode.py --url {self.target} --profile bug-bounty-safe --full --yes"))

        if self.provider:
            decisions.append(Decision(80, "model_review", "run_model_council", "Provider configured; run model council through autopilot for consensus review.", f"python3 autopilot_cli.py --target {self.target} --mode {self.mode} --provider {self.provider} --yes"))

        ordered = sorted(decisions, key=lambda d: d.priority)
        payload = {"target": self.target, "mode": self.mode, "generated_at": started, "rules": {"state_change": False, "credential_collection": False, "out_of_scope": False}, "next_action": ordered[0].to_dict() if ordered else None, "decisions": [d.to_dict() for d in ordered], "inputs_seen": {k: bool(v) for k, v in self.data.items()}}
        (OUT_DIR / "decision-plan.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        (OUT_DIR / "decision-plan.md").write_text(self._markdown(payload), encoding="utf-8")
        return payload

    def _load(self, path: str) -> Any:
        p = Path(path)
        if not p.exists():
            return None
        try:
            if p.suffix == ".json":
                return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
            return p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None

    def _markdown(self, payload: dict[str, Any]) -> str:
        lines = [f"# VulnScope Autonomous Decision Plan — {payload['target']}", "", "Safe planner output. Execute only on owned or explicitly authorized assets.", ""]
        if payload.get("next_action"):
            n = payload["next_action"]
            lines += ["## Next Best Action", f"- Action: `{n['action']}`", f"- Reason: {n['reason']}", "- Command:", "```bash", n["command"], "```", ""]
        lines.append("## Full Decision Queue")
        for item in payload.get("decisions", []):
            lines += [f"### P{item['priority']} — {item['action']}", f"- Stage: `{item['stage']}`", f"- Reason: {item['reason']}", "```bash", item["command"], "```", ""]
        return "\n".join(lines)

def build_decision_plan(target: str, provider: str | None = None, mode: str = "comprehensive") -> dict[str, Any]:
    return AutonomousDecisionEngine(target=target, provider=provider, mode=mode).decide()

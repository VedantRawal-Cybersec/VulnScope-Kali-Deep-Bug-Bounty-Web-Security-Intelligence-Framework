from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from recon.domain_expander import run_passive_domain_expansion
from review_agents.base_agent import load_json
from review_agents.specialists import SPECIALIST_AGENTS
from workflow.assessment_state import AssessmentState
from workflow.checkpoint_store import save_checkpoint

OUT_DIR = Path("reports/output/workflow")


class PhaseRunner:
    def __init__(self, state: AssessmentState) -> None:
        self.state = state
        OUT_DIR.mkdir(parents=True, exist_ok=True)

    def run_all(self) -> AssessmentState:
        self._phase("P1_SCOPE_CONFIRM", {"scope_rule": "owned or explicitly authorized targets only"})
        self._phase("P2_TARGET_INGEST", {"target": self.state.target})
        self.passive_recon()
        self.app_profile()
        self.auth_context()
        self.agent_planning()
        self.specialist_review()
        self.evidence_validation()
        self.reportability_scoring()
        self.final_report()
        return self.state

    def _phase(self, phase: str, decision: dict[str, Any]) -> None:
        self.state.mark_phase(phase)
        self.state.add_decision({"phase": phase, **decision})
        save_checkpoint(self.state)

    def passive_recon(self) -> None:
        self.state.mark_phase("P3_PASSIVE_RECON")
        result = run_passive_domain_expansion(self.state.target, include_external_tools=True, max_urls=5000)
        self.state.add_artifact("domain_expansion", "reports/output/recon/domain-expansion.json")
        self.state.add_decision({"phase": "P3_PASSIVE_RECON", "subdomains": len(result.subdomains), "archived_urls": len(result.archived_urls), "review_urls": len(result.high_value_urls)})
        save_checkpoint(self.state)

    def app_profile(self) -> None:
        self.state.mark_phase("P4_APP_PROFILE")
        evidence = load_json("reports/output/recon/domain-expansion.json")
        profile = build_app_profile(evidence)
        path = OUT_DIR / "app-profile.json"
        path.write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")
        (OUT_DIR / "app-profile.md").write_text(profile_markdown(profile), encoding="utf-8")
        self.state.add_artifact("app_profile", str(path))
        save_checkpoint(self.state)

    def auth_context(self) -> None:
        auth_available = Path("reports/output/auth").exists()
        self._phase("P5_AUTH_CONTEXT", {"auth_artifacts_available": auth_available, "recommendation": "Use auth_mode.py with owned accounts for account-bound validation."})

    def agent_planning(self) -> None:
        self.state.mark_phase("P6_AGENT_PLANNING")
        plan = {"agents": [agent.name for agent in SPECIALIST_AGENTS], "policy": "review and validation planning only", "mode": self.state.mode}
        path = OUT_DIR / "agent-plan.json"
        path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
        self.state.add_artifact("agent_plan", str(path))
        save_checkpoint(self.state)

    def specialist_review(self) -> None:
        self.state.mark_phase("P7_SPECIALIST_REVIEW")
        evidence = merge_evidence(["reports/output/recon/domain-expansion.json", "reports/output/evidence.json", "reports/output/auth/account-comparison.json"])
        out = OUT_DIR / "specialist-results"
        out.mkdir(parents=True, exist_ok=True)
        for agent in SPECIALIST_AGENTS:
            result = agent.run(evidence).to_dict()
            self.state.add_agent_result(agent.name, result)
            (out / f"{agent.name}.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        save_checkpoint(self.state)

    def evidence_validation(self) -> None:
        self.state.mark_phase("P8_EVIDENCE_VALIDATION")
        tasks = []
        for agent_name, result in self.state.agent_results.items():
            for candidate in result.get("candidates", [])[:200]:
                tasks.append({"agent": agent_name, "candidate": candidate, "validation_status": candidate.get("status", "NEEDS_REVIEW")})
        path = OUT_DIR / "validation-tasks.json"
        path.write_text(json.dumps(tasks, indent=2, ensure_ascii=False), encoding="utf-8")
        self.state.add_artifact("validation_tasks", str(path))
        save_checkpoint(self.state)

    def reportability_scoring(self) -> None:
        self.state.mark_phase("P9_REPORTABILITY_SCORING")
        scores = []
        for agent_name, result in self.state.agent_results.items():
            for candidate in result.get("candidates", [])[:200]:
                scores.append({"agent": agent_name, "candidate": candidate, "reportability_score": score_candidate(candidate), "status": "REVIEW_ONLY"})
        path = OUT_DIR / "reportability-scores.json"
        path.write_text(json.dumps(scores, indent=2, ensure_ascii=False), encoding="utf-8")
        self.state.add_artifact("reportability_scores", str(path))
        save_checkpoint(self.state)

    def final_report(self) -> None:
        self.state.mark_phase("P10_FINAL_REPORT")
        path = OUT_DIR / "vulnscope-assessment-report.md"
        path.write_text(build_final_report(self.state), encoding="utf-8")
        self.state.add_artifact("final_report", str(path))
        save_checkpoint(self.state)


def merge_evidence(paths: list[str]) -> dict[str, Any]:
    merged: dict[str, Any] = {"sources": []}
    for path in paths:
        data = load_json(path)
        if not data:
            continue
        merged["sources"].append(path)
        for key, value in data.items():
            if isinstance(value, list):
                merged.setdefault(key, []).extend(value)
            else:
                merged.setdefault(key, value)
    return merged


def build_app_profile(evidence: dict[str, Any]) -> dict[str, Any]:
    high = evidence.get("high_value_urls", []) if isinstance(evidence, dict) else []
    counts = {"api": 0, "auth": 0, "admin": 0, "object": 0, "file": 0}
    for item in high:
        for sig in item.get("signals", []) if isinstance(item, dict) else []:
            s = sig.get("signal", "")
            counts["api"] += int("api" in s)
            counts["auth"] += int("auth" in s)
            counts["admin"] += int("admin" in s)
            counts["object"] += int("object" in s or "id" in s)
            counts["file"] += int("file" in s)
    return {"target_style": "inferred", "counts": counts, "recommendations": profile_recommendations(counts)}


def profile_recommendations(counts: dict[str, int]) -> list[str]:
    recs = []
    if counts.get("api"):
        recs.append("Prioritize API route mapping and auth context review.")
    if counts.get("auth"):
        recs.append("Use owned-account authenticated validation mode.")
    if counts.get("object"):
        recs.append("Use two-account comparison for object-bound routes.")
    if counts.get("file"):
        recs.append("Review archived files and source maps carefully.")
    return recs or ["Continue passive recon and baseline validation."]


def profile_markdown(profile: dict[str, Any]) -> str:
    lines = ["# Application Profile", "", "## Signal Counts", ""]
    for key, value in profile.get("counts", {}).items():
        lines.append(f"- **{key}:** {value}")
    lines += ["", "## Recommendations", ""]
    for rec in profile.get("recommendations", []):
        lines.append(f"- {rec}")
    return "\n".join(lines)


def score_candidate(candidate: dict[str, Any]) -> int:
    text = json.dumps(candidate).lower()
    score = 20
    score += 20 if "api" in text or "object" in text else 0
    score += 20 if "auth" in text or "account" in text else 0
    score += 15 if "two_account" in text else 0
    return min(score, 100)


def build_final_report(state: AssessmentState) -> str:
    lines = ["# VulnScope Assessment Report", "", f"Target: `{state.target}`", f"Mode: `{state.mode}`", "", "## Completed Phases", ""]
    for phase in state.completed_phases:
        lines.append(f"- {phase}")
    lines += ["", "## Artifacts", ""]
    for name, path in state.artifacts.items():
        lines.append(f"- **{name}:** `{path}`")
    lines += ["", "## Specialist Review Summary", ""]
    for agent, result in state.agent_results.items():
        lines.append(f"### {agent}")
        lines.append(f"- Candidates: {len(result.get('candidates', []))}")
        lines.append(f"- Confidence: {result.get('confidence')}")
        lines.append("")
    lines += ["## Safety Rule", "", "Review candidates are not confirmed vulnerabilities until manually validated on authorized assets."]
    return "\n".join(lines)

#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from cai_error_handler import write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target
from core.scan_state import ScanState


@dataclass
class QualityIssue:
    code: str
    severity: str
    message: str
    recommendation: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class QualityResult:
    target: str
    grade: str
    score: int
    generated_at: float
    coverage: dict[str, int]
    issues: list[QualityIssue] = field(default_factory=list)
    budget: dict[str, Any] = field(default_factory=dict)
    ollama: dict[str, Any] = field(default_factory=dict)
    tool_matrix: dict[str, Any] = field(default_factory=dict)
    findings: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["issues"] = [issue.to_dict() for issue in self.issues]
        return data


class ScanQualityGate:
    """Grades whether a scan had enough surface, parameters, tests, budget, and telemetry."""

    def __init__(self, *, state: ScanState, ollama: dict[str, Any] | None = None, tool_matrix: dict[str, Any] | None = None) -> None:
        self.state = state
        self.target = normalize_target(state.target)
        self.ollama = ollama or {}
        self.tool_matrix = tool_matrix or {}
        self.issues: list[QualityIssue] = []

    def issue(self, code: str, severity: str, message: str, recommendation: str) -> None:
        self.issues.append(QualityIssue(code, severity, message, recommendation))

    def evaluate(self) -> QualityResult:
        cov = self.state.coverage()
        total_budget = int(self.state.stats.get("request_budget_total", cov.get("requests", 0)) or 0)
        budget_plan = dict(self.state.stats.get("budget_plan", {}))
        matrix_counts = dict((self.tool_matrix.get("counts") or {}))
        score = 100

        if cov["urls_total"] < 30:
            self.issue("LOW_URL_COVERAGE", "HIGH", f"Only {cov['urls_total']} URL(s) were discovered.", "Increase max-pages/request-budget, enable --render-js, and inspect sitemap/robots discovery.")
            score -= 25
        if cov["params_total"] == 0:
            self.issue("NO_PARAMETERS", "HIGH", "No parameters were discovered.", "Run with --render-js, check forms/JS/network capture, and validate scope/redirect hosts.")
            score -= 25
        if cov["params_total"] > 0 and cov["tests_total"] == 0:
            self.issue("PARAMS_WITHOUT_TESTS", "CRITICAL", "Parameters were discovered but no tests were queued.", "ParameterInventory must feed TestQueueBuilder before reporting.")
            score -= 35
        if cov["tests_total"] > 0 and cov["tests_done"] == 0:
            self.issue("TESTS_NOT_EXECUTED", "CRITICAL", "Tests were queued but none completed.", "Check test execution loop, request budget reservation, and test status transitions.")
            score -= 35
        if total_budget and cov["requests"] >= total_budget and cov["tests_done"] == 0:
            self.issue("BUDGET_EXHAUSTED_BEFORE_TESTING", "CRITICAL", "Request budget was exhausted before testing completed.", "Use split budgets: reserve at least 30% of requests for tests.")
            score -= 30
        if matrix_counts and int(matrix_counts.get("completed", 0)) == 0:
            self.issue("TOOL_ROUTER_STATIC", "MEDIUM", "Tool router shows no completed tools.", "Update router status during every real stage.")
            score -= 15
        if self.ollama and not bool(self.ollama.get("ok")) and self.ollama.get("generation_status") not in {"skipped", "disabled"}:
            self.issue("LLM_FALLBACK", "MEDIUM", "Ollama generation is unavailable or timed out.", "Use --ollama-timeout 60 or --llm-health-mode tags-only; scanner will continue deterministically.")
            score -= 10

        if score >= 80:
            grade = "HIGH"
        elif score >= 55:
            grade = "MEDIUM"
        else:
            grade = "LOW"

        result = QualityResult(
            target=self.target,
            grade=grade,
            score=max(0, min(100, score)),
            generated_at=time.time(),
            coverage=cov,
            issues=self.issues,
            budget=budget_plan,
            ollama=self.ollama,
            tool_matrix=self.tool_matrix,
            findings={
                "confirmed_vulnerabilities": cov.get("confirmed_vulnerabilities", 0),
                "potential_review_leads": cov.get("potential_review_leads", 0),
                "informational_observations": cov.get("informational_observations", 0),
            },
        )
        self.state.stats["scan_quality"] = result.to_dict()
        self.state.save()
        return result

    def write_reports(self, result: QualityResult) -> dict[str, str]:
        out = cai_output_dir(self.target)
        json_path = out / "scan-quality.json"
        md_path = out / "scan-quality.md"
        write_json(json_path, result.to_dict())
        lines = [
            "# VulnScope Scan Quality Gate",
            "",
            f"Target: `{self.target}`",
            f"Grade: `{result.grade}`",
            f"Score: `{result.score}/100`",
            "",
            "## Coverage",
            "",
            f"- URLs: `{result.coverage.get('urls_done')}/{result.coverage.get('urls_total')}`",
            f"- Parameters: `{result.coverage.get('params_done')}/{result.coverage.get('params_total')}`",
            f"- Tests: `{result.coverage.get('tests_done')}/{result.coverage.get('tests_total')}`",
            f"- Requests: `{result.coverage.get('requests')}`",
            f"- Confirmed vulnerabilities: `{result.findings.get('confirmed_vulnerabilities', 0)}`",
            f"- Potential review leads: `{result.findings.get('potential_review_leads', 0)}`",
            f"- Informational observations: `{result.findings.get('informational_observations', 0)}`",
            "",
            "## Issues",
            "",
        ]
        if not result.issues:
            lines.append("No scan-quality blockers were detected.")
        for issue in result.issues:
            lines.extend([
                f"### {issue.code}",
                f"- Severity: `{issue.severity}`",
                f"- Problem: {issue.message}",
                f"- Fix: {issue.recommendation}",
                "",
            ])
        write_markdown(md_path, lines)
        return {"scan_quality_json": str(json_path), "scan_quality_md": str(md_path)}

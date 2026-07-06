#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class SecurityScorecard:
    """Evidence-based security posture scorecard for secure and non-secure sites."""

    def __init__(self, *, state: Any, extra_reports: dict[str, str] | None = None) -> None:
        self.state = state
        self.extra_reports = extra_reports or {}
        self.out_dir = Path(getattr(state, "out_dir", "reports/output"))

    @staticmethod
    def clamp(value: int) -> int:
        return max(0, min(100, int(value)))

    def score(self) -> dict[str, Any]:
        stats = getattr(self.state, "stats", {}) or {}
        findings = getattr(self.state, "findings", []) or []
        urls = len(getattr(self.state, "urls", {}) or {})
        params = len(getattr(self.state, "params", {}) or {})
        tests = len(getattr(self.state, "tests", {}) or {})
        requests = int(stats.get("requests", 0) or 0)
        tech_count = int(stats.get("technology_count", 0) or 0)
        advisory_count = int(stats.get("advisory_count", 0) or 0)
        api_count = int(stats.get("api_discovery_endpoints", 0) or 0)
        access_items = int(stats.get("access_review_items", 0) or 0)
        high_like = sum(1 for f in findings if str(f.get("severity", "")).upper() in {"HIGH", "CRITICAL"})
        medium_like = sum(1 for f in findings if str(f.get("severity", "")).upper() == "MEDIUM")
        low_like = sum(1 for f in findings if str(f.get("severity", "")).upper() == "LOW")
        coverage_score = self.clamp(20 + min(30, urls * 2) + min(25, params * 2) + min(25, tests)) if requests else 0
        validation_score = self.clamp(100 - high_like * 25 - medium_like * 12 - low_like * 5)
        technology_score = self.clamp(100 - min(40, advisory_count * 4)) if tech_count else 70
        api_score = self.clamp(100 - min(35, api_count // 3)) if api_count else 85
        access_score = self.clamp(100 - access_items * 10)
        orchestration_score = self.clamp(100 - int(stats.get("orchestration_blocking_issues", 0) or 0) * 35 - int(stats.get("orchestration_warnings", 0) or 0) * 5)
        overall = self.clamp(round((coverage_score * 0.20) + (validation_score * 0.25) + (technology_score * 0.15) + (api_score * 0.15) + (access_score * 0.15) + (orchestration_score * 0.10)))
        return {"overall": overall, "coverage_score": coverage_score, "validation_score": validation_score, "technology_score": technology_score, "api_exposure_score": api_score, "access_matrix_score": access_score, "orchestration_score": orchestration_score, "inputs": {"urls": urls, "params": params, "tests": tests, "requests": requests, "findings": len(findings), "technology_count": tech_count, "advisory_count": advisory_count, "api_endpoints": api_count, "access_review_items": access_items, "high_or_critical": high_like, "medium": medium_like, "low": low_like}, "interpretation": self.interpret(overall)}

    @staticmethod
    def interpret(score: int) -> str:
        if score >= 85:
            return "Strong posture based on collected evidence. Review coverage gaps before making final assurance claims."
        if score >= 70:
            return "Moderate-to-strong posture with specific review areas. Improve coverage and validate review leads."
        if score >= 50:
            return "Moderate posture. Several areas need follow-up validation or hardening."
        return "Weak or insufficiently assessed posture. Improve coverage and address high-confidence findings first."

    def write(self) -> dict[str, str]:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        payload = {"target": getattr(self.state, "target", ""), "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "scorecard": self.score(), "registered_reports": self.extra_reports}
        json_path = self.out_dir / "security-scorecard.json"
        md_path = self.out_dir / "security-scorecard.md"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        s = payload["scorecard"]
        lines = ["# Security Posture Scorecard", "", f"Target: `{payload['target']}`", f"Overall Score: `{s['overall']}/100`", s["interpretation"], "", "## Category Scores", "", f"- Coverage: `{s['coverage_score']}`", f"- Validation: `{s['validation_score']}`", f"- Technology / advisory posture: `{s['technology_score']}`", f"- API exposure posture: `{s['api_exposure_score']}`", f"- Access matrix posture: `{s['access_matrix_score']}`", f"- Orchestration reliability: `{s['orchestration_score']}`", "", "## Inputs", "", "```json", json.dumps(s["inputs"], indent=2, ensure_ascii=False), "```"]
        md_path.write_text("\n".join(lines), encoding="utf-8")
        try:
            self.state.stats["security_score_overall"] = s["overall"]
            self.state.save()
        except Exception:
            pass
        return {"security_scorecard_json": str(json_path), "security_scorecard_md": str(md_path)}

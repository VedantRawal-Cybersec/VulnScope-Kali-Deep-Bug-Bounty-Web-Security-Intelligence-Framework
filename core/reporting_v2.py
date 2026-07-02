#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from cai_error_handler import write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target
from core.scan_state import ScanState


class ReportingV2:
    def __init__(self, *, state: ScanState, extra_reports: dict[str, str] | None = None) -> None:
        self.state = state
        self.target = normalize_target(state.target)
        self.out = cai_output_dir(self.target)
        self.extra_reports = extra_reports or {}

    def severity_counts(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in self.state.findings:
            sev = str(finding.get("severity") or "INFO").upper()
            counts[sev if sev in counts else "INFO"] += 1
        return counts

    def write_json_report(self) -> Path:
        path = self.out / "autonomous-scan-report.json"
        payload = {
            "target": self.target,
            "coverage": self.state.coverage(),
            "severity_counts": self.severity_counts(),
            "findings": self.state.findings,
            "parameters": [vars(item) for item in self.state.params.values()],
            "urls": [vars(item) for item in self.state.urls.values()],
            "tests": [vars(item) for item in self.state.tests.values()],
            "reports": self.extra_reports,
            "safety": {
                "same_scope_only": True,
                "transparent_user_agent": True,
                "request_budget": True,
                "adaptive_backoff": True,
                "resume_supported": True,
                "target_data_modification": False,
            },
        }
        write_json(path, payload)
        return path

    def write_markdown_report(self) -> Path:
        path = self.out / "autonomous-scan-report.md"
        cov = self.state.coverage()
        counts = self.severity_counts()
        lines = [
            "# VulnScope Autonomous Scan Report",
            "",
            f"Target: `{self.target}`",
            "",
            "## Coverage",
            "",
            f"- URLs: `{cov['urls_done']}/{cov['urls_total']}`",
            f"- Parameters: `{cov['params_done']}/{cov['params_total']}`",
            f"- Tests: `{cov['tests_done']}/{cov['tests_total']}`",
            f"- Requests: `{cov['requests']}`",
            f"- Timeouts: `{cov['timeouts']}`",
            f"- Findings/leads: `{cov['findings']}`",
            "",
            "## Severity Summary",
            "",
        ]
        for key in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            lines.append(f"- `{key}`: `{counts[key]}`")
        lines += ["", "## Findings and Review Leads", ""]
        if not self.state.findings:
            lines.append("No confirmed findings or review leads were generated in the selected safe scope.")
        for finding in self.state.findings:
            lines.extend([
                f"### {finding.get('id')} — {finding.get('title')}",
                f"- Status: `{finding.get('status')}`",
                f"- Severity: `{finding.get('severity')}`",
                f"- Confidence: `{finding.get('confidence')}%`",
                f"- Category: `{finding.get('category')}`",
                f"- URL: `{finding.get('affected_url')}`",
                f"- Parameter: `{finding.get('parameter') or 'N/A'}`",
                f"- Evidence: {finding.get('evidence')}",
                f"- Impact: {finding.get('impact')}",
                f"- Recommendation: {finding.get('recommendation')}",
                "",
                "Validation steps:",
            ])
            for step in finding.get("reproduction_steps", [])[:8]:
                lines.append(f"- {step}")
            lines.append("")
        lines += ["## Top Parameter Inventory", ""]
        for param in sorted(self.state.params.values(), key=lambda p: p.risk_score, reverse=True)[:100]:
            lines.append(f"- `{param.name}` kind=`{param.kind}` risk=`{param.risk_score}` status=`{param.status}` source=`{param.source}` url=`{param.url}`")
        if self.extra_reports:
            lines += ["", "## Additional Artifacts", ""]
            for name, report_path in self.extra_reports.items():
                lines.append(f"- `{name}`: `{report_path}`")
        write_markdown(path, lines)
        return path

    def write_csv_findings(self) -> Path:
        path = self.out / "autonomous-findings.csv"
        path.parent.mkdir(parents=True, exist_ok=True)
        fields = ["id", "title", "status", "severity", "confidence", "category", "affected_url", "parameter", "evidence", "recommendation"]
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for finding in self.state.findings:
                writer.writerow({key: finding.get(key, "") for key in fields})
        return path

    def write_parameter_inventory(self) -> Path:
        path = self.out / "parameter-inventory-v2.json"
        write_json(path, [vars(item) for item in self.state.params.values()])
        return path

    def write_all(self) -> dict[str, str]:
        self.state.save()
        state_md = self.state.write_markdown_summary()
        return {
            "autonomous_report_json": str(self.write_json_report()),
            "autonomous_report_md": str(self.write_markdown_report()),
            "autonomous_findings_csv": str(self.write_csv_findings()),
            "parameter_inventory_v2": str(self.write_parameter_inventory()),
            "autonomous_state_json": str(self.state.path),
            "autonomous_state_md": str(state_md),
            **self.extra_reports,
        }

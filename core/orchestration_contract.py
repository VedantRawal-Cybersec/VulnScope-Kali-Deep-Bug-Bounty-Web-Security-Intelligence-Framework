#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

EXPECTED_PHASES = [
    "01 Diagnostics",
    "02 Scope + Passive Analysis",
    "03 Deep Asset Discovery",
    "04 Primary Crawl",
    "05 JavaScript Endpoint Extraction",
    "06 Browser Route Discovery",
    "07 Post-Discovery Crawl",
    "08 Deep Scan Phase Pack",
    "09 LLM Surface Review",
    "10 Unified Research Orchestration",
    "11 Dynamic Tool Scheduler",
    "12 Safe Parameter + Endpoint Review",
    "13 Reporting",
]

HARD_REQUIRED = {"01 Diagnostics", "02 Scope + Passive Analysis", "04 Primary Crawl", "12 Safe Parameter + Endpoint Review", "13 Reporting"}


class OrchestrationContract:
    """Final quality gate for VulnScope scan orchestration.

    This does not require every target to have vulnerabilities. It requires every
    phase to be accounted for, every failure to be visible, and every report to
    explain what was covered and what was not.
    """

    def __init__(self, *, state: Any, phase_runner: Any, extra_reports: dict[str, str] | None = None, dynamic_summary: dict[str, Any] | None = None, react_summary: dict[str, Any] | None = None) -> None:
        self.state = state
        self.phase_runner = phase_runner
        self.extra_reports = extra_reports or {}
        self.dynamic_summary = dynamic_summary or {}
        self.react_summary = react_summary or {}
        self.out_dir = Path(getattr(state, "out_dir", "reports/output"))

    def _phase_rows(self) -> list[dict[str, Any]]:
        rows = []
        for item in getattr(self.phase_runner, "results", []) or []:
            row = item if isinstance(item, dict) else getattr(item, "__dict__", {})
            rows.append(dict(row))
        return rows

    def _phase_map(self) -> dict[str, dict[str, Any]]:
        return {str(row.get("name")): row for row in self._phase_rows()}

    def _coverage(self) -> dict[str, Any]:
        try:
            return dict(self.state.coverage())
        except Exception:
            return {}

    def _report_exists(self, value: str) -> bool:
        try:
            return bool(value and Path(value).exists() and Path(value).stat().st_size > 0)
        except Exception:
            return False

    def validate(self) -> dict[str, Any]:
        phase_map = self._phase_map()
        coverage = self._coverage()
        blocking: list[str] = []
        warnings: list[str] = []
        for name in EXPECTED_PHASES:
            row = phase_map.get(name)
            if not row:
                message = f"phase missing from runner history: {name}"
                if name in HARD_REQUIRED:
                    blocking.append(message)
                else:
                    warnings.append(message)
                continue
            status = str(row.get("status") or "unknown")
            data = row.get("data") or {}
            if status.startswith("failed"):
                message = f"phase failed: {name}: {row.get('error') or data.get('error') or 'unknown error'}"
                if name in HARD_REQUIRED:
                    blocking.append(message)
                else:
                    warnings.append(message)
            if isinstance(data, dict) and data.get("skipped"):
                warnings.append(f"phase skipped with reason: {name}: {data.get('reason', 'no reason recorded')}")
        if coverage:
            if int(coverage.get("urls_total", 0) or 0) == 0:
                blocking.append("no URLs were recorded in scan state")
            if int(coverage.get("requests", 0) or 0) == 0:
                blocking.append("no HTTP requests were recorded")
        report_failures = []
        for key, value in sorted(self.extra_reports.items()):
            if isinstance(value, str) and value and not self._report_exists(value):
                report_failures.append({"key": key, "path": value})
        if report_failures:
            warnings.append(f"{len(report_failures)} report paths were registered but not found or empty")
        react_turns = 0
        if isinstance(self.react_summary, dict):
            react_turns = len(self.react_summary.get("turns", []) or [])
            pending = (self.react_summary.get("surface") or {}).get("pending_work") or (self.react_summary.get("progress_guard") or {}).get("pending_work")
            if pending:
                warnings.append(f"autonomy loop ended with pending work: {pending}")
        dynamic_runs = len((self.dynamic_summary or {}).get("runs", []) or [])
        payload = {
            "ok": not blocking,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target": getattr(self.state, "target", ""),
            "scan_mode": (getattr(self.state, "stats", {}) or {}).get("scan_mode", ""),
            "expected_phases": EXPECTED_PHASES,
            "hard_required_phases": sorted(HARD_REQUIRED),
            "phase_count": len(phase_map),
            "phases": [phase_map.get(name, {"name": name, "status": "missing"}) for name in EXPECTED_PHASES],
            "coverage": coverage,
            "react_turns": react_turns,
            "dynamic_runs": dynamic_runs,
            "blocking_issues": blocking,
            "warnings": warnings,
            "registered_reports": self.extra_reports,
            "missing_or_empty_reports": report_failures,
        }
        return payload

    def write(self) -> dict[str, str | bool | int]:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        payload = self.validate()
        json_path = self.out_dir / "orchestration-contract.json"
        md_path = self.out_dir / "orchestration-contract.md"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        lines = ["# VulnScope Orchestration Contract", "", f"Target: `{payload['target']}`", f"Mode: `{payload['scan_mode']}`", f"Contract OK: `{payload['ok']}`", "", "## Phase Ledger", ""]
        for row in payload["phases"]:
            lines.append(f"- **{row.get('name')}** status=`{row.get('status')}` elapsed_ms=`{row.get('elapsed_ms', 0)}` error=`{row.get('error', '')}`")
        lines.extend(["", "## Blocking Issues", ""])
        if payload["blocking_issues"]:
            for item in payload["blocking_issues"]:
                lines.append(f"- {item}")
        else:
            lines.append("No blocking orchestration issues were detected.")
        lines.extend(["", "## Warnings", ""])
        if payload["warnings"]:
            for item in payload["warnings"]:
                lines.append(f"- {item}")
        else:
            lines.append("No orchestration warnings were detected.")
        lines.extend(["", "## Coverage", "", "```json", json.dumps(payload["coverage"], indent=2, ensure_ascii=False), "```"])
        md_path.write_text("\n".join(lines), encoding="utf-8")
        try:
            self.state.stats["orchestration_contract_ok"] = bool(payload["ok"])
            self.state.stats["orchestration_blocking_issues"] = len(payload["blocking_issues"])
            self.state.stats["orchestration_warnings"] = len(payload["warnings"])
            self.state.save()
        except Exception:
            pass
        return {"orchestration_contract_json": str(json_path), "orchestration_contract_md": str(md_path), "orchestration_contract_ok": bool(payload["ok"]), "orchestration_blocking_issues": len(payload["blocking_issues"]), "orchestration_warnings": len(payload["warnings"])}

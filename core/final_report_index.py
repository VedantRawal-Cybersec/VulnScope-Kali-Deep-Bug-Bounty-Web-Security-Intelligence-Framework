#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class FinalReportIndex:
    """Single report index that links and summarizes generated artifacts."""

    ORDER = [
        "autonomous_learning_md",
        "learning_graph_md",
        "self_healing_diagnostics_md",
        "technology_intelligence_md",
        "technology_test_plan_md",
        "surface_map_md",
        "browser_network_capture_md",
        "endpoint_artifact_import_md",
        "api_discovery_md",
        "access_matrix_md",
        "tool_manifest_registry_md",
        "advisory_enrichment_md",
        "security_scorecard_md",
        "ethical_methodology_md",
        "orchestration_contract_md",
        "deepseek_autonomy_markdown",
        "scan_health_md",
        "dynamic_tool_phase_summary",
        "tool_status_dashboard_json",
    ]

    def __init__(self, *, state: Any, reports: dict[str, str], summary: dict[str, Any] | None = None) -> None:
        self.state = state
        self.reports = reports
        self.summary = summary or {}
        self.out_dir = Path(getattr(state, "out_dir", "reports/output"))

    def write(self) -> dict[str, str]:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        md_path = self.out_dir / "final-report-index.md"
        json_path = self.out_dir / "final-report-index.json"
        coverage = self.state.coverage() if hasattr(self.state, "coverage") else {}
        payload = {"target": getattr(self.state, "target", ""), "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "coverage": coverage, "reports": self.reports, "summary": self.summary}
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        lines = ["# Final Report Index", "", f"Target: `{payload['target']}`", "", "## Coverage", "", "```json", json.dumps(coverage, indent=2, ensure_ascii=False), "```", "", "## Report Index", ""]
        for key in self.ORDER:
            value = self.reports.get(key)
            if value:
                lines.append(f"- `{key}` → `{value}`")
        for key, value in sorted(self.reports.items()):
            if key not in self.ORDER:
                lines.append(f"- `{key}` → `{value}`")
        lines.extend(["", "## Highlights", ""])
        for key in self.ORDER:
            path = self.reports.get(key)
            if not path:
                continue
            p = Path(path)
            if p.exists() and p.suffix.lower() == ".md":
                text = p.read_text(encoding="utf-8", errors="ignore")[:4000]
                lines.extend(["", "---", "", f"## {key}", "", text])
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return {"final_report_index_md": str(md_path), "final_report_index_json": str(json_path)}

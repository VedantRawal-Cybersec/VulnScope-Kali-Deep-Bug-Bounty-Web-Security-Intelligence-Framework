#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


def _safe_len(value: Any) -> int:
    try:
        return len(value)
    except Exception:
        return 0


class ScanHealthReporter:
    """Writes an operator-focused health report explaining scan coverage and gaps."""

    def __init__(self, *, state: Any, phase_runner: Any | None = None, dynamic_summary: dict[str, Any] | None = None, extra: dict[str, Any] | None = None) -> None:
        self.state = state
        self.phase_runner = phase_runner
        self.dynamic_summary = dynamic_summary or {}
        self.extra = extra or {}

    def _phase_summary(self) -> dict[str, Any]:
        if self.phase_runner is None or not hasattr(self.phase_runner, "summary"):
            return {"total": 0, "completed": 0, "failed_non_blocking": 0, "failed_required": 0, "phases": []}
        try:
            return self.phase_runner.summary()
        except Exception as exc:
            return {"total": 0, "error": str(exc)[:500], "phases": []}

    def _dynamic_summary(self) -> dict[str, Any]:
        runs = self.dynamic_summary.get("runs", []) if isinstance(self.dynamic_summary, dict) else []
        phase_health = self.dynamic_summary.get("phase_health", {}) if isinstance(self.dynamic_summary, dict) else {}
        return {
            "runs_total": _safe_len(runs),
            "completed": sum(1 for item in runs if item.get("status") == "completed"),
            "failed": sum(1 for item in runs if item.get("status") == "failed"),
            "timed_out": sum(1 for item in runs if item.get("status") == "timed_out"),
            "not_ready": sum(1 for item in runs if item.get("status") == "not_ready"),
            "blocked_by_safety": sum(1 for item in runs if item.get("status") == "blocked_by_safety"),
            "findings_captured": sum(int((item.get("result") or {}).get("findings_captured") or 0) for item in runs if isinstance(item, dict)),
            "why_no_dynamic_findings": self.dynamic_summary.get("why_no_dynamic_findings", []) if isinstance(self.dynamic_summary, dict) else [],
            "phase_health": phase_health,
        }

    def _why_no_findings(self, coverage: dict[str, Any], dynamic: dict[str, Any]) -> list[str]:
        reasons: list[str] = []
        if int(coverage.get("findings", 0)) > 0:
            return reasons
        stats = getattr(self.state, "stats", {}) or {}
        if stats.get("target_reachable") is False:
            reasons.append("Target was not reachable from this machine. Check DNS/proxy/VPN/firewall and logs/network_diagnostics.json.")
        if int(coverage.get("params_total", 0)) == 0:
            reasons.append("No query/form parameters were discovered or seeded. Add same-scope seed URLs or increase crawling/browser coverage.")
        if int(coverage.get("tests_done", 0)) == 0:
            reasons.append("No safe parameter tests completed. Use safe-active/bugbounty mode and ensure parameters exist.")
        if dynamic.get("runs_total", 0) == 0:
            reasons.append("No dynamic tools ran. Run `python3 vulnscope.py --ai-repair-tools` and approve safe tools.")
        elif dynamic.get("findings_captured", 0) == 0:
            reasons.extend(dynamic.get("why_no_dynamic_findings") or ["Dynamic tools ran but produced no parsed findings."])
        if not reasons:
            reasons.append("No evidence crossed the configured finding threshold under the selected safe scope and request budget.")
        return reasons

    def build(self) -> dict[str, Any]:
        coverage = self.state.coverage() if hasattr(self.state, "coverage") else {}
        stats = getattr(self.state, "stats", {}) or {}
        phases = self._phase_summary()
        dynamic = self._dynamic_summary()
        payload = {
            "generated_at": time.time(),
            "target": getattr(self.state, "target", ""),
            "host": getattr(self.state, "host", ""),
            "target_reachable": stats.get("target_reachable", None),
            "reachability_error": stats.get("target_reachability_error", ""),
            "coverage": coverage,
            "surface": {
                "urls_found": _safe_len(getattr(self.state, "urls", {})),
                "params_found": _safe_len(getattr(self.state, "params", {})),
                "tests_found": _safe_len(getattr(self.state, "tests", {})),
                "findings_found": _safe_len(getattr(self.state, "findings", [])),
                "forms_found": int(stats.get("forms", 0) or 0) + int(stats.get("browser_forms", 0) or 0),
                "scripts_found": int(stats.get("scripts", 0) or 0),
                "javascript_routes": int(stats.get("javascript_routes", 0) or 0),
            },
            "phases": phases,
            "dynamic_tools": dynamic,
            "reports": self.extra,
            "why_no_findings": self._why_no_findings(coverage, dynamic),
            "next_fix_commands": [
                "python3 scripts/network_diag.py --target <target>",
                "python3 vulnscope.py --ai-repair-tools",
                "python3 vulnscope.py --ai-repair-tools --ai-repair-approve-safe-run",
                "python3 vulnscope_deep.py <target> --seed-url '/path?param=value'",
            ],
        }
        return payload

    def write_all(self) -> dict[str, str]:
        out_dir = Path(getattr(self.state, "out_dir", "reports/output/vulnscope-health"))
        out_dir.mkdir(parents=True, exist_ok=True)
        payload = self.build()
        json_path = out_dir / "scan-health.json"
        md_path = out_dir / "scan-health.md"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        lines = [
            "# VulnScope Scan Health",
            "",
            f"Target: `{payload.get('target')}`",
            f"Reachable: `{payload.get('target_reachable')}`",
            f"Coverage: `{payload.get('coverage')}`",
            "",
            "## Why no findings / gaps",
        ]
        for reason in payload.get("why_no_findings", []):
            lines.append(f"- {reason}")
        lines += ["", "## Next fix commands"]
        for command in payload.get("next_fix_commands", []):
            lines.append(f"- `{command}`")
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return {"scan_health_json": str(json_path), "scan_health_md": str(md_path)}

#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


class SelfHealingDiagnostics:
    """Local self-diagnostics and repair-plan generator.

    This module does not silently install packages or modify target systems. It
    detects missing dependencies, compile errors, missing external binaries, and
    report gaps, then writes exact commands and safe remediation steps.
    """

    CORE_FILES = [
        "vulnscope.py",
        "core/deepseek_cli.py",
        "core/deepseek_dashboard_engine.py",
        "core/autonomous_learning_engine.py",
        "core/learning_graph.py",
        "core/safe_surface_engine.py",
        "core/test_engine.py",
        "core/reporting_v2.py",
        "core/live_dashboard_v2.py",
    ]
    OPTIONAL_IMPORTS = ["ollama", "playwright", "bs4", "requests"]
    OPTIONAL_BINARIES = ["nuclei", "katana", "httpx", "subfinder", "naabu", "ffuf"]

    def __init__(self, *, state: Any | None = None, dashboard: Any | None = None, out_dir: str | None = None) -> None:
        self.state = state
        self.dashboard = dashboard
        self.target = getattr(state, "target", "") if state is not None else ""
        self.out_dir = Path(out_dir) if out_dir else Path(getattr(state, "out_dir", "reports/output/self-healing"))
        self.issues: list[dict[str, Any]] = []
        self.actions: list[dict[str, Any]] = []

    def dash(self, action: str, status: str = "running") -> None:
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(phase="Self Diagnostics", phase_progress=84, current_agent="SelfHealingAgent", current_tool="self_healing_diagnostics", tool_status=status, action=action, endpoint=self.target or "local", safety_status="local diagnostics only")

    def add_issue(self, severity: str, title: str, evidence: str, action: str) -> None:
        self.issues.append({"severity": severity, "title": title, "evidence": evidence, "action": action})
        self.actions.append({"title": title, "command_or_step": action})

    def check_compile(self) -> None:
        existing = [p for p in self.CORE_FILES if Path(p).exists()]
        if not existing:
            self.add_issue("HIGH", "No core files found", "Expected project files were not found from the current directory.", "Run diagnostics from the repository root.")
            return
        cmd = [sys.executable, "-m", "py_compile", *existing]
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=60)
        if proc.returncode != 0:
            self.add_issue("HIGH", "Python compile failure", (proc.stderr or proc.stdout)[:2000], "Fix the file/line shown by py_compile, then re-run diagnostics.")

    def check_imports(self) -> None:
        for name in self.OPTIONAL_IMPORTS:
            if importlib.util.find_spec(name) is None:
                if name == "playwright":
                    step = "pip install playwright && playwright install chromium"
                elif name == "ollama":
                    step = "pip install ollama  # optional when using --allow-ai-fallback"
                else:
                    step = f"pip install {name}"
                self.add_issue("MEDIUM", f"Optional Python package missing: {name}", f"importlib could not locate {name}", step)

    def check_binaries(self) -> None:
        for binary in self.OPTIONAL_BINARIES:
            if shutil.which(binary) is None:
                self.add_issue("MEDIUM", f"Optional external binary missing: {binary}", f"{binary} is not in PATH", "Install the binary or keep its manifest disabled until installed.")

    def check_reports(self) -> None:
        if self.state is None:
            return
        out = Path(getattr(self.state, "out_dir", ""))
        expected = ["surface-map.md", "defined-verdict.md", "final-report-index.md", "orchestration-contract.md"]
        for name in expected:
            if out and not (out / name).exists():
                self.add_issue("LOW", f"Report not present yet: {name}", str(out / name), "This report is produced near the end of a full scan; check phase completion if missing after scan end.")

    def write(self) -> dict[str, str]:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        payload = {"target": self.target, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "issues": self.issues, "actions": self.actions, "policy": "diagnose and suggest; no silent installs or target mutation"}
        json_path = self.out_dir / "self-healing-diagnostics.json"
        md_path = self.out_dir / "self-healing-diagnostics.md"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        lines = ["# Self-Healing Diagnostics", "", f"Target: `{self.target or 'local'}`", f"Issues: `{len(self.issues)}`", "", "## Issues"]
        if not self.issues:
            lines.append("No local diagnostic issues were detected.")
        for item in self.issues:
            lines.extend(["", f"### {item['severity']} — {item['title']}", f"Evidence: `{item['evidence']}`", "", "Action:", "```bash", item["action"], "```"])
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return {"self_healing_diagnostics_json": str(json_path), "self_healing_diagnostics_md": str(md_path)}

    def run(self) -> dict[str, Any]:
        self.dash("Running local self-diagnostics")
        try:
            self.check_compile()
            self.check_imports()
            self.check_binaries()
            self.check_reports()
        except Exception as exc:
            self.add_issue("HIGH", "Diagnostics crashed", str(exc)[:1000], "Inspect self-healing diagnostics error and re-run with python -m core.self_healing_diagnostics.")
        reports = self.write()
        self.dash("Self-diagnostics completed", status="completed")
        return {"ok": True, "issues": len(self.issues), "reports": reports}


if __name__ == "__main__":
    print(json.dumps(SelfHealingDiagnostics().run(), indent=2, ensure_ascii=False))

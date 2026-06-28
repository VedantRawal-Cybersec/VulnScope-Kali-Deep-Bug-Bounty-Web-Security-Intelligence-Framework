from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

try:
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
except Exception:  # pragma: no cover
    Console = None

WATCH_FILES = {
    "workflow_report": "reports/output/workflow/vulnscope-assessment-report.md",
    "agent_summary": "reports/output/agent_core/agent-core-summary.json",
    "activity": "reports/output/agent_core/activity.jsonl",
    "council": "reports/output/agent_core/model-council/council-consensus.md",
    "quality": "reports/output/finding-quality.json",
}


def _read_json(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}


def render_table() -> Any:
    if Console is None:
        return "Install rich for dashboard: pip install rich"
    table = Table(title="VulnScope Live Dashboard")
    table.add_column("Artifact")
    table.add_column("Status")
    table.add_column("Details")
    for name, path in WATCH_FILES.items():
        p = Path(path)
        status = "ready" if p.exists() else "missing"
        details = ""
        if p.exists():
            details = f"{p.stat().st_size} bytes"
            if path.endswith(".json"):
                data = _read_json(path)
                if name == "agent_summary":
                    details = f"agents={len(data.get('agent_results', []))}, tools={len(data.get('tool_results', []))}"
                elif name == "quality":
                    details = str(data.get("summary", details))
        table.add_row(name, status, details)
    return Panel(table, title="Authorized Assessment Monitor")


def run_dashboard(refresh: float = 2.0, once: bool = False) -> None:
    if Console is None:
        print("Install rich first: pip install rich")
        return
    console = Console()
    if once:
        console.print(render_table())
        return
    with Live(render_table(), console=console, refresh_per_second=max(1, int(1 / refresh))) as live:
        while True:
            live.update(render_table())
            time.sleep(refresh)

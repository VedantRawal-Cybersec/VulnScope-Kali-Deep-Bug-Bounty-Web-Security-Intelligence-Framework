#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

OUT = Path("reports/output/kai-interface")

DASHBOARDS: dict[str, dict[str, Any]] = {
    "1": {
        "name": "Website Snapshot",
        "profile": "snapshot",
        "purpose": "Fast website overview, scope check, headers, adaptive safe parameter review, basic evidence, final brief.",
        "max_cycles": 2,
        "max_workers": 4,
        "run_main_scan": True,
        "run_top100_safe": True,
        "include_controlled_top100": False,
        "estimated_seconds": 420,
    },
    "2": {
        "name": "Website Intelligence",
        "profile": "standard",
        "purpose": "Balanced scan with evidence correlation, reportability, Top100 status, adaptive safe parameter families, and data bundle.",
        "max_cycles": 5,
        "max_workers": 6,
        "run_main_scan": True,
        "run_top100_safe": True,
        "include_controlled_top100": False,
        "estimated_seconds": 900,
    },
    "3": {
        "name": "Deep Website Evidence",
        "profile": "deep",
        "purpose": "Full authorized website review with autonomous modules, installed Top100 safe runners, and adaptive safe parameter family review.",
        "max_cycles": 8,
        "max_workers": 8,
        "run_main_scan": True,
        "run_top100_safe": True,
        "include_controlled_top100": True,
        "estimated_seconds": 1800,
    },
    "4": {
        "name": "Data Export Only",
        "profile": "export_only",
        "purpose": "Do not rescan. Rebuild final brief and create a downloadable data bundle from current reports.",
        "max_cycles": 0,
        "max_workers": 1,
        "run_main_scan": False,
        "run_top100_safe": False,
        "include_controlled_top100": False,
        "estimated_seconds": 120,
    },
    "5": {
        "name": "Top100 Tool Dashboard",
        "profile": "top100_only",
        "purpose": "Check integrated Top100 tools and run installed safe runners plus adaptive safe parameter families only for the target.",
        "max_cycles": 0,
        "max_workers": 2,
        "run_main_scan": False,
        "run_top100_safe": True,
        "include_controlled_top100": True,
        "estimated_seconds": 600,
    },
}


def _line() -> None:
    print("─" * 78, flush=True)


def show_dashboard_menu(target: str, host: str) -> None:
    print("\n" + "═" * 78, flush=True)
    print("VULNSCOPE WEBSITE SCAN DASHBOARD", flush=True)
    print("Choose what the website tool should do before the scan starts.", flush=True)
    print(f"Target: {target}", flush=True)
    print(f"Host  : {host}", flush=True)
    print("═" * 78, flush=True)
    for key, item in DASHBOARDS.items():
        print(f"[{key}] {item['name']}", flush=True)
        print(f"    {item['purpose']}", flush=True)
        print(f"    Profile={item['profile']} cycles={item['max_cycles']} workers={item['max_workers']} approx={item['estimated_seconds']}s", flush=True)
        _line()


def choose_dashboard(session: dict[str, Any]) -> dict[str, Any]:
    target = str(session.get("target", "authorized-target"))
    host = str(session.get("host", "target"))
    show_dashboard_menu(target, host)

    default_choice = "3"
    if not sys.stdin.isatty():
        choice = default_choice
        print(f"Non-interactive terminal detected. Selected default dashboard: {choice}", flush=True)
    else:
        choice = input("Select dashboard [1-5] (default 3): ").strip() or default_choice
        if choice not in DASHBOARDS:
            print("Invalid choice. Using Deep Website Evidence.", flush=True)
            choice = default_choice

    selected = dict(DASHBOARDS[choice])
    selected.update({"choice": choice, "target": target, "host": host, "selected_at": time.time()})
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "scan-dashboard-selection.json").write_text(json.dumps(selected, indent=2), encoding="utf-8")

    lines = [
        "# VulnScope Website Scan Dashboard Selection",
        "",
        f"Target: `{target}`",
        f"Host: `{host}`",
        f"Choice: `{choice}`",
        f"Dashboard: `{selected['name']}`",
        f"Profile: `{selected['profile']}`",
        f"Estimated seconds: `{selected['estimated_seconds']}`",
        "",
        "## What will run",
        f"- Main autonomous scan: `{selected['run_main_scan']}`",
        f"- Top100 safe runners and adaptive safe parameter review: `{selected['run_top100_safe']}`",
        f"- Controlled safe Top100 tools: `{selected['include_controlled_top100']}`",
        f"- Max cycles: `{selected['max_cycles']}`",
        f"- Max workers: `{selected['max_workers']}`",
        "",
        "## Purpose",
        selected["purpose"],
    ]
    (OUT / "scan-dashboard-selection.md").write_text("\n".join(lines), encoding="utf-8")

    print("\n[+] Dashboard selected")
    print(f"    {selected['name']} ({selected['profile']})")
    print("    Report: reports/output/kai-interface/scan-dashboard-selection.md")
    return selected


if __name__ == "__main__":
    sample = {"target": "https://example.com", "host": "example.com"}
    print(json.dumps(choose_dashboard(sample), indent=2))

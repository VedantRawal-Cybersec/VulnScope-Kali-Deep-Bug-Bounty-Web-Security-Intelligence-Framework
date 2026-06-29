from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from normalizers.evidence import normalize_all

OUT = Path("reports/output/tool-brain")


def build_tool_brain_plan(target: str | None = None) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    ev = normalize_all(target)
    endpoints = ev.get("endpoints", [])
    tags = {tag for e in endpoints for tag in e.get("risk_tags", [])}
    params = set(ev.get("parameters", []))
    actions = []

    def add(priority: int, action: str, reason: str, command: str, mode: str = "safe") -> None:
        actions.append({"priority": priority, "action": action, "reason": reason, "command": command, "mode": mode})

    add(10, "tool_status", "Confirm large tool registry and installed coverage before deep review.", "python3 mega_tools_cli.py --status")
    if len(endpoints) < 20:
        add(20, "expand_urls", "Endpoint corpus is small; collect more historical and crawled URLs.", f"python3 auto_mode.py --url {target or 'TARGET'} --profile bug-bounty-safe --full --yes")
    if "api_surface" in tags or any(p in params for p in ["id", "user", "account", "token"]):
        add(30, "api_intel", "API-like endpoints or auth/object parameters were observed.", f"python3 api_intel_cli.py --target {target or 'TARGET'}")
    if "object_reference" in tags:
        add(40, "auth_diff", "Object references were observed; Account A/B differential review is the next high-value step.", "python3 auth_diff_v2_cli.py")
    if "rendering_surface" in tags:
        add(50, "js_review", "Rendering-related parameters or callback surfaces exist; correlate with JS sinks.", f"python3 comprehensive_suite_cli.py --target {target or 'TARGET'} --yes")
    if "file_surface" in tags:
        add(60, "file_review", "File/download/upload routes were observed; generate evidence cards for manual review.", f"python3 evidence_cards_cli.py --target {target or 'TARGET'}")
    add(90, "asset_graph", "Build unified graph so endpoints, params, risk tags, and candidates are connected.", f"python3 asset_graph_cli.py --target {target or 'TARGET'}")
    add(100, "reportability", "Rank candidates by evidence quality and bug-bounty reportability.", f"python3 reportability_cli.py --target {target or 'TARGET'}")
    add(110, "history_diff", "Save current state and compare with previous target history.", f"python3 target_history_cli.py --target {target or 'TARGET'}")

    payload = {"target": target or ev.get("target"), "generated_at": time.time(), "signals": {"endpoints": len(endpoints), "params": len(params), "tags": sorted(tags)}, "actions": sorted(actions, key=lambda x: x["priority"])}
    (OUT / "tool-brain-plan.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"# VulnScope Tool Brain — {payload['target']}", "", "## Signals", f"- Endpoints: `{len(endpoints)}`", f"- Parameters: `{len(params)}`", f"- Tags: `{', '.join(sorted(tags)) or 'none'}`", "", "## Recommended Actions"]
    for a in payload["actions"]:
        lines += [f"### P{a['priority']} — {a['action']}", f"- Reason: {a['reason']}", "```bash", a["command"], "```", ""]
    (OUT / "tool-brain-plan.md").write_text("\n".join(lines), encoding="utf-8")
    return payload

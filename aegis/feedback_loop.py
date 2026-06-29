from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from normalizers.evidence import normalize_all
from aegis.safe_events import record

OUT = Path("reports/output/aegis/feedback")


def build_feedback_plan(target: str) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    ev = normalize_all(target)
    summary = ev.get("summary", {})
    endpoints = int(summary.get("endpoints", 0))
    params = int(summary.get("parameters", 0))
    candidates = int(summary.get("candidates", 0))
    actions = []

    def add(priority: int, label: str, reason: str, command: str) -> None:
        actions.append({"priority": priority, "label": label, "reason": reason, "command": command})

    if endpoints < 25:
        add(10, "expand_passive_and_crawl", "Low endpoint count; broaden passive URL collection and safe crawling.", f"python3 auto_mode.py --url {target} --profile bug-bounty-safe --full --yes")
    if params < 10:
        add(20, "parameter_discovery", "Low parameter count; run comprehensive review and parameter correlation.", f"python3 comprehensive_suite_cli.py --target {target} --yes")
    if candidates < 5:
        add(30, "correlate_evidence", "Low candidate count; normalize, build graph, and generate evidence cards.", f"python3 vulnscope_modes_cli.py --target {target} --scope-policy scope_policy.session.yaml")
    add(40, "public_search_review", "Check public indexed references without fetching sensitive data directly.", f"python3 aegis_public_search_cli.py --target {target}")
    add(50, "auth_precision", "If two owned test accounts exist, compare account-specific routes for access-control candidates.", f"python3 google_pair_cli.py --target {target} --profile default --max-pages 25 --skip-login --yes")
    add(60, "jarvis_summary", "Show what was found and next steps inline.", f"python3 jarvis_summary_cli.py --target {target}")

    plan = {"target": target, "generated_at": time.time(), "signals": {"endpoints": endpoints, "parameters": params, "candidates": candidates}, "actions": sorted(actions, key=lambda x: x["priority"])}
    (OUT / "feedback-plan.json").write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"# AEGIS-SAFE Feedback Plan — {target}", "", f"Endpoints: `{endpoints}`", f"Parameters: `{params}`", f"Candidates: `{candidates}`", "", "## Next Actions"]
    for item in plan["actions"]:
        lines += [f"### P{item['priority']} — {item['label']}", f"- Reason: {item['reason']}", "```bash", item["command"], "```", ""]
    (OUT / "feedback-plan.md").write_text("\n".join(lines), encoding="utf-8")
    record("feedback_plan_created", {"target": target, "actions": len(actions), "signals": plan["signals"]})
    return plan

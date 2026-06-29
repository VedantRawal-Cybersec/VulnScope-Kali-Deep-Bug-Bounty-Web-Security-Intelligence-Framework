#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

from scope.policy import load_scope_policy
from aegis.safe_events import record
from aegis.safe_policy import load_policy

OUT = Path("reports/output/aegis/run")

PHASES = [
    ("Feedback planner", "python3 aegis_feedback_cli.py --target {target}"),
    ("Tool mind", "python3 tool_mind_cli.py --target {target} --mode crazy --install-needed --yes"),
    ("Path repair", "python3 tool_path_repair_cli.py"),
    ("Public search review", "python3 aegis_public_search_cli.py --target {target}"),
    ("Core safe loop", "python3 safe_loop_v2_cli.py --target {target} --mode comprehensive --scope-policy {scope_policy} --max-cycles {cycles} --yes"),
    ("Advanced correlation", "python3 vulnscope_modes_cli.py --target {target} --scope-policy {scope_policy}"),
    ("Evidence cards", "python3 evidence_cards_cli.py --target {target}"),
    ("Reportability", "python3 reportability_cli.py --target {target}"),
    ("Final report", "python3 report_v2_cli.py --target {target}"),
    ("JARVIS summary", "python3 jarvis_summary_cli.py --target {target}"),
]


def run_command(label: str, command: str, timeout: int = 2400) -> dict:
    record("phase_started", {"label": label, "command": command})
    started = time.time()
    proc = subprocess.run(["bash", "-lc", command], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    result = {"label": label, "command": command, "ok": proc.returncode == 0, "exit_code": proc.returncode, "seconds": round(time.time() - started, 2), "output_tail": proc.stdout[-3000:]}
    record("phase_finished", {"label": label, "ok": result["ok"], "seconds": result["seconds"]})
    print(f"\n[AEGIS-SAFE] {label} -> exit={proc.returncode} seconds={result['seconds']}")
    if result["output_tail"].strip():
        print(result["output_tail"][-1800:])
    return result


def run_safe_aegis(target: str, scope_policy: str, cycles: int) -> dict:
    policy = load_policy()
    decision = load_scope_policy(scope_policy).check(target)
    if not decision.allowed:
        return {"allowed": False, "reason": decision.reason, "scope_policy": scope_policy}
    OUT.mkdir(parents=True, exist_ok=True)
    record("safe_aegis_started", {"target": target, "scope_policy": scope_policy, "policy": policy.to_dict()})
    history = []
    for label, template in PHASES:
        command = template.format(target=target, scope_policy=scope_policy, cycles=cycles)
        result = run_command(label, command)
        history.append(result)
        if not result.get("ok") and label in {"Feedback planner", "Tool mind", "Core safe loop"}:
            break
    payload = {"target": target, "scope_policy": scope_policy, "policy": policy.to_dict(), "history": history, "outputs": {"events": "reports/output/aegis/events/safe-events.jsonl", "feedback": "reports/output/aegis/feedback/feedback-plan.md", "public_search": "reports/output/aegis/google-intel/google-intel.md", "report": "reports/output/report-v2/executive-report-v2.md"}}
    (OUT / "safe-aegis-run.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    record("safe_aegis_finished", {"target": target, "phases": len(history)})
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS-SAFE non-destructive orchestrator")
    parser.add_argument("--target", required=True)
    parser.add_argument("--scope-policy", default="scope_policy.session.yaml")
    parser.add_argument("--cycles", type=int, default=8)
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args()
    if not args.yes:
        answer = input("Run AEGIS-SAFE on this authorized target? type YES: ").strip()
        if answer != "YES":
            print(json.dumps({"started": False, "reason": "confirmation not provided"}, indent=2))
            return 1
    result = run_safe_aegis(args.target, args.scope_policy, args.cycles)
    print(json.dumps({"allowed": result.get("allowed", True), "output": "reports/output/aegis/run/safe-aegis-run.json", "report": "reports/output/report-v2/executive-report-v2.md"}, indent=2))
    return 0 if result.get("allowed", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

from scope.policy import load_scope_policy

OUT = Path("reports/output/modes")

PHASES = [
    ("Mega tools coverage", "python3 mega_tools_cli.py --status"),
    ("Normalize evidence", "python3 normalize_cli.py --target {target}"),
    ("Asset graph", "python3 asset_graph_cli.py --target {target}"),
    ("Tool brain", "python3 tool_brain_cli.py --target {target}"),
    ("API intelligence", "python3 api_intel_cli.py --target {target}"),
    ("Auth differential v2", "python3 auth_diff_v2_cli.py"),
    ("Evidence cards", "python3 evidence_cards_cli.py --target {target}"),
    ("Reportability", "python3 reportability_cli.py --target {target}"),
    ("Target history", "python3 target_history_cli.py --target {target}"),
    ("Final report", "python3 report_v2_cli.py --target {target}"),
]


def run(command: str) -> dict:
    started = time.time()
    p = subprocess.run(["bash", "-lc", command], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=1200)
    return {"command": command, "ok": p.returncode == 0, "exit_code": p.returncode, "seconds": round(time.time() - started, 2), "output_tail": p.stdout[-2500:]}


def run_modes(target: str, scope_policy: str) -> dict:
    decision = load_scope_policy(scope_policy).check(target)
    if not decision.allowed:
        return {"allowed": False, "reason": decision.reason, "scope_policy": scope_policy}
    OUT.mkdir(parents=True, exist_ok=True)
    history = []
    for label, template in PHASES:
        cmd = template.format(target=target)
        print(f"\n[VulnScope Modes] {label}")
        result = run(cmd)
        print(result.get("output_tail", "")[-1200:])
        history.append({"label": label, "result": result})
        if not result.get("ok"):
            break
    payload = {"target": target, "scope_policy": scope_policy, "phases": history}
    (OUT / "modes-run.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Run advanced VulnScope modes after core scan")
    parser.add_argument("--target", required=True)
    parser.add_argument("--scope-policy", default="scope_policy.yaml")
    args = parser.parse_args()
    result = run_modes(args.target, args.scope_policy)
    print(json.dumps({"output": "reports/output/modes/modes-run.json", "phases": len(result.get("phases", [])), "allowed": result.get("allowed", True)}, indent=2))
    return 0 if result.get("allowed", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())

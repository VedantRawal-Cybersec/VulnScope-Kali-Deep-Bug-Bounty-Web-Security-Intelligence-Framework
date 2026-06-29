#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

from autonomy.decision_engine import build_decision_plan
from scope.policy import load_scope_policy

OUT = Path('reports/output/autonomy')
ALLOW = ('python3 coverage_matrix.py', 'python3 daily_update_cli.py', 'python3 autopilot_cli.py', 'python3 comprehensive_suite_cli.py', 'python3 google_context_cli.py', 'python3 report_v2_cli.py', 'python3 auto_mode.py', 'cat reports/output/')

def allowed(cmd: str) -> bool:
    cmd = cmd.strip()
    return cmd.startswith(ALLOW) and ';' not in cmd and '| sh' not in cmd

def run(cmd: str) -> dict:
    if not allowed(cmd):
        return {'ok': False, 'command': cmd, 'reason': 'not allowlisted'}
    started = time.time()
    p = subprocess.run(['bash', '-lc', cmd], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=1800)
    return {'ok': p.returncode == 0, 'command': cmd, 'exit_code': p.returncode, 'seconds': round(time.time() - started, 2), 'output_tail': p.stdout[-2000:]}

def main() -> int:
    ap = argparse.ArgumentParser(description='VulnScope safe next-step loop')
    ap.add_argument('--target', required=True)
    ap.add_argument('--mode', default='comprehensive')
    ap.add_argument('--provider', default=None)
    ap.add_argument('--scope-policy', default='scope_policy.yaml')
    ap.add_argument('--max-cycles', type=int, default=8)
    ap.add_argument('--yes', action='store_true')
    args = ap.parse_args()
    d = load_scope_policy(args.scope_policy).check(args.target)
    if not d.allowed:
        print(json.dumps({'allowed': False, 'reason': d.reason}, indent=2))
        return 1
    if not args.yes:
        ans = input('Run safe next-step loop on this authorized target? yes/no: ').strip().lower()
        if ans not in {'y', 'yes'}:
            return 1
    OUT.mkdir(parents=True, exist_ok=True)
    history = []
    seen = set()
    for cycle in range(1, args.max_cycles + 1):
        plan = build_decision_plan(args.target, provider=args.provider, mode=args.mode)
        action = plan.get('next_action')
        if not action:
            history.append({'cycle': cycle, 'status': 'complete'})
            break
        name = action.get('action')
        cmd = action.get('command', '')
        if name in seen and name not in {'generate_final_report', 'run_quality_report'}:
            history.append({'cycle': cycle, 'status': 'stopped_repeated_action', 'action': action})
            break
        seen.add(name)
        result = run(cmd)
        history.append({'cycle': cycle, 'action': action, 'result': result})
        if not result.get('ok'):
            break
    payload = {'target': args.target, 'mode': args.mode, 'cycles': len(history), 'history': history, 'decision_plan': 'reports/output/autonomy/decision-plan.md'}
    (OUT / 'safe-loop-run.json').write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps({'cycles': len(history), 'output': 'reports/output/autonomy/safe-loop-run.json', 'decision_plan': 'reports/output/autonomy/decision-plan.md'}, indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

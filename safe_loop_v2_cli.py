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


def allowed(command: str) -> bool:
    bad = [';', '| sh', 'bash -i', 'rm -rf', 'curl ', 'wget ']
    return command.strip().startswith(ALLOW) and not any(x in command for x in bad)


def run_command(command: str, cycle: int) -> dict:
    if not allowed(command):
        return {'ok': False, 'reason': 'not allowlisted', 'command': command}
    print(f'\n[VulnScope] cycle={cycle} command={command}')
    started = time.time()
    p = subprocess.run(['bash', '-lc', command], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=1800)
    print(p.stdout[-2000:])
    return {'ok': p.returncode == 0, 'exit_code': p.returncode, 'seconds': round(time.time() - started, 2), 'command': command, 'output_tail': p.stdout[-2000:]}


def main() -> int:
    parser = argparse.ArgumentParser(description='VulnScope fixed scoped decision loop')
    parser.add_argument('--target', required=True)
    parser.add_argument('--mode', default='comprehensive')
    parser.add_argument('--provider', default=None)
    parser.add_argument('--scope-policy', default='scope_policy.yaml')
    parser.add_argument('--max-cycles', type=int, default=8)
    parser.add_argument('--yes', action='store_true')
    args = parser.parse_args()

    decision = load_scope_policy(args.scope_policy).check(args.target)
    if not decision.allowed:
        print(json.dumps({'allowed': False, 'reason': decision.reason, 'scope_policy': args.scope_policy}, indent=2))
        return 1
    if not args.yes:
        answer = input('Run VulnScope loop for this scoped target? yes/no: ').strip().lower()
        if answer not in {'yes', 'y'}:
            return 1

    OUT.mkdir(parents=True, exist_ok=True)
    history = []
    seen = set()
    for cycle in range(1, args.max_cycles + 1):
        print(f'\n[VulnScope] thinking {cycle}/{args.max_cycles}')
        plan = build_decision_plan(args.target, provider=args.provider, mode=args.mode, scope_policy=args.scope_policy)
        action = plan.get('next_action')
        if not action:
            history.append({'cycle': cycle, 'status': 'complete'})
            break
        name = action.get('action')
        command = action.get('command', '')
        print(f"[VulnScope] next={name} reason={action.get('reason')}")
        if name in seen and name not in {'generate_final_report', 'run_quality_report'}:
            history.append({'cycle': cycle, 'status': 'stopped_repeated_action', 'action': action})
            break
        seen.add(name)
        result = run_command(command, cycle)
        history.append({'cycle': cycle, 'action': action, 'result': result})
        if not result.get('ok'):
            break
    payload = {'target': args.target, 'mode': args.mode, 'scope_policy': args.scope_policy, 'cycles': len(history), 'history': history, 'decision_plan': 'reports/output/autonomy/decision-plan.md'}
    (OUT / 'safe-loop-v2-run.json').write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps({'cycles': len(history), 'output': 'reports/output/autonomy/safe-loop-v2-run.json', 'decision_plan': 'reports/output/autonomy/decision-plan.md'}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

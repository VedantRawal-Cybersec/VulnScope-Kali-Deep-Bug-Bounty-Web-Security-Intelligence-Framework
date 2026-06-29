#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from autonomy.decision_engine import build_decision_plan
from scope.policy import load_scope_policy

OUT = Path('reports/output/autonomy')
AUTH_DIR = Path('reports/output/authorization')
SESSION_SCOPE = Path('scope_policy.session.yaml')
ALLOW = ('python3 coverage_matrix.py', 'python3 daily_update_cli.py', 'python3 autopilot_cli.py', 'python3 comprehensive_suite_cli.py', 'python3 google_context_cli.py', 'python3 report_v2_cli.py', 'python3 auto_mode.py', 'cat reports/output/')


def target_host(target: str) -> str:
    parsed = urlparse(target if '://' in target else 'https://' + target)
    return parsed.netloc.split(':')[0].lower().strip()


def write_session_scope(target: str, include_subdomains: bool = False) -> Path:
    host = target_host(target)
    hosts = [host]
    if include_subdomains and not host.replace('.', '').isdigit() and host != 'localhost':
        hosts.append('*.' + host)
    lines = [
        'name: session-confirmed-target',
        'allowed_hosts:',
        *[f"  - '{h}'" for h in hosts],
        'blocked_hosts: []',
        'allowed_schemes:',
        '  - https',
        '  - http',
        'max_requests_per_minute: 30',
        'active_testing_allowed: false',
        'authenticated_testing_allowed: true',
        "notes: 'Generated after user confirmation. Evidence-only safe review.'",
        '',
    ]
    SESSION_SCOPE.write_text('\n'.join(lines), encoding='utf-8')
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    audit = {
        'target': target,
        'host': host,
        'include_subdomains': include_subdomains,
        'confirmed': True,
        'confirmed_at': datetime.now(timezone.utc).isoformat(),
        'scope_policy': str(SESSION_SCOPE),
        'mode': 'evidence_only_safe_review',
    }
    (AUTH_DIR / 'session-confirmation.json').write_text(json.dumps(audit, indent=2), encoding='utf-8')
    return SESSION_SCOPE


def allowed(cmd: str) -> bool:
    cmd = cmd.strip()
    blocked = [';', '| sh', ' rm ', 'curl ', 'wget ', 'nc ', 'bash -i']
    return cmd.startswith(ALLOW) and not any(x in cmd for x in blocked)


def run(cmd: str, cycle: int) -> dict:
    if not allowed(cmd):
        return {'ok': False, 'command': cmd, 'reason': 'not allowlisted'}
    print(f'\n[VulnScope] Cycle {cycle}: running')
    print(f'[VulnScope] Command: {cmd}')
    started = time.time()
    p = subprocess.run(['bash', '-lc', cmd], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=1800)
    tail = p.stdout[-2000:]
    print(f'[VulnScope] Done: exit={p.returncode}, seconds={round(time.time() - started, 2)}')
    if tail.strip():
        print('[VulnScope] Output tail:')
        print(tail)
    return {'ok': p.returncode == 0, 'command': cmd, 'exit_code': p.returncode, 'seconds': round(time.time() - started, 2), 'output_tail': tail}


def main() -> int:
    ap = argparse.ArgumentParser(description='VulnScope safe next-step loop')
    ap.add_argument('--target', required=True)
    ap.add_argument('--mode', default='comprehensive')
    ap.add_argument('--provider', default=None)
    ap.add_argument('--scope-policy', default='scope_policy.yaml')
    ap.add_argument('--max-cycles', type=int, default=8)
    ap.add_argument('--include-subdomains', action='store_true')
    ap.add_argument('--confirm-authorized', action='store_true', help='Confirm you own or have permission for this target and create a temporary session scope')
    ap.add_argument('--yes', action='store_true')
    args = ap.parse_args()

    scope_path = Path(args.scope_policy)
    d = load_scope_policy(scope_path).check(args.target) if scope_path.exists() else None
    if not d or not d.allowed:
        if not args.confirm_authorized:
            print('Target is not currently in scope_policy.yaml.')
            ans = input(f'Do you own or have explicit permission to test {args.target}? yes/no: ').strip().lower()
            if ans not in {'y', 'yes'}:
                print(json.dumps({'allowed': False, 'reason': 'authorization not confirmed'}, indent=2))
                return 1
            sub = input('Include subdomains for this session? yes/no: ').strip().lower()
            args.include_subdomains = sub in {'y', 'yes'}
        scope_path = write_session_scope(args.target, args.include_subdomains)
        print(json.dumps({'session_scope_created': str(scope_path), 'audit': 'reports/output/authorization/session-confirmation.json'}, indent=2))

    if not args.yes:
        ans = input('Run safe next-step loop on this target? yes/no: ').strip().lower()
        if ans not in {'y', 'yes'}:
            return 1
    OUT.mkdir(parents=True, exist_ok=True)
    history = []
    seen = set()
    for cycle in range(1, args.max_cycles + 1):
        print(f'\n[VulnScope] Thinking cycle {cycle}/{args.max_cycles}')
        plan = build_decision_plan(args.target, provider=args.provider, mode=args.mode)
        action = plan.get('next_action')
        if not action:
            history.append({'cycle': cycle, 'status': 'complete'})
            break
        print(f"[VulnScope] Next: {action.get('action')} — {action.get('reason')}")
        name = action.get('action')
        cmd = action.get('command', '')
        if name in seen and name not in {'generate_final_report', 'run_quality_report'}:
            history.append({'cycle': cycle, 'status': 'stopped_repeated_action', 'action': action})
            break
        seen.add(name)
        result = run(cmd, cycle)
        history.append({'cycle': cycle, 'action': action, 'result': result})
        if not result.get('ok'):
            break
    payload = {'target': args.target, 'mode': args.mode, 'cycles': len(history), 'history': history, 'decision_plan': 'reports/output/autonomy/decision-plan.md'}
    (OUT / 'safe-loop-run.json').write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps({'cycles': len(history), 'output': 'reports/output/autonomy/safe-loop-run.json', 'decision_plan': 'reports/output/autonomy/decision-plan.md'}, indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

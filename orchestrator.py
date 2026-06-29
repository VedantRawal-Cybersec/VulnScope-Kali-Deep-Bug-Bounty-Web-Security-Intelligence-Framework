import argparse, json, subprocess, time
from pathlib import Path

OUT = Path('reports/output/neural-agent')
PHASES = [
    ('version', ['python3', 'vulnscope.py', '--version']),
    ('plan', ['python3', 'unified_mission_cli.py', '--target', '{target}', '--scope-policy', '{scope}', '--plan-only']),
    ('agent', ['python3', 'vulnscope_agent.py', '--config', '{config}']),
    ('report', ['python3', 'reporter.py', '--target', '{target}']),
]

def run_cmd(name, cmd):
    started = time.time()
    try:
        p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=7200)
        return {'name': name, 'ok': p.returncode == 0, 'exit_code': p.returncode, 'seconds': round(time.time()-started, 2), 'tail': p.stdout[-2500:]}
    except Exception as exc:
        return {'name': name, 'ok': False, 'error': str(exc), 'seconds': round(time.time()-started, 2)}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', required=True)
    ap.add_argument('--config', default='agent_config.yaml')
    ap.add_argument('--scope', default='scope_policy.session.yaml')
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    results = []
    for name, template in PHASES:
        cmd = [x.format(target=args.target, config=args.config, scope=args.scope) for x in template]
        print('[PHASE] ' + name + ' -> ' + ' '.join(cmd))
        results.append(run_cmd(name, cmd))
    payload = {'target': args.target, 'results': results, 'report': 'reports/output/neural-agent/agent-report.md'}
    (OUT / 'orchestrator-run.json').write_text(json.dumps(payload, indent=2), encoding='utf-8')
    print(json.dumps(payload, indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

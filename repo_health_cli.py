#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import py_compile
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
OUT = Path('reports/output/repo-health')
NEEDED = ['requests', 'bs4', 'rich', 'yaml', 'jinja2', 'tldextract', 'flask']
CHECKS = [
    ['python3', 'vulnscope.py', '--version'],
    ['python3', 'vulnscope_agent.py', '--config', 'agent_config.yaml', '--dry-run'],
    ['python3', 'auto_mode.py', '--version'],
    ['python3', 'coverage_matrix.py'],
    ['python3', 'mega_tools_cli.py', '--status'],
    ['python3', 'tool_mind_cli.py', '--mode', 'deep'],
    ['python3', 'tool_path_repair_cli.py'],
    ['python3', 'mission_preflight_cli.py', '--target', 'https://example.com', '--scope-policy', 'scope_policy.example.yaml', '--no-clean'],
    ['python3', 'unified_mission_cli.py', '--target', 'https://example.com', '--scope-policy', 'scope_policy.example.yaml', '--plan-only'],
    ['python3', 'mission_verdicts_cli.py', '--target', 'https://example.com'],
    ['python3', 'normalize_cli.py', '--target', 'https://example.com'],
    ['python3', 'asset_graph_cli.py', '--target', 'https://example.com'],
    ['python3', 'tool_brain_cli.py', '--target', 'https://example.com'],
    ['python3', 'api_intel_cli.py', '--target', 'https://example.com'],
    ['python3', 'aegis_public_search_cli.py', '--target', 'https://example.com'],
    ['python3', 'aegis_feedback_cli.py', '--target', 'https://example.com'],
    ['python3', 'artemis_autonomous_cli.py', '--init-config', '--config', 'reports/output/repo-health/artemis_config.test.yaml'],
    ['python3', 'artemis_proxy_passive_cli.py', '--target', 'https://example.com'],
    ['python3', 'google_pair_cli.py', '--target', 'https://example.com', '--profile', 'default', '--skip-login', '--skip-if-missing', '--yes'],
    ['python3', 'auth_diff_v2_cli.py'],
    ['python3', 'evidence_cards_cli.py', '--target', 'https://example.com'],
    ['python3', 'reportability_cli.py', '--target', 'https://example.com'],
    ['python3', 'target_history_cli.py', '--target', 'https://example.com'],
    ['python3', 'jarvis_summary_cli.py', '--target', 'https://example.com'],
    ['python3', 'report_v2_cli.py', '--target', 'https://example.com'],
]


def run(cmd: list[str], timeout: int = 300) -> dict[str, Any]:
    try:
        p = subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        return {'command': cmd, 'ok': p.returncode == 0, 'exit_code': p.returncode, 'output_tail': p.stdout[-2000:]}
    except Exception as exc:
        return {'command': cmd, 'ok': False, 'error': str(exc)}


def py_files() -> list[Path]:
    bad = {'.git', '.venv', 'venv', '__pycache__', 'reports'}
    return sorted(p for p in ROOT.rglob('*.py') if not any(part in bad for part in p.parts))


def compile_all() -> list[dict[str, Any]]:
    out = []
    for p in py_files():
        try:
            py_compile.compile(str(p), doraise=True)
            out.append({'file': str(p.relative_to(ROOT)), 'ok': True})
        except Exception as exc:
            out.append({'file': str(p.relative_to(ROOT)), 'ok': False, 'error': str(exc)})
    return out


def imports() -> list[dict[str, Any]]:
    return [{'module': m, 'ok': importlib.util.find_spec(m) is not None} for m in NEEDED]


def main() -> int:
    ap = argparse.ArgumentParser(description='VulnScope repository health check')
    ap.add_argument('--install-python-deps', action='store_true')
    ap.add_argument('--tool-update', action='store_true')
    args = ap.parse_args()
    started = time.time()
    actions = []
    if args.install_python_deps:
        actions.append(run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], 900))
    if args.tool_update:
        actions.append(run(['python3', 'daily_update_cli.py', '--profile', 'bug-bounty-safe', '--force', '--yes'], 1800))
    comp = compile_all()
    cli = [run(c) for c in CHECKS]
    imp = imports()
    data = {
        'started_at': started,
        'ended_at': time.time(),
        'actions': actions,
        'imports': imp,
        'compile': comp,
        'cli_checks': cli,
        'summary': {
            'compile_errors': len([x for x in comp if not x.get('ok')]),
            'missing_imports': [x['module'] for x in imp if not x.get('ok')],
            'cli_failures': len([x for x in cli if not x.get('ok')]),
        },
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'health.json').write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
    lines = ['# VulnScope Repo Health', '', f"Compile errors: `{data['summary']['compile_errors']}`", f"Missing imports: `{data['summary']['missing_imports']}`", f"CLI failures: `{data['summary']['cli_failures']}`", '']
    if data['summary']['cli_failures']:
        lines.append('## CLI Failures')
        for item in cli:
            if not item.get('ok'):
                lines.append(f"- `{' '.join(item.get('command', []))}`: {item.get('error') or item.get('output_tail')}")
    for item in comp:
        if not item.get('ok'):
            lines.append(f"- `{item['file']}`: {item.get('error')}")
    (OUT / 'health.md').write_text('\n'.join(lines), encoding='utf-8')
    print(json.dumps({'summary': data['summary'], 'report': 'reports/output/repo-health/health.md'}, indent=2, ensure_ascii=False))
    return 1 if data['summary']['compile_errors'] else 0


if __name__ == '__main__':
    raise SystemExit(main())

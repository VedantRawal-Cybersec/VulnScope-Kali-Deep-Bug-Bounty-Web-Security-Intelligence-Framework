from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

OUT = Path('reports/output/neural-agent')

def run_once(config):
    started = time.time()
    p = subprocess.run(['python3', 'vulnscope_agent.py', '--config', config], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=7200)
    OUT.mkdir(parents=True, exist_ok=True)
    row = {'ts': started, 'ok': p.returncode == 0, 'exit_code': p.returncode, 'seconds': round(time.time() - started, 2), 'tail': p.stdout[-2000:]}
    with (OUT / 'monitor-runs.jsonl').open('a', encoding='utf-8') as h:
        h.write(json.dumps(row, ensure_ascii=False) + '\n')
    return row

def main():
    ap = argparse.ArgumentParser(description='VulnScope agent monitor')
    ap.add_argument('--config', default='agent_config.yaml')
    ap.add_argument('--interval-minutes', type=int, default=1440)
    ap.add_argument('--once', action='store_true')
    args = ap.parse_args()
    if args.once:
        print(json.dumps(run_once(args.config), indent=2))
        return 0
    while True:
        print(json.dumps(run_once(args.config), indent=2))
        time.sleep(max(60, args.interval_minutes * 60))

if __name__ == '__main__':
    raise SystemExit(main())

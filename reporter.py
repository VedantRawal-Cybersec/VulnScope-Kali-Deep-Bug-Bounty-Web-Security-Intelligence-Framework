from __future__ import annotations

import html
import json
import time
from pathlib import Path

class AgentReporter:
    def __init__(self, out_dir='reports/output/neural-agent'):
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def _load(self, path):
        p = Path(path)
        if not p.exists():
            return {}
        try:
            data = json.loads(p.read_text(encoding='utf-8', errors='ignore'))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def build(self, target):
        verdicts = self._load('reports/output/mission-verdicts/mission-verdicts.json')
        state = self._load('reports/output/neural-agent/agent-state.json')
        rows = verdicts.get('rows', []) if isinstance(verdicts.get('rows', []), list) else []
        summary = verdicts.get('summary', {}) if isinstance(verdicts.get('summary', {}), dict) else {}
        payload = {'target': target, 'generated_at': time.time(), 'summary': summary, 'rows': rows, 'state': state}
        (self.out_dir / 'agent-report.json').write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
        md = [f'# VulnScope Agent Report - {target}', '', '**FOR AUTHORIZED SECURITY TESTING ONLY.**', '', '## Summary', '```json', json.dumps(summary, indent=2), '```', '', '## Verdict Rows', '', '| Module | Item | Verdict | Evidence |', '|---|---|---|---|']
        for r in rows[:1000]:
            md.append('| ' + str(r.get('module', '')).replace('|', '/') + ' | `' + str(r.get('item', '')).replace('|', '/')[:160] + '` | **' + str(r.get('verdict', '')).replace('|', '/') + '** | ' + str(r.get('evidence', '')).replace('|', '/')[:350] + ' |')
        md_text = '\n'.join(md)
        (self.out_dir / 'agent-report.md').write_text(md_text, encoding='utf-8')
        body = '<h1>VulnScope Agent Report</h1><p><b>Target:</b> ' + html.escape(target) + '</p><pre>' + html.escape(json.dumps(summary, indent=2)) + '</pre><table border="1"><tr><th>Module</th><th>Item</th><th>Verdict</th><th>Evidence</th></tr>'
        for r in rows[:1000]:
            body += '<tr><td>' + html.escape(str(r.get('module', ''))) + '</td><td>' + html.escape(str(r.get('item', ''))) + '</td><td>' + html.escape(str(r.get('verdict', ''))) + '</td><td>' + html.escape(str(r.get('evidence', ''))[:600]) + '</td></tr>'
        body += '</table>'
        (self.out_dir / 'agent-report.html').write_text('<!doctype html><html><body>' + body + '</body></html>', encoding='utf-8')
        return payload

if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', default='authorized-target')
    args = ap.parse_args()
    result = AgentReporter().build(args.target)
    print(json.dumps({'rows': len(result.get('rows', [])), 'report': 'reports/output/neural-agent/agent-report.md'}, indent=2))

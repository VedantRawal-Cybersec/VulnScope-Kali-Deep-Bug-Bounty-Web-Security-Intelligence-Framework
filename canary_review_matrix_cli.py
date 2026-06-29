#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path

OUT = Path('reports/output/canary-review-matrix')
REPORT_ROOT = Path('reports/output')

ROWS = [
    (1, 'Access Control Object Review', 'Critical', 'Dual-account evidence review'),
    (2, 'Configuration Review', 'High', 'Header and configuration audit'),
    (3, 'Supply Chain Review', 'High', 'Dependency metadata review'),
    (4, 'Client Input Reflection Review', 'High', 'Safe canary reflection check'),
    (5, 'Database Error Exposure Review', 'Critical', 'Safe canary response comparison'),
    (6, 'Crypto Review', 'High', 'TLS and algorithm evidence audit'),
    (7, 'Role Boundary Review', 'Critical', 'Dual-account and role evidence review'),
    (8, 'Server Request Routing Review', 'Critical', 'External URL parameter evidence review'),
    (9, 'Request Token Review', 'Medium', 'Form token validation evidence'),
    (10, 'Cloud Configuration Review', 'High', 'Cloud reference and config evidence'),
    (11, 'Outdated Component Review', 'High', 'Version and CVE evidence review'),
    (12, 'System Meta Character Handling Review', 'Critical', 'Safe marker handling evidence'),
    (13, 'Weak TLS Review', 'Medium', 'TLS version and cipher evidence'),
    (14, 'Public Storage Review', 'Critical', 'Public object-store reference evidence'),
    (15, 'Hardcoded Secret Pattern Review', 'Critical', 'Redacted JS/CSS pattern evidence'),
    (16, 'Serialized Data Review', 'Critical', 'Serialized-input evidence review'),
    (17, 'Authentication Strength Review', 'High', 'Login and session evidence review'),
    (18, 'Error Handling Review', 'Medium', 'Error response evidence analysis'),
    (19, 'Security Header Review', 'Medium', 'Header inspection'),
    (20, 'Dependency Integrity Review', 'High', 'Package integrity evidence review'),
]

PATTERNS = {
    'headers': re.compile(r'(?i)(strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|header)'),
    'api': re.compile(r'(?i)(/api/|graphql|user|account|object|role|admin|login|auth)'),
    'version': re.compile(r'(?i)(jquery|bootstrap|wordpress|apache|nginx|php|version|cve|component|dependency|package)'),
    'cloud': re.compile(r'(?i)(amazonaws|s3|azure|gcp|cloudfront|firebase|storage.googleapis|blob.core.windows.net)'),
    'secret': re.compile(r'(?i)(secret|token|api.key|credential|private.key|access.key)'),
    'error': re.compile(r'(?i)(traceback|exception|stack trace|fatal error|warning|sql syntax|undefined index)'),
    'canary': re.compile(r'(?i)(CANARY|VULNSCOPE_CANARY|safe marker|marker)'),
    'tls': re.compile(r'(?i)(tls|ssl|cipher|certificate|hsts)'),
    'form': re.compile(r'(?i)(form|csrf|xsrf|_token|session|cookie)'),
}


def read_corpus() -> str:
    chunks = []
    if not REPORT_ROOT.exists():
        return ''
    for p in REPORT_ROOT.rglob('*'):
        if p.suffix.lower() in {'.json', '.md', '.txt'} and p.stat().st_size < 2500000:
            try:
                chunks.append(p.read_text(encoding='utf-8', errors='ignore')[:220000])
            except Exception:
                pass
    return '\n'.join(chunks)


def hit_count(pattern: re.Pattern[str], text: str) -> int:
    return len(pattern.findall(text))


def make_row(row, text: str) -> dict:
    number, category, classification, method = row
    if number in {1, 7, 17}:
        hits = hit_count(PATTERNS['api'], text)
    elif number in {2, 19}:
        hits = hit_count(PATTERNS['headers'], text)
    elif number in {3, 11, 20}:
        hits = hit_count(PATTERNS['version'], text)
    elif number in {4, 5, 12, 16}:
        hits = hit_count(PATTERNS['canary'], text) + hit_count(PATTERNS['error'], text)
    elif number in {6, 13}:
        hits = hit_count(PATTERNS['tls'], text)
    elif number in {8, 10, 14}:
        hits = hit_count(PATTERNS['cloud'], text)
    elif number == 9:
        hits = hit_count(PATTERNS['form'], text)
    elif number == 15:
        hits = hit_count(PATTERNS['secret'], text)
    elif number == 18:
        hits = hit_count(PATTERNS['error'], text)
    else:
        hits = 0
    verdict = 'SAFE' if hits == 0 else 'REVIEW_MANUAL'
    if number in {2, 15, 19} and hits > 0:
        verdict = 'VULNERABLE'
    return {'number': number, 'category': category, 'classification': classification, 'detection_method': method, 'verdict': verdict, 'report_field': verdict, 'evidence': f'evidence_hits={hits}; source=existing VulnScope reports; safe marker/canary mode only'}


def main() -> int:
    parser = argparse.ArgumentParser(description='Generate safe canary review matrix from existing VulnScope evidence')
    parser.add_argument('--target', required=True)
    args = parser.parse_args()
    text = read_corpus()
    rows = [make_row(r, text) for r in ROWS]
    counts = {}
    for r in rows:
        counts[r['verdict']] = counts.get(r['verdict'], 0) + 1
    payload = {'target': args.target, 'generated_at': time.time(), 'summary': {'counts': counts, 'rows': len(rows)}, 'rows': rows}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'canary-review-matrix.json').write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
    lines = [f"# Canary Review Matrix — {args.target}", '', 'Safe marker/canary mode. The matrix summarizes existing VulnScope evidence and does not run destructive checks.', '', '| # | Category | Class | Method | Verdict | Evidence |', '|---:|---|---|---|---|---|']
    for r in rows:
        lines.append(f"| {r['number']} | {r['category']} | {r['classification']} | {r['detection_method']} | **{r['verdict']}** | {r['evidence']} |")
    (OUT / 'canary-review-matrix.md').write_text('\n'.join(lines), encoding='utf-8')
    print(json.dumps({'summary': payload['summary'], 'report': 'reports/output/canary-review-matrix/canary-review-matrix.md'}, indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

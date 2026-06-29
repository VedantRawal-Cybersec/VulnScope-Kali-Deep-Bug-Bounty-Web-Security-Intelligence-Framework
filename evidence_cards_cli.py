#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from urllib.parse import urlparse

OUT = Path('reports/output/evidence-cards')
SOURCES = [
    'reports/output/safe-discovery/safe-discovery.json',
    'reports/output/comprehensive-suite/comprehensive-suite.json',
    'reports/output/category-suite/category-suite.json',
    'reports/output/auth/google-context/google-context-review.json',
    'reports/output/finding-quality.json',
]

GUIDE = {
    'xss': ('Input/rendering review item', 'Trace whether the input reaches browser rendering and verify context-aware output encoding.'),
    'idor': ('Object access review item', 'Use two owned accounts and confirm object access is checked server-side.'),
    'idor_bola': ('Object access review item', 'Use two owned accounts and confirm object access is checked server-side.'),
    'sqli': ('Backend query review item', 'Confirm parameters are bound safely and do not change query structure.'),
    'ssrf': ('Server-side fetch review item', 'Confirm URL inputs are allowlisted and outbound access is restricted.'),
    'open_redirect': ('Redirect review item', 'Confirm redirect destinations are exact-match allowlisted.'),
    'cors': ('Cross-origin policy review item', 'Confirm origins and credential handling are intentionally restricted.'),
    'graphql': ('GraphQL review item', 'Review schema exposure, resolver authorization, and query complexity limits.'),
    'jwt_auth': ('Session/auth review item', 'Review token lifetime, cookie flags, role checks, and OAuth callback constraints.'),
    'lfi_rfi_path': ('File/path review item', 'Confirm file paths are normalized, allowlisted, and authorized.'),
    'csrf': ('Browser state-change review item', 'Confirm state-changing flows have CSRF protections and origin checks.'),
    'file_upload': ('Upload handling review item', 'Review extension, content type, storage isolation, and direct access policy.'),
    'secrets_exposure': ('Sensitive exposure review item', 'Confirm public assets do not reveal secrets, config, source maps, or debug data.'),
    'rate_limit_logic': ('Abuse-control review item', 'Review throttling, idempotency, and business rules for sensitive flows.'),
}


def load_json(path: str):
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding='utf-8', errors='ignore'))
    except Exception:
        return None


def collect_items(data, source: str) -> list[dict]:
    if not isinstance(data, dict):
        return []
    out = []
    for key in ['candidates', 'findings', 'accepted', 'needs_review']:
        value = data.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    copy = dict(item)
                    copy['_source_file'] = source
                    out.append(copy)
    return out


def category_of(item: dict) -> str:
    raw = str(item.get('category') or item.get('detector') or item.get('type') or 'general').lower()
    for key in GUIDE:
        if key in raw:
            return key
    return raw


def build_cards(target: str | None = None) -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    items = []
    for source in SOURCES:
        items += collect_items(load_json(source), source)
    cards = []
    seen = set()
    for item in items:
        cat = category_of(item)
        url = str(item.get('url') or item.get('endpoint') or item.get('target') or target or 'n/a')
        title = str(item.get('title') or item.get('name') or cat + ' review item')
        key = (cat, title, url)
        if key in seen:
            continue
        seen.add(key)
        why, check = GUIDE.get(cat, ('Security review item', 'Review the evidence manually against expected application behavior.'))
        cards.append({
            'title': title,
            'category': cat,
            'where_found': url,
            'host': urlparse(url).netloc if url.startswith(('http://', 'https://')) else 'n/a',
            'why_flagged': why,
            'safe_check': check,
            'evidence_source': item.get('_source_file'),
            'score': item.get('confidence') or item.get('quality_score') or 0.5,
            'status': 'review_needed',
        })
    payload = {'target': target or 'authorized-target', 'generated_at': time.time(), 'summary': {'cards': len(cards), 'categories': len(set(c['category'] for c in cards))}, 'cards': cards}
    (OUT / 'evidence-cards.json').write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
    lines = [f"# VulnScope Evidence Cards — {payload['target']}", '', f"Cards: `{payload['summary']['cards']}`", f"Categories: `{payload['summary']['categories']}`", '']
    for card in cards[:150]:
        lines += [f"## {card['title']}", f"- Category: `{card['category']}`", f"- Where found: `{card['where_found']}`", f"- Why flagged: {card['why_flagged']}", f"- Safe check: {card['safe_check']}", f"- Evidence source: `{card['evidence_source']}`", f"- Status: `{card['status']}`", '']
    if not cards:
        lines.append('No evidence cards yet. Run the full review first.')
    (OUT / 'evidence-cards.md').write_text('\n'.join(lines), encoding='utf-8')
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description='Generate VulnScope evidence cards')
    parser.add_argument('--target')
    args = parser.parse_args()
    result = build_cards(args.target)
    print(json.dumps({'summary': result['summary'], 'report': 'reports/output/evidence-cards/evidence-cards.md'}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

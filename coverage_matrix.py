from __future__ import annotations

import json
from pathlib import Path

OUT = Path('reports/output/tool-matrix')

CATEGORY_MODULE_COUNTS = {
    'xss': 7,
    'idor_bola': 7,
    'sqli': 7,
    'parameter_discovery': 7,
    'hidden_parameter_discovery': 7,
    'endpoint_discovery': 8,
    'api_discovery': 7,
    'ssrf': 7,
    'open_redirect': 7,
    'cors': 7,
    'graphql': 7,
    'jwt_auth': 7,
    'lfi_rfi_path': 7,
    'ssti_template': 7,
    'csrf': 7,
    'file_upload': 7,
    'sensitive_exposure': 7,
    'rate_limit_logic': 7,
    'technology_detection': 7,
    'javascript_analysis': 7,
}

def build_coverage_matrix() -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    data = {
        'mode': 'safe_module_coverage_summary',
        'category_count': len(CATEGORY_MODULE_COUNTS),
        'module_count': sum(CATEGORY_MODULE_COUNTS.values()),
        'minimum_modules_per_category': min(CATEGORY_MODULE_COUNTS.values()),
        'categories': CATEGORY_MODULE_COUNTS,
    }
    (OUT / 'tool-matrix.json').write_text(json.dumps(data, indent=2), encoding='utf-8')
    lines = ['# VulnScope Module Coverage', '', f"Categories: `{data['category_count']}`", f"Modules: `{data['module_count']}`", f"Minimum per category: `{data['minimum_modules_per_category']}`", '']
    for k, v in CATEGORY_MODULE_COUNTS.items():
        lines.append(f'- `{k}`: `{v}` modules')
    (OUT / 'tool-matrix.md').write_text('\n'.join(lines), encoding='utf-8')
    return data

if __name__ == '__main__':
    print(json.dumps(build_coverage_matrix(), indent=2))

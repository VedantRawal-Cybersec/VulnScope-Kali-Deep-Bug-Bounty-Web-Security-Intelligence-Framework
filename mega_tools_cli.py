#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from arsenal.catalog import ArsenalTool
from arsenal.installer import install_tool, is_installed

OUT = Path('reports/output/mega-tools')

MEGA_TOOLS: list[dict[str, Any]] = [
    {'name':'subfinder','category':'asset_discovery','binary':'subfinder','type':'go','package':'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest','risk':'passive'},
    {'name':'assetfinder','category':'asset_discovery','binary':'assetfinder','type':'go','package':'github.com/tomnomnom/assetfinder@latest','risk':'passive'},
    {'name':'amass','category':'asset_discovery','binary':'amass','type':'go','package':'github.com/owasp-amass/amass/v4/...@master','risk':'passive'},
    {'name':'asnmap','category':'asset_discovery','binary':'asnmap','type':'go','package':'github.com/projectdiscovery/asnmap/cmd/asnmap@latest','risk':'passive'},
    {'name':'chaos','category':'asset_discovery','binary':'chaos','type':'go','package':'github.com/projectdiscovery/chaos-client/cmd/chaos@latest','risk':'passive'},
    {'name':'github-subdomains','category':'asset_discovery','binary':'github-subdomains','type':'go','package':'github.com/gwen001/github-subdomains@latest','risk':'passive'},
    {'name':'dnsx','category':'dns_validation','binary':'dnsx','type':'go','package':'github.com/projectdiscovery/dnsx/cmd/dnsx@latest','risk':'controlled-active'},
    {'name':'tlsx','category':'tls_intel','binary':'tlsx','type':'go','package':'github.com/projectdiscovery/tlsx/cmd/tlsx@latest','risk':'controlled-active'},
    {'name':'cdncheck','category':'infra_intel','binary':'cdncheck','type':'go','package':'github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest','risk':'passive'},
    {'name':'mapcidr','category':'infra_intel','binary':'mapcidr','type':'go','package':'github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest','risk':'local-analysis'},
    {'name':'httpx','category':'http_probe','binary':'httpx','type':'go','package':'github.com/projectdiscovery/httpx/cmd/httpx@latest','risk':'controlled-active'},
    {'name':'httprobe','category':'http_probe','binary':'httprobe','type':'go','package':'github.com/tomnomnom/httprobe@latest','risk':'controlled-active'},
    {'name':'naabu','category':'port_visibility','binary':'naabu','type':'go','package':'github.com/projectdiscovery/naabu/v2/cmd/naabu@latest','risk':'controlled-active'},
    {'name':'uncover','category':'search_api','binary':'uncover','type':'go','package':'github.com/projectdiscovery/uncover/cmd/uncover@latest','risk':'passive'},
    {'name':'gau','category':'url_history','binary':'gau','type':'go','package':'github.com/lc/gau/v2/cmd/gau@latest','risk':'passive'},
    {'name':'waybackurls','category':'url_history','binary':'waybackurls','type':'go','package':'github.com/tomnomnom/waybackurls@latest','risk':'passive'},
    {'name':'waymore','category':'url_history','binary':'waymore','type':'pipx_or_pip','package':'waymore','risk':'passive'},
    {'name':'katana','category':'crawler','binary':'katana','type':'go','package':'github.com/projectdiscovery/katana/cmd/katana@latest','risk':'controlled-active'},
    {'name':'hakrawler','category':'crawler','binary':'hakrawler','type':'go','package':'github.com/hakluke/hakrawler@latest','risk':'controlled-active'},
    {'name':'gospider','category':'crawler','binary':'gospider','type':'go','package':'github.com/jaeles-project/gospider@latest','risk':'controlled-active'},
    {'name':'cariddi','category':'crawler','binary':'cariddi','type':'go','package':'github.com/edoardottt/cariddi/cmd/cariddi@latest','risk':'controlled-active'},
    {'name':'linkfinder','category':'javascript_analysis','binary':'linkfinder','type':'pipx_or_pip','package':'git+https://github.com/GerbenJavado/LinkFinder.git','risk':'local-analysis'},
    {'name':'xnLinkFinder','category':'javascript_analysis','binary':'xnLinkFinder','type':'pipx_or_pip','package':'xnLinkFinder','risk':'local-analysis'},
    {'name':'subjs','category':'javascript_analysis','binary':'subjs','type':'go','package':'github.com/lc/subjs@latest','risk':'passive'},
    {'name':'jsbeautifier','category':'javascript_analysis','binary':'js-beautify','type':'pipx_or_pip','package':'jsbeautifier','risk':'local-analysis'},
    {'name':'mantra','category':'javascript_analysis','binary':'mantra','type':'go','package':'github.com/MrEmpy/mantra@latest','risk':'local-analysis'},
    {'name':'arjun','category':'parameter_discovery','binary':'arjun','type':'pipx_or_pip','package':'arjun','risk':'controlled-active'},
    {'name':'paramspider','category':'parameter_discovery','binary':'paramspider','type':'pipx_or_pip','package':'git+https://github.com/devanshbatham/ParamSpider.git','risk':'passive'},
    {'name':'uro','category':'url_normalization','binary':'uro','type':'pipx_or_pip','package':'uro','risk':'local-analysis'},
    {'name':'unfurl','category':'url_normalization','binary':'unfurl','type':'go','package':'github.com/tomnomnom/unfurl@latest','risk':'local-analysis'},
    {'name':'anew','category':'url_normalization','binary':'anew','type':'go','package':'github.com/tomnomnom/anew@latest','risk':'local-analysis'},
    {'name':'qsreplace','category':'parameter_transform','binary':'qsreplace','type':'go','package':'github.com/tomnomnom/qsreplace@latest','risk':'local-analysis'},
    {'name':'gf','category':'pattern_matching','binary':'gf','type':'go','package':'github.com/tomnomnom/gf@latest','risk':'local-analysis'},
    {'name':'gron','category':'json_analysis','binary':'gron','type':'go','package':'github.com/tomnomnom/gron@latest','risk':'local-analysis'},
    {'name':'jq-python','category':'json_analysis','binary':'jq','type':'pipx_or_pip','package':'jq','risk':'local-analysis'},
    {'name':'nuclei','category':'template_review','binary':'nuclei','type':'go','package':'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest','risk':'controlled-active'},
    {'name':'pdtm','category':'tool_manager','binary':'pdtm','type':'go','package':'github.com/projectdiscovery/pdtm/cmd/pdtm@latest','risk':'local-analysis'},
    {'name':'gitleaks','category':'secrets_exposure','binary':'gitleaks','type':'go','package':'github.com/gitleaks/gitleaks/v8@latest','risk':'local-analysis'},
    {'name':'trufflehog','category':'secrets_exposure','binary':'trufflehog','type':'go','package':'github.com/trufflesecurity/trufflehog/v3@latest','risk':'local-analysis'},
    {'name':'git-secrets','category':'secrets_exposure','binary':'git-secrets','type':'go','package':'github.com/awslabs/git-secrets@latest','risk':'local-analysis'},
    {'name':'gobuster','category':'content_discovery','binary':'gobuster','type':'go','package':'github.com/OJ/gobuster/v3@latest','risk':'controlled-active'},
    {'name':'ffuf','category':'content_discovery','binary':'ffuf','type':'go','package':'github.com/ffuf/ffuf/v2@latest','risk':'controlled-active'},
    {'name':'dirsearch','category':'content_discovery','binary':'dirsearch','type':'pipx_or_pip','package':'dirsearch','risk':'controlled-active'},
    {'name':'feroxbuster','category':'content_discovery','binary':'feroxbuster','type':'unsupported','package':'manual-cargo-or-apt','risk':'controlled-active'},
    {'name':'gowitness','category':'visual_review','binary':'gowitness','type':'go','package':'github.com/sensepost/gowitness@latest','risk':'controlled-active'},
    {'name':'aquatone','category':'visual_review','binary':'aquatone','type':'go','package':'github.com/michenriksen/aquatone@latest','risk':'controlled-active'},
    {'name':'graphw00f','category':'graphql_review','binary':'graphw00f','type':'pipx_or_pip','package':'graphw00f','risk':'controlled-active'},
    {'name':'clairvoyance','category':'graphql_review','binary':'clairvoyance','type':'pipx_or_pip','package':'clairvoyance','risk':'controlled-active'},
    {'name':'corsy','category':'cors_review','binary':'corsy','type':'pipx_or_pip','package':'git+https://github.com/s0md3v/Corsy.git','risk':'controlled-active'},
    {'name':'crlfuzz','category':'header_review','binary':'crlfuzz','type':'go','package':'github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest','risk':'controlled-active'},
    {'name':'kxss','category':'xss_review','binary':'kxss','type':'go','package':'github.com/tomnomnom/hacks/kxss@latest','risk':'local-analysis'},
    {'name':'Gxss','category':'xss_review','binary':'Gxss','type':'go','package':'github.com/KathanP19/Gxss@latest','risk':'local-analysis'},
    {'name':'dalfox','category':'xss_review','binary':'dalfox','type':'go','package':'github.com/hahwul/dalfox/v2@latest','risk':'controlled-active'},
    {'name':'smap','category':'service_mapping','binary':'smap','type':'go','package':'github.com/s0md3v/Smap/cmd/smap@latest','risk':'controlled-active'},
    {'name':'wafw00f','category':'waf_detection','binary':'wafw00f','type':'pipx_or_pip','package':'wafw00f','risk':'controlled-active'},
    {'name':'whatweb','category':'technology_detection','binary':'whatweb','type':'unsupported','package':'apt:whatweb','risk':'controlled-active'},
    {'name':'builtwith','category':'technology_detection','binary':'builtwith','type':'pipx_or_pip','package':'builtwith','risk':'passive'},
    {'name':'retire','category':'dependency_review','binary':'retire','type':'unsupported','package':'npm:retire','risk':'local-analysis'},
    {'name':'testssl','category':'tls_review','binary':'testssl.sh','type':'unsupported','package':'apt-or-git:testssl.sh','risk':'controlled-active'},
    {'name':'hakrevdns','category':'reverse_dns','binary':'hakrevdns','type':'go','package':'github.com/hakluke/hakrevdns@latest','risk':'passive'},
    {'name':'gotator','category':'permutation','binary':'gotator','type':'go','package':'github.com/Josue87/gotator@latest','risk':'local-analysis'},
    {'name':'alterx','category':'permutation','binary':'alterx','type':'go','package':'github.com/projectdiscovery/alterx/cmd/alterx@latest','risk':'local-analysis'},
    {'name':'puredns','category':'dns_validation','binary':'puredns','type':'go','package':'github.com/d3mondev/puredns/v2@latest','risk':'controlled-active'},
    {'name':'massdns-wrapper','category':'dns_validation','binary':'massdns','type':'unsupported','package':'apt:massdns','risk':'controlled-active'},
]


def as_tool(item: dict[str, Any]) -> ArsenalTool:
    return ArsenalTool(
        name=item['name'], category=item['category'], binary=item['binary'],
        install={'type': item['type'], 'package': item['package']},
        risk_level=item['risk'], requires_approval=item['risk'] != 'passive',
        enabled_by_default=False, safe_command_template='',
        output_file=f"reports/output/mega-tools/{item['name']}.txt",
        notes='Mega tool registry entry. Install only; execution remains controlled by VulnScope methodology gates.',
    )


def build_status(install_missing: bool = False, yes: bool = False) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    for item in MEGA_TOOLS:
        tool = as_tool(item)
        supported = item['type'] in {'go', 'pipx_or_pip'}
        installed = is_installed(tool)
        if install_missing and supported and not installed:
            installed = install_tool(tool, yes=yes, allow_system=True)
        rows.append({**item, 'supported_auto_install': supported, 'installed': installed, 'path': shutil.which(item['binary'])})
    payload = {
        'tool_count': len(rows),
        'installed_count': len([r for r in rows if r['installed']]),
        'supported_auto_install_count': len([r for r in rows if r['supported_auto_install']]),
        'categories': sorted({r['category'] for r in rows}),
        'category_counts': {c: len([r for r in rows if r['category'] == c]) for c in sorted({r['category'] for r in rows})},
        'tools': rows,
    }
    (OUT / 'mega-tools-status.json').write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
    lines = ['# VulnScope Mega Tools', '', f"Tools: `{payload['tool_count']}`", f"Installed: `{payload['installed_count']}`", f"Auto-install supported: `{payload['supported_auto_install_count']}`", '', '## Categories']
    for cat, count in payload['category_counts'].items():
        lines.append(f'- `{cat}`: `{count}` tools')
    lines += ['', '## Tool Status']
    for r in rows:
        lines.append(f"- `{r['name']}` [{r['category']}] installed=`{r['installed']}` auto_install=`{r['supported_auto_install']}`")
    (OUT / 'mega-tools-status.md').write_text('\n'.join(lines), encoding='utf-8')
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description='VulnScope 50+ safe tool registry and installer')
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--status', action='store_true')
    parser.add_argument('--install-missing', action='store_true')
    parser.add_argument('--yes', action='store_true')
    args = parser.parse_args()
    result = build_status(install_missing=args.install_missing, yes=args.yes)
    print(json.dumps({'tool_count': result['tool_count'], 'installed': result['installed_count'], 'categories': len(result['categories']), 'report': 'reports/output/mega-tools/mega-tools-status.md'}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

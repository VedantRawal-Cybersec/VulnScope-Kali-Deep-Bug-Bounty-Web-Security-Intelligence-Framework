#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import re
import time
from pathlib import Path
from typing import Any

import safe_canary_cli as base
from target_scope_guard import normalize_target

OUT = Path("reports/output/safe-canary")

PARAMETER_SETS: list[dict[str, Any]] = [
    {"family": "text", "marker": "VS_TEXT_SAFE", "params": ["q", "s", "search", "query", "keyword", "term", "name", "ref"]},
    {"family": "navigation", "marker": "https://example.invalid/vs-safe-return", "params": ["next", "return", "return_url", "redirect", "continue", "url", "target"]},
    {"family": "identifier", "marker": "100000001", "params": ["id", "uid", "user_id", "account_id", "order_id", "product_id", "item_id"]},
    {"family": "file", "marker": "safe_vulnscope_file.txt", "params": ["file", "filename", "path", "download", "document", "asset"]},
    {"family": "api", "marker": "VS_API_SAFE_JSON", "params": ["format", "type", "view", "mode", "callback", "version", "output"]},
    {"family": "filter", "marker": "VS_FILTER_SAFE", "params": ["filter", "sort", "order", "page", "limit", "offset", "category", "tag", "lang", "locale"]},
    {"family": "state", "marker": "VS_STATE_SAFE", "params": ["state", "code", "nonce", "token", "key"]},
    {"family": "date", "marker": "2099-12-31", "params": ["date", "from", "to", "start", "end", "start_date", "end_date"]},
    {"family": "email", "marker": "safe-vulnscope@example.invalid", "params": ["email", "mail", "contact", "recipient"]},
]


def host_from_target(target: str) -> str:
    return base.host_from_target(target)


def run_family(target: str, item: dict[str, Any], max_urls: int, per_url_limit: int, delay: float, timeout: int) -> dict[str, Any]:
    family = str(item["family"])
    marker = str(item["marker"])
    params = [str(x) for x in item["params"]]
    original = list(getattr(base, "SAFE_PARAM_NAMES", []))
    try:
        base.SAFE_PARAM_NAMES = params
        payload = base.run_canary_review(target, canary=marker, max_urls=max_urls, per_url_limit=per_url_limit, delay=delay, timeout=timeout)
    finally:
        base.SAFE_PARAM_NAMES = original
    for row in payload.get("results", []):
        if isinstance(row, dict):
            row["family"] = family
            row["parameter_set"] = params
            row["safe_marker_family"] = family
            row["selection_reason"] = f"Selected from {family} safe parameter family."
    for row in payload.get("findings", []):
        if isinstance(row, dict):
            row["family"] = family
            row["parameter_set"] = params
            row["safe_marker_family"] = family
            row["selection_reason"] = f"Selected from {family} safe parameter family."
    return payload


def run_adaptive_safe_parameters(target: str, max_urls: int = 70, per_url_limit: int = 4, delay: float = 0.35, timeout: int = 10, families: int = 9) -> dict[str, Any]:
    target = normalize_target(target)
    OUT.mkdir(parents=True, exist_ok=True)
    started = time.time()
    all_results: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    family_summaries: list[dict[str, Any]] = []

    print("=" * 72, flush=True)
    print("VULNSCOPE ADAPTIVE SAFE PARAMETER ORCHESTRATOR", flush=True)
    print(f"Target: {target}", flush=True)
    print("Mode: GET-only safe marker families, no data modification", flush=True)
    print("=" * 72, flush=True)

    selected = PARAMETER_SETS[:max(1, min(families, len(PARAMETER_SETS)))]
    for index, item in enumerate(selected, 1):
        print(f"[family {index}/{len(selected)}] {item['family']} params={','.join(item['params'][:6])}", flush=True)
        payload = run_family(target, item, max_urls=max_urls, per_url_limit=per_url_limit, delay=delay, timeout=timeout)
        family_summaries.append({"family": item["family"], "marker": item["marker"], "params": item["params"], "summary": payload.get("summary", {})})
        all_results.extend([r for r in payload.get("results", []) if isinstance(r, dict)])
        all_findings.extend([r for r in payload.get("findings", []) if isinstance(r, dict)])

    unique_findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for row in all_findings:
        key = (str(row.get("family", "")), str(row.get("parameter", "")), str(row.get("tested_url", "")), str(row.get("evidence", ""))[:80])
        if key not in seen:
            seen.add(key)
            unique_findings.append(row)

    payload = {
        "target": target,
        "generated_at": time.time(),
        "summary": {
            "families_run": len(selected),
            "tests_run": len(all_results),
            "safe_parameter_observations": len(unique_findings),
            "canary_observations": len(unique_findings),
            "seconds": round(time.time() - started, 2),
        },
        "parameter_families": selected,
        "safety": {
            "method": "GET-only safe parameter family review",
            "no_post_requests": True,
            "no_state_changing_methods": True,
            "no_login_actions": True,
            "target_scope_only": True,
            "redirects_not_followed": True,
        },
        "family_summaries": family_summaries,
        "findings": unique_findings,
        "results": all_results,
    }
    (OUT / "safe-canary.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    (OUT / "safe-probes.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        f"# Adaptive Safe Parameter Review — {host_from_target(target)}",
        "",
        f"Target: `{target}`",
        f"Families run: `{len(selected)}`",
        f"Tests run: `{len(all_results)}`",
        f"Safe parameter observations: `{len(unique_findings)}`",
        "",
        "## Safety Controls",
        "- GET requests only.",
        "- No state-changing methods.",
        "- No login actions.",
        "- Redirects are not followed.",
        "- Only target-scoped URLs are reviewed.",
        "",
        "## Parameter Families",
    ]
    for item in selected:
        lines.append(f"- `{item['family']}` marker=`{item['marker']}` params=`{', '.join(item['params'])}`")
    lines += ["", "## Observations"]
    if not unique_findings:
        lines.append("No reflected safe-marker observations were found.")
    for idx, row in enumerate(unique_findings[:80], 1):
        lines += [
            f"### {idx}. {row.get('category', 'safe_parameter_observation')}",
            f"- Family: `{row.get('family', 'generic')}`",
            f"- Parameter: `{row.get('parameter', 'n/a')}`",
            f"- Tested URL: `{row.get('tested_url', 'n/a')}`",
            f"- Reflected in: `{', '.join(row.get('reflected_in', []))}`",
            f"- Evidence: `{html.escape(str(row.get('evidence', '')))}`",
            f"- How to confirm: {row.get('how_to_confirm', 'Repeat the same safe GET request and manually validate context before reporting.')}",
            "",
        ]
    md = "\n".join(lines)
    (OUT / "safe-canary.md").write_text(md, encoding="utf-8")
    (OUT / "safe-probes.md").write_text(md, encoding="utf-8")
    print(json.dumps({"summary": payload["summary"], "report": "reports/output/safe-canary/safe-probes.md"}, indent=2), flush=True)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Adaptive safe parameter family orchestrator")
    parser.add_argument("--target", required=True)
    parser.add_argument("--max-urls", type=int, default=70)
    parser.add_argument("--per-url-limit", type=int, default=4)
    parser.add_argument("--delay", type=float, default=0.35)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--families", type=int, default=9)
    args = parser.parse_args()
    run_adaptive_safe_parameters(args.target, max_urls=args.max_urls, per_url_limit=args.per_url_limit, delay=args.delay, timeout=args.timeout, families=args.families)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

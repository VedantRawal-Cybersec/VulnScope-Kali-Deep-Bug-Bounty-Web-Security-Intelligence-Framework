#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from target_scope_guard import normalize_target

OUT = Path("reports/output/final-dashboard")


def load_json(path: str | Path) -> Any:
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def host_from_target(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    return (parsed.hostname or parsed.netloc or target).split(":")[0].lower().strip()


def slug(target: str) -> str:
    return re.sub(r"[^a-z0-9.-]+", "-", host_from_target(target)).strip("-.") or "target"


def parts(url: str) -> dict[str, Any]:
    parsed = urlparse(url or "")
    params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    return {"path": parsed.path or "/", "query": parsed.query or "", "params": params}


def short(value: Any, n: int = 220) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= n else text[: n - 3] + "..."


def add(rows: list[dict[str, Any]], item: dict[str, Any], source: str, target: str) -> None:
    where = str(item.get("tested_url") or item.get("where_found") or item.get("url") or item.get("endpoint") or item.get("item") or target)
    p = parts(where)
    rows.append({
        "source": source,
        "title": short(item.get("title") or item.get("category") or item.get("type") or item.get("verdict") or "Review lead", 90),
        "type": short(item.get("category") or item.get("type") or item.get("module") or "review", 70),
        "where": short(where, 240),
        "path": p["path"],
        "query": p["query"],
        "parameter": item.get("parameter") or (p["params"][0] if p["params"] else "n/a"),
        "evidence": short(item.get("evidence") or item.get("why_flagged") or item.get("reason") or item.get("decision") or "Evidence available in module report.", 260),
        "status": short(item.get("status") or item.get("verdict") or "review_needed", 80),
        "real_or_not": "Candidate only; manual verification required before reporting.",
    })


def build(target: str) -> dict[str, Any]:
    target = normalize_target(target)
    s = slug(target)
    rows: list[dict[str, Any]] = []
    source_specs = [
        ("Safe CANARY_123 Review", "reports/output/safe-canary/safe-canary.json", "findings"),
        ("Final Brief", Path("reports/output/domain-reports") / f"{s}-finding-brief.json", "findings"),
        ("Mission Verdicts", "reports/output/mission-verdicts/mission-verdicts.json", "rows"),
    ]
    for source, path, key in source_specs:
        data = load_json(path)
        if not isinstance(data, dict):
            continue
        for item in data.get(key, [])[:120]:
            if isinstance(item, dict):
                add(rows, item, source, target)

    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        key = (row["type"].lower(), row["where"].lower(), row["evidence"].lower()[:80])
        if key not in seen:
            seen.add(key)
            unique.append(row)

    OUT.mkdir(parents=True, exist_ok=True)
    json_path = OUT / f"{s}-dashboard.json"
    md_path = OUT / f"{s}-dashboard.md"
    payload = {"target": target, "host": host_from_target(target), "generated_at": time.time(), "summary": {"review_leads": len(unique), "auto_confirmed": 0}, "rows": unique}
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [f"# VulnScope Output Dashboard — {payload['host']}", "", f"Target: `{target}`", f"Review leads: `{len(unique)}`", "Auto-confirmed: `0`", "", "## Leads"]
    if not unique:
        lines.append("No review lead was generated from the available evidence.")
    for i, row in enumerate(unique[:80], 1):
        lines += [f"### {i}. {row['title']}", f"- Source: `{row['source']}`", f"- Type: `{row['type']}`", f"- Real or not: {row['real_or_not']}", f"- Path: `{row['path']}`", f"- Query: `{row['query'] or 'n/a'}`", f"- Parameter: `{row['parameter']}`", f"- Where: `{row['where']}`", f"- Evidence: {row['evidence']}", ""]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"summary": payload["summary"], "markdown": str(md_path), "json": str(json_path)}, indent=2), flush=True)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate final review dashboard")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    build(args.target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

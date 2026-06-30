#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
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


def esc(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


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
        ("Adaptive Safe Parameter Review", "reports/output/safe-canary/safe-canary.json", "findings"),
        ("Final Brief", Path("reports/output/domain-reports") / f"{s}-finding-brief.json", "findings"),
        ("Mission Verdicts", "reports/output/mission-verdicts/mission-verdicts.json", "rows"),
    ]
    for source, path, key in source_specs:
        data = load_json(path)
        if not isinstance(data, dict):
            continue
        for item in data.get(key, [])[:120]:
            if isinstance(item, dict):
                verdict = str(item.get("verdict") or "").upper()
                if verdict in {"OK", "COMPLETED", "INSTALLED"}:
                    continue
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
    html_path = OUT / f"{s}-dashboard.html"
    latest_html = OUT / f"{s}-latest-dashboard.html"
    safe_count = len([r for r in unique if "safe" in r["source"].lower() or "safe" in r["type"].lower()])
    payload = {"target": target, "host": host_from_target(target), "generated_at": time.time(), "summary": {"review_leads": len(unique), "safe_parameter_observations": safe_count, "auto_confirmed": 0}, "rows": unique}
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [f"# VulnScope Output Dashboard — {payload['host']}", "", f"Target: `{target}`", f"Review leads: `{len(unique)}`", f"Safe parameter observations: `{safe_count}`", "Auto-confirmed: `0`", "", "## Leads"]
    if not unique:
        lines.append("No review lead was generated from the available evidence.")
    for i, row in enumerate(unique[:80], 1):
        lines += [f"### {i}. {row['title']}", f"- Source: `{row['source']}`", f"- Type: `{row['type']}`", f"- Real or not: {row['real_or_not']}", f"- Path: `{row['path']}`", f"- Query: `{row['query'] or 'n/a'}`", f"- Parameter: `{row['parameter']}`", f"- Where: `{row['where']}`", f"- Evidence: {row['evidence']}", ""]
    md_path.write_text("\n".join(lines), encoding="utf-8")

    cards = []
    if not unique:
        cards.append("<section class='card'><h2>No review lead generated</h2><p>No strong lead was produced from the available evidence.</p></section>")
    for i, row in enumerate(unique[:80], 1):
        cards.append(f"""
<section class="card">
  <div class="chips"><span>#{i}</span><span>{esc(row['source'])}</span><span>{esc(row['status'])}</span></div>
  <h2>{esc(row['title'])}</h2>
  <div class="grid"><div><b>Type</b><code>{esc(row['type'])}</code></div><div><b>Real or not?</b><code>{esc(row['real_or_not'])}</code></div><div><b>Path</b><code>{esc(row['path'])}</code></div><div><b>Query</b><code>{esc(row['query'] or 'n/a')}</code></div><div><b>Parameter</b><code>{esc(row['parameter'])}</code></div></div>
  <p><b>Where:</b> <code>{esc(row['where'])}</code></p>
  <p><b>Evidence:</b> {esc(row['evidence'])}</p>
</section>""")
    html_text = f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VulnScope Dashboard</title><style>body{{margin:0;background:#0b1020;color:#edf3ff;font-family:Arial,sans-serif}}header{{padding:30px;background:#121933;border-bottom:1px solid #2b3765}}main{{padding:26px}}.stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:18px}}.metric,.card{{background:#121933;border:1px solid #2b3765;border-radius:18px;padding:18px}}.metric b{{font-size:34px;color:#7aa2ff}}.card{{margin:16px 0}}.chips{{display:flex;gap:8px;flex-wrap:wrap}}.chips span{{border:1px solid #2b3765;border-radius:999px;padding:6px 10px;color:#aab6d3;font-size:12px}}.grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}}.grid div{{background:#172044;border-radius:12px;padding:12px}}p{{color:#aab6d3}}code{{color:#d8e4ff;word-break:break-word}}@media(max-width:800px){{.stats,.grid{{grid-template-columns:1fr}}}}</style></head><body><header><h1>VulnScope Autonomous Output Dashboard</h1><p>Target: <code>{esc(target)}</code></p></header><main><section class="stats"><div class="metric"><b>{len(unique)}</b><p>Review leads</p></div><div class="metric"><b>{safe_count}</b><p>Safe parameter observations</p></div><div class="metric"><b>0</b><p>Auto-confirmed</p></div></section>{''.join(cards)}</main></body></html>"""
    html_path.write_text(html_text, encoding="utf-8")
    latest_html.write_text(html_text, encoding="utf-8")
    print(json.dumps({"summary": payload["summary"], "html": str(html_path), "markdown": str(md_path), "json": str(json_path)}, indent=2), flush=True)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate final review dashboard")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    build(args.target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

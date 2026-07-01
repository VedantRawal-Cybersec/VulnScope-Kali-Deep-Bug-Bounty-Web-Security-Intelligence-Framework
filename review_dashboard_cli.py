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
    except Exception as exc:
        return {"_error": str(exc), "_path": str(path)}


def host_from_target(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    return (parsed.hostname or parsed.netloc or target).split(":")[0].lower().strip()


def slug(target: str) -> str:
    return re.sub(r"[^a-z0-9.-]+", "-", host_from_target(target)).strip("-.") or "target"


def url_parts(url: str) -> dict[str, Any]:
    parsed = urlparse(str(url or ""))
    params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    return {"path": parsed.path or "/", "query": parsed.query or "", "params": params}


def short(value: Any, n: int = 260) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= n else text[: n - 3] + "..."


def esc(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def text_value(item: dict[str, Any], keys: list[str], fallback: str = "n/a") -> str:
    for key in keys:
        value = item.get(key)
        if value not in (None, "", [], {}):
            return str(value)
    return fallback


def confirmation_status(item: dict[str, Any]) -> dict[str, Any]:
    joined = " ".join(str(item.get(k, "")) for k in ["status", "verdict", "reportability_bucket", "decision", "evidence", "title", "category", "type"]).lower()
    if any(word in joined for word in ["confirmed", "proven", "validated", "verified"]):
        return {
            "confirmed": True,
            "label": "Confirmed by available evidence",
            "reason": "The source report used confirmed or validated language. Recheck manually before external reporting.",
            "reportability": "Potentially reportable after final human review",
        }
    if any(word in joined for word in ["false_positive", "not exploitable", "not_reflected", "no issue"]):
        return {
            "confirmed": False,
            "label": "Not confirmed / likely not exploitable",
            "reason": "The available evidence does not show exploitable impact.",
            "reportability": "Do not report as a vulnerability",
        }
    return {
        "confirmed": False,
        "label": "Not confirmed automatically",
        "reason": "VulnScope found a review lead. Manual authorized validation is required before calling it a vulnerability.",
        "reportability": "Review lead only",
    }


def safe_confirm_plan(item: dict[str, Any]) -> str:
    direct = item.get("how_to_confirm") or item.get("confirmation") or item.get("manual_validation")
    if direct:
        return short(direct, 360)
    joined = " ".join(str(item.get(k, "")) for k in ["title", "type", "category", "where_found", "tested_url", "evidence"]).lower()
    if "redirect" in joined:
        return "Repeat the same safe GET request with an example.invalid return URL and verify whether external navigation is allowed. Do not use destructive payloads."
    if "safe" in joined or "parameter" in joined or "canary" in joined:
        return "Repeat the same GET request with the same harmless marker, inspect body/header/location context, and confirm whether it is only reflection or a real impact path."
    if "header" in joined or "cookie" in joined:
        return "Recheck the exact response headers and cookie flags on the affected URL, then classify as hardening unless real impact is proven."
    if "top100" in joined:
        return "Open the referenced Top102 output file, verify target scope, then manually validate only safe, authorized leads."
    return "Reproduce the observation on the authorized target, capture evidence, and mark confirmed only when real impact is safely proven."


def add(rows: list[dict[str, Any]], item: dict[str, Any], source: str, target: str) -> None:
    where = text_value(item, ["tested_url", "where_found", "url", "endpoint", "item", "target"], target)
    p = url_parts(where)
    confirm = confirmation_status(item)
    title = text_value(item, ["title", "name", "category", "type", "verdict", "module"], "Security review lead")
    ftype = text_value(item, ["type", "category", "detector", "module"], "review")
    how = text_value(item, ["how_found", "evidence_source", "source_file", "module", "_source_file"], source)
    evidence = text_value(item, ["evidence", "why_flagged", "reason", "decision", "safe_check", "verdict"], "Evidence is available in the source module report.")
    status = text_value(item, ["status", "verdict", "reportability_bucket"], "review_needed")
    rows.append({
        "source": source,
        "what_found": short(title, 120),
        "type": short(ftype, 90),
        "where_found": short(where, 260),
        "path": p["path"],
        "query": p["query"],
        "parameter": item.get("parameter") or (p["params"][0] if p["params"] else "n/a"),
        "how_found": short(how, 220),
        "evidence": short(evidence, 360),
        "confirmation_status": confirm["label"],
        "confirmed": confirm["confirmed"],
        "confirmation_reason": confirm["reason"],
        "reportability": confirm["reportability"],
        "safe_confirmation_plan": safe_confirm_plan(item),
        "status": short(status, 100),
    })


def collect_rows(target: str) -> list[dict[str, Any]]:
    s = slug(target)
    source_specs = [
        ("Final Finding Brief", Path("reports/output/domain-reports") / f"{s}-finding-brief.json", "findings"),
        ("Adaptive Safe Parameter Review", "reports/output/safe-canary/safe-canary.json", "findings"),
        ("Adaptive Safe Parameter Review", "reports/output/safe-canary/safe-probes.json", "findings"),
        ("Mission Verdicts", "reports/output/mission-verdicts/mission-verdicts.json", "rows"),
        ("Evidence Cards", "reports/output/evidence-cards/evidence-cards.json", "cards"),
        ("Reportability", "reports/output/reportability/reportability.json", "candidates"),
    ]
    rows: list[dict[str, Any]] = []
    for source, path, key in source_specs:
        data = load_json(path)
        if not isinstance(data, dict):
            continue
        for item in data.get(key, [])[:160]:
            if not isinstance(item, dict):
                continue
            verdict = str(item.get("verdict") or item.get("status") or "").upper()
            if verdict in {"OK", "COMPLETED", "INSTALLED"}:
                continue
            add(rows, item, source, target)

    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        key = (row["type"].lower(), row["where_found"].lower(), row["evidence"].lower()[:100])
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    return unique


def build(target: str) -> dict[str, Any]:
    target = normalize_target(target)
    host = host_from_target(target)
    s = slug(target)
    rows = collect_rows(target)
    confirmed_count = len([r for r in rows if r["confirmed"]])
    needs_validation = len([r for r in rows if not r["confirmed"]])
    safe_count = len([r for r in rows if "safe" in r["source"].lower() or "safe" in r["type"].lower() or "parameter" in r["type"].lower()])

    OUT.mkdir(parents=True, exist_ok=True)
    json_path = OUT / f"{s}-dashboard.json"
    md_path = OUT / f"{s}-dashboard.md"
    html_path = OUT / f"{s}-dashboard.html"
    latest_html = OUT / f"{s}-latest-dashboard.html"
    payload = {
        "target": target,
        "host": host,
        "generated_at": time.time(),
        "summary": {
            "total_review_leads": len(rows),
            "confirmed": confirmed_count,
            "not_confirmed": needs_validation,
            "safe_parameter_observations": safe_count,
            "reporting_rule": "Only confirmed findings with proven safe impact should be reported. Review leads are not vulnerabilities by themselves.",
        },
        "findings": rows,
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        f"# VulnScope Final Dashboard — {host}",
        "",
        f"Target: `{target}`",
        f"Total review leads: `{len(rows)}`",
        f"Confirmed: `{confirmed_count}`",
        f"Not confirmed / needs manual validation: `{needs_validation}`",
        f"Safe parameter observations: `{safe_count}`",
        "",
        "## Findings",
    ]
    if not rows:
        lines += ["No finding or review lead was generated from the available evidence.", ""]
    for i, row in enumerate(rows[:120], 1):
        lines += [
            f"### {i}. {row['what_found']}",
            f"- What: `{row['type']}`",
            f"- Where: `{row['where_found']}`",
            f"- Path: `{row['path']}`",
            f"- Parameter: `{row['parameter']}`",
            f"- How found: {row['how_found']}",
            f"- Evidence: {row['evidence']}",
            f"- Confirmed or not: `{row['confirmation_status']}`",
            f"- Why: {row['confirmation_reason']}",
            f"- Reportability: `{row['reportability']}`",
            f"- Safe confirmation plan: {row['safe_confirmation_plan']}",
            "",
        ]
    md_path.write_text("\n".join(lines), encoding="utf-8")

    cards: list[str] = []
    if not rows:
        cards.append("<section class='card'><h2>No findings generated</h2><p>No confirmed vulnerability or strong review lead was produced from the available evidence.</p></section>")
    for i, row in enumerate(rows[:120], 1):
        badge = "CONFIRMED" if row["confirmed"] else "NOT CONFIRMED"
        cards.append(f"""
<section class="card">
  <div class="chips"><span>#{i}</span><span>{esc(row['source'])}</span><span>{esc(badge)}</span><span>{esc(row['status'])}</span></div>
  <h2>{esc(row['what_found'])}</h2>
  <div class="grid">
    <div><b>What</b><code>{esc(row['type'])}</code></div>
    <div><b>Confirmed or not</b><code>{esc(row['confirmation_status'])}</code></div>
    <div><b>Path</b><code>{esc(row['path'])}</code></div>
    <div><b>Parameter</b><code>{esc(row['parameter'])}</code></div>
  </div>
  <p><b>Where found:</b> <code>{esc(row['where_found'])}</code></p>
  <p><b>How found:</b> {esc(row['how_found'])}</p>
  <p><b>Evidence:</b> {esc(row['evidence'])}</p>
  <p><b>Why this status:</b> {esc(row['confirmation_reason'])}</p>
  <p><b>Reportability:</b> <code>{esc(row['reportability'])}</code></p>
  <p><b>Safe confirmation plan:</b> {esc(row['safe_confirmation_plan'])}</p>
</section>""")

    html_text = f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VulnScope Final Dashboard</title><style>body{{margin:0;background:#0b1020;color:#edf3ff;font-family:Arial,sans-serif}}header{{padding:32px;background:#121933;border-bottom:1px solid #2b3765}}main{{padding:26px}}.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}}.metric,.card{{background:#121933;border:1px solid #2b3765;border-radius:18px;padding:18px}}.metric b{{font-size:34px;color:#7aa2ff}}.card{{margin:16px 0}}.chips{{display:flex;gap:8px;flex-wrap:wrap}}.chips span{{border:1px solid #2b3765;border-radius:999px;padding:6px 10px;color:#aab6d3;font-size:12px}}.grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}}.grid div{{background:#172044;border-radius:12px;padding:12px}}p{{color:#aab6d3;line-height:1.55}}code{{color:#d8e4ff;word-break:break-word}}.rule{{background:#172044;border-left:4px solid #7aa2ff;padding:12px 14px;border-radius:12px;color:#d8e4ff}}@media(max-width:900px){{.stats,.grid{{grid-template-columns:1fr}}}}</style></head><body><header><h1>VulnScope Final Finding Dashboard</h1><p>Target: <code>{esc(target)}</code></p><p class="rule">This dashboard separates confirmed findings from review leads. A lead is not a vulnerability until safe authorized validation proves real impact.</p></header><main><section class="stats"><div class="metric"><b>{len(rows)}</b><p>Total review leads</p></div><div class="metric"><b>{confirmed_count}</b><p>Confirmed</p></div><div class="metric"><b>{needs_validation}</b><p>Not confirmed</p></div><div class="metric"><b>{safe_count}</b><p>Safe parameter observations</p></div></section>{''.join(cards)}</main></body></html>"""
    html_path.write_text(html_text, encoding="utf-8")
    latest_html.write_text(html_text, encoding="utf-8")
    print(json.dumps({"summary": payload["summary"], "html": str(html_path), "latest_html": str(latest_html), "markdown": str(md_path), "json": str(json_path)}, indent=2), flush=True)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate final finding dashboard with confirmation status")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    build(args.target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

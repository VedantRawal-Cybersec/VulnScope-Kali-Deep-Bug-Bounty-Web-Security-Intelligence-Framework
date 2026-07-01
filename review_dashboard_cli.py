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

from finding_confirmation_engine import confirm_findings, write_confirmation_reports
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


def raw_add(rows: list[dict[str, Any]], item: dict[str, Any], source: str, target: str) -> None:
    where = text_value(item, ["tested_url", "where_found", "url", "endpoint", "item", "target"], target)
    p = url_parts(where)
    rows.append({
        "source": source,
        "what_found": short(text_value(item, ["title", "name", "category", "type", "verdict", "module"], "Security review lead"), 160),
        "type": short(text_value(item, ["type", "category", "detector", "module", "vulnerability_type"], "review"), 120),
        "where_found": short(where, 320),
        "tested_url": where,
        "path": p["path"],
        "query": p["query"],
        "parameter": item.get("parameter") or (p["params"][0] if p["params"] else "n/a"),
        "how_found": short(text_value(item, ["how_found", "evidence_source", "source_file", "module", "_source_file"], source), 260),
        "evidence": text_value(item, ["evidence", "evidence_detail", "why_flagged", "reason", "decision", "safe_check", "verdict", "tail"], "Evidence is available in the source module report."),
        "status": short(text_value(item, ["status", "verdict", "reportability_bucket"], "review_needed"), 120),
        "control_comparison_result": item.get("control_comparison_result") or item.get("control") or item.get("baseline") or item.get("baseline_result"),
        "raw_item": item,
    })


def collect_raw_candidates(target: str) -> list[dict[str, Any]]:
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
        for item in data.get(key, [])[:220]:
            if not isinstance(item, dict):
                continue
            verdict = str(item.get("verdict") or item.get("status") or "").upper()
            if verdict in {"OK", "COMPLETED", "INSTALLED"}:
                continue
            raw_add(rows, item, source, target)
    return rows


def finding_markdown(rows: list[dict[str, Any]]) -> list[str]:
    if not rows:
        return ["No confirmed finding or review lead survived the confirmation engine.", ""]
    lines: list[str] = []
    for i, row in enumerate(rows[:120], 1):
        lines += [
            f"### {i}. {row['what_found']}",
            f"- Classification: `{row['classification']}`",
            f"- Vulnerability type: `{row['vulnerability_type']}`",
            f"- Confidence: `{row['confidence']}`",
            f"- Dedup group size: `{row['dedup_group_size']}`",
            f"- Eligibility: {row['eligibility_check']}",
            f"- Evidence type: `{row['evidence_type']}`",
            f"- Evidence detail: {row['evidence_detail']}",
            f"- Control comparison: {row['control_comparison_result']}",
            f"- Where: `{row['where_found']}`",
            f"- Path: `{row['path']}`",
            f"- Parameter: `{row['parameter']}`",
            f"- Confirmed or not: `{row['confirmation_status']}`",
            f"- False-positive risk: {row['false_positive_risk_notes']}",
            f"- Reportability: `{row['reportability']}`",
            "",
        ]
    return lines


def card(row: dict[str, Any], i: int) -> str:
    badge = "CONFIRMED" if row.get("classification") == "CONFIRMED" else "REVIEW LEAD"
    return f"""
<section class="card">
  <div class="chips"><span>#{i}</span><span>{esc(row.get('source'))}</span><span>{esc(badge)}</span><span>confidence: {esc(row.get('confidence'))}</span><span>dedup: {esc(row.get('dedup_group_size'))}</span></div>
  <h2>{esc(row.get('what_found'))}</h2>
  <div class="grid">
    <div><b>Vulnerability type</b><code>{esc(row.get('vulnerability_type'))}</code></div>
    <div><b>Confirmed or not</b><code>{esc(row.get('confirmation_status'))}</code></div>
    <div><b>Evidence type</b><code>{esc(row.get('evidence_type'))}</code></div>
    <div><b>Parameter</b><code>{esc(row.get('parameter'))}</code></div>
  </div>
  <p><b>Where found:</b> <code>{esc(row.get('where_found'))}</code></p>
  <p><b>Path:</b> <code>{esc(row.get('path'))}</code></p>
  <p><b>Eligibility:</b> {esc(row.get('eligibility_check'))}</p>
  <p><b>Evidence detail:</b> {esc(row.get('evidence_detail'))}</p>
  <p><b>Control comparison:</b> {esc(row.get('control_comparison_result'))}</p>
  <p><b>Why this status:</b> {esc(row.get('confirmation_reason'))}</p>
  <p><b>False-positive risk:</b> {esc(row.get('false_positive_risk_notes'))}</p>
  <p><b>Reportability:</b> <code>{esc(row.get('reportability'))}</code></p>
  <p><b>Safe confirmation plan:</b> {esc(row.get('safe_confirmation_plan'))}</p>
</section>"""


def build(target: str) -> dict[str, Any]:
    target = normalize_target(target)
    host = host_from_target(target)
    s = slug(target)
    raw = collect_raw_candidates(target)
    confirmation = confirm_findings(raw, target)
    write_confirmation_reports(s, confirmation)
    rows = confirmation["surface_findings"]
    confirmed_count = confirmation["summary"]["confirmed"]
    review_count = confirmation["summary"]["review_leads"]
    suppressed_count = confirmation["summary"]["noise_suppressed"]
    needs_signal = confirmation["summary"]["needs_more_signal"]

    OUT.mkdir(parents=True, exist_ok=True)
    json_path = OUT / f"{s}-dashboard.json"
    md_path = OUT / f"{s}-dashboard.md"
    html_path = OUT / f"{s}-dashboard.html"
    latest_html = OUT / f"{s}-latest-dashboard.html"

    payload = {
        "target": target,
        "host": host,
        "generated_at": time.time(),
        "methodology": "deduplication -> eligibility gate -> evidence requirement -> confidence tiering -> confirmed/review/noise decision",
        "deduplication": confirmation["deduplication"],
        "summary": {
            "raw_candidates": confirmation["deduplication"]["raw_count"],
            "unique_candidates": confirmation["deduplication"]["unique_count"],
            "total_surface_items": len(rows),
            "confirmed": confirmed_count,
            "review_leads": review_count,
            "noise_suppressed": suppressed_count,
            "needs_more_signal": needs_signal,
            "high_confidence": confirmation["summary"]["high_confidence"],
            "medium_confidence": confirmation["summary"]["medium_confidence"],
            "reporting_rule": "Only CONFIRMED findings with captured comparable evidence should be treated as reportable. REVIEW LEAD items require more safe validation. NOISE is suppressed.",
        },
        "findings": rows,
        "suppressed_noise_report": f"reports/output/final-dashboard/{s}-suppressed-noise.json",
        "confirmation_engine_report": f"reports/output/final-dashboard/{s}-confirmation-engine.json",
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        f"# VulnScope Final Confirmation Dashboard — {host}",
        "",
        f"Target: `{target}`",
        f"Dedup ratio: `{confirmation['deduplication']['dedup_ratio']}`",
        f"Surface items: `{len(rows)}`",
        f"Confirmed: `{confirmed_count}`",
        f"Review leads: `{review_count}`",
        f"Noise suppressed: `{suppressed_count}`",
        f"Needs more signal: `{needs_signal}`",
        "",
        "## Methodology Applied",
        "1. Deduplicate by `(vulnerability_type, url_path_without_query_string)`.",
        "2. Apply class-specific eligibility gates before scoring.",
        "3. Require captured comparable evidence artifacts before surfacing.",
        "4. Surface only MEDIUM/HIGH confidence as REVIEW LEAD/CONFIRMED.",
        "5. Suppress ineligible, duplicate, and low-signal candidates.",
        "",
        "## Findings And Review Leads",
    ]
    lines += finding_markdown(rows)
    lines += [
        "## Suppressed Noise",
        f"Suppressed noise JSON: `reports/output/final-dashboard/{s}-suppressed-noise.json`",
        f"Confirmation engine JSON: `reports/output/final-dashboard/{s}-confirmation-engine.json`",
    ]
    md_path.write_text("\n".join(lines), encoding="utf-8")

    cards = [card(row, i) for i, row in enumerate(rows[:120], 1)]
    if not cards:
        cards.append("<section class='card'><h2>No surfaced findings</h2><p>All candidates were duplicates, ineligible, or lacked sufficient behavioral evidence.</p></section>")
    html_text = f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VulnScope Final Confirmation Dashboard</title><style>body{{margin:0;background:#0b1020;color:#edf3ff;font-family:Arial,sans-serif}}header{{padding:32px;background:#121933;border-bottom:1px solid #2b3765}}main{{padding:26px}}.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:18px}}.metric,.card{{background:#121933;border:1px solid #2b3765;border-radius:18px;padding:18px}}.metric b{{font-size:32px;color:#7aa2ff}}.card{{margin:16px 0}}.chips{{display:flex;gap:8px;flex-wrap:wrap}}.chips span{{border:1px solid #2b3765;border-radius:999px;padding:6px 10px;color:#aab6d3;font-size:12px}}.grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}}.grid div{{background:#172044;border-radius:12px;padding:12px}}p{{color:#aab6d3;line-height:1.55}}code{{color:#d8e4ff;word-break:break-word}}.rule{{background:#172044;border-left:4px solid #7aa2ff;padding:12px 14px;border-radius:12px;color:#d8e4ff}}@media(max-width:1000px){{.stats,.grid{{grid-template-columns:1fr}}}}</style></head><body><header><h1>VulnScope Final Confirmation Dashboard</h1><p>Target: <code>{esc(target)}</code></p><p class="rule">Confirmation engine applied: deduplication → eligibility gate → evidence requirement → confidence tiering → CONFIRMED / REVIEW LEAD / NOISE.</p></header><main><section class="stats"><div class="metric"><b>{confirmation['deduplication']['raw_count']}</b><p>Raw candidates</p></div><div class="metric"><b>{confirmation['deduplication']['unique_count']}</b><p>Unique after dedup</p></div><div class="metric"><b>{confirmed_count}</b><p>Confirmed</p></div><div class="metric"><b>{review_count}</b><p>Review leads</p></div><div class="metric"><b>{suppressed_count}</b><p>Noise suppressed</p></div></section>{''.join(cards)}<section class="card"><h2>Reports</h2><p><code>{esc(s)}-dashboard.md</code></p><p><code>{esc(s)}-confirmation-engine.json</code></p><p><code>{esc(s)}-suppressed-noise.json</code></p></section></main></body></html>"""
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

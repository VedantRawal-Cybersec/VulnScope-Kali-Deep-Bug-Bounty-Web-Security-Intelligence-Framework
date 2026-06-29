#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

OUT = Path("reports/output/mission-verdicts")

MODULE_SOURCES = {
    "Tool Mind": "reports/output/tool-mind/tool-mind.json",
    "Tool Path Repair": "reports/output/tool-path-repair/tool-path-repair.json",
    "AEGIS Public Search": "reports/output/aegis/google-intel/google-intel.json",
    "AEGIS Feedback Planner": "reports/output/aegis/feedback/feedback-plan.json",
    "ARTEMIS Passive Intelligence": "reports/output/artemis/run/artemis-run.json",
    "Comprehensive Category Review": "reports/output/comprehensive-suite/comprehensive-suite.json",
    "Google Context Review": "reports/output/auth/google-context/google-context-review.json",
    "Auth Differential v2": "reports/output/auth/differential-v2/auth-diff-v2.json",
    "API Intelligence": "reports/output/api-intel/api-intel.json",
    "Asset Graph": "reports/output/asset-graph/asset-graph.json",
    "Evidence Cards": "reports/output/evidence-cards/evidence-cards.json",
    "Reportability": "reports/output/reportability/reportability.json",
    "Final Report": "reports/output/report-v2/executive-report-v2.json",
}


def load_json(path: str | Path) -> Any:
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        return {"error": str(exc), "path": str(p)}


def verdict_from_confidence(value: float) -> str:
    if value >= 0.75:
        return "REVIEW_HIGH"
    if value >= 0.45:
        return "REVIEW_MANUAL"
    return "LOW_SIGNAL"


def add(rows: list[dict[str, Any]], module: str, item: str, verdict: str, evidence: str, severity: str = "INFO") -> None:
    rows.append({"module": module, "item": item or "n/a", "verdict": verdict, "severity": severity, "evidence": (evidence or "")[:1200]})


def collect_generic(module: str, data: Any, rows: list[dict[str, Any]]) -> None:
    if data is None:
        add(rows, module, "module-output", "NOT_TESTED", "Output file was not created.", "INFO")
        return
    if isinstance(data, dict) and data.get("error"):
        add(rows, module, "module-output", "ERROR", str(data.get("error")), "LOW")
        return
    if isinstance(data, dict):
        summary = data.get("summary", {})
        add(rows, module, "module-summary", "COMPLETED", json.dumps(summary, ensure_ascii=False), "INFO")


def collect_tool_mind(data: Any, rows: list[dict[str, Any]]) -> None:
    collect_generic("Tool Mind", data, rows)
    if isinstance(data, dict):
        for t in data.get("tools", [])[:120]:
            if isinstance(t, dict):
                verdict = "INSTALLED" if t.get("installed_after") else "OPTIONAL_MISSING"
                add(rows, "Tool Mind", str(t.get("name")), verdict, str(t.get("decision")), "INFO")


def collect_path(data: Any, rows: list[dict[str, Any]]) -> None:
    collect_generic("Tool Path Repair", data, rows)
    if isinstance(data, dict):
        for t in data.get("tools", [])[:120]:
            if isinstance(t, dict):
                verdict = "OK" if t.get("ok") else "OPTIONAL_MISSING" if t.get("optional") else "MISSING_REQUIRED"
                severity = "INFO" if verdict in {"OK", "OPTIONAL_MISSING"} else "MEDIUM"
                add(rows, "Tool Path Repair", str(t.get("binary")), verdict, str(t.get("status")), severity)


def collect_cards(data: Any, rows: list[dict[str, Any]]) -> None:
    collect_generic("Evidence Cards", data, rows)
    if isinstance(data, dict):
        cards = data.get("cards") or data.get("candidates") or []
        for card in cards[:250] if isinstance(cards, list) else []:
            if isinstance(card, dict):
                item = str(card.get("where_found") or card.get("url") or card.get("endpoint") or card.get("title") or "review-item")
                why = str(card.get("why_flagged") or card.get("why_found") or card.get("safe_check") or card.get("category") or "Evidence card")
                add(rows, "Evidence Cards", item, "REVIEW_CANDIDATE", why, str(card.get("severity") or "INFO").upper())


def collect_reportability(data: Any, rows: list[dict[str, Any]]) -> None:
    collect_generic("Reportability", data, rows)
    if isinstance(data, dict):
        candidates = data.get("candidates") or data.get("items") or []
        for item in candidates[:250] if isinstance(candidates, list) else []:
            if isinstance(item, dict):
                score = float(item.get("score") or item.get("reportability_score") or 0)
                verdict = verdict_from_confidence(score if score <= 1 else score / 100)
                where = str(item.get("url") or item.get("endpoint") or item.get("where") or item.get("title") or "candidate")
                evidence = str(item.get("reason") or item.get("why") or item.get("category") or item.get("evidence") or "Ranked review candidate")
                sev = "HIGH" if verdict == "REVIEW_HIGH" else "MEDIUM" if verdict == "REVIEW_MANUAL" else "LOW"
                add(rows, "Reportability", where, verdict, evidence, sev)


def collect_artemis(data: Any, rows: list[dict[str, Any]]) -> None:
    collect_generic("ARTEMIS Passive Intelligence", data, rows)
    if isinstance(data, dict):
        for t in data.get("targets", []) if isinstance(data.get("targets"), list) else []:
            if isinstance(t, dict):
                add(rows, "ARTEMIS Passive Intelligence", str(t.get("target")), str(t.get("report", {}).get("risk", "INFO")), json.dumps(t.get("decision", {}), ensure_ascii=False), "INFO")


def collect_google_pair(data: Any, rows: list[dict[str, Any]]) -> None:
    collect_generic("Two Google Account Precision", data, rows)
    if isinstance(data, dict):
        phases = data.get("phases", [])
        if isinstance(phases, list):
            for p in phases:
                if isinstance(p, dict):
                    ok = bool(p.get("ok"))
                    add(rows, "Two Google Account Precision", str(p.get("label") or p.get("phase") or "phase"), "COMPLETED" if ok else "NOT_TESTED", str(p.get("output_tail") or p.get("reason") or ""), "INFO" if ok else "LOW")


def collect_module_rows(target: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for module, path in MODULE_SOURCES.items():
        data = load_json(path)
        if module == "Tool Mind":
            collect_tool_mind(data, rows)
        elif module == "Tool Path Repair":
            collect_path(data, rows)
        elif module == "Evidence Cards":
            collect_cards(data, rows)
        elif module == "Reportability":
            collect_reportability(data, rows)
        elif module == "ARTEMIS Passive Intelligence":
            collect_artemis(data, rows)
        else:
            collect_generic(module, data, rows)
    collect_google_pair(load_json("reports/output/google-pair/google-pair-run.json"), rows)
    return rows


def severity_summary(rows: list[dict[str, Any]]) -> dict[str, int]:
    out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for row in rows:
        sev = str(row.get("severity") or "INFO").upper()
        out[sev if sev in out else "INFO"] += 1
    return out


def module_summary(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for r in rows:
        m = str(r.get("module") or "Unknown")
        v = str(r.get("verdict") or "UNKNOWN")
        out.setdefault(m, {})[v] = out.setdefault(m, {}).get(v, 0) + 1
    return out


def write_reports(target: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    payload = {"target": target, "summary": {"rows": len(rows), "severity": severity_summary(rows), "modules": module_summary(rows)}, "rows": rows}
    (OUT / "mission-verdicts.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        f"# Mission Verdict Report — {target}",
        "",
        "**FOR AUTHORIZED SECURITY TESTING ONLY – UNLAWFUL USE IS STRICTLY PROHIBITED.**",
        "",
        "## Global Summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for sev, count in payload["summary"]["severity"].items():
        lines.append(f"| {sev} | {count} |")
    lines += ["", "## Per-Module Summary", "", "| Module | Verdict | Count |", "|---|---|---:|"]
    for module, verdicts in payload["summary"]["modules"].items():
        for verdict, count in verdicts.items():
            lines.append(f"| {module} | {verdict} | {count} |")
    lines += ["", "## Verdict Table", "", "| Module | Item Tested | Verdict | Evidence |", "|---|---|---|---|"]
    for r in rows[:1000]:
        lines.append(f"| {r.get('module')} | `{str(r.get('item')).replace('|', '/')[:220]}` | **{r.get('verdict')}** | {str(r.get('evidence')).replace('|', '/')[:500]} |")
    (OUT / "mission-verdicts.md").write_text("\n".join(lines), encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate precise per-module mission verdict report")
    parser.add_argument("--target", default="authorized-target")
    args = parser.parse_args()
    rows = collect_module_rows(args.target)
    result = write_reports(args.target, rows)
    print(json.dumps({"summary": result["summary"], "report": "reports/output/mission-verdicts/mission-verdicts.md"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

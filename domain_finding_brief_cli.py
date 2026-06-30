#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from target_scope_guard import object_in_target_scope, session_target, url_in_target_scope

OUT = Path("reports/output/domain-reports")

SOURCES = {
    "mission_verdicts": Path("reports/output/mission-verdicts/mission-verdicts.json"),
    "evidence_cards": Path("reports/output/evidence-cards/evidence-cards.json"),
    "reportability": Path("reports/output/reportability/reportability.json"),
    "normalized": Path("reports/output/normalized/normalized-evidence.json"),
    "artemis": Path("reports/output/artemis/run/artemis-run.json"),
}

CONFIRM_GUIDE = {
    "xss": "Confirm with harmless canaries first, inspect DOM context, verify output encoding, and only escalate if safe execution evidence is proven under program rules.",
    "rendering": "Confirm whether the reflected value stays as text, attribute, URL, script, or style context. Report only if real impact is proven.",
    "redirect": "Confirm redirects are restricted to an allowlist and that external navigation cannot be forced with safe test values.",
    "cors": "Confirm allowed origins, credential behavior, and whether sensitive responses are reachable cross-origin.",
    "auth": "Confirm with owned test accounts that authorization is enforced server-side for every sensitive object and route.",
    "idor": "Confirm with two owned accounts that object IDs cannot access another account's data.",
    "api": "Confirm the endpoint purpose, authentication requirement, authorization checks, and whether sensitive data is exposed.",
    "file": "Confirm the file is intentionally public and does not expose private data, source maps, secrets, backups, or internal metadata.",
    "header": "Confirm the header is absent on affected pages, then treat it as a hardening gap unless paired with exploitable impact.",
    "cookie": "Confirm cookie flags on live responses and assess whether session cookies are protected with Secure, HttpOnly, and SameSite.",
    "default": "Confirm the finding manually using safe, authorized validation. Do not report as a vulnerability until impact is proven.",
}


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        return {"_error": str(exc), "_path": str(path)}


def normalize_target(raw: str) -> str:
    raw = str(raw or "").strip()
    return raw if "://" in raw else "https://" + raw


def host_from_target(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    host = parsed.hostname or parsed.netloc or target
    return host.split(":")[0].lower().strip()


def domain_slug(target: str) -> str:
    host = host_from_target(target)
    slug = re.sub(r"[^a-z0-9.-]+", "-", host.lower()).strip("-.")
    return slug or "target"


def first_value(item: dict[str, Any], keys: list[str], fallback: str = "n/a") -> str:
    for key in keys:
        value = item.get(key)
        if value not in (None, "", [], {}):
            return str(value)
    return fallback


def classify(text: str) -> str:
    low = text.lower()
    for key in ["xss", "rendering", "redirect", "cors", "auth", "idor", "api", "file", "header", "cookie"]:
        if key in low:
            return key
    return "default"


def short(text: Any, limit: int = 280) -> str:
    value = " ".join(str(text or "").split())
    return value if len(value) <= limit else value[: limit - 3] + "..."


def add_finding(out: list[dict[str, Any]], target: str, item: dict[str, Any]) -> None:
    if not object_in_target_scope(item, target):
        return
    title = first_value(item, ["title", "name", "category", "detector", "module", "verdict"], "Security review lead")
    category = first_value(item, ["category", "detector", "type", "module"], classify(title))
    where = first_value(item, ["where_found", "url", "endpoint", "target", "item"], target)
    evidence = first_value(item, ["why_flagged", "evidence", "reason", "safe_check", "verdict", "decision"], "Observed by scanner output")
    how = first_value(item, ["evidence_source", "source_file", "module", "_source_file"], "VulnScope correlation")
    status = first_value(item, ["reportability_bucket", "status", "verdict"], "manual_validation_needed")
    score = item.get("reportability_score") or item.get("score") or item.get("confidence") or 0
    ckey = classify(" ".join([title, category, where, evidence]))
    out.append({
        "title": short(title, 90),
        "type": short(category, 80),
        "where_found": short(where, 220),
        "how_found": short(how, 160),
        "evidence": short(evidence, 260),
        "how_to_confirm": CONFIRM_GUIDE.get(ckey, CONFIRM_GUIDE["default"]),
        "status": short(status, 80),
        "score": score,
    })


def collect_from_sources(target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    data = {name: load_json(path) for name, path in SOURCES.items()}

    cards = data.get("evidence_cards")
    if isinstance(cards, dict):
        for item in cards.get("cards", [])[:300]:
            if isinstance(item, dict):
                add_finding(findings, target, {**item, "module": "Evidence Cards"})

    reportability = data.get("reportability")
    if isinstance(reportability, dict):
        for item in reportability.get("candidates", [])[:300]:
            if isinstance(item, dict):
                add_finding(findings, target, {**item, "module": "Reportability"})

    verdicts = data.get("mission_verdicts")
    if isinstance(verdicts, dict):
        for item in verdicts.get("rows", [])[:500]:
            if isinstance(item, dict):
                verdict = str(item.get("verdict") or "")
                if verdict.upper() in {"COMPLETED", "OK", "INSTALLED"}:
                    continue
                add_finding(findings, target, item)

    normalized = data.get("normalized")
    if isinstance(normalized, dict):
        for item in normalized.get("endpoints", [])[:300]:
            if isinstance(item, dict) and item.get("risk_tags"):
                add_finding(findings, target, {**item, "title": "Endpoint review lead", "category": ",".join(item.get("risk_tags", [])), "module": "Normalized Evidence"})

    # Deduplicate by type + location + evidence.
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in findings:
        key = (item["type"].lower(), item["where_found"].lower(), item["evidence"].lower()[:100])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)

    def rank(item: dict[str, Any]) -> float:
        raw = item.get("score") or 0
        try:
            score = float(raw)
        except Exception:
            score = 0.0
        status = str(item.get("status") or "").lower()
        if "high" in status:
            score += 0.4
        if "manual" in status or "review" in status:
            score += 0.2
        return score

    unique.sort(key=rank, reverse=True)
    return unique


def write_reports(target: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    slug = domain_slug(target)
    json_path = OUT / f"{slug}-finding-brief.json"
    md_path = OUT / f"{slug}-finding-brief.md"
    payload = {
        "target": target,
        "host": host_from_target(target),
        "generated_at": time.time(),
        "summary": {"findings": len(findings), "shown": min(len(findings), 12)},
        "findings": findings,
        "note": "These are evidence-based review leads, not confirmed vulnerabilities unless impact is proven by safe authorized validation.",
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        f"# Final Finding Brief — {payload['host']}",
        "",
        f"Target: `{target}`",
        f"Findings / leads: `{len(findings)}`",
        "",
        "This brief explains what was found, where it was found, how VulnScope found it, and how to confirm it safely.",
        "",
    ]
    if not findings:
        lines += [
            "## Result",
            "No confirmed vulnerability or strong review lead was generated from the available evidence.",
            "",
            "Next step: review the full reports for hardening observations and rerun with a deeper authorized scope if needed.",
        ]
    else:
        lines.append("## Top Findings")
        for index, item in enumerate(findings[:12], 1):
            lines += [
                f"### {index}. {item['title']}",
                f"- Type: `{item['type']}`",
                f"- Where found: `{item['where_found']}`",
                f"- How found: {item['how_found']}",
                f"- Evidence: {item['evidence']}",
                f"- How to confirm: {item['how_to_confirm']}",
                f"- Status: `{item['status']}`",
                "",
            ]
    lines += [
        "## Files",
        f"- Markdown: `{md_path}`",
        f"- JSON: `{json_path}`",
    ]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    payload["reports"] = {"markdown": str(md_path), "json": str(json_path)}
    return payload


def build_domain_finding_brief(target: str | None = None) -> dict[str, Any]:
    active_target = session_target(target) or normalize_target(target or "authorized-target")
    findings = collect_from_sources(active_target)
    return write_reports(active_target, findings)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate short per-domain final finding brief")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    result = build_domain_finding_brief(args.target)
    print(json.dumps({"summary": result["summary"], "report": result["reports"]["markdown"], "json": result["reports"]["json"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

OUT = Path("reports/output/reportability")
SOURCE = Path("reports/output/normalized/normalized-evidence.json")

SENSITIVE_TAGS = {"object_reference", "api_surface", "file_surface", "redirect_surface", "rendering_surface"}


def load() -> dict[str, Any]:
    if not SOURCE.exists():
        return {}
    try:
        return json.loads(SOURCE.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}


def score_item(item: dict[str, Any]) -> dict[str, Any]:
    score = 0.20
    reasons = []
    cat = str(item.get("category") or item.get("detector") or "").lower()
    url = str(item.get("url") or item.get("endpoint") or item.get("target") or "")
    if cat:
        score += 0.15; reasons.append("has_category")
    if url.startswith(("http://", "https://")):
        score += 0.15; reasons.append("has_affected_url")
    if any(x in cat for x in ["idor", "bola", "sqli", "ssrf", "graphql", "jwt", "auth"]):
        score += 0.15; reasons.append("high_impact_category")
    if any(x in url.lower() for x in ["api", "account", "order", "invoice", "payment", "admin", "user"]):
        score += 0.15; reasons.append("sensitive_asset_hint")
    if item.get("evidence") or item.get("source_file"):
        score += 0.10; reasons.append("has_evidence_reference")
    score = min(score, 0.95)
    bucket = "high_reportability" if score >= 0.70 else "needs_manual_validation" if score >= 0.45 else "weak_signal"
    return {**item, "reportability_score": round(score, 2), "reportability_bucket": bucket, "reportability_reasons": reasons}


def build_reportability(target: str | None = None) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    data = load()
    candidates = data.get("candidates", []) if isinstance(data, dict) else []
    scored = [score_item(c) for c in candidates if isinstance(c, dict)]
    scored.sort(key=lambda x: x.get("reportability_score", 0), reverse=True)
    payload = {"target": target or data.get("target") or "authorized-target", "generated_at": time.time(), "summary": {"candidates": len(scored), "high": len([x for x in scored if x.get("reportability_bucket") == "high_reportability"]), "manual": len([x for x in scored if x.get("reportability_bucket") == "needs_manual_validation"]), "weak": len([x for x in scored if x.get("reportability_bucket") == "weak_signal"])}, "candidates": scored}
    (OUT / "reportability.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"# VulnScope Reportability — {payload['target']}", "", f"Candidates: `{len(scored)}`", f"High: `{payload['summary']['high']}`", f"Manual: `{payload['summary']['manual']}`", f"Weak: `{payload['summary']['weak']}`", "", "## Ranked Candidates"]
    for item in scored[:100]:
        lines += [f"### {item.get('title') or item.get('category') or 'Candidate'}", f"- Score: `{item.get('reportability_score')}`", f"- Bucket: `{item.get('reportability_bucket')}`", f"- URL: `{item.get('url') or item.get('endpoint') or item.get('target') or 'n/a'}`", f"- Reasons: `{', '.join(item.get('reportability_reasons', []))}`", ""]
    (OUT / "reportability.md").write_text("\n".join(lines), encoding="utf-8")
    return payload

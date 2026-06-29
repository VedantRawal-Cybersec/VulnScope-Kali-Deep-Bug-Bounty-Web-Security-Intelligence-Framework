from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

OUT = Path("reports/output/artemis/predictions")

IDOR_WORDS = {"user", "account", "profile", "order", "invoice", "transaction", "tenant", "org", "team", "file", "document"}
XSS_WORDS = {"q", "query", "search", "comment", "message", "callback", "jsonp", "redirect", "return", "next"}
API_WORDS = {"api", "graphql", "v1", "v2", "swagger", "openapi"}
INFRA_WORDS = {"admin", "debug", "backup", "old", "staging", "dev", "test"}


def score_url(url: str) -> list[dict[str, Any]]:
    parsed = urlparse(url)
    low = (parsed.path + "?" + parsed.query).lower()
    params = {k.lower() for k, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    predictions = []

    idor_signal = sum(1 for w in IDOR_WORDS if w in low) + sum(1 for p in params if p in {"id", "uid", "user_id", "account_id", "order_id", "invoice_id"})
    if idor_signal:
        predictions.append({
            "type": "IDOR_BOLA_PREDICTION",
            "confidence": min(0.95, 0.45 + idor_signal * 0.12),
            "where": url,
            "reason": "URL/parameter structure contains object or tenant reference indicators.",
            "safe_next_step": "Use two owned test accounts and compare authorization boundaries without changing state.",
        })

    xss_signal = sum(1 for w in XSS_WORDS if w in low or w in params)
    if xss_signal:
        predictions.append({
            "type": "XSS_SURFACE_PREDICTION",
            "confidence": min(0.90, 0.35 + xss_signal * 0.10),
            "where": url,
            "reason": "URL contains rendering, callback, search, or redirect-like input surfaces.",
            "safe_next_step": "Review source-to-sink flow and encoding context; avoid destructive payload execution.",
        })

    api_signal = sum(1 for w in API_WORDS if w in low)
    if api_signal:
        predictions.append({
            "type": "API_AUTH_PREDICTION",
            "confidence": min(0.92, 0.40 + api_signal * 0.10),
            "where": url,
            "reason": "API or schema surface detected from passive URL evidence.",
            "safe_next_step": "Map API routes and review authentication, authorization, rate limits, and object access controls.",
        })

    infra_signal = sum(1 for w in INFRA_WORDS if w in low)
    if infra_signal:
        predictions.append({
            "type": "INFRA_EXPOSURE_PREDICTION",
            "confidence": min(0.88, 0.38 + infra_signal * 0.10),
            "where": url,
            "reason": "Environment, admin, backup, or debug naming pattern observed in public evidence.",
            "safe_next_step": "Verify whether this is expected public exposure and review access control/remediation.",
        })
    return predictions


def predict_from_intel(intel: dict[str, Any]) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    target = str(intel.get("target") or intel.get("domain") or "authorized-target")
    urls = list(intel.get("wayback_urls") or [])
    google_candidates = []
    gi = intel.get("google_intel") or {}
    if isinstance(gi, dict):
        google_candidates = gi.get("candidates") or []
    predictions = []
    for url in urls[:1000]:
        predictions.extend(score_url(str(url)))
    for item in google_candidates:
        if isinstance(item, dict) and item.get("url"):
            predictions.append({
                "type": "PUBLIC_INTEL_REVIEW",
                "confidence": 0.55 + min(0.25, 0.05 * len(item.get("tags", []))),
                "where": item.get("url"),
                "reason": "Public search identified a potentially sensitive indexed reference.",
                "safe_next_step": "Review the public reference; do not retrieve or publish secret values.",
                "tags": item.get("tags", []),
            })
    # Deduplicate while keeping highest confidence.
    best: dict[tuple[str, str], dict[str, Any]] = {}
    for pred in predictions:
        key = (str(pred.get("type")), str(pred.get("where")))
        if key not in best or float(pred.get("confidence", 0)) > float(best[key].get("confidence", 0)):
            best[key] = pred
    ranked = sorted(best.values(), key=lambda x: float(x.get("confidence", 0)), reverse=True)
    payload = {
        "target": target,
        "generated_at": time.time(),
        "mode": "passive_prediction",
        "summary": {"predictions": len(ranked), "high_confidence": len([p for p in ranked if float(p.get("confidence", 0)) >= 0.75])},
        "predictions": ranked,
    }
    safe_name = str(intel.get("domain") or "target").replace("/", "_")
    (OUT / f"{safe_name}-predictions.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"# ARTEMIS Predictions — {target}", "", f"Predictions: `{len(ranked)}`", f"High confidence: `{payload['summary']['high_confidence']}`", "", "## Ranked Predictions"]
    for p in ranked[:100]:
        lines += [f"### {p.get('type')}", f"- Confidence: `{round(float(p.get('confidence', 0)), 2)}`", f"- Where: `{p.get('where')}`", f"- Why: {p.get('reason')}", f"- Next: {p.get('safe_next_step')}", ""]
    (OUT / f"{safe_name}-predictions.md").write_text("\n".join(lines), encoding="utf-8")
    return payload

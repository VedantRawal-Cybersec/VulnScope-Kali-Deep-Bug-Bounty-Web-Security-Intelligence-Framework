from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from artemis.knowledge import strategy_weights

OUT = Path("reports/output/artemis/reports")


def generate_report(target: str, intel: dict[str, Any], predictions: dict[str, Any]) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    preds = predictions.get("predictions", []) if isinstance(predictions, dict) else []
    high = [p for p in preds if float(p.get("confidence", 0)) >= 0.75]
    risk_score = round(sum(float(p.get("confidence", 0)) for p in preds[:20]) / max(1, min(20, len(preds))) * 100, 1) if preds else 0.0
    if risk_score >= 80:
        risk = "HIGH"
    elif risk_score >= 55:
        risk = "MEDIUM"
    elif risk_score > 0:
        risk = "LOW"
    else:
        risk = "INFO"
    payload = {
        "target": target,
        "generated_at": time.time(),
        "mode": "passive_autonomous_report",
        "summary": {
            "risk": risk,
            "risk_score": risk_score,
            "hosts": intel.get("summary", {}).get("hosts", 0),
            "urls": intel.get("summary", {}).get("wayback_urls", 0),
            "predictions": len(preds),
            "high_confidence": len(high),
        },
        "strategy_weights": strategy_weights(),
        "top_predictions": preds[:50],
        "remediation_themes": remediation_themes(preds),
    }
    safe = target.replace("://", "_").replace("/", "_").replace(":", "_")
    (OUT / f"{safe}-artemis-report.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        f"# ARTEMIS Autonomous Passive Report — {target}",
        "",
        "**FOR AUTHORIZED SECURITY TESTING ONLY – UNLAWFUL USE IS STRICTLY PROHIBITED.**",
        "",
        f"Overall risk: `{risk}` (`{risk_score}`)",
        f"Hosts: `{payload['summary']['hosts']}`",
        f"Archived URLs: `{payload['summary']['urls']}`",
        f"Predictions: `{len(preds)}`",
        f"High confidence: `{len(high)}`",
        "",
        "## Top Predictions",
    ]
    for item in preds[:25]:
        lines += [
            f"### {item.get('type')}",
            f"- Confidence: `{round(float(item.get('confidence', 0)), 2)}`",
            f"- Where: `{item.get('where')}`",
            f"- Why: {item.get('reason')}",
            f"- Safe next step: {item.get('safe_next_step')}",
            "",
        ]
    lines += ["## Strategy Weights"]
    for k, v in payload["strategy_weights"].items():
        lines.append(f"- `{k}`: `{v}`")
    lines += ["", "## Remediation Themes"]
    for theme in payload["remediation_themes"]:
        lines.append(f"- {theme}")
    (OUT / f"{safe}-artemis-report.md").write_text("\n".join(lines), encoding="utf-8")
    return payload


def remediation_themes(preds: list[dict[str, Any]]) -> list[str]:
    themes = set()
    for p in preds:
        ptype = str(p.get("type", "")).lower()
        if "idor" in ptype or "bola" in ptype:
            themes.add("Enforce object-level authorization on every user/object/tenant route.")
        if "xss" in ptype:
            themes.add("Apply context-aware output encoding and review client-side source-to-sink flows.")
        if "api" in ptype:
            themes.add("Harden API authentication, authorization, schema exposure, and rate limits.")
        if "infra" in ptype:
            themes.add("Review exposed admin/dev/staging/backup surfaces and remove public access where unnecessary.")
        if "public" in ptype:
            themes.add("Review indexed public references and remove sensitive/deprecated public exposure.")
    return sorted(themes) or ["No high-confidence remediation theme yet. Continue passive collection and manual review."]

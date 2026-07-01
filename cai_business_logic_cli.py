#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from typing import Any

from cai_error_handler import handled_error, write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target

FLOW_WORDS = {
    "checkout": "commerce-flow",
    "cart": "commerce-flow",
    "coupon": "discount-flow",
    "subscription": "subscription-flow",
    "upgrade": "subscription-flow",
    "billing": "billing-flow",
    "invoice": "billing-flow",
    "order": "order-flow",
    "profile": "account-flow",
    "settings": "account-flow",
}


def _load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        return handled_error(component="business_logic", action="load_" + path.name, error=exc, fallback_used="empty_source")


def build_business_review(target: str) -> dict[str, Any]:
    target = normalize_target(target)
    out_dir = cai_output_dir(target)
    inventory = _load(out_dir / "input-inventory.json")
    reviews = []
    if isinstance(inventory, dict):
        for endpoint in inventory.get("endpoints", []) or []:
            text = json.dumps(endpoint, ensure_ascii=False).lower()
            matched = sorted({label for key, label in FLOW_WORDS.items() if key in text})
            if not matched:
                continue
            reviews.append({
                "endpoint": endpoint.get("url"),
                "path_template": endpoint.get("path_template"),
                "workflow_tags": matched,
                "input_count": endpoint.get("input_count", 0),
                "safe_review_focus": [
                    "sequence completeness",
                    "authorization state consistency",
                    "price or quantity display consistency",
                    "server-side validation evidence",
                ],
                "status": "manual_authorized_review_required",
                "safety": "No automatic race, purchase, update, or state-changing test is executed.",
            })
    return {
        "target": target,
        "generated_at": time.time(),
        "feature": "Business Workflow Review",
        "summary": {"workflow_candidates": len(reviews)},
        "workflow_candidates": reviews,
        "safety": {"new_requests_sent": False, "state_change": False, "notes": "Business workflow review is a planner only and does not modify data."},
    }


def write_business_review_reports(target: str, payload: dict[str, Any]) -> dict[str, Any]:
    out_dir = cai_output_dir(target)
    write_json(out_dir / "business-workflow-review.json", payload)
    checkpoint = {"checkpoint": "advanced-business-logic", "name": "Business Workflow Review", "status": "completed", "target": target, "summary": payload.get("summary", {}), "reports": {"json": str(out_dir / "business-workflow-review.json"), "markdown": str(out_dir / "business-workflow-review.md")}, "generated_at": time.time()}
    write_json(out_dir / "checkpoint-business-workflow.json", checkpoint)
    lines = ["# CAI Advanced Feature — Business Workflow Review", "", f"Target: `{target}`", f"Workflow candidates: `{payload.get('summary', {}).get('workflow_candidates', 0)}`", "", "## Candidates"]
    for row in payload.get("workflow_candidates", [])[:100]:
        lines.append(f"- tags=`{', '.join(row.get('workflow_tags', []))}` endpoint=`{row.get('endpoint')}` status=`{row.get('status')}`")
    write_markdown(out_dir / "business-workflow-review.md", lines)
    return checkpoint


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI business workflow review")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    payload = build_business_review(args.target)
    print(json.dumps(write_business_review_reports(args.target, payload), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

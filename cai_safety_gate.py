#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from cai_error_handler import write_json, write_log
from cai_scope_guard import is_allowed_host, host_from_target, normalize_target

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
HIGH_RISK_TOPICS = {"remote-resource-reference-review", "business-workflow-review", "state-and-mode-review"}


def evaluate_action(
    *,
    target: str,
    candidate_url: str,
    method: str = "GET",
    topic: str = "general-review",
    include_subdomains: bool = False,
    user_approved: bool = False,
) -> dict[str, Any]:
    target = normalize_target(target)
    root = host_from_target(target)
    method = method.upper().strip()
    in_scope = is_allowed_host(candidate_url, root, include_subdomains=include_subdomains)
    safe_method = method in SAFE_METHODS
    high_risk = topic in HIGH_RISK_TOPICS
    allowed = bool(in_scope and safe_method and (not high_risk or user_approved))
    reason = []
    if not in_scope:
        reason.append("candidate outside explicit target scope")
    if not safe_method:
        reason.append("method is not read-only")
    if high_risk and not user_approved:
        reason.append("manual approval required for this review topic")
    if not reason:
        reason.append("allowed under zero-impact policy")
    return {
        "target": target,
        "candidate_url": candidate_url,
        "method": method,
        "topic": topic,
        "in_scope": in_scope,
        "safe_method": safe_method,
        "high_risk_topic": high_risk,
        "user_approved": user_approved,
        "allowed": allowed,
        "reason": "; ".join(reason),
        "generated_at": time.time(),
    }


def write_safety_decision(path: Path, payload: dict[str, Any]) -> None:
    write_json(path, payload)
    write_log(f"safety_gate allowed={payload.get('allowed')} reason={payload.get('reason')}")


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="CAI central safety gate")
    parser.add_argument("--target", required=True)
    parser.add_argument("--candidate-url", required=True)
    parser.add_argument("--method", default="GET")
    parser.add_argument("--topic", default="general-review")
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--approved", action="store_true")
    parser.add_argument("--output", default="reports/output/cai-superior/safety-decision.json")
    args = parser.parse_args()
    payload = evaluate_action(target=args.target, candidate_url=args.candidate_url, method=args.method, topic=args.topic, include_subdomains=args.include_subdomains, user_approved=args.approved)
    write_safety_decision(Path(args.output), payload)
    print(json.dumps(payload, indent=2))
    return 0 if payload.get("allowed") else 2


if __name__ == "__main__":
    raise SystemExit(main())

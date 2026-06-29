#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path
from urllib.parse import urlparse

SESSION_SCOPE = Path("scope_policy.session.yaml")
SESSION_AUDIT = Path("reports/output/authorization/target-session-confirmation.json")
CURRENT_TARGET = Path("reports/output/current-target-session.json")

TARGET_OUTPUT_DIRS = [
    "reports/output/mission-preflight",
    "reports/output/domain-recon",
    "reports/output/aegis-public-search",
    "reports/output/aegis-feedback",
    "reports/output/artemis",
    "reports/output/proxy-passive",
    "reports/output/google-pair",
    "reports/output/google-context",
    "reports/output/safe-loop-v2",
    "reports/output/comprehensive-suite",
    "reports/output/vulnscope-modes",
    "reports/output/normalized",
    "reports/output/asset-graph",
    "reports/output/api-intel",
    "reports/output/auth-diff-v2",
    "reports/output/target-history",
    "reports/output/evidence-cards",
    "reports/output/reportability",
    "reports/output/mission-verdicts",
    "reports/output/report-v2",
    "reports/output/vulnscope-main",
    "reports/output/canary-review-matrix",
    "reports/output/precision-assurance",
    "reports/output/autonomous-live",
]


def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("Target cannot be empty")
    return raw if "://" in raw else "https://" + raw


def host_from_target(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    host = parsed.hostname or parsed.netloc or ""
    host = host.split(":")[0].lower().strip()
    if not host:
        raise ValueError("Invalid target URL/domain")
    return host


def build_allowed_hosts(target: str, include_subdomains: bool) -> list[str]:
    host = host_from_target(target)
    allowed = [host]
    if include_subdomains and host != "localhost" and not host.replace(".", "").isdigit():
        allowed.append("*." + host)
    return allowed


def write_scope(target: str, include_subdomains: bool) -> Path:
    allowed = build_allowed_hosts(target, include_subdomains)
    SESSION_SCOPE.write_text("\n".join([
        "name: vulnscope-target-session",
        "allowed_hosts:",
        *["  - '" + item + "'" for item in allowed],
        "blocked_hosts: []",
        "allowed_schemes:",
        "  - https",
        "  - http",
        "max_requests_per_minute: 30",
        "active_testing_allowed: false",
        "authenticated_testing_allowed: true",
        "notes: 'Generated for the current user-entered target after explicit ownership/authorization confirmation.'",
        "",
    ]), encoding="utf-8")
    return SESSION_SCOPE


def clean_outputs() -> list[str]:
    removed: list[str] = []
    for raw in TARGET_OUTPUT_DIRS:
        path = Path(raw)
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
            removed.append(str(path))
    return removed


def create_session(target: str, include_subdomains: bool, confirmed: bool = True) -> dict:
    target = normalize_target(target)
    host = host_from_target(target)
    allowed = build_allowed_hosts(target, include_subdomains)
    removed = clean_outputs()
    scope = write_scope(target, include_subdomains)
    payload = {
        "target": target,
        "host": host,
        "allowed_hosts": allowed,
        "include_subdomains": include_subdomains,
        "confirmed_authorization": bool(confirmed),
        "scope_policy": str(scope),
        "removed_output_dirs": removed,
        "created_at": time.time(),
    }
    CURRENT_TARGET.parent.mkdir(parents=True, exist_ok=True)
    SESSION_AUDIT.parent.mkdir(parents=True, exist_ok=True)
    CURRENT_TARGET.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    SESSION_AUDIT.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a fresh VulnScope target session for the user-entered URL")
    parser.add_argument("--target", required=True)
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args()
    if not args.yes:
        answer = input("Type YES to confirm you own/have authorization for this target: ").strip()
        if answer != "YES":
            print(json.dumps({"created": False, "reason": "authorization not confirmed"}, indent=2))
            return 1
    payload = create_session(args.target, args.include_subdomains, confirmed=True)
    print(json.dumps({"created": True, "target": payload["target"], "allowed_hosts": payload["allowed_hosts"], "scope_policy": payload["scope_policy"], "removed_dirs": len(payload["removed_output_dirs"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import socket
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from scope.policy import load_scope_policy

OUT = Path("reports/output/mission-preflight")
CURRENT_TARGET = Path("reports/output/current-target.json")

STALE_DIRS = [
    "reports/output/recon",
    "reports/output/normalized",
    "reports/output/asset-graph",
    "reports/output/api-intel",
    "reports/output/comprehensive-suite",
    "reports/output/category-suite",
    "reports/output/evidence-cards",
    "reports/output/reportability",
    "reports/output/report-v2",
    "reports/output/modes",
    "reports/output/google-pair",
    "reports/output/aegis/feedback",
    "reports/output/aegis/google-intel",
    "reports/output/artemis/recon",
    "reports/output/artemis/predictions",
    "reports/output/artemis/reports",
    "reports/output/artemis/run",
    "reports/output/artemis/burp-safe",
]

STALE_FILES = [
    "reports/output/auth/auth-crawl-account_a.json",
    "reports/output/auth/auth-crawl-account_b.json",
    "reports/output/auth/account-comparison.json",
    "reports/output/auth/account-comparison.md",
    "reports/output/auth/google-context/google-context-review.json",
    "reports/output/auth/google-context/google-context-review.md",
    "reports/output/auth/differential-v2/auth-diff-v2.json",
    "reports/output/auth/differential-v2/auth-diff-v2.md",
]


def normalize_target(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("target cannot be empty")
    return raw if "://" in raw else "https://" + raw


def host_from_target(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    return parsed.netloc.split(":")[0].strip().lower()


def dns_ips(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
        return sorted({item[4][0] for item in infos})
    except Exception:
        return []


def collapse_repeated_runs(host: str) -> str:
    out = []
    last = ""
    count = 0
    for ch in host:
        if ch == last:
            count += 1
        else:
            last = ch
            count = 1
        if count <= 2:
            out.append(ch)
    return "".join(out)


def suggestions_for(host: str) -> list[dict[str, Any]]:
    candidates = []
    collapsed = collapse_repeated_runs(host)
    if collapsed != host:
        candidates.append(collapsed)
    if not host.startswith("www."):
        candidates.append("www." + host)
    seen = []
    rows = []
    for item in candidates:
        if item in seen:
            continue
        seen.append(item)
        rows.append({"host": item, "ips": dns_ips(item)})
    return rows


def clean_stale_outputs() -> dict[str, Any]:
    removed = []
    for path in STALE_DIRS:
        p = Path(path)
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)
            removed.append(path)
    for path in STALE_FILES:
        p = Path(path)
        if p.exists():
            try:
                p.unlink()
                removed.append(path)
            except Exception:
                pass
    return {"removed": removed, "count": len(removed)}


def hush_kali_banner() -> bool:
    try:
        (Path.home() / ".hushlogin").touch(exist_ok=True)
        return True
    except Exception:
        return False


def run_preflight(target: str, scope_policy: str, clean_stale: bool = True, allow_unresolved: bool = False) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    target = normalize_target(target)
    host = host_from_target(target)
    policy_decision = load_scope_policy(scope_policy).check(target)
    ips = dns_ips(host)
    suggestions = [] if ips else suggestions_for(host)
    cleanup = clean_stale_outputs() if clean_stale else {"removed": [], "count": 0}
    hush = hush_kali_banner()
    ok = bool(policy_decision.allowed and (ips or allow_unresolved))
    reason = "ok"
    if not policy_decision.allowed:
        reason = f"scope_blocked: {policy_decision.reason}"
    elif not ips and not allow_unresolved:
        good = [s for s in suggestions if s.get("ips")]
        reason = "target_dns_unresolved"
        if good:
            reason += "; possible typo: " + ", ".join(s["host"] for s in good[:3])
    payload = {
        "target": target,
        "host": host,
        "scope_policy": scope_policy,
        "allowed": bool(policy_decision.allowed),
        "policy_reason": policy_decision.reason,
        "dns_ips": ips,
        "dns_ok": bool(ips),
        "suggestions": suggestions,
        "clean_stale": clean_stale,
        "cleanup": cleanup,
        "hush_kali_banner": hush,
        "ok": ok,
        "reason": reason,
        "generated_at": time.time(),
    }
    CURRENT_TARGET.parent.mkdir(parents=True, exist_ok=True)
    CURRENT_TARGET.write_text(json.dumps({"target": target, "host": host, "started_at": time.time()}, indent=2), encoding="utf-8")
    (OUT / "preflight.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "# VulnScope Mission Preflight",
        "",
        f"Target: `{target}`",
        f"Host: `{host}`",
        f"Scope allowed: `{payload['allowed']}`",
        f"DNS OK: `{payload['dns_ok']}`",
        f"Status: `{payload['reason']}`",
        f"Cleaned stale outputs: `{cleanup['count']}`",
        f"Kali banner hushlogin: `{hush}`",
        "",
    ]
    if suggestions:
        lines.append("## DNS suggestions")
        for s in suggestions:
            lines.append(f"- `{s['host']}` ips=`{s.get('ips')}`")
    if cleanup.get("removed"):
        lines += ["", "## Removed stale outputs"]
        for item in cleanup["removed"]:
            lines.append(f"- `{item}`")
    (OUT / "preflight.md").write_text("\n".join(lines), encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate target/scope and clean stale outputs before a unified mission")
    parser.add_argument("--target", required=True)
    parser.add_argument("--scope-policy", default="scope_policy.session.yaml")
    parser.add_argument("--no-clean", action="store_true")
    parser.add_argument("--allow-unresolved", action="store_true")
    args = parser.parse_args()
    result = run_preflight(args.target, args.scope_policy, clean_stale=not args.no_clean, allow_unresolved=args.allow_unresolved)
    print(json.dumps({"ok": result["ok"], "reason": result["reason"], "dns_ips": result["dns_ips"], "suggestions": result["suggestions"], "report": "reports/output/mission-preflight/preflight.md"}, indent=2, ensure_ascii=False))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

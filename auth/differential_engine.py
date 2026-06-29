from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

OUT = Path("reports/output/auth/differential-v2")
A = Path("reports/output/auth/auth-crawl-account_a.json")
B = Path("reports/output/auth/auth-crawl-account_b.json")
COMPARE = Path("reports/output/auth/account-comparison.json")


def load(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def urls(data: Any) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    def walk(v: Any):
        if isinstance(v, dict):
            u = v.get("url") or v.get("endpoint")
            if isinstance(u, str):
                out[u] = v
            for item in v.values():
                walk(item)
        elif isinstance(v, list):
            for item in v:
                walk(item)
    walk(data)
    return out


def build_auth_diff_v2() -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    a = urls(load(A))
    b = urls(load(B))
    shared = sorted(set(a) & set(b))
    only_a = sorted(set(a) - set(b))
    only_b = sorted(set(b) - set(a))
    candidates = []
    for u in shared:
        low = u.lower()
        tags = []
        if any(x in low for x in ["id=", "user", "account", "order", "invoice", "tenant", "org"]):
            tags.append("object_reference_shared_between_accounts")
        if any(x in low for x in ["edit", "delete", "update", "transfer", "admin"]):
            tags.append("sensitive_route_shared_between_accounts")
        if tags:
            candidates.append({"url": u, "category": "idor_bola", "tags": tags, "status": "manual_validation_required", "safe_check": "Use owned Account A and Account B only; verify server-side object authorization without changing state."})
    payload = {"generated_at": time.time(), "summary": {"account_a_urls": len(a), "account_b_urls": len(b), "shared": len(shared), "only_a": len(only_a), "only_b": len(only_b), "candidates": len(candidates)}, "only_a": only_a[:500], "only_b": only_b[:500], "shared": shared[:500], "candidates": candidates, "legacy_compare_loaded": COMPARE.exists()}
    (OUT / "auth-diff-v2.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = ["# VulnScope Account A/B Differential v2", "", f"Shared URLs: `{len(shared)}`", f"Only Account A: `{len(only_a)}`", f"Only Account B: `{len(only_b)}`", f"Candidates: `{len(candidates)}`", "", "## Candidates"]
    for c in candidates[:100]:
        lines += [f"- `{c['url']}` tags=`{','.join(c['tags'])}`", f"  - Safe check: {c['safe_check']}"]
    if not candidates:
        lines.append("No A/B differential candidates found. Run auth crawl for both owned accounts first.")
    (OUT / "auth-diff-v2.md").write_text("\n".join(lines), encoding="utf-8")
    return payload

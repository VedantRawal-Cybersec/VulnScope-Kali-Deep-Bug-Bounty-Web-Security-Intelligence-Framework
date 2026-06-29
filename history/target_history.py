from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from normalizers.evidence import normalize_all

BASE = Path("reports/output/history")


def safe_name(target: str) -> str:
    return hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]


def save_history(target: str) -> dict[str, Any]:
    BASE.mkdir(parents=True, exist_ok=True)
    current = normalize_all(target)
    target_dir = BASE / safe_name(target)
    target_dir.mkdir(parents=True, exist_ok=True)
    latest = target_dir / "latest.json"
    previous = json.loads(latest.read_text(encoding="utf-8")) if latest.exists() else None
    latest.write_text(json.dumps(current, indent=2, ensure_ascii=False), encoding="utf-8")
    diff = build_diff(previous, current)
    payload = {"target": target, "generated_at": time.time(), "history_dir": str(target_dir), "diff": diff}
    (target_dir / "diff.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"# VulnScope Target History — {target}", "", f"New endpoints: `{len(diff['new_endpoints'])}`", f"Removed endpoints: `{len(diff['removed_endpoints'])}`", f"New parameters: `{len(diff['new_parameters'])}`", f"New candidates: `{len(diff['new_candidates'])}`", "", "## New Endpoints"]
    for item in diff["new_endpoints"][:100]:
        lines.append(f"- `{item}`")
    (target_dir / "diff.md").write_text("\n".join(lines), encoding="utf-8")
    (BASE / "last-run.md").write_text("\n".join(lines), encoding="utf-8")
    return payload


def build_diff(previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, list[str]]:
    if not previous:
        return {
            "new_endpoints": [e.get("url") for e in current.get("endpoints", []) if e.get("url")],
            "removed_endpoints": [],
            "new_parameters": current.get("parameters", []),
            "new_candidates": [str(c.get("title") or c.get("category") or c.get("detector") or "candidate") for c in current.get("candidates", [])],
        }
    old_urls = {e.get("url") for e in previous.get("endpoints", []) if e.get("url")}
    new_urls = {e.get("url") for e in current.get("endpoints", []) if e.get("url")}
    old_params = set(previous.get("parameters", []))
    new_params = set(current.get("parameters", []))
    old_c = {str(c.get("title") or c.get("category") or c.get("detector") or "candidate") for c in previous.get("candidates", [])}
    new_c = {str(c.get("title") or c.get("category") or c.get("detector") or "candidate") for c in current.get("candidates", [])}
    return {
        "new_endpoints": sorted(new_urls - old_urls),
        "removed_endpoints": sorted(old_urls - new_urls),
        "new_parameters": sorted(new_params - old_params),
        "new_candidates": sorted(new_c - old_c),
    }

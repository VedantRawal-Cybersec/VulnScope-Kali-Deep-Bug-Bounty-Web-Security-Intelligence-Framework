#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from kai_safe_interface import main as _kai_main
from target_scope_guard import normalize_target

SESSION = Path("reports/output/kai-interface/direct-session.json")


def _slug(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    host = (parsed.hostname or parsed.netloc or target).split(":")[0].lower().strip()
    return re.sub(r"[^a-z0-9.-]+", "-", host).strip("-.") or "target"


def _target() -> str | None:
    try:
        data = json.loads(SESSION.read_text(encoding="utf-8", errors="ignore"))
        return str(data.get("target") or "") or None
    except Exception:
        return None


def _dashboard() -> None:
    target = _target()
    if not target:
        return
    try:
        from review_dashboard_cli import build
        payload = build(target)
        s = _slug(target)
        print("\n[+] Final review dashboard ready:", flush=True)
        print(f"- reports/output/final-dashboard/{s}-dashboard.html", flush=True)
        print(f"- reports/output/final-dashboard/{s}-dashboard.md", flush=True)
        print(f"- reports/output/final-dashboard/{s}-dashboard.json", flush=True)
        print(json.dumps(payload.get("summary", {}), indent=2), flush=True)
    except Exception as exc:
        out = Path("reports/output/final-dashboard")
        out.mkdir(parents=True, exist_ok=True)
        (out / "dashboard-generation-error.json").write_text(json.dumps({"error": str(exc)}, indent=2), encoding="utf-8")


def main() -> int:
    code = int(_kai_main())
    _dashboard()
    return code


if __name__ == "__main__":
    raise SystemExit(main())

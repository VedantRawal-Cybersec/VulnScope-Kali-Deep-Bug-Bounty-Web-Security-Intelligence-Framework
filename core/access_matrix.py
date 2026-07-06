#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.auth_session import AuthProfile, load_auth_profiles

REVIEW_PATH_HINTS = ["dashboard", "settings", "account", "profile", "api", "internal", "report", "manage"]


class AccessMatrixEngine:
    """GET-only comparison across user-supplied authorized profiles."""

    def __init__(self, *, state: Any, client: Any, dashboard: Any | None = None, auth_profiles_file: str = "", max_urls: int = 80) -> None:
        self.state = state
        self.client = client
        self.dashboard = dashboard
        self.target = getattr(state, "target", "")
        self.out_dir = Path(getattr(state, "out_dir", "reports/output"))
        self.auth_profiles_file = auth_profiles_file
        self.max_urls = max(1, int(max_urls))
        self.profiles: list[AuthProfile] = load_auth_profiles(auth_profiles_file) if auth_profiles_file else []
        self.matrix: list[dict[str, Any]] = []
        self.review_items: list[dict[str, Any]] = []

    def dash(self, action: str, evidence: str = "") -> None:
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(phase="Access Matrix", phase_progress=64, current_agent="AccessMatrixAgent", current_tool="access_matrix", action=action, endpoint=self.target, evidence=evidence[:1000], safety_status="GET-only profile comparison • authorized sessions only • no state change")
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO", action)

    def candidate_urls(self) -> list[str]:
        rows = []
        for url in list(getattr(self.state, "urls", {}).keys()):
            path = (urlparse(url).path or "/").lower()
            score = 1 + sum(2 for hint in REVIEW_PATH_HINTS if hint in path)
            rows.append((score, url))
        rows.sort(key=lambda item: item[0], reverse=True)
        return [url for _, url in rows[: self.max_urls]]

    @staticmethod
    def page_shape(text: str) -> dict[str, Any]:
        text = text or ""
        low = text.lower()
        return {"length": len(text), "has_form": "<form" in low, "has_login_text": "login" in low or "sign in" in low, "has_access_text": "access" in low or "permission" in low}

    def fetch_as(self, profile: AuthProfile, url: str) -> dict[str, Any]:
        old_headers = dict(self.client.session.headers)
        try:
            self.client.session.headers.update(profile.request_headers())
            res = self.client.get(url, purpose="access-matrix", allow_redirects=False)
            return {"profile": profile.name, "role": profile.role, "status_code": res.status_code, "received": res.received, "location": res.headers.get("Location", ""), "shape": self.page_shape(res.text), "error": res.error}
        except Exception as exc:
            return {"profile": profile.name, "role": profile.role, "status_code": 0, "received": False, "location": "", "shape": {}, "error": str(exc)[:300]}
        finally:
            self.client.session.headers.clear()
            self.client.session.headers.update(old_headers)

    def analyze(self, url: str, rows: list[dict[str, Any]]) -> None:
        statuses = {row.get("status_code") for row in rows if row.get("received")}
        lengths = [int((row.get("shape") or {}).get("length", 0) or 0) for row in rows if row.get("received")]
        path = (urlparse(url).path or "/").lower()
        has_review_hint = any(hint in path for hint in REVIEW_PATH_HINTS)
        if len(statuses) > 1:
            self.review_items.append({"title": "Different profile responses", "url": url, "evidence": json.dumps({row['profile']: row.get('status_code') for row in rows}, ensure_ascii=False), "recommendation": "Review whether the observed profile differences match the intended access model."})
        if lengths and max(lengths) - min(lengths) > 2000 and has_review_hint:
            self.review_items.append({"title": "Large content difference between profiles", "url": url, "evidence": f"response length range={min(lengths)}..{max(lengths)}", "recommendation": "Review whether the content difference is expected for these profiles."})

    def run(self) -> dict[str, Any]:
        if len(self.profiles) < 2:
            reports = self.write_reports(skipped=True, reason="Need at least two supplied auth profiles for comparison.")
            return {"ok": True, "skipped": True, "reason": "Need at least two supplied auth profiles for comparison.", "reports": reports}
        self.dash("Starting profile comparison")
        for url in self.candidate_urls():
            rows = [self.fetch_as(profile, url) for profile in self.profiles]
            self.matrix.append({"url": url, "profiles": rows})
            self.analyze(url, rows)
        reports = self.write_reports(skipped=False)
        try:
            self.state.stats["access_profiles"] = len(self.profiles)
            self.state.stats["access_matrix_urls"] = len(self.matrix)
            self.state.stats["access_review_items"] = len(self.review_items)
            self.state.save()
        except Exception:
            pass
        return {"ok": True, "profiles": len(self.profiles), "urls_checked": len(self.matrix), "review_items": len(self.review_items), "reports": reports}

    def write_reports(self, *, skipped: bool, reason: str = "") -> dict[str, str]:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        payload = {"target": self.target, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "skipped": skipped, "reason": reason, "profiles": [p.masked() for p in self.profiles], "matrix": self.matrix, "review_items": self.review_items, "rules": "GET-only comparison using user-supplied authorized profiles."}
        json_path = self.out_dir / "access-matrix.json"
        md_path = self.out_dir / "access-matrix.md"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        lines = ["# Access Matrix", "", f"Target: `{self.target}`", f"Skipped: `{skipped}`", "", "## Profiles", ""]
        if reason:
            lines.append("Reason: " + reason)
        for profile in payload["profiles"]:
            lines.append(f"- `{profile['name']}` role=`{profile['role']}` cookie=`{profile.get('cookie')}` token=`{profile.get('bearer_token')}`")
        lines.extend(["", "## Review Items", ""])
        if not self.review_items:
            lines.append("No access comparison review items were generated.")
        else:
            for item in self.review_items[:100]:
                lines.append(f"- **{item['title']}** url=`{item['url']}` evidence={item['evidence']}")
        lines.extend(["", "## Matrix Summary", ""])
        for item in self.matrix[:100]:
            statuses = ", ".join(f"{row['profile']}={row.get('status_code')}" for row in item.get("profiles", []))
            lines.append(f"- `{item['url']}` → {statuses}")
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return {"access_matrix_json": str(json_path), "access_matrix_md": str(md_path)}

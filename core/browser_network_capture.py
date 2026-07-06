#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.auth_session import load_auth_profiles


class BrowserNetworkCapture:
    """Optional Playwright network capture for authorized sessions.

    This module records navigation URLs and browser-observed network endpoints. It
    does not submit forms, brute force, or mutate state. If Playwright is missing,
    it writes a skipped report with the exact reason.
    """

    def __init__(self, *, state: Any, dashboard: Any | None = None, auth_profiles_file: str = "", max_pages: int = 40, max_events: int = 500) -> None:
        self.state = state
        self.dashboard = dashboard
        self.target = getattr(state, "target", "")
        self.host = getattr(state, "host", urlparse(self.target).hostname or "")
        self.out_dir = Path(getattr(state, "out_dir", "reports/output"))
        self.auth_profiles_file = auth_profiles_file
        self.profiles = load_auth_profiles(auth_profiles_file) if auth_profiles_file else []
        self.max_pages = max(1, int(max_pages))
        self.max_events = max(10, int(max_events))
        self.events: list[dict[str, Any]] = []
        self.routes: list[str] = []
        self.errors: list[dict[str, str]] = []

    def dash(self, action: str, evidence: str = "") -> None:
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(phase="Browser Network Capture", phase_progress=55, current_agent="BrowserNetworkAgent", current_tool="browser_network_capture", action=action, endpoint=self.target, evidence=evidence[:1000], safety_status="browser navigation • network capture • no form submission")
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO", action)

    def same_scope(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        base = self.host.lower()
        if host == base:
            return True
        return bool(getattr(self.state, "stats", {}).get("include_subdomains", False) and host.endswith("." + base))

    def add_event(self, profile: str, event_type: str, url: str, method: str = "GET", status: int | None = None, resource_type: str = "") -> None:
        if not url or not self.same_scope(url):
            return
        row = {"profile": profile, "type": event_type, "method": method, "url": url, "status": status, "resource_type": resource_type}
        self.events.append(row)
        path = (urlparse(url).path or "").lower()
        if any(token in path for token in ["/api", "graphql", "/v1", "/v2", "/v3", "ajax"]):
            self.routes.append(url)
        try:
            if method.upper() in {"GET", "HEAD"}:
                self.state.add_url(url, depth=1, source="browser-network")
        except Exception:
            pass

    def run_profile(self, profile_name: str, storage_state: str = "") -> None:
        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:
            raise RuntimeError("Playwright is not installed. Install with: pip install playwright && playwright install chromium") from exc
        self.dash("Starting browser capture for " + profile_name)
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context_kwargs: dict[str, Any] = {"ignore_https_errors": True}
            if storage_state and Path(storage_state).exists():
                context_kwargs["storage_state"] = storage_state
            context = browser.new_context(**context_kwargs)
            page = context.new_page()

            def on_request(req: Any) -> None:
                if len(self.events) < self.max_events:
                    self.add_event(profile_name, "request", req.url, method=req.method, resource_type=req.resource_type)

            def on_response(res: Any) -> None:
                if len(self.events) < self.max_events:
                    self.add_event(profile_name, "response", res.url, method=res.request.method, status=res.status, resource_type=res.request.resource_type)

            page.on("request", on_request)
            page.on("response", on_response)
            page.goto(self.target, wait_until="networkidle", timeout=30000)
            anchors = page.locator("a[href]")
            count = min(anchors.count(), self.max_pages)
            hrefs: list[str] = []
            for idx in range(count):
                try:
                    href = anchors.nth(idx).get_attribute("href") or ""
                    if href:
                        hrefs.append(href)
                except Exception:
                    continue
            for href in hrefs[: self.max_pages]:
                try:
                    page.goto(href, wait_until="networkidle", timeout=20000)
                except Exception as exc:
                    self.errors.append({"profile": profile_name, "url": href, "error": str(exc)[:300]})
            context.close()
            browser.close()

    def run(self) -> dict[str, Any]:
        profile_rows = self.profiles or []
        if not profile_rows:
            # anonymous capture still useful
            profile_rows = [type("Anon", (), {"name": "anonymous", "storage_state": ""})()]
        try:
            for profile in profile_rows[:4]:
                self.run_profile(str(getattr(profile, "name", "profile")), str(getattr(profile, "storage_state", "")))
            skipped = False
            reason = ""
        except Exception as exc:
            skipped = True
            reason = str(exc)[:500]
            self.errors.append({"stage": "browser_capture", "error": reason})
        reports = self.write_reports(skipped=skipped, reason=reason)
        try:
            self.state.stats["browser_network_events"] = len(self.events)
            self.state.stats["browser_network_routes"] = len(set(self.routes))
            self.state.save()
        except Exception:
            pass
        return {"ok": True, "skipped": skipped, "reason": reason, "events": len(self.events), "routes": len(set(self.routes)), "reports": reports}

    def write_reports(self, *, skipped: bool, reason: str = "") -> dict[str, str]:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        payload = {"target": self.target, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "skipped": skipped, "reason": reason, "events": self.events, "api_like_routes": sorted(set(self.routes)), "errors": self.errors, "rules": "Browser navigation and network capture only. No form submission or state-changing automation."}
        json_path = self.out_dir / "browser-network-capture.json"
        md_path = self.out_dir / "browser-network-capture.md"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        lines = ["# Browser Network Capture", "", f"Target: `{self.target}`", f"Skipped: `{skipped}`", f"Reason: `{reason}`", "", f"Network events: `{len(self.events)}`", f"API-like routes: `{len(set(self.routes))}`", "", "## API-like Routes", ""]
        for route in sorted(set(self.routes))[:300]:
            lines.append(f"- `{route}`")
        if not self.routes:
            lines.append("No API-like browser network routes were captured.")
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return {"browser_network_capture_json": str(json_path), "browser_network_capture_md": str(md_path)}

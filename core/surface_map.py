#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

from bs4 import BeautifulSoup

from core.scan_state import ParamRecord, _param_kind, _risk_score

BASIC_PATHS = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/security.txt", "/login", "/search", "/api", "/admin"]
ROUTE_RE = re.compile(r"[\"']((?:/|\./|\.\./)[A-Za-z0-9_./?=&%:#-]{2,180})[\"']")
CALL_RE = re.compile(r"(?:fetch|axios\.(?:get|post)|open)\s*\(\s*[\"']([^\"']{2,180})[\"']", re.I)


class SurfaceMapBuilder:
    def __init__(self, *, target: str, state: Any, client: Any, dashboard: Any | None = None, max_pages: int = 100, max_depth: int = 3) -> None:
        self.target = target
        self.state = state
        self.client = client
        self.dashboard = dashboard
        self.max_pages = max(1, int(max_pages))
        self.max_depth = max(0, int(max_depth))
        self.host = (urlparse(target).hostname or "").lower()
        self.forms: list[dict[str, Any]] = []
        self.js_files: set[str] = set()
        self.js_routes: set[str] = set()
        self.errors: list[dict[str, str]] = []

    def same_scope(self, url: str) -> bool:
        return (urlparse(url).hostname or "").lower() == self.host

    def absolute(self, raw: str, base: str | None = None) -> str:
        raw = str(raw or "").strip()
        if not raw or raw.startswith(("mailto:", "tel:", "javascript:", "data:")):
            return ""
        return urljoin(base or self.target, raw).split("#", 1)[0]

    def dash(self, action: str, url: str = "") -> None:
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            parsed = urlparse(url or self.target)
            self.dashboard.update(phase="Surface Mapping", current_agent="SurfaceMapBuilder", current_tool="surface_map", action=action, endpoint=url or self.target, request_line="GET " + (parsed.path or "/") + (("?" + parsed.query) if parsed.query else ""), path=parsed.path or "/", parameters=parsed.query or "No query parameters on current URL", requests=(getattr(self.state, "stats", {}) or {}).get("requests", 0), findings=len(getattr(self.state, "findings", []) or []), safety_status="same-scope GET/HEAD only")
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO", action)

    def add_url(self, url: str, *, depth: int = 0, source: str = "surface") -> None:
        if not url or not self.same_scope(url):
            return
        self.state.add_url(url, depth=depth, source=source)
        parsed = urlparse(url)
        for name, values in parse_qs(parsed.query, keep_blank_values=True).items():
            kind = _param_kind(name)
            self.state.add_param(ParamRecord(url=url, name=name, value=values[0] if values else "", source=source, kind=kind, method="GET", risk_score=_risk_score(name, kind, url), notes=[f"discovered by {source}"]))

    def get(self, url: str, purpose: str) -> Any | None:
        if not self.same_scope(url):
            return None
        self.dash(f"Fetching {url}", url)
        response = self.client.get(url, purpose=purpose)
        rec = self.state.urls.get(url)
        if rec:
            rec.status = "done" if response.ok else "failed"
            rec.status_code = response.status_code
            rec.content_type = response.headers.get("Content-Type", "") if response.headers else ""
            rec.error = response.error
        if response.error:
            self.errors.append({"url": url, "error": response.error})
        return response

    def parse_page(self, response: Any, depth: int) -> None:
        text = response.text or ""
        url = response.url
        try:
            soup = BeautifulSoup(text, "html.parser")
        except Exception as exc:
            self.errors.append({"url": url, "error": f"html parse failed: {exc}"})
            return
        for tag in soup.find_all(["a", "link", "script", "img", "iframe", "form"]):
            for attr in ["href", "src", "action"]:
                value = tag.get(attr)
                if not value:
                    continue
                found = self.absolute(value, url)
                if not found or not self.same_scope(found):
                    continue
                if tag.name == "script" and attr == "src":
                    self.js_files.add(found)
                self.add_url(found, depth=depth + 1, source=f"html:{tag.name}:{attr}")
        for form in soup.find_all("form"):
            method = str(form.get("method", "get") or "get").upper()
            action = self.absolute(form.get("action") or url, url)
            fields: list[dict[str, str]] = []
            values: dict[str, str] = {}
            for field in form.find_all(["input", "select", "textarea"]):
                name = str(field.get("name") or "").strip()
                if not name:
                    continue
                field_type = str(field.get("type") or field.name or "text")
                value = str(field.get("value") or "test")
                fields.append({"name": name, "type": field_type})
                values[name] = value
            self.forms.append({"url": url, "method": method, "action": action, "fields": fields})
            if method == "GET" and action and self.same_scope(action) and values:
                self.add_url(action.split("?", 1)[0] + "?" + urlencode(values), depth=depth + 1, source="get-form")

    def parse_js(self, response: Any) -> None:
        text = response.text or ""
        for raw in list(ROUTE_RE.findall(text)) + list(CALL_RE.findall(text)):
            found = self.absolute(raw, response.url)
            if found and self.same_scope(found):
                self.js_routes.add(found)
                self.add_url(found, depth=1, source="javascript-route")

    def parse_robots(self) -> None:
        res = self.get(urljoin(self.target.rstrip("/") + "/", "robots.txt"), "robots")
        if not res or not res.ok:
            self.state.add_event("INFO", "robots unavailable or not readable")
            return
        for line in (res.text or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            low = line.lower()
            if low.startswith(("allow:", "disallow:")):
                path = line.split(":", 1)[1].strip()
                if path:
                    self.add_url(urljoin(self.target, path), depth=0, source="robots")
            if low.startswith("sitemap:"):
                self.add_url(line.split(":", 1)[1].strip(), depth=0, source="robots-sitemap")

    def parse_sitemap(self) -> None:
        res = self.get(urljoin(self.target.rstrip("/") + "/", "sitemap.xml"), "sitemap")
        if not res or not res.ok:
            self.state.add_event("INFO", "sitemap unavailable or not readable")
            return
        for loc in re.findall(r"<loc>\s*([^<]+)\s*</loc>", res.text or "", flags=re.I):
            if self.same_scope(loc.strip()):
                self.add_url(loc.strip(), depth=0, source="sitemap")

    def crawl(self) -> None:
        self.add_url(self.target, depth=0, source="seed")
        self.parse_robots()
        self.parse_sitemap()
        for path in BASIC_PATHS:
            self.add_url(urljoin(self.target.rstrip("/") + "/", path.lstrip("/")), depth=0, source="safe-checklist")
        pages = 0
        while pages < self.max_pages:
            queued = [u for u in self.state.urls.values() if u.status == "queued" and u.depth <= self.max_depth]
            if not queued:
                break
            rec = queued[0]
            res = self.get(rec.url, "surface-crawl")
            pages += 1
            if not res or not res.ok:
                continue
            ctype = (res.headers.get("Content-Type", "") if res.headers else "").lower()
            if "html" in ctype or "<html" in (res.text or "")[:500].lower():
                self.parse_page(res, rec.depth)
            if "javascript" in ctype or rec.url.endswith(".js"):
                self.parse_js(res)
        for js in list(self.js_files)[:60]:
            res = self.get(js, "js-route-review")
            if res and res.ok:
                self.parse_js(res)

    def write_reports(self) -> dict[str, str]:
        out = Path(getattr(self.state, "out_dir", "reports/output"))
        out.mkdir(parents=True, exist_ok=True)
        data = {"target": self.target, "urls": [asdict(u) for u in self.state.urls.values()], "parameters": [asdict(p) for p in self.state.params.values()], "forms": self.forms, "js_files": sorted(self.js_files), "js_routes": sorted(self.js_routes), "errors": self.errors}
        json_path = out / "surface-map.json"
        json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        md_path = out / "surface-map.md"
        lines = ["# VulnScope Surface Map", "", f"Target: `{self.target}`", "", "## Summary", f"- URLs discovered: `{len(data['urls'])}`", f"- Parameters discovered: `{len(data['parameters'])}`", f"- Forms discovered: `{len(data['forms'])}`", f"- JavaScript files: `{len(data['js_files'])}`", f"- JavaScript routes: `{len(data['js_routes'])}`", ""]
        if not data["urls"]:
            lines.append("No internal paths were discovered within the selected scan scope.")
        if not data["parameters"]:
            lines.append("No safe query parameters or GET inputs were discovered within the selected scan scope.")
        lines += ["", "## Parameters"]
        for p in data["parameters"][:120]:
            lines.append(f"- `{p.get('name')}` kind=`{p.get('kind')}` score=`{p.get('risk_score')}` url=`{p.get('url')}`")
        md_path.write_text("\n".join(lines), encoding="utf-8")
        self.state.stats["surface_map"] = {"json": str(json_path), "markdown": str(md_path), "urls": len(data["urls"]), "params": len(data["parameters"]), "forms": len(data["forms"]), "js_routes": len(data["js_routes"])}
        self.state.save()
        return {"surface_map_json": str(json_path), "surface_map_md": str(md_path)}

    def run(self) -> dict[str, Any]:
        self.dash("Starting deterministic surface mapping", self.target)
        self.crawl()
        reports = self.write_reports()
        payload = {"ok": True, "reports": reports, "urls": len(self.state.urls), "params": len(self.state.params)}
        self.state.add_event("INFO", "surface map completed", **payload)
        self.state.save()
        return payload

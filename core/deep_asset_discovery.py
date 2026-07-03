#!/usr/bin/env python3
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from core.parameter_inventory import add_params_from_url
from core.scan_state import ScanState


SEED_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/humans.txt",
    "/manifest.json",
    "/site.webmanifest",
    "/service-worker.js",
    "/sw.js",
    "/asset-manifest.json",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/api-docs",
    "/api/docs",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/graphql",
    "/wp-json/",
]

INTERESTING_EXTENSIONS = (
    ".json", ".xml", ".txt", ".js", ".map", ".config", ".bak", ".old", ".backup",
)

ROUTE_PATTERNS = [
    r"https?://[^\s'\"<>]+",
    r"['\"](/(?:api|v\d+|admin|login|auth|dashboard|account|user|users|profile|upload|download|files|documents|search|ajax|graphql)[^'\"\s<>]*)['\"]",
    r"(?:fetch|axios\.get|axios\.post|open)\(\s*['\"]([^'\"]+)['\"]",
    r"(?:url|endpoint|route|path|apiUrl|baseUrl)\s*[:=]\s*['\"]([^'\"]+)['\"]",
]


@dataclass
class DeepAssetResult:
    seeds_checked: int = 0
    seeds_ok: int = 0
    urls_added: int = 0
    params_added: int = 0
    subdomain_hints: int = 0
    interesting_assets: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class DeepAssetDiscovery:
    """Safe same-scope asset and endpoint discovery.

    This module only performs low-impact GET requests against common public
    discovery documents and extracts same-scope URLs, API routes, sitemap links,
    and parameterized endpoints.
    """

    def __init__(self, *, state: ScanState, client: object, include_subdomains: bool = False, dashboard: object | None = None, max_docs: int = 40) -> None:
        self.state = state
        self.client = client
        self.include_subdomains = include_subdomains
        self.dashboard = dashboard
        self.max_docs = max(1, int(max_docs))
        self.root = self.state.target.rstrip("/") + "/"
        self.base_host = self.state.host.lower()

    def _allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in {"http", "https"} or not host:
            return False
        if host == self.base_host:
            return True
        return bool(self.include_subdomains and host.endswith("." + self.base_host))

    def _update(self, message: str, url: str, progress: int, result: DeepAssetResult) -> None:
        parsed = urlparse(url)
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(
                phase="Deep Asset Discovery",
                phase_progress=progress,
                current_agent="AssetDiscoveryAgent",
                current_tool="deep_asset_discovery",
                decision="discover_public_assets",
                action=message,
                endpoint=url,
                request_line="GET " + (parsed.path or "/") + (("?" + parsed.query) if parsed.query else ""),
                path=parsed.path or "/",
                parameters=parsed.query or "No query parameters in this asset document.",
                domain=parsed.hostname or self.base_host,
                probe_string="public-discovery-documents",
                evidence=f"seeds_ok={result.seeds_ok} urls_added={result.urls_added} params_added={result.params_added}",
                safety_status="public asset discovery • same-scope • GET only",
                urls_found=len(self.state.urls),
                paths_found=len({urlparse(item.url).path or '/' for item in self.state.urls.values()}),
                params_found=len(self.state.params),
                forms_found=int(self.state.stats.get("forms", 0)) + int(self.state.stats.get("browser_forms", 0)),
                js_found=int(self.state.stats.get("scripts", 0)),
                api_routes_found=sum(1 for item in self.state.urls.values() if "/api/" in (urlparse(item.url).path or "").lower() or "graphql" in (urlparse(item.url).path or "").lower()),
                requests=int(self.state.stats.get("requests", 0)),
                findings=len(self.state.findings),
            )
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO", message)

    def _add_url(self, url: str, source: str, result: DeepAssetResult) -> None:
        normalized = url.split("#")[0]
        if not normalized or not self._allowed(normalized):
            return
        before_urls = len(self.state.urls)
        before_params = len(self.state.params)
        self.state.add_url(normalized, depth=1, source=source)
        add_params_from_url(self.state, normalized, source)
        result.urls_added += max(0, len(self.state.urls) - before_urls)
        result.params_added += max(0, len(self.state.params) - before_params)
        if (urlparse(normalized).path or "").lower().endswith(INTERESTING_EXTENSIONS):
            result.interesting_assets.append(normalized)

    def _extract_from_text(self, text: str, base_url: str, result: DeepAssetResult, source: str) -> None:
        body = text or ""
        for pattern in ROUTE_PATTERNS:
            for match in re.finditer(pattern, body, re.I):
                value = match.group(1) if match.lastindex else match.group(0)
                if not value or value.startswith(("mailto:", "tel:", "javascript:")):
                    continue
                self._add_url(urljoin(base_url, value), source, result)
        for host in set(re.findall(r"[a-zA-Z0-9._-]+\." + re.escape(self.base_host), body)):
            if host.lower() != self.base_host:
                result.subdomain_hints += 1
                self.state.stats.setdefault("subdomain_hints", [])
                if host not in self.state.stats["subdomain_hints"]:
                    self.state.stats["subdomain_hints"].append(host)
                if self.include_subdomains:
                    self._add_url("https://" + host + "/", "subdomain-hint", result)

    def _extract_sitemap(self, text: str, base_url: str, result: DeepAssetResult) -> None:
        try:
            root = ET.fromstring(text.encode("utf-8", errors="ignore"))
            for loc in root.iter():
                if loc.tag.lower().endswith("loc") and loc.text:
                    self._add_url(loc.text.strip(), "sitemap", result)
        except Exception:
            self._extract_from_text(text, base_url, result, "sitemap-text")

    def _extract_robots(self, text: str, base_url: str, result: DeepAssetResult) -> None:
        for line in (text or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if key in {"allow", "disallow", "sitemap"} and value:
                self._add_url(urljoin(base_url, value), "robots", result)

    def run(self) -> DeepAssetResult:
        result = DeepAssetResult()
        seed_urls = [urljoin(self.root, item.lstrip("/")) for item in SEED_PATHS]
        seen: set[str] = set()
        for index, url in enumerate(seed_urls[: self.max_docs], 1):
            if url in seen or self.client.budget_remaining() <= 0:
                continue
            seen.add(url)
            result.seeds_checked += 1
            self._update(f"Checking public discovery document {index}/{min(len(seed_urls), self.max_docs)}", url, int(18 + index * 12 / max(1, min(len(seed_urls), self.max_docs))), result)
            try:
                response = self.client.get(url, purpose="deep-asset-discovery")
                if not getattr(response, "ok", False) or response.status_code not in {200, 204, 206}:
                    continue
                result.seeds_ok += 1
                self._add_url(response.url, "deep-asset-seed", result)
                content_type = response.headers.get("Content-Type", "")
                path = (urlparse(response.url).path or "").lower()
                if "robots.txt" in path:
                    self._extract_robots(response.text, response.url, result)
                elif "sitemap" in path or "xml" in content_type:
                    self._extract_sitemap(response.text, response.url, result)
                else:
                    self._extract_from_text(response.text, response.url, result, "deep-asset-doc")
            except Exception as exc:
                result.errors.append(f"{url}: {str(exc)[:200]}")
        self.state.stats["deep_asset_discovery"] = {
            "seeds_checked": result.seeds_checked,
            "seeds_ok": result.seeds_ok,
            "urls_added": result.urls_added,
            "params_added": result.params_added,
            "subdomain_hints": result.subdomain_hints,
            "interesting_assets": result.interesting_assets[:80],
        }
        self.state.save()
        return result

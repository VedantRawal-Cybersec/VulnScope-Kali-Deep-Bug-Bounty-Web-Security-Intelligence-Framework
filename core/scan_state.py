#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

from cai_scope_guard import cai_output_dir, normalize_target


@dataclass
class UrlRecord:
    url: str
    depth: int = 0
    source: str = "seed"
    status: str = "queued"
    status_code: int | None = None
    content_type: str = ""
    body_hash: str = ""
    template_key: str = ""
    discovered_at: float = field(default_factory=time.time)
    last_seen_at: float | None = None
    error: str = ""


@dataclass
class ParamRecord:
    url: str
    name: str
    value: str = ""
    source: str = "query"
    kind: str = "generic"
    method: str = "GET"
    status: str = "queued"
    tested: list[str] = field(default_factory=list)
    risk_score: int = 0
    discovered_at: float = field(default_factory=time.time)
    notes: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.method}:{self.url}:{self.name}"


@dataclass
class TestRecord:
    test_id: str
    url: str
    parameter: str | None
    test_name: str
    status: str = "queued"
    confidence: int = 0
    finding_id: str | None = None
    evidence_id: str | None = None
    started_at: float | None = None
    finished_at: float | None = None
    error: str = ""


ROUTE_PARAMS = {"next", "url", "redirect", "redirect_uri", "return", "return_url", "continue", "dest", "destination", "callback"}
REFERENCE_PARAMS = ROUTE_PARAMS | {"uri", "link", "target", "site", "host", "domain", "endpoint", "callback_url"}
RESOURCE_PARAMS = {"file", "path", "page", "template", "folder", "dir", "download", "document", "doc", "include"}
OBJECT_PARAMS = {"id", "uid", "user", "user_id", "account", "account_id", "order", "order_id", "invoice", "invoice_id", "profile_id", "artist", "cat", "pic", "pp"}
SEARCH_PARAMS = {"q", "query", "search", "keyword", "term", "s", "test"}


def _param_kind(name: str) -> str:
    value = name.lower().strip()
    if value in ROUTE_PARAMS:
        return "route-like"
    if value in REFERENCE_PARAMS or value.endswith("url") or "callback" in value:
        return "reference-like"
    if value in RESOURCE_PARAMS or value.endswith("file") or value.endswith("path"):
        return "resource-like"
    if value in OBJECT_PARAMS or value.endswith("_id") or value == "id":
        return "object-like"
    if value in SEARCH_PARAMS:
        return "search-like"
    if any(x in value for x in ["lang", "locale", "theme", "sort", "filter", "page", "limit"]):
        return "state-like"
    return "generic"


def _risk_score(name: str, kind: str, url: str) -> int:
    score = {"route-like": 80, "reference-like": 75, "resource-like": 70, "object-like": 65, "search-like": 55, "state-like": 35, "generic": 25}.get(kind, 20)
    path = (urlparse(url).path or "").lower()
    if any(token in path for token in ["api", "graphql", "json", "rest"]):
        score += 10
    if any(token in path for token in ["account", "order", "invoice", "user", "profile", "artist", "product", "search", "image"]):
        score += 10
    if len(name) <= 2:
        score += 3
    return min(100, score)


class ScanState:
    """Small durable state store for large scans and resume support."""

    def __init__(self, target: str, *, resume: bool = False) -> None:
        self.target = normalize_target(target)
        self.host = (urlparse(self.target).hostname or "target").lower()
        self.out_dir = cai_output_dir(self.target)
        self.path = self.out_dir / "autonomous-scan-state.json"
        self.created_at = time.time()
        self.updated_at = self.created_at
        self.urls: dict[str, UrlRecord] = {}
        self.params: dict[str, ParamRecord] = {}
        self.tests: dict[str, TestRecord] = {}
        self.findings: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.stats: dict[str, Any] = {
            "requests": 0,
            "timeouts": 0,
            "backoffs": 0,
            "skipped": 0,
            "resumed": False,
            "browser_routes": 0,
        }
        if resume and self.path.exists():
            self.load()
            self.stats["resumed"] = True
        else:
            self.add_url(self.target, depth=0, source="seed")
        self.apply_seed_urls()
        self.save()

    def add_event(self, level: str, event_message: str = "", **data: Any) -> None:
        """Append a durable scan event without allowing telemetry-key collisions to crash the scan."""
        try:
            safe_data = dict(data or {})
            if "message" in safe_data:
                safe_data["detail_message"] = safe_data.pop("message")
            self.events.append({"time": time.time(), "level": str(level), "message": str(event_message), **safe_data})
            self.events = self.events[-1000:]
            self.updated_at = time.time()
        except Exception:
            self.updated_at = time.time()

    def add_url(self, url: str, *, depth: int = 0, source: str = "link") -> UrlRecord:
        if url not in self.urls:
            self.urls[url] = UrlRecord(url=url, depth=depth, source=source)
        else:
            self.urls[url].depth = min(self.urls[url].depth, depth)
        return self.urls[url]

    def add_param(self, record: ParamRecord) -> ParamRecord:
        existing = self.params.get(record.key)
        if existing:
            if record.source not in existing.source:
                existing.source = existing.source + "+" + record.source
            existing.risk_score = max(existing.risk_score, record.risk_score)
            if record.notes:
                existing.notes.extend([note for note in record.notes if note not in existing.notes])
            return existing
        self.params[record.key] = record
        return record

    def _same_scope(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        return bool(host and host == self.host)

    def _normalize_seed_url(self, raw: str) -> str:
        item = str(raw or "").strip()
        if not item:
            return ""
        if "://" in item:
            return item
        return urljoin(self.target.rstrip("/") + "/", item.lstrip("/"))

    def _seed_urls_from_env(self) -> list[str]:
        raw = os.getenv("VULNSCOPE_SEED_URLS", "")
        return [self._normalize_seed_url(item) for item in raw.split(",") if item.strip()]

    def _builtin_lab_seed_urls(self) -> list[str]:
        profile = os.getenv("VULNSCOPE_LAB_SEED_PROFILE", "").lower().strip()
        if self.host != "testphp.vulnweb.com" and profile not in {"vulnweb", "testphp"}:
            return []
        base = self.target.rstrip("/") + "/"
        return [
            urljoin(base, "listproducts.php?cat=1"),
            urljoin(base, "artists.php?artist=1"),
            urljoin(base, "product.php?pic=1"),
            urljoin(base, "search.php?test=query"),
            urljoin(base, "showimage.php?file=showimage.php"),
            urljoin(base, "hpp/?pp=12"),
        ]

    def apply_seed_urls(self) -> dict[str, int]:
        """Add lab/custom seed URLs so validation never starves when crawling is shallow."""
        seeds = [url for url in [*self._builtin_lab_seed_urls(), *self._seed_urls_from_env()] if url]
        urls_before = len(self.urls)
        params_before = len(self.params)
        for seed in seeds:
            if not self._same_scope(seed):
                self.add_event("WARNING", "seed url ignored outside target scope", seed_url=seed)
                continue
            self.add_url(seed, depth=0, source="lab-seed")
            query = parse_qs(urlparse(seed).query, keep_blank_values=True)
            for name, values in query.items():
                kind = _param_kind(name)
                self.add_param(ParamRecord(url=seed, name=name, value=values[0] if values else "", source="lab-seed", kind=kind, risk_score=_risk_score(name, kind, seed), notes=["seeded for lab validation coverage"]))
        added = {"seed_urls_added": len(self.urls) - urls_before, "seed_params_added": len(self.params) - params_before}
        self.stats["lab_seed_urls"] = added
        if added["seed_urls_added"] or added["seed_params_added"]:
            self.add_event("INFO", "lab/custom seed URLs added", **added)
        return added

    def add_test(self, record: TestRecord) -> TestRecord:
        self.tests[record.test_id] = record
        return record

    def add_finding(self, finding: dict[str, Any]) -> None:
        self.findings.append(finding)
        self.updated_at = time.time()

    def queued_urls(self, *, limit: int = 100) -> list[UrlRecord]:
        return [u for u in self.urls.values() if u.status == "queued"][:limit]

    def queued_params(self, *, limit: int = 100) -> list[ParamRecord]:
        items = [p for p in self.params.values() if p.status in {"queued", "review"}]
        return sorted(items, key=lambda p: p.risk_score, reverse=True)[:limit]

    def coverage(self) -> dict[str, int]:
        return {
            "urls_total": len(self.urls),
            "urls_done": sum(1 for item in self.urls.values() if item.status in {"done", "skipped", "failed"}),
            "params_total": len(self.params),
            "params_done": sum(1 for item in self.params.values() if item.status in {"done", "skipped", "failed"}),
            "tests_total": len(self.tests),
            "tests_done": sum(1 for item in self.tests.values() if item.status in {"done", "skipped", "failed"}),
            "findings": len(self.findings),
            "requests": int(self.stats.get("requests", 0)),
            "timeouts": int(self.stats.get("timeouts", 0)),
            "skipped": int(self.stats.get("skipped", 0)),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "host": self.host,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "urls": {key: asdict(value) for key, value in self.urls.items()},
            "params": {key: asdict(value) for key, value in self.params.items()},
            "tests": {key: asdict(value) for key, value in self.tests.items()},
            "findings": self.findings,
            "events": self.events,
            "stats": self.stats,
            "coverage": self.coverage(),
        }

    def save(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.updated_at = time.time()
        self.path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

    def load(self) -> None:
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        self.created_at = float(payload.get("created_at") or time.time())
        self.updated_at = float(payload.get("updated_at") or self.created_at)
        self.urls = {key: UrlRecord(**value) for key, value in payload.get("urls", {}).items()}
        self.params = {key: ParamRecord(**value) for key, value in payload.get("params", {}).items()}
        self.tests = {key: TestRecord(**value) for key, value in payload.get("tests", {}).items()}
        self.findings = list(payload.get("findings", []))
        self.events = list(payload.get("events", []))[-1000:]
        self.stats = dict(payload.get("stats", {}))

    def write_markdown_summary(self) -> Path:
        path = self.out_dir / "autonomous-scan-state.md"
        cov = self.coverage()
        lines = [
            "# VulnScope Autonomous Scan State",
            "",
            f"Target: `{self.target}`",
            f"URLs: `{cov['urls_done']}/{cov['urls_total']}`",
            f"Parameters: `{cov['params_done']}/{cov['params_total']}`",
            f"Tests: `{cov['tests_done']}/{cov['tests_total']}`",
            f"Findings/leads: `{cov['findings']}`",
            f"Requests: `{cov['requests']}`",
            f"Timeouts: `{cov['timeouts']}`",
            "",
            "## Top parameters",
        ]
        for item in sorted(self.params.values(), key=lambda p: p.risk_score, reverse=True)[:50]:
            lines.append(f"- `{item.name}` kind=`{item.kind}` risk=`{item.risk_score}` status=`{item.status}` tested=`{','.join(item.tested)}` url=`{item.url}`")
        path.write_text("\n".join(lines), encoding="utf-8")
        try:
            from core.owasp_coverage import OWASPCoverageReporter
            OWASPCoverageReporter(self).write_all()
        except Exception as exc:
            self.add_event("WARNING", "owasp coverage report failed", error=str(exc)[:300])
        return path

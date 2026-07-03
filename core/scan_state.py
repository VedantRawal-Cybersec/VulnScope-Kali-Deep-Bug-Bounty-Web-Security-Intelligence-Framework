#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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
            self.save()

    def add_event(self, level: str, message: str, **data: Any) -> None:
        self.events.append({"time": time.time(), "level": level, "message": message, **data})
        self.events = self.events[-1000:]
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
            return existing
        self.params[record.key] = record
        return record

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

    def finding_buckets(self) -> dict[str, int]:
        confirmed = 0
        potential = 0
        informational = 0
        for finding in self.findings:
            status = str(finding.get("status") or "Potential").lower()
            if status == "confirmed":
                confirmed += 1
            elif status.startswith("info"):
                informational += 1
            else:
                potential += 1
        return {
            "confirmed_vulnerabilities": confirmed,
            "potential_review_leads": potential,
            "informational_observations": informational,
        }

    def coverage(self) -> dict[str, int]:
        buckets = self.finding_buckets()
        return {
            "urls_total": len(self.urls),
            "urls_done": sum(1 for item in self.urls.values() if item.status in {"done", "skipped", "failed"}),
            "params_total": len(self.params),
            "params_done": sum(1 for item in self.params.values() if item.status in {"done", "skipped", "failed"}),
            "tests_total": len(self.tests),
            "tests_done": sum(1 for item in self.tests.values() if item.status in {"done", "skipped", "failed"}),
            "findings": len(self.findings),
            **buckets,
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
            f"Confirmed vulnerabilities: `{cov['confirmed_vulnerabilities']}`",
            f"Potential review leads: `{cov['potential_review_leads']}`",
            f"Informational observations: `{cov['informational_observations']}`",
            f"Requests: `{cov['requests']}`",
            f"Timeouts: `{cov['timeouts']}`",
            "",
            "## Top parameters",
        ]
        for item in sorted(self.params.values(), key=lambda p: p.risk_score, reverse=True)[:50]:
            lines.append(f"- `{item.name}` kind=`{item.kind}` risk=`{item.risk_score}` status=`{item.status}` url=`{item.url}`")
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

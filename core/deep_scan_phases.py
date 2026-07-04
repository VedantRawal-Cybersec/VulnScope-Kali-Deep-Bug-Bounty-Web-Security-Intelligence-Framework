#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.parameter_inventory import add_params_from_url, param_kind, risk_score
from core.scan_state import ParamRecord, ScanState

COMMON_PARAMETER_NAMES = [
    "id", "uid", "user", "user_id", "account", "account_id", "profile", "profile_id",
    "order", "order_id", "invoice", "invoice_id", "product", "product_id", "item", "item_id",
    "cat", "category", "page", "file", "path", "q", "query", "search", "keyword", "term",
    "next", "url", "redirect", "return", "return_url", "continue", "callback", "lang", "sort", "filter",
]

INTERESTING_JS_PATTERNS = {
    "route": re.compile(r"(?i)(/api/[^'\"\s<>]+|/v\d+/[^'\"\s<>]+|/graphql|/admin[^'\"\s<>]*|/ajax/[^'\"\s<>]+)"),
    "token_word": re.compile(r"(?i)(api[_-]?key|access[_-]?token|bearer|jwt|secret|client[_-]?id|firebase|s3|bucket)"),
    "url": re.compile(r"https?://[^'\"\s<>]+"),
}


@dataclass
class DeepPhaseResult:
    phase: str
    status: str = "completed"
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    elapsed_ms: int = 0
    summary: dict[str, Any] = field(default_factory=dict)

    def finish(self, **summary: Any) -> "DeepPhaseResult":
        self.finished_at = time.time()
        self.elapsed_ms = int((self.finished_at - self.started_at) * 1000)
        self.summary.update(summary)
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DeepScanPhasePack:
    """Safe deep-scan strengthening phases for owned/authorized targets.

    These phases enrich scan state and telemetry. They do not perform credential
    attacks, destructive actions, or target data modification.
    """

    def __init__(self, *, state: ScanState, client: Any | None = None, dashboard: Any | None = None, include_subdomains: bool = False) -> None:
        self.state = state
        self.client = client
        self.dashboard = dashboard
        self.include_subdomains = include_subdomains
        self.results: list[dict[str, Any]] = []

    def _emit(self, phase: str, action: str, progress: int, evidence: str = "") -> None:
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(
                phase=phase,
                phase_progress=progress,
                current_agent="DeepScanPhasePack",
                current_tool="deep_scan_phase_pack",
                decision="deep-safe-active-coverage",
                action=action,
                endpoint=self.state.target,
                evidence=evidence or self._coverage_text(),
                safety_status="deep safe-active enrichment • same-scope • no destructive actions",
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
            self.dashboard.event("INFO", f"{phase}: {action}")

    def _coverage_text(self) -> str:
        cov = self.state.coverage()
        return f"urls={cov['urls_done']}/{cov['urls_total']} params={cov['params_done']}/{cov['params_total']} tests={cov['tests_done']}/{cov['tests_total']} req={cov['requests']} findings={cov['findings']}"

    def _same_host_or_subdomain(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        base = self.state.host.lower()
        return bool(host == base or (self.include_subdomains and host.endswith("." + base)))

    def subdomain_liveness_audit(self) -> DeepPhaseResult:
        result = DeepPhaseResult("Subdomain Liveness Audit")
        self._emit(result.phase, "collecting same-scope host candidates", 46)
        hosts = {self.state.host}
        for item in self.state.urls.values():
            host = (urlparse(item.url).hostname or "").lower()
            if host and self._same_host_or_subdomain(item.url):
                hosts.add(host)
        for hint in self.state.stats.get("subdomain_hints", []) or []:
            if isinstance(hint, str) and (hint == self.state.host or hint.endswith("." + self.state.host)):
                hosts.add(hint)
        alive: list[str] = []
        checked: list[dict[str, Any]] = []
        if self.client is not None:
            for host in sorted(hosts)[:80]:
                url = "https://" + host + "/"
                try:
                    response = self.client.get(url, purpose="subdomain-liveness-audit")
                    checked.append({"host": host, "url": response.url, "ok": bool(getattr(response, "ok", False)), "status_code": getattr(response, "status_code", 0), "error": getattr(response, "error", "")[:200]})
                    if getattr(response, "ok", False):
                        alive.append(host)
                        self.state.add_url(response.url, depth=0, source="subdomain-liveness")
                except Exception as exc:
                    checked.append({"host": host, "ok": False, "error": str(exc)[:200]})
        self.state.stats["subdomain_liveness"] = {"candidates": sorted(hosts), "alive": alive, "checked": checked[:100]}
        self.state.save()
        self._emit(result.phase, f"alive hosts={len(alive)} candidates={len(hosts)}", 49)
        return result.finish(candidates=len(hosts), alive=len(alive), checked=checked[:100])

    def javascript_signal_audit(self) -> DeepPhaseResult:
        result = DeepPhaseResult("JavaScript Signal Audit")
        self._emit(result.phase, "scoring JavaScript route and secret-word signals", 53)
        js_urls = [item.url for item in self.state.urls.values() if (urlparse(item.url).path or "").lower().endswith(".js")]
        signals: list[dict[str, Any]] = []
        api_routes_added = 0
        if self.client is not None:
            for js_url in js_urls[:120]:
                try:
                    response = self.client.get(js_url, purpose="javascript-signal-audit")
                    if not getattr(response, "ok", False):
                        continue
                    text = getattr(response, "text", "") or ""
                    found_routes = sorted(set(INTERESTING_JS_PATTERNS["route"].findall(text)))[:80]
                    found_urls = sorted(set(INTERESTING_JS_PATTERNS["url"].findall(text)))[:40]
                    token_words = sorted(set(match.group(1).lower() for match in INTERESTING_JS_PATTERNS["token_word"].finditer(text)))[:30]
                    for route in found_routes:
                        joined = urlunparse((urlparse(js_url).scheme, urlparse(js_url).netloc, route if route.startswith("/") else "/" + route, "", "", ""))
                        before = len(self.state.urls)
                        self.state.add_url(joined, depth=1, source="js-signal-audit")
                        api_routes_added += max(0, len(self.state.urls) - before)
                    for discovered in found_urls:
                        if self._same_host_or_subdomain(discovered):
                            self.state.add_url(discovered, depth=1, source="js-url-signal")
                            add_params_from_url(self.state, discovered, "js-url-signal")
                    if found_routes or found_urls or token_words:
                        signals.append({"js_url": js_url, "routes": found_routes[:20], "same_scope_urls": found_urls[:20], "interesting_words": token_words})
                except Exception as exc:
                    signals.append({"js_url": js_url, "error": str(exc)[:200]})
        self.state.stats["javascript_signal_audit"] = {"scripts_seen": len(js_urls), "signals": signals[:80], "routes_added": api_routes_added}
        self.state.save()
        self._emit(result.phase, f"scripts={len(js_urls)} route_signals={api_routes_added}", 56)
        return result.finish(scripts=len(js_urls), route_signals=api_routes_added, signals=signals[:80])

    def parameter_expansion(self) -> DeepPhaseResult:
        result = DeepPhaseResult("Parameter Expansion")
        self._emit(result.phase, "expanding likely GET parameters from discovered routes", 60)
        before_params = len(self.state.params)
        candidate_urls = [item.url for item in self.state.urls.values() if self._same_host_or_subdomain(item.url)]
        expanded = 0
        for url in candidate_urls[:250]:
            parsed = urlparse(url)
            if parsed.query:
                continue
            path = (parsed.path or "/").lower()
            if not any(token in path for token in ["search", "product", "item", "user", "profile", "account", "order", "invoice", "download", "file", "api", "admin", "category", "page"]):
                continue
            names = COMMON_PARAMETER_NAMES
            if "search" in path:
                names = ["q", "query", "search", "keyword", "term", *names]
            elif any(token in path for token in ["product", "item", "category"]):
                names = ["id", "product_id", "item_id", "cat", "category", "page", *names]
            elif any(token in path for token in ["user", "profile", "account"]):
                names = ["id", "user", "user_id", "profile_id", "account_id", *names]
            for name in list(dict.fromkeys(names))[:18]:
                query = urlencode({name: "1"})
                seed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", query, ""))
                kind = param_kind(name)
                record = ParamRecord(url=seed_url, name=name, value="1", source="deep-parameter-expansion", kind=kind, risk_score=risk_score(name, kind, seed_url), notes=["synthetic same-scope parameter candidate for safe validation prioritization"])
                before = len(self.state.params)
                self.state.add_param(record)
                if len(self.state.params) > before:
                    self.state.add_url(seed_url, depth=parsed.path.count("/"), source="deep-parameter-expansion")
                    expanded += 1
        after_params = len(self.state.params)
        self.state.stats["parameter_expansion"] = {"before": before_params, "after": after_params, "added": after_params - before_params, "expanded_candidates": expanded}
        self.state.save()
        self._emit(result.phase, f"parameters added={after_params - before_params}", 63)
        return result.finish(before=before_params, after=after_params, added=after_params - before_params, expanded_candidates=expanded)

    def endpoint_prioritization(self) -> DeepPhaseResult:
        result = DeepPhaseResult("Endpoint Prioritization")
        self._emit(result.phase, "prioritizing high-signal endpoints and parameters", 66)
        params = sorted(self.state.params.values(), key=lambda p: p.risk_score, reverse=True)
        endpoints = sorted(self.state.urls.values(), key=lambda u: (u.depth, u.url))
        prioritized_params = [asdict(item) for item in params[:150]]
        prioritized_endpoints = [asdict(item) for item in endpoints[:250]]
        out_dir = self.state.out_dir
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / "deep-scan-prioritization.json"
        payload = {
            "generated_at": time.time(),
            "target": self.state.target,
            "prioritized_params": prioritized_params,
            "prioritized_endpoints": prioritized_endpoints,
            "coverage": self.state.coverage(),
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        self.state.stats["deep_scan_prioritization_path"] = str(path)
        self.state.save()
        self._emit(result.phase, f"top_params={len(prioritized_params)} top_endpoints={len(prioritized_endpoints)}", 68)
        return result.finish(prioritized_params=len(prioritized_params), prioritized_endpoints=len(prioritized_endpoints), path=str(path))

    def run_all(self) -> dict[str, Any]:
        results = [
            self.subdomain_liveness_audit().to_dict(),
            self.javascript_signal_audit().to_dict(),
            self.parameter_expansion().to_dict(),
            self.endpoint_prioritization().to_dict(),
        ]
        self.results = results
        summary = {"phases": results, "coverage": self.state.coverage(), "stats": {k: self.state.stats.get(k) for k in ["subdomain_liveness", "javascript_signal_audit", "parameter_expansion", "deep_scan_prioritization_path"]}}
        path = self.state.out_dir / "deep-scan-phase-summary.json"
        path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        summary["summary_path"] = str(path)
        return summary

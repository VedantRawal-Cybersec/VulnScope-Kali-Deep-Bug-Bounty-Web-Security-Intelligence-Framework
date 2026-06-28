from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

import requests

from scope.policy import load_scope_policy

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}


@dataclass
class ReplayCandidate:
    method: str
    url: str
    source: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReplayResult:
    method: str
    url: str
    allowed: bool
    status_code: int | None
    body_hash: str | None
    length: int | None
    reason: str
    elapsed_ms: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _body_hash(text: str) -> str:
    return hashlib.sha256(text[:200000].encode(errors="ignore")).hexdigest()[:16]


def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", query, ""))


def collect_replay_candidates(paths: list[str] | None = None) -> list[ReplayCandidate]:
    paths = paths or ["reports/output/imports/har-import.json", "reports/output/imports/burp-import.json"]
    candidates: list[ReplayCandidate] = []
    seen: set[str] = set()
    for path in paths:
        p = Path(path)
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        for endpoint in data.get("endpoints", []) if isinstance(data, dict) else []:
            if not isinstance(endpoint, dict):
                continue
            method = str(endpoint.get("method", "GET")).upper()
            url = str(endpoint.get("url", ""))
            if not url or method not in SAFE_METHODS:
                continue
            key = f"{method} {_normalize_url(url)}"
            if key in seen:
                continue
            seen.add(key)
            reason = ",".join(endpoint.get("risk_signals", [])) if isinstance(endpoint.get("risk_signals"), list) else "imported_endpoint"
            candidates.append(ReplayCandidate(method=method, url=_normalize_url(url), source=path, reason=reason or "imported_endpoint"))
    return candidates


def run_replay_validation(scope_policy_path: str = "scope_policy.yaml", max_requests: int = 25, timeout: int = 10, dry_run: bool = False) -> dict[str, Any]:
    policy = load_scope_policy(scope_policy_path)
    candidates = collect_replay_candidates()[:max_requests]
    results: list[ReplayResult] = []
    for cand in candidates:
        decision = policy.check(cand.url)
        if not decision.allowed:
            results.append(ReplayResult(cand.method, cand.url, False, None, None, None, decision.reason))
            continue
        if dry_run:
            results.append(ReplayResult(cand.method, cand.url, True, None, None, None, "dry-run planned"))
            continue
        started = time.time()
        try:
            response = requests.request(cand.method, cand.url, headers={"User-Agent": "VulnScope-SafeReplay/1.0"}, timeout=timeout, allow_redirects=False)
            elapsed = int((time.time() - started) * 1000)
            text = response.text or ""
            results.append(ReplayResult(cand.method, cand.url, True, response.status_code, _body_hash(text), len(text), "safe replay complete", elapsed))
        except Exception as exc:
            results.append(ReplayResult(cand.method, cand.url, True, None, None, None, f"request failed: {exc}"))
    return {"policy": policy.to_dict(), "count": len(results), "results": [r.to_dict() for r in results], "rules": {"safe_methods_only": sorted(SAFE_METHODS), "no_auth_headers_reused": True, "scope_policy_required": True}}


def save_replay_validation(out_path: str | Path = "reports/output/validation/replay-validation.json", **kwargs: Any) -> Path:
    result = run_replay_validation(**kwargs)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return out

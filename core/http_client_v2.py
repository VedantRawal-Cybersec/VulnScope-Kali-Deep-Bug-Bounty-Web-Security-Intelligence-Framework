#!/usr/bin/env python3
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from core.evidence_store import EvidenceStore
from core.scan_state import ScanState

DEFAULT_USER_AGENT = "VulnScope-Autonomous-Safe-Scanner/1.9"


@dataclass
class ResponseRecord:
    url: str
    status_code: int
    headers: dict[str, str]
    text: str
    elapsed_ms: int
    request_id: str
    response_id: str
    error: str = ""

    @property
    def received(self) -> bool:
        return not self.error and self.status_code > 0

    @property
    def ok(self) -> bool:
        return not self.error and 200 <= self.status_code < 400


class SafeHttpClientV2:
    """Transparent, budgeted, rate-aware GET/HEAD client for authorized scans."""

    def __init__(self, *, state: ScanState, evidence: EvidenceStore, headers: dict[str, str] | None = None, timeout: int = 8, delay: float = 0.5, request_budget: int = 500, max_body_bytes: int = 1024 * 1024) -> None:
        self.state = state
        self.evidence = evidence
        self.timeout = max(3, int(timeout))
        self.delay = max(0.0, float(delay))
        self.request_budget = max(1, int(request_budget))
        self.max_body_bytes = max(16384, int(max_body_bytes))
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": DEFAULT_USER_AGENT, **(headers or {})})
        self.last_request_at = 0.0
        self.pause_until = 0.0
        self.consecutive_errors = 0

    def include_subdomains(self) -> bool:
        return bool(self.state.stats.get("include_subdomains", False))

    def budget_remaining(self) -> int:
        return max(0, self.request_budget - int(self.state.stats.get("requests", 0)))

    def _pace(self) -> None:
        wait = max(self.pause_until - time.time(), self.delay - (time.time() - self.last_request_at))
        if wait > 0:
            time.sleep(min(wait, 20))
        self.last_request_at = time.time()

    def _same_host_guard(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("non-http URL is outside scan scope")
        if not parsed.hostname:
            raise ValueError("URL without hostname is outside scan scope")
        host = parsed.hostname.lower()
        base = self.state.host.lower()
        if host == base:
            return
        if self.include_subdomains() and host.endswith("." + base):
            return
        raise ValueError("hostname is outside scan scope")

    def _fetch_once(self, method: str, url: str, purpose: str) -> ResponseRecord:
        self._same_host_guard(url)
        if self.budget_remaining() <= 0:
            raise RuntimeError("request budget exhausted")
        self._pace()
        req_id = self.evidence.record_request(method=method, url=url, headers=dict(self.session.headers), purpose=purpose)
        started = time.time()
        self.state.stats["requests"] = int(self.state.stats.get("requests", 0)) + 1
        try:
            response = self.session.request(method, url, timeout=self.timeout, allow_redirects=False, stream=True)
            chunks: list[bytes] = []
            total = 0
            if method != "HEAD":
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= self.max_body_bytes:
                        break
            response.close()
            elapsed_ms = int((time.time() - started) * 1000)
            text = b"".join(chunks).decode(response.encoding or "utf-8", errors="ignore")
            headers = {str(k): str(v) for k, v in response.headers.items()}
            if response.status_code in {429, 500, 502, 503, 504}:
                self.consecutive_errors += 1
                self.state.stats["backoffs"] = int(self.state.stats.get("backoffs", 0)) + 1
                self.pause_until = time.time() + min(30, self.delay + self.consecutive_errors * 2)
            else:
                self.consecutive_errors = 0
            res_id = self.evidence.record_response(request_id=req_id, url=str(response.url), status_code=int(response.status_code), headers=headers, body=text, elapsed_ms=elapsed_ms)
            return ResponseRecord(url=str(response.url), status_code=int(response.status_code), headers=headers, text=text, elapsed_ms=elapsed_ms, request_id=req_id, response_id=res_id)
        except requests.Timeout as exc:
            self.state.stats["timeouts"] = int(self.state.stats.get("timeouts", 0)) + 1
            elapsed_ms = int((time.time() - started) * 1000)
            res_id = self.evidence.record_response(request_id=req_id, url=url, status_code=0, headers={}, body="", elapsed_ms=elapsed_ms, error=str(exc))
            return ResponseRecord(url=url, status_code=0, headers={}, text="", elapsed_ms=elapsed_ms, request_id=req_id, response_id=res_id, error=str(exc))
        except Exception as exc:
            elapsed_ms = int((time.time() - started) * 1000)
            res_id = self.evidence.record_response(request_id=req_id, url=url, status_code=0, headers={}, body="", elapsed_ms=elapsed_ms, error=str(exc))
            return ResponseRecord(url=url, status_code=0, headers={}, text="", elapsed_ms=elapsed_ms, request_id=req_id, response_id=res_id, error=str(exc))

    def request(self, method: str, url: str, *, purpose: str = "scan", allow_redirects: bool = True) -> ResponseRecord:
        method = method.upper()
        if method not in {"GET", "HEAD"}:
            raise ValueError("safe client only permits GET and HEAD")
        response = self._fetch_once(method, url, purpose)
        redirects = 0
        while allow_redirects and response.status_code in {301, 302, 303, 307, 308} and redirects < 3:
            location = response.headers.get("Location", "")
            if not location:
                break
            next_url = urljoin(response.url, location)
            try:
                self._same_host_guard(next_url)
            except Exception:
                self.state.add_event("INFO", "redirect left scan scope", source=response.url, location=location)
                break
            redirects += 1
            response = self._fetch_once("GET" if response.status_code in {301, 302, 303} else method, next_url, purpose + ":redirect")
        return response

    def get(self, url: str, *, purpose: str = "scan", allow_redirects: bool = True) -> ResponseRecord:
        return self.request("GET", url, purpose=purpose, allow_redirects=allow_redirects)

    def head(self, url: str, *, purpose: str = "scan", allow_redirects: bool = True) -> ResponseRecord:
        return self.request("HEAD", url, purpose=purpose, allow_redirects=allow_redirects)

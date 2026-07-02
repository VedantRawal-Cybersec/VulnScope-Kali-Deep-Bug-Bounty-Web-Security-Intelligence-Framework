#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from pathlib import Path
from typing import Any

from cai_scope_guard import cai_output_dir, normalize_target


def redact(value: Any, limit: int = 2000) -> str:
    text = str(value if value is not None else "")
    text = text.replace("\r", " ")
    for label in ["authorization", "cookie", "api_key", "token", "secret", "password"]:
        text = re.sub(label + r"(\s*[:=]\s*)([^\s;,]+)", label + r"\1<redacted>", text, flags=re.I)
    return text[:limit] + ("…" if len(text) > limit else "")


def body_hash(body: str) -> str:
    return hashlib.sha256((body or "").encode("utf-8", errors="ignore")).hexdigest()[:24]


def stable_template_key(url: str, status_code: int, body: str) -> str:
    normalized = re.sub(r"\d+", "{n}", url)
    normalized = re.sub(r"[a-f0-9]{8,}", "{hex}", normalized, flags=re.I)
    text = re.sub(r"\s+", " ", body or "")[:2000]
    text = re.sub(r"\d+", "{n}", text)
    return hashlib.sha256(f"{status_code}:{normalized}:{text}".encode("utf-8", errors="ignore")).hexdigest()[:20]


class EvidenceStore:
    """Append-only evidence store for safe scanner telemetry and findings."""

    def __init__(self, target: str) -> None:
        self.target = normalize_target(target)
        self.out_dir = cai_output_dir(self.target) / "evidence"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.requests_path = self.out_dir / "requests.jsonl"
        self.responses_path = self.out_dir / "responses.jsonl"
        self.comparisons_path = self.out_dir / "comparisons.jsonl"
        self.findings_path = self.out_dir / "findings.jsonl"
        self.index_path = self.out_dir / "evidence-index.json"
        self.index: dict[str, Any] = {"target": self.target, "items": []}
        if self.index_path.exists():
            try:
                self.index = json.loads(self.index_path.read_text(encoding="utf-8"))
            except Exception:
                pass

    def _append(self, path: Path, item: dict[str, Any]) -> dict[str, Any]:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")
        self.index.setdefault("items", []).append({"id": item.get("id"), "type": item.get("type"), "time": item.get("time"), "path": str(path)})
        self.index["items"] = self.index["items"][-5000:]
        self.index_path.write_text(json.dumps(self.index, indent=2, ensure_ascii=False), encoding="utf-8")
        return item

    def record_request(self, *, method: str, url: str, headers: dict[str, str] | None = None, purpose: str = "") -> str:
        item_id = "req_" + uuid.uuid4().hex[:12]
        self._append(self.requests_path, {"id": item_id, "type": "request", "time": time.time(), "method": method.upper(), "url": url, "headers": {k: redact(v, 300) for k, v in (headers or {}).items()}, "purpose": purpose})
        return item_id

    def record_response(self, *, request_id: str, url: str, status_code: int, headers: dict[str, str], body: str, elapsed_ms: int, error: str = "") -> str:
        item_id = "res_" + uuid.uuid4().hex[:12]
        self._append(self.responses_path, {"id": item_id, "type": "response", "time": time.time(), "request_id": request_id, "url": url, "status_code": status_code, "elapsed_ms": elapsed_ms, "headers": {k: redact(v, 400) for k, v in headers.items()}, "body_hash": body_hash(body), "body_length": len(body or ""), "body_snippet": redact(body, 1200), "error": redact(error, 500)})
        return item_id

    def record_comparison(self, *, baseline_id: str, test_id: str, url: str, parameter: str | None, result: dict[str, Any]) -> str:
        item_id = "cmp_" + uuid.uuid4().hex[:12]
        self._append(self.comparisons_path, {"id": item_id, "type": "comparison", "time": time.time(), "baseline_id": baseline_id, "test_id": test_id, "url": url, "parameter": parameter, "result": result})
        return item_id

    def record_finding(self, finding: dict[str, Any]) -> str:
        item = dict(finding)
        item.setdefault("id", "finding_" + uuid.uuid4().hex[:10])
        item.setdefault("type", "finding")
        item.setdefault("time", time.time())
        item["evidence"] = redact(item.get("evidence", ""), 2000)
        self._append(self.findings_path, item)
        return str(item["id"])

    def write_markdown_index(self) -> Path:
        path = self.out_dir / "evidence-index.md"
        lines = ["# VulnScope Evidence Index", "", f"Target: `{self.target}`", ""]
        counts: dict[str, int] = {}
        for item in self.index.get("items", []):
            item_type = item.get("type", "unknown")
            counts[item_type] = counts.get(item_type, 0) + 1
        for key in sorted(counts):
            lines.append(f"- `{key}`: `{counts[key]}`")
        lines += ["", "## Files", "", f"- Requests: `{self.requests_path}`", f"- Responses: `{self.responses_path}`", f"- Comparisons: `{self.comparisons_path}`", f"- Findings: `{self.findings_path}`"]
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

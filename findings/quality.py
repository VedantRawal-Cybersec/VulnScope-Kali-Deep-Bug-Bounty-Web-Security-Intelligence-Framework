from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse


@dataclass
class FindingRecord:
    title: str
    category: str
    url: str
    evidence: list[str]
    severity: str = "info"
    confidence: float = 0.0
    source: str = "unknown"
    fingerprint: str = ""
    quality_notes: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/") or "/", "", query, ""))


def fingerprint_finding(item: dict[str, Any]) -> str:
    base = "|".join([
        str(item.get("category", "")).lower(),
        str(item.get("title", "")).lower()[:120],
        normalize_url(str(item.get("url", item.get("endpoint", "")))),
    ])
    return hashlib.sha256(base.encode()).hexdigest()[:16]


def quality_score(item: dict[str, Any]) -> tuple[float, list[str]]:
    score = 0.0
    notes: list[str] = []
    evidence = item.get("evidence") or item.get("evidence_refs") or []
    if isinstance(evidence, str):
        evidence = [evidence]
    if evidence:
        score += 0.35
        notes.append("has evidence reference")
    else:
        notes.append("missing evidence reference")
    if item.get("url") or item.get("endpoint"):
        score += 0.2
    else:
        notes.append("missing affected URL/endpoint")
    if item.get("category"):
        score += 0.15
    if item.get("severity") and str(item.get("severity")).lower() != "info":
        score += 0.1
    confidence = float(item.get("confidence", 0.0) or 0.0)
    score += min(confidence, 1.0) * 0.2
    if not evidence and confidence >= 0.7:
        notes.append("high model confidence without evidence; manual review required")
        score -= 0.15
    return max(0.0, min(1.0, score)), notes


def dedupe_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for item in items:
        fp = fingerprint_finding(item)
        item = dict(item)
        item["fingerprint"] = fp
        q, notes = quality_score(item)
        item["quality_score"] = q
        item["quality_notes"] = notes
        if fp not in seen or q > float(seen[fp].get("quality_score", 0.0)):
            seen[fp] = item
    return sorted(seen.values(), key=lambda x: float(x.get("quality_score", 0.0)), reverse=True)


def reduce_low_quality(items: list[dict[str, Any]], threshold: float = 0.45) -> dict[str, Any]:
    deduped = dedupe_findings(items)
    accepted = [i for i in deduped if float(i.get("quality_score", 0.0)) >= threshold]
    review = [i for i in deduped if float(i.get("quality_score", 0.0)) < threshold]
    return {"accepted": accepted, "needs_review": review, "summary": {"input": len(items), "deduped": len(deduped), "accepted": len(accepted), "needs_review": len(review)}}


def load_findings_from_reports(paths: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path in paths:
        p = Path(path)
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        if isinstance(data, list):
            out.extend([x for x in data if isinstance(x, dict)])
        elif isinstance(data, dict):
            for key in ["findings", "candidates", "agent_results", "results"]:
                value = data.get(key)
                if isinstance(value, list):
                    out.extend([x for x in value if isinstance(x, dict)])
    return out

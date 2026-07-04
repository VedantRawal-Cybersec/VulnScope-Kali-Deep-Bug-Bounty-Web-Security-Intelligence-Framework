#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

PHASE_KEYWORDS = {
    "recon": ["subdomain", "dns", "whois", "certificate", "asn", "httpx", "probe", "port scan", "naabu"],
    "discovery": ["crawl", "crawler", "spider", "katana", "url", "wayback", "endpoint", "javascript", "directory", "content discovery", "ffuf", "ferox", "arjun", "parameter"],
    "validation": ["nuclei", "template", "vulnerability scan", "scanner", "xss", "sqli", "cors", "header", "misconfig", "lfi", "ssrf"],
    "reporting": ["report", "dashboard", "html", "markdown", "sarif", "json report"],
}


@dataclass
class PhaseDecision:
    phase: str
    confidence: int
    reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def classify_tool_phase(*, name: str, text: str) -> PhaseDecision:
    haystack = " ".join([name or "", text or ""]).lower()
    scores: dict[str, int] = {phase: 0 for phase in PHASE_KEYWORDS}
    reasons: list[str] = []
    for phase, words in PHASE_KEYWORDS.items():
        for word in words:
            if word in haystack:
                scores[phase] += 1
                reasons.append(f"{phase}: {word}")
    best_phase = max(scores, key=lambda item: scores[item])
    score = scores[best_phase]
    if score == 0:
        return PhaseDecision("discovery", 35, ["no strong phase signal; defaulted to discovery"])
    confidence = min(95, 45 + score * 12)
    return PhaseDecision(best_phase, confidence, reasons[:20])

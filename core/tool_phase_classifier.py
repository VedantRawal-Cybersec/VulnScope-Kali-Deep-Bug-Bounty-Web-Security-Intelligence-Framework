#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

KNOWN_PHASES = {
    "nuclei": "validation",
    "dalfox": "validation",
    "sqlmap": "validation",
    "katana": "discovery",
    "hakrawler": "discovery",
    "gospider": "discovery",
    "arjun": "discovery",
    "ffuf": "discovery",
    "feroxbuster": "discovery",
    "subfinder": "recon",
    "assetfinder": "recon",
    "amass": "recon",
    "httpx": "recon",
    "naabu": "recon",
    "dnsx": "recon",
}

PHASE_KEYWORDS = {
    "recon": {"subdomain": 3, "dns": 2, "whois": 1, "certificate": 1, "asn": 1, "httpx": 5, "probe": 1, "port scan": 2, "naabu": 5},
    "discovery": {"crawl": 4, "crawler": 4, "spider": 4, "katana": 6, "url": 1, "wayback": 3, "endpoint": 3, "javascript": 2, "directory": 3, "content discovery": 4, "ffuf": 6, "ferox": 6, "arjun": 6, "parameter": 3},
    "validation": {"nuclei": 12, "template": 5, "vulnerability scan": 8, "vulnerability scanner": 8, "scanner": 2, "xss": 5, "sqli": 5, "sql injection": 5, "cors": 4, "header": 2, "misconfig": 4, "lfi": 4, "ssrf": 4, "cve": 5},
    "reporting": {"report": 3, "dashboard": 3, "html": 1, "markdown": 1, "sarif": 4, "json report": 4},
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
    reasons: list[str] = []
    for known, phase in KNOWN_PHASES.items():
        if known in haystack:
            return PhaseDecision(phase, 96, [f"known tool signal: {known} -> {phase}"])
    scores: dict[str, int] = {phase: 0 for phase in PHASE_KEYWORDS}
    for phase, words in PHASE_KEYWORDS.items():
        for word, weight in words.items():
            if word in haystack:
                scores[phase] += weight
                reasons.append(f"{phase}: {word} (+{weight})")
    best_phase = max(scores, key=lambda item: scores[item])
    score = scores[best_phase]
    if score == 0:
        return PhaseDecision("discovery", 35, ["no strong phase signal; defaulted to discovery"])
    confidence = min(95, 45 + score * 5)
    return PhaseDecision(best_phase, confidence, reasons[:30])

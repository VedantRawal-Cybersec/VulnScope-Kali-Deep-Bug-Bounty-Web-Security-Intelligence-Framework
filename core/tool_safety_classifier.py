#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

BLOCK_WORDS = {
    "reverse shell", "payload generator", "persistence", "privilege escalation",
    "credential stuffing", "bruteforce", "brute force", "password spray", "keylogger",
    "ransomware", "botnet", "stealer", "miner", "ddos", "dos attack", "wiper",
}
KNOWN_SAFE_ACTIVE = {"nuclei", "katana", "httpx", "ffuf", "ferox", "arjun", "naabu", "dnsx"}
KNOWN_PASSIVE = {"subfinder", "assetfinder", "waybackurls", "gau", "amass"}
KNOWN_LAB_ONLY = {"sqlmap", "dalfox"}
LAB_ONLY_WORDS = {
    "sql injection", "sqli", "xss", "ssti", "ssrf", "rce", "exploit", "exploitation",
    "command injection", "lfi", "rfi", "fuzz", "fuzzer",
}
PASSIVE_WORDS = {
    "subdomain", "dns", "whois", "certificate", "passive", "crawler", "spider",
    "javascript", "js", "endpoint", "archive", "wayback", "url discovery",
}
SAFE_ACTIVE_WORDS = {
    "http probe", "httpx", "katana", "nuclei", "scanner", "template", "header", "cors",
    "directory", "content discovery", "ffuf", "ferox", "param", "arjun", "vulnerability scanner",
}


@dataclass
class SafetyDecision:
    safety_level: str
    required_scan_mode: str
    auto_approve_run: bool
    blocked: bool
    reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def classify_tool_safety(*, name: str, text: str, commands: list[str] | None = None) -> SafetyDecision:
    """Classify a GitHub tool for VulnScope's consent-gated scheduler.

    This uses known-tool overrides and weighted signals. Unknown tools remain
    manual-review. Compatible safe-active tools still require explicit run
    approval unless the operator uses the approval flag.
    """
    haystack = " ".join([name or "", text or "", " ".join(commands or [])]).lower()
    reasons: list[str] = []
    for word in sorted(BLOCK_WORDS):
        if word in haystack:
            reasons.append(f"blocked keyword: {word}")
    if reasons:
        return SafetyDecision("blocked", "lab", False, True, reasons)
    for known in KNOWN_LAB_ONLY:
        if known in haystack:
            return SafetyDecision("lab-only", "lab", False, False, [f"known lab-only tool: {known}"])
    for known in KNOWN_SAFE_ACTIVE:
        if known in haystack:
            return SafetyDecision("safe-active", "safe-active", False, False, [f"known safe-active tool: {known}"])
    for known in KNOWN_PASSIVE:
        if known in haystack:
            return SafetyDecision("passive", "passive", False, False, [f"known passive tool: {known}"])
    scores = {"passive": 0, "safe-active": 0, "lab-only": 0}
    for word in PASSIVE_WORDS:
        if word in haystack:
            scores["passive"] += 1
            reasons.append(f"passive signal: {word}")
    for word in SAFE_ACTIVE_WORDS:
        if word in haystack:
            scores["safe-active"] += 3
            reasons.append(f"safe-active signal: {word}")
    for word in LAB_ONLY_WORDS:
        if word in haystack:
            scores["lab-only"] += 2
            reasons.append(f"validation/lab signal: {word}")
    best = max(scores, key=lambda key: scores[key])
    if scores[best] == 0:
        return SafetyDecision("manual-review", "safe-active", False, False, ["unknown tool behavior; manual approval required"])
    if best == "passive":
        return SafetyDecision("passive", "passive", False, False, reasons[:20])
    if best == "safe-active":
        return SafetyDecision("safe-active", "safe-active", False, False, reasons[:20])
    return SafetyDecision("lab-only", "lab", False, False, reasons[:20])

#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

BLOCK_WORDS = {
    "reverse shell", "payload generator", "persistence", "privilege escalation",
    "credential stuffing", "bruteforce", "brute force", "password spray", "keylogger",
    "ransomware", "botnet", "stealer", "miner", "ddos", "dos attack", "wiper",
}
LAB_ONLY_WORDS = {
    "sql injection", "sqli", "xss", "ssti", "ssrf", "rce", "exploit", "exploitation",
    "command injection", "lfi", "rfi", "dalfox", "sqlmap", "nuclei", "fuzz", "fuzzer",
}
PASSIVE_WORDS = {
    "subdomain", "dns", "whois", "certificate", "passive", "crawler", "spider",
    "javascript", "js", "endpoint", "archive", "wayback", "url discovery",
}
SAFE_ACTIVE_WORDS = {
    "http probe", "httpx", "katana", "nuclei", "scanner", "template", "header", "cors",
    "directory", "content discovery", "ffuf", "ferox", "param", "arjun",
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

    The classifier is intentionally conservative. Unknown tools are not blocked,
    but they require manual run approval unless the probe and manifest are clear.
    """
    haystack = " ".join([name or "", text or "", " ".join(commands or [])]).lower()
    reasons: list[str] = []
    for word in sorted(BLOCK_WORDS):
        if word in haystack:
            reasons.append(f"blocked keyword: {word}")
    if reasons:
        return SafetyDecision("blocked", "lab", False, True, reasons)
    for word in sorted(PASSIVE_WORDS):
        if word in haystack:
            reasons.append(f"passive signal: {word}")
            return SafetyDecision("passive", "passive", False, False, reasons)
    for word in sorted(SAFE_ACTIVE_WORDS):
        if word in haystack:
            reasons.append(f"safe-active signal: {word}")
            return SafetyDecision("safe-active", "safe-active", False, False, reasons)
    for word in sorted(LAB_ONLY_WORDS):
        if word in haystack:
            reasons.append(f"validation/lab signal: {word}")
            return SafetyDecision("lab-only", "lab", False, False, reasons)
    return SafetyDecision("manual-review", "safe-active", False, False, ["unknown tool behavior; manual approval required"])

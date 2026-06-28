from __future__ import annotations

import shutil
from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class ToolSpec:
    name: str
    binary: str
    purpose: str
    risk_level: str
    requires_approval: bool
    installed: bool
    safe_command_hint: str
    output_note: str


def get_tool_registry() -> list[ToolSpec]:
    specs = [
        ("nmap", "nmap", "port/service visibility for authorized hosts", "controlled-active", True, "nmap -sV -Pn --top-ports 100 <host>", "Use only with authorization and low rate."),
        ("httpx", "httpx", "HTTP probing and web technology detection", "passive-to-controlled", True, "httpx -u <url> -title -tech-detect -status-code", "External binary if installed."),
        ("katana", "katana", "same-scope crawling", "controlled-active", True, "katana -u <url> -d 2 -silent", "Keep depth low."),
        ("nuclei", "nuclei", "template-based safe checks", "controlled-active", True, "nuclei -u <url> -severity info,low,medium -rl 3", "Use curated non-invasive templates only."),
        ("waybackurls", "waybackurls", "historical URL discovery", "passive", False, "echo <domain> | waybackurls", "Passive URL enrichment."),
        ("gau", "gau", "historical URL discovery", "passive", False, "gau <domain>", "Passive URL enrichment."),
        ("subfinder", "subfinder", "passive subdomain discovery", "passive", True, "subfinder -d <domain> -silent", "Run only when subdomains are in scope."),
        ("ffuf", "ffuf", "controlled content discovery", "controlled-active", True, "ffuf -u <url>/FUZZ -w <small_wordlist> -rate 5", "Approval required; rate-limited only."),
        ("zap-baseline.py", "zap-baseline.py", "baseline web security checks", "controlled-active", True, "zap-baseline.py -t <url> -r zap-baseline.html", "Baseline mode only."),
    ]
    return [ToolSpec(name, binary, purpose, risk, approval, shutil.which(binary) is not None, hint, note) for name, binary, purpose, risk, approval, hint, note in specs]


def registry_as_dict() -> list[dict]:
    return [asdict(tool) for tool in get_tool_registry()]


def recommended_tools_for_evidence(evidence: dict) -> list[ToolSpec]:
    registry = {tool.name: tool for tool in get_tool_registry()}
    endpoints = evidence.get("endpoints", []) if isinstance(evidence, dict) else []
    findings = evidence.get("findings", []) if isinstance(evidence, dict) else []
    names = ["waybackurls", "gau", "httpx", "katana"]
    text = str(endpoints[:80]) + str(findings[:40])
    lowered = text.lower()
    if "api" in lowered or "swagger" in lowered or "openapi" in lowered:
        names.append("nuclei")
    if "admin" in lowered or "login" in lowered or "upload" in lowered:
        names.append("ffuf")
    return [registry[name] for name in names if name in registry]

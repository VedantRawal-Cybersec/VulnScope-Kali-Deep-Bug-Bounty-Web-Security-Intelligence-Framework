from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, asdict
from typing import Any

from core.evidence_store import EvidenceStore, Finding


TRUSTED_TOOLS = {
    "nuclei": "Template-based detection and misconfiguration checks",
    "katana": "Advanced crawling and JavaScript-aware discovery",
    "httpx": "HTTP probing and enrichment",
    "ffuf": "Controlled content and parameter discovery",
    "dalfox": "XSS signal collection and parameter analysis",
    "zap-baseline.py": "OWASP ZAP baseline checks",
    "sqlmap": "Restricted detection-only SQLi signal validation for lab mode only",
}


@dataclass
class ToolStatus:
    name: str
    role: str
    installed: bool
    path: str | None
    version_hint: str | None
    activation: str


def collect_external_tool_status(store: EvidenceStore) -> None:
    """Detect trusted tools without executing scans.

    This module only checks whether supported tools exist and tries short version
    checks. It does not scan targets and does not run untrusted commands.
    """
    statuses: list[ToolStatus] = []

    for tool, role in TRUSTED_TOOLS.items():
        path = shutil.which(tool)
        version_hint = _safe_version_hint(tool) if path else None
        activation = "available_review_required" if path else "not_installed"
        if tool == "sqlmap" and path:
            activation = "lab_only_review_required"
        statuses.append(
            ToolStatus(
                name=tool,
                role=role,
                installed=bool(path),
                path=path,
                version_hint=version_hint,
                activation=activation,
            )
        )

    store.metadata["external_tool_status"] = [asdict(status) for status in statuses]

    installed = [status for status in statuses if status.installed]
    if installed:
        store.add_finding(
            Finding(
                finding_id=store.next_finding_id(),
                title="Trusted External Tools Detected",
                category="Tool Orchestration Readiness",
                severity="Info",
                confidence="High",
                status="Discovered",
                endpoint="Local Kali environment",
                where_found="System PATH tool detection",
                how_detected=["Supported tools were detected in the local environment without running any target scan"],
                why_risky="This is not a vulnerability. It shows which trusted tools can later be integrated through controlled, scope-aware orchestration.",
                evidence={"installed_tools": [asdict(status) for status in installed]},
                recommended_validation=["Review each tool before enabling it for bug bounty workflows."],
                remediation=["No remediation required. Keep unknown tools disabled by default."],
            )
        )


def _safe_version_hint(tool: str) -> str | None:
    candidates = ([tool, "-version"], [tool, "--version"], [tool, "-h"])
    for command in candidates:
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=3,
                check=False,
            )
            output = (result.stdout or "").strip().splitlines()
            if output:
                return output[0][:160]
        except (OSError, subprocess.SubprocessError):
            continue
    return None

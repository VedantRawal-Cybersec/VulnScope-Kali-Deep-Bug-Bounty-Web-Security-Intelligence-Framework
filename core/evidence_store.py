from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    finding_id: str
    title: str
    category: str
    severity: str
    confidence: str
    status: str
    endpoint: str
    method: str = "GET"
    parameter: str | None = None
    where_found: str = ""
    how_detected: list[str] = field(default_factory=list)
    why_risky: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    recommended_validation: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)


class EvidenceStore:
    def __init__(self) -> None:
        self.endpoints: set[str] = set()
        self.parameters: dict[str, list[str]] = {}
        self.forms: list[dict[str, Any]] = []
        self.findings: list[Finding] = []
        self.metadata: dict[str, Any] = {}

    def add_endpoint(self, url: str) -> None:
        self.endpoints.add(url)

    def add_parameter(self, endpoint: str, parameter: str) -> None:
        self.parameters.setdefault(endpoint, [])
        if parameter not in self.parameters[endpoint]:
            self.parameters[endpoint].append(parameter)

    def add_form(self, form: dict[str, Any]) -> None:
        self.forms.append(form)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def next_finding_id(self) -> str:
        return f"VS-{len(self.findings) + 1:03d}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata,
            "endpoints": sorted(self.endpoints),
            "parameters": self.parameters,
            "forms": self.forms,
            "findings": [asdict(finding) for finding in self.findings],
        }

    def write_json(self, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

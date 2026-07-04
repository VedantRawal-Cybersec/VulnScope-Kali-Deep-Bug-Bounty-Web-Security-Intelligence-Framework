#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.ai_brain import AIBrain


class ReportGenerator:
    def __init__(self, brain: AIBrain | None = None) -> None:
        self.brain = brain or AIBrain()

    def cvss_score(self, finding: dict[str, Any]) -> float:
        severity = str(finding.get("severity") or "INFO").upper()
        try:
            confidence = float(finding.get("confidence", finding.get("confidence_score", 0)) or 0)
        except Exception:
            confidence = 0.0
        if confidence > 1:
            confidence = confidence / 100.0
        base = {"CRITICAL": 9.3, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.1, "INFO": 0.0}.get(severity, 0.0)
        if confidence >= 0.9:
            return round(base, 1)
        if confidence >= 0.7:
            return round(max(0.0, base - 0.5), 1)
        if confidence >= 0.4:
            return round(max(0.0, base - 1.5), 1)
        return round(max(0.0, base - 3.0), 1)

    def normalize_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        item = dict(finding)
        item.setdefault("title", item.get("type") or item.get("name") or "Security Finding")
        item.setdefault("severity", "INFO")
        item.setdefault("confidence", item.get("confidence_score", 0))
        item.setdefault("affected_url", item.get("url") or item.get("endpoint") or "")
        item.setdefault("parameter", item.get("param") or item.get("parameter") or "")
        item.setdefault("evidence", item.get("evidence") or item.get("description") or "")
        item["cvss"] = self.cvss_score(item)
        return item

    def generate_executive_summary(self, target: str, findings: list[dict[str, Any]]) -> str:
        prompt = "Write a concise executive summary for this authorized security assessment. Include severity distribution and business impact. Target: " + target + "\nFindings:\n" + json.dumps(findings[:50], indent=2, ensure_ascii=False)
        answer = self.brain.ask_ollama(prompt)
        if answer:
            return answer
        counts: dict[str, int] = {}
        for finding in findings:
            sev = str(finding.get("severity") or "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return "Assessment completed. Severity distribution: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))

    def finding_section(self, index: int, finding: dict[str, Any]) -> str:
        title = finding.get("title", "Security Finding")
        severity = str(finding.get("severity") or "INFO").upper()
        affected = finding.get("affected_url") or finding.get("url") or "N/A"
        parameter = finding.get("parameter") or "N/A"
        evidence = finding.get("evidence") or "N/A"
        prompt = "Create safe reproduction steps, business impact, and remediation guidance for this report finding. Keep it concise and do not invent evidence.\n" + json.dumps(finding, indent=2, ensure_ascii=False)
        ai = self.brain.ask_ollama(prompt)
        if not ai:
            ai = "### Reproduction Steps\n1. Open the affected endpoint inside the authorized scope.\n2. Review the captured evidence and tool output.\n3. Manually validate behavior before submission.\n\n### Business Impact\nRisk depends on affected data, exploitability, and authorization boundaries.\n\n### Remediation\nReview the affected component and apply secure configuration or code-level fixes."
        return f"""
## Finding {index}: {title}

- **Severity:** {severity}
- **CVSS:** {finding.get('cvss')}
- **Confidence:** {finding.get('confidence')}
- **Affected URL:** `{affected}`
- **Parameter:** `{parameter}`

### Evidence
```text
{str(evidence)[:3000]}
```

{ai}
""".strip()

    def generate_markdown(self, target: str, findings: list[dict[str, Any]], context: dict[str, Any] | None = None) -> str:
        normalized = [self.normalize_finding(item) for item in findings]
        normalized.sort(key=lambda item: float(item.get("cvss", 0)), reverse=True)
        summary = self.generate_executive_summary(target, normalized)
        lines = [
            "# VulnScope Security Assessment Report",
            "",
            f"- **Target:** `{target}`",
            f"- **Generated:** `{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}`",
            f"- **Findings:** `{len(normalized)}`",
            "",
            "## Executive Summary",
            "",
            summary,
            "",
            "## Assessment Context",
            "",
            "```json",
            json.dumps(context or {}, indent=2, ensure_ascii=False)[:5000],
            "```",
            "",
            "## Findings",
            "",
        ]
        if not normalized:
            lines.extend(["No confirmed findings were captured. Review scan-health.json and dynamic-tool-phase-summary.json for coverage gaps.", ""])
        else:
            for index, finding in enumerate(normalized, 1):
                lines.append(self.finding_section(index, finding))
                lines.append("")
        lines.extend(["## Notes", "", "- This report is intended for owned or explicitly authorized security testing.", "- Findings should be manually validated before third-party submission."])
        return "\n".join(lines)

    def write_report(self, target: str, findings: list[dict[str, Any]], out_dir: str | Path | None = None, context: dict[str, Any] | None = None) -> Path:
        if out_dir is None:
            host = urlparse(target if "://" in target else "https://" + target).hostname or "target"
            out_dir = Path("reports/output") / host
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        path = out / "final-report.md"
        path.write_text(self.generate_markdown(target, findings, context=context), encoding="utf-8")
        return path

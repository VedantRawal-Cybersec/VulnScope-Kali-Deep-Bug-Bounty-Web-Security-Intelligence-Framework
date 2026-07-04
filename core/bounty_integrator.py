#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import requests


class BountyIntegrator:
    def __init__(self, platform: str, api_key: str | None = None, base_url: str | None = None) -> None:
        self.platform = platform.lower().strip()
        self.api_key = api_key or os.getenv("BOUNTY_API_KEY", "")
        self.base_url = base_url or os.getenv("BOUNTY_API_BASE", "")
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"Authorization": f"Bearer {self.api_key}"})
        self.session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})

    def _default_base_url(self) -> str:
        if self.base_url:
            return self.base_url.rstrip("/")
        if self.platform == "hackerone":
            return "https://api.hackerone.com"
        if self.platform == "bugcrowd":
            return "https://api.bugcrowd.com"
        raise ValueError("Unsupported bounty platform. Use hackerone or bugcrowd.")

    def _highest_severity(self, findings: list[dict[str, Any]]) -> str:
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        best = "INFO"
        for finding in findings:
            sev = str(finding.get("severity") or "INFO").upper()
            if sev in order and order.index(sev) > order.index(best):
                best = sev
        return best

    def build_payload(self, program: str, report_path: str | Path, target: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
        report_text = Path(report_path).read_text(encoding="utf-8", errors="ignore")
        return {"program": program, "target": target, "title": f"VulnScope Security Assessment Report for {target}", "body": report_text, "findings": findings, "severity": self._highest_severity(findings), "tool": "VulnScope"}

    def submit_report(self, *, program: str, report_path: str | Path, target: str, findings: list[dict[str, Any]], confirm: bool = False) -> dict[str, Any]:
        if not confirm:
            return {"ok": False, "status": "cancelled", "reason": "confirmation required"}
        if not self.api_key:
            return {"ok": False, "status": "failed", "reason": "missing API key"}
        if not Path(report_path).exists():
            return {"ok": False, "status": "failed", "reason": f"report not found: {report_path}"}
        base = self._default_base_url()
        payload = self.build_payload(program, report_path, target, findings)
        if self.platform == "hackerone":
            url = f"{base}/v1/hackers/programs/{program}/reports"
        elif self.platform == "bugcrowd":
            url = f"{base}/programs/{program}/submissions"
        else:
            return {"ok": False, "status": "failed", "reason": "unsupported platform"}
        try:
            response = self.session.post(url, data=json.dumps(payload), timeout=45)
            return {"ok": response.status_code in {200, 201, 202}, "status_code": response.status_code, "url": url, "response": response.text[:5000]}
        except Exception as exc:
            return {"ok": False, "status": "failed", "error": str(exc)}

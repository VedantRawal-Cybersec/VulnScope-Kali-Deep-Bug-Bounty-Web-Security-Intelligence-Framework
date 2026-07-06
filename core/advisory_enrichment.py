#!/usr/bin/env python3
from __future__ import annotations

import csv
import io
import json
import os
import time
from pathlib import Path
from typing import Any

import requests


class AdvisoryEnrichment:
    """Adds public risk intelligence signals to detected advisory leads."""

    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_URL = "https://api.first.org/data/v1/epss"

    def __init__(self, *, state: Any, dashboard: Any | None = None) -> None:
        self.state = state
        self.dashboard = dashboard
        self.target = getattr(state, "target", "")
        self.out_dir = Path(getattr(state, "out_dir", "reports/output"))
        self.rows: list[dict[str, Any]] = []
        self.errors: list[dict[str, str]] = []

    def dash(self, action: str) -> None:
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(phase="Advisory Enrichment", phase_progress=79, current_agent="AdvisoryEnrichmentAgent", current_tool="advisory_enrichment", action=action, endpoint=self.target, safety_status="public advisory metadata lookup")
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO", action)

    def candidate_cves(self) -> list[str]:
        cves: set[str] = set()
        for path in [self.out_dir / "technology-intelligence.json"]:
            if not path.exists():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
                for row in data.get("advisories", []) or []:
                    cid = str(row.get("id") or "")
                    if cid.startswith("CVE-"):
                        cves.add(cid)
            except Exception:
                continue
        return sorted(cves)[:100]

    def fetch_kev(self) -> dict[str, Any]:
        try:
            res = requests.get(self.CISA_KEV_URL, timeout=10, headers={"User-Agent": "VulnScope-Advisory-Enrichment/1.0"})
            if res.status_code != 200:
                return {}
            data = res.json()
            return {row.get("cveID"): row for row in data.get("vulnerabilities", []) if row.get("cveID")}
        except Exception as exc:
            self.errors.append({"stage": "cisa_kev", "error": str(exc)[:300]})
            return {}

    def fetch_epss(self, cve: str) -> dict[str, Any]:
        try:
            res = requests.get(self.EPSS_URL, params={"cve": cve}, timeout=10, headers={"User-Agent": "VulnScope-Advisory-Enrichment/1.0"})
            if res.status_code != 200:
                return {}
            data = res.json()
            rows = data.get("data", []) or []
            return rows[0] if rows else {}
        except Exception as exc:
            self.errors.append({"stage": "epss", "cve": cve, "error": str(exc)[:300]})
            return {}

    def run(self) -> dict[str, Any]:
        if os.getenv("VULNSCOPE_DISABLE_ADVISORY_ENRICHMENT", "0") == "1":
            reports = self.write_reports(skipped=True, reason="disabled")
            return {"ok": True, "skipped": True, "reports": reports}
        cves = self.candidate_cves()
        self.dash("Enriching public advisory leads")
        kev = self.fetch_kev() if cves else {}
        for cve in cves:
            epss = self.fetch_epss(cve)
            kev_row = kev.get(cve, {})
            self.rows.append({"cve": cve, "known_exploited": bool(kev_row), "kev": kev_row, "epss": epss})
        reports = self.write_reports(skipped=False)
        try:
            self.state.stats["advisory_enriched"] = len(self.rows)
            self.state.save()
        except Exception:
            pass
        return {"ok": True, "items": len(self.rows), "errors": len(self.errors), "reports": reports}

    def write_reports(self, *, skipped: bool, reason: str = "") -> dict[str, str]:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        payload = {"target": self.target, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "skipped": skipped, "reason": reason, "items": self.rows, "errors": self.errors}
        json_path = self.out_dir / "advisory-enrichment.json"
        md_path = self.out_dir / "advisory-enrichment.md"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        lines = ["# Advisory Enrichment", "", f"Skipped: `{skipped}`", f"Reason: `{reason}`", f"Items: `{len(self.rows)}`", "", "## Items", ""]
        for row in self.rows[:100]:
            epss = row.get("epss") or {}
            lines.append(f"- `{row['cve']}` known_exploited=`{row['known_exploited']}` epss=`{epss.get('epss','')}` percentile=`{epss.get('percentile','')}`")
        if not self.rows:
            lines.append("No advisory items were enriched.")
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return {"advisory_enrichment_json": str(json_path), "advisory_enrichment_md": str(md_path)}

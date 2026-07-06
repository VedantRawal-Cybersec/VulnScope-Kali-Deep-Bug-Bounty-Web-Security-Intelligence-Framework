#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class TechnologyTestPlanner:
    """Creates a deterministic next-step plan from detected technology evidence."""

    RULES = {
        "wordpress": ["Review public plugin/theme exposure", "Check common hardening headers", "Prioritize advisory validation if version is known"],
        "next.js": ["Inspect _next static manifests", "Review client-side routes", "Prioritize browser network capture"],
        "react": ["Prioritize browser network capture", "Map API calls from JS bundles"],
        "vue.js": ["Prioritize browser network capture", "Map API calls from JS bundles"],
        "angular": ["Prioritize browser network capture", "Map API calls from JS bundles"],
        "cloudflare": ["Record CDN/WAF posture", "Use conservative timing", "Treat origin information as not directly visible"],
        "nginx": ["Review server header exposure", "Check TLS and header hardening"],
        "apache http server": ["Review server header exposure", "Check TLS and header hardening"],
        "graphql": ["Prioritize GraphQL endpoint inventory", "Do not execute mutation operations"],
    }

    def __init__(self, *, state: Any, dashboard: Any | None = None) -> None:
        self.state = state
        self.dashboard = dashboard
        self.target = getattr(state, "target", "")
        self.out_dir = Path(getattr(state, "out_dir", "reports/output"))
        self.plan: list[dict[str, Any]] = []

    def detected(self) -> list[str]:
        path = self.out_dir / "technology-intelligence.json"
        names: list[str] = []
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
                for item in data.get("technologies", []) or []:
                    name = str(item.get("name") or "").strip()
                    if name:
                        names.append(name)
            except Exception:
                pass
        return names

    def run(self) -> dict[str, Any]:
        names = self.detected()
        for name in names:
            low = name.lower()
            for key, steps in self.RULES.items():
                if key in low:
                    self.plan.append({"technology": name, "rule": key, "steps": steps})
        if not self.plan:
            self.plan.append({"technology": "generic", "rule": "default", "steps": ["Complete surface mapping", "Run API discovery", "Review access matrix if profiles are supplied", "Check final scorecard and coverage gaps"]})
        reports = self.write_reports()
        try:
            self.state.stats["technology_plan_items"] = len(self.plan)
            self.state.save()
        except Exception:
            pass
        return {"ok": True, "items": len(self.plan), "reports": reports}

    def write_reports(self) -> dict[str, str]:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        payload = {"target": self.target, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "plan": self.plan}
        json_path = self.out_dir / "technology-test-plan.json"
        md_path = self.out_dir / "technology-test-plan.md"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        lines = ["# Technology Driven Test Plan", "", f"Items: `{len(self.plan)}`", ""]
        for item in self.plan:
            lines.append(f"## {item['technology']}")
            for step in item["steps"]:
                lines.append("- " + step)
            lines.append("")
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return {"technology_test_plan_json": str(json_path), "technology_test_plan_md": str(md_path)}

#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.engines.research_profiles import RESEARCH_PROFILES, ResearchProfile, all_profiles, profiles_by_phase
from core.tool_registry import ToolRegistry


@dataclass
class ResearchDecision:
    profile: str
    repository: str
    phase: str
    action: str
    rationale: str
    dynamic_tools: list[str] = field(default_factory=list)
    confidence: int = 60
    evidence: dict[str, Any] = field(default_factory=dict)


class UnifiedResearchOrchestrator:
    """Native decision-making layer inspired by public security frameworks.

    This class does not copy or embed exploit/payload logic from third-party
    projects. It converts their high-level orchestration patterns into safe,
    evidence-first VulnScope decisions and delegates offensive execution to
    separately installed, approved dynamic tools.
    """

    def __init__(self, *, state: Any, dashboard: Any | None = None, registry: ToolRegistry | None = None) -> None:
        self.state = state
        self.dashboard = dashboard
        self.registry = registry or ToolRegistry()
        self.out_dir = Path(getattr(state, "out_dir", Path("reports/output/research")))
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.decisions: list[ResearchDecision] = []

    def _surface(self) -> dict[str, Any]:
        urls = list(getattr(self.state, "urls", {}).values())
        params = list(getattr(self.state, "params", {}).values())
        paths = sorted({urlparse(item.url).path or "/" for item in urls if getattr(item, "url", "")})
        api_urls = [item.url for item in urls if "/api/" in (urlparse(item.url).path or "").lower() or "graphql" in (urlparse(item.url).path or "").lower()]
        interesting = []
        for item in urls:
            path = (urlparse(item.url).path or "/").lower()
            if any(token in path for token in ["admin", "login", "auth", "upload", "api", "download", "file", "user", "account", "graphql"]):
                interesting.append(item.url)
        return {
            "urls_total": len(urls),
            "paths_total": len(paths),
            "params_total": len(params),
            "api_urls_total": len(api_urls),
            "interesting_urls": interesting[:30],
            "paths_sample": paths[:40],
            "params_sample": [getattr(item, "name", "") for item in params[:50]],
            "enabled_dynamic_tools": [tool.name for tool in self.registry.list(enabled_only=True)],
        }

    def _dashboard(self, phase: str, message: str, evidence: str) -> None:
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(
                phase="Unified Research Orchestrator",
                current_agent="UnifiedResearchOrchestrator",
                current_tool="unified_research_orchestrator",
                decision=phase,
                action=message,
                evidence=evidence,
                safety_status="decision layer only • no embedded exploit payloads • external tools remain approval-gated",
                findings=len(getattr(self.state, "findings", [])),
            )
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO", message)

    def _matching_dynamic_tools(self, profile: ResearchProfile) -> list[str]:
        installed = self.registry.list(enabled_only=True)
        names = [tool.name.lower() for tool in installed]
        matches: list[str] = []
        for preferred in profile.preferred_dynamic_tools:
            preferred_l = preferred.lower()
            for tool in installed:
                if preferred_l in tool.name.lower() or preferred_l in tool.tool_id.lower():
                    matches.append(tool.tool_id)
        if not matches and names:
            for tool in installed[:3]:
                matches.append(tool.tool_id)
        return sorted(set(matches))

    def _decision_for_profile(self, profile: ResearchProfile, phase: str, surface: dict[str, Any]) -> ResearchDecision:
        tools = self._matching_dynamic_tools(profile)
        signal = surface.get("params_total", 0) + surface.get("api_urls_total", 0) * 2 + len(surface.get("interesting_urls", []))
        confidence = min(92, 55 + int(signal))
        action = "create_review_plan"
        if tools:
            action = "delegate_to_approved_dynamic_tools"
        if phase == "reporting":
            action = "normalize_findings_and_write_report_sections"
        rationale = "; ".join(profile.decision_rules[:3])
        return ResearchDecision(
            profile=profile.name,
            repository=profile.repository,
            phase=phase,
            action=action,
            rationale=rationale,
            dynamic_tools=tools,
            confidence=confidence,
            evidence={
                "family": profile.family,
                "core_logic": profile.core_logic,
                "expected_outputs": profile.evidence_outputs,
                "surface": surface,
            },
        )

    def run_phase(self, phase: str) -> dict[str, Any]:
        surface = self._surface()
        selected = profiles_by_phase(phase)
        phase_decisions = [self._decision_for_profile(profile, phase, surface) for profile in selected]
        self.decisions.extend(phase_decisions)
        self._dashboard(phase, f"Generated {len(phase_decisions)} research decisions for {phase}", json.dumps({"phase": phase, "decisions": len(phase_decisions), "surface": surface}, ensure_ascii=False)[:1200])
        return {
            "phase": phase,
            "decisions": [asdict(item) for item in phase_decisions],
            "surface": surface,
        }

    def run_all(self) -> dict[str, Any]:
        grouped: dict[str, Any] = {}
        for phase in ["recon", "discovery", "validation", "reporting"]:
            grouped[phase] = self.run_phase(phase)
        return self.write_reports(extra={"grouped": grouped})

    def write_reports(self, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {
            "generated_at": time.time(),
            "objective": "safe orchestration and decision-making consolidation",
            "copied_offensive_code": False,
            "embedded_attack_payloads": False,
            "profiles": all_profiles(),
            "decisions": [asdict(item) for item in self.decisions],
        }
        if extra:
            payload.update(extra)
        json_path = self.out_dir / "unified-research-orchestration.json"
        md_path = self.out_dir / "unified-research-orchestration.md"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        lines = ["# Unified Research Orchestration", "", "This report consolidates orchestration patterns from public security tooling into safe VulnScope decision profiles.", "", "## Safety Boundary", "", "- No third-party exploit source code was copied into VulnScope core.", "- No attack payloads are embedded in these profiles.", "- Offensive execution remains delegated to separately installed, approved dynamic tools.", "", "## Decisions"]
        for decision in self.decisions:
            lines.append(f"- **{decision.phase} / {decision.profile}**: `{decision.action}` confidence=`{decision.confidence}` tools=`{', '.join(decision.dynamic_tools) or 'none'}`")
            lines.append(f"  - Rationale: {decision.rationale}")
        md_path.write_text("\n".join(lines), encoding="utf-8")
        payload["json_path"] = str(json_path)
        payload["markdown_path"] = str(md_path)
        try:
            self.state.stats["unified_research_orchestration"] = {"decisions": len(self.decisions), "json_path": str(json_path), "markdown_path": str(md_path)}
            self.state.save()
        except Exception:
            pass
        return payload

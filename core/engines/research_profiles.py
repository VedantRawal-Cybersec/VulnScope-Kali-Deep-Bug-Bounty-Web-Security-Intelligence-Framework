#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ResearchProfile:
    name: str
    repository: str
    family: str
    phases: list[str]
    core_logic: list[str]
    decision_rules: list[str]
    evidence_outputs: list[str]
    preferred_dynamic_tools: list[str] = field(default_factory=list)
    safe_notes: str = "Decision-layer profile only; offensive actions remain delegated to approved external tools."

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


RESEARCH_PROFILES: list[ResearchProfile] = [
    ResearchProfile(
        name="Strix",
        repository="https://github.com/usestrix/strix.git",
        family="agentic-orchestration",
        phases=["recon", "discovery", "validation", "reporting"],
        core_logic=["multi-step planning", "tool-result triage", "finding normalization", "phase handoff"],
        decision_rules=["prefer high-signal assets first", "run discovery before validation", "downgrade weak tool output to review lead"],
        evidence_outputs=["tool plan", "triage notes", "validated finding candidates"],
        preferred_dynamic_tools=["nuclei", "katana", "httpx"],
    ),
    ResearchProfile(
        name="Raptor Framework",
        repository="https://github.com/raptor-framework/raptor.git",
        family="workflow-orchestration",
        phases=["recon", "discovery", "validation"],
        core_logic=["module sequencing", "stateful workflow", "retry/fallback routing"],
        decision_rules=["continue after module failure", "promote endpoints with parameters", "record skipped reasons"],
        evidence_outputs=["phase state", "module status", "retry summary"],
        preferred_dynamic_tools=["nmap", "ffuf", "nuclei"],
    ),
    ResearchProfile(
        name="AI-VAPT",
        repository="https://github.com/vikramrajkumarmajji/AI-VAPT.git",
        family="ai-vapt-planning",
        phases=["discovery", "validation", "reporting"],
        core_logic=["AI-assisted prioritization", "surface summarization", "report drafting"],
        decision_rules=["prioritize authentication, upload, admin, API, and object-id routes", "only trust evidence-backed observations"],
        evidence_outputs=["AI plan", "surface summary", "report recommendations"],
        preferred_dynamic_tools=["nuclei", "sqlmap", "dalfox"],
    ),
    ResearchProfile(
        name="HexStrike AI",
        repository="https://github.com/santhosh-ceo/Hexstrike-AI.git",
        family="agentic-tool-router",
        phases=["recon", "discovery", "validation", "reporting"],
        core_logic=["tool selection", "confidence scoring", "autonomous next-action selection"],
        decision_rules=["map tool output to confidence", "prefer non-overlapping tools", "fallback to passive review if active tool unavailable"],
        evidence_outputs=["tool matrix", "confidence notes", "finding candidates"],
        preferred_dynamic_tools=["nuclei", "katana", "ffuf", "dalfox"],
    ),
    ResearchProfile(
        name="Villager HexStrike AI",
        repository="https://github.com/Yenn503/villager-hexstrike-AI.git",
        family="agentic-tool-router",
        phases=["recon", "discovery", "validation"],
        core_logic=["agent grouping", "tool queueing", "status dashboarding"],
        decision_rules=["group related observations", "queue validation after discovery", "avoid repeated tests"],
        evidence_outputs=["agent queue", "status log", "grouped leads"],
        preferred_dynamic_tools=["nuclei", "ffuf"],
    ),
    ResearchProfile(
        name="AutoPentestFramework",
        repository="https://github.com/ZeroDayZeus/AutoPentestFramework.git",
        family="pentest-workflow",
        phases=["recon", "discovery", "validation", "reporting"],
        core_logic=["phase playbooks", "host/service enumeration", "report assembly"],
        decision_rules=["enumerate before assessment", "separate host/service/app evidence", "write phase summary"],
        evidence_outputs=["playbook result", "service inventory", "phase report"],
        preferred_dynamic_tools=["nmap", "nuclei"],
    ),
    ResearchProfile(
        name="Pentest Google ADK Agent",
        repository="https://github.com/manishmitra017/Pentest-google-adk-agent.git",
        family="agent-framework",
        phases=["recon", "discovery", "reporting"],
        core_logic=["agent task decomposition", "tool-call planning", "memory-backed reporting"],
        decision_rules=["split broad objectives into small safe tasks", "store decisions", "avoid unapproved action classes"],
        evidence_outputs=["agent task graph", "memory summary", "report outline"],
        preferred_dynamic_tools=["katana", "nuclei"],
    ),
    ResearchProfile(
        name="Lethal",
        repository="https://github.com/Zuk4r1/lethal.git",
        family="assessment-automation",
        phases=["discovery", "validation"],
        core_logic=["target classification", "module choice", "result filtering"],
        decision_rules=["classify target type", "prefer relevant module only", "filter low-signal output"],
        evidence_outputs=["classification", "module result", "filtered leads"],
        preferred_dynamic_tools=["nuclei", "ffuf"],
    ),
    ResearchProfile(
        name="HuntBot",
        repository="https://github.com/Matador-og/huntbot.git",
        family="bug-bounty-hunting",
        phases=["recon", "discovery", "validation"],
        core_logic=["bug bounty surface queue", "target expansion", "lead ranking"],
        decision_rules=["rank endpoints by bounty value", "prioritize object references and auth flows", "deduplicate leads"],
        evidence_outputs=["ranked leads", "surface queue", "dedupe summary"],
        preferred_dynamic_tools=["katana", "ffuf", "nuclei"],
    ),
    ResearchProfile(
        name="Claude Bug Bounty",
        repository="https://github.com/Mikacr1138/claude-bug-bounty.git",
        family="llm-bug-bounty-assistant",
        phases=["discovery", "validation", "reporting"],
        core_logic=["LLM triage", "bug report formatting", "evidence sufficiency review"],
        decision_rules=["require reproduction evidence", "separate confirmed from potential", "write concise bug bounty report"],
        evidence_outputs=["triage report", "finding narrative", "impact summary"],
        preferred_dynamic_tools=["nuclei"],
    ),
    ResearchProfile(
        name="Bug Hunter Toolkit",
        repository="https://github.com/codebytaki/bug-hunter-toolkit.git",
        family="toolkit-orchestration",
        phases=["recon", "discovery", "validation"],
        core_logic=["toolkit menu abstraction", "common recon chain", "artifact collection"],
        decision_rules=["run low-cost recon first", "save all artifacts", "only validate high-value leads"],
        evidence_outputs=["artifact index", "tool output", "lead list"],
        preferred_dynamic_tools=["subfinder", "httpx", "katana", "nuclei"],
    ),
    ResearchProfile(
        name="ZeroHuntAI",
        repository="https://github.com/a1k-ghaz1/ZeroHuntAI-WEBSITE-VULNERABILITY-SQLI-XSS-SCANNER-2025.git",
        family="web-vulnerability-triage",
        phases=["discovery", "validation"],
        core_logic=["parameter risk ranking", "reflection and error signal triage", "finding confidence"],
        decision_rules=["rank input-bearing routes higher", "promote reflected harmless canaries", "externalize specialized validators"],
        evidence_outputs=["parameter ranking", "signal comparison", "confidence score"],
        preferred_dynamic_tools=["dalfox", "sqlmap"],
    ),
    ResearchProfile(
        name="CVE-Hunter",
        repository="https://github.com/daik0000/CVE-Hunter.git",
        family="cve-intelligence",
        phases=["recon", "validation", "reporting"],
        core_logic=["technology fingerprinting", "CVE matching", "version evidence"],
        decision_rules=["require version evidence before CVE mapping", "mark unverified CVEs as review leads"],
        evidence_outputs=["tech inventory", "CVE candidates", "version proof"],
        preferred_dynamic_tools=["nuclei"],
    ),
    ResearchProfile(
        name="DeepSubs",
        repository="https://github.com/d3x1er/DeepSubs.git",
        family="subdomain-discovery",
        phases=["recon", "discovery"],
        core_logic=["passive subdomain discovery", "source aggregation", "deduplication"],
        decision_rules=["exact-scope unless subdomains are authorized", "deduplicate before probing", "record source"],
        evidence_outputs=["subdomain inventory", "source map", "dedupe report"],
        preferred_dynamic_tools=["subfinder", "httpx"],
    ),
    ResearchProfile(
        name="SamoScout",
        repository="https://github.com/samogod/samoscout.git",
        family="recon-scouting",
        phases=["recon", "discovery"],
        core_logic=["asset scouting", "URL enrichment", "interesting path ranking"],
        decision_rules=["rank URLs with parameters and API hints", "record path source", "avoid duplicate crawling"],
        evidence_outputs=["asset list", "interesting URLs", "ranked paths"],
        preferred_dynamic_tools=["katana", "ffuf"],
    ),
    ResearchProfile(
        name="ghsubs",
        repository="https://github.com/BountyOS/ghsubs.git",
        family="github-osint-recon",
        phases=["recon"],
        core_logic=["GitHub dork source aggregation", "subdomain extraction", "secret-safe artifact review"],
        decision_rules=["do not collect secrets", "record public source only", "scope-check every host"],
        evidence_outputs=["public-source hits", "subdomain candidates", "scope decision"],
        preferred_dynamic_tools=["gitfive"],
    ),
    ResearchProfile(
        name="Domain Scan",
        repository="https://github.com/valllabh/domain-scan.git",
        family="domain-recon",
        phases=["recon"],
        core_logic=["domain metadata collection", "DNS and web surface inventory", "risk notes"],
        decision_rules=["collect metadata before probing", "respect exact-domain mode", "separate informational from actionable"],
        evidence_outputs=["domain metadata", "DNS inventory", "risk notes"],
        preferred_dynamic_tools=["httpx", "nmap"],
    ),
    ResearchProfile(
        name="WebStrike Framework",
        repository="https://github.com/FlinnZee/webstrike-framework.git",
        family="web-assessment-workflow",
        phases=["discovery", "validation", "reporting"],
        core_logic=["web assessment sequence", "module status", "report collation"],
        decision_rules=["complete discovery before validation", "write tool-status matrix", "collate evidence by endpoint"],
        evidence_outputs=["module matrix", "endpoint evidence", "report sections"],
        preferred_dynamic_tools=["katana", "nuclei", "ffuf"],
    ),
    ResearchProfile(
        name="SecuSploitX",
        repository="https://github.com/Largo-m/SecuSploitX.git",
        family="lab-validation-workflow",
        phases=["validation"],
        core_logic=["lab-only validation queue", "finding classification", "risk escalation"],
        decision_rules=["lab-only for high-risk categories", "never run unapproved modules", "record manual validation steps"],
        evidence_outputs=["validation queue", "risk notes", "manual steps"],
        preferred_dynamic_tools=["nuclei", "dalfox", "sqlmap"],
    ),
    ResearchProfile(
        name="Master OSINT Toolkit",
        repository="https://github.com/techenthusiast167/Master-OSINT-Toolkit-.git",
        family="osint-collection",
        phases=["recon"],
        core_logic=["public-source collection", "artifact indexing", "source traceability"],
        decision_rules=["public sources only", "no credential capture", "keep source links and timestamps"],
        evidence_outputs=["OSINT artifact index", "source notes", "scope-safe leads"],
        preferred_dynamic_tools=["gitfive"],
    ),
    ResearchProfile(
        name="GitFive",
        repository="https://github.com/gitfive/gitfive.git",
        family="github-osint",
        phases=["recon"],
        core_logic=["GitHub identity and repo metadata collection", "public artifact indexing", "scope traceability"],
        decision_rules=["do not collect secrets", "only use public metadata", "treat OSINT as review context"],
        evidence_outputs=["public GitHub metadata", "artifact notes", "review context"],
        preferred_dynamic_tools=["gitfive"],
    ),
]


def profiles_by_phase(phase: str) -> list[ResearchProfile]:
    phase = phase.lower()
    return [profile for profile in RESEARCH_PROFILES if phase in profile.phases]


def profiles_by_family(family: str) -> list[ResearchProfile]:
    family = family.lower()
    return [profile for profile in RESEARCH_PROFILES if profile.family == family]


def all_profiles() -> list[dict[str, Any]]:
    return [profile.to_dict() for profile in RESEARCH_PROFILES]

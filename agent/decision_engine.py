from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from integrations.tool_registry import recommended_tools_for_evidence, registry_as_dict


def load_evidence(path: str = "reports/output/evidence.json") -> dict[str, Any]:
    file_path = Path(path)
    if not file_path.exists():
        return {}
    try:
        return json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}


def build_next_action_plan(evidence_path: str = "reports/output/evidence.json") -> dict[str, Any]:
    evidence = load_evidence(evidence_path)
    endpoints = evidence.get("endpoints", []) if isinstance(evidence, dict) else []
    findings = evidence.get("findings", []) if isinstance(evidence, dict) else []
    forms = evidence.get("forms", []) if isinstance(evidence, dict) else []
    recommended = recommended_tools_for_evidence(evidence)

    actions = []
    actions.append({"name": "Run AI Discovery", "command": "python3 ai_discovery_cli.py --input reports/output/evidence.json", "risk": "internal", "approval_required": False, "why": "AI can inspect current evidence for missed review candidates."})
    actions.append({"name": "Run Mythic Validation", "command": "python3 mythic_hunter_cli.py --input reports/output/evidence.json --depth DEEP_HUNTER_MODE", "risk": "internal", "approval_required": False, "why": "Validation reduces false positives and clarifies required proof."})
    actions.append({"name": "Run Uplift Analyzer", "command": "python3 mythic_uplift_cli.py --input reports/output/evidence.json", "risk": "internal", "approval_required": False, "why": "Uplift maps API, workflow, cache, cloud, and session review candidates."})
    for tool in recommended:
        actions.append({"name": f"Consider {tool.name}", "command": tool.safe_command_hint, "risk": tool.risk_level, "approval_required": tool.requires_approval, "why": tool.purpose, "installed": tool.installed})

    return {
        "evidence_path": evidence_path,
        "summary": {
            "endpoints": len(endpoints),
            "findings": len(findings),
            "forms": len(forms),
            "registered_tools": registry_as_dict(),
        },
        "recommended_actions": actions,
        "rule": "Run only on authorized in-scope assets. Controlled active actions require approval.",
    }

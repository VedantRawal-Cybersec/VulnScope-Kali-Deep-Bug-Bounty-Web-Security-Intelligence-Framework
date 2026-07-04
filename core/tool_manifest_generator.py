#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.ai_tool_analyzer import ToolAnalysis


def generate_manifest(analysis: ToolAnalysis) -> dict[str, Any]:
    """Generate a ToolManifest-compatible manifest from analysis output."""
    run = " ".join(analysis.run_command) if analysis.run_command else ""
    entry_point = analysis.run_command[0] if analysis.run_command else ""
    manifest = {
        "name": analysis.name,
        "version": "unknown",
        "entry_point": entry_point,
        "phase": analysis.phase,
        "output_format": analysis.output_parser,
        "timeout": 240,
        "dependencies": analysis.install_commands,
        "safe_flags": [item for item in analysis.run_command[1:] if item.startswith("-")],
        "run": run,
        "arguments": [{"name": "target", "description": "Target URL or domain", "required": True}],
        "metadata": {
            "generated_by": "VulnScope AI Tool Auto-Configurator",
            "repo_url": analysis.repo_url,
            "language": analysis.language,
            "safety_level": analysis.safety_level,
            "required_scan_mode": analysis.required_scan_mode,
            "analysis_status": analysis.status,
            "analysis_report": analysis.report_path,
            "reasons": analysis.reasons,
            "phase_confidence": analysis.metadata.get("phase_confidence"),
            "auto_approve_run": False,
        },
    }
    return manifest


def write_manifest(analysis: ToolAnalysis) -> str:
    path = Path(analysis.local_path) / "manifest.json"
    manifest = generate_manifest(analysis)
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    analysis.manifest_path = str(path)
    return str(path)

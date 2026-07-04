#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.ai_tool_analyzer import AIToolAnalyzer
from core.tool_manifest_generator import write_manifest
from core.tool_manager import ToolManager


class AIToolAutoConfigurator:
    """End-to-end GitHub tool auto-configurator.

    Contract:
    - Analyze every pasted repo.
    - Configure compatible tools automatically.
    - Never mark broken/unsafe tools READY.
    - Never auto-run a third-party tool against a target during configuration.
    """

    def __init__(self, *, timeout: int = 25, use_llm: bool = True) -> None:
        self.analyzer = AIToolAnalyzer(timeout=timeout, use_llm=use_llm)
        self.manager = ToolManager()

    def configure(self, repo_url: str, *, install: bool = False, approve_install: bool = False, approve_run: bool = False, enable: bool = True) -> dict[str, Any]:
        analysis = self.analyzer.analyze(repo_url, install=install, register=False)
        manifest_path = ""
        tool_payload: dict[str, Any] | None = None
        final_status = analysis.status
        if analysis.status != "BLOCKED":
            manifest_path = write_manifest(analysis)
            analysis.manifest_path = manifest_path
            try:
                tool = self.manager.add_tool(repo_url, approve_install=approve_install, approve_run=False, enable=enable)
                if approve_run and analysis.status == "ANALYZED" and analysis.safety_level in {"passive", "safe-active"}:
                    tool = self.manager.registry.approve(tool.tool_id, install=approve_install, run=True, enable=enable)
                tool_payload = tool.to_dict()
                if analysis.status == "ANALYZED" and tool.run:
                    final_status = "READY" if tool.approved_for_run else "REGISTERED_REQUIRES_APPROVAL"
                elif analysis.status == "ANALYZED":
                    final_status = "NEEDS_MANUAL_REVIEW"
            except Exception as exc:
                final_status = "NEEDS_MANUAL_REVIEW"
                analysis.reasons.append("registration failed: " + str(exc)[:500])
        payload = {
            "repo_url": repo_url,
            "status": final_status,
            "analysis": analysis.to_dict(),
            "manifest_path": manifest_path,
            "registered_tool": tool_payload,
            "guarantee": {
                "silent_failure": False,
                "auto_target_execution": False,
                "ready_requires_manifest_and_run_command": True,
                "manual_review_if_uncertain": True,
            },
        }
        report_dir = Path("logs/tool_analysis")
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / (analysis.name.replace("/", "_") + "_auto_config_result.json")
        report_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        payload["result_path"] = str(report_path)
        return payload

    def configure_file(self, file_path: str, *, install: bool = False, approve_install: bool = False, approve_run: bool = False, enable: bool = True) -> dict[str, Any]:
        path = Path(file_path)
        repos = []
        for line in path.read_text(encoding="utf-8").splitlines():
            item = line.strip()
            if item and not item.startswith("#"):
                repos.append(item)
        results = [self.configure(repo, install=install, approve_install=approve_install, approve_run=approve_run, enable=enable) for repo in repos]
        summary = {
            "file": str(path),
            "total": len(results),
            "ready": sum(1 for item in results if item.get("status") == "READY"),
            "registered_requires_approval": sum(1 for item in results if item.get("status") == "REGISTERED_REQUIRES_APPROVAL"),
            "manual_review": sum(1 for item in results if item.get("status") == "NEEDS_MANUAL_REVIEW"),
            "blocked": sum(1 for item in results if item.get("status") == "BLOCKED"),
            "results": results,
        }
        report_dir = Path("logs/tool_analysis")
        report_dir.mkdir(parents=True, exist_ok=True)
        path_out = report_dir / "batch_auto_config_summary.json"
        path_out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        summary["result_path"] = str(path_out)
        return summary

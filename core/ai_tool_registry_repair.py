#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from core.ai_tool_analyzer import AIToolAnalyzer
from core.tool_manifest_generator import write_manifest
from core.tool_manager import ToolManager
from core.tool_registry import ToolRegistry


class AIToolRegistryRepair:
    """Repair legacy/bad dynamic tool registry entries.

    Old installers may have marked many tools as installed+approved without a
    verified manifest, run template, phase, or safety classification. This repair
    pass re-analyzes each repo and downgrades uncertain tools instead of leaving
    them fake-ready.
    """

    def __init__(self, *, timeout: int = 25, use_llm: bool = True) -> None:
        self.analyzer = AIToolAnalyzer(timeout=timeout, use_llm=use_llm)
        self.manager = ToolManager()
        self.registry: ToolRegistry = self.manager.registry

    def _dedupe_tools(self) -> dict[str, Any]:
        seen: set[str] = set()
        kept = {}
        removed = []
        for tool_id, tool in sorted(self.registry.tools.items(), key=lambda item: (item[1].repo_url or item[1].local_path, item[0])):
            key = (tool.repo_url or "") + "|" + (tool.local_path or "")
            if key in seen:
                removed.append(tool.to_dict())
                continue
            seen.add(key)
            kept[tool_id] = tool
        self.registry.tools = kept
        if removed:
            self.registry.save()
        return {"removed_duplicates": len(removed), "duplicates": removed}

    def _status_from_analysis(self, analysis: Any, tool: Any, *, approve_safe_run: bool) -> str:
        if analysis.status == "BLOCKED" or analysis.safety_level == "blocked":
            tool.enabled = False
            tool.approved_for_run = False
            tool.metadata["ai_repair_status"] = "BLOCKED"
            tool.metadata["ai_repair_reason"] = analysis.reasons
            return "BLOCKED"
        has_run = bool(tool.run)
        if analysis.status == "ANALYZED" and has_run:
            if approve_safe_run and analysis.safety_level in {"passive", "safe-active"}:
                tool.enabled = True
                tool.approved_for_run = True
                tool.metadata["ai_repair_status"] = "READY"
                return "READY"
            tool.enabled = True
            tool.approved_for_run = False
            tool.metadata["ai_repair_status"] = "REGISTERED_REQUIRES_APPROVAL"
            return "REGISTERED_REQUIRES_APPROVAL"
        tool.enabled = False
        tool.approved_for_run = False
        tool.metadata["ai_repair_status"] = "NEEDS_MANUAL_REVIEW"
        tool.metadata["ai_repair_reason"] = analysis.reasons
        return "NEEDS_MANUAL_REVIEW"

    def repair_all(self, *, approve_safe_run: bool = False, enable: bool = True, limit: int = 0) -> dict[str, Any]:
        started = time.time()
        dedupe = self._dedupe_tools()
        results = []
        tools = list(self.registry.list())
        if limit > 0:
            tools = tools[:limit]
        for existing in tools:
            repo_url = existing.repo_url or ""
            if not repo_url.startswith("http"):
                existing.enabled = False
                existing.approved_for_run = False
                existing.metadata["ai_repair_status"] = "NEEDS_MANUAL_REVIEW"
                existing.metadata["ai_repair_reason"] = ["missing GitHub repo_url; cannot re-analyze automatically"]
                self.registry.upsert(existing)
                results.append({"tool_id": existing.tool_id, "name": existing.name, "status": "NEEDS_MANUAL_REVIEW", "reason": "missing repo_url"})
                continue
            try:
                analysis = self.analyzer.analyze(repo_url, install=False, register=False)
                manifest_path = ""
                if analysis.status != "BLOCKED":
                    manifest_path = write_manifest(analysis)
                    analysis.manifest_path = manifest_path
                repaired = self.manager.add_tool(repo_url, approve_install=existing.approved_for_install, approve_run=False, enable=enable)
                repaired.installed = existing.installed
                repaired.approved_for_install = existing.approved_for_install
                status = self._status_from_analysis(analysis, repaired, approve_safe_run=approve_safe_run)
                repaired.metadata.update({
                    "ai_repaired": True,
                    "ai_repaired_at": time.time(),
                    "ai_analysis_report": analysis.report_path,
                    "ai_manifest_path": manifest_path,
                    "ai_safety_level": analysis.safety_level,
                    "ai_required_scan_mode": analysis.required_scan_mode,
                })
                self.registry.upsert(repaired)
                results.append({"tool_id": repaired.tool_id, "name": repaired.name, "repo_url": repo_url, "status": status, "phase": repaired.phase, "safety_level": analysis.safety_level, "manifest_path": manifest_path, "analysis_report": analysis.report_path})
            except Exception as exc:
                existing.enabled = False
                existing.approved_for_run = False
                existing.metadata["ai_repair_status"] = "NEEDS_MANUAL_REVIEW"
                existing.metadata["ai_repair_error"] = str(exc)[:1000]
                self.registry.upsert(existing)
                results.append({"tool_id": existing.tool_id, "name": existing.name, "repo_url": repo_url, "status": "NEEDS_MANUAL_REVIEW", "error": str(exc)[:1000]})
        summary = {
            "status": "completed",
            "started_at": started,
            "elapsed_ms": int((time.time() - started) * 1000),
            "approve_safe_run": approve_safe_run,
            "dedupe": dedupe,
            "total_processed": len(results),
            "ready": sum(1 for item in results if item.get("status") == "READY"),
            "registered_requires_approval": sum(1 for item in results if item.get("status") == "REGISTERED_REQUIRES_APPROVAL"),
            "manual_review": sum(1 for item in results if item.get("status") == "NEEDS_MANUAL_REVIEW"),
            "blocked": sum(1 for item in results if item.get("status") == "BLOCKED"),
            "results": results,
        }
        out = Path("logs/tool_analysis/registry_repair_summary.json")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        summary["result_path"] = str(out)
        return summary

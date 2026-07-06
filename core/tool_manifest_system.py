#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any


class ToolManifestSystem:
    """Manifest-based registry for approved external utilities."""

    def __init__(self, *, state: Any, dashboard: Any | None = None, manifest_dir: str = "tool_manifests") -> None:
        self.state = state
        self.dashboard = dashboard
        self.manifest_dir = Path(manifest_dir)
        self.target = getattr(state, "target", "")
        self.out_dir = Path(getattr(state, "out_dir", "reports/output"))
        self.manifests: list[dict[str, Any]] = []
        self.ready: list[dict[str, Any]] = []
        self.not_ready: list[dict[str, Any]] = []

    def dash(self, action: str) -> None:
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(phase="Tool Manifest Registry", phase_progress=77, current_agent="ToolManifestAgent", current_tool="tool_manifest_system", action=action, endpoint=self.target, safety_status="manifest-based utility selection")
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO", action)

    def load(self) -> None:
        self.manifests = []
        if not self.manifest_dir.exists():
            return
        for path in sorted(self.manifest_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
                if isinstance(data, dict):
                    data["_path"] = str(path)
                    self.manifests.append(data)
            except Exception:
                continue

    def evaluate(self) -> None:
        self.ready = []
        self.not_ready = []
        mode = str((getattr(self.state, "stats", {}) or {}).get("scan_mode", "safe-active"))
        for item in self.manifests:
            name = str(item.get("tool_id") or item.get("name") or "unknown")
            command = item.get("command") or []
            binary = command[0] if isinstance(command, list) and command else item.get("binary")
            safe_modes = item.get("safe_modes") or item.get("modes") or []
            approved = bool(item.get("approved", item.get("requires_approval", True) is False))
            reasons = []
            if safe_modes and mode not in safe_modes:
                reasons.append("mode not allowed")
            if not binary or shutil.which(str(binary)) is None:
                reasons.append("binary missing")
            if not approved:
                reasons.append("not approved")
            row = {"tool_id": name, "phase": item.get("phase", ""), "binary": binary, "approved": approved, "safe_modes": safe_modes, "manifest": item.get("_path", "")}
            if reasons:
                row["reasons"] = reasons
                self.not_ready.append(row)
            else:
                self.ready.append(row)

    def run(self) -> dict[str, Any]:
        self.dash("Loading tool manifests")
        self.load()
        self.evaluate()
        reports = self.write_reports()
        try:
            self.state.stats["tool_manifests_total"] = len(self.manifests)
            self.state.stats["tool_manifests_ready"] = len(self.ready)
            self.state.save()
        except Exception:
            pass
        return {"ok": True, "total": len(self.manifests), "ready": len(self.ready), "not_ready": len(self.not_ready), "reports": reports}

    def write_reports(self) -> dict[str, str]:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        payload = {"target": self.target, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "manifest_dir": str(self.manifest_dir), "ready": self.ready, "not_ready": self.not_ready}
        json_path = self.out_dir / "tool-manifest-registry.json"
        md_path = self.out_dir / "tool-manifest-registry.md"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        lines = ["# Tool Manifest Registry", "", f"Ready: `{len(self.ready)}`", f"Not ready: `{len(self.not_ready)}`", "", "## Ready", ""]
        for row in self.ready:
            lines.append(f"- `{row['tool_id']}` phase=`{row.get('phase','')}` binary=`{row.get('binary')}`")
        lines.extend(["", "## Not Ready", ""])
        for row in self.not_ready[:200]:
            lines.append(f"- `{row['tool_id']}` reasons=`{', '.join(row.get('reasons') or [])}`")
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return {"tool_manifest_registry_json": str(json_path), "tool_manifest_registry_md": str(md_path)}


def write_manifest_template(path: str = "tool_manifests/example.json") -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {"tool_id": "example", "phase": "discovery", "safe_modes": ["passive", "safe-active"], "command": ["example", "--target", "{target}"], "parser": "text", "approved": False, "notes": "Copy and edit for approved local utilities."}
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(p)

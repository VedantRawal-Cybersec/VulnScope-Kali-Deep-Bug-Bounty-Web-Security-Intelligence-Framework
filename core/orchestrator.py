#!/usr/bin/env python3
from __future__ import annotations

import ast
import json
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.ai_brain import AIBrain
from core.autonomous_planner import AutonomousPlanner
from core.report_generator import ReportGenerator
from core.tool_manager import ToolManager


class ReActOrchestrator:
    LAB_INTENSITY_FLAGS = {
        "nuclei": ["-tags", "critical,high", "-severity", "critical,high"],
        "ffuf": ["-rate", "100", "-t", "20"],
        "sqlmap": ["--level", "5", "--risk", "3", "--batch"],
    }

    def __init__(self, target: str, *, mode: str = "bugbounty", aggressive: bool = False, max_turns: int = 30, out_dir: str | Path | None = None, brain: AIBrain | None = None, planner: AutonomousPlanner | None = None) -> None:
        self.target = target if "://" in target else "https://" + target
        self.mode = "lab" if mode == "lab" else "bugbounty"
        self.aggressive = bool(aggressive and self.mode == "lab")
        self.max_turns = max_turns
        self.brain = brain or AIBrain()
        self.planner = planner or AutonomousPlanner()
        self.tool_manager = ToolManager()
        self.reporter = ReportGenerator(self.brain)
        host = urlparse(self.target).hostname or "target"
        self.out_dir = Path(out_dir or Path("reports/output") / host)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.urls: list[str] = [self.target]
        self.parameters: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self.observations: list[dict[str, Any]] = []
        self.actions: list[dict[str, Any]] = []
        self.report_path: Path | None = None
        self.finished = False

    def detect_stack(self) -> list[str]:
        text = " ".join(self.urls).lower()
        stack: list[str] = []
        if ".php" in text or "php" in text:
            stack.append("php")
        if "api/" in text:
            stack.append("api")
        if "graphql" in text:
            stack.append("graphql")
        return stack or ["unknown"]

    def available_tools(self) -> list[str]:
        self.tool_manager.reconcile_installed_tools(approve_known=True, enable=True)
        tools: list[str] = []
        for tool in self.tool_manager.registry.list(enabled_only=True):
            if not tool.run or not tool.approved_for_run:
                continue
            if self.mode != "lab" and tool.phase == "exploitation":
                continue
            tools.append(tool.name)
        return tools

    def context(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "mode": self.mode,
            "aggressive": self.aggressive,
            "surface": {"urls": len(self.urls), "params": len(self.parameters), "findings": len(self.findings), "observations": len(self.observations)},
            "urls": self.urls[-50:],
            "parameters": self.parameters[-100:],
            "findings": self.findings[-50:],
            "available_tools": self.available_tools(),
            "tech_stack": self.detect_stack(),
            "last_actions": self.actions[-10:],
        }

    def tool_by_name(self, name: str):
        wanted = name.lower().strip()
        for tool in self.tool_manager.registry.list(enabled_only=True):
            if tool.name.lower() == wanted or tool.tool_id.lower() == wanted or wanted in tool.name.lower():
                return tool
        return None

    def parse_action(self, action: str) -> tuple[str, Any]:
        action = str(action or "").strip()
        if action.startswith("run_tool:"):
            return "run_tool", action.split(":", 1)[1].strip()
        if action.startswith("inject_endpoints:"):
            raw = action.split(":", 1)[1].strip()
            try:
                value = ast.literal_eval(raw)
                if isinstance(value, list):
                    return "inject_endpoints", [str(item) for item in value]
            except Exception:
                pass
            return "inject_endpoints", []
        if action == "generate_report":
            return "generate_report", None
        if action == "finish":
            return "finish", None
        return "unknown", action

    def safe_scope_url(self, url: str) -> bool:
        target_host = urlparse(self.target).hostname or ""
        full = url if "://" in url else self.target.rstrip("/") + "/" + url.lstrip("/")
        test_host = urlparse(full).hostname or ""
        return target_host.lower() == test_host.lower()

    def inject_endpoints(self, endpoints: list[str]) -> dict[str, Any]:
        added: list[str] = []
        for endpoint in endpoints:
            url = endpoint if "://" in endpoint else self.target.rstrip("/") + "/" + endpoint.lstrip("/")
            if self.safe_scope_url(url) and url not in self.urls:
                self.urls.append(url)
                added.append(url)
        return {"added": added, "count": len(added)}

    def format_command(self, command: list[str]) -> list[str]:
        parsed = urlparse(self.target)
        host = parsed.hostname or self.target
        return [str(token).replace("{target}", self.target.rstrip("/")).replace("{host}", host).replace("{output_format}", "json") for token in command]

    def run_tool(self, tool_name: str) -> dict[str, Any]:
        tool = self.tool_by_name(tool_name)
        if tool is None:
            return {"ok": False, "error": f"tool not found: {tool_name}"}
        if not tool.approved_for_run:
            return {"ok": False, "error": f"tool is not approved for run: {tool.name}"}
        if not tool.run:
            return {"ok": False, "error": f"tool has no run command: {tool.name}"}
        command = self.format_command(tool.run)
        if self.aggressive:
            lower_name = tool.name.lower()
            for key, flags in self.LAB_INTENSITY_FLAGS.items():
                if key in lower_name:
                    command.extend(flags)
                    break
        started = time.time()
        stdout_path = self.out_dir / f"{tool.tool_id}_{int(started)}.stdout.txt"
        stderr_path = self.out_dir / f"{tool.tool_id}_{int(started)}.stderr.txt"
        try:
            with stdout_path.open("w", encoding="utf-8", errors="ignore") as stdout, stderr_path.open("w", encoding="utf-8", errors="ignore") as stderr:
                proc = subprocess.run(command, cwd=tool.local_path or ".", stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL, text=True, timeout=600 if self.aggressive else 240, shell=False, check=False)
            result = {"ok": proc.returncode == 0, "tool": tool.name, "tool_id": tool.tool_id, "command": command, "exit_code": proc.returncode, "stdout_path": str(stdout_path), "stderr_path": str(stderr_path), "elapsed_ms": int((time.time() - started) * 1000)}
        except Exception as exc:
            result = {"ok": False, "tool": tool.name, "tool_id": tool.tool_id, "command": command, "error": str(exc), "elapsed_ms": int((time.time() - started) * 1000)}
        self.observations.append(result)
        findings = self.extract_findings_from_output(tool.name, stdout_path if stdout_path.exists() else None)
        self.findings.extend(findings)
        self.planner.update(self.context(), tool.name, findings)
        return {**result, "findings_added": len(findings)}

    def extract_findings_from_output(self, tool_name: str, stdout_path: Path | None) -> list[dict[str, Any]]:
        if stdout_path is None or not stdout_path.exists():
            return []
        text = stdout_path.read_text(encoding="utf-8", errors="ignore")
        findings: list[dict[str, Any]] = []
        for line in text.splitlines()[:5000]:
            stripped = line.strip()
            if not stripped:
                continue
            item: dict[str, Any] | None = None
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, dict):
                    item = parsed
            except Exception:
                pass
            if item:
                severity = str(item.get("severity") or item.get("info", {}).get("severity") or "INFO").upper()
                title = item.get("name") or item.get("template-id") or item.get("matched-at") or f"{tool_name} observation"
                findings.append({"title": str(title), "severity": severity, "confidence": 0.75 if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else 0.45, "affected_url": item.get("matched-at") or item.get("url") or self.target, "evidence": json.dumps(item, ensure_ascii=False)[:2000], "tool": tool_name, "status": "review_lead"})
        return findings[:100]

    def generate_report(self) -> dict[str, Any]:
        self.report_path = self.reporter.write_report(self.target, self.findings, out_dir=self.out_dir, context=self.context())
        return {"ok": True, "report_path": str(self.report_path), "findings": len(self.findings)}

    def next_action(self) -> str:
        ctx = self.context()
        tools = ctx["available_tools"]
        if self.aggressive and tools:
            selected = self.planner.choose_tool(ctx, tools, aggressive=True)
            if selected:
                return f"run_tool:{selected}"
        return self.brain.decide_next_action(ctx, tools)

    def run(self) -> dict[str, Any]:
        for turn in range(1, self.max_turns + 1):
            if self.finished:
                break
            action = self.next_action()
            action_type, payload = self.parse_action(action)
            record = {"turn": turn, "action": action, "type": action_type, "payload": payload, "time": time.time()}
            if action_type == "run_tool":
                result = self.run_tool(str(payload))
            elif action_type == "inject_endpoints":
                result = self.inject_endpoints(payload or [])
            elif action_type == "generate_report":
                result = self.generate_report()
                self.finished = True
            elif action_type == "finish":
                result = self.generate_report() if self.report_path is None else {"ok": True, "status": "finished"}
                self.finished = True
            else:
                result = {"ok": False, "error": f"unknown action: {action}"}
                self.finished = True
            record["result"] = result
            self.actions.append(record)
            self.brain.store_decision(json.dumps(self.context(), ensure_ascii=False), action, json.dumps(result, ensure_ascii=False), metadata={"mode": self.mode, "aggressive": self.aggressive})
        if self.report_path is None:
            self.generate_report()
        payload = {"target": self.target, "mode": self.mode, "aggressive": self.aggressive, "actions": self.actions, "findings": self.findings, "observations": self.observations, "report_path": str(self.report_path) if self.report_path else ""}
        (self.out_dir / "orchestrator-result.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return payload


Orchestrator = ReActOrchestrator

#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

from core.tool_registry import RegisteredTool, ToolArgument, ToolRegistry, VALID_PARSERS, VALID_PHASES

TOOLS_DIR = Path("tools")
RUNS_DIR = Path("reports/output/dynamic-tools")


@dataclass
class CommandResult:
    command: list[str]
    cwd: str
    status: str
    started_at: float
    finished_at: float
    elapsed_ms: int
    stdout_path: str = ""
    stderr_path: str = ""
    exit_code: int | None = None
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ToolManager:
    """Install, register, and execute manifest-based dynamic tools.

    Safety model:
    - A repository can be cloned without running its code.
    - Install commands require approval.
    - Run commands require approval and enabled=true.
    - Commands are tokenized with shlex and executed with shell=False.
    - The run template receives only declared context fields.
    """

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self.registry = registry or ToolRegistry()
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        RUNS_DIR.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _slug_from_repo_url(repo_url: str) -> str:
        parsed = urlparse(repo_url)
        path = parsed.path.strip("/").removesuffix(".git")
        slug = re.sub(r"[^a-zA-Z0-9_.-]+", "_", path.replace("/", "__"))
        if not slug:
            slug = hashlib.sha256(repo_url.encode()).hexdigest()[:12]
        return slug[:120]

    @staticmethod
    def _tool_id(name: str, repo_url: str) -> str:
        base = re.sub(r"[^a-zA-Z0-9_.-]+", "_", name.lower()).strip("_") or "tool"
        suffix = hashlib.sha256(repo_url.encode()).hexdigest()[:8]
        return f"{base}_{suffix}"

    @staticmethod
    def _load_manifest(path: Path) -> dict[str, Any] | None:
        yaml_path = path / "tool.yaml"
        yml_path = path / "tool.yml"
        json_path = path / "tool.json"
        if yaml_path.exists() or yml_path.exists():
            source = yaml_path if yaml_path.exists() else yml_path
            if yaml is None:
                raise RuntimeError("PyYAML is required to read tool.yaml. Install pyyaml or use tool.json.")
            return yaml.safe_load(source.read_text(encoding="utf-8")) or {}
        if json_path.exists():
            return json.loads(json_path.read_text(encoding="utf-8"))
        return None

    @staticmethod
    def _split_command(command: str | list[str]) -> list[str]:
        if isinstance(command, list):
            return [str(item) for item in command]
        return shlex.split(str(command))

    def _infer_manifest(self, repo_url: str, local_path: Path) -> dict[str, Any]:
        name = local_path.name.replace("__", "/")
        install: list[str] = []
        run = ""
        parser = "plain"
        if (local_path / "requirements.txt").exists():
            install.append("python3 -m pip install -r requirements.txt")
        if (local_path / "pyproject.toml").exists() or (local_path / "setup.py").exists():
            install.append("python3 -m pip install .")
        if (local_path / "go.mod").exists():
            install.append("go build ./...")
        if (local_path / "package.json").exists():
            install.append("npm install")
        for candidate in ["main.py", "scanner.py", "scan.py", "app.py"]:
            if (local_path / candidate).exists():
                run = f"python3 {candidate} --target {{target}}"
                break
        if not run:
            run = ""
        return {
            "name": name,
            "version": "unknown",
            "phase": "discovery",
            "install": install,
            "run": run,
            "arguments": [{"name": "target", "description": "Target URL", "required": True}],
            "output_parser": parser,
            "metadata": {"manifest_inferred": True, "requires_manual_run_command": not bool(run)},
        }

    def _normalize_manifest(self, manifest: dict[str, Any], repo_url: str, local_path: Path) -> RegisteredTool:
        name = str(manifest.get("name") or local_path.name)
        phase = str(manifest.get("phase") or "discovery").lower()
        if phase not in VALID_PHASES:
            phase = "discovery"
        parser = str(manifest.get("output_parser") or "plain").lower()
        if parser not in VALID_PARSERS:
            parser = "plain"
        install_commands = [self._split_command(command) for command in manifest.get("install", [])]
        run_value = manifest.get("run") or []
        run_command = self._split_command(run_value) if run_value else []
        args: list[ToolArgument] = []
        for item in manifest.get("arguments", []) or []:
            if isinstance(item, dict):
                args.append(ToolArgument(name=str(item.get("name") or ""), description=str(item.get("description") or ""), required=bool(item.get("required", False)), default=str(item.get("default") or "")))
        return RegisteredTool(
            tool_id=self._tool_id(name, repo_url),
            name=name,
            version=str(manifest.get("version") or "unknown"),
            repo_url=repo_url,
            local_path=str(local_path),
            phase=phase,
            install=install_commands,
            run=run_command,
            arguments=args,
            output_parser=parser,
            metadata=dict(manifest.get("metadata") or {}),
        )

    def clone_or_update(self, repo_url: str) -> Path:
        slug = self._slug_from_repo_url(repo_url)
        local_path = TOOLS_DIR / slug
        if local_path.exists() and (local_path / ".git").exists():
            subprocess.run(["git", "-C", str(local_path), "pull", "--ff-only"], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
            return local_path
        if local_path.exists() and not (local_path / ".git").exists():
            raise RuntimeError(f"tool path exists but is not a git repo: {local_path}")
        subprocess.run(["git", "clone", "--depth", "1", repo_url, str(local_path)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=240)
        return local_path

    def add_tool(self, repo_url: str, *, approve_install: bool = False, approve_run: bool = False, enable: bool = False, run_command: str = "") -> RegisteredTool:
        local_path = self.clone_or_update(repo_url)
        manifest = self._load_manifest(local_path)
        if manifest is None:
            manifest = self._infer_manifest(repo_url, local_path)
            if run_command:
                manifest["run"] = run_command
                manifest.setdefault("metadata", {})["manual_run_command_provided"] = True
        tool = self._normalize_manifest(manifest, repo_url, local_path)
        if approve_install:
            tool.approved_for_install = True
        if approve_run:
            tool.approved_for_run = True
        if enable:
            tool.enabled = True
        self.registry.upsert(tool)
        return tool

    def install_tool(self, tool_id: str, *, confirm: bool = False, timeout: int = 600) -> list[CommandResult]:
        tool = self.registry.get(tool_id)
        if not tool:
            raise KeyError(tool_id)
        if not confirm and not tool.approved_for_install:
            raise PermissionError("installation requires approval")
        results: list[CommandResult] = []
        for command in tool.install:
            results.append(self._run_command(command, cwd=Path(tool.local_path), timeout=timeout, label=f"install_{tool_id}"))
        self.registry.set_installed(tool_id, installed=all(item.status == "completed" for item in results) if results else True)
        return results

    def _format_run_args(self, token: str, context: dict[str, str]) -> str:
        try:
            return token.format(**context)
        except KeyError as exc:
            raise KeyError(f"missing required context variable in run command: {exc}")

    def run_tool(self, tool_id: str, *, target: str, parameter: str = "", output_format: str = "json", confirm: bool = False, timeout: int = 300) -> dict[str, Any]:
        tool = self.registry.get(tool_id)
        if not tool:
            raise KeyError(tool_id)
        if not tool.enabled:
            raise PermissionError("tool is registered but disabled")
        if not confirm and not tool.approved_for_run:
            raise PermissionError("tool execution requires approval")
        if not tool.run:
            raise ValueError("tool has no run command configured")
        context = {"target": target, "parameter": parameter, "output_format": output_format, "tool_dir": tool.local_path}
        command = [self._format_run_args(token, context) for token in tool.run]
        result = self._run_command(command, cwd=Path(tool.local_path), timeout=timeout, label=f"run_{tool_id}")
        parsed = self.parse_output(tool.output_parser, result.stdout_path)
        payload = {"tool": tool.to_dict(), "result": result.to_dict(), "parsed_output": parsed}
        run_report = RUNS_DIR / f"{tool_id}_{int(time.time())}.json"
        run_report.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return payload

    def _run_command(self, command: list[str], *, cwd: Path, timeout: int, label: str) -> CommandResult:
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        run_id = hashlib.sha256((label + str(time.time())).encode()).hexdigest()[:12]
        stdout_path = RUNS_DIR / f"{run_id}.stdout.txt"
        stderr_path = RUNS_DIR / f"{run_id}.stderr.txt"
        started = time.time()
        try:
            with stdout_path.open("w", encoding="utf-8", errors="ignore") as stdout, stderr_path.open("w", encoding="utf-8", errors="ignore") as stderr:
                proc = subprocess.run(command, cwd=str(cwd), stdout=stdout, stderr=stderr, text=True, stdin=subprocess.DEVNULL, timeout=timeout, shell=False)
            return CommandResult(command=command, cwd=str(cwd), status="completed" if proc.returncode == 0 else "failed", started_at=started, finished_at=time.time(), elapsed_ms=int((time.time() - started) * 1000), stdout_path=str(stdout_path), stderr_path=str(stderr_path), exit_code=proc.returncode)
        except subprocess.TimeoutExpired:
            return CommandResult(command=command, cwd=str(cwd), status="timed_out", started_at=started, finished_at=time.time(), elapsed_ms=int((time.time() - started) * 1000), stdout_path=str(stdout_path), stderr_path=str(stderr_path), error=f"timeout after {timeout}s")
        except Exception as exc:
            return CommandResult(command=command, cwd=str(cwd), status="failed", started_at=started, finished_at=time.time(), elapsed_ms=int((time.time() - started) * 1000), stdout_path=str(stdout_path), stderr_path=str(stderr_path), error=str(exc)[:1000])

    @staticmethod
    def parse_output(parser: str, stdout_path: str) -> Any:
        path = Path(stdout_path)
        if not path.exists():
            return None
        text = path.read_text(encoding="utf-8", errors="ignore")
        if parser == "json":
            try:
                return json.loads(text)
            except Exception:
                return {"raw": text[:5000], "parse_error": "invalid json"}
        if parser == "jsonl":
            rows = []
            for line in text.splitlines():
                if not line.strip():
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    rows.append({"raw": line[:1000]})
            return rows[:1000]
        return {"raw": text[:10000]}

    def list_tools(self) -> list[dict[str, Any]]:
        return self.registry.as_table_rows()

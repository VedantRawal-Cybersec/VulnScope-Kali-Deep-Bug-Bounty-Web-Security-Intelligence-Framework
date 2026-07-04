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
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

from core.tool_manifest import ToolManifest
from core.tool_registry import RegisteredTool, ToolArgument, ToolRegistry, VALID_PARSERS, VALID_PHASES

TOOLS_DIR = Path("tools")
RUNS_DIR = Path("reports/output/dynamic-tools")
LOGS_DIR = Path("logs")
TOOL_INSTALL_LOG = LOGS_DIR / "tool_install.log"
VULNSCOPE_LOG = LOGS_DIR / "vulnscope.log"

KNOWN_TOOL_PROFILES: dict[str, dict[str, Any]] = {
    "nuclei": {"phase": "validation", "output_parser": "jsonl", "run": "nuclei -u {target} -jsonl -silent -severity info,low,medium -rate-limit 5 -no-interactsh -disable-update-check", "finding_tool": True},
    "katana": {"phase": "discovery", "output_parser": "jsonl", "run": "katana -u {target} -silent -jsonl -d 2 -ct 120", "finding_tool": False},
    "httpx": {"phase": "recon", "output_parser": "jsonl", "run": "httpx -u {target} -json -silent -follow-redirects", "finding_tool": False},
    "ffuf": {"phase": "discovery", "output_parser": "json", "run": "ffuf -u {target}/FUZZ -w {wordlist} -of json -rate 50 -t 5 -mc 200,204,301,302,307,308,401,403", "finding_tool": False},
    "subfinder": {"phase": "recon", "output_parser": "jsonl", "run": "subfinder -d {host} -json -silent", "finding_tool": False, "requires_subdomain_authorization": True},
    "naabu": {"phase": "recon", "output_parser": "jsonl", "run": "naabu -host {host} -json -silent -rate 100", "finding_tool": False},
}

MANUAL_PROFILE_NOTES: dict[str, str] = {
    "sqlmap": "registered for visibility, but no automatic run command is generated. Add a reviewed manifest.json/tool.yaml run profile for owned lab targets.",
    "dalfox": "registered for visibility, but no automatic run command is generated. Add a reviewed manifest.json/tool.yaml run profile for owned lab targets.",
}


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
    """Install, register, repair, and execute manifest-based dynamic tools.

    Approval model:
    - Known safe profiles may be auto-approved when `approve_known=True`.
    - AI-repaired tools may be auto-approved only when metadata says READY.
    - Unknown heuristic tools are never auto-approved just because a run command exists.
    """

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self.registry = registry or ToolRegistry()
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        LOGS_DIR.mkdir(parents=True, exist_ok=True)

    def _log(self, message: str, *, level: str = "INFO", data: dict[str, Any] | None = None) -> None:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        payload = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "level": level, "message": message, "data": data or {}}
        for path in [TOOL_INSTALL_LOG, VULNSCOPE_LOG]:
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

    @staticmethod
    def _slug_from_repo_url(repo_url: str) -> str:
        parsed = urlparse(repo_url)
        path = parsed.path.strip("/").removesuffix(".git")
        slug = re.sub(r"[^a-zA-Z0-9_.-]+", "_", path.replace("/", "__"))
        return (slug or hashlib.sha256(repo_url.encode()).hexdigest()[:12])[:120]

    @staticmethod
    def _tool_id(name: str, repo_url: str) -> str:
        base = re.sub(r"[^a-zA-Z0-9_.-]+", "_", name.lower()).strip("_") or "tool"
        suffix = hashlib.sha256(repo_url.encode()).hexdigest()[:8]
        return f"{base}_{suffix}"

    @staticmethod
    def _split_command(command: str | list[str]) -> list[str]:
        if isinstance(command, list):
            return [str(item) for item in command]
        return shlex.split(str(command))

    @staticmethod
    def _load_manifest(path: Path) -> dict[str, Any] | None:
        manifest_json_path = path / "manifest.json"
        if manifest_json_path.exists():
            return ToolManifest(path).to_registry_manifest()
        yaml_path = path / "tool.yaml"
        yml_path = path / "tool.yml"
        if yaml_path.exists() or yml_path.exists():
            if yaml is None:
                raise RuntimeError("PyYAML is required to read tool.yaml. Install pyyaml or use manifest.json/tool.json.")
            source = yaml_path if yaml_path.exists() else yml_path
            return yaml.safe_load(source.read_text(encoding="utf-8")) or {}
        json_path = path / "tool.json"
        if json_path.exists():
            return json.loads(json_path.read_text(encoding="utf-8"))
        return None

    @staticmethod
    def _tool_key_from_path(local_path: Path, name: str = "") -> str:
        joined = " ".join([local_path.name.lower(), name.lower()]).replace("__", "/")
        for key in sorted(KNOWN_TOOL_PROFILES, key=len, reverse=True):
            if key in joined:
                return key
        for key in sorted(MANUAL_PROFILE_NOTES, key=len, reverse=True):
            if key in joined:
                return key
        return ""

    def _known_profile_for(self, local_path: Path, name: str = "") -> dict[str, Any] | None:
        return KNOWN_TOOL_PROFILES.get(self._tool_key_from_path(local_path, name))

    def _can_auto_approve(self, tool: RegisteredTool, local_path: Path) -> bool:
        if not tool.run:
            return False
        metadata = tool.metadata or {}
        known_profile = metadata.get("known_profile") or self._tool_key_from_path(local_path, tool.name)
        if known_profile in KNOWN_TOOL_PROFILES:
            return True
        if str(metadata.get("ai_repair_status") or metadata.get("analysis_status") or "").upper() == "READY":
            return True
        return False

    def _infer_manifest(self, repo_url: str, local_path: Path) -> dict[str, Any]:
        name = local_path.name.replace("__", "/")
        install: list[str] = []
        if (local_path / "requirements.txt").exists():
            install.append("python3 -m pip install -r requirements.txt")
        if (local_path / "pyproject.toml").exists():
            install.append("python3 -m pip install .")
        if (local_path / "setup.py").exists():
            install.append("python3 -m pip install .")
        if (local_path / "go.mod").exists():
            install.append("go build ./...")
        if (local_path / "package.json").exists():
            install.append("npm install")
        if (local_path / "install.sh").exists():
            install.append("bash install.sh")

        phase = "discovery"
        parser = "plain"
        run = ""
        metadata: dict[str, Any] = {"manifest_inferred": True}
        profile = self._known_profile_for(local_path, name)
        if profile:
            phase = str(profile.get("phase") or phase)
            parser = str(profile.get("output_parser") or parser)
            run = str(profile.get("run") or "")
            metadata.update({"known_profile": self._tool_key_from_path(local_path, name), **{k: v for k, v in profile.items() if k not in {"run", "phase", "output_parser"}}})
        else:
            for candidate in ["main.py", "scanner.py", "scan.py", "app.py"]:
                if (local_path / candidate).exists():
                    run = f"python3 {candidate} --target {{target}}"
                    break
        key = self._tool_key_from_path(local_path, name)
        if key in MANUAL_PROFILE_NOTES and not run:
            metadata["manual_profile_note"] = MANUAL_PROFILE_NOTES[key]
        metadata["requires_manual_run_command"] = not bool(run)
        return {"name": name, "version": "unknown", "phase": phase, "install": install, "run": run, "arguments": [{"name": "target", "description": "Target URL", "required": True}], "output_parser": parser, "metadata": metadata}

    def _normalize_manifest(self, manifest: dict[str, Any], repo_url: str, local_path: Path) -> RegisteredTool:
        name = str(manifest.get("name") or local_path.name)
        profile = self._known_profile_for(local_path, name)
        phase = str(manifest.get("phase") or (profile or {}).get("phase") or "discovery").lower()
        if phase not in VALID_PHASES:
            phase = "discovery"
        parser = str(manifest.get("output_parser") or (profile or {}).get("output_parser") or "plain").lower()
        if parser not in VALID_PARSERS:
            parser = "plain"
        install_commands = [self._split_command(command) for command in manifest.get("install", [])]
        run_value = manifest.get("run") or (profile or {}).get("run") or []
        run_command = self._split_command(run_value) if run_value else []
        args: list[ToolArgument] = []
        for item in manifest.get("arguments", []) or []:
            if isinstance(item, dict):
                args.append(ToolArgument(name=str(item.get("name") or ""), description=str(item.get("description") or ""), required=bool(item.get("required", False)), default=str(item.get("default") or "")))
        metadata = dict(manifest.get("metadata") or {})
        if profile:
            metadata.update({"known_profile": self._tool_key_from_path(local_path, name), **{k: v for k, v in profile.items() if k not in {"run", "phase", "output_parser"}}})
        return RegisteredTool(tool_id=self._tool_id(name, repo_url), name=name, version=str(manifest.get("version") or "unknown"), repo_url=repo_url, local_path=str(local_path), phase=phase, install=install_commands, run=run_command, arguments=args, output_parser=parser, metadata=metadata)

    def clone_or_update(self, repo_url: str) -> Path:
        slug = self._slug_from_repo_url(repo_url)
        local_path = TOOLS_DIR / slug
        if local_path.exists() and (local_path / ".git").exists():
            self._log("Updating existing tool repository", data={"url": repo_url, "path": str(local_path)})
            subprocess.run(["git", "-C", str(local_path), "pull", "--ff-only"], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
            return local_path
        if local_path.exists() and not (local_path / ".git").exists():
            raise RuntimeError(f"tool path exists but is not a git repo: {local_path}")
        self._log("Cloning tool repository", data={"url": repo_url, "path": str(local_path)})
        subprocess.run(["git", "clone", "--depth", "1", repo_url, str(local_path)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=240)
        return local_path

    def add_tool(self, repo_url: str, *, approve_install: bool = False, approve_run: bool = False, enable: bool = False, run_command: str = "") -> RegisteredTool:
        local_path = self.clone_or_update(repo_url)
        manifest = self._load_manifest(local_path) or self._infer_manifest(repo_url, local_path)
        if run_command:
            manifest["run"] = run_command
            manifest.setdefault("metadata", {})["manual_run_command_provided"] = True
        tool = self._normalize_manifest(manifest, repo_url, local_path)
        if approve_install:
            tool.approved_for_install = True
        if approve_run and tool.run:
            tool.approved_for_run = True
        if enable:
            tool.enabled = True
        self.registry.upsert(tool)
        self._log("Registered dynamic tool", data={"tool_id": tool.tool_id, "name": tool.name, "phase": tool.phase, "path": tool.local_path, "has_run": bool(tool.run), "approved_for_run": tool.approved_for_run})
        return tool

    def reconcile_installed_tools(self, *, approve_known: bool = True, enable: bool = True) -> dict[str, Any]:
        added = 0
        repaired = 0
        skipped = 0
        errors: list[dict[str, str]] = []
        known_paths = {str(Path(tool.local_path).resolve()): tool for tool in self.registry.list() if tool.local_path}
        if not TOOLS_DIR.exists():
            return {"added": 0, "repaired": 0, "skipped": 0, "errors": [], "registry": str(self.registry.path)}
        for path in sorted(item for item in TOOLS_DIR.iterdir() if item.is_dir()):
            try:
                resolved = str(path.resolve())
                existing = known_paths.get(resolved)
                if existing:
                    changed = False
                    manifest = self._load_manifest(path)
                    if manifest:
                        candidate = self._normalize_manifest(manifest, existing.repo_url or f"file://{path.as_posix()}", path)
                        if candidate.run and candidate.run != existing.run:
                            existing.run = candidate.run
                            existing.output_parser = candidate.output_parser
                            existing.phase = candidate.phase
                            existing.metadata.update(candidate.metadata)
                            changed = True
                    if not existing.run:
                        profile = self._known_profile_for(path, existing.name)
                        if profile and profile.get("run"):
                            existing.run = self._split_command(str(profile["run"]))
                            existing.output_parser = str(profile.get("output_parser") or existing.output_parser)
                            existing.phase = str(profile.get("phase") or existing.phase)
                            existing.metadata.update({"known_profile": self._tool_key_from_path(path, existing.name), "auto_repaired_run": True})
                            changed = True
                    should_auto_approve = bool(approve_known and self._can_auto_approve(existing, path))
                    if should_auto_approve and not existing.approved_for_run:
                        existing.approved_for_run = True
                        changed = True
                    if not should_auto_approve and not existing.metadata.get("manual_run_approval") and existing.metadata.get("manifest_inferred") and existing.approved_for_run:
                        existing.approved_for_run = False
                        existing.metadata["approval_reset_reason"] = "unknown inferred tool requires AI repair or manual approval"
                        changed = True
                    if enable and not existing.enabled:
                        existing.enabled = True
                        changed = True
                    if path.exists() and not existing.installed:
                        existing.installed = True
                        changed = True
                    if changed:
                        self.registry.upsert(existing)
                        repaired += 1
                    else:
                        skipped += 1
                    continue
                repo_url = f"file://{path.as_posix()}"
                manifest = self._load_manifest(path) or self._infer_manifest(repo_url, path)
                tool = self._normalize_manifest(manifest, repo_url, path)
                tool.installed = True
                tool.enabled = enable
                if approve_known and self._can_auto_approve(tool, path):
                    tool.approved_for_run = True
                self.registry.upsert(tool)
                added += 1
                self._log("Auto-registered installed tool directory", data={"tool_id": tool.tool_id, "path": str(path), "has_run": bool(tool.run), "approved_for_run": tool.approved_for_run})
            except Exception as exc:
                errors.append({"path": str(path), "error": str(exc)[:500]})
                self._log("Failed to auto-register installed tool directory", level="ERROR", data={"path": str(path), "error": str(exc)[:500]})
        summary = {"added": added, "repaired": repaired, "skipped": skipped, "errors": errors, "registry": str(self.registry.path)}
        self._log("Registry reconciliation completed", data=summary)
        return summary

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
        self._log("Install completed", data={"tool_id": tool_id, "results": [item.to_dict() for item in results]})
        return results

    def _read_tool_file(self, file_path: str | Path) -> list[str]:
        raw = str(file_path).strip()
        if raw.startswith("-") and not raw.startswith("--"):
            raw = raw[1:]
        path = Path(raw)
        return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.strip().startswith("#")]

    def install_from_file(self, file_path: str | Path, *, confirm_authorization: bool = False, install_timeout: int = 900) -> dict[str, Any]:
        if not confirm_authorization:
            answer = input("This will install tools from the list. Do you have authorization to use these tools on your targets? (yes/no): ").strip().lower()
            if answer not in {"yes", "y"}:
                self._log("Batch install aborted by user", level="WARNING", data={"file": str(file_path)})
                return {"status": "aborted", "installed_successfully": 0, "failed": 0, "results": [], "log": str(TOOL_INSTALL_LOG)}
        urls = self._read_tool_file(file_path)
        results: list[dict[str, Any]] = []
        success = 0
        failed = 0
        self._log("Batch tool install started", data={"file": str(file_path), "count": len(urls)})
        for index, url in enumerate(urls, 1):
            result = self._install_single(url, install_timeout=install_timeout, index=index, total=len(urls))
            results.append(result)
            if result.get("ok"):
                success += 1
            else:
                failed += 1
        repair = self.reconcile_installed_tools(approve_known=True, enable=True)
        summary = {"status": "completed", "installed_successfully": success, "failed": failed, "total": len(urls), "results": results, "repair": repair, "registry": str(self.registry.path), "log": str(TOOL_INSTALL_LOG)}
        summary_path = LOGS_DIR / "tool_install_summary.json"
        summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        self._log("Batch tool install completed", data={"success": success, "failed": failed, "total": len(urls), "summary": str(summary_path)})
        return summary

    def _install_single(self, url: str, *, install_timeout: int = 900, index: int = 1, total: int = 1) -> dict[str, Any]:
        started = time.time()
        try:
            self._log("Installing batch tool", data={"url": url, "index": index, "total": total})
            tool = self.add_tool(url, approve_install=True, approve_run=False, enable=True)
            install_results = self.install_tool(tool.tool_id, confirm=True, timeout=install_timeout)
            tool = self.registry.get(tool.tool_id) or tool
            ok = all(item.status == "completed" for item in install_results) if install_results else True
            payload = {"ok": ok, "url": url, "tool_id": tool.tool_id, "name": tool.name, "phase": tool.phase, "local_path": tool.local_path, "installed": tool.installed, "enabled": tool.enabled, "approved_for_run": tool.approved_for_run, "has_run": bool(tool.run), "install_results": [item.to_dict() for item in install_results], "elapsed_ms": int((time.time() - started) * 1000)}
            self._log("Batch tool installed" if ok else "Batch tool install had failures", level="INFO" if ok else "ERROR", data=payload)
            return payload
        except Exception as exc:
            payload = {"ok": False, "url": url, "error": str(exc)[:1000], "elapsed_ms": int((time.time() - started) * 1000)}
            self._log("Batch tool install failed", level="ERROR", data=payload)
            return payload

    def _format_run_args(self, token: str, context: dict[str, str]) -> str:
        try:
            return token.format(**context)
        except KeyError as exc:
            raise KeyError(f"missing required context variable in run command: {exc}")

    def _resolve_command(self, command: list[str], cwd: Path) -> list[str]:
        if not command:
            return command
        first = command[0]
        if first.startswith("./") or first.startswith("/") or shutil.which(first):
            return command
        local_binary = cwd / first
        if local_binary.exists():
            return ["./" + first, *command[1:]]
        local_bin_binary = cwd / "bin" / first
        if local_bin_binary.exists():
            return [str(local_bin_binary), *command[1:]]
        return command

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
        parsed_target = urlparse(target if "://" in target else "https://" + target)
        host = parsed_target.hostname or target.replace("https://", "").replace("http://", "").split("/")[0]
        context = {"target": target.rstrip("/"), "host": host, "parameter": parameter, "output_format": output_format, "tool_dir": tool.local_path, "wordlist": os.getenv("VULNSCOPE_FFUF_WORDLIST", "/usr/share/wordlists/dirb/common.txt")}
        command = [self._format_run_args(token, context) for token in tool.run]
        command = self._resolve_command(command, Path(tool.local_path))
        self._log("Running dynamic tool", data={"tool_id": tool_id, "command": command, "target": target})
        result = self._run_command(command, cwd=Path(tool.local_path), timeout=timeout, label=f"run_{tool_id}")
        parsed = self.parse_output(tool.output_parser, result.stdout_path)
        payload = {"tool": tool.to_dict(), "result": result.to_dict(), "parsed_output": parsed}
        run_report = RUNS_DIR / f"{tool_id}_{int(time.time())}.json"
        run_report.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        self._log("Dynamic tool run finished", data={"tool_id": tool_id, "status": result.status, "exit_code": result.exit_code, "stdout": result.stdout_path, "stderr": result.stderr_path, "report": str(run_report)})
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

    def diagnose_tools(self) -> dict[str, Any]:
        self.reconcile_installed_tools(approve_known=True, enable=True)
        rows = []
        for tool in self.registry.list():
            path = Path(tool.local_path)
            executable = tool.run[0] if tool.run else ""
            rows.append({"tool_id": tool.tool_id, "name": tool.name, "phase": tool.phase, "path_exists": path.exists(), "enabled": tool.enabled, "installed": tool.installed, "approved_for_run": tool.approved_for_run, "has_run_command": bool(tool.run), "run": tool.run, "first_executable_available": bool(executable and (shutil.which(executable) or (path / executable).exists() or (path / "bin" / executable).exists())), "metadata": tool.metadata})
        payload = {"generated_at": time.time(), "tools": rows, "registry": str(self.registry.path)}
        diag_path = LOGS_DIR / "tool_diagnostics.json"
        diag_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        self._log("Tool diagnostics written", data={"path": str(diag_path), "tools": len(rows)})
        return payload

    def list_tools(self) -> list[dict[str, Any]]:
        self.reconcile_installed_tools(approve_known=True, enable=True)
        return self.registry.as_table_rows()

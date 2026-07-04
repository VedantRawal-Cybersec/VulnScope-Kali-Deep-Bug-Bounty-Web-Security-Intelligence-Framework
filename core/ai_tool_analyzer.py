#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.tool_phase_classifier import classify_tool_phase
from core.tool_safety_classifier import classify_tool_safety

TOOLS_DIR = Path("tools")
LOG_DIR = Path("logs/tool_analysis")
README_NAMES = ["README.md", "README.rst", "README.txt", "readme.md"]


@dataclass
class ProbeResult:
    command: list[str]
    status: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    elapsed_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolAnalysis:
    repo_url: str
    local_path: str
    name: str
    language: str
    install_commands: list[str]
    entrypoint_candidates: list[str]
    run_command: list[str]
    help_probe_commands: list[list[str]]
    output_parser: str
    phase: str
    safety_level: str
    required_scan_mode: str
    status: str
    reasons: list[str] = field(default_factory=list)
    probes: list[dict[str, Any]] = field(default_factory=list)
    manifest_path: str = ""
    report_path: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AIToolAnalyzer:
    """Deep static + safe-probe analyzer for pasted GitHub security tool repos.

    It does not run a tool against a target during analysis. It only clones,
    reads files, runs help/version probes, and writes a manifest candidate.
    """

    def __init__(self, *, timeout: int = 25, use_llm: bool = True) -> None:
        self.timeout = max(5, int(timeout))
        self.use_llm = use_llm
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        LOG_DIR.mkdir(parents=True, exist_ok=True)

    def slug(self, repo_url: str) -> str:
        parsed = urlparse(repo_url)
        path = parsed.path.strip("/").removesuffix(".git")
        slug = re.sub(r"[^a-zA-Z0-9_.-]+", "__", path) or "tool"
        return slug[:120]

    def clone_or_update(self, repo_url: str) -> Path:
        target = TOOLS_DIR / self.slug(repo_url)
        if target.exists() and (target / ".git").exists():
            subprocess.run(["git", "-C", str(target), "pull", "--ff-only"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120, check=False)
            return target
        if target.exists() and not (target / ".git").exists():
            raise RuntimeError(f"tool path exists but is not a git repo: {target}")
        subprocess.run(["git", "clone", "--depth", "1", repo_url, str(target)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=240, check=True)
        return target

    def read_repo_text(self, path: Path) -> str:
        chunks: list[str] = []
        for name in README_NAMES:
            item = path / name
            if item.exists():
                chunks.append(f"# {name}\n" + item.read_text(encoding="utf-8", errors="ignore")[:18000])
                break
        for name in ["package.json", "pyproject.toml", "setup.py", "requirements.txt", "go.mod", "Cargo.toml", "Makefile", "Dockerfile"]:
            item = path / name
            if item.exists():
                chunks.append(f"# {name}\n" + item.read_text(encoding="utf-8", errors="ignore")[:6000])
        files = []
        for item in path.rglob("*"):
            if item.is_file() and ".git" not in item.parts:
                rel = item.relative_to(path).as_posix()
                if len(files) < 300:
                    files.append(rel)
        chunks.append("# file_tree\n" + "\n".join(files))
        return "\n\n".join(chunks)[:55000]

    def detect_language(self, path: Path) -> str:
        if (path / "go.mod").exists():
            return "go"
        if (path / "package.json").exists():
            return "node"
        if (path / "pyproject.toml").exists() or (path / "setup.py").exists() or (path / "requirements.txt").exists():
            return "python"
        if (path / "Cargo.toml").exists():
            return "rust"
        if any(path.glob("*.py")):
            return "python"
        if any(path.glob("*.go")):
            return "go"
        if any(path.glob("*.js")):
            return "node"
        if any(path.glob("*.sh")):
            return "shell"
        return "unknown"

    def install_commands(self, path: Path, language: str) -> list[str]:
        commands: list[str] = []
        if (path / "requirements.txt").exists():
            commands.append("python3 -m pip install -r requirements.txt")
        if (path / "pyproject.toml").exists():
            commands.append("python3 -m pip install .")
        if (path / "setup.py").exists():
            commands.append("python3 -m pip install .")
        if (path / "package.json").exists():
            commands.append("npm install")
        if (path / "go.mod").exists():
            commands.append("go build ./...")
        if (path / "Cargo.toml").exists():
            commands.append("cargo build --release")
        if (path / "install.sh").exists():
            commands.append("bash install.sh")
        return list(dict.fromkeys(commands))

    def entrypoints(self, path: Path, language: str) -> list[str]:
        candidates: list[str] = []
        for name in [path.name, "main", "scanner", "scan", "cli", "app"]:
            if name:
                candidates.append(name)
        if language == "python":
            for rel in ["main.py", "scanner.py", "scan.py", "cli.py", "app.py"]:
                if (path / rel).exists():
                    candidates.append(f"python3 {rel}")
            for item in sorted(path.glob("*.py"))[:10]:
                candidates.append(f"python3 {item.name}")
        elif language == "go":
            candidates.extend([path.name, "go run ."])
            if (path / "cmd").exists():
                for item in sorted((path / "cmd").iterdir())[:8]:
                    if item.is_dir():
                        candidates.append(f"go run ./cmd/{item.name}")
        elif language == "node":
            if (path / "package.json").exists():
                try:
                    package = json.loads((path / "package.json").read_text(encoding="utf-8", errors="ignore"))
                    bin_value = package.get("bin")
                    if isinstance(bin_value, str):
                        candidates.append("node " + bin_value)
                    elif isinstance(bin_value, dict):
                        for _, value in list(bin_value.items())[:5]:
                            candidates.append("node " + str(value))
                    scripts = package.get("scripts") or {}
                    for key in ["start", "cli", "scan"]:
                        if key in scripts:
                            candidates.append(f"npm run {key} --")
                except Exception:
                    pass
            for item in ["index.js", "cli.js", "app.js"]:
                if (path / item).exists():
                    candidates.append("node " + item)
        elif language == "rust":
            candidates.extend(["cargo run --", str(path.name)])
        elif language == "shell":
            for item in sorted(path.glob("*.sh"))[:8]:
                candidates.append("bash " + item.name)
        output: list[str] = []
        for candidate in candidates:
            if candidate and candidate not in output:
                output.append(candidate)
        return output[:20]

    def help_probe_commands(self, candidates: list[str]) -> list[list[str]]:
        probes: list[list[str]] = []
        for candidate in candidates[:8]:
            base = shlex.split(candidate)
            probes.append(base + ["--help"])
            probes.append(base + ["-h"])
            probes.append(base + ["--version"])
        return probes[:18]

    def run_probe(self, path: Path, command: list[str]) -> ProbeResult:
        started = time.time()
        try:
            proc = subprocess.run(command, cwd=str(path), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL, timeout=self.timeout, shell=False)
            return ProbeResult(command=command, status="completed" if proc.returncode == 0 else "failed", exit_code=proc.returncode, stdout=proc.stdout[:5000], stderr=proc.stderr[:5000], elapsed_ms=int((time.time() - started) * 1000))
        except subprocess.TimeoutExpired:
            return ProbeResult(command=command, status="timed_out", error=f"timeout after {self.timeout}s", elapsed_ms=int((time.time() - started) * 1000))
        except FileNotFoundError as exc:
            return ProbeResult(command=command, status="missing_binary", error=str(exc), elapsed_ms=int((time.time() - started) * 1000))
        except Exception as exc:
            return ProbeResult(command=command, status="failed", error=str(exc)[:1000], elapsed_ms=int((time.time() - started) * 1000))

    def infer_output_parser(self, text: str) -> str:
        lower = text.lower()
        if "jsonl" in lower or "-jsonl" in lower or "--jsonl" in lower:
            return "jsonl"
        if "json" in lower or "-json" in lower or "--json" in lower:
            return "json"
        return "plain"

    def infer_run_command(self, *, name: str, candidates: list[str], probe_text: str, output_parser: str) -> list[str]:
        chosen = shlex.split(candidates[0]) if candidates else [name]
        lower = probe_text.lower()
        target_flag = ""
        for flag in ["-u", "--url", "--target", "-target", "-host", "--host", "-d", "--domain"]:
            if flag in lower:
                target_flag = flag
                break
        if not target_flag:
            target_flag = "--target"
        command = [*chosen, target_flag, "{target}"]
        if output_parser == "jsonl" and "jsonl" in lower:
            if "-jsonl" in lower:
                command.append("-jsonl")
            elif "--jsonl" in lower:
                command.append("--jsonl")
        elif output_parser == "json" and "json" in lower:
            if "-json" in lower:
                command.append("-json")
            elif "--json" in lower:
                command.append("--json")
        if "rate-limit" in lower:
            command.extend(["-rate-limit", "5"])
        if "silent" in lower:
            command.append("-silent")
        return command

    def analyze(self, repo_url: str, *, install: bool = False, register: bool = False) -> ToolAnalysis:
        path = self.clone_or_update(repo_url)
        name = path.name.replace("__", "/").split("/")[-1]
        text = self.read_repo_text(path)
        language = self.detect_language(path)
        install_cmds = self.install_commands(path, language)
        candidates = self.entrypoints(path, language)
        probes = []
        probe_text = ""
        for command in self.help_probe_commands(candidates):
            result = self.run_probe(path, command)
            probes.append(result.to_dict())
            probe_text += "\n" + result.stdout + "\n" + result.stderr + "\n" + result.error
            if result.status == "completed" and ("usage" in (result.stdout + result.stderr).lower() or "help" in (result.stdout + result.stderr).lower()):
                break
        combined = text + "\n" + probe_text
        phase = classify_tool_phase(name=name, text=combined)
        safety = classify_tool_safety(name=name, text=combined, commands=candidates)
        output_parser = self.infer_output_parser(combined)
        run_cmd = self.infer_run_command(name=name, candidates=candidates, probe_text=combined, output_parser=output_parser)
        reasons = [*phase.reasons, *safety.reasons]
        status = "BLOCKED" if safety.blocked else "ANALYZED"
        if not candidates:
            status = "NEEDS_MANUAL_REVIEW"
            reasons.append("no CLI entrypoint candidate detected")
        if probes and not any(item.get("status") == "completed" for item in probes):
            status = "NEEDS_MANUAL_REVIEW" if status != "BLOCKED" else status
            reasons.append("help/version probe did not complete successfully")
        analysis = ToolAnalysis(repo_url=repo_url, local_path=str(path), name=name, language=language, install_commands=install_cmds, entrypoint_candidates=candidates, run_command=run_cmd, help_probe_commands=self.help_probe_commands(candidates), output_parser=output_parser, phase=phase.phase, safety_level=safety.safety_level, required_scan_mode=safety.required_scan_mode, status=status, reasons=reasons[:80], probes=probes, metadata={"phase_confidence": phase.confidence, "auto_approve_run": safety.auto_approve_run, "blocked": safety.blocked})
        report_path = LOG_DIR / (re.sub(r"[^a-zA-Z0-9_.-]+", "_", name) + "_analysis.json")
        report_path.write_text(json.dumps(analysis.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        analysis.report_path = str(report_path)
        return analysis

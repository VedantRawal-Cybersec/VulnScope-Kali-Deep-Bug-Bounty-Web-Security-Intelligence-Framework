#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.ai_brain import AIBrain
from core.tool_manager import ToolManager


class DynamicToolInstaller:
    def __init__(self, brain: AIBrain | None = None, tools_dir: str | Path = "tools") -> None:
        self.brain = brain or AIBrain()
        self.tools_dir = Path(tools_dir)
        self.tools_dir.mkdir(parents=True, exist_ok=True)
        self.manager = ToolManager()

    def slug(self, repo_url: str) -> str:
        parsed = urlparse(repo_url)
        path = parsed.path.strip("/").removesuffix(".git")
        return re.sub(r"[^a-zA-Z0-9_.-]+", "__", path)[:120] or f"tool_{int(time.time())}"

    def clone_or_update(self, repo_url: str) -> Path:
        target = self.tools_dir / self.slug(repo_url)
        if target.exists() and (target / ".git").exists():
            subprocess.run(["git", "-C", str(target), "pull", "--ff-only"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120, check=False)
            return target
        if target.exists():
            raise RuntimeError(f"Tool path exists but is not a git repo: {target}")
        subprocess.run(["git", "clone", "--depth", "1", repo_url, str(target)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=240, check=True)
        return target

    def repo_text(self, path: Path) -> str:
        chunks: list[str] = []
        for name in ["README.md", "README.rst", "README.txt", "pyproject.toml", "package.json", "go.mod"]:
            item = path / name
            if item.exists():
                chunks.append(f"# {name}\n" + item.read_text(encoding="utf-8", errors="ignore")[:12000])
        files: list[str] = []
        for item in path.rglob("*"):
            if item.is_file() and ".git" not in item.parts:
                files.append(item.relative_to(path).as_posix())
            if len(files) >= 250:
                break
        chunks.append("# files\n" + "\n".join(files))
        return "\n\n".join(chunks)[:50000]

    def heuristic_manifest(self, repo_url: str, path: Path) -> dict[str, Any]:
        name = path.name.replace("__", "/")
        lower = name.lower()
        phase = "discovery"
        parser = "plain"
        run: list[str] = []
        if "nuclei" in lower:
            phase = "validation"
            parser = "jsonl"
            run = ["nuclei", "-u", "{target}", "-jsonl", "-silent", "-severity", "info,low,medium", "-rate-limit", "5", "-no-interactsh"]
        elif "httpx" in lower:
            phase = "recon"
            parser = "json"
            run = ["httpx", "-u", "{target}", "-json", "-silent", "-follow-redirects"]
        elif "katana" in lower:
            phase = "discovery"
            parser = "jsonl"
            run = ["katana", "-u", "{target}", "-jsonl", "-silent", "-d", "2"]
        elif "subfinder" in lower:
            phase = "recon"
            parser = "jsonl"
            run = ["subfinder", "-d", "{host}", "-json", "-silent"]
        install: list[str] = []
        if (path / "requirements.txt").exists():
            install.append("python3 -m pip install -r requirements.txt")
        if (path / "package.json").exists():
            install.append("npm install")
        if (path / "go.mod").exists():
            install.append("go build ./...")
        return {"name": name, "version": "unknown", "phase": phase, "install": install, "run": run, "arguments": [{"name": "target", "description": "Target URL", "required": True}], "output_parser": parser, "metadata": {"requires_manual_review": not bool(run), "heuristic_manifest": True, "repo_url": repo_url}}

    def generate_manifest(self, repo_url: str, path: Path) -> dict[str, Any]:
        prompt = "Create a safe VulnScope manifest for this CLI assessment tool. Return JSON only with fields name, version, phase, install, run, arguments, output_parser, metadata. If unsure, run must be an empty list. Repo: " + repo_url + "\n" + self.repo_text(path)
        answer = self.brain.ask_ollama(prompt)
        try:
            manifest = json.loads(answer[answer.find("{"):answer.rfind("}") + 1])
        except Exception:
            manifest = self.heuristic_manifest(repo_url, path)
        manifest.setdefault("name", path.name.replace("__", "/"))
        manifest.setdefault("version", "unknown")
        manifest.setdefault("phase", "discovery")
        manifest.setdefault("install", [])
        manifest.setdefault("run", [])
        manifest.setdefault("arguments", [{"name": "target", "description": "Target URL", "required": True}])
        manifest.setdefault("output_parser", "plain")
        manifest.setdefault("metadata", {})
        manifest["metadata"]["repo_url"] = repo_url
        manifest["metadata"]["generated_by"] = "vulnscope_dynamic_tool_installer"
        return manifest

    def write_manifest(self, path: Path, manifest: dict[str, Any]) -> Path:
        out = path / "manifest.json"
        out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        return out

    def install_dependencies(self, path: Path, manifest: dict[str, Any], *, approve_install: bool = False) -> list[dict[str, Any]]:
        if not approve_install:
            return [{"status": "skipped", "reason": "install approval not provided"}]
        results: list[dict[str, Any]] = []
        for command in manifest.get("install", []) or []:
            cmd = command.split() if isinstance(command, str) else [str(item) for item in command]
            started = time.time()
            try:
                proc = subprocess.run(cmd, cwd=str(path), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300, check=False)
                results.append({"command": cmd, "exit_code": proc.returncode, "stdout": proc.stdout[-2000:], "stderr": proc.stderr[-2000:], "elapsed_ms": int((time.time() - started) * 1000)})
            except Exception as exc:
                results.append({"command": cmd, "error": str(exc), "elapsed_ms": int((time.time() - started) * 1000)})
        return results

    def install_and_register(self, repo_url: str, *, approve_install: bool = False, approve_run: bool = False, enable: bool = True) -> dict[str, Any]:
        path = self.clone_or_update(repo_url)
        manifest = self.generate_manifest(repo_url, path)
        manifest_path = self.write_manifest(path, manifest)
        install_results = self.install_dependencies(path, manifest, approve_install=approve_install)
        tool = self.manager.add_tool(repo_url, approve_install=approve_install, approve_run=approve_run and bool(manifest.get("run")), enable=enable)
        return {"repo_url": repo_url, "local_path": str(path), "manifest_path": str(manifest_path), "install_results": install_results, "tool": tool.to_dict(), "approved_run": tool.approved_for_run}

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

OUT = Path("reports/output/vulnscope-main")

DEFAULT_OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_OLLAMA_MODEL = "qwen2.5:3b"

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
DIM = "\033[2m"

PYTHON_PACKAGES = [
    ("requests", "requests"),
    ("beautifulsoup4", "bs4"),
    ("lxml", "lxml"),
    ("python-dotenv", "dotenv"),
    ("click", "click"),
    ("pyyaml", "yaml"),
    ("colorama", "colorama"),
    ("tqdm", "tqdm"),
]

CORE_TOOLS = ["git", "curl", "python3"]
OPTIONAL_DISCOVERY_TOOLS = ["nmap", "dirsearch", "subfinder"]


def color(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if sys.stdout.isatty() else text


def _now() -> float:
    return time.time()


def _run(cmd: list[str], timeout: int = 300) -> dict[str, Any]:
    started = _now()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return {
            "status": "ok" if proc.returncode == 0 else "nonzero_exit",
            "ok": proc.returncode == 0,
            "exit_code": proc.returncode,
            "command": cmd,
            "seconds": round(_now() - started, 2),
            "output_tail": (proc.stdout or "")[-4000:],
        }
    except FileNotFoundError as exc:
        return {"status": "missing_binary", "ok": False, "command": cmd, "error": str(exc), "seconds": round(_now() - started, 2)}
    except subprocess.TimeoutExpired as exc:
        return {"status": "timeout", "ok": False, "command": cmd, "error": str(exc), "seconds": round(_now() - started, 2)}
    except Exception as exc:
        return {"status": "error", "ok": False, "command": cmd, "error": str(exc), "seconds": round(_now() - started, 2)}


def _json_get(url: str, timeout: int = 8) -> tuple[bool, dict[str, Any] | str]:
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
        try:
            return True, json.loads(raw)
        except Exception:
            return True, raw[:1000]
    except urllib.error.URLError as exc:
        return False, str(exc)
    except Exception as exc:
        return False, str(exc)


def _ollama_tags_url(generate_url: str) -> str:
    value = generate_url.strip().rstrip("/")
    if value.endswith("/api/generate"):
        return value[: -len("/api/generate")] + "/api/tags"
    if value.endswith("/api/chat"):
        return value[: -len("/api/chat")] + "/api/tags"
    if value.endswith("/api/tags"):
        return value
    return value + "/api/tags"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    _write(path, json.dumps(payload, indent=2, ensure_ascii=False))


def check_python_packages() -> list[dict[str, Any]]:
    rows = []
    for package, module in PYTHON_PACKAGES:
        result = _run([sys.executable, "-c", f"import {module}; print('ok')"], timeout=30)
        rows.append({"package": package, "module": module, "status": "installed" if result.get("ok") else "missing", "detail": result})
    return rows


def install_python_packages() -> dict[str, Any]:
    packages = [name for name, _module in PYTHON_PACKAGES]
    return _run([sys.executable, "-m", "pip", "install", "--upgrade", *packages], timeout=600)


def check_tools(tools: list[str]) -> list[dict[str, Any]]:
    rows = []
    for tool in tools:
        path = shutil.which(tool)
        rows.append({"tool": tool, "status": "available" if path else "missing", "path": path or ""})
    return rows


def check_core_tools() -> list[dict[str, Any]]:
    return check_tools(CORE_TOOLS)


def check_optional_tools() -> list[dict[str, Any]]:
    return check_tools(OPTIONAL_DISCOVERY_TOOLS)


def run_safe_tool_setup(enabled: bool = True) -> dict[str, Any]:
    if not enabled:
        return {"status": "skipped", "ok": True, "reason": "disabled_by_flag"}
    script = Path("safe_tool_setup_cli.py")
    if not script.exists():
        return {"status": "missing", "ok": False, "reason": "safe_tool_setup_cli.py not found"}
    return _run([sys.executable, str(script), "--yes"], timeout=1800)


def start_ollama_if_possible() -> dict[str, Any]:
    if not shutil.which("ollama"):
        return {"status": "missing_binary", "ok": False, "message": "ollama command not found"}
    log_path = Path("reports/output/runtime-logs/ollama-preflight.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with log_path.open("ab") as log:
            subprocess.Popen(["ollama", "serve"], stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
        time.sleep(3)
        return {"status": "started_or_already_running", "ok": True, "log": str(log_path)}
    except Exception as exc:
        return {"status": "start_failed", "ok": False, "error": str(exc), "log": str(log_path)}


def check_ollama(*, generate_url: str, model: str, auto_pull_model: bool = True) -> dict[str, Any]:
    started = _now()
    binary = shutil.which("ollama")
    tags_url = _ollama_tags_url(generate_url)
    service_ok, service_payload = _json_get(tags_url, timeout=8)
    start_result: dict[str, Any] = {}
    if not service_ok and binary:
        start_result = start_ollama_if_possible()
        service_ok, service_payload = _json_get(tags_url, timeout=8)

    models: list[str] = []
    if service_ok and isinstance(service_payload, dict):
        for row in service_payload.get("models", []) or []:
            name = str(row.get("name") or row.get("model") or "")
            if name:
                models.append(name)

    model_present = model in models or any(x.startswith(model + ":") for x in models)
    pull_result: dict[str, Any] = {}
    if service_ok and binary and model and not model_present and auto_pull_model:
        pull_result = _run(["ollama", "pull", model], timeout=7200)
        service_ok, service_payload = _json_get(tags_url, timeout=8)
        models = []
        if service_ok and isinstance(service_payload, dict):
            for row in service_payload.get("models", []) or []:
                name = str(row.get("name") or row.get("model") or "")
                if name:
                    models.append(name)
        model_present = model in models or any(x.startswith(model + ":") for x in models)

    return {
        "binary": "available" if binary else "missing",
        "binary_path": binary or "",
        "generate_url": generate_url,
        "tags_url": tags_url,
        "service": "running" if service_ok else "unreachable",
        "service_detail": service_payload if not service_ok else "ok",
        "start_attempt": start_result,
        "model": model,
        "models": models,
        "model_present": model_present,
        "latency_ms": int((_now() - started) * 1000),
        "pull_attempt": pull_result,
        "ok": bool(binary and service_ok and model_present),
        "install_hint": "Install Ollama and run: ollama pull " + model if not binary else "",
    }


def render_report(payload: dict[str, Any]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    _write_json(OUT / "preflight.json", payload)
    lines = [
        "# VulnScope One-Command Preflight",
        "",
        f"Status: `{'READY' if payload.get('ok') else 'ACTION_REQUIRED'}`",
        "",
        "## Summary",
        "```json",
        json.dumps(payload.get("summary", {}), indent=2, ensure_ascii=False),
        "```",
        "",
        "## Python Packages",
    ]
    for row in payload.get("python_packages", []):
        lines.append(f"- `{row.get('package')}` status=`{row.get('status')}`")
    lines += ["", "## Core Tools"]
    for row in payload.get("core_tools", []):
        lines.append(f"- `{row.get('tool')}` status=`{row.get('status')}` path=`{row.get('path')}`")
    lines += ["", "## Optional Discovery Tools"]
    for row in payload.get("optional_tools", []):
        lines.append(f"- `{row.get('tool')}` status=`{row.get('status')}` path=`{row.get('path')}`")
    lines += ["", "## Tool Setup", "```json", json.dumps(payload.get("safe_tool_setup", {}), indent=2, ensure_ascii=False)[:3000], "```", "", "## Ollama", "```json", json.dumps(payload.get("ollama", {}), indent=2, ensure_ascii=False)[:3000], "```"]
    if payload.get("blocking_issues"):
        lines += ["", "## Blocking Issues"]
        for issue in payload.get("blocking_issues", []):
            lines.append(f"- {issue}")
    _write(OUT / "preflight.md", "\n".join(lines))


def run_preflight(
    *,
    install_python: bool = True,
    run_tool_setup_flag: bool = True,
    check_ollama_flag: bool = True,
    require_ollama: bool = True,
    auto_pull_model: bool = True,
    ollama_url: str | None = None,
    ollama_model: str | None = None,
) -> dict[str, Any]:
    ollama_url = ollama_url or os.getenv("VULNSCOPE_OLLAMA_URL", DEFAULT_OLLAMA_URL)
    ollama_model = ollama_model or os.getenv("VULNSCOPE_OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)

    core_tools = check_core_tools()
    optional_tools = check_optional_tools()
    py_before = check_python_packages()
    missing_py = [x for x in py_before if x.get("status") != "installed"]
    python_install_result: dict[str, Any] = {}
    if missing_py and install_python:
        python_install_result = install_python_packages()
    py_after = check_python_packages()

    safe_tool_setup = run_safe_tool_setup(enabled=run_tool_setup_flag)
    ollama = check_ollama(generate_url=ollama_url, model=ollama_model, auto_pull_model=auto_pull_model) if check_ollama_flag else {"ok": True, "status": "skipped", "latency_ms": 0}

    missing_after = [x.get("package") for x in py_after if x.get("status") != "installed"]
    missing_core = [x.get("tool") for x in core_tools if x.get("status") != "available"]
    blocking: list[str] = []
    if missing_after:
        blocking.append("Missing Python packages: " + ", ".join(map(str, missing_after)))
    if missing_core:
        blocking.append("Missing core tools: " + ", ".join(map(str, missing_core)))
    if not safe_tool_setup.get("ok"):
        blocking.append("Safe tool setup did not complete. See reports/output/top100-tools/ and reports/output/vulnscope-main/preflight.md")
    if check_ollama_flag and require_ollama and not ollama.get("ok"):
        blocking.append("Ollama is not ready. Install/start Ollama and pull the selected model, or run with --allow-ollama-fallback.")

    payload = {
        "generated_at": _now(),
        "ok": not blocking,
        "blocking_issues": blocking,
        "summary": {
            "python_version": ".".join(map(str, sys.version_info[:3])),
            "python_missing": len(missing_after),
            "core_tools_missing": len(missing_core),
            "optional_tools_available": sum(1 for x in optional_tools if x.get("status") == "available"),
            "safe_tool_setup": safe_tool_setup.get("status"),
            "ollama_ready": bool(ollama.get("ok")),
            "ollama_model": ollama_model,
            "ollama_url": ollama_url,
            "ollama_latency_ms": ollama.get("latency_ms", 0),
            "workspace": str(Path.cwd() / "reports/output"),
        },
        "python_packages": py_after,
        "python_install": python_install_result,
        "core_tools": core_tools,
        "optional_tools": optional_tools,
        "safe_tool_setup": safe_tool_setup,
        "ollama": ollama,
        "reports": {"json": str(OUT / "preflight.json"), "markdown": str(OUT / "preflight.md")},
    }
    render_report(payload)
    return payload


def print_preflight_status(payload: dict[str, Any]) -> None:
    status = "READY" if payload.get("ok") else "ACTION REQUIRED"
    print(color(f"\n[Preflight] {status}", GREEN if payload.get("ok") else RED))
    summary = payload.get("summary", {})
    py_version = summary.get("python_version") or f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    core = ", ".join(row.get("tool", "") for row in payload.get("core_tools", []) if row.get("status") == "available") or "none"
    optional = ", ".join(row.get("tool", "") for row in payload.get("optional_tools", []) if row.get("status") == "available")
    if optional:
        core_display = core + ", " + optional
    else:
        core_display = core
    print(color(f"  ✅ Python {py_version}", GREEN))
    print(color(f"  ✅ Core tools: {core_display}", GREEN))
    setup = summary.get("safe_tool_setup")
    print(color(f"  ✅ Safe tool setup: {setup}", GREEN) if setup in {"ok", "skipped"} else color(f"  ⚠️  Safe tool setup: {setup}", YELLOW))
    if summary.get("ollama_ready"):
        print(color(f"  ✅ Ollama ready: {summary.get('ollama_model')} (latency {summary.get('ollama_latency_ms', 0)}ms)", GREEN))
    else:
        print(color(f"  ⚠️  Ollama fallback mode: {summary.get('ollama_model')}", YELLOW))
    print(color(f"  ✅ Workspace: {summary.get('workspace')}", GREEN))
    for issue in payload.get("blocking_issues", []):
        print(color(f"[BLOCKING] {issue}", RED))


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope one-command preflight")
    parser.add_argument("--no-python-install", action="store_true")
    parser.add_argument("--skip-tool-setup", action="store_true")
    parser.add_argument("--skip-ollama", action="store_true")
    parser.add_argument("--allow-ollama-fallback", action="store_true")
    parser.add_argument("--no-model-pull", action="store_true")
    parser.add_argument("--ollama-url", default=os.getenv("VULNSCOPE_OLLAMA_URL", DEFAULT_OLLAMA_URL))
    parser.add_argument("--ollama-model", default=os.getenv("VULNSCOPE_OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL))
    args = parser.parse_args()
    payload = run_preflight(
        install_python=not args.no_python_install,
        run_tool_setup_flag=not args.skip_tool_setup,
        check_ollama_flag=not args.skip_ollama,
        require_ollama=not args.allow_ollama_fallback,
        auto_pull_model=not args.no_model_pull,
        ollama_url=args.ollama_url,
        ollama_model=args.ollama_model,
    )
    print_preflight_status(payload)
    return 0 if payload.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())

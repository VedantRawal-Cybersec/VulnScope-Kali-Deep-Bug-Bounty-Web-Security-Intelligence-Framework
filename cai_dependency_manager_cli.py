#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from cai_error_handler import handled_error, write_json, write_markdown

OUT = Path("reports/output/cai-superior/dependencies")

PYTHON_PACKAGES = [
    "tqdm",
    "colorama",
    "requests",
    "beautifulsoup4",
    "lxml",
    "python-dotenv",
    "click",
    "pyyaml",
]

SAFE_TOOL_STATUS = [
    "git",
    "curl",
    "wget",
    "subfinder",
    "amass",
    "dnsx",
    "httpx",
    "katana",
    "gospider",
    "gau",
    "waybackurls",
    "tlsx",
    "nuclei",
    "nikto",
]

MANUAL_REVIEW_TOOLS = [
    "hydra",
    "john",
    "msfconsole",
]


def _run(cmd: list[str], timeout: int = 120) -> dict[str, Any]:
    started = time.time()
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return {"status": "ok" if proc.returncode == 0 else "nonzero_exit", "exit_code": proc.returncode, "stdout_tail": proc.stdout[-4000:], "seconds": round(time.time() - started, 2)}
    except FileNotFoundError as exc:
        return handled_error(component="dependency_manager", action="run_" + cmd[0], error=exc, fallback_used="tool_missing")
    except subprocess.TimeoutExpired as exc:
        return handled_error(component="dependency_manager", action="run_" + cmd[0], error=exc, fallback_used="timeout_continue")
    except Exception as exc:
        return handled_error(component="dependency_manager", action="run_" + cmd[0], error=exc)


def _python_import_name(package: str) -> str:
    return {"beautifulsoup4": "bs4", "python-dotenv": "dotenv", "pyyaml": "yaml"}.get(package, package.replace("-", "_"))


def package_status() -> list[dict[str, Any]]:
    rows = []
    for package in PYTHON_PACKAGES:
        mod = _python_import_name(package)
        result = _run([sys.executable, "-c", f"import {mod}; print('ok')"], timeout=20)
        rows.append({"name": package, "type": "python", "module": mod, "status": "installed" if result.get("status") == "ok" else "missing", "detail": result})
    return rows


def tool_status() -> list[dict[str, Any]]:
    rows = []
    for tool in SAFE_TOOL_STATUS:
        path = shutil.which(tool)
        rows.append({"name": tool, "type": "safe_cli_tool", "status": "available" if path else "missing", "path": path or ""})
    for tool in MANUAL_REVIEW_TOOLS:
        path = shutil.which(tool)
        rows.append({"name": tool, "type": "manual_review_tool", "status": "available_but_disabled" if path else "not_installed_or_not_in_path", "path": path or "", "policy": "not executed by CAI zero-impact automation"})
    return rows


def install_python_packages() -> dict[str, Any]:
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", *PYTHON_PACKAGES]
    return _run(cmd, timeout=240)


def clone_cai_reference() -> dict[str, Any]:
    dest = Path("external/cai-reference")
    if dest.exists():
        return {"status": "already_present", "path": str(dest)}
    dest.parent.mkdir(parents=True, exist_ok=True)
    return _run(["git", "clone", "--depth", "1", "https://github.com/aliasrobotics/cai", str(dest)], timeout=240)


def build_dependency_report(*, install_python: bool = False, clone_reference: bool = False) -> dict[str, Any]:
    actions: dict[str, Any] = {}
    if install_python:
        actions["python_package_install"] = install_python_packages()
    if clone_reference:
        actions["cai_reference_clone"] = clone_cai_reference()
    py = package_status()
    tools = tool_status()
    payload = {
        "generated_at": time.time(),
        "layer": 0,
        "name": "System Initialization and Dependency Manager",
        "actions": actions,
        "python_packages": py,
        "tools": tools,
        "summary": {
            "python_installed": len([x for x in py if x.get("status") == "installed"]),
            "python_missing": len([x for x in py if x.get("status") != "installed"]),
            "safe_tools_available": len([x for x in tools if x.get("type") == "safe_cli_tool" and x.get("status") == "available"]),
            "safe_tools_missing": len([x for x in tools if x.get("type") == "safe_cli_tool" and x.get("status") == "missing"]),
            "manual_review_tools": len(MANUAL_REVIEW_TOOLS),
        },
        "safety": {
            "zero_impact_mode": True,
            "credential_attack_tools_executed": False,
            "exploit_frameworks_executed": False,
            "manual_review_note": "Tools associated with credential attacks or exploitation are only inventoried, never executed by the agentic pipeline.",
        },
    }
    return payload


def write_dependency_report(payload: dict[str, Any]) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    write_json(OUT / "dependency-report.json", payload)
    checkpoint = {"checkpoint": "0-dependencies", "name": "Dependency Manager", "status": "completed", "summary": payload.get("summary", {}), "reports": {"json": str(OUT / "dependency-report.json"), "markdown": str(OUT / "dependency-report.md")}, "generated_at": time.time()}
    write_json(OUT / "checkpoint-dependencies.json", checkpoint)
    lines = [
        "# CAI Dependency Report",
        "",
        "## Summary",
        "```json",
        json.dumps(payload.get("summary", {}), indent=2, ensure_ascii=False),
        "```",
        "",
        "## Python Packages",
    ]
    for row in payload.get("python_packages", []):
        lines.append(f"- `{row.get('name')}` status=`{row.get('status')}`")
    lines += ["", "## Tool Status"]
    for row in payload.get("tools", []):
        lines.append(f"- `{row.get('name')}` type=`{row.get('type')}` status=`{row.get('status')}` policy=`{row.get('policy', '')}`")
    write_markdown(OUT / "dependency-report.md", lines)
    return checkpoint


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI agentic dependency manager")
    parser.add_argument("--install-python", action="store_true")
    parser.add_argument("--clone-cai-reference", action="store_true")
    args = parser.parse_args()
    payload = build_dependency_report(install_python=args.install_python, clone_reference=args.clone_cai_reference)
    print(json.dumps(write_dependency_report(payload), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

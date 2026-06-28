from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from arsenal.catalog import ArsenalTool

TOOLS_HOME = Path.home() / ".vulnscope" / "tools"
GO_BIN = Path.home() / "go" / "bin"


def is_installed(tool: ArsenalTool) -> bool:
    if shutil.which(tool.binary):
        return True
    if (GO_BIN / tool.binary).exists():
        return True
    if (TOOLS_HOME / "bin" / tool.binary).exists():
        return True
    return False


def install_tool(tool: ArsenalTool, yes: bool = False) -> bool:
    if is_installed(tool):
        print(f"[+] {tool.name} already installed")
        return True
    install_type = tool.install.get("type")
    package = tool.install.get("package")
    if not package:
        print(f"[!] {tool.name}: missing package in catalog")
        return False

    print("\n┌──────────────────── Arsenal Install Request ────────────────────┐")
    print(f"Tool      : {tool.name}")
    print(f"Category  : {tool.category}")
    print(f"Method    : {install_type}")
    print(f"Package   : {package}")
    print(f"Risk      : {tool.risk_level}")
    print("Install dir uses user-local paths where possible.")
    print("└─────────────────────────────────────────────────────────────────┘")
    if not yes:
        answer = input("Install this tool? yes/no: ").strip().lower()
        if answer not in {"yes", "y"}:
            print(f"[!] Skipped install: {tool.name}")
            return False

    if install_type == "go":
        return _install_go(package)
    if install_type == "pipx_or_pip":
        return _install_pip(package)
    print(f"[!] Unsupported install type for {tool.name}: {install_type}")
    return False


def _install_go(package: str) -> bool:
    if not shutil.which("go"):
        print("[!] Go is not installed. Install it first: sudo apt install golang-go -y")
        return False
    command = ["go", "install", package]
    print("[+] " + " ".join(command))
    return subprocess.call(command) == 0


def _install_pip(package: str) -> bool:
    if shutil.which("pipx"):
        command = ["pipx", "install", package]
    else:
        command = ["python3", "-m", "pip", "install", "--user", package]
    print("[+] " + " ".join(command))
    return subprocess.call(command) == 0


def ensure_profile_tools(tools: list[ArsenalTool], auto_install: bool = False, yes: bool = False) -> dict[str, bool]:
    results = {}
    for tool in tools:
        installed = is_installed(tool)
        if not installed and auto_install:
            installed = install_tool(tool, yes=yes)
        results[tool.name] = installed
    return results

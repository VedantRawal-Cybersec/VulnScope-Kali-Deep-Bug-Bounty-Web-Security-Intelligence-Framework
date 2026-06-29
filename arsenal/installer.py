from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from arsenal.catalog import ArsenalTool

TOOLS_HOME = Path.home() / ".vulnscope" / "tools"
GO_BIN = Path.home() / "go" / "bin"
LOG_DIR = Path("reports/output/arsenal")


def is_installed(tool: ArsenalTool) -> bool:
    if shutil.which(tool.binary):
        return True
    if (GO_BIN / tool.binary).exists():
        return True
    if (TOOLS_HOME / "bin" / tool.binary).exists():
        return True
    return False


def _run(command: list[str], *, env: dict[str, str] | None = None) -> bool:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with (LOG_DIR / "install-repair.log").open("a", encoding="utf-8", errors="ignore") as log:
        log.write("\n$ " + " ".join(command) + "\n")
        return subprocess.call(command, stdout=log, stderr=subprocess.STDOUT, env=env) == 0


def _ensure_path_env() -> dict[str, str]:
    env = dict(os.environ)
    extra = [str(GO_BIN), str(TOOLS_HOME / "bin"), str(Path.home() / ".local" / "bin")]
    env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "")])
    return env


def ensure_prerequisites(install_type: str | None, yes: bool = False, allow_system: bool = True) -> bool:
    """Best-effort dependency repair for Kali/Linux.

    User-local installs are preferred. System package installation is attempted
    only when `yes` and `allow_system` are both true.
    """
    if install_type == "go" and shutil.which("go"):
        return True
    if install_type == "pipx_or_pip" and (shutil.which("pipx") or shutil.which("pip3") or shutil.which("pip")):
        return True
    if not yes or not allow_system:
        return False
    if not shutil.which("apt-get"):
        return False
    if install_type == "go":
        return _run(["sudo", "apt-get", "update"]) and _run(["sudo", "apt-get", "install", "-y", "golang-go", "git"])
    if install_type == "pipx_or_pip":
        return _run(["sudo", "apt-get", "update"]) and _run(["sudo", "apt-get", "install", "-y", "python3-pip", "pipx", "git"])
    return False


def install_tool(tool: ArsenalTool, yes: bool = False, allow_system: bool = True) -> bool:
    if is_installed(tool):
        print(f"[+] {tool.name} already installed")
        return True
    install_type = tool.install.get("type")
    package = tool.install.get("package")
    if not package:
        print(f"[!] {tool.name}: missing package in catalog")
        return False

    print("\n┌──────────────────── Arsenal Install/Repair Request ────────────────────┐")
    print(f"Tool      : {tool.name}")
    print(f"Category  : {tool.category}")
    print(f"Method    : {install_type}")
    print(f"Package   : {package}")
    print(f"Risk      : {tool.risk_level}")
    print("Install dir uses user-local paths where possible.")
    print("Log       : reports/output/arsenal/install-repair.log")
    print("└───────────────────────────────────────────────────────────────────────┘")
    if not yes:
        answer = input("Install or repair this tool? yes/no: ").strip().lower()
        if answer not in {"yes", "y"}:
            print(f"[!] Skipped install: {tool.name}")
            return False

    ensure_prerequisites(install_type, yes=yes, allow_system=allow_system)
    if install_type == "go":
        ok = _install_go(package)
    elif install_type == "pipx_or_pip":
        ok = _install_pip(package)
    else:
        print(f"[!] Unsupported install type for {tool.name}: {install_type}")
        return False
    if ok and is_installed(tool):
        print(f"[+] {tool.name} installed/repaired successfully")
        return True
    print(f"[!] {tool.name} install command finished but binary was not found in PATH")
    return is_installed(tool)


def upgrade_tool(tool: ArsenalTool, yes: bool = False, allow_system: bool = True) -> bool:
    """Refresh a curated tool to its catalog package version, usually @latest."""
    if not yes:
        answer = input(f"Update {tool.name} from curated source? yes/no: ").strip().lower()
        if answer not in {"yes", "y"}:
            return False
    if not is_installed(tool):
        return install_tool(tool, yes=True, allow_system=allow_system)
    install_type = tool.install.get("type")
    package = tool.install.get("package")
    if install_type == "go" and package:
        return _install_go(package)
    if install_type == "pipx_or_pip" and package:
        return _upgrade_pip(package)
    return False


def _install_go(package: str) -> bool:
    if not shutil.which("go"):
        print("[!] Go is not installed and automatic prerequisite repair did not complete.")
        return False
    command = ["go", "install", package]
    print("[+] " + " ".join(command))
    return _run(command, env=_ensure_path_env())


def _install_pip(package: str) -> bool:
    if shutil.which("pipx"):
        command = ["pipx", "install", package]
    else:
        command = ["python3", "-m", "pip", "install", "--user", package]
    print("[+] " + " ".join(command))
    return _run(command, env=_ensure_path_env())


def _upgrade_pip(package: str) -> bool:
    if shutil.which("pipx") and not package.startswith("git+"):
        command = ["pipx", "upgrade", package]
    else:
        command = ["python3", "-m", "pip", "install", "--user", "--upgrade", package]
    print("[+] " + " ".join(command))
    return _run(command, env=_ensure_path_env())


def ensure_profile_tools(tools: list[ArsenalTool], auto_install: bool = False, yes: bool = False, allow_system: bool = True) -> dict[str, bool]:
    results = {}
    for tool in tools:
        installed = is_installed(tool)
        if not installed and auto_install:
            installed = install_tool(tool, yes=yes, allow_system=allow_system)
        results[tool.name] = installed
    return results

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from urllib.request import Request, urlopen

from arsenal.catalog import ArsenalTool

TOOLS_HOME = Path.home() / ".vulnscope" / "tools"
GO_ROOT = TOOLS_HOME / "go"
GO_BIN = Path.home() / "go" / "bin"
LOCAL_BIN = TOOLS_HOME / "bin"
LOG_DIR = Path("reports/output/arsenal")
PIPX_HOME = Path.home() / ".local" / "share" / "pipx" / "venvs"


def is_installed(tool: ArsenalTool) -> bool:
    return _find_binary(tool.binary) is not None


def _find_binary(binary: str) -> str | None:
    found = shutil.which(binary)
    if found:
        return found
    candidates = [GO_BIN / binary, LOCAL_BIN / binary, Path.home() / ".local" / "bin" / binary, GO_ROOT / "bin" / binary]
    for item in candidates:
        if item.exists():
            return str(item)
    for root in [PIPX_HOME, TOOLS_HOME]:
        if root.exists():
            for item in root.rglob(binary):
                if item.is_file():
                    return str(item)
    return None


def _run(command: list[str], *, env: dict[str, str] | None = None) -> bool:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with (LOG_DIR / "install-repair.log").open("a", encoding="utf-8", errors="ignore") as log:
        log.write("\n$ " + " ".join(command) + "\n")
        return subprocess.call(command, stdout=log, stderr=subprocess.STDOUT, env=env) == 0


def _ensure_path_env() -> dict[str, str]:
    env = dict(os.environ)
    extra = [str(GO_ROOT / "bin"), str(GO_BIN), str(LOCAL_BIN), str(Path.home() / ".local" / "bin")]
    env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "")])
    env.setdefault("GOBIN", str(GO_BIN))
    return env


def _sudo_apt(*args: str) -> bool:
    """Non-interactive apt helper. Fails fast if sudo needs a password."""
    if not shutil.which("sudo"):
        return False
    return _run(["sudo", "-n", "apt-get", *args])


def ensure_prerequisites(install_type: str | None, yes: bool = False, allow_system: bool = True) -> bool:
    """Best-effort dependency repair for Kali/Linux.

    For Go tools, VulnScope first tries apt. If sudo cannot run non-interactively,
    it bootstraps an official user-local Go release under ~/.vulnscope/tools/go
    so gau, waybackurls, katana, httpx, nuclei, and similar Go tools can install
    without requiring a root password.
    """
    if install_type == "go" and _go_command():
        return True
    if install_type == "pipx_or_pip" and (shutil.which("pipx") or shutil.which("pip3") or shutil.which("pip")):
        return True
    if not yes:
        return False
    if allow_system and shutil.which("apt-get"):
        if install_type == "go" and _sudo_apt("update") and _sudo_apt("install", "-y", "golang-go", "git"):
            return True
        if install_type == "pipx_or_pip" and _sudo_apt("update") and _sudo_apt("install", "-y", "python3-pip", "pipx", "git"):
            return True
    if install_type == "go":
        return _bootstrap_user_go()
    if install_type == "pipx_or_pip" and not shutil.which("pipx"):
        return shutil.which("pip3") is not None or shutil.which("pip") is not None
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
        ok = _install_pip(package, tool.binary)
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
        return _upgrade_pip(package, tool.binary)
    return False


def _go_command() -> str | None:
    found = shutil.which("go")
    if found:
        return found
    local = GO_ROOT / "bin" / "go"
    if local.exists():
        return str(local)
    return None


def _install_go(package: str) -> bool:
    go = _go_command()
    if not go and not _bootstrap_user_go():
        print("[!] Go is not installed and user-local Go bootstrap failed.")
        return False
    go = _go_command()
    if not go:
        return False
    GO_BIN.mkdir(parents=True, exist_ok=True)
    command = [go, "install", package]
    print("[+] " + " ".join(command))
    return _run(command, env=_ensure_path_env())


def _bootstrap_user_go() -> bool:
    if _go_command():
        return True
    machine = platform.machine().lower()
    arch = "amd64" if machine in {"x86_64", "amd64"} else "arm64" if machine in {"aarch64", "arm64"} else ""
    if not arch:
        print(f"[!] Unsupported architecture for user-local Go bootstrap: {machine}")
        return False
    try:
        req = Request("https://go.dev/VERSION?m=text", headers={"User-Agent": "VulnScope-Installer/1.0"})
        with urlopen(req, timeout=20) as response:
            version = response.read(128).decode("utf-8", errors="ignore").splitlines()[0].strip()
        if not version.startswith("go"):
            raise RuntimeError("unexpected Go version response")
        url = f"https://go.dev/dl/{version}.linux-{arch}.tar.gz"
        print(f"[+] Bootstrapping user-local Go: {version} ({arch})")
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "go.tar.gz"
            req = Request(url, headers={"User-Agent": "VulnScope-Installer/1.0"})
            with urlopen(req, timeout=120) as response, archive.open("wb") as handle:
                shutil.copyfileobj(response, handle)
            if GO_ROOT.exists():
                shutil.rmtree(GO_ROOT)
            TOOLS_HOME.mkdir(parents=True, exist_ok=True)
            with tarfile.open(archive, "r:gz") as tar:
                tar.extractall(TOOLS_HOME)
        return (GO_ROOT / "bin" / "go").exists()
    except Exception as exc:
        print(f"[!] User-local Go bootstrap failed: {exc}")
        return False


def _install_pip(package: str, binary: str) -> bool:
    if shutil.which("pipx"):
        command = ["pipx", "install", "--force", package]
    else:
        command = ["python3", "-m", "pip", "install", "--user", "--upgrade", package]
    print("[+] " + " ".join(command))
    ok = _run(command, env=_ensure_path_env())
    _repair_python_binary(binary)
    return ok


def _upgrade_pip(package: str, binary: str) -> bool:
    if shutil.which("pipx") and not package.startswith("git+"):
        command = ["pipx", "upgrade", package]
    elif shutil.which("pipx"):
        command = ["pipx", "install", "--force", package]
    else:
        command = ["python3", "-m", "pip", "install", "--user", "--upgrade", package]
    print("[+] " + " ".join(command))
    ok = _run(command, env=_ensure_path_env())
    _repair_python_binary(binary)
    return ok


def _repair_python_binary(binary: str) -> None:
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    found = _find_binary(binary)
    if found:
        target = LOCAL_BIN / binary
        if not target.exists():
            try:
                target.symlink_to(found)
            except Exception:
                pass


def ensure_profile_tools(tools: list[ArsenalTool], auto_install: bool = False, yes: bool = False, allow_system: bool = True) -> dict[str, bool]:
    results = {}
    for tool in tools:
        installed = is_installed(tool)
        if not installed and auto_install:
            installed = install_tool(tool, yes=yes, allow_system=allow_system)
        results[tool.name] = installed
    return results

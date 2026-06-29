from __future__ import annotations

import os
import platform
import shutil
import stat
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
USER_LOCAL_BIN = Path.home() / ".local" / "bin"
PIPX_HOME = Path.home() / ".local" / "share" / "pipx" / "venvs"
LOG_DIR = Path("reports/output/arsenal")

ALIASES: dict[str, list[str]] = {
    "linkfinder": ["linkfinder", "LinkFinder", "linkfinder.py", "LinkFinder.py"],
    "xnLinkFinder": ["xnLinkFinder", "xnlinkfinder", "xnlinkfinder.py"],
    "graphw00f": ["graphw00f", "Graphw00f", "graphw00f.py"],
    "Gxss": ["Gxss", "gxss"],
}


def names_for(binary: str) -> list[str]:
    names = [binary] + ALIASES.get(binary, []) + ALIASES.get(binary.lower(), [])
    return list(dict.fromkeys([x for x in names if x]))


def is_installed(tool: ArsenalTool) -> bool:
    return _find_binary(tool.binary) is not None


def _find_binary(binary: str) -> str | None:
    for name in names_for(binary):
        found = shutil.which(name)
        if found:
            return found
    wanted = {x.lower() for x in names_for(binary)}
    roots = [LOCAL_BIN, GO_BIN, USER_LOCAL_BIN, GO_ROOT / "bin", PIPX_HOME, TOOLS_HOME]
    for root in roots:
        if not root.exists():
            continue
        for name in names_for(binary):
            direct = root / name
            if direct.exists() and direct.is_file():
                return str(direct)
        try:
            for item in root.rglob("*"):
                if item.is_file() and item.name.lower() in wanted:
                    return str(item)
        except Exception:
            continue
    return None


def _run(command: list[str], *, env: dict[str, str] | None = None) -> bool:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with (LOG_DIR / "install-repair.log").open("a", encoding="utf-8", errors="ignore") as log:
        log.write("\n$ " + " ".join(command) + "\n")
        return subprocess.call(command, stdout=log, stderr=subprocess.STDOUT, env=env) == 0


def _ensure_path_env() -> dict[str, str]:
    env = dict(os.environ)
    extra = [str(LOCAL_BIN), str(GO_ROOT / "bin"), str(GO_BIN), str(USER_LOCAL_BIN)]
    env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "")])
    env["GOBIN"] = str(LOCAL_BIN)
    env["GOPATH"] = str(Path.home() / "go")
    return env


def _chmod_executable(path: Path) -> None:
    try:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass


def _symlink_or_copy(found: str, binary: str) -> None:
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    src = Path(found)
    _chmod_executable(src)
    for name in names_for(binary)[:1]:
        target = LOCAL_BIN / name
        if target.exists():
            _chmod_executable(target)
            continue
        try:
            target.symlink_to(src)
        except Exception:
            try:
                shutil.copy2(src, target)
            except Exception:
                pass
        _chmod_executable(target)


def _post_install_repair(binary: str) -> None:
    found = _find_binary(binary)
    if found:
        _symlink_or_copy(found, binary)


def _sudo_apt(*args: str) -> bool:
    if not shutil.which("sudo"):
        return False
    return _run(["sudo", "-n", "apt-get", *args])


def ensure_prerequisites(install_type: str | None, yes: bool = False, allow_system: bool = True) -> bool:
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
    return shutil.which("python3") is not None


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
        ok = _install_go(package, tool.binary)
    elif install_type == "pipx_or_pip":
        ok = _install_pip(package, tool.binary)
    else:
        print(f"[!] Unsupported install type for {tool.name}: {install_type}")
        return False
    _post_install_repair(tool.binary)
    found = _find_binary(tool.binary)
    if ok and found:
        print(f"[+] {tool.name} installed/repaired successfully: {found}")
        return True
    print(f"[!] {tool.name} install finished but binary was not discovered. See reports/output/arsenal/install-repair.log")
    return found is not None


def upgrade_tool(tool: ArsenalTool, yes: bool = False, allow_system: bool = True) -> bool:
    if not yes:
        answer = input(f"Update {tool.name} from curated source? yes/no: ").strip().lower()
        if answer not in {"yes", "y"}:
            return False
    if not is_installed(tool):
        return install_tool(tool, yes=True, allow_system=allow_system)
    install_type = tool.install.get("type")
    package = tool.install.get("package")
    if install_type == "go" and package:
        return _install_go(package, tool.binary)
    if install_type == "pipx_or_pip" and package:
        return _upgrade_pip(package, tool.binary)
    return False


def _go_command() -> str | None:
    found = shutil.which("go")
    if found:
        return found
    local = GO_ROOT / "bin" / "go"
    return str(local) if local.exists() else None


def _install_go(package: str, binary: str | None = None) -> bool:
    go = _go_command()
    if not go and not _bootstrap_user_go():
        print("[!] Go is not installed and user-local Go bootstrap failed.")
        return False
    go = _go_command()
    if not go:
        return False
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    command = [go, "install", package]
    print("[+] " + " ".join(command))
    ok = _run(command, env=_ensure_path_env())
    if binary:
        _post_install_repair(binary)
    return ok


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
    command = ["pipx", "install", "--force", package] if shutil.which("pipx") else ["python3", "-m", "pip", "install", "--user", "--upgrade", package]
    print("[+] " + " ".join(command))
    ok = _run(command, env=_ensure_path_env())
    _post_install_repair(binary)
    return ok


def _upgrade_pip(package: str, binary: str) -> bool:
    command = ["pipx", "install", "--force", package] if shutil.which("pipx") else ["python3", "-m", "pip", "install", "--user", "--upgrade", package]
    print("[+] " + " ".join(command))
    ok = _run(command, env=_ensure_path_env())
    _post_install_repair(binary)
    return ok


def ensure_profile_tools(tools: list[ArsenalTool], auto_install: bool = False, yes: bool = False, allow_system: bool = True) -> dict[str, bool]:
    results = {}
    for tool in tools:
        installed = is_installed(tool)
        if not installed and auto_install:
            installed = install_tool(tool, yes=yes, allow_system=allow_system)
        results[tool.name] = installed
    return results

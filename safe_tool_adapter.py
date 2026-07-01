#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path

TOOLS_HOME = Path.home() / ".vulnscope" / "tools"
LOCAL_BIN = TOOLS_HOME / "bin"
NPM_BIN = TOOLS_HOME / "npm" / "bin"
GO_BIN = Path.home() / "go" / "bin"
USER_LOCAL_BIN = Path.home() / ".local" / "bin"
VENV_BIN = Path(sys.executable).resolve().parent
REPO_FALLBACK_BIN = Path.cwd() / ".vulnscope" / "tools" / "bin"
ADAPTER_MANIFEST = Path("reports/output/top100-tools/safe-adapters.json")

ALIASES: dict[str, list[str]] = {
    "python": ["python", "python3"],
    "pip": ["pip", "pip3"],
    "node": ["node", "nodejs"],
    "testssl.sh": ["testssl.sh", "testssl"],
    "retire-js": ["retire-js", "retire"],
    "npm-audit": ["npm-audit", "npm"],
    "SecretFinder": ["SecretFinder", "SecretFinder.py", "secretfinder"],
    "LinkFinder": ["LinkFinder", "LinkFinder.py", "linkfinder", "linkfinder.py"],
    "cyclonedx-py": ["cyclonedx-py", "cyclonedx-bom"],
    "getJS": ["getJS", "getjs"],
    "zap-baseline.py": ["zap-baseline.py", "zap-baseline"],
    "chromedriver": ["chromedriver", "chromium-driver"],
    "firefox": ["firefox", "firefox-esr"],
    "google-chrome": ["google-chrome", "google-chrome-stable"],
    "osv-scanner": ["osv-scanner", "osv"],
}


def _clean_name(value: str) -> str:
    value = Path(str(value)).name.strip()
    return value or "vulnscope-tool"


def names_for(name: str, binary: str | None = None) -> list[str]:
    values = [_clean_name(binary or name), _clean_name(name)]
    for key in [name, binary or "", str(name).lower(), str(binary or "").lower()]:
        values.extend(_clean_name(x) for x in ALIASES.get(key, []))
    return list(dict.fromkeys([x for x in values if x])) or ["vulnscope-tool"]


def chmod_exec(path: Path) -> None:
    try:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass


def _is_writable_dir(path: Path) -> bool:
    try:
        if path.exists() and not path.is_dir():
            backup = path.with_name(path.name + ".backup")
            path.rename(backup)
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".vulnscope_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def adapter_bin_dirs() -> list[Path]:
    return [LOCAL_BIN, USER_LOCAL_BIN, VENV_BIN, REPO_FALLBACK_BIN]


def adapter_bin_dir() -> Path:
    for candidate in adapter_bin_dirs():
        if _is_writable_dir(candidate):
            return candidate
    REPO_FALLBACK_BIN.mkdir(parents=True, exist_ok=True)
    return REPO_FALLBACK_BIN


def ensure_dirs() -> None:
    for candidate in [LOCAL_BIN, NPM_BIN, GO_BIN, USER_LOCAL_BIN, ADAPTER_MANIFEST.parent, REPO_FALLBACK_BIN]:
        try:
            if candidate.exists() and not candidate.is_dir():
                candidate.rename(candidate.with_name(candidate.name + ".backup"))
            candidate.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
    adapter_bin_dir()


def is_adapter(path: str | None) -> bool:
    if not path:
        return False
    try:
        return "VULNSCOPE_SAFE_TOOL_ADAPTER" in Path(path).read_text(encoding="utf-8", errors="ignore")[:1000]
    except Exception:
        return False


def read_manifest() -> dict:
    try:
        return json.loads(ADAPTER_MANIFEST.read_text(encoding="utf-8"))
    except Exception:
        return {"adapters": {}}


def write_manifest(data: dict) -> None:
    ADAPTER_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    tmp = ADAPTER_MANIFEST.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(ADAPTER_MANIFEST)


def _adapter_source(name: str, binary: str, reason: str) -> str:
    return f'''#!/usr/bin/env python3
# VULNSCOPE_SAFE_TOOL_ADAPTER
from __future__ import annotations
import json, pathlib, sys, time
TOOL_NAME = {name!r}
BINARY_NAME = {binary!r}
REASON = {reason!r}

def find_output_path(args):
    flags = ['-o', '--output', '--output-file', '--json', '--save', '--write']
    for i, arg in enumerate(args):
        if arg in flags and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith('--output='):
            return arg.split('=', 1)[1]
        if arg.startswith('--output-file='):
            return arg.split('=', 1)[1]
    return None

def main():
    args = sys.argv[1:]
    if any(a in args for a in ['--version', '-version', 'version', '-v']):
        print(f"{{TOOL_NAME}} VulnScope safe adapter 1.0")
        return 0
    payload = {{
        "tool": TOOL_NAME,
        "binary": BINARY_NAME,
        "adapter": True,
        "status": "safe_adapter_executed",
        "reason": REASON,
        "args": args,
        "timestamp": time.time(),
        "note": "Safe no-op compatibility adapter. Native upstream tool was unavailable or failed to install."
    }}
    out = find_output_path(args)
    if out:
        try:
            p = pathlib.Path(out)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(payload, indent=2), encoding='utf-8')
        except Exception as exc:
            payload['output_error'] = str(exc)
    print(json.dumps(payload))
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
'''


def create_safe_adapter(name: str, binary: str | None = None, reason: str = "native installer failed") -> Path:
    ensure_dirs()
    clean_binary = names_for(name, binary)[0]
    errors: list[str] = []
    for bin_dir in adapter_bin_dirs():
        try:
            if bin_dir.exists() and not bin_dir.is_dir():
                bin_dir.rename(bin_dir.with_name(bin_dir.name + ".backup"))
            bin_dir.mkdir(parents=True, exist_ok=True)
            path = bin_dir / clean_binary
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(path.name + ".tmp")
            tmp.write_text(_adapter_source(name, clean_binary, reason), encoding="utf-8")
            chmod_exec(tmp)
            tmp.replace(path)
            chmod_exec(path)
            manifest = read_manifest()
            manifest.setdefault("adapters", {})[name] = {
                "binary": clean_binary,
                "path": str(path),
                "reason": reason,
                "created_at": time.time(),
            }
            write_manifest(manifest)
            return path
        except Exception as exc:
            errors.append(f"{bin_dir}: {exc}")
            continue
    raise RuntimeError(f"unable to create VulnScope safe adapter for {name}: {' | '.join(errors)}")


def adapter_path(name: str, binary: str | None = None) -> Path:
    return adapter_bin_dir() / names_for(name, binary)[0]

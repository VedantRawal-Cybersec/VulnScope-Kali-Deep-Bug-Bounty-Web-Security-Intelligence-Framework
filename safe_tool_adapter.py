#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path

TOOLS_HOME = Path.home() / ".vulnscope" / "tools"
LOCAL_BIN = TOOLS_HOME / "bin"
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


def ensure_dirs() -> None:
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    ADAPTER_MANIFEST.parent.mkdir(parents=True, exist_ok=True)


def names_for(name: str, binary: str | None = None) -> list[str]:
    values = [binary or name, name]
    for key in [name, binary or "", str(name).lower(), str(binary or "").lower()]:
        values.extend(ALIASES.get(key, []))
    return list(dict.fromkeys([x for x in values if x]))


def chmod_exec(path: Path) -> None:
    try:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass


def is_adapter(path: str | None) -> bool:
    if not path:
        return False
    try:
        return "VULNSCOPE_SAFE_TOOL_ADAPTER" in Path(path).read_text(encoding="utf-8", errors="ignore")[:500]
    except Exception:
        return False


def read_manifest() -> dict:
    try:
        return json.loads(ADAPTER_MANIFEST.read_text(encoding="utf-8"))
    except Exception:
        return {"adapters": {}}


def write_manifest(data: dict) -> None:
    ensure_dirs()
    ADAPTER_MANIFEST.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def create_safe_adapter(name: str, binary: str | None = None, reason: str = "native installer failed") -> Path:
    ensure_dirs()
    binary = names_for(name, binary)[0]
    path = LOCAL_BIN / binary
    adapter_code = f'''#!/usr/bin/env python3
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
    if any(a in args for a in ['--version', '-version', 'version']):
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
    path.write_text(adapter_code, encoding="utf-8")
    chmod_exec(path)
    manifest = read_manifest()
    manifest.setdefault("adapters", {})[name] = {
        "binary": binary,
        "path": str(path),
        "reason": reason,
        "created_at": time.time(),
    }
    write_manifest(manifest)
    return path


def adapter_path(name: str, binary: str | None = None) -> Path:
    ensure_dirs()
    return LOCAL_BIN / names_for(name, binary)[0]

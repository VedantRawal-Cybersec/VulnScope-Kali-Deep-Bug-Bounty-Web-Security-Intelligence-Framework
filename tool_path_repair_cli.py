#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
from pathlib import Path

OUT = Path("reports/output/tool-path-repair")
LOCAL_BIN = Path.home() / ".vulnscope" / "tools" / "bin"
SEARCH_ROOTS = [
    Path.home() / "go" / "bin",
    Path.home() / ".vulnscope" / "tools" / "bin",
    Path.home() / ".vulnscope" / "tools" / "go" / "bin",
    Path.home() / ".local" / "bin",
    Path.home() / ".local" / "share" / "pipx" / "venvs",
]
ALIASES = {
    "linkfinder": ["linkfinder", "LinkFinder", "linkfinder.py", "LinkFinder.py"],
    "xnLinkFinder": ["xnLinkFinder", "xnlinkfinder", "xnlinkfinder.py"],
    "graphw00f": ["graphw00f", "Graphw00f"],
    "Gxss": ["Gxss", "gxss"],
}
DEFAULT_TOOLS = [
    "gitleaks", "graphw00f", "linkfinder", "mantra", "trufflehog", "xnLinkFinder", "Gxss",
    "subfinder", "assetfinder", "amass", "httpx", "katana", "gau", "waybackurls", "arjun", "nuclei",
]


def names_for(binary: str) -> list[str]:
    out = [binary]
    out += ALIASES.get(binary, [])
    out += ALIASES.get(binary.lower(), [])
    return list(dict.fromkeys(out))


def chmod_exec(path: Path) -> None:
    try:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass


def find_binary(binary: str) -> str | None:
    for name in names_for(binary):
        found = shutil.which(name)
        if found:
            return found
    wanted = {n.lower() for n in names_for(binary)}
    for root in SEARCH_ROOTS:
        if not root.exists():
            continue
        for item in root.rglob("*"):
            if item.is_file() and item.name.lower() in wanted:
                return str(item)
    return None


def link_binary(binary: str, found: str) -> str | None:
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    src = Path(found)
    chmod_exec(src)
    dst = LOCAL_BIN / binary
    if dst.exists():
        chmod_exec(dst)
        return str(dst)
    try:
        dst.symlink_to(src)
    except Exception:
        try:
            shutil.copy2(src, dst)
        except Exception:
            return None
    chmod_exec(dst)
    return str(dst)


def update_shell_path() -> dict:
    export_line = 'export PATH="$HOME/.vulnscope/tools/go/bin:$HOME/go/bin:$HOME/.vulnscope/tools/bin:$HOME/.local/bin:$PATH"'
    changed = []
    for rc in [Path.home() / ".zshrc", Path.home() / ".bashrc"]:
        text = rc.read_text(encoding="utf-8", errors="ignore") if rc.exists() else ""
        if export_line not in text:
            with rc.open("a", encoding="utf-8") as h:
                h.write("\n# VulnScope tool paths\n" + export_line + "\n")
            changed.append(str(rc))
    return {"export_line": export_line, "changed": changed}


def repair(tools: list[str]) -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    for binary in tools:
        found = find_binary(binary)
        linked = link_binary(binary, found) if found else None
        rows.append({"binary": binary, "found": found, "linked": linked, "ok": bool(found or shutil.which(binary))})
    payload = {"path_env_now": os.environ.get("PATH", ""), "shell_path": update_shell_path(), "tools": rows, "summary": {"requested": len(rows), "repaired_or_found": len([r for r in rows if r["ok"]]), "missing": len([r for r in rows if not r["ok"]])}}
    (OUT / "tool-path-repair.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = ["# VulnScope Tool Path Repair", "", f"Requested: `{payload['summary']['requested']}`", f"Found/repaired: `{payload['summary']['repaired_or_found']}`", f"Missing: `{payload['summary']['missing']}`", "", "## Tools"]
    for row in rows:
        lines.append(f"- `{row['binary']}` found=`{row['found']}` linked=`{row['linked']}` ok=`{row['ok']}`")
    lines += ["", "## PATH line", "```bash", payload["shell_path"]["export_line"], "```"]
    (OUT / "tool-path-repair.md").write_text("\n".join(lines), encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Repair VulnScope user-local tool PATH and symlinks")
    parser.add_argument("--tools", nargs="*", default=DEFAULT_TOOLS)
    args = parser.parse_args()
    result = repair(args.tools)
    print(json.dumps({"summary": result["summary"], "report": "reports/output/tool-path-repair/tool-path-repair.md"}, indent=2))
    return 0 if result["summary"]["missing"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

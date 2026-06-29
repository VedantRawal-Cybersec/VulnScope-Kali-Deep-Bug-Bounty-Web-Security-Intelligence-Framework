#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

OUT = Path("reports/output/tool-doctor")
LOCAL_BIN = Path.home() / ".vulnscope" / "tools" / "bin"
GO_ROOT = Path.home() / ".vulnscope" / "tools" / "go"
GO_BIN = Path.home() / "go" / "bin"
USER_LOCAL_BIN = Path.home() / ".local" / "bin"
PIPX_HOME = Path.home() / ".local" / "share" / "pipx" / "venvs"

TOOLS: dict[str, dict[str, Any]] = {
    "gitleaks": {
        "binary": "gitleaks",
        "category": "secret-pattern review",
        "install": [["go", "install", "github.com/gitleaks/gitleaks/v8@latest"]],
        "aliases": ["gitleaks"],
        "optional": True,
    },
    "trufflehog": {
        "binary": "trufflehog",
        "category": "secret-pattern review",
        "install": [["go", "install", "github.com/trufflesecurity/trufflehog/v3@latest"]],
        "aliases": ["trufflehog"],
        "optional": True,
    },
    "linkfinder": {
        "binary": "linkfinder",
        "category": "local JS endpoint extraction",
        "install": [[sys.executable, "-m", "pip", "install", "--user", "--upgrade", "git+https://github.com/GerbenJavado/LinkFinder.git"]],
        "aliases": ["linkfinder", "LinkFinder", "linkfinder.py", "LinkFinder.py"],
        "optional": True,
        "wrapper": "python3 -m linkfinder \"$@\"",
    },
    "graphw00f": {
        "binary": "graphw00f",
        "category": "GraphQL review helper",
        "install": [[sys.executable, "-m", "pip", "install", "--user", "--upgrade", "graphw00f"]],
        "aliases": ["graphw00f", "Graphw00f", "graphw00f.py"],
        "optional": True,
        "wrapper": "python3 -m graphw00f \"$@\"",
    },
    "mantra": {
        "binary": "mantra",
        "category": "local JS/secret pattern review",
        "install": [["go", "install", "github.com/MrEmpy/mantra@latest"], ["go", "install", "github.com/MrEmpy/Mantra@latest"]],
        "aliases": ["mantra", "Mantra"],
        "optional": True,
    },
    "xnLinkFinder": {
        "binary": "xnLinkFinder",
        "category": "local JS endpoint extraction",
        "install": [[sys.executable, "-m", "pip", "install", "--user", "--upgrade", "xnLinkFinder"]],
        "aliases": ["xnLinkFinder", "xnlinkfinder", "xnlinkfinder.py"],
        "optional": True,
        "wrapper": "python3 -m xnLinkFinder \"$@\"",
    },
}


def env() -> dict[str, str]:
    e = dict(os.environ)
    extra = [str(LOCAL_BIN), str(GO_ROOT / "bin"), str(GO_BIN), str(USER_LOCAL_BIN)]
    e["PATH"] = os.pathsep.join(extra + [e.get("PATH", "")])
    e["GOBIN"] = str(LOCAL_BIN)
    e["GOPATH"] = str(Path.home() / "go")
    return e


def go_command() -> str | None:
    return shutil.which("go") or (str(GO_ROOT / "bin" / "go") if (GO_ROOT / "bin" / "go").exists() else None)


def chmod(path: Path) -> None:
    try:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass


def candidates(tool: dict[str, Any]) -> list[Path]:
    names = list(dict.fromkeys([tool["binary"], *tool.get("aliases", [])]))
    roots = [LOCAL_BIN, GO_BIN, USER_LOCAL_BIN, GO_ROOT / "bin", PIPX_HOME, Path.home() / ".local" / "share", Path.home() / "go"]
    out: list[Path] = []
    for name in names:
        found = shutil.which(name, path=env().get("PATH"))
        if found:
            out.append(Path(found))
    wanted = {n.lower() for n in names}
    for root in roots:
        if not root.exists():
            continue
        for name in names:
            p = root / name
            if p.exists() and p.is_file():
                out.append(p)
        try:
            for p in root.rglob("*"):
                if p.is_file() and p.name.lower() in wanted:
                    out.append(p)
        except Exception:
            pass
    return list(dict.fromkeys(out))


def link_found(tool: dict[str, Any]) -> str | None:
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    for p in candidates(tool):
        chmod(p)
        target = LOCAL_BIN / tool["binary"]
        if not target.exists():
            try:
                target.symlink_to(p)
            except Exception:
                try:
                    shutil.copy2(p, target)
                except Exception:
                    pass
        chmod(target)
        return str(target if target.exists() else p)
    return None


def write_wrapper(tool: dict[str, Any]) -> str | None:
    wrapper = tool.get("wrapper")
    if not wrapper:
        return None
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    target = LOCAL_BIN / tool["binary"]
    if target.exists():
        return str(target)
    target.write_text("#!/usr/bin/env bash\n" + wrapper + "\n", encoding="utf-8")
    chmod(target)
    return str(target)


def run(command: list[str]) -> dict[str, Any]:
    actual = list(command)
    if actual and actual[0] == "go":
        go = go_command()
        if not go:
            return {"command": command, "ok": False, "error": "go is not installed"}
        actual[0] = go
    started = time.time()
    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / "tool-doctor-install.log").open("a", encoding="utf-8", errors="ignore") as log:
        log.write("\n$ " + " ".join(actual) + "\n")
        try:
            p = subprocess.run(actual, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=1200, env=env())
            log.write(p.stdout[-6000:])
            return {"command": actual, "ok": p.returncode == 0, "exit_code": p.returncode, "seconds": round(time.time() - started, 2), "tail": p.stdout[-1000:]}
        except Exception as exc:
            log.write(str(exc))
            return {"command": actual, "ok": False, "error": str(exc), "seconds": round(time.time() - started, 2)}


def doctor_one(name: str, install: bool) -> dict[str, Any]:
    tool = TOOLS[name]
    before = link_found(tool)
    installs = []
    if not before and install:
        for command in tool.get("install", []):
            res = run(command)
            installs.append(res)
            after_attempt = link_found(tool)
            if after_attempt:
                break
    after = link_found(tool)
    wrapper = None
    if not after:
        wrapper = write_wrapper(tool)
        after = link_found(tool) or wrapper
    return {
        "name": name,
        "category": tool.get("category"),
        "optional": tool.get("optional", True),
        "installed_before": bool(before),
        "installed_after": bool(after),
        "path": after,
        "install_attempts": installs,
        "wrapper_created": bool(wrapper),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Repair high-value optional VulnScope tools with user-local installs and wrappers")
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--tools", nargs="*", default=list(TOOLS))
    args = parser.parse_args()
    if args.install and not args.yes:
        ans = input("Install/repair optional user-local helper tools? type YES: ").strip()
        if ans != "YES":
            print(json.dumps({"started": False, "reason": "confirmation not provided"}, indent=2))
            return 1
    OUT.mkdir(parents=True, exist_ok=True)
    names = [n for n in args.tools if n in TOOLS]
    rows = [doctor_one(n, args.install) for n in names]
    summary = {"requested": len(rows), "installed": len([r for r in rows if r["installed_after"]]), "missing_optional": len([r for r in rows if not r["installed_after"]])}
    payload = {"summary": summary, "tools": rows, "path_hint": f"export PATH='{LOCAL_BIN}:{GO_ROOT / 'bin'}:{GO_BIN}:{USER_LOCAL_BIN}:$PATH'"}
    (OUT / "tool-doctor.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = ["# VulnScope Tool Doctor", "", f"Requested: `{summary['requested']}`", f"Installed/found: `{summary['installed']}`", f"Missing optional: `{summary['missing_optional']}`", "", "## Tools"]
    for r in rows:
        lines.append(f"- `{r['name']}` installed=`{r['installed_after']}` path=`{r.get('path')}` wrapper=`{r.get('wrapper_created')}`")
    lines += ["", "## PATH", "```bash", payload["path_hint"], "```"]
    (OUT / "tool-doctor.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"summary": summary, "report": "reports/output/tool-doctor/tool-doctor.md"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

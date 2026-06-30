#!/usr/bin/env python3
from __future__ import annotations

import os
import queue
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

OUT = Path("reports/output/tool-doctor")
LOCAL_BIN = Path.home() / ".vulnscope" / "tools" / "bin"
GO_BIN = Path.home() / "go" / "bin"
USER_LOCAL_BIN = Path.home() / ".local" / "bin"


@dataclass(frozen=True)
class HelperTool:
    name: str
    binary: str
    install_cmd: list[str] | None
    timeout: int = 240
    optional: bool = True


HELPER_TOOLS: list[HelperTool] = [
    HelperTool("Git", "git", ["bash", "-lc", "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y git"], 180),
    HelperTool("Curl", "curl", ["bash", "-lc", "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y curl"], 180),
    HelperTool("Wget", "wget", ["bash", "-lc", "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y wget"], 180),
    HelperTool("JQ", "jq", ["bash", "-lc", "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y jq"], 180),
    HelperTool("Python Requests", "python-requests", ["python3", "-m", "pip", "install", "--user", "--upgrade", "requests"], 180),
    HelperTool("BeautifulSoup", "python-bs4", ["python3", "-m", "pip", "install", "--user", "--upgrade", "beautifulsoup4"], 180),
    HelperTool("PyYAML", "python-yaml", ["python3", "-m", "pip", "install", "--user", "--upgrade", "pyyaml"], 180),
    HelperTool("TLDExtract", "python-tldextract", ["python3", "-m", "pip", "install", "--user", "--upgrade", "tldextract"], 180),
    HelperTool("HTTPX Toolkit", "httpx", ["bash", "-lc", "command -v go >/dev/null 2>&1 && GOBIN=$HOME/.vulnscope/tools/bin go install github.com/projectdiscovery/httpx/cmd/httpx@latest || true"], 300),
    HelperTool("Katana", "katana", ["bash", "-lc", "command -v go >/dev/null 2>&1 && GOBIN=$HOME/.vulnscope/tools/bin go install github.com/projectdiscovery/katana/cmd/katana@latest || true"], 300),
    HelperTool("Nuclei", "nuclei", ["bash", "-lc", "command -v go >/dev/null 2>&1 && GOBIN=$HOME/.vulnscope/tools/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true"], 300),
    HelperTool("Gau", "gau", ["bash", "-lc", "command -v go >/dev/null 2>&1 && GOBIN=$HOME/.vulnscope/tools/bin go install github.com/lc/gau/v2/cmd/gau@latest || true"], 300),
    HelperTool("Waybackurls", "waybackurls", ["bash", "-lc", "command -v go >/dev/null 2>&1 && GOBIN=$HOME/.vulnscope/tools/bin go install github.com/tomnomnom/waybackurls@latest || true"], 300),
]


def _env() -> dict[str, str]:
    env = dict(os.environ)
    extra = [str(LOCAL_BIN), str(GO_BIN), str(USER_LOCAL_BIN)]
    env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "")])
    env.setdefault("DEBIAN_FRONTEND", "noninteractive")
    env.setdefault("PYTHONUNBUFFERED", "1")
    return env


def _tool_exists(binary: str) -> bool:
    if binary.startswith("python-"):
        module = binary.replace("python-", "", 1)
        module_map = {"bs4": "bs4", "yaml": "yaml", "requests": "requests", "tldextract": "tldextract"}
        module = module_map.get(module, module)
        return subprocess.call(
            ["python3", "-c", f"import {module}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ) == 0
    return shutil.which(binary, path=_env().get("PATH")) is not None


def _clean(line: str, limit: int = 110) -> str:
    text = " ".join(line.strip().split())
    if not text:
        return ""
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _reader(stream: Any, output_queue: "queue.Queue[str]") -> None:
    try:
        for line in iter(stream.readline, ""):
            output_queue.put(line)
    finally:
        try:
            stream.close()
        except Exception:
            pass


def _run_live(tool: HelperTool, command: list[str], timeout: int, log_path: Path) -> dict[str, Any]:
    started = time.time()
    output_queue: "queue.Queue[str]" = queue.Queue()

    print(f"\n[download] {tool.name}", flush=True)
    print(f"[command] {' '.join(command)}", flush=True)
    print(f"[timeout] {timeout}s", flush=True)
    print(f"[log] {log_path}", flush=True)

    with log_path.open("a", encoding="utf-8", errors="ignore") as log:
        log.write("\n$ " + " ".join(command) + "\n")
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=_env(),
            )
        except Exception as exc:
            log.write(str(exc) + "\n")
            print(f"[failed] could not start {tool.name}: {exc}", flush=True)
            return {"tool": tool.name, "ok": False, "error": str(exc), "seconds": 0}

        if process.stdout is not None:
            threading.Thread(target=_reader, args=(process.stdout, output_queue), daemon=True).start()

        last_heartbeat = 0.0
        tail: list[str] = []
        timed_out = False

        while process.poll() is None:
            while True:
                try:
                    line = output_queue.get_nowait()
                except queue.Empty:
                    break
                log.write(line)
                log.flush()
                tail.append(line)
                tail = tail[-30:]
                cleaned = _clean(line)
                if cleaned:
                    print(f"[{int(time.time() - started):>4}s] {tool.name}: {cleaned}", flush=True)

            elapsed = time.time() - started
            if elapsed - last_heartbeat >= 5:
                print(f"[{int(elapsed):>4}s] {tool.name}: still running...", flush=True)
                last_heartbeat = elapsed

            if elapsed > timeout:
                timed_out = True
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                break
            time.sleep(0.2)

        while True:
            try:
                line = output_queue.get_nowait()
            except queue.Empty:
                break
            log.write(line)
            tail.append(line)
            tail = tail[-30:]
            cleaned = _clean(line)
            if cleaned:
                print(f"[{int(time.time() - started):>4}s] {tool.name}: {cleaned}", flush=True)

    seconds = round(time.time() - started, 2)

    if timed_out:
        print(f"[timeout] {tool.name} exceeded {timeout}s. Skipped; scan will continue.", flush=True)
        return {"tool": tool.name, "ok": False, "timeout": True, "seconds": seconds, "tail": "".join(tail)[-1000:]}

    ok = process.returncode == 0 or _tool_exists(tool.binary)
    status = "done" if ok else "failed"
    print(f"[{status}] {tool.name} finished in {seconds}s", flush=True)
    return {"tool": tool.name, "ok": ok, "exit_code": process.returncode, "seconds": seconds, "tail": "".join(tail)[-1000:]}


def run_preflight_repair(repair: bool = True) -> int:
    """Visible optional helper-tool preflight for the direct Kali interface."""
    if os.getenv("VULNSCOPE_SKIP_REPAIR", "0") == "1":
        print("[skip] VULNSCOPE_SKIP_REPAIR=1 detected. Optional helper repair skipped.", flush=True)
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    log_path = OUT / "tool-doctor-install.log"
    max_timeout = int(os.getenv("VULNSCOPE_TOOL_TIMEOUT", "240"))

    print("\n" + "═" * 72, flush=True)
    print(" VULNSCOPE PREFLIGHT DEPENDENCY MANAGER", flush=True)
    print(" Checking optional helper tools with visible progress.", flush=True)
    print(" Missing optional tools will not block the scan.", flush=True)
    print(" Logs: reports/output/tool-doctor/tool-doctor-install.log", flush=True)
    print("═" * 72, flush=True)

    results: list[dict[str, Any]] = []
    for index, tool in enumerate(HELPER_TOOLS, 1):
        print(f"\n[{index}/{len(HELPER_TOOLS)}] Checking {tool.name} ({tool.binary})", flush=True)
        installed_before = _tool_exists(tool.binary)
        if installed_before:
            print(f"[ok] {tool.name} already installed.", flush=True)
            results.append({"tool": tool.name, "binary": tool.binary, "status": "installed", "installed_before": True})
            continue

        if not repair or not tool.install_cmd:
            print(f"[missing] {tool.name} missing. No safe auto-install command configured.", flush=True)
            results.append({"tool": tool.name, "binary": tool.binary, "status": "missing", "installed_before": False})
            continue

        timeout = min(max_timeout, tool.timeout)
        result = _run_live(tool, tool.install_cmd, timeout, log_path)
        installed_after = _tool_exists(tool.binary)
        result.update({"binary": tool.binary, "installed_before": False, "installed_after": installed_after})
        results.append(result)

    installed = len([r for r in results if r.get("status") == "installed" or r.get("installed_after") or r.get("ok")])
    missing = len(results) - installed
    payload = {
        "summary": {
            "checked": len(results),
            "installed_or_available": installed,
            "missing_optional": missing,
        },
        "tools": results,
        "path_hint": f"export PATH='{LOCAL_BIN}:{GO_BIN}:{USER_LOCAL_BIN}:$PATH'",
    }
    (OUT / "tool-doctor.json").write_text(__import__("json").dumps(payload, indent=2), encoding="utf-8")

    lines = [
        "# VulnScope Visible Dependency Preflight",
        "",
        f"Checked: `{len(results)}`",
        f"Installed or available: `{installed}`",
        f"Missing optional: `{missing}`",
        "",
        "## Tool Status",
    ]
    for r in results:
        lines.append(f"- `{r['tool']}` binary=`{r.get('binary')}` ok=`{bool(r.get('ok') or r.get('status') == 'installed' or r.get('installed_after'))}` seconds=`{r.get('seconds', 0)}`")
    lines += ["", "## PATH", "```bash", payload["path_hint"], "```", "", "## Log", "`reports/output/tool-doctor/tool-doctor-install.log`"]
    (OUT / "tool-doctor.md").write_text("\n".join(lines), encoding="utf-8")

    print("\n" + "═" * 72, flush=True)
    print(" PREFLIGHT SUMMARY", flush=True)
    print(f" Checked: {len(results)}", flush=True)
    print(f" Installed or available: {installed}", flush=True)
    print(f" Missing optional: {missing}", flush=True)
    print(" Report: reports/output/tool-doctor/tool-doctor.md", flush=True)
    print(" Log: reports/output/tool-doctor/tool-doctor-install.log", flush=True)
    print("═" * 72, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_preflight_repair(repair=True))

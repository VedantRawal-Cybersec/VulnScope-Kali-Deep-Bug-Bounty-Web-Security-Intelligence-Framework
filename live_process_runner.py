#!/usr/bin/env python3
from __future__ import annotations

import os
import queue
import shlex
import subprocess
import threading
import time
from pathlib import Path
from typing import Any


def _reader(stream: Any, q: "queue.Queue[str]") -> None:
    try:
        for line in iter(stream.readline, ""):
            q.put(line)
    finally:
        try:
            stream.close()
        except Exception:
            pass


def _bar(percent: float, width: int = 22) -> str:
    percent = max(0.0, min(100.0, percent))
    filled = int((percent / 100.0) * width)
    return "█" * filled + "░" * (width - filled)


def _eta_text(elapsed: int, estimated_seconds: int | None) -> str:
    if not estimated_seconds or estimated_seconds <= 0:
        return "ETA: calculating"
    remaining = max(0, estimated_seconds - elapsed)
    return f"ETA: ~{remaining}s"


def run_visible_command(
    label: str,
    command: list[str] | str,
    *,
    env: dict[str, str] | None = None,
    timeout: int = 1800,
    estimated_seconds: int | None = None,
    log_path: str | Path | None = None,
    heartbeat: int = 5,
) -> int:
    """Run a subprocess with a visible loading screen, heartbeat, live output, log, and timeout."""
    if isinstance(command, list):
        display_command = " ".join(shlex.quote(str(part)) for part in command)
        popen_command = command
        shell = False
    else:
        display_command = command
        popen_command = ["bash", "-lc", command]
        shell = False

    run_env = dict(os.environ)
    if env:
        run_env.update(env)
    run_env["PYTHONUNBUFFERED"] = "1"

    log = Path(log_path or f"reports/output/runtime-logs/{label.lower().replace(' ', '-')}.log")
    log.parent.mkdir(parents=True, exist_ok=True)

    print("\n" + "═" * 78, flush=True)
    print(f"▶ {label}", flush=True)
    print(f"Command : {display_command}", flush=True)
    print(f"Log     : {log}", flush=True)
    print(f"Timeout : {timeout}s", flush=True)
    print("═" * 78, flush=True)

    started = time.time()
    last_heartbeat = 0.0
    output_lines = 0
    last_output_at = started
    q: "queue.Queue[str]" = queue.Queue()

    try:
        proc = subprocess.Popen(
            popen_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            env=run_env,
            shell=shell,
        )
    except Exception as exc:
        print(f"[failed-start] {label}: {exc}", flush=True)
        return 1

    if proc.stdout is not None:
        threading.Thread(target=_reader, args=(proc.stdout, q), daemon=True).start()

    with log.open("w", encoding="utf-8", errors="ignore") as handle:
        handle.write("$ " + display_command + "\n")
        handle.write(f"started_at={time.strftime('%Y-%m-%d %H:%M:%S')} pid={proc.pid}\n\n")
        while proc.poll() is None:
            while True:
                try:
                    line = q.get_nowait()
                except queue.Empty:
                    break
                output_lines += 1
                last_output_at = time.time()
                handle.write(line)
                handle.flush()
                clean = " ".join(line.strip().split())
                if clean:
                    print(f"[live] {label}: {clean[:220]}", flush=True)

            elapsed = int(time.time() - started)
            no_output = int(time.time() - last_output_at)
            if elapsed - last_heartbeat >= max(2, heartbeat):
                percent = min(99.0, (elapsed / max(1, estimated_seconds or timeout)) * 100.0)
                print(
                    f"[working] {label} elapsed={elapsed}s {_eta_text(elapsed, estimated_seconds)} "
                    f"pid={proc.pid} output_lines={output_lines} no_output={no_output}s "
                    f"{_bar(percent)} {percent:05.1f}% log={log}",
                    flush=True,
                )
                last_heartbeat = elapsed

            if elapsed > timeout:
                handle.write(f"\nTIMEOUT after {elapsed}s\n")
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                print(f"[timeout] {label} exceeded {timeout}s. Continuing safely.", flush=True)
                return 124
            time.sleep(0.15)

        while True:
            try:
                line = q.get_nowait()
            except queue.Empty:
                break
            output_lines += 1
            handle.write(line)
            clean = " ".join(line.strip().split())
            if clean:
                print(f"[live] {label}: {clean[:220]}", flush=True)

        code = proc.returncode if proc.returncode is not None else 1
        handle.write(f"\nfinished_at={time.strftime('%Y-%m-%d %H:%M:%S')} exit_code={code}\n")

    total = round(time.time() - started, 2)
    status = "completed" if code == 0 else "review"
    print(f"[{status}] {label} exit_code={code} seconds={total} log={log}", flush=True)
    return int(code)

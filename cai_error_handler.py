#!/usr/bin/env python3
from __future__ import annotations

import json
import time
import traceback
from pathlib import Path
from typing import Any, Callable

ROOT_OUT = Path("reports/output/cai-superior")
LOG_PATH = ROOT_OUT / "cai_superior.log"


def ensure_root() -> None:
    ROOT_OUT.mkdir(parents=True, exist_ok=True)


def now() -> float:
    return time.time()


def write_log(message: str, *, level: str = "INFO") -> None:
    ensure_root()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with LOG_PATH.open("a", encoding="utf-8", errors="ignore") as fh:
        fh.write(f"{stamp} [{level}] {message}\n")


def handled_error(
    *,
    component: str,
    action: str,
    error: BaseException | str,
    fallback_used: str = "continue_without_optional_signal",
    next_action: str = "continue_safe_pipeline",
    auto_repair_attempted: bool = False,
) -> dict[str, Any]:
    err_text = str(error)
    payload = {
        "status": "handled_error",
        "component": component,
        "action": action,
        "root_cause": err_text[:800],
        "error_type": type(error).__name__ if isinstance(error, BaseException) else "ErrorString",
        "auto_repair_attempted": bool(auto_repair_attempted),
        "fallback_used": fallback_used,
        "next_action": next_action,
        "timestamp": now(),
    }
    if isinstance(error, BaseException):
        payload["traceback"] = traceback.format_exception_only(type(error), error)[-1].strip()
    write_log(f"{component}.{action} handled_error: {payload['root_cause']}", level="WARN")
    return payload


def safe_call(
    component: str,
    action: str,
    func: Callable[[], Any],
    *,
    fallback: Any = None,
    fallback_used: str = "continue_without_optional_signal",
) -> Any:
    try:
        return func()
    except Exception as exc:  # pragma: no cover - deliberate safety net
        return fallback if fallback is not None else handled_error(
            component=component,
            action=action,
            error=exc,
            fallback_used=fallback_used,
        )


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def write_markdown(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("\n".join(lines), encoding="utf-8")
    tmp.replace(path)

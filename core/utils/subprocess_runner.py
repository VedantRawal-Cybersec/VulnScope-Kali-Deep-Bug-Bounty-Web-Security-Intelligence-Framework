#!/usr/bin/env python3
from __future__ import annotations

import logging
import subprocess
from typing import Tuple

logger = logging.getLogger(__name__)


def run_command(cmd: list[str], timeout: int = 120, env: dict | None = None, cwd: str | None = None) -> Tuple[str, str]:
    """Run a command with shell disabled and captured stdout/stderr."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd, stdin=subprocess.DEVNULL, shell=False)
        if proc.returncode != 0:
            logger.warning("Command returned non-zero exit=%s cmd=%s stderr=%s", proc.returncode, cmd, proc.stderr[:1000])
        return proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        logger.error("Command timed out after %ss cmd=%s", timeout, cmd)
        raise
    except Exception as exc:
        logger.error("Command failed cmd=%s error=%s", cmd, exc)
        raise

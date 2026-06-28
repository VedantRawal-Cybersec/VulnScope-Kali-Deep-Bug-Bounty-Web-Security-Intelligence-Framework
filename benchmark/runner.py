from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from benchmark.lab_targets import get_lab, list_labs

OUT_DIR = Path("reports/output/benchmark")


@dataclass
class BenchmarkResult:
    name: str
    target: str
    mode: str
    started_at: float
    ended_at: float
    return_code: int
    command: list[str]
    stdout_tail: str
    stderr_tail: str
    artifacts: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_benchmark(name: str, target: str | None = None, mode: str = "bounty", council: bool = True, dry_run: bool = False) -> BenchmarkResult:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    lab = get_lab(name)
    if lab and not target:
        target = lab["url"]
    if not target or target == "manual":
        raise ValueError("Provide --target for this benchmark target")
    cmd = ["python3", "hunt.py", "--target", target, "--mode", mode, "--agent-core", "--yes"]
    if council:
        cmd.append("--model-council")
    if dry_run:
        cmd.append("--dry-run")
    started = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    ended = time.time()
    result = BenchmarkResult(
        name=name,
        target=target,
        mode=mode,
        started_at=started,
        ended_at=ended,
        return_code=proc.returncode,
        command=cmd,
        stdout_tail=proc.stdout[-4000:],
        stderr_tail=proc.stderr[-4000:],
        artifacts=[
            "reports/output/workflow/vulnscope-assessment-report.md",
            "reports/output/agent_core/agent-core-summary.json",
            "reports/output/agent_core/model-council/council-consensus.md",
        ],
    )
    out = OUT_DIR / f"{name}-benchmark.json"
    out.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return result


def benchmark_index() -> dict[str, Any]:
    return {"available_labs": list_labs(), "output_dir": str(OUT_DIR)}

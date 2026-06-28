from __future__ import annotations

import json
import re
from pathlib import Path

from workflow.assessment_state import AssessmentState

CHECKPOINT_DIR = Path("reports/output/workflow")


def safe_name(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", target).strip("_")[:120] or "target"


def checkpoint_path(target: str) -> Path:
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    return CHECKPOINT_DIR / f"{safe_name(target)}-checkpoint.json"


def save_checkpoint(state: AssessmentState) -> Path:
    path = checkpoint_path(state.target)
    path.write_text(json.dumps(state.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def load_checkpoint(target: str) -> AssessmentState | None:
    path = checkpoint_path(target)
    if not path.exists():
        return None
    return AssessmentState.from_file(path)

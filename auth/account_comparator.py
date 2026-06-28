from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def compare_account_crawls(account_a_path: str, account_b_path: str) -> dict[str, Any]:
    a = _load(account_a_path)
    b = _load(account_b_path)
    a_pages = a.get("pages", [])
    b_pages = b.get("pages", [])
    b_text = "\n".join(str(page.get("text_sample", "")) for page in b_pages)

    markers = _extract_candidate_markers(a_pages)
    visible_in_b = []
    for marker in markers:
        if marker and marker in b_text:
            visible_in_b.append(marker)

    result = {
        "rule": "Two-account comparison is a validation assistant, not automatic proof by itself.",
        "account_a_pages": len(a_pages),
        "account_b_pages": len(b_pages),
        "candidate_markers_from_a": markers[:200],
        "markers_visible_in_b": visible_in_b[:100],
        "status": "NEEDS_MANUAL_VALIDATION" if visible_in_b else "NO_CROSS_ACCOUNT_MARKER_OBSERVED",
        "required_proof": [
            "Confirm Account A marker is private and not generic content",
            "Confirm Account B should not access that marker",
            "Capture request/response evidence for both owned accounts",
            "Confirm no destructive or privacy-invasive action was performed",
        ],
    }
    out = Path("reports/output/auth")
    out.mkdir(parents=True, exist_ok=True)
    (out / "account-comparison.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "account-comparison.md").write_text(_markdown(result), encoding="utf-8")
    return result


def _load(path: str) -> dict[str, Any]:
    file_path = Path(path)
    if not file_path.exists():
        return {}
    try:
        return json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}


def _extract_candidate_markers(pages: list[dict[str, Any]]) -> list[str]:
    text = "\n".join(str(page.get("text_sample", "")) for page in pages)
    candidates = set()
    patterns = [
        r"\b[A-Z0-9]{8,}\b",
        r"\b(?:order|user|account|invoice|ticket|booking)[-_:# ]?[A-Za-z0-9]{3,}\b",
        r"\b[\w.+-]+@[\w.-]+\.\w+\b",
    ]
    for pattern in patterns:
        for match in re.findall(pattern, text, flags=re.IGNORECASE):
            value = str(match).strip()
            if 5 <= len(value) <= 120:
                candidates.add(value)
    return sorted(candidates)


def _markdown(result: dict[str, Any]) -> str:
    lines = ["# Authenticated Two-Account Comparison", "", f"Status: **{result.get('status')}**", "", "## Candidate Account A Markers", ""]
    for marker in result.get("candidate_markers_from_a", [])[:50]:
        lines.append(f"- `{marker}`")
    lines += ["", "## Markers Visible In Account B", ""]
    if not result.get("markers_visible_in_b"):
        lines.append("No Account A markers were observed in Account B crawl samples.")
    for marker in result.get("markers_visible_in_b", [])[:50]:
        lines.append(f"- `{marker}`")
    lines += ["", "## Required Proof", ""]
    for item in result.get("required_proof", []):
        lines.append(f"- {item}")
    return "\n".join(lines)

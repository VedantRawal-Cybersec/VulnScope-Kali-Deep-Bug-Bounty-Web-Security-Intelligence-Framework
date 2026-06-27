from __future__ import annotations

from collections import defaultdict
from typing import Any

from core.evidence_store import EvidenceStore, Finding


CONFIDENCE_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Strong": 4}


def correlate_findings(store: EvidenceStore) -> None:
    """Deduplicate and enrich findings without claiming false confirmation.

    The correlation engine merges repeated observations by category, title,
    endpoint, and parameter. It also records endpoint-level signal density so
    reports can show which areas deserve manual review first.
    """
    unique: dict[tuple[str, str, str, str | None], Finding] = {}

    for finding in store.findings:
        key = (finding.category, finding.title, finding.endpoint, finding.parameter)
        if key not in unique:
            unique[key] = finding
            continue

        existing = unique[key]
        existing.how_detected = sorted(set(existing.how_detected + finding.how_detected))
        existing.recommended_validation = sorted(
            set(existing.recommended_validation + finding.recommended_validation)
        )
        existing.remediation = sorted(set(existing.remediation + finding.remediation))
        existing.evidence = _merge_evidence(existing.evidence, finding.evidence)
        existing.confidence = _max_confidence(existing.confidence, finding.confidence)

    store.findings = list(unique.values())

    endpoint_signals: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in store.findings:
        endpoint_signals[finding.endpoint].append(
            {
                "finding_id": finding.finding_id,
                "title": finding.title,
                "category": finding.category,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "status": finding.status,
            }
        )

    prioritized = sorted(
        endpoint_signals.items(),
        key=lambda item: len(item[1]),
        reverse=True,
    )
    store.metadata["correlation"] = {
        "unique_findings": len(store.findings),
        "endpoint_signal_density": [
            {"endpoint": endpoint, "signal_count": len(signals), "signals": signals}
            for endpoint, signals in prioritized[:25]
        ],
    }


def _merge_evidence(first: dict[str, Any], second: dict[str, Any]) -> dict[str, Any]:
    merged = dict(first)
    for key, value in second.items():
        if key not in merged:
            merged[key] = value
        elif merged[key] != value:
            merged[key] = [merged[key], value]
    return merged


def _max_confidence(first: str, second: str) -> str:
    return first if CONFIDENCE_ORDER.get(first, 0) >= CONFIDENCE_ORDER.get(second, 0) else second

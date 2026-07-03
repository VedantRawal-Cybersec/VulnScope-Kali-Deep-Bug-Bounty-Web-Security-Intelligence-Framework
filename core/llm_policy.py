#!/usr/bin/env python3
from __future__ import annotations

import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class LLMPolicy:
    """Central policy for when VulnScope is allowed to use an LLM.

    The scanner stays deterministic for crawling, extraction, and simple safe tests.
    Ollama is used for diagnostics, public reasoning summaries, ambiguous evidence,
    strategy after low-yield scans, and report narration.
    """

    enabled: bool = True
    planner_enabled: bool = True
    deep_reasoning_enabled: bool = True
    report_enabled: bool = True
    max_page_chars_for_llm: int = 2500
    max_evidence_chars_for_llm: int = 5000
    min_interval_seconds: float = 8.0
    last_call_by_phase: dict[str, float] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "LLMPolicy":
        return cls(
            enabled=os.getenv("VULNSCOPE_LLM_ENABLED", "1") != "0",
            planner_enabled=os.getenv("VULNSCOPE_USE_OLLAMA_PLANNER", "1") != "0",
            deep_reasoning_enabled=os.getenv("VULNSCOPE_DEEP_REASONING", "1") != "0",
            report_enabled=os.getenv("VULNSCOPE_LLM_REPORT", "1") != "0",
            max_page_chars_for_llm=int(os.getenv("VULNSCOPE_LLM_PAGE_CHARS", "2500")),
            max_evidence_chars_for_llm=int(os.getenv("VULNSCOPE_LLM_EVIDENCE_CHARS", "5000")),
            min_interval_seconds=float(os.getenv("VULNSCOPE_LLM_MIN_INTERVAL", "8")),
        )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def _rate_allowed(self, phase: str) -> bool:
        now = time.time()
        previous = self.last_call_by_phase.get(phase, 0.0)
        if now - previous < self.min_interval_seconds:
            return False
        self.last_call_by_phase[phase] = now
        return True

    def allow(self, phase: str, *, ambiguous: bool = False, no_results_after_50: bool = False, force: bool = False) -> tuple[bool, str]:
        if not self.enabled:
            return False, "LLM disabled by policy"
        if force:
            return self._rate_allowed(phase), "forced LLM call with rate limit"
        if phase in {"diagnostics", "final_report", "public_reasoning"}:
            return self._rate_allowed(phase), "LLM allowed for diagnostics/report/reasoning"
        if phase == "planning":
            if not self.planner_enabled:
                return False, "planner LLM disabled"
            if ambiguous or no_results_after_50:
                return self._rate_allowed(phase), "LLM allowed for ambiguous or low-yield planning"
            return False, "deterministic planning is preferred"
        if phase == "evidence_validation":
            if ambiguous and self.deep_reasoning_enabled:
                return self._rate_allowed(phase), "LLM allowed for ambiguous evidence validation"
            return False, "evidence validation is deterministic"
        return False, "phase not eligible for LLM"

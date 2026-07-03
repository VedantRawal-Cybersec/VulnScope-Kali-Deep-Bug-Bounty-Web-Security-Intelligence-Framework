#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import asdict, dataclass
from urllib.parse import urlparse

from core.parameter_inventory import dedupe_by_cluster
from core.scan_state import ParamRecord, ScanState, TestRecord

SENSITIVE_PATH_HINTS = {"login", "logout", "signin", "signup", "password", "checkout", "payment", "cart", "delete", "upload"}
NETWORK_TESTS = {"reflection_canary", "redirect_review", "baseline", "error_behavior"}
PASSIVE_TESTS = {"classification_review"}


@dataclass
class TestQueueSummary:
    parameters_considered: int = 0
    safe_active_parameters: int = 0
    tests_created: int = 0
    passive_tests: int = 0
    safe_active_tests: int = 0
    blocked_by_mode: int = 0
    skipped_sensitive: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def is_safe_get_parameter(param: ParamRecord) -> tuple[bool, str]:
    if param.method.upper() != "GET":
        return False, "non-GET parameter"
    parsed = urlparse(param.url)
    path = (parsed.path or "/").lower()
    if any(hint in path for hint in SENSITIVE_PATH_HINTS):
        return False, "sensitive workflow path"
    low = param.name.lower()
    if any(token in low for token in ["password", "passwd", "token", "csrf", "session", "auth"]):
        return False, "sensitive parameter name"
    return True, "safe GET parameter"


class TestQueueBuilder:
    """Turns discovered parameters into explicit test records before execution.

    This prevents the scanner from reporting zero tests when parameters exist. Passive
    mode still runs passive classification reviews. Safe-active mode adds harmless
    canary tests only for safe GET parameters.
    """

    def __init__(self, *, state: ScanState, scan_mode: str = "passive", max_params: int = 250) -> None:
        self.state = state
        self.scan_mode = scan_mode if scan_mode in {"passive", "safe-active", "lab"} else "passive"
        self.max_params = max(1, int(max_params))
        self.summary = TestQueueSummary()

    def _add_test(self, param: ParamRecord, test_name: str) -> None:
        test_id = f"{param.key}:{test_name}"
        if test_id not in self.state.tests:
            self.state.add_test(TestRecord(test_id=test_id, url=param.url, parameter=param.name, test_name=test_name))
            self.summary.tests_created += 1
        if test_name in PASSIVE_TESTS:
            self.summary.passive_tests += 1
        else:
            self.summary.safe_active_tests += 1

    def build(self) -> TestQueueSummary:
        params = dedupe_by_cluster(self.state.queued_params(limit=self.max_params), max_per_cluster=3)
        if not params:
            params = dedupe_by_cluster(list(self.state.params.values())[: self.max_params], max_per_cluster=3)
        self.summary.parameters_considered = len(params)
        for param in params:
            self._add_test(param, "classification_review")
            safe, reason = is_safe_get_parameter(param)
            if not safe:
                param.notes.append(f"safe-active skipped: {reason}") if reason not in param.notes else None
                if "sensitive" in reason:
                    self.summary.skipped_sensitive += 1
                continue
            self.summary.safe_active_parameters += 1
            if self.scan_mode in {"safe-active", "lab"}:
                if param.kind in {"route-like", "reference-like"}:
                    self._add_test(param, "redirect_review")
                else:
                    self._add_test(param, "reflection_canary")
            else:
                self.summary.blocked_by_mode += 1
        self.state.stats["test_queue"] = self.summary.to_dict()
        self.state.save()
        return self.summary

    def ordered_tests(self) -> list[TestRecord]:
        priority = {"classification_review": 10, "redirect_review": 20, "reflection_canary": 30, "baseline": 40, "error_behavior": 50}
        return sorted(
            [item for item in self.state.tests.values() if item.status == "queued"],
            key=lambda item: (priority.get(item.test_name, 99), item.url, item.parameter or ""),
        )


def test_requires_network(test_name: str) -> bool:
    return test_name in NETWORK_TESTS

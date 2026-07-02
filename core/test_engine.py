#!/usr/bin/env python3
from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass
from html import escape
from urllib.parse import urljoin

from core.evidence_store import body_hash
from core.http_client_v2 import ResponseRecord, SafeHttpClientV2
from core.parameter_inventory import replace_param
from core.scan_state import ParamRecord, ScanState, TestRecord


def canary() -> str:
    return "vs_canary_" + uuid.uuid4().hex[:12]


@dataclass
class TestOutcome:
    status: str
    finding: dict | None = None
    evidence_id: str | None = None
    confidence: int = 0
    message: str = ""


class TestEngine:
    """Safe test engine: baseline comparison, canary reflection, input behavior, and review leads."""

    def __init__(self, *, state: ScanState, client: SafeHttpClientV2, dashboard: object | None = None) -> None:
        self.state = state
        self.client = client
        self.dashboard = dashboard

    def _dash(self, message: str, *, param: ParamRecord | None = None, probe: str = "—", evidence: str = "", progress: int = 0) -> None:
        url = param.url if param else self.state.target
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            from core.live_dashboard import target_components
            parts = target_components(url)
            self.dashboard.update(
                phase="Safe Test Engine",
                phase_progress=progress,
                requests=self.state.stats.get("requests", 0),
                findings=len(self.state.findings),
                endpoint=parts["endpoint"],
                domain=parts["domain"],
                request_line=parts["request_line"],
                path=parts["path"],
                parameters=param.name if param else parts["parameters"],
                probe_string=probe,
                action=message,
                hypothesis="baseline and harmless canary comparison",
                evidence=evidence,
                safety_status="safe parameter testing • no destructive methods • no production data modification",
            )
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO", message)

    def _finding(self, *, title: str, status: str, severity: str, confidence: int, category: str, url: str, parameter: str | None, evidence: str, impact: str, recommendation: str, response: ResponseRecord | None = None, probe: str | None = None, steps: list[str] | None = None) -> dict:
        finding = {
            "id": "auto_" + uuid.uuid4().hex[:10],
            "title": title,
            "status": status,
            "severity": severity,
            "confidence": confidence,
            "category": category,
            "affected_url": url,
            "parameter": parameter,
            "evidence": evidence,
            "impact": impact,
            "recommendation": recommendation,
            "response_status": response.status_code if response else None,
            "response_time_ms": response.elapsed_ms if response else None,
            "safe_probe": probe,
            "reproduction_steps": steps or [f"Review {url} inside the authorized scope.", "Validate with approved low-impact methods only."],
        }
        finding_id = self.client.evidence.record_finding(finding)
        finding["id"] = finding_id
        self.state.add_finding(finding)
        if self.dashboard is not None and hasattr(self.dashboard, "add_finding"):
            self.dashboard.add_finding(title, impact, severity, url=url, parameter=parameter or "—", test_string=probe or "safe-observation", evidence=evidence, confidence=f"{confidence}%", reproduction="\n".join(finding["reproduction_steps"]), confirmation="confirmed" if status.lower() == "confirmed" else "review_lead")
        return finding

    def compare(self, baseline: ResponseRecord, test: ResponseRecord, probe: str | None = None) -> dict:
        return {
            "baseline_status": baseline.status_code,
            "test_status": test.status_code,
            "baseline_length": len(baseline.text or ""),
            "test_length": len(test.text or ""),
            "length_delta": len(test.text or "") - len(baseline.text or ""),
            "baseline_hash": body_hash(baseline.text),
            "test_hash": body_hash(test.text),
            "probe_reflected": bool(probe and probe in (test.text or "")),
            "test_error": test.error,
        }

    def run_test(self, param: ParamRecord, test_name: str) -> TestOutcome:
        test_id = f"{param.key}:{test_name}"
        record = self.state.tests.get(test_id) or TestRecord(test_id=test_id, url=param.url, parameter=param.name, test_name=test_name)
        record.status = "running"
        record.started_at = time.time()
        self.state.add_test(record)
        self.state.save()
        try:
            if test_name == "baseline":
                outcome = self.baseline(param)
            elif test_name == "reflection_canary":
                outcome = self.reflection_canary(param)
            elif test_name == "error_behavior":
                outcome = self.error_behavior(param)
            elif test_name == "redirect_review":
                outcome = self.redirect_review(param)
            else:
                outcome = self.classification_review(param)
            record.status = "done" if outcome.status in {"done", "finding"} else outcome.status
            record.confidence = outcome.confidence
            record.evidence_id = outcome.evidence_id
            if outcome.finding:
                record.finding_id = outcome.finding.get("id")
            param.tested.append(test_name) if test_name not in param.tested else None
            if all(name in param.tested for name in ["reflection_canary", "classification_review"]):
                param.status = "done"
            record.finished_at = time.time()
            self.state.save()
            return outcome
        except Exception as exc:
            record.status = "failed"
            record.error = str(exc)[:500]
            record.finished_at = time.time()
            self.state.save()
            return TestOutcome(status="failed", message=str(exc), confidence=0)

    def baseline(self, param: ParamRecord) -> TestOutcome:
        self._dash("Running baseline request", param=param, probe="baseline")
        response = self.client.get(param.url, purpose="baseline")
        if not response.ok:
            return TestOutcome(status="failed", evidence_id=response.response_id, message=response.error)
        return TestOutcome(status="done", evidence_id=response.response_id, confidence=80, message="baseline captured")

    def reflection_canary(self, param: ParamRecord) -> TestOutcome:
        probe = canary()
        test_url = replace_param(param.url, param.name, probe)
        self._dash(f"Testing parameter {param.name} with harmless canary", param=param, probe=probe)
        baseline = self.client.get(param.url, purpose="baseline-before-canary")
        test = self.client.get(test_url, purpose="harmless-canary")
        comparison = self.compare(baseline, test, probe=probe)
        evidence_id = self.client.evidence.record_comparison(baseline_id=baseline.response_id, test_id=test.response_id, url=test_url, parameter=param.name, result=comparison)
        if probe in (test.text or ""):
            context = self.reflection_context(test.text, probe)
            finding = self._finding(
                title="Reflected Input Observation",
                status="Confirmed",
                severity="LOW",
                confidence=95,
                category="Reflection",
                url=test_url,
                parameter=param.name,
                evidence=f"Exact harmless canary appeared in response. Context: {context}",
                impact="A confirmed reflection point needs output-encoding review. It is not automatically script execution.",
                recommendation="Review output context and encode user-controlled values before rendering.",
                response=test,
                probe=probe,
                steps=[f"Open the baseline URL: {param.url}", f"Set `{param.name}` to `{probe}`.", "Confirm the exact canary appears in the response body."],
            )
            return TestOutcome(status="finding", finding=finding, evidence_id=evidence_id, confidence=95, message="canary reflected")
        if test.status_code >= 500 and baseline.status_code < 500:
            finding = self._finding(
                title="Harmless Parameter Input Triggered Server Error",
                status="Confirmed",
                severity="MEDIUM",
                confidence=85,
                category="Input Handling",
                url=test_url,
                parameter=param.name,
                evidence=f"Baseline HTTP {baseline.status_code}; canary HTTP {test.status_code}.",
                impact="Unexpected server errors during harmless input handling can indicate fragile validation or exception handling.",
                recommendation="Review parameter validation and exception handling for this route.",
                response=test,
                probe=probe,
            )
            return TestOutcome(status="finding", finding=finding, evidence_id=evidence_id, confidence=85, message="server error delta")
        return TestOutcome(status="done", evidence_id=evidence_id, confidence=70, message="no reflection observed")

    def error_behavior(self, param: ParamRecord) -> TestOutcome:
        probe = canary() + "_long"
        return self.reflection_canary(ParamRecord(url=param.url, name=param.name, value=param.value, source=param.source, kind=param.kind, risk_score=param.risk_score))

    def redirect_review(self, param: ParamRecord) -> TestOutcome:
        probe = "/" + canary()
        test_url = replace_param(param.url, param.name, probe)
        self._dash("Reviewing redirect behavior with same-site style value", param=param, probe=probe)
        response = self.client.get(test_url, purpose="redirect-review", allow_redirects=False)
        if response.status_code in {301, 302, 303, 307, 308}:
            location = response.headers.get("Location", "")
            absolute = urljoin(response.url, location)
            same_site = (absolute.startswith("/") or absolute.startswith(self.state.target.rsplit("/", 1)[0]))
            finding = self._finding(
                title="Redirect Parameter Behavior Observed",
                status="Confirmed" if same_site else "Manual Review Lead",
                severity="INFO" if same_site else "MEDIUM",
                confidence=80,
                category="Redirect Review",
                url=test_url,
                parameter=param.name,
                evidence=f"HTTP {response.status_code} Location: {escape(location[:200])}",
                impact="Redirect parameters require strict destination allowlisting and normalization.",
                recommendation="Confirm that destination values are allowlisted and cannot be influenced toward unapproved hosts.",
                response=response,
                probe=probe,
            )
            return TestOutcome(status="finding", finding=finding, evidence_id=response.response_id, confidence=80)
        return TestOutcome(status="done", evidence_id=response.response_id, confidence=60, message="no redirect response")

    def classification_review(self, param: ParamRecord) -> TestOutcome:
        lead_map = {
            "object-like": ("Object Reference Parameter Review Lead", "Object-level access checks should be validated with approved test accounts."),
            "reference-like": ("Reference-Like Parameter Review Lead", "Server-side use of referenced endpoints should be reviewed in an approved environment."),
            "resource-like": ("Resource Path Parameter Review Lead", "Path/resource resolution should be allowlisted and normalized."),
            "route-like": ("Route Parameter Review Lead", "Redirect or route-destination parameters should be allowlisted."),
        }
        if param.kind not in lead_map:
            return TestOutcome(status="done", confidence=50, message="no classification lead")
        title, impact = lead_map[param.kind]
        finding = self._finding(
            title=title,
            status="Manual Review Lead",
            severity="INFO",
            confidence=70,
            category="Parameter Review",
            url=param.url,
            parameter=param.name,
            evidence=f"Parameter `{param.name}` classified as `{param.kind}` with risk score {param.risk_score}. No risky value was submitted.",
            impact=impact,
            recommendation="Validate manually using authorized accounts or a staging environment. Keep production testing low-impact.",
            probe="classification-only",
            steps=[f"Review `{param.name}` on {param.url}.", "Check server-side validation and authorization behavior in an approved environment."],
        )
        return TestOutcome(status="finding", finding=finding, confidence=70, message="classification review lead")

    @staticmethod
    def reflection_context(body: str, probe: str) -> str:
        idx = (body or "").find(probe)
        if idx < 0:
            return "not reflected"
        left = body[max(0, idx - 80) : idx]
        right = body[idx + len(probe) : idx + len(probe) + 80]
        if "<script" in left.lower() and "</script" in right.lower():
            return "script-like context"
        if "<" in left[-20:] and ">" in right[:20]:
            return "html-tag-adjacent context"
        if "=\"" in left[-40:] or "='" in left[-40:]:
            return "attribute-like context"
        if body.strip().startswith("{") or body.strip().startswith("["):
            return "json-like context"
        return "text/html body context"

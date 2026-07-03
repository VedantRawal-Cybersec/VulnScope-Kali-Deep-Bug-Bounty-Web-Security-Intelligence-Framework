#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse

from core.parameter_inventory import dedupe_by_cluster
from core.scan_state import ParamRecord, ScanState


ALLOWED_REACT_TOOLS = {
    "crawl",
    "review_scripts",
    "test_parameter",
    "summarize_surface",
    "write_reports",
    "stop",
}

ALLOWED_TESTS = {
    "baseline",
    "reflection_canary",
    "redirect_review",
    "classification_review",
}

TOOL_DESCRIPTIONS = {
    "crawl": "Continue same-scope GET/HEAD crawling with request budget and rate limit.",
    "review_scripts": "Fetch same-scope JavaScript files and extract route/query hints.",
    "test_parameter": "Run one approved zero-impact parameter review on an already discovered safe GET parameter.",
    "summarize_surface": "Summarize discovered surface without sending requests.",
    "write_reports": "Stop active work and write evidence-based reports.",
    "stop": "Stop the ReAct loop safely.",
}

TOOL_ROUTER_ALIASES = {
    "crawl": "crawler_v2",
    "review_scripts": "js_route_review",
    "test_parameter": "safe_canary_reflection",
    "summarize_surface": "llm_public_reasoning",
    "write_reports": "report_generator",
    "stop": "llm_public_reasoning",
}


@dataclass
class ReactDecision:
    reasoning: str
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    confidence: int = 50
    source: str = "deterministic"

    def safe(self, *, scan_mode: str) -> "ReactDecision":
        tool = str(self.tool or "stop").strip()
        if tool not in ALLOWED_REACT_TOOLS:
            return ReactDecision(
                reasoning="Rejected unsupported tool request from planner.",
                tool="stop",
                arguments={},
                confidence=0,
                source=self.source,
            )
        args = dict(self.arguments or {})
        test_name = str(args.get("test_name") or "classification_review").strip()
        if test_name not in ALLOWED_TESTS:
            test_name = "classification_review"
        if scan_mode == "passive" and tool == "test_parameter":
            test_name = "classification_review"
        args["test_name"] = test_name
        self.tool = tool
        self.arguments = args
        self.confidence = max(0, min(100, int(self.confidence or 0)))
        return self


@dataclass
class ReactObservation:
    turn_id: str
    tool: str
    status: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)
    elapsed_ms: int = 0


class SafeCAIReactAgent:
    """Autonomous, evidence-first ReAct controller for authorized VulnScope scans.

    The deterministic scheduler owns forward progress. The LLM improves prioritization
    and interpretation, but cannot stall scanning, invent targets, or end the scan while
    safe queued work remains.
    """

    SYSTEM_PROMPT = """
You are VulnScope's defensive CAI-style ReAct planner.
Return JSON only. Do not reveal hidden chain-of-thought.
Use concise public reasoning.

Hard rules:
- Authorized defensive web assessment only.
- Same-scope only.
- Use only the listed tools.
- Do not propose brute force, credential attacks, login bypass, exploit chaining,
  destructive payloads, DoS, stealth, WAF bypass, data theft, reverse shells,
  SSRF exploitation, SQL injection exploit payloads, XSS exploit payloads,
  or production data modification.
- Parameter tests may use only already discovered safe GET/query parameters.
- If safe queued work remains, do not choose write_reports.

Required JSON schema:
{
  "reasoning": "brief public rationale",
  "tool": "crawl|review_scripts|test_parameter|summarize_surface|write_reports|stop",
  "arguments": {"url": "optional existing URL", "parameter": "optional existing parameter", "test_name": "reflection_canary|redirect_review|classification_review|baseline"},
  "confidence": 0
}
""".strip()

    def __init__(
        self,
        *,
        target: str,
        scan_mode: str,
        state: ScanState,
        crawler: Any,
        tester: Any,
        llm: Any,
        dashboard: Any | None,
        trace: Any | None,
        turns: Any | None,
        tool_router: Any | None,
        max_turns: int = 160,
        max_params: int = 250,
    ) -> None:
        self.target = target
        self.scan_mode = scan_mode if scan_mode in {"passive", "safe-active", "lab"} else "passive"
        self.state = state
        self.crawler = crawler
        self.tester = tester
        self.llm = llm
        self.dashboard = dashboard
        self.trace = trace
        self.turns = turns
        self.tool_router = tool_router
        self.max_turns = max(1, int(max_turns))
        self.max_params = max(1, int(max_params))
        self.history: list[dict[str, Any]] = []
        self.current_tool: str | None = None
        self.decision_index = 0
        self.llm_interval = max(1, int(os.getenv("VULNSCOPE_LLM_DECISION_INTERVAL", "4")))
        self.llm_timeout = max(2, int(os.getenv("VULNSCOPE_LLM_DECISION_TIMEOUT", "6")))
        self.llm_disabled = os.getenv("VULNSCOPE_DISABLE_LLM_PLANNER", "0") == "1"

    def _coverage_text(self) -> str:
        cov = self.state.coverage()
        return (
            f"urls={cov['urls_done']}/{cov['urls_total']} "
            f"params={cov['params_done']}/{cov['params_total']} "
            f"tests={cov['tests_done']}/{cov['tests_total']} "
            f"req={cov['requests']} findings={cov['findings']} "
            f"timeouts={cov['timeouts']}"
        )

    def _surface(self) -> dict[str, int]:
        paths = {urlparse(item.url).path or "/" for item in self.state.urls.values()}
        api_like = [
            item.url
            for item in self.state.urls.values()
            if "/api/" in (urlparse(item.url).path or "").lower()
            or "graphql" in (urlparse(item.url).path or "").lower()
        ]
        return {
            "urls_found": len(self.state.urls),
            "paths_found": len(paths),
            "params_found": len(self.state.params),
            "forms_found": int(self.state.stats.get("forms", 0)) + int(self.state.stats.get("browser_forms", 0)),
            "js_found": int(self.state.stats.get("scripts", 0)),
            "api_routes_found": len(api_like) + int(self.state.stats.get("javascript_routes", 0)),
        }

    def _next_test_for_param(self, item: ParamRecord) -> str | None:
        tested = set(item.tested or [])
        if item.status in {"done", "skipped", "failed"}:
            return None
        if self.scan_mode == "passive":
            return None if "classification_review" in tested else "classification_review"
        if item.kind in {"object-like", "resource-like"}:
            return None if "classification_review" in tested else "classification_review"
        if item.kind in {"route-like", "reference-like"}:
            if "redirect_review" not in tested:
                return "redirect_review"
            return None if "classification_review" in tested else "classification_review"
        if "reflection_canary" not in tested:
            return "reflection_canary"
        return None if "classification_review" in tested else "classification_review"

    def _top_parameters(self, limit: int = 18) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for item in dedupe_by_cluster(list(self.state.params.values()), max_per_cluster=2)[:limit]:
            output.append(
                {
                    "url": item.url,
                    "name": item.name,
                    "kind": item.kind,
                    "risk_score": item.risk_score,
                    "status": item.status,
                    "tested": list(item.tested),
                    "next_test": self._next_test_for_param(item),
                    "source": item.source,
                }
            )
        return output

    def _context(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scan_mode": self.scan_mode,
            "coverage": self.state.coverage(),
            "surface": self._surface(),
            "budget_remaining": self.tester.client.budget_remaining() if hasattr(self.tester, "client") else 0,
            "queued_urls": [item.url for item in self.state.queued_urls(limit=5)],
            "top_parameters": self._top_parameters(limit=12),
            "recent_observations": self.history[-4:],
            "available_tools": TOOL_DESCRIPTIONS,
            "safety_boundary": {
                "same_scope_only": True,
                "safe_methods_only": True,
                "production_data_modification": False,
                "credential_or_login_testing": False,
                "exploit_payloads": False,
            },
        }

    def _next_turn_id(self) -> str:
        if self.turns is not None and hasattr(self.turns, "next_turn"):
            return self.turns.next_turn()
        return f"turn_{len(self.history) + 1:04d}"

    def _turn_count(self) -> int:
        values = [len(self.history)]
        if self.turns is not None and hasattr(self.turns, "index"):
            values.append(int(getattr(self.turns, "index", 0)))
        if self.trace is not None and hasattr(self.trace, "events"):
            values.append(len(getattr(self.trace, "events", [])))
        return max(values or [0])

    def _matrix_counts(self, tool: str, status: str = "running") -> dict[str, int]:
        if self.tool_router is None:
            return {}
        tool_id = TOOL_ROUTER_ALIASES.get(tool, tool)
        router_ids = {item.tool_id for item in getattr(self.tool_router, "tools", [])}
        if self.current_tool and self.current_tool != tool_id and self.current_tool in router_ids:
            self.tool_router.mark(self.current_tool, "completed", "completed before next ReAct action")
        if tool_id in router_ids:
            self.tool_router.mark(tool_id, status, "current CAI ReAct action")
            self.current_tool = tool_id
        matrix = self.tool_router.matrix()
        counts = matrix.get("counts", {})
        return {
            "tools_total": int(matrix.get("total", 0)),
            "tools_running": int(counts.get("running", 0)),
            "tools_completed": int(counts.get("completed", 0)),
            "tools_failed": int(counts.get("failed", 0)) + int(counts.get("timed_out", 0)),
            "tools_skipped": int(counts.get("skipped", 0)),
            "tools_blocked": int(counts.get("blocked_by_scope", 0)) + int(counts.get("blocked_by_safety", 0)),
        }

    def _dashboard(self, *, phase: str, decision: ReactDecision, action: str, progress: int, evidence: str = "") -> None:
        if self.dashboard is None or not hasattr(self.dashboard, "update"):
            return
        url = str(decision.arguments.get("url") or self.target)
        parsed = urlparse(url)
        parameter = str(decision.arguments.get("parameter") or parsed.query or "No safe query parameters or GET inputs were discovered in the selected scope.")
        self.dashboard.update(
            phase=phase,
            phase_progress=progress,
            turn=self._turn_count(),
            max_turns=self.max_turns,
            requests=self.state.stats.get("requests", 0),
            findings=len(self.state.findings),
            current_agent="CAIReActPlannerAgent",
            current_tool=decision.tool,
            decision=decision.tool,
            action=action,
            endpoint=url,
            request_line="GET " + (parsed.path or "/") + (("?" + parsed.query) if parsed.query else ""),
            path=parsed.path or "/",
            parameters=parameter,
            probe_string=str(decision.arguments.get("test_name") or "react-plan"),
            hypothesis=decision.reasoning,
            evidence=evidence or self._coverage_text(),
            safety_status="CAI ReAct guardrails • same-scope • safe tools only • no credentials/exploit payloads/destructive actions",
            **self._surface(),
            **self._matrix_counts(decision.tool, "running"),
        )
        if hasattr(self.dashboard, "event"):
            self.dashboard.event("THINKING", f"ReAct decision: {decision.tool} — {decision.reasoning}")

    def _trace(self, *, turn_id: str, agent_name: str, tool_name: str, phase: str, status: str, message: str, decision: ReactDecision | None = None, evidence_summary: str = "", progress: int = 0) -> None:
        if self.trace is None or not hasattr(self.trace, "log"):
            return
        url = self.target
        param = ""
        if decision:
            url = str(decision.arguments.get("url") or self.target)
            param = str(decision.arguments.get("parameter") or "")
        self.trace.log(
            turn_id=turn_id,
            agent_name=agent_name,
            tool_name=tool_name,
            phase=phase,
            status=status,
            target_url=url,
            path=urlparse(url).path or "/",
            parameter=param,
            message=message,
            evidence_summary=evidence_summary[:1000],
            progress_percent=progress,
        )

    def _next_parameter_decision(self) -> ReactDecision | None:
        candidates = dedupe_by_cluster(self.state.queued_params(limit=self.max_params), max_per_cluster=2)
        for item in candidates:
            next_test = self._next_test_for_param(item)
            if next_test is None:
                item.status = "done"
                continue
            item.status = "review"
            return ReactDecision(
                f"Next safe test for parameter `{item.name}` is `{next_test}`; kind={item.kind} risk={item.risk_score}.",
                "test_parameter",
                {"url": item.url, "parameter": item.name, "test_name": next_test},
                92,
                "deterministic",
            ).safe(scan_mode=self.scan_mode)
        return None

    def _fallback_decision(self) -> ReactDecision:
        cov = self.state.coverage()
        if self.state.queued_urls(limit=1) and cov["urls_done"] < max(1, min(cov["urls_total"], int(self.state.stats.get("max_pages", 120)))):
            return ReactDecision("Queued URLs remain; continue safe same-scope crawling.", "crawl", {}, 85, "deterministic")
        if int(self.state.stats.get("javascript_routes", 0)) == 0 and int(self.state.stats.get("scripts", 0)) > 0:
            return ReactDecision("Scripts were discovered; review them for route and query hints.", "review_scripts", {}, 80, "deterministic")
        parameter_decision = self._next_parameter_decision()
        if parameter_decision is not None:
            return parameter_decision
        self.state.save()
        return ReactDecision("No queued URLs or safe parameter test steps remain; write reports.", "write_reports", {}, 90, "deterministic")

    def _llm_should_run(self, fallback: ReactDecision) -> bool:
        if self.llm_disabled:
            return False
        if os.getenv("VULNSCOPE_LLM_EVERY_TURN", "0") == "1":
            return True
        if fallback.tool in {"write_reports", "stop"}:
            return False
        return self.decision_index == 1 or self.decision_index % self.llm_interval == 0

    def _llm_decision(self, fallback: ReactDecision) -> ReactDecision:
        try:
            response = self.llm.chat_json(
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps(self._context(), ensure_ascii=False)},
                ],
                model_role="fast",
                timeout=self.llm_timeout,
            )
        except Exception:
            return fallback
        if not getattr(response, "ok", False) or not getattr(response, "parsed", None):
            return fallback
        parsed = response.parsed or {}
        decision = ReactDecision(
            reasoning=str(parsed.get("reasoning") or fallback.reasoning),
            tool=str(parsed.get("tool") or fallback.tool),
            arguments=dict(parsed.get("arguments") or fallback.arguments),
            confidence=int(parsed.get("confidence") or fallback.confidence),
            source="ollama",
        ).safe(scan_mode=self.scan_mode)
        # Do not let the LLM stop/report early while deterministic safe work remains.
        if fallback.tool not in {"write_reports", "stop"} and decision.tool in {"write_reports", "stop", "summarize_surface"}:
            return fallback
        return self._bind_to_discovered_input(decision, fallback)

    def _find_param(self, url: str, parameter: str) -> ParamRecord | None:
        for item in self.state.params.values():
            if item.url == url and item.name == parameter:
                return item
        return None

    def _bind_to_discovered_input(self, decision: ReactDecision, fallback: ReactDecision) -> ReactDecision:
        if decision.tool != "test_parameter":
            return decision
        url = str(decision.arguments.get("url") or "")
        param = str(decision.arguments.get("parameter") or "")
        found = self._find_param(url, param) if url and param else None
        if found is not None:
            planned = self._next_test_for_param(found)
            if planned is None:
                found.status = "done"
                return fallback
            decision.arguments["test_name"] = planned
            return decision.safe(scan_mode=self.scan_mode)
        if fallback.tool == "test_parameter":
            return fallback
        parameter_decision = self._next_parameter_decision()
        if parameter_decision is not None:
            return parameter_decision
        return ReactDecision("Planner requested parameter testing, but no discovered safe parameter exists.", "summarize_surface", {}, 70, decision.source)

    def decide(self) -> ReactDecision:
        self.decision_index += 1
        fallback = self._fallback_decision().safe(scan_mode=self.scan_mode)
        if not self._llm_should_run(fallback):
            return fallback
        return self._llm_decision(fallback).safe(scan_mode=self.scan_mode)

    def execute(self, decision: ReactDecision, turn_id: str, progress: int) -> ReactObservation:
        started = time.time()
        try:
            if decision.tool == "crawl":
                result = self.crawler.crawl()
                data = asdict(result) if hasattr(result, "__dataclass_fields__") else dict(result or {})
                return ReactObservation(turn_id, decision.tool, "completed", "safe crawl completed", data, int((time.time() - started) * 1000))
            if decision.tool == "review_scripts":
                count = self.crawler.analyze_scripts(limit=80)
                return ReactObservation(turn_id, decision.tool, "completed", f"JavaScript route review added {count} route hints", {"routes_added": count}, int((time.time() - started) * 1000))
            if decision.tool == "test_parameter":
                param = self._find_param(str(decision.arguments.get("url") or ""), str(decision.arguments.get("parameter") or ""))
                if param is None:
                    return ReactObservation(turn_id, decision.tool, "skipped", "No matching discovered safe parameter", {}, int((time.time() - started) * 1000))
                test_name = str(decision.arguments.get("test_name") or self._next_test_for_param(param) or "classification_review")
                outcome = self.tester.run_test(param, test_name)
                next_test = self._next_test_for_param(param)
                if next_test is None:
                    param.status = "done"
                elif outcome.status in {"done", "finding"}:
                    param.status = "review"
                self.state.save()
                return ReactObservation(
                    turn_id,
                    decision.tool,
                    "completed" if outcome.status in {"done", "finding"} else outcome.status,
                    outcome.message or f"{test_name} completed; next={next_test or 'done'}",
                    {"test_name": test_name, "next_test": next_test, "status": outcome.status, "confidence": outcome.confidence, "evidence_id": outcome.evidence_id},
                    int((time.time() - started) * 1000),
                )
            if decision.tool == "summarize_surface":
                return ReactObservation(turn_id, decision.tool, "completed", self._coverage_text(), {"surface": self._surface()}, int((time.time() - started) * 1000))
            if decision.tool in {"write_reports", "stop"}:
                return ReactObservation(turn_id, decision.tool, "completed", "ReAct loop stopped safely", {}, int((time.time() - started) * 1000))
            return ReactObservation(turn_id, decision.tool, "failed", "Unsupported tool after validation", {}, int((time.time() - started) * 1000))
        except Exception as exc:
            return ReactObservation(turn_id, decision.tool, "failed", str(exc)[:500], {}, int((time.time() - started) * 1000))

    def run(self) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        for index in range(self.max_turns):
            turn_id = self._next_turn_id()
            progress = min(90, 42 + int((index + 1) * 45 / max(1, self.max_turns)))
            decision = self.decide()
            self._trace(
                turn_id=turn_id,
                agent_name="CAIReActPlannerAgent",
                tool_name="llm_react_decision",
                phase="CAI ReAct Planning",
                status="completed",
                message=decision.reasoning,
                decision=decision,
                evidence_summary=json.dumps({"source": decision.source, "confidence": decision.confidence, "llm_interval": self.llm_interval}, ensure_ascii=False),
                progress=progress,
            )
            self._dashboard(phase="CAI ReAct Planning", decision=decision, action=decision.reasoning, progress=progress)
            observation = self.execute(decision, turn_id, progress)
            observations.append(asdict(observation))
            self.history.append({"decision": asdict(decision), "observation": asdict(observation)})
            self._trace(
                turn_id=turn_id,
                agent_name="CAIReActToolExecutor",
                tool_name=decision.tool,
                phase="CAI ReAct Execution",
                status=observation.status,
                message=observation.message,
                decision=decision,
                evidence_summary=json.dumps(observation.data, ensure_ascii=False),
                progress=progress,
            )
            if self.dashboard is not None and hasattr(self.dashboard, "event"):
                self.dashboard.event("INFO", f"ReAct observation: {decision.tool} -> {observation.status}: {observation.message}")
            self.state.add_event("INFO", "cai react observation", tool=decision.tool, status=observation.status, message=observation.message)
            self.state.save()
            if observation.status == "failed":
                if hasattr(self.tester, "client") and self.tester.client.budget_remaining() <= 0:
                    break
                continue
            if decision.tool in {"write_reports", "stop"}:
                break
        if self.current_tool and self.tool_router is not None:
            router_ids = {item.tool_id for item in getattr(self.tool_router, "tools", [])}
            if self.current_tool in router_ids:
                self.tool_router.mark(self.current_tool, "completed", "CAI ReAct loop completed")
        return {
            "mode": "safe-cai-react",
            "turns": len(observations),
            "observations": observations,
            "history": self.history[-50:],
            "coverage": self.state.coverage(),
            "surface": self._surface(),
            "llm_pacing": {
                "decision_interval": self.llm_interval,
                "decision_timeout": self.llm_timeout,
                "disabled": self.llm_disabled,
            },
            "safety": {
                "same_scope_only": True,
                "allowed_tools_only": True,
                "credential_testing": False,
                "exploit_payloads": False,
                "destructive_actions": False,
            },
        }

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table

from ai.finding_review import run_ai_finding_review
from core.correlation_engine import correlate_findings
from core.evidence_store import EvidenceStore
from core.external_tool_orchestrator import collect_external_tool_status
from core.request_engine import RequestEngine
from core.validators import Target
from modules.access_control_hints import analyze_access_control_hints
from modules.api_surface_mapper import map_api_surface
from modules.cors_analyzer import analyze_cors
from modules.crawler import crawl_same_domain
from modules.deep_route_intelligence import analyze_deep_routes
from modules.exposure_finder import find_sensitive_exposure_signals
from modules.header_cookie_auditor import audit_headers_and_cookies
from modules.http_intelligence import collect_http_metadata
from modules.ip_route_intelligence import collect_ip_route_intelligence
from modules.js_endpoint_miner import mine_javascript_endpoints
from modules.parameter_discovery import analyze_parameters
from modules.robots_sitemap import analyze_robots_and_sitemap
from modules.sqli_signal_analysis import analyze_sqli_signals
from modules.xss_precision import analyze_xss_precision
from reports.markdown_report import generate_markdown_report

console = Console()


class VulnScopeScanner:
    def __init__(
        self,
        target: Target,
        mode: str,
        max_pages: int,
        output_dir: Path,
        ai_review: bool = False,
        ai_providers: list[str] | None = None,
        timeout: int = 30,
        delay: float = 0.7,
        retries: int = 2,
    ) -> None:
        self.target = target
        self.mode = mode
        self.max_pages = max_pages
        self.output_dir = output_dir
        self.ai_review = ai_review
        self.ai_providers = ai_providers
        self.timeout = timeout
        self.delay = delay
        self.retries = retries
        self.request_engine = RequestEngine(timeout=timeout, delay=delay, retries=retries)
        self.store = EvidenceStore()

    def run(self) -> None:
        console.print("\n[cyan][+] Initializing VulnScope-Kali Intelligence modules...[/cyan]")
        self._print_module_status(self.ai_review)

        console.print("\n[cyan][01/18] Collecting IP route intelligence...[/cyan]")
        collect_ip_route_intelligence(self.store, self.target.normalized_url)

        console.print("[cyan][02/18] Detecting trusted external tool readiness...[/cyan]")
        collect_external_tool_status(self.store)

        console.print("[cyan][03/18] Probing root target...[/cyan]")
        root_response = self.request_engine.get(self.target.normalized_url)
        collect_http_metadata(self.store, root_response)

        if root_response.error:
            console.print(f"[yellow][!] Root request failed but scan will continue safely:[/yellow] {root_response.error}")
            console.print("[yellow][!] For slow/CDN-heavy sites, rerun with: --timeout 45 --delay 1.0 --retries 3 --max-pages 5[/yellow]")
            self.store.metadata["root_probe_warning"] = {
                "error": root_response.error,
                "safe_continuation": True,
                "suggested_command_flags": "--timeout 45 --delay 1.0 --retries 3 --max-pages 5",
            }
        else:
            self.store.add_endpoint(root_response.url)

        console.print("[cyan][04/18] Auditing security headers and cookies...[/cyan]")
        audit_headers_and_cookies(self.store, root_response)

        console.print("[cyan][05/18] Analyzing CORS posture...[/cyan]")
        analyze_cors(self.store, root_response)

        console.print("[cyan][06/18] Parsing robots.txt and sitemap.xml...[/cyan]")
        analyze_robots_and_sitemap(
            base_url=self.target.base_url,
            target_host=self.target.host,
            request_engine=self.request_engine,
            store=self.store,
        )

        console.print("[cyan][07/18] Crawling same-domain pages...[/cyan]")
        responses = crawl_same_domain(
            start_url=root_response.url or self.target.normalized_url,
            target_host=self.target.host,
            request_engine=self.request_engine,
            store=self.store,
            max_pages=self.max_pages,
        )
        all_responses = [root_response] + responses

        console.print("[cyan][08/18] Mining JavaScript endpoints...[/cyan]")
        mine_javascript_endpoints(
            responses=all_responses,
            target_host=self.target.host,
            request_engine=self.request_engine,
            store=self.store,
        )

        console.print("[cyan][09/18] Classifying deep route intelligence...[/cyan]")
        analyze_deep_routes(self.store)

        console.print("[cyan][10/18] Mapping API surface...[/cyan]")
        map_api_surface(self.store)

        console.print("[cyan][11/18] Analyzing parameters and forms...[/cyan]")
        analyze_parameters(self.store)

        console.print("[cyan][12/18] Identifying access-control review candidates...[/cyan]")
        analyze_access_control_hints(self.store)

        console.print("[cyan][13/18] Running safe XSS precision signals...[/cyan]")
        analyze_xss_precision(self.store, all_responses)

        console.print("[cyan][14/18] Running safe SQLi signal analysis...[/cyan]")
        analyze_sqli_signals(self.store, all_responses)

        console.print("[cyan][15/18] Searching for sensitive exposure signals...[/cyan]")
        find_sensitive_exposure_signals(self.store, all_responses)

        console.print("[cyan][16/18] Correlating evidence and deduplicating findings...[/cyan]")
        correlate_findings(self.store)

        if self.ai_review:
            console.print("[cyan][17/18] Running AI Analyst Engine on redacted evidence...[/cyan]")
            run_ai_finding_review(self.store, providers=self.ai_providers)
            correlate_findings(self.store)
        else:
            console.print("[yellow][17/18] AI Analyst Engine skipped. Use --ai-review to enable.[/yellow]")

        console.print("[cyan][18/18] Writing reports...[/cyan]")
        report_path = self.output_dir / "target-report.md"
        evidence_path = self.output_dir / "evidence.json"
        generate_markdown_report(self.store, report_path, self.target.normalized_url, self.mode)
        self.store.write_json(evidence_path)

        self._print_summary(report_path, evidence_path)

    @staticmethod
    def _print_module_status(ai_review: bool) -> None:
        table = Table(title="VulnScope Intelligence Modules")
        table.add_column("ID", style="cyan")
        table.add_column("Module")
        table.add_column("Status")
        modules = [
            ("01", "IP Route Intelligence", "READY"),
            ("02", "External Tool Orchestrator Status", "READY"),
            ("03", "HTTP Intelligence", "READY"),
            ("04", "Header & Cookie Auditor", "READY"),
            ("05", "CORS Analyzer", "READY"),
            ("06", "robots.txt + Sitemap Intelligence", "READY"),
            ("07", "Same-Domain Crawler", "READY"),
            ("08", "JavaScript Endpoint Miner", "READY"),
            ("09", "DeepRoute Intelligence", "READY"),
            ("10", "API Surface Mapper", "READY"),
            ("11", "Parameter Intelligence", "READY"),
            ("12", "Access Control / IDOR Hints", "READY"),
            ("13", "XSS Precision Signals", "READY"),
            ("14", "SQLi Signal Analysis", "READY"),
            ("15", "Sensitive Exposure Finder", "READY"),
            ("16", "Evidence Correlation Engine", "READY"),
            ("17", "AI Analyst Engine", "READY" if ai_review else "OPTIONAL"),
            ("18", "Report Generator", "READY"),
        ]
        for row in modules:
            table.add_row(*row)
        console.print(table)

    def _print_summary(self, report_path: Path, evidence_path: Path) -> None:
        table = Table(title="Scan Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value")
        table.add_row("Target", self.target.normalized_url)
        table.add_row("Mode", self.mode)
        table.add_row("AI Review", "Enabled" if self.ai_review else "Disabled")
        table.add_row("Timeout", f"{self.timeout}s")
        table.add_row("Delay", f"{self.delay}s")
        table.add_row("Retries", str(self.retries))
        ip_info = self.store.metadata.get("ip_route_intelligence", {})
        table.add_row("Resolved IPs", str(ip_info.get("resolved_ip_count", 0)))
        tool_status = self.store.metadata.get("external_tool_status", [])
        installed_tools = [tool for tool in tool_status if tool.get("installed")]
        table.add_row("Trusted Tools Detected", str(len(installed_tools)))
        table.add_row("Endpoints Discovered", str(len(self.store.endpoints)))
        table.add_row("Forms Detected", str(len(self.store.forms)))
        table.add_row("Findings Generated", str(len(self.store.findings)))
        table.add_row("Markdown Report", str(report_path))
        table.add_row("Evidence JSON", str(evidence_path))
        console.print("\n[green][+] Scan completed successfully.[/green]")
        console.print(table)

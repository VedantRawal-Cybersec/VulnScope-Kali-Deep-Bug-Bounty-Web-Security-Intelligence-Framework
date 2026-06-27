from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table

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
    def __init__(self, target: Target, mode: str, max_pages: int, output_dir: Path) -> None:
        self.target = target
        self.mode = mode
        self.max_pages = max_pages
        self.output_dir = output_dir
        self.request_engine = RequestEngine(timeout=10, delay=0.4)
        self.store = EvidenceStore()

    def run(self) -> None:
        console.print("\n[cyan][+] Initializing VulnScope-Kali Intelligence modules...[/cyan]")
        self._print_module_status()

        console.print("\n[cyan][01/17] Collecting IP route intelligence...[/cyan]")
        collect_ip_route_intelligence(self.store, self.target.normalized_url)

        console.print("[cyan][02/17] Detecting trusted external tool readiness...[/cyan]")
        collect_external_tool_status(self.store)

        console.print("[cyan][03/17] Probing root target...[/cyan]")
        root_response = self.request_engine.get(self.target.normalized_url)
        collect_http_metadata(self.store, root_response)

        if root_response.error:
            console.print(f"[red][!] Root request failed: {root_response.error}[/red]")
        else:
            self.store.add_endpoint(root_response.url)

        console.print("[cyan][04/17] Auditing security headers and cookies...[/cyan]")
        audit_headers_and_cookies(self.store, root_response)

        console.print("[cyan][05/17] Analyzing CORS posture...[/cyan]")
        analyze_cors(self.store, root_response)

        console.print("[cyan][06/17] Parsing robots.txt and sitemap.xml...[/cyan]")
        analyze_robots_and_sitemap(
            base_url=self.target.base_url,
            target_host=self.target.host,
            request_engine=self.request_engine,
            store=self.store,
        )

        console.print("[cyan][07/17] Crawling same-domain pages...[/cyan]")
        responses = crawl_same_domain(
            start_url=root_response.url or self.target.normalized_url,
            target_host=self.target.host,
            request_engine=self.request_engine,
            store=self.store,
            max_pages=self.max_pages,
        )
        all_responses = [root_response] + responses

        console.print("[cyan][08/17] Mining JavaScript endpoints...[/cyan]")
        mine_javascript_endpoints(
            responses=all_responses,
            target_host=self.target.host,
            request_engine=self.request_engine,
            store=self.store,
        )

        console.print("[cyan][09/17] Classifying deep route intelligence...[/cyan]")
        analyze_deep_routes(self.store)

        console.print("[cyan][10/17] Mapping API surface...[/cyan]")
        map_api_surface(self.store)

        console.print("[cyan][11/17] Analyzing parameters and forms...[/cyan]")
        analyze_parameters(self.store)

        console.print("[cyan][12/17] Identifying access-control review candidates...[/cyan]")
        analyze_access_control_hints(self.store)

        console.print("[cyan][13/17] Running safe XSS precision signals...[/cyan]")
        analyze_xss_precision(self.store, all_responses)

        console.print("[cyan][14/17] Running safe SQLi signal analysis...[/cyan]")
        analyze_sqli_signals(self.store, all_responses)

        console.print("[cyan][15/17] Searching for sensitive exposure signals...[/cyan]")
        find_sensitive_exposure_signals(self.store, all_responses)

        console.print("[cyan][16/17] Correlating evidence and deduplicating findings...[/cyan]")
        correlate_findings(self.store)

        console.print("[cyan][17/17] Writing reports...[/cyan]")
        report_path = self.output_dir / "target-report.md"
        evidence_path = self.output_dir / "evidence.json"
        generate_markdown_report(self.store, report_path, self.target.normalized_url, self.mode)
        self.store.write_json(evidence_path)

        self._print_summary(report_path, evidence_path)

    @staticmethod
    def _print_module_status() -> None:
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
            ("17", "Report Generator", "READY"),
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

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table

from core.evidence_store import EvidenceStore
from core.request_engine import RequestEngine
from core.validators import Target
from modules.crawler import crawl_same_domain
from modules.header_cookie_auditor import audit_headers_and_cookies
from modules.http_intelligence import collect_http_metadata
from modules.js_endpoint_miner import mine_javascript_endpoints
from modules.parameter_discovery import analyze_parameters
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
        console.print("\n[cyan][+] Initializing VulnScope-Kali Phase 1 modules...[/cyan]")
        self._print_module_status()

        console.print("\n[cyan][01/06] Probing root target...[/cyan]")
        root_response = self.request_engine.get(self.target.normalized_url)
        collect_http_metadata(self.store, root_response)

        if root_response.error:
            console.print(f"[red][!] Root request failed: {root_response.error}[/red]")
        else:
            self.store.add_endpoint(root_response.url)

        console.print("[cyan][02/06] Auditing security headers and cookies...[/cyan]")
        audit_headers_and_cookies(self.store, root_response)

        console.print("[cyan][03/06] Crawling same-domain pages...[/cyan]")
        responses = crawl_same_domain(
            start_url=root_response.url or self.target.normalized_url,
            target_host=self.target.host,
            request_engine=self.request_engine,
            store=self.store,
            max_pages=self.max_pages,
        )

        console.print("[cyan][04/06] Mining JavaScript endpoints...[/cyan]")
        mine_javascript_endpoints(
            responses=responses,
            target_host=self.target.host,
            request_engine=self.request_engine,
            store=self.store,
        )

        console.print("[cyan][05/06] Analyzing parameters and forms...[/cyan]")
        analyze_parameters(self.store)

        console.print("[cyan][06/06] Writing reports...[/cyan]")
        report_path = self.output_dir / "target-report.md"
        evidence_path = self.output_dir / "evidence.json"
        generate_markdown_report(self.store, report_path, self.target.normalized_url, self.mode)
        self.store.write_json(evidence_path)

        self._print_summary(report_path, evidence_path)

    @staticmethod
    def _print_module_status() -> None:
        table = Table(title="Phase 1 Modules")
        table.add_column("ID", style="cyan")
        table.add_column("Module")
        table.add_column("Status")
        modules = [
            ("01", "HTTP Intelligence", "READY"),
            ("02", "Header & Cookie Auditor", "READY"),
            ("03", "Same-Domain Crawler", "READY"),
            ("04", "JavaScript Endpoint Miner", "READY"),
            ("05", "Parameter Intelligence", "READY"),
            ("06", "Report Generator", "READY"),
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
        table.add_row("Endpoints Discovered", str(len(self.store.endpoints)))
        table.add_row("Forms Detected", str(len(self.store.forms)))
        table.add_row("Findings Generated", str(len(self.store.findings)))
        table.add_row("Markdown Report", str(report_path))
        table.add_row("Evidence JSON", str(evidence_path))
        console.print("\n[green][+] Scan completed successfully.[/green]")
        console.print(table)

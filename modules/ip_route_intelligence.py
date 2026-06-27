from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from core.evidence_store import EvidenceStore, Finding


def collect_ip_route_intelligence(store: EvidenceStore, target_url: str) -> None:
    """Collect safe DNS/IP route metadata for efficiency and scope clarity.

    This module does not scan IP ranges, does not probe ports, and does not touch
    routers. It resolves the target hostname and classifies the resolved IPs so
    the framework can deduplicate work, avoid scope mistakes, and improve report
    context.
    """
    parsed = urlparse(target_url)
    host = parsed.hostname
    if not host:
        return

    records: list[dict[str, str | bool]] = []
    errors: list[str] = []

    try:
        addr_infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        errors.append(str(exc))
        addr_infos = []

    seen: set[str] = set()
    for info in addr_infos:
        ip_value = info[4][0]
        if ip_value in seen:
            continue
        seen.add(ip_value)
        try:
            ip_obj = ipaddress.ip_address(ip_value)
            records.append(
                {
                    "ip": ip_value,
                    "version": f"IPv{ip_obj.version}",
                    "is_private": ip_obj.is_private,
                    "is_loopback": ip_obj.is_loopback,
                    "is_reserved": ip_obj.is_reserved,
                    "is_global": ip_obj.is_global,
                }
            )
        except ValueError:
            records.append(
                {
                    "ip": ip_value,
                    "version": "unknown",
                    "is_private": False,
                    "is_loopback": False,
                    "is_reserved": False,
                    "is_global": False,
                }
            )

    store.metadata["ip_route_intelligence"] = {
        "host": host,
        "resolved_ip_count": len(records),
        "resolved_ips": records,
        "errors": errors,
        "safety_note": "DNS/IP metadata only. No IP range scanning, port scanning, or router interaction performed.",
    }

    if records:
        store.add_finding(
            Finding(
                finding_id=store.next_finding_id(),
                title="IP Route Intelligence Collected",
                category="Infrastructure Context",
                severity="Info",
                confidence="High",
                status="Discovered",
                endpoint=target_url,
                where_found="DNS hostname resolution",
                how_detected=["The target hostname was resolved to one or more IP addresses for scope and deduplication context"],
                why_risky="This is not a vulnerability. It helps the scanner understand target routing, avoid duplicate work, and prevent scope mistakes when hostnames resolve to shared infrastructure.",
                evidence={
                    "host": host,
                    "resolved_ip_count": len(records),
                    "resolved_ips": records,
                },
                recommended_validation=[
                    "Confirm that testing by direct IP address is allowed before using any IP-based target.",
                    "Prefer hostname-based testing unless the program scope explicitly includes the IP address.",
                ],
                remediation=["No remediation required. This is infrastructure context for authorized testing."],
            )
        )

    if any(bool(record.get("is_private")) or bool(record.get("is_loopback")) for record in records):
        store.add_finding(
            Finding(
                finding_id=store.next_finding_id(),
                title="Private or Local IP Resolution Observed",
                category="Scope Safety",
                severity="Info",
                confidence="High",
                status="Scope Review Required",
                endpoint=target_url,
                where_found="DNS/IP route classification",
                how_detected=["At least one resolved IP address was classified as private or loopback"],
                why_risky="Private or loopback targets may represent local labs, internal networks, or development environments. Scope should be confirmed before testing.",
                evidence={"resolved_ips": records},
                recommended_validation=["Verify whether this is a local lab, owned environment, or explicitly authorized private target."],
                remediation=["No remediation required for the scanner. Confirm authorization and scope before continuing."],
            )
        )

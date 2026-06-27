# VulnScope-Kali Modules

This document summarizes the current implemented modules and the safety model.

## Implemented Core Modules

| Module | Purpose | Safety Behavior |
|---|---|---|
| IP Route Intelligence | Resolves target hostname and classifies IP metadata | DNS/IP metadata only; no IP range or port scanning |
| External Tool Orchestrator Status | Detects trusted tools installed locally | Does not scan targets or auto-enable tools |
| HTTP Intelligence | Collects root response metadata | Single safe GET request |
| Header & Cookie Auditor | Reviews security headers and cookie flags | Observation only |
| CORS Analyzer | Reviews root CORS response headers | Observation only |
| robots.txt + Sitemap Intelligence | Parses public robots and sitemap files | Same-domain route discovery only |
| Same-Domain Crawler | Crawls links within the target host | Same-domain only, rate-limited |
| JavaScript Endpoint Miner | Extracts same-domain routes from JavaScript files | Redacts values; no secret publishing |
| DeepRoute Intelligence | Classifies discovered route purpose | Heuristic prioritization only |
| API Surface Mapper | Identifies API-like routes and object-route candidates | Manual review hints only |
| Parameter Intelligence | Extracts and classifies URL/form parameters | Manual review hints only |
| Access Control / IDOR Hints | Finds object-level authorization review candidates | Requires manual validation with authorized accounts |
| XSS Precision Signals | Non-destructive reflection and browser-hardening signals | Does not inject XSS payloads |
| SQLi Signal Analysis | Non-destructive DB error and numeric parameter signals | Does not inject SQL payloads or dump data |
| Sensitive Exposure Finder | Looks for sensitive keyword classes and exposure-prone routes | Redacts values; manual validation required |
| Evidence Correlation Engine | Deduplicates and correlates findings | Does not upgrade potential findings to confirmed vulnerabilities |
| Report Generator | Writes Markdown and JSON evidence reports | Professional bug-bounty style output |

## Implemented Automation Support

| Component | Purpose |
|---|---|
| AutoPilot n8n Blueprint | Daily update and trend-monitoring workflow design |
| Trusted Update Sources | Trusted-source policy for safe automation |
| AutoPilot Environment Scanner | Local trusted-tool readiness report |
| Python Syntax Check Workflow | GitHub Actions compile check on push/PR/manual run |

## Finding Standards

Each finding should explain:

- Where it was found
- Which endpoint or parameter is affected
- How it was detected
- Why it matters
- Evidence collected
- Severity
- Confidence
- Status
- Manual validation steps
- Remediation guidance

## Safety Rules

VulnScope-Kali currently avoids:

- Brute force
- Credential capture
- Database dumping
- Unknown tool execution
- Destructive payloads
- Out-of-scope scanning
- Automatic exploitation
- Automatic activation of risky modules

## Current Philosophy

VulnScope-Kali is not a payload-heavy attack script. It is an authorized security intelligence framework that prioritizes discovery, classification, correlation, evidence quality, and safe manual validation.

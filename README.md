# VulnScope-Kali

**Deep Bug Bounty Web Security Intelligence Framework for Kali Linux**

VulnScope-Kali is an authorized web security assessment framework designed to combine safe discovery, endpoint intelligence, security header analysis, parameter mapping, evidence correlation, confidence scoring, adaptive knowledge, automation support, and professional reporting.

> This project is built for authorized testing only: owned applications, local labs, CTF environments, and in-scope bug bounty targets where automated testing is permitted by the program policy.

## Current Version

`v0.2.0-alpha` — Multi-module safe intelligence engine.

## Current Capabilities

Implemented modules:

- Kali-style terminal banner
- Interactive target URL input
- Authorization confirmation
- Scan mode selection
- URL validation
- Same-domain scope guard
- IP Route Intelligence
- Trusted external tool readiness detection
- Basic HTTP metadata collection
- Security header audit
- Cookie flag audit
- CORS analysis
- robots.txt and sitemap.xml parsing
- Same-domain crawler
- JavaScript file discovery
- Endpoint extraction from JavaScript text
- DeepRoute Intelligence Engine
- API Surface Mapper
- Parameter and form discovery
- Access Control / IDOR candidate hints
- Safe XSS precision signals
- Safe SQLi signal analysis
- Sensitive exposure signal finder
- Evidence correlation engine
- Finding evidence store
- Markdown and JSON report generation
- n8n AutoPilot automation blueprint
- Trusted update source policy
- AutoPilot environment scanner
- GitHub Actions Python compile check

## Advanced Engines Included as Safe Foundations

- DeepRoute Intelligence Engine
- ParamSense-style parameter intelligence
- API Surface Mapper
- XSS Precision Signal Module
- SQLi Signal Module
- Access Control / IDOR Hint Module
- CORS & Client Trust Analyzer
- Sensitive Exposure Finder
- Evidence Correlation Engine
- Adaptive Learning Knowledge Base
- AutoPilot Update Engine blueprint
- Controlled external-tool readiness layer for nuclei, katana, httpx, ffuf, dalfox, OWASP ZAP, and restricted sqlmap lab mode

## Ethical Guardrails

VulnScope-Kali is designed with safety controls from the beginning:

- Authorization confirmation before scanning
- Same-domain scope lock
- Rate limiting
- Request timeout controls
- No brute force
- No credential capture
- No database dumping
- No destructive payloads
- No out-of-scope scanning
- No unknown tool auto-execution
- No automatic activation of risky modules
- Safe XSS and SQLi modules are signal-based and non-destructive
- Lab aggressive mode is disabled by default and reserved only for intentionally vulnerable local labs in future versions

## Installation

```bash
sudo apt update
sudo apt install python3 python3-pip git -y
pip3 install -r requirements.txt
```

## Usage

Interactive mode:

```bash
python3 vulnscope.py
```

Direct URL mode:

```bash
python3 vulnscope.py --url https://example.com --mode passive
```

Safe active mode is currently conservative and does not perform exploit attempts:

```bash
python3 vulnscope.py --url https://example.com --mode safe-active --max-pages 25
```

AutoPilot local environment check:

```bash
python3 autopilot/environment_scanner.py
```

## Output

Reports are generated in:

```text
reports/output/
├── target-report.md
├── evidence.json
└── autopilot-environment.json
```

## Finding Philosophy

VulnScope-Kali does not rely on vague scanner output. Each finding is designed to explain:

- Where the signal was found
- Which endpoint or parameter was affected
- How it was detected
- Why it may matter
- Evidence collected
- Severity
- Confidence
- Status
- Recommended validation
- Suggested remediation

## Important Disclaimer

This tool must only be used against systems you own or have explicit permission to test. You are responsible for following all applicable laws, platform rules, and bug bounty program scope requirements.

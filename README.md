# VulnScope-Kali

**Deep Bug Bounty Web Security Intelligence Framework for Kali Linux**

VulnScope-Kali is an authorized web security assessment framework designed to combine safe discovery, endpoint intelligence, security header analysis, parameter mapping, evidence correlation, confidence scoring, and professional reporting.

> This project is built for authorized testing only: owned applications, local labs, CTF environments, and in-scope bug bounty targets where automated testing is permitted by the program policy.

## Current Version

`v0.1.0-alpha` — Phase 1 scaffold and safe passive assessment engine.

## Current Capabilities

Phase 1 includes:

- Kali-style terminal banner
- Interactive target URL input
- Authorization confirmation
- Scan mode selection
- URL validation
- Same-domain scope guard
- Basic HTTP metadata collection
- Security header audit
- Cookie flag audit
- Same-domain crawler
- JavaScript file discovery
- Endpoint extraction from JavaScript text
- Parameter and form discovery
- Finding evidence store
- Markdown and JSON report generation

## Planned Advanced Engines

Future phases will add:

- DeepRoute Intelligence Engine
- ParamSense behavior engine
- API Surface Mapper
- XSS Precision Module
- SQLi Signal Module
- Access Control / IDOR Hint Module
- CORS & Client Trust Analyzer
- Sensitive Exposure Finder
- Evidence Correlation Engine
- Adaptive Learning Engine
- AutoPilot Update Engine
- Controlled integrations with tools such as nuclei, katana, httpx, ffuf, dalfox, and restricted sqlmap detection mode

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
- Lab aggressive mode reserved only for local vulnerable labs in future versions

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

## Output

Reports are generated in:

```text
reports/output/
├── target-report.md
└── evidence.json
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
- Recommended validation
- Suggested remediation

## Important Disclaimer

This tool must only be used against systems you own or have explicit permission to test. You are responsible for following all applicable laws, platform rules, and bug bounty program scope requirements.

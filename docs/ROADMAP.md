# VulnScope-Kali Roadmap

## Phase 1 — Safe Passive Intelligence Engine

Status: In progress

- Banner and interactive target input
- Authorization guard
- URL validation
- Same-domain crawling
- HTTP metadata collection
- Security header audit
- Cookie audit
- JavaScript endpoint discovery
- Parameter and form mapping
- Markdown and JSON reports

## Phase 2 — DeepRoute Intelligence Engine

- Advanced JavaScript endpoint extraction
- Source map detection
- robots.txt and sitemap.xml enrichment
- Route classification
- API-like endpoint detection
- Admin/debug/upload/payment route hints

## Phase 3 — ParamSense Engine

- Parameter source classification
- Risky parameter mapping
- Safe behavior-difference checks
- Response length comparison
- Redirect behavior comparison
- Parameter priority ranking

## Phase 4 — External Tool Orchestration

- Controlled nuclei integration
- Controlled katana integration
- Controlled httpx integration
- Controlled ffuf integration
- Controlled dalfox integration
- Restricted sqlmap detection-only wrapper for local/lab mode

## Phase 5 — Multi-Method Vulnerability Modules

- XSS Precision Module
- SQLi Signal Module
- API Surface Mapper
- Access Control / IDOR Hint Module
- CORS Analyzer
- Sensitive Exposure Finder

## Phase 6 — Evidence Correlation Engine

- Merge duplicate findings
- Combine signals by endpoint and parameter
- Confidence scoring
- Severity scoring
- Manual validation guidance
- Bug bounty style finding cards

## Phase 7 — Adaptive Learning Engine

- Knowledge-base assisted classification
- Endpoint risk pattern database
- Parameter risk map
- False-positive feedback tracking
- Confirmed finding pattern tracking

## Phase 8 — AutoPilot Update Engine

- Installed tool detection
- Supported tool version checks
- Trusted template update workflow
- New tool review mode
- Compatibility testing
- Rollback checkpoints

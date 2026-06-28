# VulnScope Assessment Workflow

This is the phase-based autonomous-style workflow for authorized assets.

It combines:

- passive domain expansion
- archived URL intelligence
- application profiling
- authenticated context awareness
- specialist review agents
- validation task generation
- reportability scoring
- final report generation
- checkpoint/resume support

## Main Command

```bash
python3 hunt.py --target https://example.com --mode bounty
```

With automatic scope confirmation:

```bash
python3 hunt.py --target https://example.com --mode bounty --yes
```

Resume checkpoint:

```bash
python3 hunt.py --target https://example.com --resume --yes
```

## Modes

```text
bounty          focused report-ready candidates
pentest         broader review coverage
comprehensive   all observations and validation tasks
learning        portfolio/demo-friendly mode
```

## Phases

```text
P0_INIT
P1_SCOPE_CONFIRM
P2_TARGET_INGEST
P3_PASSIVE_RECON
P4_APP_PROFILE
P5_AUTH_CONTEXT
P6_AGENT_PLANNING
P7_SPECIALIST_REVIEW
P8_EVIDENCE_VALIDATION
P9_REPORTABILITY_SCORING
P10_FINAL_REPORT
```

## Outputs

```text
reports/output/workflow/app-profile.json
reports/output/workflow/app-profile.md
reports/output/workflow/agent-plan.json
reports/output/workflow/specialist-results/
reports/output/workflow/validation-tasks.json
reports/output/workflow/reportability-scores.json
reports/output/workflow/vulnscope-assessment-report.md
reports/output/workflow/<target>-checkpoint.json
```

## Specialist Review Agents

```text
ReconReviewAgent
AppProfileAgent
APIReviewAgent
AuthReviewAgent
IDORBOLAReviewAgent
JSIntelReviewAgent
ValidationReviewAgent
```

These agents produce review candidates and validation tasks. They do not perform destructive actions.

## Safety Rule

Review candidates are not confirmed vulnerabilities until manually validated on authorized assets.

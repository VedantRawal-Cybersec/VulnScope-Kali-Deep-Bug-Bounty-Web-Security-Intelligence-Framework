# n8n AutoPilot Automation Blueprint

This blueprint describes how n8n can be used as an external automation layer for VulnScope-Kali.

The goal is to keep the framework updated with trusted security intelligence, new tool versions, template updates, and trend signals without allowing unsafe automatic execution of untrusted code.

## Automation Goal

VulnScope-Kali AutoPilot should help with:

- Daily trusted-tool update checks
- Security template update checks
- New security methodology monitoring
- GitHub release monitoring for supported tools
- Safe update proposal generation
- Compatibility test triggering
- Pull request creation for approved changes
- Manual review before activation

## Critical Rule

n8n must not directly enable dangerous modules or run unknown GitHub tools automatically.

The automation can collect data, summarize trends, open issues, open pull requests, and trigger safe tests. New tools and risky modules must stay disabled until manually approved.

## Suggested n8n Workflow

### 1. Schedule Trigger

Run once daily.

Recommended cadence:

```text
Every day at 08:00 local time
```

### 2. Trusted Source Fetch

Use HTTP Request nodes to collect metadata from trusted sources only.

Trusted source categories:

- Official GitHub releases for supported tools
- Trusted template repositories
- OWASP resources
- PortSwigger learning material references
- Public CVE/NVD summaries
- Curated bug bounty writeup feeds
- VulnScope repository issues and roadmap

### 3. Tool Version Monitor

Check supported tools:

- nuclei
- katana
- httpx
- ffuf
- dalfox
- OWASP ZAP

Output:

```json
{
  "tool": "nuclei",
  "current_version": "local_or_last_known",
  "latest_version": "remote_version",
  "status": "update_available",
  "risk": "safe_review_required"
}
```

### 4. Trend Intelligence Collector

Collect public trend signals such as:

- New OWASP Top 10 discussion areas
- Common bug bounty writeup themes
- New defensive scanner templates
- New API security patterns
- High-frequency endpoint/parameter patterns

Do not collect or store exploit chains, credentials, private target data, or out-of-scope scanning instructions.

### 5. Pattern Extraction Node

Normalize collected intelligence into safe pattern records.

Example output:

```json
{
  "pattern_type": "endpoint_risk_hint",
  "pattern": "/api/orders/{id}",
  "category": "Access Control / BOLA Review",
  "safe_usage": "Use only as a manual review hint",
  "confidence": "medium",
  "activation": "review_required"
}
```

### 6. Safety Gate

Before creating a pull request, the workflow must check:

- Is the source trusted?
- Is the pattern detection-only?
- Does it avoid destructive payloads?
- Does it avoid credential capture?
- Does it require manual approval?
- Does it preserve bug bounty safe mode rules?

If any check fails, create an issue instead of a pull request.

### 7. GitHub Issue Creation

For new trends or tools that need review, create a GitHub issue.

Issue title format:

```text
[AutoPilot Review] Evaluate new pattern/tool: <name>
```

Issue body should include:

- Source
- Summary
- Proposed use
- Risk level
- Required review
- Suggested module
- Activation status: disabled by default

### 8. Pull Request Creation

Only create pull requests for safe updates such as:

- Knowledge-base additions
- Documentation updates
- Safe detection patterns
- Tool registry version notes
- Template metadata updates

Do not auto-merge.

### 9. Compatibility Test Trigger

After a safe pull request is created, trigger a test workflow or local test checklist:

- Run unit checks
- Run against local demo target
- Generate sample report
- Verify no destructive behavior
- Verify no scope bypass

### 10. Manual Approval

A human must approve:

- New external tools
- New active modules
- New payload families
- Lab-aggressive checks
- Any workflow with command execution

## Recommended n8n Node Chain

```text
Schedule Trigger
  -> HTTP Request: GitHub releases
  -> HTTP Request: trusted templates
  -> HTTP Request: OWASP/security references
  -> Code/Function: normalize metadata
  -> IF: safe source?
  -> IF: detection-only?
  -> GitHub: create issue or pull request
  -> Notification: email/Telegram/Slack summary
```

## Security Controls

Use these controls for the n8n deployment:

- Self-host n8n only if you can maintain updates
- Keep n8n updated
- Disable unnecessary Code nodes when possible
- Do not store GitHub tokens in plaintext
- Use least-privilege GitHub tokens
- Separate read-only intelligence workflows from write-capable GitHub workflows
- Require manual approval for pull requests
- Keep audit logs enabled
- Never pass secrets into AI prompts or public issues

## Update Modes

### Check Only Mode

Collect updates and create a report. No GitHub writes.

### Review Mode

Create GitHub issues for human review.

### Safe PR Mode

Create pull requests only for detection-only knowledge updates.

### Blocked Mode

Any untrusted, aggressive, or destructive update is blocked and logged.

## What n8n Should Not Do

- It should not run scans against real bug bounty targets automatically.
- It should not execute unknown GitHub code.
- It should not auto-enable aggressive modules.
- It should not auto-merge pull requests.
- It should not store secrets in reports.
- It should not create exploit chains.

## Final Automation Principle

n8n should make VulnScope-Kali smarter every day by updating knowledge, templates, and review queues.

It should not make the tool unsafe by blindly running untrusted automation.

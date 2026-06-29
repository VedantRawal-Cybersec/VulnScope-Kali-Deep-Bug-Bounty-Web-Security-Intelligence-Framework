# VulnScope Daily Maintenance

VulnScope now has a built-in maintenance layer for keeping the curated local toolkit fresh and reducing missing-tool failures.

## What it updates

- Curated Arsenal tools from `arsenal/tool_catalog.yaml`.
- Local healthcheck state.
- Local template updates where supported by installed tools.
- Defensive intelligence cache in `reports/output/maintenance/latest-intel.json`.

## Commands

Run once per day only when needed:

```bash
python3 daily_update_cli.py --profile bug-bounty-safe --yes
```

Force an update now:

```bash
python3 daily_update_cli.py --profile bug-bounty-safe --force --yes
```

Run normal Auto Mode with daily maintenance and auto repair:

```bash
python3 auto_mode.py --url https://example.com --profile bug-bounty-safe --full --yes
```

Autopilot also runs daily maintenance automatically when `allow_daily_updates: true` is present in `autonomy_policy.yaml`.

## Output files

```text
reports/output/maintenance/daily-update-state.json
reports/output/maintenance/latest-intel.json
reports/output/maintenance/daily-update.log
reports/output/arsenal/install-repair.log
reports/output/arsenal/healthcheck.json
```

## Notes

System package repair is best effort. VulnScope uses non-interactive sudo, so it fails cleanly instead of hanging for a password. If a package manager step cannot run, the log will explain the reason.

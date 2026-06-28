# Authenticated Manual Validation Mode

Authenticated Manual Validation Mode lets VulnScope-Kali work with owned test accounts for authorized validation.

Credentials are never committed to GitHub. They stay local in:

```text
~/.vulnscope/auth_profiles.local.json
```

Use only owned accounts and authorized targets.

## Install Playwright

```bash
pip install playwright
playwright install chromium
```

## Setup Accounts

```bash
python3 auth_mode.py --setup-accounts
```

You can configure:

- target base URL
- login URL
- Account A
- optional Account B for comparison

## Login and Save Session

```bash
python3 auth_mode.py --profile default --login --account a
```

For both accounts:

```bash
python3 auth_mode.py --profile default --login --account both
```

The browser opens. Complete OTP/CAPTCHA manually if needed, then press Enter in terminal.

## Authenticated Crawl

```bash
python3 auth_mode.py --profile default --crawl --account a --max-pages 10
```

For both accounts:

```bash
python3 auth_mode.py --profile default --crawl --account both --max-pages 10
```

## Compare Accounts

```bash
python3 auth_mode.py --profile default --compare-accounts
```

## Full Authenticated Workflow

```bash
python3 auth_mode.py --profile default --full-auth --max-pages 10
```

## Outputs

```text
reports/output/auth/states/default-account_a.json
reports/output/auth/states/default-account_b.json
reports/output/auth/auth-crawl-account_a.json
reports/output/auth/auth-crawl-account_b.json
reports/output/auth/account-comparison.json
reports/output/auth/account-comparison.md
```

## Safety Rules

The module does not:

- brute force login
- bypass OTP/CAPTCHA
- steal sessions
- use third-party credentials
- perform destructive account changes
- make purchases/payments
- dump private data

It helps validate authenticated workflows, access-control candidates, and two-account comparison evidence.

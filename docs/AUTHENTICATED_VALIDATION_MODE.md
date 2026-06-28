# Authenticated Manual Validation Mode

Authenticated Manual Validation Mode lets VulnScope-Kali work with owned test accounts for authorized validation.

Credentials are never committed to GitHub. They stay local in:

```text
~/.vulnscope/auth_profiles.local.json
```

Use only owned accounts and authorized targets.

## Important Google Login Rule

For Google login, the tool does not collect or store Google passwords.

The user logs in directly inside the real browser page opened by Playwright. The tool saves only the browser session state after the login is completed.

The best flow is:

```text
Open target app login page
Click Continue with Google
Google opens real accounts.google.com page
User enters Google credentials manually
Google redirects back to target app
Tool saves authenticated browser session state
```

A generic Google login page alone does not authenticate the target app. OAuth must normally start from the target application's own login page or a target-generated OAuth URL.

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
- Account A label/username
- optional Account B for comparison

For Google OAuth flows, the username/password fields are only local labels. The real Google password is entered manually in the browser and is not stored by VulnScope.

## Normal Login and Save Session

```bash
python3 auth_mode.py --profile default --login --account a
```

For both accounts:

```bash
python3 auth_mode.py --profile default --login --account both
```

The browser opens. Complete OTP/CAPTCHA manually if needed, then press Enter in terminal.

## Google/OAuth Login and Save Session

Account A:

```bash
python3 auth_mode.py --profile default --google-login --account a
```

Both accounts:

```bash
python3 auth_mode.py --profile default --google-login --account both
```

With a target-generated OAuth URL:

```bash
python3 auth_mode.py --profile default --google-login --account a --oauth-url "https://accounts.google.com/o/oauth2/v2/auth?..."
```

If the browser opens the target login page instead of Google, click the target app's `Continue with Google` button manually. After login redirects back to the target app dashboard, press Enter in terminal.

## Authenticated Crawl

```bash
python3 auth_mode.py --profile default --crawl --account a --max-pages 10
```

For both accounts:

```bash
python3 auth_mode.py --profile default --crawl --account both --max-pages 10
```

The crawler automatically prefers Google OAuth session files if they exist:

```text
reports/output/auth/states/default-account_a-google.json
reports/output/auth/states/default-account_b-google.json
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
reports/output/auth/states/default-account_a-google.json
reports/output/auth/states/default-account_b-google.json
reports/output/auth/auth-crawl-account_a.json
reports/output/auth/auth-crawl-account_b.json
reports/output/auth/account-comparison.json
reports/output/auth/account-comparison.md
```

## Safety Rules

The module does not:

- ask for Google passwords in terminal
- store Google passwords
- brute force login
- bypass OTP/CAPTCHA
- steal sessions
- use third-party credentials
- perform destructive account changes
- make purchases/payments
- dump private data

It helps validate authenticated workflows, access-control candidates, and two-account comparison evidence using owned accounts only.

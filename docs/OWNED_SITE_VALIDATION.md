# Consented Owned-Site Validation

VulnScope is designed for websites you own or where you have explicit written authorization.

## What changed

Earlier builds could spend too long crawling before validating parameters. The current scheduler now prioritizes already discovered or explicitly seeded GET/query parameters in `safe-active` and `lab` modes. This prevents validation starvation on authorized targets.

## Recommended command

```bash
python3 scripts/owned_site_scan.py \
  --target https://your-owned-site.com \
  --mode bugbounty \
  --seed-url '/search?q=test' \
  --seed-url '/product?id=1' \
  --max-pages 80 \
  --max-depth 3 \
  --max-actions 120 \
  --request-budget 400
```

Use `--yes` only when written authorization is already confirmed and you want a non-interactive run.

## Seed URLs

Seed URLs are normal same-scope application URLs with existing query parameters. They are not payloads. They tell VulnScope where your owned application accepts input so the safe validation engine does not starve behind crawling.

Examples:

```bash
--seed-url '/search?q=test'
--seed-url '/items?id=1'
--seed-url 'https://your-owned-site.com/catalog?page=1'
```

Out-of-scope seed URLs are ignored.

## Environment alternative

```bash
VULNSCOPE_SEED_URLS='https://your-owned-site.com/search?q=test,https://your-owned-site.com/items?id=1' \
python3 vulnscope.py --target https://your-owned-site.com --mode bugbounty
```

## Safety model

- Same-scope only.
- Consent prompt remains active unless `--yes` is used.
- No credential attacks.
- No destructive actions.
- No target data modification.
- Parameter checks use harmless canaries, baseline comparisons, redirect review, and classification review.

## Where to verify

After a run, inspect:

```bash
cat reports/output/cai-superior/<host>/autonomous-scan-state.json
cat reports/output/cai-superior/<host>/cai-react-summary.json
cat reports/output/cai-superior/<host>/final-findings-dashboard.txt
```

Look for `params_total`, `tests_total`, `findings`, and `lab-seed` or custom seed sources.

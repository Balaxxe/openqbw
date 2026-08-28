---
title: CLI quickstart
sidebar_label: CLI quickstart
---

# CLI quickstart

```sh
openqbw accounting-report SAMPLE_COMPANY.qbw \
  --report trial-balance --as-of 2026-12-31 \
  --fiscal-year-start 2026-01-01 \
  --retained-earnings-account-id ACCOUNT_ID \
  --retained-earnings-report-name "Retained Earnings" \
  --entity-id SAMPLE_ENTITY --source-label local-copy \
  --generated-at 2026-12-31T00:00:00Z --snapshot-id SNAPSHOT_ID \
  --format csv --out trial-balance.csv

openqbw reconcile-qbw-trial-balance --qbw SAMPLE_COMPANY.qbw \
  --native-tb native-trial-balance.csv --as-of 2026-12-31 \
  --fiscal-year-start 2026-01-01 \
  --retained-earnings-account-id ACCOUNT_ID --snapshot-id SNAPSHOT_ID
```

See the full [CLI reference](./cli.md) for every subcommand
and flag. The command opens only a local copy, fails closed on an unsupported
Enterprise 24 layout, and never uses QuickBooks, the Desktop SDK, COM, ODBC,
or a GUI session at runtime. `--as-of` and `--fiscal-year-start` are strict
ISO dates; the retained-earnings ID is intentionally explicit until company
preference discovery is implemented.

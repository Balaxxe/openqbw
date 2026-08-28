# Use cases

OpenQBW exists to provide long-term access to locally owned QuickBooks Desktop
data. This document walks through the four most common scenarios.

## 1. Data liberation: leaving the QuickBooks ecosystem

You have a local `.qbw` copy and need an independently runnable accounting
extract. For a supported Enterprise 24 R21 layout, first create a reconciled
accrual Trial Balance and retain the source copy and native report separately.

```console
$ openqbw accounting-report SAMPLE_COMPANY.qbw --report trial-balance \
    --as-of 2026-12-31 --fiscal-year-start 2026-01-01 \
    --retained-earnings-account-id ACCOUNT_ID \
    --entity-id SAMPLE_ENTITY --source-label local-copy \
    --generated-at 2026-12-31T00:00:00Z --snapshot-id SNAPSHOT_ID \
    --format sqlite --out trial-balance.sqlite
```

See [migration-guide.md](migration-guide.md) for the
target-product-specific mapping advice.

## 2. Forensic accounting and litigation support

A `.qbw` file has been produced in discovery. The QuickBooks
application is not available on the analyst's workstation, or the
opposing party has not produced credentials.

OpenQBW reads the on-disk layout. It does **not** crack passwords
or bypass DRM. If the file has a password set in QuickBooks, you
will only see metadata and obfuscated rows -- not the cleartext
financial data. You still get:

- Table inventory and row counts
- Schema and index metadata
- File-level metadata that can support timeline analysis

For supported local Enterprise 24 R21 copies, OpenQBW can also produce a
normalized General Ledger and accrual Trial Balance without QuickBooks at
runtime. Preserve the original and reconcile against a native report before
relying on a new source file. Unknown schemas and layouts are rejected.

## 3. Audit and discovery

You suspect a record was deleted or you want to inventory the
schema. OpenQBW can tell you:

```console
# Tables present in the file
$ openqbw catalog mybooks.qbw

# Index inventory (FK indexes only)
$ openqbw indexes mybooks.qbw --fk-only

# Per-table null-flag histogram (suggests defaults / deletions)
$ openqbw nulls mybooks.qbw

# Run legacy attribution diagnostics
$ openqbw verify mybooks.qbw
```

## 4. Long-term archival

QuickBooks files are sometimes the only complete record of a
business's books for the years before a SaaS migration. Supported files can
be preserved with an accounting export alongside the original:

```console
$ openqbw accounting-report SAMPLE_COMPANY.qbw --report general-ledger \
    --as-of 2026-12-31 --entity-id SAMPLE_ENTITY --source-label archival-copy \
    --generated-at 2026-12-31T00:00:00Z --snapshot-id SNAPSHOT_ID \
    --format sqlite --out archive/general-ledger.sqlite
```

A SQLite file is broadly portable, but preserve its tool version, report
policy, snapshot identifier, and source QBW copy with it. Cash-basis reports,
automatic company-preference discovery, VSS/snapshot orchestration, and
cross-company consolidation remain future work.

# Accounting acceptance

OpenQBW's Enterprise 24 R21 accounting path is release-gated against native
QuickBooks Desktop reports. Acceptance uses a local copy of a company file and
the production CLI build; the QBW is opened read-only.

The current private acceptance corpus covers:

- accrual Trial Balances at three private as-of dates, including a prior
  fiscal-year end and current-period dates;
- accrual General Ledgers over three private ranges, including a short range,
  a current-year-to-date range, and a prior full fiscal year;
- exact account identity, debit, credit, and signed-cent reconciliation;
- exact dated General Ledger movement multisets, with neutral native zero rows
  classified separately rather than treated as postings; and
- an unchanged QBW content hash before and after the complete acceptance run.

Every accepted Trial Balance had no missing, extra, or mismatched visible
accounts and zero-cent total variance. Every accepted General Ledger had no
missing or extra dated movements. Company names, dates, account names, IDs,
paths, hashes, row counts, and report values remain private.

The direct acceptance commands are:

```powershell
openqbw reconcile-qbw-trial-balance --qbw SAMPLE_COMPANY.qbw `
  --native-tb SAMPLE_NATIVE_TB.csv --as-of 2026-01-31 `
  --fiscal-year-start 2026-01-01 `
  --retained-earnings-account-id SAMPLE_RE_ACCOUNT_ID `
  --retained-earnings-report-name "SAMPLE_RE_REPORT_NAME" `
  --snapshot-id SAMPLE_SNAPSHOT

openqbw reconcile-qbw-general-ledger --qbw SAMPLE_COMPANY.qbw `
  --native-gl SAMPLE_NATIVE_GL.csv --from 2026-01-01 `
  --through 2026-01-31 --snapshot-id SAMPLE_SNAPSHOT
```

No QuickBooks SDK, COM automation, GUI session, ODBC driver, or local server is
used by those commands. Transaction fields that have not been independently
decoded, currently including the native transaction number, are reported as
unavailable rather than inferred.

This acceptance applies only when the strict Enterprise 24 R21 catalog and row
attestations pass. Unknown layouts, posting families, account classifications,
and ambiguous native account mappings fail closed.

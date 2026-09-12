# Derived financial statements

The operational CLI derives accrual Profit & Loss and Balance Sheet reports
from the same complete ledger used by the validated General Ledger and Trial
Balance. No additional native reports, new QBW decoders, or QuickBooks runtime
are required. Existing schema, coverage, lifecycle, and balance gates apply.
All chart accounts must retain a proven source-granularity classification that
agrees with their broad accounting type. Categories are never inferred from
account names.

## Profit & Loss

```powershell
openqbw accounting-report SAMPLE_COMPANY.qbw `
  --report profit-and-loss --from 2026-01-01 --as-of 2026-01-31 `
  --entity-id SAMPLE_ENTITY --source-label SAMPLE_LOCAL_COPY `
  --generated-at 2026-01-31T00:00:00Z --snapshot-id SAMPLE_SNAPSHOT `
  --format csv --out SAMPLE_PL.csv
```

Both dates are inclusive. Monthly, quarterly, year-to-date, and periods
crossing fiscal years use the same calculation. No fiscal reset is applied
inside a requested P&L range. Fiscal-year and Retained Earnings options are
rejected for P&L, so callers cannot accidentally imply an unused policy.

Income, cost of goods sold, expense, other income, and other expense are
separate sections. Gross profit is income less COGS. Net operating income
also subtracts expenses. Net income adds other income and subtracts other
expense. Revenue and expenses display positive on their conventional sides;
returns, contra activity, and losses retain their negative sign.

## Balance Sheet

```powershell
openqbw accounting-report SAMPLE_COMPANY.qbw `
  --report balance-sheet --as-of 2026-01-31 --fiscal-year-start 2026-01-01 `
  --retained-earnings-account-id SAMPLE_RE_ACCOUNT_ID `
  --entity-id SAMPLE_ENTITY --source-label SAMPLE_LOCAL_COPY `
  --generated-at 2026-01-31T00:00:00Z --snapshot-id SAMPLE_SNAPSHOT `
  --format sqlite --out SAMPLE_BS.sqlite
```

The Balance Sheet uses the existing explicit Trial Balance fiscal policy.
Prior-year P&L is already included in Retained Earnings, alongside direct
postings to that account. Current-year P&L becomes one calculated equity row,
`current_year_net_income`. It is not assigned an invented account ID or added
to Retained Earnings a second time. Assets must exactly equal liabilities plus
equity, including that current-year amount.

Assets, liabilities, and equity display positive on their conventional sides;
contra balances remain negative. Source-granularity account classifications
remain available for more detailed grouping. An optional
`--retained-earnings-report-name` changes only the statement row's label, while
the source chart name and account identity are preserved. `--from` is rejected
for an as-of Balance Sheet.

## Rows and output formats

Both reports accept `--format csv|json|sqlite` and
`--include-zero-balance-accounts`. By default, zero-balance account rows are
omitted while section totals and derived net income remain visible.

| Field | Meaning |
| --- | --- |
| `report_type` | `profit_and_loss` or `balance_sheet` |
| `from_day`, `as_of_day` | Source accounting day numbers; `from_day` is absent for Balance Sheet |
| `row_index` | Zero-based deterministic presentation order |
| `row_key` | `account:<source id>` or a named total/calculation |
| `row_kind` | `account`, `subtotal`, or `calculated` |
| `section` | Statement group, independent of account names |
| `account_id` | Source identity for account rows; absent for derived rows |
| `amount_cents` | Exact signed presentation amount in integer minor units |
| `net_cents` | Original debit-positive GL/TB amount for account rows; absent for derived rows |

CSV and JSON also provide fixed two-decimal `amount` and `net` strings.
The `label` uses the account's full display hierarchy, or the derived row's
label. Account amounts are direct amounts only: a parent row does not include
its children's activity. Do not sum account rows together with their subtotals
or calculated rows. This avoids double-counting when consuming the output.

CSV repeats source account metadata and caller-supplied provenance on report
rows. JSON has `metadata`, the complete `accounts` catalog, and `rows`.
Balance Sheet CSV/JSON retain the existing `tb_policy_*` fields and
`trial_balance_policy` metadata name because that is the policy being reused.

SQLite writes the complete chart to `accounts`, including zero-balance parents,
and writes reports to `financial_statement_metadata` and
`financial_statement_rows`. The report key is entity, report type, period start,
and cutoff; `period_start_day` equals `from_day` for P&L and `as_of_day` for
Balance Sheet. Separate P&L periods with the same end date coexist. The writer
replaces only the selected entity/report/period inside an atomic transaction.
As in the existing report database, the account catalog is scoped by entity.

Source labels, parser version, generation timestamp, and explicit fiscal
policy accompany output. The original QBW remains read-only. Existing files
require `--force`; input aliases are always rejected. Complete output is staged
before publication. A validation or overflow failure produces no partial report.

## Acceptance and scope

Tests reconcile P&L account amounts to the dated GL, Balance Sheet account
amounts to the fiscal-policy TB, and current-year net income between the two
new statements. Independently specified synthetic amounts verify subtotals,
inclusive dates, fiscal transitions, direct Retained Earnings postings,
hierarchy, contra balances, losses, zero accounts, and overflow. Output tests
verify cents, quoting, hierarchy, policy agreement, period isolation, and
transactional replacement.

Native P&L and Balance Sheet exports are optional corroboration rather than
a release prerequisite. This scope establishes derived accounting reports;
it does not reproduce every native QuickBooks report layout or filter.
Cash basis, cash flow classification, payment applications, aging, budgets,
and reports by customer, vendor, job, or class require separate scope and
evidence. No support for those fields is inferred from ledger totals.

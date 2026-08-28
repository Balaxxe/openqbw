# CLI reference

```console
$ openqbw --help
```

| Subcommand            | What it does                                                   |
|-----------------------|----------------------------------------------------------------|
| `catalog`             | Print recovered physical SYSTABLE catalog rows.                |
| `schema`              | Print the columns of a table (via SYSCOLUMN bridged to SYSTABLE).|
| `nulls`               | Counts SYSCOLUMN N/Y nullability values with sample columns.   |
| `indexes`             | List SYSINDEX and compare legacy attribution with diagnostics. |
| `fkgraph`             | Print heuristic foreign-key edges (name-based fallback).       |
| `validate-attribution`| Validate position attribution against SYSCOLUMN width bands.   |
| `export`              | Export transactions and line items to SQLite.                  |
| `migrate`             | Export to CSV, SQLite, or IIF for data liberation.             |
| `forensics`           | File-level discovery report (pages, ap coverage, anomalies).   |
| `verify`              | Validate an export against known invariants.                   |
| `reconcile-trial-balance` | Compare two QuickBooks-style Trial Balance CSV files exactly. |
| `reconcile-qbw-trial-balance` | Extract and reconcile a local QBW TB to a native CSV. |
| `reconcile-qbw-general-ledger` | Extract and reconcile dated direct-QBW GL movements to a native CSV. |
| `accounting-report` | Emit a validated Trial Balance or General Ledger. |
| `batch-extract` | Inspect copied QBW files in parallel. |
| `batch-trial-balance` | Produce an all-or-nothing consolidated SQLite TB from a private manifest. |

The default CLI is read-only and does not require QuickBooks, the Desktop SDK,
COM, ODBC, or a GUI session. The direct accounting commands accept only a
validated Enterprise 24 R21 schema/layout/family combination and fail closed
on anything else. Use local QBW copies only. `reconcile-trial-balance`
compares CSVs; the two `reconcile-qbw-*` commands perform direct QBW paths.

Controlled fixture/oracle commands are deliberately excluded from the default
binary. Development builds can opt in with `cargo run -p openqbw-cli --features
research-tools -- <command>`; their local fixtures and outputs must remain
ignored and must never be published.

### `compare-snapshots <before.qbw> <after.qbw>` (research feature only)

```console
$ openqbw compare-snapshots before.qbw after.qbw --output control.json
$ openqbw compare-snapshots baseline.qbw no-op-save.qbw \
    --control-noise-manifest control.json --output delta.json
```

This controlled-delta research command requires regular files of exactly the
same size, aligned to 4096-byte pages. It streams the two files one page at a
time and emits deterministic JSON containing only file lengths/SHA-256 hashes,
aggregate changed-page and CRC-footer counts, raw page-type-transition
histograms, and aggregate opaque before/after page-hash-transition counts.
It never emits file paths, page numbers, byte offsets, or QBW payload bytes.

`--control-noise-manifest` accepts a prior `compare-snapshots` JSON result.
It subtracts only the multiset intersection of complete before/after page hash
pairs. It does not subtract by page type, count, page position, or any logical
interpretation. The response retains both raw and remaining aggregates so the
subtraction is auditable. `--before-source-identifier` and
`--after-source-identifier` are optional caller-provided labels and are the
only source names the JSON may contain. `--output` creates a new JSON file and
refuses to overwrite an existing artifact; without it, JSON is printed to stdout.

### `probe-account-delta <before.qbw> <after.qbw>` (research feature only)

```console
$ openqbw probe-account-delta 01-no-edit.qbw 02-accounts.qbw \
    --control-noise-manifest control.json \
    --literal SAMPLE_ACCOUNT_001 --literal SAMPLE_BANK_ACCOUNT --literal SAMPLE_MARKER-bank \
    --output account-delta.json
```

This is a narrowly scoped controlled-delta research probe, not an account
decoder. It requires explicitly supplied, unique, non-empty ASCII synthetic
markers, each of which must be absent from the complete `before` snapshot; it
has no wildcard, regular-expression, or general text-search mode. It subtracts
the control by exact opaque before/after page-hash pair, then counts the
supplied markers only in the remaining changed pages. Its JSON
contains aggregate marker counts and co-occurrence/page-type clusters, but
never paths, page numbers, offsets, page hashes, surrounding bytes, or any
non-sentinel company contents. A marker match is evidence for a bounded
candidate set only; it does not establish an account row layout, field map, or
decoder correctness. For an account-creation experiment, supply the unique
number, name, and description for every synthetic account. Promotion to a row
decoder requires a subsequent bounded-row test that repeats across all
accounts and joins a known AccountQuery ListID; a same-page marker cluster is
not that test.

Pass `--ap-aware` only when controlled-delta research specifically needs to
test the documented SA17 AP transform. It remains opt-in and fail-closed from
the normal raw-byte mode: the command retains the complete raw probe result,
checks the complete `before` snapshot both as stored and after the same
candidate AP transform, and reports only aggregate matches of the
caller-supplied synthetic literals after AP recovery. It never
prints decoded bytes, page positions, paths, or non-sentinel text. This is
format evidence, not an account decoder or an assertion that every account
row has been recovered. The AP-aware JSON explicitly sets
`plaintext_certified` to `false` and labels the result `candidate_only`:
`recover_bv_any` and the AP-model fallback select candidate transform
parameters from page-local structural/statistical signals. They do not use a
supplied sentinel as a crib, but a subsequent hit still is not an
authentication of the decoded page, field, or record. A decoder must reject
these candidates unless independent row grammar, cross-stage behavior, and
reference-report reconciliation validate them.

### `probe-posting-delta <before.qbw> <after.qbw>` (research feature only)

```console
$ openqbw probe-posting-delta 03-account-rename.qbw 04-je1.qbw \
    --control-noise-manifest control.json \
    --marker ref-number=SAMPLE_JE_001 \
    --marker line-memo-1=SAMPLE_JE_001_LINE_001 \
    --marker line-memo-2=SAMPLE_JE_001_LINE_002 \
    --marker line-memo-3=SAMPLE_JE_001_LINE_003 \
    --marker line-memo-4=SAMPLE_JE_001_LINE_004 \
    --marker account-bank=SAMPLE_BANK_ACCOUNT \
    --marker account-asset=SAMPLE_ASSET_ACCOUNT_RENAMED \
    --marker account-liability=SAMPLE_LIABILITY_ACCOUNT \
    --marker account-expense=SAMPLE_EXPENSE_ACCOUNT \
    --marker account-income=SAMPLE_INCOME_ACCOUNT \
    --ap-aware \
    --output 04-je1-posting-evidence.json
```

This is a transaction evidence probe, not a posting decoder. It accepts only
explicit `lowercase-role=ASCII-synthetic-marker` arguments, subtracts the
no-edit control only by exact opaque hash-pair match, and emits aggregate
marker/page-type co-occurrence evidence. There is no generic search mode and
no output paths, locations, hashes, surrounding bytes, or decoded company
values.

`--ap-aware` is an opt-in candidate-only pass analogous to the account
probe's AP-aware mode. It scans only the explicit markers after candidate AP
recovery and reports separate `heuristic_candidate_page_count` and
`model_candidate_page_count` aggregates, with `plaintext_certified:false`.
It never decodes or identifies a posting. Account references use roles named
`account` or `account-*` and may be preexisting synthetic values in the full
before image. Every other marker (including the RefNumber and all line memos)
must be absent from the complete before image both as stored and after the
same candidate AP transform; this prevents a preexisting transaction marker
from being misrepresented as evidence of the new edit.

A textual hit does **not** prove a transaction-header field, date encoding,
TxnID/TxnLineID representation, account reference, signed cents, source type,
deleted state, or void state. Each must be established by independently
reproducible controlled stages and their read-only oracle/report goldens.

For a controlled deletion, retain chronological input order and add
`--removal`:

```console
$ openqbw probe-posting-delta 07-delete-before.qbw 08-delete-after.qbw \
    --control-noise-manifest control.json --removal --ap-aware \
    --marker ref-number=SAMPLE_DELETE_001 \
    --marker line-memo-1=SAMPLE_DELETE_001_LINE_001 \
    --marker line-memo-2=SAMPLE_DELETE_001_LINE_002 \
    --marker account-expense=SAMPLE_EXPENSE_ACCOUNT \
    --marker account-liability=SAMPLE_LIABILITY_ACCOUNT
```

This is a distinct chronological-removal mode, not a creation probe with the
snapshots reversed. Every non-account marker must occur in the complete before
image and be absent from the complete after image. Account controls (`account`
or `account-*`) may preexist in both images. Exact hash-pair control-noise
subtraction and aggregate-only output are preserved. With `--ap-aware`, the
same removal contract is also applied to the complete candidate-decoded images;
the result is `candidate_only`, never a plaintext, deletion, or posting-decoder
certificate.

### `probe-account-rename-structure <before.qbw> <after.qbw>` (research feature only)

```console
$ openqbw probe-account-rename-structure 02-accounts.qbw 03-account-rename.qbw \
    --control-noise-manifest control.json \
    --old-name SAMPLE_ASSET_ACCOUNT \
    --new-name SAMPLE_ASSET_ACCOUNT_RENAMED \
    --stable-literal SAMPLE_ACCOUNT_002 \
    --stable-literal SAMPLE_ASSET_MARKER
```

This controlled-delta research command pairs only the explicitly supplied
synthetic rename markers. It reports aggregate counts for exact normalized
stored-byte windows separately from `recover_bv_any` candidate decodes. The
former certifies only a byte-level invariant; neither section certifies
plaintext, a logical account row, or a field boundary.

## Subcommand details

### `catalog`

```console
$ openqbw catalog mybooks.qbw
```

Prints one line per user table from SYSTABLE. Useful as a first
look at any file.

### `schema <table>`

```console
$ openqbw schema mybooks.qbw abmc_invoice_lineitem
```

Lists recovered columns for the named table. In the Enterprise 24 research
dialect, SYSCOLUMN ownership joins directly to the physical SYSTABLE table ID.

### `indexes [--fk-only] [--summary-only]`

```console
$ openqbw indexes mybooks.qbw
$ openqbw indexes mybooks.qbw --fk-only
$ openqbw indexes mybooks.qbw --summary-only
```

Lists every recovered index from SYSINDEX. With
`--fk-only`, restricts to indexes whose name suggests a foreign
key. With `--summary-only`, prints only the cross-validation
result (agree / disagree / missing / orphan counts). The page-shaped value
being compared is a diagnostic candidate, not a proven index root or traversal
target.

### `export <INPUT.QBW> <OUTPUT.SQLITE>`

```console
$ openqbw export mybooks.qbw books.sqlite
```

Writes a SQLite database containing catalog and legacy discovery results. The
output is deterministic for the same input, but is not a reconciled accounting
export.

### `migrate <INPUT.QBW> --out <PATH> [--format csv|sqlite|iif]`

```console
$ openqbw migrate mybooks.qbw --out books.sqlite --format sqlite
$ openqbw migrate mybooks.qbw --out out_csv     --format csv
$ openqbw migrate mybooks.qbw --out books.iif   --format iif
```

Data-liberation export with three target formats:

- `csv` (default): writes `catalog.csv`, `transactions.csv`,
  and `lineitems.csv` into the directory given by `--out`
  (created if missing). Fields are RFC 4180 quoted only when
  needed.
- `sqlite`: alias for `export --out <PATH>`. Single
  deterministic SQLite database.
- `iif`: writes a single Intuit Interchange Format file with
  CRLF line endings. Line items are grouped by their parent
  invoice id; each group becomes one `TRNS` followed by `SPL`
  rows and an `ENDTRNS`. When a matching transaction header is
  available the header's transaction type is used, otherwise the
  group is emitted as `GENERAL JOURNAL`. SPL amounts are negated
  per IIF's double-entry convention.

### `forensics`

```console
$ openqbw forensics mybooks.qbw
```

File-level discovery report covering:

- File and page-store stats (size, page count, AP learned
  block coverage).
- Catalog summary (total tables, user tables).
- Business-record summary (transaction headers, line items,
  distinct parent ids, orphan parents, childless headers,
  lineitem grand total).

A non-zero orphan-parent count is a discovery signal: the file
may contain partially purged records or a header table this
build does not parse yet.

### `verify`

```console
$ openqbw verify mybooks.qbw
```

Runs legacy/sample-oriented regression invariants:

- Invoice grand-total reconciliation (Phase 5)
- Legacy position-attribution diagnostics
- SYSINDEX candidate comparison

Exit code is non-zero if any invariant fails.

### `validate-attribution`

```console
$ openqbw validate-attribution mybooks.qbw
```

Runs a legacy diagnostic comparison between position-based page attribution and
SYSCOLUMN-derived width bands. It does not establish Enterprise 24 table
ownership.

### `fkgraph`

```console
$ openqbw fkgraph mybooks.qbw
```

Falls back to a name-heuristic FK graph (`*_id`, `*_id_h`) for
files where SYSINDEX is unparseable. Superseded by `indexes`
when SYSINDEX is available.

### `nulls`

```console
$ openqbw nulls mybooks.qbw
```

Counts recovered `SYSCOLUMN.nulls` N/Y values with sample column names.
`N` means the catalog says NULL values are not allowed and `Y` means they are
allowed. This is catalog metadata; it does not yet prove the physical null
bitmap layout of Enterprise 24 user rows.

### Research-oracle commands (research feature only)

`inspect-sdk-oracle-manifest`, `normalize-sdk-oracle`, and `fixture-audit`
support controlled, local acceptance research. They are not a QBW extractor:
the first reads only a privacy-safe manifest, the second consumes already
collected local QBXML files to create ignored local TSV fixtures, and the third
checks private report inputs for local decoder acceptance. None
invokes QuickBooks, the Desktop SDK, COM, ODBC, or a GUI session at runtime.

### `accounting-report <INPUT.QBW>`

```console
$ openqbw accounting-report SAMPLE_COMPANY.qbw --report trial-balance \
    --as-of 2026-12-31 --fiscal-year-start 2026-01-01 \
    --retained-earnings-account-id ACCOUNT_ID \
    --retained-earnings-report-name "Retained Earnings" \
    --entity-id SAMPLE_ENTITY --source-label local-copy \
    --generated-at 2026-12-31T00:00:00Z --snapshot-id SNAPSHOT_ID \
    --format json --out trial-balance.json

$ openqbw accounting-report SAMPLE_COMPANY.qbw --report general-ledger \
    --as-of 2026-12-31 --entity-id SAMPLE_ENTITY --source-label local-copy \
    --generated-at 2026-12-31T00:00:00Z --snapshot-id SNAPSHOT_ID \
    --format sqlite --out general-ledger.sqlite
```

Writes a new CSV, JSON, or SQLite report; it refuses to overwrite the output.
For an accrual Trial Balance, `--fiscal-year-start` and
`--retained-earnings-account-id` are required. The optional
`--retained-earnings-report-name` changes only native-report presentation; it
does not modify the decoded chart. Account numbers retain QuickBooks'
inherited-display behavior.

Every Trial Balance and General Ledger output includes both `account_type` and
`quickbooks_classification`. `account_type` is the normalized reporting group;
`quickbooks_classification` preserves the calibrated source classification
(for example `Bank`, `AccountsPayable`, `CostOfGoodsSold`, or `OtherIncome`).
The latter is nullable for a non-source-specific generic account API value;
an uncalibrated materialized discriminator is rejected before production
accounting output is created. CSV and JSON carry it per account/entry; SQLite
stores it in `accounts.quickbooks_classification`.

### `reconcile-qbw-trial-balance`

```console
$ openqbw reconcile-qbw-trial-balance --qbw SAMPLE_COMPANY.qbw \
    --native-tb native-trial-balance.csv --as-of 2026-12-31 \
    --fiscal-year-start 2026-01-01 \
    --retained-earnings-account-id ACCOUNT_ID --snapshot-id SNAPSHOT_ID
```

Builds the direct QBW accrual Trial Balance and compares it account-by-account
and cent-by-cent with the supplied native QuickBooks CSV. It exits nonzero for
an unbalanced input, unsupported decoding condition, missing/extra account,
or any variance.

### `reconcile-qbw-general-ledger`

```console
$ openqbw reconcile-qbw-general-ledger --qbw SAMPLE_COMPANY.qbw \
    --native-gl native-general-ledger.csv --from 2026-01-01 \
    --through 2026-12-31 --snapshot-id SNAPSHOT_ID
```

Builds a direct-QBW General Ledger through `--through`, filters the inclusive
`--from`/`--through` range, resolves native account sections against the
complete decoded chart, and compares the dated debit/credit posting multiset.
It exits nonzero on an unsupported decode, unresolved/ambiguous account
section, or missing/extra movement. Transaction type and number are reported
as unavailable rather than guessed until their physical fields are separately
established.

### `batch-extract <INPUTS...> [--workers N]`

```console
$ openqbw batch-extract copy-a.qbw copy-b.qbw --workers 2
```

Emits one deterministic JSON result per input, including a local snapshot hash
and an isolated input error where applicable. Each worker reads its input once
so a later path change cannot race the decode. It is an inspection/snapshot
command; use `batch-trial-balance` for accounting output.

### `batch-trial-balance`

```console
$ openqbw batch-trial-balance --manifest private-inputs.csv \
    --as-of 2026-12-31 --workers 2 \
    --generated-at 2026-12-31T00:00:00Z --out consolidated.sqlite
```

The private local CSV manifest has exactly these headers:

```text
entity_id,qbw_path,snapshot_id,fiscal_year_start,retained_earnings_account_id,retained_earnings_report_name
```

Every input must pass the same direct decoder validation. The operation is
all-or-nothing and never overwrites `--out`. Do not commit manifests, QBWs,
native reports, snapshot identifiers, or extracted output.

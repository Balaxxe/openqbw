# Migration guide: leaving QuickBooks Desktop

This guide describes the supported accounting-extraction workflow. The direct
path is limited to the validated Enterprise 24 R21 schema manifest and its
known row layouts/families; it fails closed outside that boundary.

## Step 1: Make a backup

Copy the `.qbw` file to a working directory. OpenQBW is read-only,
but it's good practice:

```console
$ cp mybooks.qbw mybooks.qbw.bak
```

## Step 2: Inventory what is in the file

```console
$ openqbw catalog mybooks.qbw
```

This prints every user table. Look for the ones you care about:

- `abmc_*_header` -- transaction headers (invoices, bills, payments)
- `abmc_*_*line*` -- line items
- Customer, vendor, item, and account lists also live in `abmc_*`
  tables.

## Step 3: Create supported accounting reports

Use a local read-only copy and explicit accounting policy inputs. The retained
earnings account identifier is required because automatic company-preference
discovery is not yet implemented.

| Format | Current status |
|--------|----------------|
| SQLite | Supported Trial Balance or General Ledger output |
| CSV | Supported Trial Balance or General Ledger output |
| JSON | Supported Trial Balance or General Ledger output |
| IIF | Legacy diagnostic output only; do not import as books |

## Step 4: Reconcile each Trial Balance

```console
$ openqbw reconcile-qbw-trial-balance --qbw SAMPLE_COMPANY.qbw \
    --native-tb native-trial-balance.csv --as-of 2026-12-31 \
    --fiscal-year-start 2026-01-01 \
    --retained-earnings-account-id ACCOUNT_ID --snapshot-id SNAPSHOT_ID
```

## Step 5: Verify scope before downstream use

Exact Trial Balance reconciliation establishes the supported accrual report
for that local snapshot and policy. It is not evidence that cash-basis reports,
other QuickBooks versions, vendor/customer extraction, company-preference
discovery, or a multi-company consolidated report are supported.

For movement-level validation, use the corresponding inclusive-date General
Ledger reconciliation:

```console
$ openqbw reconcile-qbw-general-ledger --qbw SAMPLE_COMPANY.qbw \
    --native-gl native-general-ledger.csv --from 2026-01-01 \
    --through 2026-12-31 --snapshot-id SNAPSHOT_ID
```

## Mapping notes

- Catalog rows retain their physical provenance and bounded field values.
- SYSINDEX page-shaped values are diagnostic candidates, not proven foreign-key
  or page-navigation pointers.
- Current-record and lifecycle evidence is enforced for supported posting
  families; unrecognized states fail closed.
- Output retains normalized `account_type` and calibrated source-level
  `quickbooks_classification`; do not replace the latter with a name heuristic.

## Decoder-contract migration note

The Rust `DecodedPostings` boundary now accepts `PostingDisposition` values.
Pass a normal non-zero `Posting` as before (it converts automatically), but
represent a proven physical non-posting row with `PostingExclusion` and one of
the closed `PostingExclusionReason` values.  This is required for source/link
rows, deletion tombstones, and a decoder-proven canonical-zero void row.

`CompleteCoverage::new(recognized, handled)` now counts both normalized
postings and these explicit exclusions.  The ledger still receives only
non-zero postings, so a zero-amount `Posting` is rejected rather than silently
treated as an exclusion.  Non-zero superseded rows remain normal `Posting`
values with `CurrentState::Superseded` and are retained for auditability.

Do not put actual company names, customer/vendor data, row locators, report
values, or QBW artifacts in commits, tests, examples, issues, or pull requests.
Use synthetic identifiers and amounts when documenting validation.

## Account activity in normalized reports

An account can now be `active`, `inactive`, or `unknown`.  `unknown` means
the decoder identified the account but did not prove its current QuickBooks
activity state; it does not mean inactive and does not change account or
posting selection.

CSV retains its prior `active` column, leaving it blank for an unknown value,
and adds the authoritative `activity` column. JSON emits `"active": null`
and `"activity":"unknown"`. SQLite retains `accounts.active` as a nullable
integer and adds `accounts.activity`; existing two-valued databases are
migrated atomically with their historical values preserved.

## Limitations

- Password-protected files: structural metadata only; row content
  remains obfuscated until QuickBooks decrypts it on open.
- Multi-user (.QBX, .QBA) files: not yet supported.
- Cash-basis reports, other QuickBooks versions, automatic company preference
  and Retained Earnings-label discovery, VSS/snapshot automation, and
  consolidation are not yet supported.

If you hit a limitation, please open an issue with the file
size, QB version, and the failing command. **Do not attach the
file -- attach the redacted output only.**

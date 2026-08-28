# Format overview

This is a high-level orientation map. The detailed specification
is in [SPECIFICATION.md](./specification.md), and the empirical
notebook is in [re/NOTES.md](https://github.com/Sigilweaver/OpenQBW/blob/main/re/NOTES.md).

## Three layers

A `.qbw` file is an onion:

```
+-------------------------------------------+
|  QuickBooks business layer                |
|  Accounts + five R21 posting families     |
|  -> normalized Ledger -> TB / GL          |
+-------------------------------------------+
|  SA17 page-store catalog                  |
|  (SYSTABLE, SYSCOLUMN, SYSINDEX, ...)     |
|  -- parsed by `openqbw` crate             |
+-------------------------------------------+
|  SA17 raw page store + AP obfuscation     |
|  (4096-byte pages, slot directories)      |
|  -- parsed by `opensqlany` crate          |
+-------------------------------------------+
```

## Layer 1: raw page store

Provided by [OpenSQLAnywhere](https://github.com/Sigilweaver/OpenSQLAnywhere).
The file is divided into 4096-byte pages. Each page has a trailer
at offset 0xFF0..0xFFF that includes a CRC and a one-byte page
type (`A` alloc, `E` extent, `C` catalog, `I` index, ...).

QuickBooks applies an **additive-progression cipher** on top: the
plaintext page byte at offset `i` in block `b` is `obfuscated[i]
- ap_table[b][i]`. The `ApModel` in `opensqlany` learns the
per-block additive table from the known-plaintext trailer.

## Layer 2: SA17 catalog

SQL Anywhere uses on-page system tables (SYSTABLE, SYSCOLUMN,
SYSINDEX, SYSOBJECT) instead of a separate metadata file. OpenQBW recovers
bounded physical catalog rows and uses their verified table/object joins as
diagnostic metadata.

Enterprise 24 revalidation showed that the SYSINDEX page-shaped field can
target allocation pages and can be confused with bytes inside QBID values. It
is exposed only as a `catalog_page_candidate`; it does not validate index
ownership, page attribution, or B-tree navigation.

## Layer 3: QuickBooks business layer

QuickBooks business rows are materialized and then checked against the
Enterprise 24 R21 catalog manifest. OpenQBW supports Account rows and five
physical posting families: Bill (which also carries the VendorCredit view),
Bill-Payment Check, Check, Deposit, and General Journal. Validated rows enter
a normalized, balanced Ledger; it produces an accrual Trial Balance with an
explicit fiscal-year/Retained-Earnings policy, or a General Ledger through an
ISO as-of date.

This is deliberately a narrow compatibility contract. A non-matching catalog,
unattested row layout, unrecognized row lifecycle, or unknown posting family
is an error, not a best-effort accounting result. Account-number presentation
uses inherited display semantics. Cash basis and automatic discovery of
company preferences or a native Retained Earnings report label remain future
work.

Each normalized account carries two classifications: `account_type` is the
reporting group (asset, liability, equity, income, COGS, or expense), while
`quickbooks_classification` retains the calibrated QuickBooks source class
(such as `Bank`, `AccountsPayable`, `OtherAsset`, or `OtherExpense`). This
source class is emitted in CSV, JSON, and SQLite and supports strict native
General Ledger section resolution without name or amount guessing.

## Where to read the code

- `crates/openqbw/src/lib.rs` -- top-level re-exports
- `crates/openqbw/src/accounting.rs` -- normalized accounting/reporting core
- `crates/openqbw/src/opaque_page_tuples.rs` -- bounded diagnostic scanner for
  an unproven page-like tuple relation; it does not attribute table pages
- `crates/openqbw/src/row_scan.rs` -- provenance-preserving row discovery
- `crates/openqbw/src/sysindex.rs` -- index catalog
- `crates/openqbw-cli/src/main.rs` -- the CLI front-end

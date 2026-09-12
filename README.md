# OpenQBW

[![CI](https://github.com/Sigilweaver/OpenQBW/actions/workflows/ci.yml/badge.svg)](https://github.com/Sigilweaver/OpenQBW/actions/workflows/ci.yml)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20470597.svg)](https://doi.org/10.5281/zenodo.20470597)
[![crates.io](https://img.shields.io/crates/v/openqbw.svg)](https://crates.io/crates/openqbw)
[![PyPI](https://img.shields.io/pypi/v/openqbw.svg)](https://pypi.org/project/openqbw/)
[![docs.rs](https://img.shields.io/docsrs/openqbw)](https://docs.rs/openqbw)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust MSRV](https://img.shields.io/badge/rust-1.95%2B-orange.svg)](https://www.rust-lang.org)
[![Docs](https://img.shields.io/badge/docs-sigilweaver.app-blue.svg)](https://sigilweaver.app/openqbw/docs/)

> Open specification and open-source parser for the **QuickBooks Desktop company file** (`.qbw`) format.

QuickBooks company files often need to remain accessible long after the
original workstation, installation, or subscription changes. OpenQBW
documents the on-disk format and ships a read-only Rust parser so lawful
owners can keep independent access to accounting data they already own.

## Status

OpenQBW now contains a direct, read-only accounting path for the validated
QuickBooks Desktop Enterprise 24 R21 schema manifest. It extracts the Chart
of Accounts and normalized posting ledger from a local QBW copy, then emits
an accrual Trial Balance or General Ledger in CSV, JSON, or SQLite. The same
ledger also produces accrual Profit & Loss and Balance Sheet reports. The
extractor fails closed when the catalog/schema, materialized-row layout, or
posting family is outside its evidence-bound support.

The production path is:

```text
OpenSQLAnywhere: SA17 page store and page materialization
        -> OpenQBW: bounded SYSTABLE/SYSCOLUMN catalog + R21 manifest
        -> Accounts + five physical posting families
           (Bill / VendorCredit view, Bill-Payment Check, Check, Deposit,
            General Journal)
        -> normalized Ledger
        -> accrual Trial Balance / General Ledger / Profit & Loss / Balance Sheet
        -> CSV, JSON, SQLite, reconciliation, and parallel batch output
```

Account display preserves QuickBooks' inherited account-number semantics; it
does not invent a number for a child account. The accrued Trial Balance uses
an explicitly supplied fiscal-year start and retained-earnings `AccountId`.
An optional retained-earnings report name is presentation-only, for native
report labels that differ from the chart name.

Private acceptance has reconciled the supported path exactly to native
QuickBooks reports at three as-of dates, with all visible accounts and
zero-cent variance. That evidence is aggregate-only: no company names,
dates, paths, row counts, report values, or hashes are published.
The same release gate covers three General Ledger date ranges and verifies
that the local QBW content hash is unchanged. See the
[accounting acceptance protocol](docs/docs/accounting-acceptance.md).

### Supported matrix

| Input / capability | Status |
| --- | --- |
| Enterprise 24 R21 schema-manifest match | Supported, direct read-only extraction |
| Accounts and five posting families above | Supported subject to row-level validation |
| Accrual Trial Balance and General Ledger | Supported with explicit report policy inputs |
| Accrual Profit & Loss and Balance Sheet | Derived from validated GL/TB; explicit period/fiscal policy |
| CSV, JSON, SQLite, exact TB reconciliation, batch TB | Supported |
| Other QB versions, unknown schemas/layouts/families | Rejected fail-closed |
| Cash-basis reports; automatic company-preference or RE-label discovery | Not yet supported |
| Snapshot/VSS orchestration and consolidated operations | Future work |

The detailed physical-format work remains in [SPECIFICATION.md](SPECIFICATION.md).
Research-only commands are compiled only with `--features research-tools`; the
feature is off by default and its local inputs and outputs are never part of
the public repository.

## Non-goals

- Shipping, linking, or distributing any Intuit code or trademarks.
- Breaking passwords or DRM. OpenQBW targets the on-disk layout of
  company files that the lawful owner can already open.
- Writing `.qbw` files. OpenQBW is **read-only**.
- Requiring QuickBooks, its Desktop SDK, COM, ODBC, or a GUI session at runtime.

## Use cases

- **Data liberation for users leaving the QuickBooks Desktop ecosystem.**
  Export your transactions to CSV, SQLite, or IIF so you can move
  them to another accounting package, or just keep an offline copy
  for the legally required retention period after the SaaS subscription
  lapses.
- **Forensic accounting and litigation support.** Read a `.qbw` file
  without owning a QuickBooks license, including offline copies on
  machines where the QB application has been uninstalled.
- **Audit and discovery.** Inventory tables, indexes, row counts,
  and surface gaps that suggest deleted records or schema drift.
- **Long-term archival.** Keep an open-format snapshot of the books
  every fiscal year, independent of Intuit's product roadmap.

## Install

OpenQBW depends on the [OpenSQLAnywhere](https://github.com/Sigilweaver/OpenSQLAnywhere)
crate, which lives in a sibling directory via a relative path. Clone
both side by side:

```console
$ git clone https://github.com/Sigilweaver/OpenSQLAnywhere.git
$ git clone https://github.com/Sigilweaver/OpenQBW.git
$ cd OpenQBW
$ cargo build --release
$ ./target/release/openqbw --help
```

Rust 1.95+ is required (workspace uses edition 2024).

### Python bindings

A PyO3-based extension lives in `crates/openqbw-py` and ships as a
package named `openqbw`. To build and install into the active Python
environment:

```console
$ pip install maturin
$ cd crates/openqbw-py
$ maturin develop --release
$ python -c "import openqbw; r = openqbw.open('mybooks.qbw'); print(r.page_count, 'pages')"
```

See [crates/openqbw-py/README.md](crates/openqbw-py/README.md) for the
full Python API.

## CLI quickstart

```console
# Write an accrual Trial Balance from a local copy. Outputs never overwrite.
$ openqbw accounting-report SAMPLE_COMPANY.qbw \
    --report trial-balance --as-of 2026-12-31 \
    --fiscal-year-start 2026-01-01 \
    --retained-earnings-account-id ACCOUNT_ID \
    --retained-earnings-report-name "Retained Earnings" \
    --entity-id SAMPLE_ENTITY --source-label local-copy \
    --generated-at 2026-12-31T00:00:00Z --snapshot-id SNAPSHOT_ID \
    --format csv --out trial-balance.csv

# Reconcile the direct QBW result with a native QuickBooks Trial Balance CSV.
$ openqbw reconcile-qbw-trial-balance --qbw SAMPLE_COMPANY.qbw \
    --native-tb native-trial-balance.csv --as-of 2026-12-31 \
    --fiscal-year-start 2026-01-01 \
    --retained-earnings-account-id ACCOUNT_ID --snapshot-id SNAPSHOT_ID

# Reconcile dated debit/credit movements in a General Ledger range.
$ openqbw reconcile-qbw-general-ledger --qbw SAMPLE_COMPANY.qbw \
    --native-gl native-general-ledger.csv --from 2026-01-01 \
    --through 2026-12-31 --snapshot-id SNAPSHOT_ID

# General Ledger and non-destructive catalog diagnostics are also available.
$ openqbw accounting-report SAMPLE_COMPANY.qbw --report general-ledger \
    --as-of 2026-12-31 --entity-id SAMPLE_ENTITY --source-label local-copy \
    --generated-at 2026-12-31T00:00:00Z --snapshot-id SNAPSHOT_ID \
    --format sqlite --out general-ledger.sqlite
$ openqbw catalog SAMPLE_COMPANY.qbw
```

See [docs/CLI reference](docs/docs/cli.md) for the full subcommand reference.
See [derived statements](docs/docs/derived-financial-statements.md) for P&L,
Balance Sheet, their acceptance checks, and their output schema.

## Library usage

```rust,no_run
use openqbw::iter_systable_entries;
use opensqlany::{ApModel, PageStore};

let store = PageStore::open("mybooks.qbw")?;
let model = ApModel::learn(&store);
for table in iter_systable_entries(&store, &model) {
    println!("{} {}", table.table_id, table.name);
}
# Ok::<(), anyhow::Error>(())
```

## Documentation

- [SPECIFICATION.md](SPECIFICATION.md) - physical format specification and scope
- [docs/use-cases.md](docs/use-cases.md) - extended use-case walkthroughs
- [docs/migration-guide.md](docs/migration-guide.md) - leaving the QuickBooks ecosystem
- [docs/format-overview.md](docs/format-overview.md) - high-level pointer into the spec
- [docs/cli.md](docs/cli.md) - full CLI reference

## Handoff

The source projects remain separate under Balaxxe: OpenQBW owns QuickBooks
schemas and accounting extraction, while OpenSQLAnywhere owns generic SQL
Anywhere storage decoding. A future private operational repository,
`Deen-Media/qbw-direct`, can pin and compose them for multi-entity workflows;
it is not a replacement for either source project.

## Legal and ethical

- **No raw corpus repository is published.** During corpus collection
  we found that several public GitHub repositories had accidentally
  committed real business financial data, including personal names,
  home addresses, phone numbers, and US Social Security / tax
  identification numbers. Affected repository owners have been
  contacted directly. Out of caution the full downloaded corpus is
  kept private and is not redistributed.
- QuickBooks(R) is a registered trademark of Intuit Inc. OpenQBW is
  an independent project and is not affiliated with, endorsed by, or
  sponsored by Intuit Inc.
- License: [Apache-2.0](LICENSE). See also [NOTICE](NOTICE) and
  [CONTRIBUTING.md](CONTRIBUTING.md).

## Companion projects

- **[OpenSQLAnywhere](https://github.com/Sigilweaver/OpenSQLAnywhere)** --
  the lower-level SA17 page-store reader OpenQBW depends on.

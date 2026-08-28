---
title: Introduction
sidebar_label: Intro
slug: /
---

# OpenQBW

**Pure-Rust reader and open specification for Intuit QuickBooks
Desktop `.QBW` company files.**

OpenQBW is a clean-room project. It is derived from observation of
the on-disk bytes of `.QBW` files and from public documentation
of the underlying database engine. It ships with no Intuit or SAP
code or binaries.

## Why

QuickBooks company files may need to remain accessible independently of a
particular workstation, installation, subscription, or product lifecycle.
Companies that have kept books in QuickBooks Desktop for decades
need a way to migrate that data to other accounting products, or
just to preserve it in an open format, **without** depending on
the QuickBooks Desktop application continuing to install and run.

OpenQBW reads the `.QBW` file directly. It is read-only and its production
architecture does not require QuickBooks, the Desktop SDK, COM, ODBC, or a GUI
session.

## What you can do today

- Open a `.QBW` file with no QuickBooks installed.
- Enumerate user tables via the `SYSTABLE` catalog.
- Parse `SYSCOLUMN`, `SYSINDEX`, `SYSOBJECT`.
- Inspect bounded physical catalog rows and legacy discovery diagnostics.
- Directly extract validated Accounts and normalized postings from a local
  Enterprise 24 R21 QBW copy.
- Produce a General Ledger or an accrual Trial Balance as CSV, JSON, or
  SQLite, and reconcile the latter to a native QuickBooks CSV exactly.
- Process independent local copies in parallel through a private batch
  manifest.

The production decoder is version- and layout-bound. It supports only the
validated Enterprise 24 R21 catalog manifest and five physical posting
families: Bill (including the VendorCredit view), Bill-Payment Check, Check,
Deposit, and General Journal. Any unknown schema, row layout, or family is
rejected rather than guessed.

## How it stacks

```
.QBW file
   |
   v
 OpenQBW                 (catalog + R21 accounts/postings + Ledger/reports)
   |
   v
 OpenSQLAnywhere         (SA17 page store + AP deobfuscation primitive)
```

`OpenSQLAnywhere` is the companion project; see
[https://sigilweaver.app/opensqlanywhere/docs/](https://sigilweaver.app/opensqlanywhere/docs/).

The direct path is read-only and has no runtime QuickBooks, Desktop SDK, COM,
ODBC, or GUI dependency. Use only local copies of company files.

## Get started

- [Install](./install.md)
- [CLI quickstart](./quickstart-cli.md)
- [Rust quickstart](./quickstart-rust.md)
- [Python quickstart](./quickstart-python.md)
- [Migration guide](./migration-guide.md) - the recommended path
  for accountants and end users

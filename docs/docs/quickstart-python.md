---
title: Python quickstart
sidebar_label: Python quickstart
---

# Python quickstart

```python
import openqbw

company = openqbw.open("Company.QBW")

for table in company.tables():
    print(table["table_id"], table["name"], table["row_count"])
```

The Python wheel is an `abi3-py39` build of the same Rust code that
backs the CLI. Its currently exposed Python surface remains catalog and legacy
discovery diagnostics. Use the CLI for the supported Enterprise 24 R21 Trial
Balance and General Ledger workflow.

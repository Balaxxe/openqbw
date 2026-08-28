---
title: Rust quickstart
sidebar_label: Rust quickstart
---

# Rust quickstart

```rust
use openqbw::iter_systable_entries;
use opensqlany::{ApModel, PageStore};

fn main() -> Result<(), opensqlany::Error> {
    let store = PageStore::open("Company.QBW")?;
    let model = ApModel::learn(&store);

    for table in iter_systable_entries(&store, &model) {
        println!("{:>4} rows  {}", table.row_count, table.name);
    }
    Ok(())
}
```

The example peels the additive-progression obfuscation layer
(via `opensqlany::ApModel`), then walks the underlying SA17 page
store and exposes bounded catalog primitives. The production accounting API
adds an evidence-bound Enterprise 24 R21 Account/posting pipeline; use the CLI
for its complete report-policy, serialization, and reconciliation workflow.

# openqbw (Python)

Python bindings for [OpenQBW](https://github.com/Sigilweaver/OpenQBW), a
read-only parser for QuickBooks `.qbw` files. Its Python API currently exposes
catalog and legacy discovery diagnostics for forensic/research workflows. The
supported Enterprise 24 R21 accounting extractor is available through the
parent project's CLI; it is not yet exposed as a Python API.

> Prototype-quality Python surface. See the parent repository's `README.md`
> and `SPECIFICATION.md` for the supported CLI compatibility boundary.

## Install (from source)

```bash
pip install maturin
cd OpenQBW/crates/openqbw-py
maturin develop --release
```

This builds the extension and installs it into the active Python
environment.

## Quick start

```python
import openqbw

r = openqbw.open("/path/to/file.qbw")
print(r.page_count, "pages,", r.file_size, "bytes")

for t in r.tables()[:5]:
    print(t["table_id"], t["name"])

for li in r.line_items()[:3]:
    print(li["invoice_id"], li["amount_cents"], li["source_table"])

for h in r.transactions()[:3]:
    print(h["qb_id"], h["txn_type"])
```

## API

`openqbw.open(path) -> Reader`

`Reader` attributes:
- `path`, `page_count`, `file_size`

`Reader` methods (each returns a list of dicts):
- `tables()` - SYSTABLE catalog rows
- `indexes()` - SYSINDEX entries
- `line_items()` - legacy invoice-line discovery results (not accounting output)
- `transactions()` - legacy transaction-header discovery results (not accounting output)

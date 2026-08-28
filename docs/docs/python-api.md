# Python API reference

The `openqbw` wheel is a PyO3 extension built from the same Rust core
that backs the CLI. It exposes a small, read-only diagnostic surface: open a
file, then pull recovered catalog/index rows and legacy discovery results as
lists of dicts. The supported Enterprise 24 R21 Trial Balance and General
Ledger workflow is currently CLI-only.

```python
import openqbw

r = openqbw.open("/path/to/file.qbw")
print(r.page_count, "pages,", r.file_size, "bytes")
```

## `openqbw.open(path) -> Reader`

Opens a `.qbw` file, decodes the page store, and learns the additive-
progression model. Raises `OSError` if the file cannot be opened.

## `Reader`

| Member | Type | Description |
|---|---|---|
| `path` | `str` | The filesystem path the reader was opened from. |
| `page_count` | `int` | Number of pages in the underlying page-store. |
| `file_size` | `int` | File size in bytes. |
| `tables()` | `list[dict]` | SYSTABLE catalog rows. |
| `indexes()` | `list[dict]` | SYSINDEX entries. |
| `line_items()` | `list[dict]` | Legacy invoice-line discovery results; not Enterprise 24 accounting output. |
| `transactions()` | `list[dict]` | Legacy transaction-header discovery results; not Enterprise 24 accounting output. |

### `tables()`

Each dict has `table_id`, `object_id`, `name`, `row_count`,
`table_page_count`, `ext_page_count`, `row_length`, `row_flags`, and
`page_number`. Legacy compatibility keys `col_count`, `data_root_page`, and
`last_page` may also be present, but are not decoded Enterprise 24 fields and
must not be used as roots or page-navigation pointers.

```python
for t in r.tables()[:5]:
    print(t["table_id"], t["name"])
```

### `indexes()`

Each dict has `name`, `owner_object_id`, optionally resolved `table_id` and
`table_name`, `catalog_page_candidate`, and `page_number`. The page candidate
is diagnostic metadata only: it is not a proven index root, ownership pointer,
or navigation target.

```python
for idx in r.indexes()[:5]:
    print(idx["name"], idx["table_id"])
```

### `line_items()`

Each dict has `invoice_id`, `item_qb_id`, `amount_cents`,
`amount_cents_signed`, `txn_date_days_since_unix`, `source_table`,
`page_number`, `page_offset`.

```python
for li in r.line_items()[:3]:
    print(li["invoice_id"], li["amount_cents"], li["source_table"])
```

### `transactions()`

Each dict has `qb_id`, `source_table`, `txn_type`, `page_number`,
`page_offset`.

```python
for h in r.transactions()[:3]:
    print(h["qb_id"], h["txn_type"])
```

## Next

- [Python quickstart](./quickstart-python)
- [CLI reference](./cli)
- [Format specification](./specification)

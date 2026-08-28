# `qbci32` sparse `drec` codec

`openqbw::parse_drec` and `openqbw::encode_drec` implement only the proven,
descriptor-directed record-body grammar used by the `qbci32` CIndex side path:

```text
flag:u8 (ordinal:u16 payload)* FFFF:u16
```

The caller selects the ordinal byte order; it also controls the established
fixed-width scalar payloads. Ordinals are strictly increasing, and encoding is
deterministic descriptor-order output. The caller supplies a descriptor array
addressed by zero-based ordinal and terminated by one final `E` entry.

Only `S`, `B`, `F`, `I`, `L`, `H`, `U`, `M`, and `Z` are accepted: `S` has a
bounded NUL terminator, `B` uses the descriptor length, `F`/`I`/`L` have four
bytes, `H`/`U` two bytes, `M` is `QuickBooksLegacyBalance`'s six-byte envelope,
and `Z` is nine opaque bytes. `D` is rejected because its pointer-sized width
is not a portable, established on-disk property. The current Targ descriptor
normalization path is not sufficiently resolved for this codec to accept a
putative four-byte `H` field.

The decoded record keeps exact record-relative field/payload ranges. Omitted
ordinals remain omitted; an explicit default can only be materialized from the
caller schema. Both parsing and encoding enforce the proven `0x7530`-byte
builder bound. This codec does not discover physical records, identify the
applicable descriptor table, determine current state, or decode accounts and
postings. It is a safe primitive, not a QBW scanning or reporting feature.

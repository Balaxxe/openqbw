//! Fail-closed parser for one bounded materialized transaction-master row.
//!
//! This is deliberately a structural research parser, not a QuickBooks
//! transaction or posting decoder.  It accepts only the materialized segment
//! dialect witnessed by the controlled stage-09 voided Check capture.  In
//! particular, it does not assign account, date, amount, debit/credit,
//! current-state, ownership, continuation, or posting semantics.

use std::str;

/// Expected flags for the bounded materialized master-row witness.
pub const MATERIALIZED_MASTER_FLAGS: u8 = 0x40;
/// Expected kind byte for the bounded materialized master-row witness.
pub const MATERIALIZED_MASTER_KIND: u8 = 0x02;

const FIXED_HEADER_LEN: usize = 0x16;
const OPAQUE_TOKEN_OFFSET: usize = 0x16;
const DOCUMENT_REFERENCE_OFFSET: usize = 0x37;
const VOID_MEMO_WITNESS_OFFSET: usize = 0x83;

/// One bounded materialized transaction-master row.
///
/// The field names intentionally describe representation rather than
/// accounting semantics.  The only identifier assignment is the controlled
/// witness that `master_record_number` matches the hexadecimal first component
/// of the external transaction ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedTransactionMasterRow {
    /// Validated segment length, read as little-endian `u16`.
    pub declared_len: usize,
    /// The validated, but otherwise uninterpreted, segment flags.
    pub flags: u8,
    /// The validated materialized-row kind byte (`0x02`).
    pub kind: u8,
    /// Controlled-witness transaction-master record number at byte `+0x08`.
    pub master_record_number: u32,
    /// Adjacent `u32le` at byte `+0x0c`, retained without link semantics.
    pub adjacent_record_number: u32,
    /// Opaque `u16le` value at byte `+0x14`.
    pub opaque_type: u16,
    /// Optional byte string framed by the witnessed length byte at `+0x16`.
    ///
    /// This is not an account, ListID, or owner field.
    pub opaque_token: Option<Vec<u8>>,
    /// Optional UTF-8 document/reference text framed at the fixed `+0x37`
    /// witness location.
    pub document_reference: Option<String>,
    /// Optional exact `VOID: ` text witness at `+0x83`.
    ///
    /// A value here is not a decoded current-state field.  Non-void text at
    /// the same offset is intentionally not exposed because the r1 evidence
    /// does not establish a generic memo-field grammar.
    pub void_memo_witness: Option<String>,
}

/// Rejection reasons for [`parse_materialized_transaction_master_row`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaterializedTransactionMasterRowError {
    /// Fewer than the fixed header bytes were supplied.
    TooShort {
        /// Bytes supplied by the caller.
        actual: usize,
        /// Minimum fixed header size required by this parser.
        minimum: usize,
    },
    /// The self-declared segment length did not exactly bound the input.
    DeclaredLengthMismatch {
        /// Segment length read from the leading little-endian u16.
        declared: usize,
        /// Exact number of input bytes supplied by the caller.
        actual: usize,
    },
    /// The segment did not carry the one bounded-witness flags value.
    UnexpectedFlags {
        /// Flags byte observed at offset `+0x02`.
        actual: u8,
    },
    /// The segment did not carry materialized master kind `0x02`.
    UnexpectedKind {
        /// Kind byte observed at offset `+0x03`.
        actual: u8,
    },
    /// A validated fixed-location length prefix exceeded the segment.
    LengthPrefixedFieldOutOfBounds {
        /// Structural field label.
        field: &'static str,
        /// Fixed byte offset of the length prefix.
        offset: usize,
        /// Length declared by that byte.
        declared: usize,
        /// Segment length that was validated before parsing the field.
        segment_len: usize,
    },
    /// The fixed-location document/reference bytes were not UTF-8.
    DocumentReferenceNotUtf8,
}

impl std::fmt::Display for MaterializedTransactionMasterRowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { actual, minimum } => {
                write!(
                    f,
                    "materialized master row had {actual} bytes, needs {minimum}"
                )
            }
            Self::DeclaredLengthMismatch { declared, actual } => write!(
                f,
                "materialized master row declared {declared} bytes but input had {actual}"
            ),
            Self::UnexpectedFlags { actual } => {
                write!(f, "materialized master row flags were 0x{actual:02x}")
            }
            Self::UnexpectedKind { actual } => {
                write!(f, "materialized master row kind was 0x{actual:02x}")
            }
            Self::LengthPrefixedFieldOutOfBounds {
                field,
                offset,
                declared,
                segment_len,
            } => write!(
                f,
                "materialized master row {field} at {offset:#x} declared {declared} bytes beyond {segment_len}"
            ),
            Self::DocumentReferenceNotUtf8 => {
                f.write_str("materialized master row document/reference was not UTF-8")
            }
        }
    }
}

impl std::error::Error for MaterializedTransactionMasterRowError {}

/// Parses one exactly bounded materialized master-row segment.
///
/// The input must start at the returned record boundary, not the page
/// directory prefix.  It is rejected unless its little-endian declared length
/// exactly equals `input.len()`, flags are `0x40`, and kind is `0x02`.
///
/// This parser is intentionally not generic.  It reads a document/reference
/// only from its one controlled-witness position; a void memo is emitted only
/// for the exact `VOID: ` witness framing.  All other trailing content remains
/// uninterpreted.
pub fn parse_materialized_transaction_master_row(
    input: &[u8],
) -> Result<MaterializedTransactionMasterRow, MaterializedTransactionMasterRowError> {
    if input.len() < FIXED_HEADER_LEN {
        return Err(MaterializedTransactionMasterRowError::TooShort {
            actual: input.len(),
            minimum: FIXED_HEADER_LEN,
        });
    }
    let declared_len = usize::from(u16::from_le_bytes([input[0], input[1]]));
    if declared_len != input.len() {
        return Err(
            MaterializedTransactionMasterRowError::DeclaredLengthMismatch {
                declared: declared_len,
                actual: input.len(),
            },
        );
    }
    if input[2] != MATERIALIZED_MASTER_FLAGS {
        return Err(MaterializedTransactionMasterRowError::UnexpectedFlags { actual: input[2] });
    }
    if input[3] != MATERIALIZED_MASTER_KIND {
        return Err(MaterializedTransactionMasterRowError::UnexpectedKind { actual: input[3] });
    }

    let opaque_token = parse_optional_bytes(input, OPAQUE_TOKEN_OFFSET, "opaque token")?;
    let document_reference =
        parse_optional_bytes(input, DOCUMENT_REFERENCE_OFFSET, "document/reference")?
            .map(|bytes| {
                str::from_utf8(&bytes)
                    .map(str::to_owned)
                    .map_err(|_| MaterializedTransactionMasterRowError::DocumentReferenceNotUtf8)
            })
            .transpose()?;

    // `+0x83` has one controlled void-memo witness, not a proven generic
    // sequential field grammar.  Only expose an exact void witness, and leave
    // every other byte pattern opaque.
    let void_memo_witness = parse_optional_bytes_if_bounded(input, VOID_MEMO_WITNESS_OFFSET)
        .and_then(|bytes| str::from_utf8(&bytes).ok().map(str::to_owned))
        .filter(|value| value.starts_with("VOID: "));

    Ok(MaterializedTransactionMasterRow {
        declared_len,
        flags: input[2],
        kind: input[3],
        master_record_number: u32::from_le_bytes(input[8..12].try_into().expect("fixed header")),
        adjacent_record_number: u32::from_le_bytes(input[12..16].try_into().expect("fixed header")),
        opaque_type: u16::from_le_bytes(input[20..22].try_into().expect("fixed header")),
        opaque_token,
        document_reference,
        void_memo_witness,
    })
}

fn parse_optional_bytes(
    input: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<Option<Vec<u8>>, MaterializedTransactionMasterRowError> {
    let Some(&length) = input.get(offset) else {
        return Ok(None);
    };
    let length = usize::from(length);
    let start = offset + 1;
    let Some(end) = start.checked_add(length) else {
        return Err(
            MaterializedTransactionMasterRowError::LengthPrefixedFieldOutOfBounds {
                field,
                offset,
                declared: length,
                segment_len: input.len(),
            },
        );
    };
    let bytes = input.get(start..end).ok_or(
        MaterializedTransactionMasterRowError::LengthPrefixedFieldOutOfBounds {
            field,
            offset,
            declared: length,
            segment_len: input.len(),
        },
    )?;
    Ok((!bytes.is_empty()).then(|| bytes.to_vec()))
}

fn parse_optional_bytes_if_bounded(input: &[u8], offset: usize) -> Option<Vec<u8>> {
    let length = usize::from(*input.get(offset)?);
    let start = offset.checked_add(1)?;
    let end = start.checked_add(length)?;
    let bytes = input.get(start..end)?;
    (!bytes.is_empty()).then(|| bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn witness() -> Vec<u8> {
        let mut row = vec![0_u8; 0xa7];
        let length = row.len() as u16;
        row[..2].copy_from_slice(&length.to_le_bytes());
        row[2] = MATERIALIZED_MASTER_FLAGS;
        row[3] = MATERIALIZED_MASTER_KIND;
        row[8..12].copy_from_slice(&0x0012_3456_u32.to_le_bytes());
        row[12..16].copy_from_slice(&0x0012_3457_u32.to_le_bytes());
        row[20..22].copy_from_slice(&3_u16.to_le_bytes());
        row[OPAQUE_TOKEN_OFFSET] = 3;
        row[OPAQUE_TOKEN_OFFSET + 1..OPAQUE_TOKEN_OFFSET + 4].copy_from_slice(b"xyz");
        row[DOCUMENT_REFERENCE_OFFSET] = 8;
        row[DOCUMENT_REFERENCE_OFFSET + 1..DOCUMENT_REFERENCE_OFFSET + 9]
            .copy_from_slice(b"SAMPLE01");
        let memo = b"VOID: SAMPLE TRANSACTION";
        row[VOID_MEMO_WITNESS_OFFSET] = memo.len() as u8;
        row[VOID_MEMO_WITNESS_OFFSET + 1..VOID_MEMO_WITNESS_OFFSET + 1 + memo.len()]
            .copy_from_slice(memo);
        row
    }

    #[test]
    fn parses_only_the_bounded_master_witness_fields() {
        let parsed = parse_materialized_transaction_master_row(&witness()).unwrap();
        assert_eq!(parsed.declared_len, 0xa7);
        assert_eq!(parsed.master_record_number, 0x0012_3456);
        assert_eq!(parsed.adjacent_record_number, 0x0012_3457);
        assert_eq!(parsed.opaque_type, 3);
        assert_eq!(parsed.opaque_token, Some(b"xyz".to_vec()));
        assert_eq!(parsed.document_reference.as_deref(), Some("SAMPLE01"));
        assert_eq!(
            parsed.void_memo_witness.as_deref(),
            Some("VOID: SAMPLE TRANSACTION")
        );
    }

    #[test]
    fn rejects_any_unbounded_or_other_dialect_segment() {
        let mut row = witness();
        row[0] = 0;
        assert_eq!(
            parse_materialized_transaction_master_row(&row),
            Err(
                MaterializedTransactionMasterRowError::DeclaredLengthMismatch {
                    declared: 0,
                    actual: 0xa7,
                }
            )
        );
        let mut row = witness();
        row[2] = 0x04;
        assert_eq!(
            parse_materialized_transaction_master_row(&row),
            Err(MaterializedTransactionMasterRowError::UnexpectedFlags { actual: 0x04 })
        );
        let mut row = witness();
        row[3] = 3;
        assert_eq!(
            parse_materialized_transaction_master_row(&row),
            Err(MaterializedTransactionMasterRowError::UnexpectedKind { actual: 3 })
        );
    }

    #[test]
    fn rejects_a_fixed_reference_that_overruns_the_segment() {
        let mut row = witness();
        row[DOCUMENT_REFERENCE_OFFSET] = 0xff;
        assert_eq!(
            parse_materialized_transaction_master_row(&row),
            Err(
                MaterializedTransactionMasterRowError::LengthPrefixedFieldOutOfBounds {
                    field: "document/reference",
                    offset: DOCUMENT_REFERENCE_OFFSET,
                    declared: 0xff,
                    segment_len: 0xa7,
                }
            )
        );
    }

    #[test]
    fn does_not_promote_non_void_text_as_a_memo() {
        let mut row = witness();
        row[VOID_MEMO_WITNESS_OFFSET] = 4;
        row[VOID_MEMO_WITNESS_OFFSET + 1..VOID_MEMO_WITNESS_OFFSET + 5].copy_from_slice(b"memo");
        assert_eq!(
            parse_materialized_transaction_master_row(&row)
                .unwrap()
                .void_memo_witness,
            None
        );
    }
}

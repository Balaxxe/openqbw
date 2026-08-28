//! Structural decoder for materialized Bill headers.
//!
//! A Bill header is a transaction carrier, not an accounting posting. The
//! payable and expense/asset legs are represented by its table-3042 lines.

use thiserror::Error;

/// Materialized physical table identifier for Bill headers.
pub const MATERIALIZED_BILL_HEADER_TABLE_ID: u32 = 3040;

const EXPECTED_FLAGS: u8 = 0x40;
const EXPECTED_ROW_CLASS: u8 = 0x02;
const MASTER_RECORD_OFFSET: usize = 7;
const MIN_LEN: usize = MASTER_RECORD_OFFSET + 4;

/// Observed Bill-header row kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterializedBillHeaderKind {
    /// Ordinary Bill header.
    Ordinary,
    /// Alternate observed Bill-header carrier.
    Alternate,
}

/// A validated materialized Bill transaction carrier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedBillHeaderRow {
    bill_master_record_number: u32,
    kind: MaterializedBillHeaderKind,
}

impl MaterializedBillHeaderRow {
    /// Parses an exactly bounded table-3040 Bill header carrier.
    pub fn parse(input: &[u8]) -> Result<Self, MaterializedBillHeaderRowError> {
        if input.len() < MIN_LEN {
            return Err(MaterializedBillHeaderRowError::SegmentTooShort {
                actual: input.len(),
            });
        }
        let declared = usize::from(u16::from_le_bytes([input[0], input[1]]));
        if declared != input.len() {
            return Err(MaterializedBillHeaderRowError::DeclaredLengthMismatch {
                declared,
                actual: input.len(),
            });
        }
        if input[2] != EXPECTED_FLAGS {
            return Err(MaterializedBillHeaderRowError::UnexpectedFlags { actual: input[2] });
        }
        if input[3] != EXPECTED_ROW_CLASS {
            return Err(MaterializedBillHeaderRowError::UnexpectedRowClass { actual: input[3] });
        }
        let kind = match input[4] {
            0xff => MaterializedBillHeaderKind::Ordinary,
            0xf7 => MaterializedBillHeaderKind::Alternate,
            actual => return Err(MaterializedBillHeaderRowError::UnexpectedRowKind { actual }),
        };
        let bill_master_record_number = u32::from_le_bytes(
            input[MASTER_RECORD_OFFSET..MASTER_RECORD_OFFSET + 4]
                .try_into()
                .expect("fixed bounds"),
        );
        if bill_master_record_number == 0 {
            return Err(MaterializedBillHeaderRowError::MissingMasterRecordReference);
        }
        Ok(Self {
            bill_master_record_number,
            kind,
        })
    }

    /// Record number referenced by table-3042 Bill lines.
    #[must_use]
    pub const fn bill_master_record_number(&self) -> u32 {
        self.bill_master_record_number
    }

    /// Observed header carrier kind.
    #[must_use]
    pub const fn kind(&self) -> MaterializedBillHeaderKind {
        self.kind
    }
}

/// Errors returned by [`MaterializedBillHeaderRow::parse`].
#[allow(missing_docs)]
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MaterializedBillHeaderRowError {
    #[error("materialized Bill header is too short: {actual} bytes")]
    SegmentTooShort { actual: usize },
    #[error("materialized Bill header length mismatch: declared {declared}, actual {actual}")]
    DeclaredLengthMismatch { declared: usize, actual: usize },
    #[error("unsupported materialized Bill header flags {actual:#04x}")]
    UnexpectedFlags { actual: u8 },
    #[error("unsupported materialized Bill header row class {actual:#04x}")]
    UnexpectedRowClass { actual: u8 },
    #[error("unsupported materialized Bill header row kind {actual:#04x}")]
    UnexpectedRowKind { actual: u8 },
    #[error("materialized Bill header has no master record reference")]
    MissingMasterRecordReference,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(kind: u8) -> Vec<u8> {
        let mut row = vec![0_u8; 16];
        row[2] = EXPECTED_FLAGS;
        row[3] = EXPECTED_ROW_CLASS;
        row[4] = kind;
        row[MASTER_RECORD_OFFSET..MASTER_RECORD_OFFSET + 4]
            .copy_from_slice(&0x0010_0001_u32.to_le_bytes());
        let len = row.len() as u16;
        row[..2].copy_from_slice(&len.to_le_bytes());
        row
    }
    #[test]
    fn parses_sample_only_header_kinds() {
        assert_eq!(
            MaterializedBillHeaderRow::parse(&row(0xff)).unwrap().kind(),
            MaterializedBillHeaderKind::Ordinary
        );
        assert_eq!(
            MaterializedBillHeaderRow::parse(&row(0xf7))
                .unwrap()
                .bill_master_record_number(),
            0x0010_0001
        );
    }
    #[test]
    fn rejects_unproven_header_forms() {
        assert!(matches!(
            MaterializedBillHeaderRow::parse(&row(0)),
            Err(MaterializedBillHeaderRowError::UnexpectedRowKind { .. })
        ));
    }
}

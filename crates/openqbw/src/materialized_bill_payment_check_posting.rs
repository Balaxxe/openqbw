//! Fail-closed decoder for materialized Bill-Payment-Check posting rows.
//!
//! This grammar is restricted to physical table `3039` after the caller has
//! established page ownership.  It covers the three row shapes observed in a
//! complete local table census: a linked bank leg, a normal terminal payable
//! leg, and its compact canonical-zero form.  It deliberately does not select
//! row versions, resolve referenced records, or infer account names.

use thiserror::Error;

use crate::{
    MaterializedPostingDate, MaterializedPostingDateError,
    materialized_numeric::MaterializedPostingCents,
};

/// Materialized physical table identifier for Bill-Payment-Check line rows.
pub const MATERIALIZED_BILL_PAYMENT_CHECK_TABLE_ID: u32 = 3039;

const EXPECTED_FLAGS: u8 = 0x40;
const EXPECTED_ROW_CLASS: u8 = 1;
const TARGET_OFFSET: usize = 9;
const MASTER_OFFSET: usize = 13;
const ACCOUNT_OFFSET: usize = 17;
const DATE_RAW_OFFSET: usize = 21;
const VIEW_TYPE_OFFSET: usize = 25;
const TARGET_TYPE_OFFSET: usize = 27;
const STATUS_OFFSET: usize = 31;
const LINK_KIND_OFFSET: usize = 33;
const NEXT_OR_SOURCE_OFFSET: usize = 37;
const SOURCE_OFFSET: usize = 41;
const LINKED_AMOUNT_OFFSET: usize = 90;
const TERMINAL_AMOUNT_OFFSET: usize = 94;
const COMPACT_TERMINAL_AMOUNT_OFFSET: usize = 86;
const TRAILING_AMOUNT_SUFFIX_LEN: usize = 6;
const LINKED_TRAILING_SUFFIX: [u8; TRAILING_AMOUNT_SUFFIX_LEN] = [0; TRAILING_AMOUNT_SUFFIX_LEN];
const TERMINAL_TRAILING_SUFFIX: [u8; TRAILING_AMOUNT_SUFFIX_LEN] = [0, 0, 1, 0, 0, 0];

/// The three fully observed Bill-Payment-Check line layouts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterializedBillPaymentCheckPostingShape {
    /// A bank-side row points to its payable-side sibling.
    Linked {
        /// Bounded record number for the paired payable-side row.
        next_target_record_number: u32,
    },
    /// A payable-side row stores its bank-side sibling at the second link slot.
    Terminal,
    /// A canonical-zero payable row compacts away the empty first link slot.
    CompactTerminal,
}

/// A bounded, validated Bill-Payment-Check accounting line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedBillPaymentCheckPostingRow {
    row_link_prefix: [u8; 6],
    target_record_number: u32,
    master_record_number: u32,
    account_record_number: u32,
    date_raw: u32,
    view_type: u16,
    target_type_record_number: u32,
    status: u16,
    link_kind: u32,
    shape: MaterializedBillPaymentCheckPostingShape,
    source_account_record_number: u32,
    signed_cents: i64,
    canonical_zero_amount: bool,
}

impl MaterializedBillPaymentCheckPostingRow {
    /// Parses one exactly bounded materialized table-3039 row.
    pub fn parse(input: &[u8]) -> Result<Self, MaterializedBillPaymentCheckPostingRowError> {
        if input.len() < SOURCE_OFFSET + size_of::<u32>() {
            return Err(
                MaterializedBillPaymentCheckPostingRowError::SegmentTooShort {
                    actual: input.len(),
                    minimum: SOURCE_OFFSET + size_of::<u32>(),
                },
            );
        }
        let declared = usize::from(u16::from_le_bytes([input[0], input[1]]));
        if declared != input.len() {
            return Err(
                MaterializedBillPaymentCheckPostingRowError::DeclaredLengthMismatch {
                    declared,
                    actual: input.len(),
                },
            );
        }
        if input[2] != EXPECTED_FLAGS {
            return Err(
                MaterializedBillPaymentCheckPostingRowError::UnexpectedFlags { actual: input[2] },
            );
        }
        if input[3] != EXPECTED_ROW_CLASS {
            return Err(
                MaterializedBillPaymentCheckPostingRowError::UnexpectedRowClass {
                    actual: input[3],
                },
            );
        }
        let target_record_number = u32_at(input, TARGET_OFFSET);
        let master_record_number = u32_at(input, MASTER_OFFSET);
        let account_record_number = u32_at(input, ACCOUNT_OFFSET);
        require_nonzero("target", target_record_number)?;
        require_nonzero("master", master_record_number)?;
        require_nonzero("account", account_record_number)?;

        let first_link = u32_at(input, NEXT_OR_SOURCE_OFFSET);
        let second_link = u32_at(input, SOURCE_OFFSET);
        let (shape, source_account_record_number, amount_offset, trailing_suffix) =
            if first_link != 0 && is_compact_terminal(input) {
                (
                    MaterializedBillPaymentCheckPostingShape::CompactTerminal,
                    first_link,
                    COMPACT_TERMINAL_AMOUNT_OFFSET,
                    &TERMINAL_TRAILING_SUFFIX,
                )
            } else if first_link != 0 && second_link != 0 {
                (
                    MaterializedBillPaymentCheckPostingShape::Linked {
                        next_target_record_number: first_link,
                    },
                    second_link,
                    LINKED_AMOUNT_OFFSET,
                    &LINKED_TRAILING_SUFFIX,
                )
            } else if first_link == 0 && second_link != 0 {
                (
                    MaterializedBillPaymentCheckPostingShape::Terminal,
                    second_link,
                    TERMINAL_AMOUNT_OFFSET,
                    &TERMINAL_TRAILING_SUFFIX,
                )
            } else {
                return Err(
                    MaterializedBillPaymentCheckPostingRowError::UnsupportedLinkShape {
                        first_link,
                        second_link,
                    },
                );
            };
        require_nonzero("source account", source_account_record_number)?;

        let amount = parse_amount_at(input, amount_offset)?;
        let trailing_start = input
            .len()
            .checked_sub(amount.bytes_len + TRAILING_AMOUNT_SUFFIX_LEN)
            .ok_or(MaterializedBillPaymentCheckPostingRowError::TrailingAmountOutsideSegment)?;
        let trailing_end = trailing_start + amount.bytes_len;
        if input.get(trailing_start..trailing_end) != Some(amount.bytes.as_slice()) {
            return Err(MaterializedBillPaymentCheckPostingRowError::TrailingAmountMismatch);
        }
        if input.get(trailing_end..) != Some(trailing_suffix.as_slice()) {
            return Err(MaterializedBillPaymentCheckPostingRowError::UnexpectedTrailingSuffix);
        }

        Ok(Self {
            row_link_prefix: input[3..9].try_into().expect("fixed bounds"),
            target_record_number,
            master_record_number,
            account_record_number,
            date_raw: u32_at(input, DATE_RAW_OFFSET),
            view_type: u16_at(input, VIEW_TYPE_OFFSET),
            target_type_record_number: u32_at(input, TARGET_TYPE_OFFSET),
            status: u16_at(input, STATUS_OFFSET),
            link_kind: u32_at(input, LINK_KIND_OFFSET),
            shape,
            source_account_record_number,
            signed_cents: amount.signed_cents,
            canonical_zero_amount: amount.canonical_zero,
        })
    }

    /// Opaque six-byte table-row link prefix. It is not a resolved target.
    #[must_use]
    pub const fn row_link_prefix(&self) -> [u8; 6] {
        self.row_link_prefix
    }
    /// Posting-line record number.
    #[must_use]
    pub const fn target_record_number(&self) -> u32 {
        self.target_record_number
    }
    /// Transaction-master record number.
    #[must_use]
    pub const fn master_record_number(&self) -> u32 {
        self.master_record_number
    }
    /// Posting account record number.
    #[must_use]
    pub const fn account_record_number(&self) -> u32 {
        self.account_record_number
    }
    /// Raw little-endian SQL Anywhere minute-date bits.
    ///
    /// Use [`Self::posting_date`] for strict calendar interpretation.
    #[must_use]
    pub const fn date_raw_bits(&self) -> u32 {
        self.date_raw
    }
    /// Backward-compatible alias for [`Self::date_raw_bits`].
    #[must_use]
    pub const fn date_raw(&self) -> u32 {
        self.date_raw_bits()
    }
    /// Strictly decodes the SQL Anywhere minute-date bits as a midnight posting date.
    pub fn posting_date(&self) -> Result<MaterializedPostingDate, MaterializedPostingDateError> {
        MaterializedPostingDate::from_raw_minutes(i32::from_le_bytes(self.date_raw.to_le_bytes()))
    }
    /// Opaque, observed view value.
    #[must_use]
    pub const fn view_type(&self) -> u16 {
        self.view_type
    }
    /// Opaque record reference carried in the target-type field.
    #[must_use]
    pub const fn target_type_record_number(&self) -> u32 {
        self.target_type_record_number
    }
    /// Opaque table-row status value.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }
    /// Opaque table-row link-kind value.
    #[must_use]
    pub const fn link_kind(&self) -> u32 {
        self.link_kind
    }
    /// Established physical link layout.
    #[must_use]
    pub const fn shape(&self) -> MaterializedBillPaymentCheckPostingShape {
        self.shape
    }
    /// Paired source-account record number.
    #[must_use]
    pub const fn source_account_record_number(&self) -> u32 {
        self.source_account_record_number
    }
    /// Signed amount in whole cents; sign is established only for this family.
    #[must_use]
    pub const fn signed_cents(&self) -> i64 {
        self.signed_cents
    }
    /// Whether the controlled amount token was the canonical zero form.
    #[must_use]
    pub const fn has_canonical_zero_amount(&self) -> bool {
        self.canonical_zero_amount
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
/// Fail-closed parsing failures for a Bill-Payment-Check posting row.
pub enum MaterializedBillPaymentCheckPostingRowError {
    /// Input could not contain the fixed table-3039 reference fields.
    #[error("materialized Bill-Payment-Check row is too short: {actual} bytes (need {minimum})")]
    SegmentTooShort {
        /// Supplied byte count.
        actual: usize,
        /// Minimum required byte count.
        minimum: usize,
    },
    /// The leading segment length did not exactly bound input.
    #[error(
        "materialized Bill-Payment-Check row length mismatch: declared {declared}, actual {actual}"
    )]
    DeclaredLengthMismatch {
        /// Little-endian declared segment length.
        declared: usize,
        /// Supplied byte count.
        actual: usize,
    },
    /// Flags differ from the sole observed table-3039 flags value.
    #[error("unsupported materialized Bill-Payment-Check flags {actual:#04x}")]
    UnexpectedFlags {
        /// Observed flags value.
        actual: u8,
    },
    /// Row class differs from the sole observed table-3039 row class.
    #[error("unsupported materialized Bill-Payment-Check row class {actual:#04x}")]
    UnexpectedRowClass {
        /// Observed row class.
        actual: u8,
    },
    /// A proven required record reference was zero.
    #[error("Bill-Payment-Check {field} record reference is zero")]
    ZeroRequiredReference {
        /// Name of the fixed reference field.
        field: &'static str,
    },
    /// The two physical link slots did not select a proven layout.
    #[error("unsupported materialized Bill-Payment-Check link shape ({first_link}, {second_link})")]
    UnsupportedLinkShape {
        /// First physical link slot.
        first_link: u32,
        /// Second physical link slot.
        second_link: u32,
    },
    /// The selected primary amount field was not fully bounded by input.
    #[error("Bill-Payment-Check amount is outside its bounded segment")]
    AmountOutsideSegment,
    /// The Bill-Payment family has not established this shared-codec marker.
    #[error("unsupported Bill-Payment-Check amount marker {marker:#04x}")]
    UnsupportedBillPaymentAmountMarker {
        /// Observed sign/scale marker.
        marker: u8,
    },
    /// The shared controlled posting-number codec rejected the token.
    #[error("invalid Bill-Payment-Check amount token")]
    InvalidSharedAmount,
    /// The trailing duplicate amount did not fit input.
    #[error("Bill-Payment-Check trailing amount is outside its segment")]
    TrailingAmountOutsideSegment,
    /// Primary and trailing duplicate amount tokens differed.
    #[error("Bill-Payment-Check primary and trailing amounts differ")]
    TrailingAmountMismatch,
    /// The shape-specific bytes following the trailing amount were not exact.
    #[error("unsupported Bill-Payment-Check trailing amount suffix")]
    UnexpectedTrailingSuffix,
}

struct ParsedAmount {
    bytes: Vec<u8>,
    bytes_len: usize,
    signed_cents: i64,
    canonical_zero: bool,
}

fn parse_amount_at(
    input: &[u8],
    offset: usize,
) -> Result<ParsedAmount, MaterializedBillPaymentCheckPostingRowError> {
    let marker = *input
        .get(offset + 1)
        .ok_or(MaterializedBillPaymentCheckPostingRowError::AmountOutsideSegment)?;
    let digits = usize::from(
        *input
            .get(offset)
            .ok_or(MaterializedBillPaymentCheckPostingRowError::AmountOutsideSegment)?,
    );
    let end = offset
        .checked_add(2)
        .and_then(|v| v.checked_add(digits))
        .ok_or(MaterializedBillPaymentCheckPostingRowError::AmountOutsideSegment)?;
    let bytes = input
        .get(offset..end)
        .ok_or(MaterializedBillPaymentCheckPostingRowError::AmountOutsideSegment)?;
    if digits != 0 && !(0x3f..=0x42).contains(&(marker & 0x7f)) {
        return Err(
            MaterializedBillPaymentCheckPostingRowError::UnsupportedBillPaymentAmountMarker {
                marker,
            },
        );
    }
    let amount = MaterializedPostingCents::parse(bytes)
        .map_err(|_| MaterializedBillPaymentCheckPostingRowError::InvalidSharedAmount)?;
    Ok(ParsedAmount {
        bytes: bytes.to_vec(),
        bytes_len: bytes.len(),
        signed_cents: amount.signed_cents(),
        canonical_zero: amount.is_canonical_zero(),
    })
}

fn require_nonzero(
    field: &'static str,
    value: u32,
) -> Result<(), MaterializedBillPaymentCheckPostingRowError> {
    if value == 0 {
        return Err(MaterializedBillPaymentCheckPostingRowError::ZeroRequiredReference { field });
    }
    Ok(())
}

fn is_compact_terminal(input: &[u8]) -> bool {
    input.get(SOURCE_OFFSET) == Some(&0x10)
        && input
            .get(SOURCE_OFFSET + 1..SOURCE_OFFSET + 17)
            .is_some_and(|value| value.iter().all(u8::is_ascii_alphanumeric))
}

fn u16_at(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(input[offset..offset + 2].try_into().expect("fixed bounds"))
}
fn u32_at(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().expect("fixed bounds"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(shape: MaterializedBillPaymentCheckPostingShape, amount: &[u8]) -> Vec<u8> {
        let amount_offset = match shape {
            MaterializedBillPaymentCheckPostingShape::Linked { .. } => LINKED_AMOUNT_OFFSET,
            MaterializedBillPaymentCheckPostingShape::Terminal => TERMINAL_AMOUNT_OFFSET,
            MaterializedBillPaymentCheckPostingShape::CompactTerminal => {
                COMPACT_TERMINAL_AMOUNT_OFFSET
            }
        };
        let suffix = match shape {
            MaterializedBillPaymentCheckPostingShape::Linked { .. } => LINKED_TRAILING_SUFFIX,
            MaterializedBillPaymentCheckPostingShape::Terminal
            | MaterializedBillPaymentCheckPostingShape::CompactTerminal => TERMINAL_TRAILING_SUFFIX,
        };
        let mut row = vec![0_u8; amount_offset + amount.len() + 12];
        row[2] = EXPECTED_FLAGS;
        row[3] = EXPECTED_ROW_CLASS;
        row[3..9].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        row[TARGET_OFFSET..TARGET_OFFSET + 4].copy_from_slice(&101_u32.to_le_bytes());
        row[MASTER_OFFSET..MASTER_OFFSET + 4].copy_from_slice(&100_u32.to_le_bytes());
        row[ACCOUNT_OFFSET..ACCOUNT_OFFSET + 4].copy_from_slice(&700_u32.to_le_bytes());
        row[DATE_RAW_OFFSET..DATE_RAW_OFFSET + 4].copy_from_slice(&220_000_000_u32.to_le_bytes());
        row[VIEW_TYPE_OFFSET..VIEW_TYPE_OFFSET + 2].copy_from_slice(&14_u16.to_le_bytes());
        row[TARGET_TYPE_OFFSET..TARGET_TYPE_OFFSET + 4].copy_from_slice(&42_u32.to_le_bytes());
        row[STATUS_OFFSET..STATUS_OFFSET + 2].copy_from_slice(&101_u16.to_le_bytes());
        row[LINK_KIND_OFFSET..LINK_KIND_OFFSET + 4].copy_from_slice(&101_u32.to_le_bytes());
        match shape {
            MaterializedBillPaymentCheckPostingShape::Linked {
                next_target_record_number,
            } => {
                row[NEXT_OR_SOURCE_OFFSET..NEXT_OR_SOURCE_OFFSET + 4]
                    .copy_from_slice(&next_target_record_number.to_le_bytes());
                row[SOURCE_OFFSET..SOURCE_OFFSET + 4].copy_from_slice(&701_u32.to_le_bytes());
            }
            MaterializedBillPaymentCheckPostingShape::Terminal => {
                row[SOURCE_OFFSET..SOURCE_OFFSET + 4].copy_from_slice(&700_u32.to_le_bytes());
            }
            MaterializedBillPaymentCheckPostingShape::CompactTerminal => {
                row[NEXT_OR_SOURCE_OFFSET..NEXT_OR_SOURCE_OFFSET + 4]
                    .copy_from_slice(&700_u32.to_le_bytes());
                row[SOURCE_OFFSET] = 0x10;
                row[SOURCE_OFFSET + 1..SOURCE_OFFSET + 17].copy_from_slice(b"SAMPLETOKEN00000");
            }
        }
        row[amount_offset..amount_offset + amount.len()].copy_from_slice(amount);
        let tail = row.len() - amount.len() - TRAILING_AMOUNT_SUFFIX_LEN;
        row[tail..tail + amount.len()].copy_from_slice(amount);
        row[tail + amount.len()..].copy_from_slice(&suffix);
        let declared_len = row.len() as u16;
        row[..2].copy_from_slice(&declared_len.to_le_bytes());
        row
    }

    #[test]
    fn parses_balanced_sample_bank_and_payable_legs() {
        let bank = MaterializedBillPaymentCheckPostingRow::parse(&row(
            MaterializedBillPaymentCheckPostingShape::Linked {
                next_target_record_number: 101,
            },
            &[3, 0x3f, 77, 80, 1],
        ))
        .unwrap();
        let payable = MaterializedBillPaymentCheckPostingRow::parse(&row(
            MaterializedBillPaymentCheckPostingShape::Terminal,
            &[3, 0xbf, 77, 80, 1],
        ))
        .unwrap();
        assert_eq!(bank.signed_cents(), -18_077);
        assert_eq!(payable.signed_cents(), 18_077);
        assert_eq!(bank.signed_cents() + payable.signed_cents(), 0);
    }

    #[test]
    fn parses_compact_zero_and_trailing_zero_contract() {
        let compact = MaterializedBillPaymentCheckPostingRow::parse(&row(
            MaterializedBillPaymentCheckPostingShape::CompactTerminal,
            &[0, 0x81],
        ))
        .unwrap();
        assert_eq!(
            compact.shape(),
            MaterializedBillPaymentCheckPostingShape::CompactTerminal
        );
        assert!(compact.has_canonical_zero_amount());
        assert_eq!(compact.source_account_record_number(), 700);
    }

    #[test]
    fn marker_exponent_compresses_whole_base_100_groups() {
        let token = [2, 0xc0, 50, 50];
        let value = MaterializedBillPaymentCheckPostingRow::parse(&row(
            MaterializedBillPaymentCheckPostingShape::Terminal,
            &token,
        ))
        .unwrap();
        assert_eq!(value.signed_cents(), 505_000);
        assert_eq!(
            value.signed_cents(),
            crate::materialized_numeric::MaterializedPostingCents::parse(&token)
                .unwrap()
                .signed_cents()
        );
    }

    #[test]
    fn rejects_tampered_duplicate_amount() {
        let mut sample = row(
            MaterializedBillPaymentCheckPostingShape::Terminal,
            &[2, 0xbf, 1, 2],
        );
        let last_amount = sample.len() - 8;
        sample[last_amount] = 3;
        assert!(matches!(
            MaterializedBillPaymentCheckPostingRow::parse(&sample),
            Err(MaterializedBillPaymentCheckPostingRowError::TrailingAmountMismatch)
        ));
    }

    #[test]
    fn rejects_zero_required_references() {
        for (offset, field) in [
            (TARGET_OFFSET, "target"),
            (MASTER_OFFSET, "master"),
            (ACCOUNT_OFFSET, "account"),
        ] {
            let mut sample = row(
                MaterializedBillPaymentCheckPostingShape::Linked {
                    next_target_record_number: 101,
                },
                &[1, 0x3f, 1],
            );
            sample[offset..offset + 4].fill(0);
            assert_eq!(
                MaterializedBillPaymentCheckPostingRow::parse(&sample),
                Err(MaterializedBillPaymentCheckPostingRowError::ZeroRequiredReference { field })
            );
        }

        let mut linked = row(
            MaterializedBillPaymentCheckPostingShape::Linked {
                next_target_record_number: 101,
            },
            &[1, 0x3f, 1],
        );
        linked[SOURCE_OFFSET..SOURCE_OFFSET + 4].fill(0);
        assert!(matches!(
            MaterializedBillPaymentCheckPostingRow::parse(&linked),
            Err(MaterializedBillPaymentCheckPostingRowError::UnsupportedLinkShape { .. })
        ));
    }
}

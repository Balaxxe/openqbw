//! Fail-closed parser for observed materialized Bill line rows.
//!
//! This parser is restricted to physical table `3042` after the caller has
//! established page ownership. It validates the one complete controlled row
//! grammar observed in the local Enterprise corpus. It does not resolve the
//! nullable link or sibling-account columns, choose a current version, or
//! assign debit/credit meaning.

use thiserror::Error;

use crate::materialized_numeric::MaterializedPostingCents;
use crate::{MaterializedPostingDate, MaterializedPostingDateError};

/// Materialized physical table identifier for Bill line rows.
pub const MATERIALIZED_BILL_POSTING_TABLE_ID: u32 = 3042;

const EXPECTED_FLAGS: u8 = 0x40;
const EXPECTED_ROW_CLASS: u8 = 0x02;
const EXPECTED_ROW_KIND: u8 = 0xe4;
const TARGET_OFFSET: usize = 0x0c;
const MASTER_OFFSET: usize = 0x10;
const ACCOUNT_OFFSET: usize = 0x14;
const DATE_RAW_OFFSET: usize = 0x18;
const VIEW_TYPE_OFFSET: usize = 0x1c;
const FIXED_FIELDS_END: usize = VIEW_TYPE_OFFSET + 2;
const MAX_OBSERVED_AMOUNT_DIGITS: usize = 4;
const TRAILING_AMOUNT_END_GAP: usize = 8;
const TRAILING_CANONICAL_ZERO: [u8; 5] = [0, 0, 0, 0, 0x81];

/// Controlled Enterprise 24 transaction semantics carried by a Bill-line
/// `transaction_view_type` value.
///
/// An unrecognized view remains unknown. Callers may still use the row for
/// amount aggregation, but must not attach a display transaction type from
/// this enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterializedBillTransactionKind {
    /// An ordinary Bill transaction.
    Bill,
    /// A vendor credit stored in the Bill physical line family.
    VendorCredit,
}

/// A validated, controlled-family materialized Bill line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedBillPostingRow {
    target_record_number: u32,
    master_record_number: u32,
    account_record_number: u32,
    date_raw: u32,
    view_type: u16,
    signed_cents: i64,
    canonical_zero_amount: bool,
}

impl MaterializedBillPostingRow {
    /// Parses one exactly bounded materialized table-3042 Bill line.
    ///
    /// The Bill row stores its accounting amount as one bounded base-100 token
    /// ending eight bytes before the record end. Multiple distinct valid
    /// tokens at that boundary are rejected rather than selected heuristically.
    pub fn parse(input: &[u8]) -> Result<Self, MaterializedBillPostingRowError> {
        if input.len() < FIXED_FIELDS_END + TRAILING_AMOUNT_END_GAP + 3 {
            return Err(MaterializedBillPostingRowError::SegmentTooShort {
                actual: input.len(),
                minimum: FIXED_FIELDS_END + TRAILING_AMOUNT_END_GAP + 3,
            });
        }
        let declared = usize::from(u16::from_le_bytes([input[0], input[1]]));
        if declared != input.len() {
            return Err(MaterializedBillPostingRowError::DeclaredLengthMismatch {
                declared,
                actual: input.len(),
            });
        }
        if input[2] != EXPECTED_FLAGS {
            return Err(MaterializedBillPostingRowError::UnexpectedFlags { actual: input[2] });
        }
        if input[3] != EXPECTED_ROW_CLASS {
            return Err(MaterializedBillPostingRowError::UnexpectedRowClass { actual: input[3] });
        }
        if input[4] != EXPECTED_ROW_KIND {
            return Err(MaterializedBillPostingRowError::UnexpectedRowKind { actual: input[4] });
        }
        if !input.ends_with(&TRAILING_CANONICAL_ZERO) {
            return Err(MaterializedBillPostingRowError::UnexpectedTrailingSuffix);
        }
        let amount_end = input
            .len()
            .checked_sub(TRAILING_AMOUNT_END_GAP)
            .ok_or(MaterializedBillPostingRowError::AmountOutsideSegment)?;
        let (signed_cents, canonical_zero_amount) = parse_trailing_amount(input, amount_end)?;
        let target_record_number = u32_at(input, TARGET_OFFSET);
        let master_record_number = u32_at(input, MASTER_OFFSET);
        let account_record_number = u32_at(input, ACCOUNT_OFFSET);
        if target_record_number == 0 || master_record_number == 0 || account_record_number == 0 {
            return Err(MaterializedBillPostingRowError::MissingRequiredRecordReference);
        }
        Ok(Self {
            target_record_number,
            master_record_number,
            account_record_number,
            date_raw: u32_at(input, DATE_RAW_OFFSET),
            view_type: u16_at(input, VIEW_TYPE_OFFSET),
            signed_cents,
            canonical_zero_amount,
        })
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

    /// Raw SQL Anywhere minute-date field, without calendar interpretation.
    #[must_use]
    pub const fn date_raw(&self) -> u32 {
        self.date_raw
    }

    /// Decodes the controlled raw date as a timezone-free calendar date.
    pub fn posting_date(&self) -> Result<MaterializedPostingDate, MaterializedPostingDateError> {
        MaterializedPostingDate::from_disk_bytes(self.date_raw.to_le_bytes())
    }

    /// Opaque observed view value.
    #[must_use]
    pub const fn view_type(&self) -> u16 {
        self.view_type
    }

    /// Returns the semantic type for an oracle-attested view value.
    ///
    /// Controlled transaction-index joins establish view `9` as Bill and
    /// view `12` as VendorCredit. Other values deliberately remain unknown.
    #[must_use]
    pub const fn transaction_kind(&self) -> Option<MaterializedBillTransactionKind> {
        match self.view_type {
            9 => Some(MaterializedBillTransactionKind::Bill),
            12 => Some(MaterializedBillTransactionKind::VendorCredit),
            _ => None,
        }
    }

    /// Signed Bill-line amount in cents.
    #[must_use]
    pub const fn signed_cents(&self) -> i64 {
        self.signed_cents
    }

    /// Whether the amount uses the exact canonical zero token.
    ///
    /// This is structural evidence only; it does not by itself establish a
    /// voided, deleted, or current row state.
    #[must_use]
    pub const fn has_canonical_zero_amount(&self) -> bool {
        self.canonical_zero_amount
    }
}

/// Errors returned by [`MaterializedBillPostingRow::parse`].
#[allow(missing_docs)]
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MaterializedBillPostingRowError {
    #[error("materialized Bill row is too short: {actual} bytes (need {minimum})")]
    SegmentTooShort { actual: usize, minimum: usize },
    #[error("materialized Bill row length mismatch: declared {declared}, actual {actual}")]
    DeclaredLengthMismatch { declared: usize, actual: usize },
    #[error("unsupported materialized Bill flags {actual:#04x}")]
    UnexpectedFlags { actual: u8 },
    #[error("unsupported materialized Bill row class {actual:#04x}")]
    UnexpectedRowClass { actual: u8 },
    #[error("unsupported materialized Bill row kind {actual:#04x}")]
    UnexpectedRowKind { actual: u8 },
    #[error("materialized Bill row has an unsupported terminal suffix")]
    UnexpectedTrailingSuffix,
    #[error("materialized Bill amount is outside its bounded segment")]
    AmountOutsideSegment,
    #[error("materialized Bill amount uses unsupported zero marker {marker:#04x}")]
    UnsupportedZeroAmountMarker { marker: u8 },
    #[error("materialized Bill amount uses unsupported marker {marker:#04x}")]
    UnsupportedAmountMarker { marker: u8 },
    #[error("materialized Bill amount has invalid base-100 digit {digit}")]
    InvalidBase100Digit { digit: u8 },
    #[error("materialized Bill amount exceeded signed cents")]
    AmountOverflow,
    #[error("materialized Bill row has ambiguous terminal amount tokens")]
    AmbiguousTrailingAmount,
    #[error("materialized Bill row lacks a target, master, or account reference")]
    MissingRequiredRecordReference,
}

fn parse_trailing_amount(
    input: &[u8],
    amount_end: usize,
) -> Result<(i64, bool), MaterializedBillPostingRowError> {
    let mut candidates = Vec::new();
    for digits in 0..=MAX_OBSERVED_AMOUNT_DIGITS {
        let Some(start) = amount_end.checked_sub(digits + 2) else {
            continue;
        };
        if input[start] != digits as u8 {
            continue;
        }
        match MaterializedPostingCents::parse(&input[start..amount_end]) {
            Ok(amount) => {
                let candidate = (amount.signed_cents(), amount.is_canonical_zero());
                candidates.push((start, candidate));
            }
            Err(_) => continue,
        }
    }
    if candidates.is_empty() {
        return Err(MaterializedBillPostingRowError::AmountOutsideSegment);
    }
    let distinct = candidates
        .iter()
        .map(|(_, value)| *value)
        .collect::<std::collections::BTreeSet<_>>();
    if distinct.len() == 1 {
        return Ok(candidates[0].1);
    }
    let repeated = candidates
        .into_iter()
        .filter(|(start, _)| {
            let len = amount_end - *start;
            *start >= len + 5 && input[*start - len - 5..*start - 5] == input[*start..amount_end]
        })
        .collect::<Vec<_>>();
    if repeated.len() == 1 {
        Ok(repeated[0].1)
    } else {
        Err(MaterializedBillPostingRowError::AmbiguousTrailingAmount)
    }
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

    fn row(amount: &[u8]) -> Vec<u8> {
        let amount_end = 80;
        let mut row = vec![0_u8; amount_end + TRAILING_AMOUNT_END_GAP];
        row[2] = EXPECTED_FLAGS;
        row[3] = EXPECTED_ROW_CLASS;
        row[4] = EXPECTED_ROW_KIND;
        row[TARGET_OFFSET..TARGET_OFFSET + 4].copy_from_slice(&0x0010_0001_u32.to_le_bytes());
        row[MASTER_OFFSET..MASTER_OFFSET + 4].copy_from_slice(&0x0010_0002_u32.to_le_bytes());
        row[ACCOUNT_OFFSET..ACCOUNT_OFFSET + 4].copy_from_slice(&0x0010_0003_u32.to_le_bytes());
        row[DATE_RAW_OFFSET..DATE_RAW_OFFSET + 4].copy_from_slice(&0x0d00_1000_u32.to_le_bytes());
        row[VIEW_TYPE_OFFSET..VIEW_TYPE_OFFSET + 2].copy_from_slice(&9_u16.to_le_bytes());
        let start = amount_end - amount.len();
        row[start..amount_end].copy_from_slice(amount);
        let suffix_start = row.len() - TRAILING_CANONICAL_ZERO.len();
        row[suffix_start..].copy_from_slice(&TRAILING_CANONICAL_ZERO);
        let len = row.len() as u16;
        row[..2].copy_from_slice(&len.to_le_bytes());
        row
    }

    #[test]
    fn parses_sample_only_bill_fields_and_scaled_amount() {
        let parsed = MaterializedBillPostingRow::parse(&row(&[1, 0xc1, 4])).unwrap();
        assert_eq!(parsed.target_record_number(), 0x0010_0001);
        assert_eq!(parsed.master_record_number(), 0x0010_0002);
        assert_eq!(parsed.account_record_number(), 0x0010_0003);
        assert_eq!(parsed.date_raw(), 0x0d00_1000);
        assert_eq!(parsed.view_type(), 9);
        assert_eq!(
            parsed.transaction_kind(),
            Some(MaterializedBillTransactionKind::Bill)
        );
        assert_eq!(parsed.signed_cents(), 40_000);
    }

    #[test]
    fn classifies_only_oracle_attested_view_values() {
        let mut vendor_credit = row(&[1, 0xc1, 4]);
        vendor_credit[VIEW_TYPE_OFFSET..VIEW_TYPE_OFFSET + 2]
            .copy_from_slice(&12_u16.to_le_bytes());
        let vendor_credit = MaterializedBillPostingRow::parse(&vendor_credit).unwrap();
        assert_eq!(
            vendor_credit.transaction_kind(),
            Some(MaterializedBillTransactionKind::VendorCredit)
        );

        let mut unknown = row(&[1, 0xc1, 4]);
        unknown[VIEW_TYPE_OFFSET..VIEW_TYPE_OFFSET + 2].copy_from_slice(&99_u16.to_le_bytes());
        let unknown = MaterializedBillPostingRow::parse(&unknown).unwrap();
        assert_eq!(unknown.transaction_kind(), None);
    }

    #[test]
    fn resolves_ambiguous_inner_token_from_repeated_prior_field() {
        let amount = [3, 0xbf, 1, 0x3f, 12];
        let mut input = row(&amount);
        let end = input.len() - TRAILING_AMOUNT_END_GAP;
        let start = end - amount.len();
        input[start - amount.len() - 5..start - 5].copy_from_slice(&amount);
        let parsed = MaterializedBillPostingRow::parse(&input).unwrap();
        assert_eq!(parsed.signed_cents(), 126_301);
    }

    #[test]
    fn rejects_unproven_header_suffix_and_amount_forms() {
        let mut bad_flags = row(&[2, 0xbf, 2, 1]);
        bad_flags[2] = 0;
        assert!(matches!(
            MaterializedBillPostingRow::parse(&bad_flags),
            Err(MaterializedBillPostingRowError::UnexpectedFlags { .. })
        ));
        let zero = MaterializedBillPostingRow::parse(&row(&[0, 0x81])).unwrap();
        assert!(zero.has_canonical_zero_amount());
        let mut bad_suffix = row(&[2, 0xbf, 2, 1]);
        *bad_suffix.last_mut().unwrap() = 0;
        assert!(matches!(
            MaterializedBillPostingRow::parse(&bad_suffix),
            Err(MaterializedBillPostingRowError::UnexpectedTrailingSuffix)
        ));
        assert!(matches!(
            MaterializedBillPostingRow::parse(&row(&[1, 0x99, 1])),
            Err(MaterializedBillPostingRowError::AmountOutsideSegment)
        ));
    }
}

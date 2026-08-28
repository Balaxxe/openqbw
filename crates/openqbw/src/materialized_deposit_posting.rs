//! Fail-closed parser for controlled materialized Deposit posting rows.
//!
//! This parser is calibrated only by a controlled Deposit containing a bank
//! header and two source rows. It accepts an exactly bounded materialized row;
//! it does not infer table ownership, traverse continuation links, select a
//! current row version, or assign debit/credit meaning to the signed amount.

use thiserror::Error;

use crate::materialized_numeric::{MaterializedPostingCents, MaterializedPostingCentsError};

/// Observed materialized kind for a Deposit row with a next-target reference.
pub const MATERIALIZED_DEPOSIT_POSTING_KIND: u8 = 0xe1;

/// Observed materialized kind for the terminal Deposit source row.
pub const MATERIALIZED_DEPOSIT_TERMINAL_POSTING_KIND: u8 = 0xe0;
/// Observed compact counterpart row kind in the bounded Deposit table census.
pub const MATERIALIZED_DEPOSIT_COUNTERPART_F0_KIND: u8 = 0xf0;
/// Observed expanded counterpart row kind in the bounded Deposit table census.
pub const MATERIALIZED_DEPOSIT_COUNTERPART_F1_KIND: u8 = 0xf1;

const EXPECTED_FLAGS: u8 = 0;
const TARGET_OFFSET: usize = 0x08;
const MASTER_OFFSET: usize = 0x0c;
const ACCOUNT_OFFSET: usize = 0x10;
const DATE_RAW_OFFSET: usize = 0x14;
const VIEW_TYPE_OFFSET: usize = 0x18;
const LINK_OR_SOURCE_ACCOUNT_OFFSET: usize = 0x1a;
const SOURCE_ACCOUNT_AFTER_LINK_OFFSET: usize = 0x1e;
const LINKED_AMOUNT_OFFSET: usize = 0x32;
const TERMINAL_AMOUNT_OFFSET: usize = 0x2e;
const COUNTERPART_MASTER_OFFSET: usize = 0x0c;
const COUNTERPART_DATE_OFFSET: usize = 0x14;
const COUNTERPART_F0_ACCOUNT_OFFSET: usize = 0x1e;
const COUNTERPART_F1_ACCOUNT_OFFSET: usize = 0x22;
const COUNTERPART_TRAILING_SUFFIX_LEN: usize = 5;

/// A validated bounded Deposit counterpart/detail row.
///
/// This covers only the two row kinds established by the table-3069 census.
/// It does not assign a target-record field or interpret its five trailing
/// opaque bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedDepositCounterpartPostingRow {
    master_record_number: u32,
    account_record_number: u32,
    date_raw: u32,
    kind: u8,
    signed_cents: i64,
    canonical_zero_amount: bool,
}

impl MaterializedDepositCounterpartPostingRow {
    /// Parses one exactly bounded `f0` or `f1` Deposit counterpart row.
    pub fn parse(input: &[u8]) -> Result<Self, MaterializedDepositPostingRowError> {
        if input.len() < 4 {
            return Err(MaterializedDepositPostingRowError::SegmentTooShort {
                actual: input.len(),
                minimum: 4,
            });
        }
        let declared = usize::from(u16::from_le_bytes([input[0], input[1]]));
        if declared != input.len() {
            return Err(MaterializedDepositPostingRowError::DeclaredLengthMismatch {
                declared,
                actual: input.len(),
            });
        }
        if input[2] != EXPECTED_FLAGS {
            return Err(MaterializedDepositPostingRowError::UnexpectedFlags { actual: input[2] });
        }
        let account_offset = match input[3] {
            MATERIALIZED_DEPOSIT_COUNTERPART_F0_KIND => COUNTERPART_F0_ACCOUNT_OFFSET,
            MATERIALIZED_DEPOSIT_COUNTERPART_F1_KIND => COUNTERPART_F1_ACCOUNT_OFFSET,
            actual => return Err(MaterializedDepositPostingRowError::UnexpectedKind { actual }),
        };
        ensure_minimum(
            input,
            account_offset + 4 + COUNTERPART_TRAILING_SUFFIX_LEN + 2,
        )?;
        let suffix_start = input.len() - COUNTERPART_TRAILING_SUFFIX_LEN;
        require_reference(u32_at(input, COUNTERPART_MASTER_OFFSET), "master")?;
        require_reference(u32_at(input, account_offset), "account")?;
        let candidates = (0..=4)
            .rev()
            .filter_map(|digits| {
                let start = suffix_start.checked_sub(digits + 2)?;
                (input[start] == digits as u8)
                    .then(|| decode_amount(&input[start..suffix_start], start))
                    .transpose()
                    .ok()
                    .flatten()
            })
            .collect::<Vec<_>>();
        let (signed_cents, canonical_zero_amount) = match candidates.as_slice() {
            [candidate] => *candidate,
            [] => {
                return Err(MaterializedDepositPostingRowError::AmountOutsideSegment {
                    digits: 0,
                    segment_len: input.len(),
                });
            }
            _ => {
                return Err(MaterializedDepositPostingRowError::AmbiguousTailAmount {
                    count: candidates.len(),
                });
            }
        };
        Ok(Self {
            master_record_number: u32_at(input, COUNTERPART_MASTER_OFFSET),
            account_record_number: u32_at(input, account_offset),
            date_raw: u32_at(input, COUNTERPART_DATE_OFFSET),
            kind: input[3],
            signed_cents,
            canonical_zero_amount,
        })
    }
    /// Returns the controlled master record number.
    #[must_use]
    pub const fn master_record_number(&self) -> u32 {
        self.master_record_number
    }
    /// Returns the controlled counterpart account record number.
    #[must_use]
    pub const fn account_record_number(&self) -> u32 {
        self.account_record_number
    }
    /// Returns the opaque raw date token.
    #[must_use]
    pub const fn date_raw(&self) -> u32 {
        self.date_raw
    }
    /// Returns the observed counterpart row kind.
    #[must_use]
    pub const fn kind(&self) -> u8 {
        self.kind
    }
    /// Returns the bounded signed cents amount.
    #[must_use]
    pub const fn signed_cents(&self) -> i64 {
        self.signed_cents
    }
    /// Returns whether the exact canonical zero token was used.
    #[must_use]
    pub const fn has_canonical_zero_amount(&self) -> bool {
        self.canonical_zero_amount
    }
}

/// A validated, controlled-family materialized Deposit posting row.
///
/// `date_raw` and `view_type` intentionally remain opaque. A zero amount is
/// represented only when the shared controlled numeric codec accepts its exact
/// canonical form; it does not by itself establish row state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedDepositPostingRow {
    target_record_number: u32,
    master_record_number: u32,
    account_record_number: u32,
    date_raw: u32,
    view_type: u16,
    next_target_record_number: Option<u32>,
    source_account_record_number: u32,
    signed_cents: i64,
    canonical_zero_amount: bool,
}

impl MaterializedDepositPostingRow {
    /// Parses one exactly bounded row from the controlled Deposit grammar.
    ///
    /// Rows with kind [`MATERIALIZED_DEPOSIT_POSTING_KIND`] have a next-target
    /// reference at `+0x1a` and source account at `+0x1e`. The only observed
    /// terminal kind moves its source account to `+0x1a`; this shifted form is
    /// rejected for every other kind.
    pub fn parse(input: &[u8]) -> Result<Self, MaterializedDepositPostingRowError> {
        if input.len() < 4 {
            return Err(MaterializedDepositPostingRowError::SegmentTooShort {
                actual: input.len(),
                minimum: 4,
            });
        }
        let declared = usize::from(u16::from_le_bytes([input[0], input[1]]));
        if declared != input.len() {
            return Err(MaterializedDepositPostingRowError::DeclaredLengthMismatch {
                declared,
                actual: input.len(),
            });
        }
        if input[2] != EXPECTED_FLAGS {
            return Err(MaterializedDepositPostingRowError::UnexpectedFlags { actual: input[2] });
        }

        require_reference(u32_at(input, TARGET_OFFSET), "target")?;
        require_reference(u32_at(input, MASTER_OFFSET), "master")?;
        require_reference(u32_at(input, ACCOUNT_OFFSET), "account")?;

        let (next_target_record_number, source_account_record_number, amount_offset) = match input
            [3]
        {
            MATERIALIZED_DEPOSIT_POSTING_KIND => {
                ensure_minimum(input, LINKED_AMOUNT_OFFSET + 2)?;
                (
                    nonzero(u32_at(input, LINK_OR_SOURCE_ACCOUNT_OFFSET)),
                    u32_at(input, SOURCE_ACCOUNT_AFTER_LINK_OFFSET),
                    LINKED_AMOUNT_OFFSET,
                )
            }
            MATERIALIZED_DEPOSIT_TERMINAL_POSTING_KIND => {
                ensure_minimum(input, TERMINAL_AMOUNT_OFFSET + 2)?;
                (
                    None,
                    u32_at(input, LINK_OR_SOURCE_ACCOUNT_OFFSET),
                    TERMINAL_AMOUNT_OFFSET,
                )
            }
            actual => return Err(MaterializedDepositPostingRowError::UnexpectedKind { actual }),
        };
        require_reference(source_account_record_number, "source account")?;
        if let Some(next) = next_target_record_number {
            require_reference(next, "next target")?;
        }

        let (signed_cents, canonical_zero_amount) =
            decode_amount(&input[amount_offset..], amount_offset)?;
        Ok(Self {
            target_record_number: u32_at(input, TARGET_OFFSET),
            master_record_number: u32_at(input, MASTER_OFFSET),
            account_record_number: u32_at(input, ACCOUNT_OFFSET),
            date_raw: u32_at(input, DATE_RAW_OFFSET),
            view_type: u16_at(input, VIEW_TYPE_OFFSET),
            next_target_record_number,
            source_account_record_number,
            signed_cents,
            canonical_zero_amount,
        })
    }

    /// Returns the controlled target record number at `+0x08`.
    #[must_use]
    pub const fn target_record_number(&self) -> u32 {
        self.target_record_number
    }

    /// Returns the controlled master record number at `+0x0c`.
    #[must_use]
    pub const fn master_record_number(&self) -> u32 {
        self.master_record_number
    }

    /// Returns the posting-account record number at `+0x10`.
    #[must_use]
    pub const fn account_record_number(&self) -> u32 {
        self.account_record_number
    }

    /// Returns the opaque raw date token at `+0x14`.
    #[must_use]
    pub const fn date_raw(&self) -> u32 {
        self.date_raw
    }

    /// Returns the opaque view/type value at `+0x18`.
    #[must_use]
    pub const fn view_type(&self) -> u16 {
        self.view_type
    }

    /// Returns the optional next target only for the proven linked form.
    #[must_use]
    pub const fn next_target_record_number(&self) -> Option<u32> {
        self.next_target_record_number
    }

    /// Returns the controlled source account, including the proven terminal shift.
    #[must_use]
    pub const fn source_account_record_number(&self) -> u32 {
        self.source_account_record_number
    }

    /// Returns the controlled signed monetary amount in cents.
    #[must_use]
    pub const fn signed_cents(&self) -> i64 {
        self.signed_cents
    }

    /// Returns whether the exact controlled canonical zero token was used.
    #[must_use]
    pub const fn has_canonical_zero_amount(&self) -> bool {
        self.canonical_zero_amount
    }
}

/// Errors returned by [`MaterializedDepositPostingRow::parse`].
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MaterializedDepositPostingRowError {
    /// A required bounded record reference was zero.
    #[error("materialized Deposit posting row has zero required {field} reference")]
    MissingRequiredReference {
        /// Structural reference label.
        field: &'static str,
    },
    /// More than one end-framed numeric token was structurally valid.
    #[error("materialized Deposit counterpart has {count} valid tail amount tokens")]
    AmbiguousTailAmount {
        /// Number of valid candidate tokens.
        count: usize,
    },
    /// The supplied segment cannot contain the requested fixed fields.
    #[error(
        "materialized Deposit posting row is too short: {actual} bytes (need at least {minimum})"
    )]
    SegmentTooShort {
        /// Number of bytes supplied by the caller.
        actual: usize,
        /// Minimum bytes required for the selected controlled form.
        minimum: usize,
    },
    /// The leading length did not exactly bound the supplied segment.
    #[error(
        "materialized Deposit posting row length mismatch: declared {declared}, actual {actual}"
    )]
    DeclaredLengthMismatch {
        /// Declared little-endian segment length.
        declared: usize,
        /// Actual input length.
        actual: usize,
    },
    /// The flags byte differed from the only controlled witness value.
    #[error("unsupported materialized Deposit posting flags {actual:#04x}")]
    UnexpectedFlags {
        /// Observed flags byte.
        actual: u8,
    },
    /// The kind byte was outside the two controlled Deposit row forms.
    #[error("unsupported materialized Deposit posting kind {actual:#04x}")]
    UnexpectedKind {
        /// Observed kind byte.
        actual: u8,
    },
    /// The bounded numeric token extended beyond the segment.
    #[error(
        "materialized Deposit posting amount declares {digits} base-100 digits beyond a {segment_len}-byte segment"
    )]
    AmountOutsideSegment {
        /// Number of base-100 digits declared by the token.
        digits: usize,
        /// Exact segment length.
        segment_len: usize,
    },
    /// The zero token did not use the exact controlled marker.
    #[error("unsupported zero-length materialized Deposit amount marker {marker:#04x}")]
    UnsupportedZeroAmountMarker {
        /// Observed zero-token marker.
        marker: u8,
    },
    /// The sign/scale marker was not one of the controlled forms.
    #[error("unsupported materialized Deposit amount sign/scale marker {marker:#04x}")]
    UnsupportedAmountMarker {
        /// Observed sign/scale marker.
        marker: u8,
    },
    /// A base-100 digit exceeded 99.
    #[error("invalid materialized Deposit base-100 digit {digit}")]
    InvalidBase100Digit {
        /// Invalid base-100 digit byte.
        digit: u8,
    },
    /// The controlled numeric value did not fit signed cents.
    #[error("materialized Deposit amount exceeded signed cents")]
    AmountOverflow,
}

fn ensure_minimum(input: &[u8], minimum: usize) -> Result<(), MaterializedDepositPostingRowError> {
    if input.len() < minimum {
        Err(MaterializedDepositPostingRowError::SegmentTooShort {
            actual: input.len(),
            minimum,
        })
    } else {
        Ok(())
    }
}

fn require_reference(
    value: u32,
    field: &'static str,
) -> Result<(), MaterializedDepositPostingRowError> {
    (value != 0)
        .then_some(())
        .ok_or(MaterializedDepositPostingRowError::MissingRequiredReference { field })
}

fn decode_amount(
    input: &[u8],
    amount_offset: usize,
) -> Result<(i64, bool), MaterializedDepositPostingRowError> {
    let amount = MaterializedPostingCents::parse(input).map_err(|error| match error {
        MaterializedPostingCentsError::TokenTooShort { .. }
        | MaterializedPostingCentsError::DigitsOutsideToken { digits: 0, .. } => {
            MaterializedDepositPostingRowError::AmountOutsideSegment {
                digits: 0,
                segment_len: input.len() + amount_offset,
            }
        }
        MaterializedPostingCentsError::DigitsOutsideToken { digits, .. } => {
            MaterializedDepositPostingRowError::AmountOutsideSegment {
                digits,
                segment_len: input.len() + amount_offset,
            }
        }
        MaterializedPostingCentsError::UnsupportedZeroMarker { marker } => {
            MaterializedDepositPostingRowError::UnsupportedZeroAmountMarker { marker }
        }
        MaterializedPostingCentsError::UnsupportedMarker { marker } => {
            MaterializedDepositPostingRowError::UnsupportedAmountMarker { marker }
        }
        MaterializedPostingCentsError::InvalidBase100Digit { digit } => {
            MaterializedDepositPostingRowError::InvalidBase100Digit { digit }
        }
        MaterializedPostingCentsError::CentsOverflow => {
            MaterializedDepositPostingRowError::AmountOverflow
        }
    })?;
    Ok((amount.signed_cents(), amount.is_canonical_zero()))
}

fn u16_at(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(input[offset..offset + 2].try_into().expect("fixed bounds"))
}

fn u32_at(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().expect("fixed bounds"))
}

const fn nonzero(value: u32) -> Option<u32> {
    if value == 0 { None } else { Some(value) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        kind: u8,
        target: u32,
        account: u32,
        next: Option<u32>,
        source: u32,
        amount: &[u8],
    ) -> Vec<u8> {
        let amount_offset = if kind == MATERIALIZED_DEPOSIT_TERMINAL_POSTING_KIND {
            TERMINAL_AMOUNT_OFFSET
        } else {
            LINKED_AMOUNT_OFFSET
        };
        let mut row = vec![0_u8; amount_offset + amount.len()];
        let length = row.len() as u16;
        row[..2].copy_from_slice(&length.to_le_bytes());
        row[3] = kind;
        row[TARGET_OFFSET..TARGET_OFFSET + 4].copy_from_slice(&target.to_le_bytes());
        row[MASTER_OFFSET..MASTER_OFFSET + 4].copy_from_slice(&0x0010_0020_u32.to_le_bytes());
        row[ACCOUNT_OFFSET..ACCOUNT_OFFSET + 4].copy_from_slice(&account.to_le_bytes());
        row[DATE_RAW_OFFSET..DATE_RAW_OFFSET + 4].copy_from_slice(&0x0d00_1000_u32.to_le_bytes());
        row[VIEW_TYPE_OFFSET..VIEW_TYPE_OFFSET + 2].copy_from_slice(&2_u16.to_le_bytes());
        row[LINK_OR_SOURCE_ACCOUNT_OFFSET..LINK_OR_SOURCE_ACCOUNT_OFFSET + 4]
            .copy_from_slice(&next.unwrap_or(source).to_le_bytes());
        if kind == MATERIALIZED_DEPOSIT_POSTING_KIND {
            row[SOURCE_ACCOUNT_AFTER_LINK_OFFSET..SOURCE_ACCOUNT_AFTER_LINK_OFFSET + 4]
                .copy_from_slice(&source.to_le_bytes());
        }
        row[amount_offset..].copy_from_slice(amount);
        row
    }

    #[test]
    fn parses_controlled_linked_and_terminal_deposit_rows() {
        let header = MaterializedDepositPostingRow::parse(&row(
            MATERIALIZED_DEPOSIT_POSTING_KIND,
            0x101,
            10,
            Some(0x102),
            10,
            &[2, 0xbf, 0, 3],
        ))
        .unwrap();
        assert_eq!(header.master_record_number(), 0x0010_0020);
        assert_eq!(header.account_record_number(), 10);
        assert_eq!(header.next_target_record_number(), Some(0x102));
        assert_eq!(header.source_account_record_number(), 10);
        assert_eq!(header.date_raw(), 0x0d00_1000);
        assert_eq!(header.view_type(), 2);
        assert_eq!(header.signed_cents(), 300);

        let source = MaterializedDepositPostingRow::parse(&row(
            MATERIALIZED_DEPOSIT_POSTING_KIND,
            0x102,
            20,
            Some(0x103),
            10,
            &[2, 0x3f, 25, 1],
        ))
        .unwrap();
        assert_eq!(source.signed_cents(), -125);
        assert_eq!(source.next_target_record_number(), Some(0x103));

        let terminal = MaterializedDepositPostingRow::parse(&row(
            MATERIALIZED_DEPOSIT_TERMINAL_POSTING_KIND,
            0x103,
            30,
            None,
            10,
            &[2, 0x3f, 75, 1],
        ))
        .unwrap();
        assert_eq!(terminal.signed_cents(), -175);
        assert_eq!(terminal.next_target_record_number(), None);
        assert_eq!(terminal.source_account_record_number(), 10);
    }

    #[test]
    fn rejects_unproven_forms_and_bad_bounds() {
        let linked = row(
            MATERIALIZED_DEPOSIT_POSTING_KIND,
            1,
            2,
            None,
            3,
            &[1, 0xbf, 1],
        );
        let mut bad_length = linked.clone();
        bad_length[0] = 0;
        assert!(matches!(
            MaterializedDepositPostingRow::parse(&bad_length),
            Err(MaterializedDepositPostingRowError::DeclaredLengthMismatch { .. })
        ));
        let unknown_kind = row(0xe2, 1, 2, None, 3, &[1, 0xbf, 1]);
        assert!(matches!(
            MaterializedDepositPostingRow::parse(&unknown_kind),
            Err(MaterializedDepositPostingRowError::UnexpectedKind { actual: 0xe2 })
        ));
        let truncated = row(
            MATERIALIZED_DEPOSIT_TERMINAL_POSTING_KIND,
            1,
            2,
            None,
            3,
            &[3, 0xbf],
        );
        assert!(matches!(
            MaterializedDepositPostingRow::parse(&truncated),
            Err(MaterializedDepositPostingRowError::AmountOutsideSegment { .. })
        ));
    }

    #[test]
    fn parses_sample_counterpart_variants_with_end_framed_amounts() {
        fn counterpart(kind: u8, account: u32, amount: &[u8]) -> Vec<u8> {
            let account_offset = if kind == MATERIALIZED_DEPOSIT_COUNTERPART_F0_KIND {
                COUNTERPART_F0_ACCOUNT_OFFSET
            } else {
                COUNTERPART_F1_ACCOUNT_OFFSET
            };
            let mut row =
                vec![0_u8; account_offset.max(COUNTERPART_DATE_OFFSET) + 4 + amount.len() + 5];
            let amount_start = row.len() - 5 - amount.len();
            row[3] = kind;
            row[COUNTERPART_MASTER_OFFSET..COUNTERPART_MASTER_OFFSET + 4]
                .copy_from_slice(&0x0010_0020_u32.to_le_bytes());
            row[COUNTERPART_DATE_OFFSET..COUNTERPART_DATE_OFFSET + 4]
                .copy_from_slice(&0x0d00_1000_u32.to_le_bytes());
            row[account_offset..account_offset + 4].copy_from_slice(&account.to_le_bytes());
            row[amount_start..amount_start + amount.len()].copy_from_slice(amount);
            let length = row.len();
            row[length - 5..].copy_from_slice(&[1, 2, 3, 4, 5]);
            row[..2].copy_from_slice(&(length as u16).to_le_bytes());
            row
        }
        let compact = MaterializedDepositCounterpartPostingRow::parse(&counterpart(
            MATERIALIZED_DEPOSIT_COUNTERPART_F0_KIND,
            10,
            &[1, 0xc0, 2],
        ))
        .unwrap();
        assert_eq!(compact.account_record_number(), 10);
        assert_eq!(compact.signed_cents(), 200);
        let expanded = MaterializedDepositCounterpartPostingRow::parse(&counterpart(
            MATERIALIZED_DEPOSIT_COUNTERPART_F1_KIND,
            20,
            &[2, 0x3f, 25, 1],
        ))
        .unwrap();
        assert_eq!(expanded.account_record_number(), 20);
        assert_eq!(expanded.signed_cents(), -125);
    }
}

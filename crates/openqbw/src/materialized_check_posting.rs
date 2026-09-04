//! Fail-closed parser for the bounded materialized Check posting-target row.
//!
//! The layout is calibrated only by the controlled two-split Check across its
//! creation and voided current versions.  It accepts already-bounded
//! materialized rows and does not resolve raw QBW pages, table ownership,
//! continuation traversal, account names, document text, or other transaction
//! families.

use thiserror::Error;

use crate::materialized_numeric::{MaterializedPostingCents, MaterializedPostingCentsError};
use crate::{MaterializedPostingDate, MaterializedPostingDateError};

/// Observed materialized target-row kind for the bounded Check posting witness.
pub const MATERIALIZED_CHECK_POSTING_KIND: u8 = 0xe4;

const EXPECTED_FLAGS: u8 = 0;
const TARGET_OFFSET: usize = 0x0c;
const MASTER_OFFSET: usize = 0x10;
const ACCOUNT_OFFSET: usize = 0x14;
const DATE_RAW_OFFSET: usize = 0x18;
const VIEW_TYPE_OFFSET: usize = 0x1c;
const NEXT_TARGET_OFFSET: usize = 0x1e;
const SOURCE_ACCOUNT_OFFSET: usize = 0x22;
const LINKED_EDIT_SEQUENCE_OFFSET: usize = 0x32;
const TERMINAL_EDIT_SEQUENCE_OFFSET: usize = 0x2e;
// The independently calibrated e4 carrier keeps its monetary token at this
// fixed offset for both observed link shapes.  The earlier shape-relative
// offsets pointed into relationship metadata and consequently rejected every
// real target row as an unsupported numeric dialect.
const AMOUNT_OFFSET: usize = 0x53;
const MIN_SEGMENT_LEN: usize = AMOUNT_OFFSET + 2;

/// The two independently witnessed Check target-row link shapes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterializedCheckPostingShape {
    /// `+0x1e` is a next-target candidate and `+0x22` is the source account.
    Linked {
        /// Bounded next target record number; traversal remains out of scope.
        next_target_record_number: u32,
    },
    /// `+0x1e` is the source account and `+0x22` is an exact zero sentinel.
    Terminal,
}

/// A validated, controlled-family Check posting-target row.
///
/// No getter assigns a calendar epoch to `date_raw`, a table/view meaning to
/// `view_type`, or a current/deleted state to a zero amount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedCheckPostingRow {
    target_record_number: u32,
    master_record_number: u32,
    account_record_number: u32,
    date_raw: u32,
    view_type: u16,
    shape: MaterializedCheckPostingShape,
    source_account_record_number: u32,
    edit_sequence: u32,
    signed_cents: i64,
    canonical_zero_amount: bool,
}

impl MaterializedCheckPostingRow {
    /// Parses an exactly bounded materialized Check posting-target segment.
    ///
    /// The caller must provide a segment beginning at the returned materialized
    /// record boundary.  This r1 parser rejects all flags/kinds/numeric
    /// sign-scale forms outside the controlled Check witness.
    pub fn parse(input: &[u8]) -> Result<Self, MaterializedCheckPostingRowError> {
        if input.len() < MIN_SEGMENT_LEN {
            return Err(MaterializedCheckPostingRowError::SegmentTooShort {
                actual: input.len(),
                minimum: MIN_SEGMENT_LEN,
            });
        }
        let declared_len = usize::from(u16::from_le_bytes([input[0], input[1]]));
        if declared_len != input.len() {
            return Err(MaterializedCheckPostingRowError::DeclaredLengthMismatch {
                declared: declared_len,
                actual: input.len(),
            });
        }
        if input[2] != EXPECTED_FLAGS {
            return Err(MaterializedCheckPostingRowError::UnexpectedFlags { actual: input[2] });
        }
        if input[3] != MATERIALIZED_CHECK_POSTING_KIND {
            return Err(MaterializedCheckPostingRowError::UnexpectedKind { actual: input[3] });
        }

        let (shape, source_account_record_number, edit_sequence_offset) =
            if u32_at(input, SOURCE_ACCOUNT_OFFSET) != 0 {
                (
                    MaterializedCheckPostingShape::Linked {
                        next_target_record_number: u32_at(input, NEXT_TARGET_OFFSET),
                    },
                    u32_at(input, SOURCE_ACCOUNT_OFFSET),
                    LINKED_EDIT_SEQUENCE_OFFSET,
                )
            } else {
                (
                    MaterializedCheckPostingShape::Terminal,
                    u32_at(input, NEXT_TARGET_OFFSET),
                    TERMINAL_EDIT_SEQUENCE_OFFSET,
                )
            };
        if source_account_record_number == 0 {
            return Err(MaterializedCheckPostingRowError::MissingSourceAccount { shape });
        }
        let target_record_number = u32_at(input, TARGET_OFFSET);
        let master_record_number = u32_at(input, MASTER_OFFSET);
        let account_record_number = u32_at(input, ACCOUNT_OFFSET);
        if target_record_number == 0 || master_record_number == 0 || account_record_number == 0 {
            return Err(MaterializedCheckPostingRowError::MissingRequiredRecordReference);
        }
        let (signed_cents, canonical_zero_amount) =
            decode_shape_amount(input, shape, AMOUNT_OFFSET)?;
        Ok(Self {
            target_record_number,
            master_record_number,
            account_record_number,
            date_raw: u32_at(input, DATE_RAW_OFFSET),
            view_type: u16_at(input, VIEW_TYPE_OFFSET),
            shape,
            source_account_record_number,
            edit_sequence: u32_at(input, edit_sequence_offset),
            signed_cents,
            canonical_zero_amount,
        })
    }

    /// Returns the controlled target-row record number at `+0x0c`.
    #[must_use]
    pub const fn target_record_number(&self) -> u32 {
        self.target_record_number
    }

    /// Returns the controlled master record number at `+0x10`.
    #[must_use]
    pub const fn master_record_number(&self) -> u32 {
        self.master_record_number
    }

    /// Returns the controlled posting-account record number at `+0x14`.
    #[must_use]
    pub const fn account_record_number(&self) -> u32 {
        self.account_record_number
    }

    /// Returns the stable raw date token at `+0x18` without calendar decoding.
    #[must_use]
    pub const fn date_raw(&self) -> u32 {
        self.date_raw
    }

    /// Returns the exact little-endian date field bits without interpreting
    /// them as an unsigned quantity.
    #[must_use]
    pub const fn date_raw_bits(&self) -> u32 {
        self.date_raw
    }

    /// Decodes the signed SQL Anywhere minute date into a calendar date.
    pub fn posting_date(&self) -> Result<MaterializedPostingDate, MaterializedPostingDateError> {
        MaterializedPostingDate::from_disk_bytes(self.date_raw.to_le_bytes())
    }

    /// Returns the opaque view/type value at `+0x1c`.
    #[must_use]
    pub const fn view_type(&self) -> u16 {
        self.view_type
    }

    /// Returns the independently witnessed linked/terminal layout shape.
    #[must_use]
    pub const fn shape(&self) -> MaterializedCheckPostingShape {
        self.shape
    }

    /// Returns the source account: `+0x22` when linked, `+0x1e` when terminal.
    #[must_use]
    pub const fn source_account_record_number(&self) -> u32 {
        self.source_account_record_number
    }

    /// Returns the shape-specific Check edit-sequence value (`+0x32` linked, `+0x2e` terminal).
    #[must_use]
    pub const fn edit_sequence(&self) -> u32 {
        self.edit_sequence
    }

    /// Returns the r1-calibrated signed monetary cents at the shape-specific field.
    #[must_use]
    pub const fn signed_cents(&self) -> i64 {
        self.signed_cents
    }

    /// Returns whether the amount uses the exact controlled canonical zero token.
    ///
    /// This is not an `is_voided` or current-state flag.
    #[must_use]
    pub const fn has_canonical_zero_amount(&self) -> bool {
        self.canonical_zero_amount
    }
}

/// Errors returned by [`MaterializedCheckPostingRow::parse`].
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MaterializedCheckPostingRowError {
    /// The slice cannot contain every calibrated fixed field and numeric header.
    #[error(
        "materialized Check posting row is too short: {actual} bytes (need at least {minimum})"
    )]
    SegmentTooShort {
        /// Number of bytes supplied by the caller.
        actual: usize,
        /// Minimum bytes required for the r1 grammar.
        minimum: usize,
    },
    /// The leading u16 did not exactly bound the supplied segment.
    #[error("materialized Check posting row length mismatch: declared {declared}, actual {actual}")]
    DeclaredLengthMismatch {
        /// Declared little-endian segment length.
        declared: usize,
        /// Actual input length.
        actual: usize,
    },
    /// The flags byte was not the single calibrated target-row value.
    #[error("unsupported materialized Check posting flags {actual:#04x}")]
    UnexpectedFlags {
        /// Observed flags byte.
        actual: u8,
    },
    /// The row-kind byte was not the calibrated target-row kind.
    #[error("unsupported materialized Check posting kind {actual:#04x}")]
    UnexpectedKind {
        /// Observed row-kind byte.
        actual: u8,
    },
    /// The variable numeric token exceeded the exactly bounded segment.
    #[error(
        "materialized Check posting amount declares {digits} base-100 digits beyond a {segment_len}-byte segment"
    )]
    AmountOutsideSegment {
        /// Number of base-100 digits declared by the token.
        digits: usize,
        /// Exact segment length.
        segment_len: usize,
    },
    /// The r1 amount token had a zero digit count without its canonical zero marker.
    #[error("unsupported zero-length materialized Check amount marker {marker:#04x}")]
    UnsupportedZeroAmountMarker {
        /// Observed sign/scale marker.
        marker: u8,
    },
    /// The r1 amount token used a sign/scale marker outside the calibrated pair.
    #[error("unsupported materialized Check amount sign/scale marker {marker:#04x}")]
    UnsupportedAmountMarker {
        /// Observed sign/scale marker.
        marker: u8,
    },
    /// A declared base-100 digit exceeded 99.
    #[error("invalid materialized Check base-100 digit {digit}")]
    InvalidBase100Digit {
        /// Invalid digit byte.
        digit: u8,
    },
    /// The bounded base-100 amount did not fit signed cents.
    #[error("materialized Check amount exceeded signed cents")]
    AmountOverflow,
    /// The row contains bytes outside every explicitly calibrated amount envelope.
    #[error("materialized Check amount has no attested envelope in a {segment_len}-byte segment")]
    UnattestedAmountEnvelope {
        /// Exact declared row length that did not match a calibrated envelope.
        segment_len: usize,
    },
    /// Neither controlled shape supplied a nonzero source account at its shape-specific offset.
    #[error("materialized Check {shape:?} row lacks a source account")]
    MissingSourceAccount {
        /// Shape selected by the exact `+0x22` sentinel rule.
        shape: MaterializedCheckPostingShape,
    },
    /// A required target, master, or posting-account record reference was zero.
    #[error("materialized Check row lacks a target, master, or posting-account reference")]
    MissingRequiredRecordReference,
}

fn decode_shape_amount(
    input: &[u8],
    shape: MaterializedCheckPostingShape,
    offset: usize,
) -> Result<(i64, bool), MaterializedCheckPostingRowError> {
    let amount =
        match shape {
            MaterializedCheckPostingShape::Linked { .. } => input.get(offset..).ok_or(
                MaterializedCheckPostingRowError::AmountOutsideSegment {
                    digits: 0,
                    segment_len: input.len(),
                },
            )?,
            MaterializedCheckPostingShape::Terminal => {
                let field = input.get(offset..).ok_or(
                    MaterializedCheckPostingRowError::AmountOutsideSegment {
                        digits: 0,
                        segment_len: input.len(),
                    },
                )?;
                // The terminal witness begins its count-prefixed numeric field
                // directly at +0x3a. Bytes before that field are opaque.
                field
            }
        };
    // A direct field is attested only when it consumes the whole bounded
    // carrier.  Parsing a valid numeric prefix while ignoring arbitrary
    // declared bytes would turn an unknown row revision into a current
    // accounting posting.
    let direct_token_len = amount
        .first()
        .and_then(|digits| usize::from(*digits).checked_add(2));
    let direct_is_exact =
        direct_token_len.and_then(|length| offset.checked_add(length)) == Some(input.len());
    let primary_error = match decode_amount(amount, input.len()) {
        // Preserve a malformed numeric diagnostic even if the surrounding
        // envelope is not recognized.
        Err(error) => error,
        Ok(decoded) if direct_is_exact => return Ok(decoded),
        Ok(_) => MaterializedCheckPostingRowError::UnattestedAmountEnvelope {
            segment_len: input.len(),
        },
    };
    match decode_repeated_tail_amount(input) {
        RepeatedTailAmount::Decoded(decoded) => Ok(decoded),
        RepeatedTailAmount::Malformed => Err(primary_error),
        RepeatedTailAmount::NotApplicable => {
            // Enterprise 24 also materializes the same Check amount field
            // after one of three longer nullable/variable envelopes.  Accept
            // an alternate envelope only when exactly one bounded amount is
            // repeated later byte-for-byte in the same row.
            // The only non-tail alternative calibrated so far is the
            // fixed 0x90-byte nullable envelope.  It carries exactly two
            // matching copies at the fixed offsets below.
            if input.len() != 0x90 {
                return Err(primary_error);
            }
            let candidates = [0x6d_usize, 0x80]
                .into_iter()
                .filter_map(|candidate_offset| {
                    let tail = input.get(candidate_offset..)?;
                    let digits = usize::from(*tail.first()?);
                    let token_len = 2_usize.checked_add(digits)?;
                    let token = tail.get(..token_len)?;
                    let decoded = decode_amount(token, input.len()).ok()?;
                    input
                        .get(if candidate_offset == 0x6d { 0x80 } else { 0x6d }..)
                        .is_some_and(|other| other.get(..token_len) == Some(token))
                        .then_some(decoded)
                })
                .collect::<Vec<_>>();
            match candidates.first().copied() {
                Some(decoded) if candidates.iter().all(|candidate| *candidate == decoded) => {
                    Ok(decoded)
                }
                _ => Err(primary_error),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepeatedTailAmount {
    NotApplicable,
    Decoded((i64, bool)),
    Malformed,
}

fn decode_repeated_tail_amount(input: &[u8]) -> RepeatedTailAmount {
    let grammars = [
        (
            matches!(input.len(), 209 | 216 | 217),
            2_usize,
            &[107_usize, 126][..],
        ),
        (true, 6_usize, &[115_usize][..]),
    ];
    let mut saw_signature = false;
    let mut decoded = Vec::new();
    // The bounded e4 family also carries one amount token at +0x6d and
    // repeats that exact token twice in terminal carrier fields. The three
    // fields must not overlap, and the count is bounded by the observed
    // two-to-six-byte token family.
    if input.len() >= 196 {
        collect_triplicate_tail_amount(input, 109, None, &mut saw_signature, &mut decoded);
    }
    // A distinct long nullable family begins at +0x4f and has three
    // length-relative tail copies. Its adjacent first two tail copies are
    // structural, rather than an unrestricted repeated-token search.
    collect_quadruplicate_tail_amount(input, 79, &mut saw_signature, &mut decoded);
    // This fixed 218-byte nullable variant uses +0x7d and the same bounded
    // triplicate tail relation. Its length remains fixed until another
    // independent carrier establishes a variable-length family.
    collect_triplicate_tail_amount(input, 125, Some(218), &mut saw_signature, &mut decoded);
    // The direct +0x53 field can use the same four-copy nullable envelope as
    // +0x4f, with the first numeric token retained before its three terminal
    // copies. A plain direct prefix is still insufficient: all four fields
    // must agree.
    collect_quadruplicate_tail_amount(input, 83, &mut saw_signature, &mut decoded);
    for (length_matches, token_len, prefix_offsets) in grammars {
        if !length_matches
            || input.get(prefix_offsets[0]).copied() != u8::try_from(token_len - 2).ok()
        {
            continue;
        }
        saw_signature = true;
        let Some(second_start) = input.len().checked_sub(token_len + 7) else {
            continue;
        };
        let Some(first_start) = second_start.checked_sub(token_len + 5) else {
            continue;
        };
        let Some(first) = input.get(first_start..first_start + token_len) else {
            continue;
        };
        let Some(second) = input.get(second_start..second_start + token_len) else {
            continue;
        };
        if first != second
            || usize::from(first[0]) + 2 != token_len
            || prefix_offsets
                .iter()
                .any(|offset| input.get(*offset..*offset + token_len) != Some(first))
        {
            continue;
        }
        if let Ok(amount) = decode_amount(first, input.len()) {
            decoded.push(amount);
        }
    }
    // A 215-byte canonical-zero carrier has two fixed copies immediately
    // before the variable tail pair.  It is a separate observed envelope;
    // changing any of the four copies rejects the row.
    if input.len() == 215 {
        let token = [0, 0x81];
        if input.get(106..108) == Some(&token)
            && input.get(125..127) == Some(&token)
            && input.get(199..201) == Some(&token)
            && input.get(206..208) == Some(&token)
        {
            saw_signature = true;
            decoded.push((0, true));
        }
    }
    match decoded.as_slice() {
        [amount] => RepeatedTailAmount::Decoded(*amount),
        [] if !saw_signature => RepeatedTailAmount::NotApplicable,
        _ => RepeatedTailAmount::Malformed,
    }
}

fn bounded_amount_token(input: &[u8], offset: usize) -> Option<&[u8]> {
    let digits = usize::from(*input.get(offset)?);
    let token_len = digits.checked_add(2)?;
    (2..=6)
        .contains(&token_len)
        .then(|| input.get(offset..offset.checked_add(token_len)?))?
}

fn collect_triplicate_tail_amount(
    input: &[u8],
    prefix_offset: usize,
    required_len: Option<usize>,
    saw_signature: &mut bool,
    decoded: &mut Vec<(i64, bool)>,
) {
    if required_len.is_some_and(|length| input.len() != length) {
        return;
    }
    let Some(token) = bounded_amount_token(input, prefix_offset) else {
        return;
    };
    let Ok(amount) = decode_amount(token, input.len()) else {
        return;
    };
    *saw_signature = true;
    let token_len = token.len();
    let Some(second_start) = input.len().checked_sub(token_len + 7) else {
        return;
    };
    let Some(first_start) = second_start.checked_sub(token_len + 5) else {
        return;
    };
    let Some(prefix_end) = prefix_offset.checked_add(token_len) else {
        return;
    };
    if prefix_end > first_start
        || input.get(first_start..first_start + token_len) != Some(token)
        || input.get(second_start..second_start + token_len) != Some(token)
    {
        return;
    }
    decoded.push(amount);
}

fn collect_quadruplicate_tail_amount(
    input: &[u8],
    prefix_offset: usize,
    saw_signature: &mut bool,
    decoded: &mut Vec<(i64, bool)>,
) {
    let Some(token) = bounded_amount_token(input, prefix_offset) else {
        return;
    };
    let Ok(amount) = decode_amount(token, input.len()) else {
        return;
    };
    *saw_signature = true;
    let token_len = token.len();
    let Some(third_start) = input.len().checked_sub(token_len + 7) else {
        return;
    };
    let Some(second_start) = third_start.checked_sub(token_len + 5) else {
        return;
    };
    let Some(first_start) = second_start.checked_sub(token_len) else {
        return;
    };
    let Some(prefix_end) = prefix_offset.checked_add(token_len) else {
        return;
    };
    if prefix_end > first_start
        || input.get(first_start..first_start + token_len) != Some(token)
        || input.get(second_start..second_start + token_len) != Some(token)
        || input.get(third_start..third_start + token_len) != Some(token)
    {
        return;
    }
    decoded.push(amount);
}

fn decode_amount(
    input: &[u8],
    segment_len: usize,
) -> Result<(i64, bool), MaterializedCheckPostingRowError> {
    let amount = MaterializedPostingCents::parse(input).map_err(|error| match error {
        MaterializedPostingCentsError::TokenTooShort { .. }
        | MaterializedPostingCentsError::DigitsOutsideToken { digits: 0, .. } => {
            MaterializedCheckPostingRowError::AmountOutsideSegment {
                digits: 0,
                segment_len,
            }
        }
        MaterializedPostingCentsError::DigitsOutsideToken { digits, .. } => {
            MaterializedCheckPostingRowError::AmountOutsideSegment {
                digits,
                segment_len,
            }
        }
        MaterializedPostingCentsError::UnsupportedZeroMarker { marker } => {
            MaterializedCheckPostingRowError::UnsupportedZeroAmountMarker { marker }
        }
        MaterializedPostingCentsError::UnsupportedMarker { marker } => {
            MaterializedCheckPostingRowError::UnsupportedAmountMarker { marker }
        }
        MaterializedPostingCentsError::InvalidBase100Digit { digit } => {
            MaterializedCheckPostingRowError::InvalidBase100Digit { digit }
        }
        MaterializedPostingCentsError::CentsOverflow => {
            MaterializedCheckPostingRowError::AmountOverflow
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

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MASTER: u32 = 0x0012_3456;
    const SAMPLE_EXPENSE_TARGET: u32 = 0x0012_3457;
    const SAMPLE_ASSET_TARGET: u32 = 0x0012_3458;
    const SAMPLE_BANK_ACCOUNT: u32 = 500;
    const SAMPLE_EXPENSE_ACCOUNT: u32 = 501;
    const SAMPLE_ASSET_ACCOUNT: u32 = 502;
    const SAMPLE_DATE_RAW: u32 = 0x0102_0304;
    const SAMPLE_EDIT_BEFORE: u32 = 42;
    const SAMPLE_EDIT_AFTER: u32 = 43;

    fn row(target: u32, account: u32, next: Option<u32>, amount: &[u8], edit: u32) -> Vec<u8> {
        let amount_offset = AMOUNT_OFFSET;
        let mut row = vec![0_u8; amount_offset + amount.len()];
        let length = row.len() as u16;
        row[..2].copy_from_slice(&length.to_le_bytes());
        row[3] = MATERIALIZED_CHECK_POSTING_KIND;
        row[TARGET_OFFSET..TARGET_OFFSET + 4].copy_from_slice(&target.to_le_bytes());
        row[MASTER_OFFSET..MASTER_OFFSET + 4].copy_from_slice(&SAMPLE_MASTER.to_le_bytes());
        row[ACCOUNT_OFFSET..ACCOUNT_OFFSET + 4].copy_from_slice(&account.to_le_bytes());
        row[DATE_RAW_OFFSET..DATE_RAW_OFFSET + 4].copy_from_slice(&SAMPLE_DATE_RAW.to_le_bytes());
        row[VIEW_TYPE_OFFSET..VIEW_TYPE_OFFSET + 2].copy_from_slice(&3_u16.to_le_bytes());
        if let Some(next) = next {
            row[NEXT_TARGET_OFFSET..NEXT_TARGET_OFFSET + 4].copy_from_slice(&next.to_le_bytes());
            row[SOURCE_ACCOUNT_OFFSET..SOURCE_ACCOUNT_OFFSET + 4]
                .copy_from_slice(&SAMPLE_BANK_ACCOUNT.to_le_bytes());
        } else {
            row[NEXT_TARGET_OFFSET..NEXT_TARGET_OFFSET + 4]
                .copy_from_slice(&SAMPLE_BANK_ACCOUNT.to_le_bytes());
        }
        let edit_offset = if next.is_some() {
            LINKED_EDIT_SEQUENCE_OFFSET
        } else {
            TERMINAL_EDIT_SEQUENCE_OFFSET
        };
        row[edit_offset..edit_offset + 4].copy_from_slice(&edit.to_le_bytes());
        row[amount_offset..].copy_from_slice(amount);
        row
    }

    #[test]
    fn parses_prevoid_split_targets_and_their_chain() {
        let expense = MaterializedCheckPostingRow::parse(&row(
            SAMPLE_EXPENSE_TARGET,
            SAMPLE_EXPENSE_ACCOUNT,
            Some(SAMPLE_ASSET_TARGET),
            &[2, 0xbf, 41, 37],
            SAMPLE_EDIT_BEFORE,
        ))
        .unwrap();
        assert_eq!(expense.master_record_number(), SAMPLE_MASTER);
        assert_eq!(expense.account_record_number(), SAMPLE_EXPENSE_ACCOUNT);
        assert_eq!(
            expense.shape(),
            MaterializedCheckPostingShape::Linked {
                next_target_record_number: SAMPLE_ASSET_TARGET,
            }
        );
        assert_eq!(expense.source_account_record_number(), SAMPLE_BANK_ACCOUNT);
        assert_eq!(expense.date_raw(), SAMPLE_DATE_RAW);
        assert_eq!(expense.view_type(), 3);
        assert_eq!(expense.signed_cents(), 3741);
        assert!(!expense.has_canonical_zero_amount());

        let asset = MaterializedCheckPostingRow::parse(&row(
            SAMPLE_ASSET_TARGET,
            SAMPLE_ASSET_ACCOUNT,
            None,
            &[3, 0xbf, 5, 0, 10],
            SAMPLE_EDIT_BEFORE,
        ))
        .unwrap();
        assert_eq!(asset.signed_cents(), 100_005);
        assert_eq!(asset.shape(), MaterializedCheckPostingShape::Terminal);
        assert_eq!(asset.source_account_record_number(), SAMPLE_BANK_ACCOUNT);
        assert_eq!(asset.edit_sequence(), SAMPLE_EDIT_BEFORE);
    }

    #[test]
    fn parses_negative_header_and_canonical_void_zero() {
        let header = MaterializedCheckPostingRow::parse(&row(
            SAMPLE_MASTER + 1,
            SAMPLE_BANK_ACCOUNT,
            Some(SAMPLE_EXPENSE_TARGET),
            &[3, 0x3f, 46, 37, 10],
            SAMPLE_EDIT_BEFORE,
        ))
        .unwrap();
        assert_eq!(header.signed_cents(), -103_746);

        let voided = MaterializedCheckPostingRow::parse(&row(
            SAMPLE_EXPENSE_TARGET,
            SAMPLE_EXPENSE_ACCOUNT,
            Some(SAMPLE_ASSET_TARGET),
            &[0, 0x81],
            SAMPLE_EDIT_AFTER,
        ))
        .unwrap();
        assert_eq!(voided.signed_cents(), 0);
        assert!(voided.has_canonical_zero_amount());
        assert_eq!(voided.edit_sequence(), SAMPLE_EDIT_AFTER);
    }

    #[test]
    fn alternate_amount_envelope_requires_one_repeated_value() {
        let mut extended = row(
            SAMPLE_EXPENSE_TARGET,
            SAMPLE_EXPENSE_ACCOUNT,
            None,
            &[1, 0x14, 0],
            SAMPLE_EDIT_BEFORE,
        );
        extended.resize(0x90, 0);
        let extended_len = extended.len() as u16;
        extended[..2].copy_from_slice(&extended_len.to_le_bytes());
        let amount = [2, 0xbf, 41, 37];
        extended[0x6d..0x6d + amount.len()].copy_from_slice(&amount);
        extended[0x80..0x80 + amount.len()].copy_from_slice(&amount);
        assert_eq!(
            MaterializedCheckPostingRow::parse(&extended)
                .unwrap()
                .signed_cents(),
            3_741
        );

        let mut ambiguous = extended;
        ambiguous.resize(0xa0, 0);
        let ambiguous_len = ambiguous.len() as u16;
        ambiguous[..2].copy_from_slice(&ambiguous_len.to_le_bytes());
        let other = [1, 0x3f, 9];
        ambiguous[0x4f..0x4f + other.len()].copy_from_slice(&other);
        ambiguous[0x94..0x94 + other.len()].copy_from_slice(&other);
        assert!(MaterializedCheckPostingRow::parse(&ambiguous).is_err());
    }

    #[test]
    fn rejects_a_valid_amount_prefix_with_unattested_declared_tail_bytes() {
        let mut extended = row(
            SAMPLE_EXPENSE_TARGET,
            SAMPLE_EXPENSE_ACCOUNT,
            None,
            &[2, 0xbf, 41, 37],
            SAMPLE_EDIT_BEFORE,
        );
        extended.extend_from_slice(&[0xde, 0xad]);
        let extended_len = extended.len();
        extended[..2].copy_from_slice(&(extended_len as u16).to_le_bytes());
        assert_eq!(
            MaterializedCheckPostingRow::parse(&extended),
            Err(MaterializedCheckPostingRowError::UnattestedAmountEnvelope {
                segment_len: extended_len,
            })
        );
    }

    #[test]
    fn repeated_tail_zero_envelope_requires_all_four_exact_copies() {
        for envelope_len in [209_usize, 216, 217] {
            let mut extended = row(
                SAMPLE_EXPENSE_TARGET,
                SAMPLE_EXPENSE_ACCOUNT,
                None,
                &[1, 0x14, 0],
                SAMPLE_EDIT_BEFORE,
            );
            extended.resize(envelope_len, 0);
            extended[..2].copy_from_slice(&(envelope_len as u16).to_le_bytes());
            let zero = [0, 0x81];
            for offset in [107, 126, envelope_len - 16, envelope_len - 9] {
                extended[offset..offset + zero.len()].copy_from_slice(&zero);
            }
            let parsed = MaterializedCheckPostingRow::parse(&extended).unwrap();
            assert_eq!(parsed.signed_cents(), 0);
            assert!(parsed.has_canonical_zero_amount());

            extended[envelope_len - 9 + 1] ^= 1;
            assert!(MaterializedCheckPostingRow::parse(&extended).is_err());
        }

        let mut unsupported_len = row(
            SAMPLE_EXPENSE_TARGET,
            SAMPLE_EXPENSE_ACCOUNT,
            None,
            &[1, 0x14, 0],
            SAMPLE_EDIT_BEFORE,
        );
        unsupported_len.resize(218, 0);
        unsupported_len[..2].copy_from_slice(&218_u16.to_le_bytes());
        for offset in [107, 126, 218 - 16, 218 - 9] {
            unsupported_len[offset..offset + 2].copy_from_slice(&[0, 0x81]);
        }
        assert!(MaterializedCheckPostingRow::parse(&unsupported_len).is_err());
    }

    #[test]
    fn repeated_tail_variable_envelopes_require_their_exact_prefix_and_tail_copies() {
        for (envelope_len, amount, expected) in [
            (217_usize, vec![1, 0xbf, 7], 7_i64),
            (209_usize, vec![1, 0xbf, 7], 7_i64),
            (216_usize, vec![2, 0xbf, 41, 37], 3_741_i64),
        ] {
            let mut extended = row(
                SAMPLE_EXPENSE_TARGET,
                SAMPLE_EXPENSE_ACCOUNT,
                None,
                &[1, 0x14, 0],
                SAMPLE_EDIT_BEFORE,
            );
            extended.resize(envelope_len, 0);
            extended[..2].copy_from_slice(&(envelope_len as u16).to_le_bytes());
            let token_len = amount.len();
            let second_tail = envelope_len - token_len - 7;
            let first_tail = second_tail - token_len - 5;
            for offset in [109, first_tail, second_tail] {
                extended[offset..offset + token_len].copy_from_slice(&amount);
            }
            extended[129..131].copy_from_slice(&[0, 0x81]);
            assert_eq!(
                MaterializedCheckPostingRow::parse(&extended)
                    .unwrap()
                    .signed_cents(),
                expected
            );

            extended[second_tail + token_len - 1] ^= 1;
            assert!(MaterializedCheckPostingRow::parse(&extended).is_err());
        }
    }

    #[test]
    fn variable_triplicate_envelope_binds_the_counted_token_to_both_tail_offsets() {
        let envelope_len = 236_usize;
        let mut extended = row(
            SAMPLE_EXPENSE_TARGET,
            SAMPLE_EXPENSE_ACCOUNT,
            None,
            &[1, 0x14, 0],
            SAMPLE_EDIT_BEFORE,
        );
        extended.resize(envelope_len, 0);
        extended[..2].copy_from_slice(&(envelope_len as u16).to_le_bytes());
        let amount = [3, 0xbf, 41, 37, 12];
        let token_len = amount.len();
        let second_tail = envelope_len - token_len - 7;
        let first_tail = second_tail - token_len - 5;
        for offset in [109, first_tail, second_tail] {
            extended[offset..offset + token_len].copy_from_slice(&amount);
        }
        assert_eq!(
            MaterializedCheckPostingRow::parse(&extended)
                .unwrap()
                .signed_cents(),
            123_741
        );

        for offset in [109, first_tail, second_tail] {
            let mut changed = extended.clone();
            changed[offset + token_len - 1] ^= 1;
            assert!(MaterializedCheckPostingRow::parse(&changed).is_err());
        }
        let mut changed_count = extended.clone();
        changed_count[109] = 2;
        assert!(MaterializedCheckPostingRow::parse(&changed_count).is_err());
        let mut truncated = extended;
        truncated.pop();
        let truncated_len = truncated.len() as u16;
        truncated[..2].copy_from_slice(&truncated_len.to_le_bytes());
        assert!(MaterializedCheckPostingRow::parse(&truncated).is_err());
    }

    #[test]
    fn observed_215_byte_canonical_zero_envelope_requires_all_four_copies() {
        let envelope_len = 215_usize;
        let mut extended = row(
            SAMPLE_EXPENSE_TARGET,
            SAMPLE_EXPENSE_ACCOUNT,
            None,
            &[1, 0x14, 0],
            SAMPLE_EDIT_BEFORE,
        );
        extended.resize(envelope_len, 0);
        extended[..2].copy_from_slice(&(envelope_len as u16).to_le_bytes());
        let zero = [0, 0x81];
        for offset in [106, 125, 199, 206] {
            extended[offset..offset + zero.len()].copy_from_slice(&zero);
        }
        let parsed = MaterializedCheckPostingRow::parse(&extended).unwrap();
        assert_eq!(parsed.signed_cents(), 0);
        assert!(parsed.has_canonical_zero_amount());

        for offset in [106, 125, 199, 206] {
            let mut changed = extended.clone();
            changed[offset + 1] ^= 1;
            assert!(MaterializedCheckPostingRow::parse(&changed).is_err());
        }
        let mut shifted = row(
            SAMPLE_EXPENSE_TARGET,
            SAMPLE_EXPENSE_ACCOUNT,
            None,
            &[1, 0x14, 0],
            SAMPLE_EDIT_BEFORE,
        );
        shifted.resize(envelope_len, 0);
        shifted[..2].copy_from_slice(&(envelope_len as u16).to_le_bytes());
        for offset in [107, 126, 199, 206] {
            shifted[offset..offset + zero.len()].copy_from_slice(&zero);
        }
        assert!(MaterializedCheckPostingRow::parse(&shifted).is_err());
    }

    #[test]
    fn quadruplicate_4f_envelope_requires_each_bounded_copy() {
        let envelope_len = 206_usize;
        let mut extended = row(
            SAMPLE_EXPENSE_TARGET,
            SAMPLE_EXPENSE_ACCOUNT,
            None,
            &[1, 0x14, 0],
            SAMPLE_EDIT_BEFORE,
        );
        extended.resize(envelope_len, 0);
        extended[..2].copy_from_slice(&(envelope_len as u16).to_le_bytes());
        let amount = [3, 0xbf, 41, 37, 12];
        let token_len = amount.len();
        let third_tail = envelope_len - token_len - 7;
        let second_tail = third_tail - token_len - 5;
        let first_tail = second_tail - token_len;
        for offset in [79, first_tail, second_tail, third_tail] {
            extended[offset..offset + token_len].copy_from_slice(&amount);
        }
        assert_eq!(
            MaterializedCheckPostingRow::parse(&extended)
                .unwrap()
                .signed_cents(),
            123_741
        );
        for offset in [79, first_tail, second_tail, third_tail] {
            let mut changed = extended.clone();
            changed[offset + token_len - 1] ^= 1;
            assert!(MaterializedCheckPostingRow::parse(&changed).is_err());
        }
    }

    #[test]
    fn direct_quadruplicate_envelope_does_not_accept_an_unattested_suffix() {
        let envelope_len = 188_usize;
        let mut extended = row(
            SAMPLE_EXPENSE_TARGET,
            SAMPLE_EXPENSE_ACCOUNT,
            None,
            &[1, 0x14, 0],
            SAMPLE_EDIT_BEFORE,
        );
        extended.resize(envelope_len, 0);
        extended[..2].copy_from_slice(&(envelope_len as u16).to_le_bytes());
        let amount = [3, 0xbf, 41, 37, 12];
        let token_len = amount.len();
        let third_tail = envelope_len - token_len - 7;
        let second_tail = third_tail - token_len - 5;
        let first_tail = second_tail - token_len;
        for offset in [AMOUNT_OFFSET, first_tail, second_tail, third_tail] {
            extended[offset..offset + token_len].copy_from_slice(&amount);
        }
        assert_eq!(
            MaterializedCheckPostingRow::parse(&extended)
                .unwrap()
                .signed_cents(),
            123_741
        );
        for offset in [AMOUNT_OFFSET, first_tail, second_tail, third_tail] {
            let mut changed = extended.clone();
            changed[offset + token_len - 1] ^= 1;
            assert!(MaterializedCheckPostingRow::parse(&changed).is_err());
        }
    }

    #[test]
    fn fixed_218_byte_7d_envelope_requires_its_three_bounded_copies() {
        let envelope_len = 218_usize;
        let mut extended = row(
            SAMPLE_EXPENSE_TARGET,
            SAMPLE_EXPENSE_ACCOUNT,
            None,
            &[1, 0x14, 0],
            SAMPLE_EDIT_BEFORE,
        );
        extended.resize(envelope_len, 0);
        extended[..2].copy_from_slice(&(envelope_len as u16).to_le_bytes());
        let amount = [3, 0xbf, 41, 37, 12];
        let token_len = amount.len();
        let second_tail = envelope_len - token_len - 7;
        let first_tail = second_tail - token_len - 5;
        for offset in [125, first_tail, second_tail] {
            extended[offset..offset + token_len].copy_from_slice(&amount);
        }
        assert_eq!(
            MaterializedCheckPostingRow::parse(&extended)
                .unwrap()
                .signed_cents(),
            123_741
        );
        for offset in [125, first_tail, second_tail] {
            let mut changed = extended.clone();
            changed[offset + token_len - 1] ^= 1;
            assert!(MaterializedCheckPostingRow::parse(&changed).is_err());
        }
    }

    #[test]
    fn overlapping_triplicate_grammars_remain_ambiguous() {
        let envelope_len = 240_usize;
        let mut extended = row(
            SAMPLE_EXPENSE_TARGET,
            SAMPLE_EXPENSE_ACCOUNT,
            None,
            &[1, 0x14, 0],
            SAMPLE_EDIT_BEFORE,
        );
        extended.resize(envelope_len, 0);
        extended[..2].copy_from_slice(&(envelope_len as u16).to_le_bytes());
        let amount = [4, 0xbf, 1, 2, 3, 4];
        for offset in [109, 216, 227, 115, 222] {
            extended[offset..offset + amount.len()].copy_from_slice(&amount);
        }
        assert!(MaterializedCheckPostingRow::parse(&extended).is_err());
    }

    #[test]
    fn repeated_tail_nonzero_envelope_uses_only_its_three_proven_copies() {
        let envelope_len = 240_usize;
        let mut extended = row(
            SAMPLE_EXPENSE_TARGET,
            SAMPLE_EXPENSE_ACCOUNT,
            None,
            &[1, 0x14, 0],
            SAMPLE_EDIT_BEFORE,
        );
        extended.resize(envelope_len, 0);
        extended[..2].copy_from_slice(&(envelope_len as u16).to_le_bytes());
        let amount = [4, 0xbf, 1, 2, 3, 4];
        for offset in [115, envelope_len - 24, envelope_len - 13] {
            extended[offset..offset + amount.len()].copy_from_slice(&amount);
        }
        // A different, repeated valid token at legacy candidate locations
        // must not displace the independently attested tail grammar.
        extended[0x4f..0x51].copy_from_slice(&[0, 0x81]);
        extended[0x6a..0x6c].copy_from_slice(&[0, 0x81]);
        assert_eq!(
            MaterializedCheckPostingRow::parse(&extended)
                .unwrap()
                .signed_cents(),
            4_030_201
        );

        extended[envelope_len - 13 + 2] ^= 1;
        assert!(MaterializedCheckPostingRow::parse(&extended).is_err());
    }

    #[test]
    fn rejects_other_dialects_and_malformed_numeric_bounds() {
        let mut malformed = row(1, 2, None, &[2, 0xbf, 1, 2], 3);
        malformed[0] = 0;
        assert!(matches!(
            MaterializedCheckPostingRow::parse(&malformed),
            Err(MaterializedCheckPostingRowError::DeclaredLengthMismatch { .. })
        ));
        let unsupported = row(1, 2, None, &[1, 0x99, 1], 3);
        assert!(matches!(
            MaterializedCheckPostingRow::parse(&unsupported),
            Err(MaterializedCheckPostingRowError::UnsupportedAmountMarker { marker: 0x99 })
        ));
        let truncated = row(1, 2, None, &[3, 0xbf], 3);
        assert!(matches!(
            MaterializedCheckPostingRow::parse(&truncated),
            Err(MaterializedCheckPostingRowError::AmountOutsideSegment { .. })
        ));
    }

    #[test]
    fn rejects_zero_required_references_and_exposes_signed_date_bits() {
        let mut missing_target = row(0, SAMPLE_EXPENSE_ACCOUNT, None, &[2, 0xbf, 1, 1], 3);
        assert!(matches!(
            MaterializedCheckPostingRow::parse(&missing_target),
            Err(MaterializedCheckPostingRowError::MissingRequiredRecordReference)
        ));
        missing_target = row(1, SAMPLE_EXPENSE_ACCOUNT, None, &[2, 0xbf, 1, 1], 3);
        missing_target[MASTER_OFFSET..MASTER_OFFSET + 4].fill(0);
        assert!(matches!(
            MaterializedCheckPostingRow::parse(&missing_target),
            Err(MaterializedCheckPostingRowError::MissingRequiredRecordReference)
        ));
        missing_target = row(1, 0, None, &[2, 0xbf, 1, 1], 3);
        assert!(matches!(
            MaterializedCheckPostingRow::parse(&missing_target),
            Err(MaterializedCheckPostingRowError::MissingRequiredRecordReference)
        ));
        let parsed = MaterializedCheckPostingRow::parse(&row(
            1,
            SAMPLE_EXPENSE_ACCOUNT,
            None,
            &[2, 0xbf, 1, 1],
            3,
        ))
        .unwrap();
        assert_eq!(parsed.date_raw_bits(), SAMPLE_DATE_RAW);

        let expected_date = MaterializedPostingDate::from_ymd(2024, 2, 29).unwrap();
        let mut dated = row(1, SAMPLE_EXPENSE_ACCOUNT, None, &[2, 0xbf, 1, 1], 3);
        dated[DATE_RAW_OFFSET..DATE_RAW_OFFSET + 4]
            .copy_from_slice(&expected_date.raw_minutes().to_le_bytes());
        assert_eq!(
            MaterializedCheckPostingRow::parse(&dated)
                .unwrap()
                .posting_date()
                .unwrap(),
            expected_date
        );
    }
}

//! Fail-closed parsers for controlled materialized General Journal rows.
//!
//! The two observed row shapes are modeled separately. A source/link row and
//! a posting-target row share their leading flags/kind, but place identifiers
//! and dates at different offsets. Neither parser determines current/deleted
//! state, assigns a calendar epoch, or authorizes link traversal.

use thiserror::Error;

use crate::materialized_numeric::{MaterializedPostingCents, MaterializedPostingCentsError};

/// Observed flags byte shared by the controlled General Journal row shapes.
pub const MATERIALIZED_GENERAL_JOURNAL_FLAGS: u8 = 0x40;
/// Observed row-kind byte shared by the controlled General Journal row shapes.
pub const MATERIALIZED_GENERAL_JOURNAL_ROW_KIND: u8 = 0x01;

const SOURCE_RECORD: usize = 0x0b;
const SOURCE_MASTER: usize = 0x0f;
const SOURCE_DATE: usize = 0x13;
const SOURCE_VIEW: usize = 0x17;
const SOURCE_NEXT: usize = 0x19;
const SOURCE_ACCOUNT: usize = 0x1d;
const SOURCE_MIN_LEN: usize = SOURCE_ACCOUNT + 4;
const SOURCE_LAYOUT_PREFIX: [u8; 7] = [0x60, 0x93, 0xff, 0x80, 0x40, 0x00, 0x20];
const SOURCE_LAYOUT_PREFIX_OFFSET: usize = 0x04;

const TARGET_RECORD: usize = 0x0b;
const TARGET_MASTER: usize = 0x0f;
const TARGET_ACCOUNT: usize = 0x13;
const TARGET_DATE: usize = 0x17;
const TARGET_VIEW: usize = 0x1b;
const TARGET_NEXT: usize = 0x1d;
const TERMINAL_LINK_TAIL: usize = 0x21;
const LINKED_TARGET_LAYOUT_MARKER: u8 = 0x83;
const TERMINAL_TARGET_LAYOUT_MARKER: u8 = 0x03;
const TARGET_LAYOUT_MARKER_OFFSET: usize = 0x05;
const LINKED_TARGET_AMOUNT: usize = 0x67;
const TERMINAL_TARGET_AMOUNT: usize = 0x63;
const TARGET_MIN_LEN: usize = TERMINAL_TARGET_AMOUNT + 2;

/// A controlled General Journal source/link row.
///
/// This is structural evidence, not a posting: it has no monetary amount and
/// its optional link is intentionally not traversed here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedGeneralJournalSourceLinkRow {
    source_link_record_number: u32,
    master_record_number: u32,
    date_raw: u32,
    view_type: u16,
    next_target_record_number: Option<u32>,
    account_record_number: u32,
}

impl MaterializedGeneralJournalSourceLinkRow {
    /// Parses an exactly bounded controlled General Journal source/link row.
    pub fn parse(input: &[u8]) -> Result<Self, MaterializedGeneralJournalPostingRowError> {
        validate_header(input, SOURCE_MIN_LEN)?;
        if input.len() != SOURCE_MIN_LEN {
            return Err(
                MaterializedGeneralJournalPostingRowError::UnexpectedTrailingData {
                    expected_end: SOURCE_MIN_LEN,
                    segment_len: input.len(),
                },
            );
        }
        if input
            [SOURCE_LAYOUT_PREFIX_OFFSET..SOURCE_LAYOUT_PREFIX_OFFSET + SOURCE_LAYOUT_PREFIX.len()]
            != SOURCE_LAYOUT_PREFIX
        {
            return Err(MaterializedGeneralJournalPostingRowError::UnexpectedSourceLayoutPrefix);
        }
        let source_link_record_number = required_reference(input, SOURCE_RECORD, "source/link")?;
        let master_record_number = required_reference(input, SOURCE_MASTER, "master")?;
        let account_record_number = required_reference(input, SOURCE_ACCOUNT, "account")?;
        Ok(Self {
            source_link_record_number,
            master_record_number,
            date_raw: u32_at(input, SOURCE_DATE),
            view_type: u16_at(input, SOURCE_VIEW),
            next_target_record_number: nonzero(u32_at(input, SOURCE_NEXT)),
            account_record_number,
        })
    }

    /// Returns the source/link record number at `+0x0b`.
    #[must_use]
    pub const fn source_link_record_number(&self) -> u32 {
        self.source_link_record_number
    }
    /// Returns the master record number at `+0x0f`.
    #[must_use]
    pub const fn master_record_number(&self) -> u32 {
        self.master_record_number
    }
    /// Returns the opaque raw date at `+0x13`.
    #[must_use]
    pub const fn date_raw(&self) -> u32 {
        self.date_raw
    }
    /// Returns the opaque view/type value at `+0x17`.
    #[must_use]
    pub const fn view_type(&self) -> u16 {
        self.view_type
    }
    /// Returns the optional link candidate at `+0x19`, without traversing it.
    #[must_use]
    pub const fn next_target_record_number(&self) -> Option<u32> {
        self.next_target_record_number
    }
    /// Returns the account record number at `+0x1d`.
    #[must_use]
    pub const fn account_record_number(&self) -> u32 {
        self.account_record_number
    }
}

/// The controlled layout family of a General Journal posting-target row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterializedGeneralJournalPostingTargetShape {
    /// A target with a nonterminal `next_target_record_number` field and its
    /// amount token at `+0x67`.
    Linked,
    /// A terminal target with no next target and its amount token at `+0x63`.
    Terminal,
}

/// A controlled General Journal posting-target row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedGeneralJournalPostingTargetRow {
    target_record_number: u32,
    master_record_number: u32,
    account_record_number: u32,
    date_raw: u32,
    view_type: u16,
    next_target_record_number: Option<u32>,
    shape: MaterializedGeneralJournalPostingTargetShape,
    signed_cents: i64,
    canonical_zero_amount: bool,
}

impl MaterializedGeneralJournalPostingTargetRow {
    /// Parses an exactly bounded controlled General Journal posting-target row.
    pub fn parse(input: &[u8]) -> Result<Self, MaterializedGeneralJournalPostingRowError> {
        validate_header(input, TARGET_MIN_LEN)?;
        let (shape, amount_offset) = match input[TARGET_LAYOUT_MARKER_OFFSET] {
            LINKED_TARGET_LAYOUT_MARKER => (
                MaterializedGeneralJournalPostingTargetShape::Linked,
                LINKED_TARGET_AMOUNT,
            ),
            TERMINAL_TARGET_LAYOUT_MARKER => (
                MaterializedGeneralJournalPostingTargetShape::Terminal,
                TERMINAL_TARGET_AMOUNT,
            ),
            actual => {
                return Err(
                    MaterializedGeneralJournalPostingRowError::UnexpectedTargetLayoutMarker {
                        actual,
                    },
                );
            }
        };
        if input.len() < amount_offset + 2 {
            return Err(MaterializedGeneralJournalPostingRowError::SegmentTooShort {
                actual: input.len(),
                minimum: amount_offset + 2,
            });
        }
        let amount = decode_amount(&input[amount_offset..], amount_offset)?;
        let target_record_number = required_reference(input, TARGET_RECORD, "target")?;
        let master_record_number = required_reference(input, TARGET_MASTER, "master")?;
        let account_record_number = required_reference(input, TARGET_ACCOUNT, "account")?;
        let next_target = u32_at(input, TARGET_NEXT);
        if shape == MaterializedGeneralJournalPostingTargetShape::Linked && next_target == 0 {
            return Err(MaterializedGeneralJournalPostingRowError::MissingLinkedTargetRecordNumber);
        }
        if shape == MaterializedGeneralJournalPostingTargetShape::Terminal
            && (next_target != 0 || u32_at(input, TERMINAL_LINK_TAIL) != 0)
        {
            return Err(
                MaterializedGeneralJournalPostingRowError::UnexpectedTerminalLinkFields {
                    next_target,
                    link_tail: u32_at(input, TERMINAL_LINK_TAIL),
                },
            );
        }
        Ok(Self {
            target_record_number,
            master_record_number,
            account_record_number,
            date_raw: u32_at(input, TARGET_DATE),
            view_type: u16_at(input, TARGET_VIEW),
            next_target_record_number: nonzero(next_target),
            shape,
            signed_cents: amount.signed_cents(),
            canonical_zero_amount: amount.is_canonical_zero(),
        })
    }

    /// Returns the posting-target record number at `+0x0b`.
    #[must_use]
    pub const fn target_record_number(&self) -> u32 {
        self.target_record_number
    }
    /// Returns the master record number at `+0x0f`.
    #[must_use]
    pub const fn master_record_number(&self) -> u32 {
        self.master_record_number
    }
    /// Returns the posting account record number at `+0x13`.
    #[must_use]
    pub const fn account_record_number(&self) -> u32 {
        self.account_record_number
    }
    /// Returns the opaque raw date at `+0x17`.
    #[must_use]
    pub const fn date_raw(&self) -> u32 {
        self.date_raw
    }
    /// Returns the opaque view/type value at `+0x1b`.
    #[must_use]
    pub const fn view_type(&self) -> u16 {
        self.view_type
    }
    /// Returns the optional same-master link candidate at `+0x1d`.
    #[must_use]
    pub const fn next_target_record_number(&self) -> Option<u32> {
        self.next_target_record_number
    }
    /// Returns the observed target layout, including its amount offset.
    #[must_use]
    pub const fn shape(&self) -> MaterializedGeneralJournalPostingTargetShape {
        self.shape
    }
    /// Returns the controlled signed cents amount at the shape-specific offset.
    #[must_use]
    pub const fn signed_cents(&self) -> i64 {
        self.signed_cents
    }
    /// Returns whether the amount is the observed canonical zero token.
    /// This is not a current/deleted/voided-state determination.
    #[must_use]
    pub const fn has_canonical_zero_amount(&self) -> bool {
        self.canonical_zero_amount
    }
}

/// Rejection reasons for the controlled General Journal row parsers.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MaterializedGeneralJournalPostingRowError {
    /// The supplied segment cannot contain the calibrated fixed fields.
    #[error(
        "materialized General Journal row is too short: {actual} bytes (need at least {minimum})"
    )]
    SegmentTooShort {
        /// Actual supplied bytes.
        actual: usize,
        /// Minimum bytes.
        minimum: usize,
    },
    /// The leading length field did not exactly bound the supplied segment.
    #[error(
        "materialized General Journal row length mismatch: declared {declared}, actual {actual}"
    )]
    DeclaredLengthMismatch {
        /// Declared bytes.
        declared: usize,
        /// Actual bytes.
        actual: usize,
    },
    /// The flags byte was outside the controlled witness.
    #[error("unsupported materialized General Journal row flags {actual:#04x}")]
    UnexpectedFlags {
        /// Observed flags.
        actual: u8,
    },
    /// The row kind was outside the controlled witness.
    #[error("unsupported materialized General Journal row kind {actual:#04x}")]
    UnexpectedKind {
        /// Observed kind.
        actual: u8,
    },
    /// The source/link row did not use the controlled structural prefix.
    #[error("unsupported materialized General Journal source/link layout prefix")]
    UnexpectedSourceLayoutPrefix,
    /// The target did not use one of the controlled layout markers.
    #[error("unsupported materialized General Journal target layout marker {actual:#04x}")]
    UnexpectedTargetLayoutMarker {
        /// Observed layout marker at `+0x05`.
        actual: u8,
    },
    /// A terminal target carried nonzero link fields outside the controlled witness.
    #[error(
        "materialized General Journal terminal target has link fields next={next_target:#010x} tail={link_tail:#010x}"
    )]
    UnexpectedTerminalLinkFields {
        /// Value at `+0x1d`.
        next_target: u32,
        /// Value at `+0x21`.
        link_tail: u32,
    },
    /// A linked target did not contain the corroborated nonzero next target.
    #[error("materialized General Journal linked target has no next target record number")]
    MissingLinkedTargetRecordNumber,
    /// A required identifier was the zero sentinel.
    #[error("materialized General Journal row has zero required {field} reference")]
    MissingRequiredReference {
        /// Structural identifier label.
        field: &'static str,
    },
    /// Bytes followed a complete controlled structure or amount token.
    #[error(
        "materialized General Journal row has unrecognized trailing data: expected end {expected_end}, segment is {segment_len} bytes"
    )]
    UnexpectedTrailingData {
        /// First unrecognized byte.
        expected_end: usize,
        /// Exact bounded row length.
        segment_len: usize,
    },
    /// The amount token reached beyond the exactly bounded target row.
    #[error(
        "materialized General Journal target amount declares {digits} base-100 digits beyond a {segment_len}-byte segment"
    )]
    AmountOutsideSegment {
        /// Declared digits.
        digits: usize,
        /// Bounded length.
        segment_len: usize,
    },
    /// The zero-length amount token had an unsupported marker.
    #[error(
        "unsupported zero-length materialized General Journal target amount marker {marker:#04x}"
    )]
    UnsupportedZeroAmountMarker {
        /// Observed marker.
        marker: u8,
    },
    /// The amount token used an unsupported sign/scale marker.
    #[error("unsupported materialized General Journal target amount marker {marker:#04x}")]
    UnsupportedAmountMarker {
        /// Observed marker.
        marker: u8,
    },
    /// A base-100 amount digit exceeded 99.
    #[error("invalid materialized General Journal target base-100 digit {digit}")]
    InvalidBase100Digit {
        /// Invalid digit.
        digit: u8,
    },
    /// The amount cannot fit signed cents.
    #[error("materialized General Journal target amount exceeded signed cents")]
    AmountOverflow,
}

fn validate_header(
    input: &[u8],
    minimum: usize,
) -> Result<(), MaterializedGeneralJournalPostingRowError> {
    if input.len() < minimum {
        return Err(MaterializedGeneralJournalPostingRowError::SegmentTooShort {
            actual: input.len(),
            minimum,
        });
    }
    let declared = usize::from(u16_at(input, 0));
    if declared != input.len() {
        return Err(
            MaterializedGeneralJournalPostingRowError::DeclaredLengthMismatch {
                declared,
                actual: input.len(),
            },
        );
    }
    if input[2] != MATERIALIZED_GENERAL_JOURNAL_FLAGS {
        return Err(MaterializedGeneralJournalPostingRowError::UnexpectedFlags {
            actual: input[2],
        });
    }
    if input[3] != MATERIALIZED_GENERAL_JOURNAL_ROW_KIND {
        return Err(MaterializedGeneralJournalPostingRowError::UnexpectedKind { actual: input[3] });
    }
    Ok(())
}

fn decode_amount(
    input: &[u8],
    amount_offset: usize,
) -> Result<MaterializedPostingCents, MaterializedGeneralJournalPostingRowError> {
    let token_len = input
        .first()
        .and_then(|digits| usize::from(*digits).checked_add(2))
        .ok_or(
            MaterializedGeneralJournalPostingRowError::AmountOutsideSegment {
                digits: 0,
                segment_len: input.len() + amount_offset,
            },
        )?;
    if token_len != input.len() {
        return Err(
            MaterializedGeneralJournalPostingRowError::UnexpectedTrailingData {
                expected_end: amount_offset + token_len,
                segment_len: input.len() + amount_offset,
            },
        );
    }
    MaterializedPostingCents::parse(input).map_err(|error| match error {
        MaterializedPostingCentsError::TokenTooShort { .. }
        | MaterializedPostingCentsError::DigitsOutsideToken { digits: 0, .. } => {
            MaterializedGeneralJournalPostingRowError::AmountOutsideSegment {
                digits: 0,
                segment_len: input.len() + amount_offset,
            }
        }
        MaterializedPostingCentsError::DigitsOutsideToken { digits, .. } => {
            MaterializedGeneralJournalPostingRowError::AmountOutsideSegment {
                digits,
                segment_len: input.len() + amount_offset,
            }
        }
        MaterializedPostingCentsError::UnsupportedZeroMarker { marker } => {
            MaterializedGeneralJournalPostingRowError::UnsupportedZeroAmountMarker { marker }
        }
        MaterializedPostingCentsError::UnsupportedMarker { marker } => {
            MaterializedGeneralJournalPostingRowError::UnsupportedAmountMarker { marker }
        }
        MaterializedPostingCentsError::InvalidBase100Digit { digit } => {
            MaterializedGeneralJournalPostingRowError::InvalidBase100Digit { digit }
        }
        MaterializedPostingCentsError::CentsOverflow => {
            MaterializedGeneralJournalPostingRowError::AmountOverflow
        }
    })
}
fn required_reference(
    input: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<u32, MaterializedGeneralJournalPostingRowError> {
    let value = u32_at(input, offset);
    (value != 0)
        .then_some(value)
        .ok_or(MaterializedGeneralJournalPostingRowError::MissingRequiredReference { field })
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

/// Physical table identifier for the Enterprise General Journal line store.
pub const MATERIALIZED_GENERAL_JOURNAL_POSTING_TABLE_ID: u32 = 3078;

// The production grammar is intentionally separate from the controlled
// delta-row parsers above.  A table-3078 row cannot be accepted merely
// because it has a plausible numeric token: the token must be in one of the
// attested envelopes and be repeated later byte-for-byte.
const PRODUCTION_PREFIX_OFFSET: usize = 0x04;
const PRODUCTION_LINK_MARKER_OFFSET: usize = 0x05;
const PRODUCTION_PREFIX_REQUIRED_BYTE: usize = 0x06;
const PRODUCTION_PREFIX_REQUIRED_VALUE: u8 = 0xff;
const PRODUCTION_SHORT_E4_PREFIX_VALUE: u8 = 0x9f;
const PRODUCTION_TARGET: usize = 0x0b;
const PRODUCTION_MASTER: usize = 0x0f;
const PRODUCTION_ACCOUNT: usize = 0x13;
const PRODUCTION_DATE: usize = 0x17;
const PRODUCTION_VIEW: usize = 0x1b;
const PRODUCTION_NEXT_TARGET: usize = 0x1d;
const PRODUCTION_FIXED_END: usize = PRODUCTION_NEXT_TARGET + 4;
const PRODUCTION_AMOUNT_BASE: usize = 0x63;
const PRODUCTION_AMOUNT_LINKED_SHIFT: usize = 4;

/// The fixed, attested amount envelope used by a posting row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterializedGeneralJournalAmountPosition {
    /// A token at the shape-specific pre-base position.
    MainPrebase,
    /// A token at the direct base position.
    MainDirect,
    /// A token in a separately attested short posting envelope.
    SpecialEnvelope,
}

/// A validated current-layout Enterprise 24 General Journal posting row.
///
/// This parser deliberately requires a byte-identical later copy of its
/// selected amount token.  The duplicate is a structural attestation, not a
/// second posting amount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedGeneralJournalPostingRow {
    target_record_number: u32,
    master_record_number: u32,
    account_record_number: u32,
    date_raw: u32,
    view_type: u16,
    next_target_record_number: Option<u32>,
    family: u8,
    amount_position: MaterializedGeneralJournalAmountPosition,
    signed_cents: i64,
}

impl MaterializedGeneralJournalPostingRow {
    /// Parses one exactly bounded table-3078 General Journal posting carrier.
    ///
    /// Only bounded, shape-specific candidate offsets are considered.  This
    /// is not a row-wide numeric search.
    pub fn parse(input: &[u8]) -> Result<Self, MaterializedGeneralJournalProductionRowError> {
        validate_production_header(input)?;
        let family = input[PRODUCTION_PREFIX_OFFSET];
        let family_shift = match family {
            0xe0 => 0,
            0xe4 => 4,
            0xe8 => 8,
            actual => {
                return Err(
                    MaterializedGeneralJournalProductionRowError::UnsupportedFamily { actual },
                );
            }
        };
        let link_marker = input[PRODUCTION_LINK_MARKER_OFFSET];
        let link_class = link_marker & 0x7f;
        let linked = link_marker & 0x80 != 0;
        let is_short_e4_terminal = family == 0xe4
            && !linked
            && link_class == 0x13
            && input.len() == 129
            && input[PRODUCTION_PREFIX_REQUIRED_BYTE] == PRODUCTION_SHORT_E4_PREFIX_VALUE;
        if input[PRODUCTION_PREFIX_REQUIRED_BYTE] != PRODUCTION_PREFIX_REQUIRED_VALUE
            && !is_short_e4_terminal
        {
            return Err(
                MaterializedGeneralJournalProductionRowError::UnexpectedPrefixByte {
                    actual: input[PRODUCTION_PREFIX_REQUIRED_BYTE],
                },
            );
        }
        let is_e4_prebase_variant = family == 0xe4 && link_class == 0x03;
        if link_class != 0x13 && !(family == 0xe8 && link_class == 0x17) && !is_e4_prebase_variant {
            return Err(
                MaterializedGeneralJournalProductionRowError::UnexpectedLinkMarker {
                    actual: link_marker,
                },
            );
        }
        let target_record_number =
            production_required_reference(input, PRODUCTION_TARGET, "target")?;
        let master_record_number =
            production_required_reference(input, PRODUCTION_MASTER, "master")?;
        let account_record_number =
            production_required_reference(input, PRODUCTION_ACCOUNT, "account")?;
        let date_raw = u32_at(input, PRODUCTION_DATE);
        // A raw date which is not a whole valid business day must not become a
        // posting merely because the surrounding bytes look plausible.
        crate::MaterializedPostingDate::from_raw_bits(date_raw).map_err(|_| {
            MaterializedGeneralJournalProductionRowError::InvalidPostingDate { raw: date_raw }
        })?;
        let next_target = u32_at(input, PRODUCTION_NEXT_TARGET);
        // A clear link-marker high bit chooses this row family's amount
        // envelope; it does not establish that the adjacent relationship
        // metadata is present. Ordinary materialized postings exhibit both
        // zero and nonzero values here, so preserve it as opaque optional
        // metadata rather than rejecting an otherwise fully attested row.
        let base = PRODUCTION_AMOUNT_BASE
            + family_shift
            + if linked {
                PRODUCTION_AMOUNT_LINKED_SHIFT
            } else {
                0
            };
        let (amount_position, amount) = if is_short_e4_terminal {
            select_short_e4_terminal_amount(input, base)?
        } else if is_e4_prebase_variant {
            select_fixed_prebase_amount(input, base, 8)?
        } else {
            select_main_amount(input, family, linked, base)?
        };
        if amount.is_canonical_zero() {
            return Err(MaterializedGeneralJournalProductionRowError::CanonicalZeroPosting);
        }
        Ok(Self {
            target_record_number,
            master_record_number,
            account_record_number,
            date_raw,
            view_type: u16_at(input, PRODUCTION_VIEW),
            next_target_record_number: linked.then(|| nonzero(next_target)).flatten(),
            family,
            amount_position,
            signed_cents: amount.signed_cents(),
        })
    }

    /// Returns the General Journal target-line record number.
    #[must_use]
    pub const fn target_record_number(&self) -> u32 {
        self.target_record_number
    }
    /// Returns the containing General Journal master record number.
    #[must_use]
    pub const fn master_record_number(&self) -> u32 {
        self.master_record_number
    }
    /// Returns the posting Account physical record number.
    #[must_use]
    pub const fn account_record_number(&self) -> u32 {
        self.account_record_number
    }
    /// Returns the exact raw SQL Anywhere minute-date bits.
    #[must_use]
    pub const fn date_raw(&self) -> u32 {
        self.date_raw
    }
    /// Decodes the already-validated posting business date.
    pub fn posting_date(
        &self,
    ) -> Result<crate::MaterializedPostingDate, crate::MaterializedPostingDateError> {
        crate::MaterializedPostingDate::from_raw_bits(self.date_raw)
    }
    /// Returns the observed General Journal view/type field.
    #[must_use]
    pub const fn view_type(&self) -> u16 {
        self.view_type
    }
    /// Returns the next posting target for linked rows.
    #[must_use]
    pub const fn next_target_record_number(&self) -> Option<u32> {
        self.next_target_record_number
    }
    /// Returns the established physical layout family byte.
    #[must_use]
    pub const fn family(&self) -> u8 {
        self.family
    }
    /// Returns the selected nullable-boundary amount position.
    #[must_use]
    pub const fn amount_position(&self) -> MaterializedGeneralJournalAmountPosition {
        self.amount_position
    }
    /// Returns the signed materialized cents amount.
    #[must_use]
    pub const fn signed_cents(&self) -> i64 {
        self.signed_cents
    }
}

/// A fully attested General Journal main-envelope row whose selected amount
/// is the canonical zero token.
///
/// This carries physical identifiers for audit and complete-coverage
/// accounting, but deliberately makes no lifecycle assertion (for example,
/// it does not call the row a void).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedGeneralJournalCanonicalZeroAmount {
    target_record_number: u32,
    master_record_number: u32,
    account_record_number: u32,
    date_raw: u32,
    view_type: u16,
    family: u8,
    amount_position: MaterializedGeneralJournalAmountPosition,
}

impl MaterializedGeneralJournalCanonicalZeroAmount {
    /// Returns the physical General Journal target-line record number.
    #[must_use]
    pub const fn target_record_number(&self) -> u32 {
        self.target_record_number
    }
    /// Returns the containing General Journal master record number.
    #[must_use]
    pub const fn master_record_number(&self) -> u32 {
        self.master_record_number
    }
    /// Returns the referenced Account physical record number.
    #[must_use]
    pub const fn account_record_number(&self) -> u32 {
        self.account_record_number
    }
    /// Returns the validated raw business-date bits.
    #[must_use]
    pub const fn date_raw(&self) -> u32 {
        self.date_raw
    }
    /// Returns the opaque view/type field.
    #[must_use]
    pub const fn view_type(&self) -> u16 {
        self.view_type
    }
    /// Returns the physical layout family byte.
    #[must_use]
    pub const fn family(&self) -> u8 {
        self.family
    }
    /// Returns the selected amount location.
    #[must_use]
    pub const fn amount_position(&self) -> MaterializedGeneralJournalAmountPosition {
        self.amount_position
    }
}

/// A non-posting General Journal source/link carrier. It is accepted only
/// when its next-target relation closes over a posting in the same master and
/// date, or when an independently witnessed terminal variant has exactly one
/// same-master/date posting for its Account, during
/// [`classify_materialized_general_journal_rows`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedGeneralJournalSourceLink {
    target_record_number: u32,
    master_record_number: u32,
    account_record_number: u32,
    date_raw: u32,
    view_type: u16,
    next_target_record_number: Option<u32>,
}

impl MaterializedGeneralJournalSourceLink {
    /// Returns the source carrier's own record number.
    #[must_use]
    pub const fn target_record_number(&self) -> u32 {
        self.target_record_number
    }
    /// Returns the containing transaction master record number.
    #[must_use]
    pub const fn master_record_number(&self) -> u32 {
        self.master_record_number
    }
    /// Returns the referenced Account record number.
    #[must_use]
    pub const fn account_record_number(&self) -> u32 {
        self.account_record_number
    }
    /// Returns the raw SQL Anywhere posting-date bits.
    #[must_use]
    pub const fn date_raw(&self) -> u32 {
        self.date_raw
    }
    /// Returns the opaque source view/type value.
    #[must_use]
    pub const fn view_type(&self) -> u16 {
        self.view_type
    }
    /// Returns the linked posting target, or `None` for a terminal source carrier.
    #[must_use]
    pub const fn next_target_record_number(&self) -> Option<u32> {
        self.next_target_record_number
    }
}

/// One closed disposition for a complete table-3078 row collection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaterializedGeneralJournalDisposition {
    /// A fully attested monetary posting.
    Posting(MaterializedGeneralJournalPostingRow),
    /// A relationship carrier with no monetary meaning of its own.
    SourceOrLink(MaterializedGeneralJournalSourceLink),
    /// A fully attested main-envelope canonical-zero amount.  This is a
    /// neutral, complete-coverage disposition, not a claim that the row was
    /// voided or deleted.
    CanonicalZeroAmount(MaterializedGeneralJournalCanonicalZeroAmount),
    /// A closed, independently balanced 2-, 4-, or 6-node auxiliary relationship chain.
    AuxiliaryLinkChain {
        /// The chain's transaction master.
        master_record_number: u32,
        /// The auxiliary carrier record.
        target_record_number: u32,
    },
    /// A singleton terminal relationship-metadata carrier with no monetary
    /// token, corroborated by exactly one same-context posting Account.
    TerminalMetadataCarrier {
        /// The carrier's transaction master.
        master_record_number: u32,
        /// The metadata carrier record.
        target_record_number: u32,
    },
    /// A family-64 source carrier corroborated by one General Journal header.
    /// Its next field is header metadata rather than a table-3078 link.
    HeaderMetadataCarrier {
        /// The carrier's transaction master.
        master_record_number: u32,
        /// The corroborating header's group field.
        header_group: u32,
    },
}

/// One consensus-resolved table-3076 General Journal header witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeneralJournalHeaderMetadataWitness {
    /// Header record identifier at byte offset 0x0b.
    pub id: u32,
    /// Header business-date bits at byte offset 0x0f.
    pub date_raw: u32,
    /// Header group at byte offset 0x13.
    pub group: u32,
}

impl GeneralJournalHeaderMetadataWitness {
    /// Parses the complete, fixed General Journal header framing.
    pub fn parse(input: &[u8]) -> Result<Self, MaterializedGeneralJournalProductionRowError> {
        if input.len() < 23
            || usize::from(u16_at(input, 0)) != input.len()
            || input.get(2) != Some(&MATERIALIZED_GENERAL_JOURNAL_FLAGS)
            || input.get(3) != Some(&MATERIALIZED_GENERAL_JOURNAL_ROW_KIND)
            || input.get(4..7) != Some(&[0xa7, 0xfe, 0][..])
        {
            return Err(MaterializedGeneralJournalProductionRowError::UnrecognizedCarrier);
        }
        let id = u32_at(input, 11);
        let date_raw = u32_at(input, 15);
        let group = u32_at(input, 19);
        if id == 0 || group == 0 {
            return Err(
                MaterializedGeneralJournalProductionRowError::MissingRequiredReference {
                    field: "header witness",
                },
            );
        }
        crate::MaterializedPostingDate::from_raw_bits(date_raw).map_err(|_| {
            MaterializedGeneralJournalProductionRowError::InvalidPostingDate { raw: date_raw }
        })?;
        Ok(Self {
            id,
            date_raw,
            group,
        })
    }
}

/// Classifies every consensus-resolved table-3078 row exactly once.
///
/// The caller must provide one row for every logical table record.  This
/// function is intentionally table-wide because source relations and the
/// auxiliary relationship chains cannot safely be identified row by row.
pub fn classify_materialized_general_journal_rows(
    rows: &[Vec<u8>],
) -> Result<Vec<MaterializedGeneralJournalDisposition>, MaterializedGeneralJournalProductionRowError>
{
    classify_materialized_general_journal_rows_with_header_witnesses(rows, &[])
}

/// Classifies a complete table-3078 collection with consensus header context.
pub fn classify_materialized_general_journal_rows_with_header_witnesses(
    rows: &[Vec<u8>],
    witnesses: &[GeneralJournalHeaderMetadataWitness],
) -> Result<Vec<MaterializedGeneralJournalDisposition>, MaterializedGeneralJournalProductionRowError>
{
    let mut result = Vec::with_capacity(rows.len());
    let mut postings = std::collections::BTreeMap::new();
    let mut sources = Vec::new();
    let mut canonical_zeroes = std::collections::BTreeMap::new();
    // Identify the exact auxiliary grammar before ordinary posting parsing.
    // Its terminal carrier intentionally carries nonzero +1d metadata, so it
    // would otherwise be indistinguishable from a valid ordinary main row
    // once that metadata is correctly treated as opaque.
    let residual = identify_auxiliary_candidate_indices(rows)?;
    let residual_indices = residual
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    for (index, bytes) in rows.iter().enumerate() {
        if residual_indices.contains(&index) {
            result.push(None);
        } else if let Ok(posting) = MaterializedGeneralJournalPostingRow::parse(bytes) {
            if postings
                .insert(posting.target_record_number(), posting.clone())
                .is_some()
            {
                return Err(MaterializedGeneralJournalProductionRowError::DuplicateTarget);
            }
            result.push(Some(MaterializedGeneralJournalDisposition::Posting(
                posting,
            )));
        } else if let Some(zero) = parse_main_canonical_zero(bytes)? {
            if canonical_zeroes
                .insert(zero.target_record_number(), zero.clone())
                .is_some()
            {
                return Err(MaterializedGeneralJournalProductionRowError::DuplicateTarget);
            }
            result.push(Some(
                MaterializedGeneralJournalDisposition::CanonicalZeroAmount(zero),
            ));
        } else if let Some(posting) = parse_special_posting(bytes)? {
            if postings
                .insert(posting.target_record_number(), posting.clone())
                .is_some()
            {
                return Err(MaterializedGeneralJournalProductionRowError::DuplicateTarget);
            }
            result.push(Some(MaterializedGeneralJournalDisposition::Posting(
                posting,
            )));
        } else if let Some(source) = parse_source_link(bytes)? {
            sources.push((index, source));
            result.push(None);
        } else {
            return Err(MaterializedGeneralJournalProductionRowError::UnrecognizedCarrier);
        }
    }
    // The residual carriers are accepted only as one exact, balanced
    // bounded auxiliary chains before source relations are traversed. Source
    // nodes may reference that attested non-posting chain, but cannot turn an
    // arbitrary unparsed carrier into a valid graph destination.
    classify_auxiliary_link_chain(
        rows,
        &postings,
        &canonical_zeroes,
        &sources,
        &residual,
        &mut result,
    )?;
    let mut auxiliary_cores = std::collections::BTreeMap::new();
    let mut residual_targets = std::collections::BTreeSet::new();
    for index in &residual {
        let bytes = &rows[*index];
        let target = production_required_reference(bytes, PRODUCTION_TARGET, "auxiliary target")?;
        let master = production_required_reference(bytes, PRODUCTION_MASTER, "auxiliary master")?;
        let date_raw = u32_at(bytes, PRODUCTION_DATE);
        crate::MaterializedPostingDate::from_raw_bits(date_raw).map_err(|_| {
            MaterializedGeneralJournalProductionRowError::InvalidPostingDate { raw: date_raw }
        })?;
        if postings.contains_key(&target)
            || canonical_zeroes.contains_key(&target)
            || !residual_targets.insert(target)
        {
            return Err(MaterializedGeneralJournalProductionRowError::DuplicateTarget);
        }
        if matches!(
            result.get(*index),
            Some(Some(
                MaterializedGeneralJournalDisposition::AuxiliaryLinkChain { .. }
            ))
        ) {
            auxiliary_cores.insert(target, (master, date_raw));
        }
    }
    let mut source_nodes = std::collections::BTreeMap::new();
    for (_, source) in &sources {
        if postings.contains_key(&source.target_record_number)
            || canonical_zeroes.contains_key(&source.target_record_number)
            || residual_targets.contains(&source.target_record_number)
            || source_nodes
                .insert(source.target_record_number, source.clone())
                .is_some()
        {
            return Err(MaterializedGeneralJournalProductionRowError::DuplicateTarget);
        }
    }
    let has_unique_terminal_source_destination =
        |terminal_source: &MaterializedGeneralJournalSourceLink| {
            postings
                .values()
                .filter(|posting| {
                    posting.master_record_number == terminal_source.master_record_number
                        && posting.date_raw == terminal_source.date_raw
                        && posting.account_record_number == terminal_source.account_record_number
                })
                .count()
                == 1
        };
    for (index, source) in sources {
        // Preserve the established source/link grammar whenever it resolves.
        // Header metadata is a fallback grammar for a source whose ordinary
        // same-master traversal is impossible, never an override for it.
        let ordinary_topology_succeeds = || {
            let Some(mut next_target) = source.next_target_record_number else {
                return has_unique_terminal_source_destination(&source);
            };
            let mut visited = std::collections::BTreeSet::new();
            loop {
                if !visited.insert(next_target) {
                    return false;
                }
                if let Some(posting) = postings.get(&next_target) {
                    return posting.master_record_number == source.master_record_number
                        && posting.date_raw == source.date_raw;
                }
                if let Some(zero) = canonical_zeroes.get(&next_target) {
                    return zero.master_record_number == source.master_record_number
                        && zero.date_raw == source.date_raw;
                }
                if let Some(&(master, date_raw)) = auxiliary_cores.get(&next_target) {
                    return master == source.master_record_number && date_raw == source.date_raw;
                }
                if visited.len() > source_nodes.len() {
                    return false;
                }
                let Some(next_source) = source_nodes.get(&next_target) else {
                    return false;
                };
                if next_source.master_record_number != source.master_record_number
                    || next_source.date_raw != source.date_raw
                {
                    return false;
                }
                let Some(next) = next_source.next_target_record_number else {
                    return has_unique_terminal_source_destination(next_source);
                };
                next_target = next;
            }
        };
        let is_header_metadata_family = (rows[index].len() == 151
            && rows[index].get(4..11) == Some(&[0x64, 0x93, 0xff, 0xc0, 0x40, 0x80, 0x20][..]))
            || (rows[index].len() == 201
                && rows[index].get(4..11) == Some(&[0x64, 0x13, 0xff, 0x80, 0x60, 0x00, 0x20][..]));
        if is_header_metadata_family && !witnesses.is_empty() && !ordinary_topology_succeeds() {
            let expected_id = source
                .master_record_number
                .checked_add(1)
                .ok_or(MaterializedGeneralJournalProductionRowError::SourceTopologyMismatch)?;
            let matching = witnesses
                .iter()
                .filter(|witness| {
                    witness.date_raw == source.date_raw
                        && Some(witness.group) == source.next_target_record_number
                })
                .collect::<Vec<_>>();
            let expected_id_count = witnesses
                .iter()
                .filter(|witness| witness.id == expected_id)
                .count();
            let master_postings = postings
                .values()
                .filter(|posting| posting.master_record_number == source.master_record_number)
                .collect::<Vec<_>>();
            let all_same_date = !master_postings.is_empty()
                && master_postings
                    .iter()
                    .all(|posting| posting.date_raw == source.date_raw);
            let balanced = master_postings
                .iter()
                .map(|posting| i128::from(posting.signed_cents))
                .sum::<i128>()
                == 0;
            if matching.len() != 1
                || matching[0].id != expected_id
                || expected_id_count != 1
                || !all_same_date
                || !balanced
            {
                return Err(MaterializedGeneralJournalProductionRowError::SourceTopologyMismatch);
            }
            result[index] = Some(
                MaterializedGeneralJournalDisposition::HeaderMetadataCarrier {
                    master_record_number: source.master_record_number,
                    header_group: source
                        .next_target_record_number
                        .expect("a matching header requires a nonzero group"),
                },
            );
            continue;
        }
        let Some(mut next_target) = source.next_target_record_number else {
            if !has_unique_terminal_source_destination(&source) {
                return Err(MaterializedGeneralJournalProductionRowError::SourceTopologyMismatch);
            }
            result[index] = Some(MaterializedGeneralJournalDisposition::SourceOrLink(source));
            continue;
        };
        let mut visited = std::collections::BTreeSet::new();
        loop {
            if !visited.insert(next_target) {
                return Err(MaterializedGeneralJournalProductionRowError::SourceTopologyMismatch);
            }
            if let Some(posting) = postings.get(&next_target) {
                // The source Account field is relationship metadata for this
                // carrier family.  Its destination must preserve transaction
                // master and business date, but need not be the same posting
                // Account. Monetary interpretation still belongs solely to
                // the terminal posting carrier.
                if posting.master_record_number != source.master_record_number
                    || posting.date_raw != source.date_raw
                {
                    return Err(
                        MaterializedGeneralJournalProductionRowError::SourceTopologyMismatch,
                    );
                }
                break;
            }
            if let Some(zero) = canonical_zeroes.get(&next_target) {
                if zero.master_record_number != source.master_record_number
                    || zero.date_raw != source.date_raw
                {
                    return Err(
                        MaterializedGeneralJournalProductionRowError::SourceTopologyMismatch,
                    );
                }
                break;
            }
            if let Some(&(master, date_raw)) = auxiliary_cores.get(&next_target) {
                if master != source.master_record_number || date_raw != source.date_raw {
                    return Err(
                        MaterializedGeneralJournalProductionRowError::SourceTopologyMismatch,
                    );
                }
                break;
            }
            if visited.len() > source_nodes.len() {
                return Err(MaterializedGeneralJournalProductionRowError::SourceTopologyMismatch);
            }
            let Some(next_source) = source_nodes.get(&next_target) else {
                return Err(MaterializedGeneralJournalProductionRowError::SourceTopologyMismatch);
            };
            if next_source.master_record_number != source.master_record_number
                || next_source.date_raw != source.date_raw
            {
                return Err(MaterializedGeneralJournalProductionRowError::SourceTopologyMismatch);
            }
            let Some(next) = next_source.next_target_record_number else {
                if !has_unique_terminal_source_destination(next_source) {
                    return Err(
                        MaterializedGeneralJournalProductionRowError::SourceTopologyMismatch,
                    );
                }
                break;
            };
            next_target = next;
        }
        result[index] = Some(MaterializedGeneralJournalDisposition::SourceOrLink(source));
    }
    result
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(MaterializedGeneralJournalProductionRowError::UnclassifiedCarrier)
}

/// Finds only the physically attested non-posting auxiliary candidates.
///
/// Candidate identification establishes the negative monetary facts and the
/// required negative monetary evidence. [`classify_auxiliary_link_chain`] then
/// makes the table-wide bounded-cardinality, balance, and relationship decision.
fn identify_auxiliary_candidate_indices(
    rows: &[Vec<u8>],
) -> Result<Vec<usize>, MaterializedGeneralJournalProductionRowError> {
    let mut result = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        // The two exact seven-byte envelopes are independently established
        // for the auxiliary family. They are only candidates here: the caller
        // must still prove the complete bounded topology, balance, and
        // nonsemantic collision below before excluding any record.
        if matches!(
            row.get(4..11),
            Some([0xe0, 0x13, 0xff, 0x80, 0x60, 0x00, 0x20])
                | Some([0xe0, 0x93, 0xff, 0x80, 0x60, 0x00, 0x20])
        ) {
            result.push(index);
        }
    }
    Ok(result)
}

/// Validates that every supplied General Journal master sums to zero.
///
/// This is deliberately a separate, table-wide gate: row parsing alone can
/// establish syntax, but only a complete current-row collection establishes a
/// balanced accounting transaction.
pub fn validate_materialized_general_journal_master_balances(
    rows: &[MaterializedGeneralJournalPostingRow],
) -> Result<(), MaterializedGeneralJournalProductionRowError> {
    use std::collections::BTreeMap;
    let mut balances = BTreeMap::<u32, i128>::new();
    for row in rows {
        *balances.entry(row.master_record_number).or_default() += i128::from(row.signed_cents);
    }
    if let Some((&master, &balance)) = balances.iter().find(|(_, balance)| **balance != 0) {
        return Err(
            MaterializedGeneralJournalProductionRowError::UnbalancedMaster {
                master,
                signed_cents: balance,
            },
        );
    }
    Ok(())
}

/// Errors returned by the full-corpus table-3078 General Journal row parser.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum MaterializedGeneralJournalProductionRowError {
    #[error(
        "materialized General Journal production row is too short: {actual} bytes (need at least {minimum})"
    )]
    SegmentTooShort { actual: usize, minimum: usize },
    #[error(
        "materialized General Journal production row length mismatch: declared {declared}, actual {actual}"
    )]
    DeclaredLengthMismatch { declared: usize, actual: usize },
    #[error("unsupported materialized General Journal production flags {actual:#04x}")]
    UnexpectedFlags { actual: u8 },
    #[error("unsupported materialized General Journal production row kind {actual:#04x}")]
    UnexpectedKind { actual: u8 },
    #[error("unsupported materialized General Journal production family {actual:#04x}")]
    UnsupportedFamily { actual: u8 },
    #[error("unsupported materialized General Journal production prefix byte {actual:#04x}")]
    UnexpectedPrefixByte { actual: u8 },
    #[error("unsupported materialized General Journal production link marker {actual:#04x}")]
    UnexpectedLinkMarker { actual: u8 },
    #[error("materialized General Journal production row has zero {field} record reference")]
    MissingRequiredReference { field: &'static str },
    #[error(
        "materialized General Journal production row has invalid business-date bits {raw:#010x}"
    )]
    InvalidPostingDate { raw: u32 },
    #[error("materialized General Journal linked row has no next target")]
    MissingLinkedTarget,
    #[error("materialized General Journal terminal row has next target {next_target:#010x}")]
    UnexpectedTerminalLink { next_target: u32 },
    #[error("materialized General Journal production row has no bounded amount token at {base:#x} or {next:#x}", next = .base + 1)]
    NoBoundedAmountToken { base: usize },
    #[error(
        "materialized General Journal production row has {count} bounded amount tokens at nullable boundary {base:#x}"
    )]
    AmbiguousAmountToken { base: usize, count: usize },
    #[error("materialized General Journal posting amount has no later byte-identical copy")]
    MissingAmountCopy,
    #[error("materialized General Journal current posting used the canonical zero amount token")]
    CanonicalZeroPosting,
    #[error("materialized General Journal carrier duplicated a target record number")]
    DuplicateTarget,
    #[error(
        "materialized General Journal source/link topology did not resolve to its same-master posting"
    )]
    SourceTopologyMismatch,
    #[error(
        "materialized General Journal auxiliary link-chain topology is not the closed attested shape"
    )]
    AuxiliaryTopologyMismatch,
    #[error("materialized General Journal auxiliary link-chain had an attested posting amount")]
    AuxiliaryHasPostingAmount,
    #[error("materialized General Journal auxiliary master was not independently balanced")]
    AuxiliaryMasterNotBalanced,
    #[error("unrecognized materialized General Journal carrier")]
    UnrecognizedCarrier,
    #[error("materialized General Journal carrier was not assigned a closed disposition")]
    UnclassifiedCarrier,
    #[error(
        "materialized General Journal master {master:#010x} is unbalanced by {signed_cents} cents"
    )]
    UnbalancedMaster { master: u32, signed_cents: i128 },
}

fn bounded_token(input: &[u8], offset: usize) -> Option<(usize, MaterializedPostingCents)> {
    let digits = usize::from(*input.get(offset)?);
    let end = offset.checked_add(2)?.checked_add(digits)?;
    let bytes = input.get(offset..end)?;
    MaterializedPostingCents::parse(bytes)
        .ok()
        .map(|amount| (end - offset, amount))
}

fn has_later_copy(input: &[u8], offset: usize, len: usize) -> bool {
    let Some(token) = input.get(offset..offset + len) else {
        return false;
    };
    (offset + len..input.len()).any(|later| input.get(later..later + len) == Some(token))
}

fn main_prebase_range(family: u8, linked: bool, base: usize) -> std::ops::Range<usize> {
    match (family, linked) {
        (0xe0, _) => base - 4..base,
        (0xe4, _) => base - 4..base,
        (0xe8, false) => base - 8..base - 2,
        (0xe8, true) => base - 8..base - 2,
        _ => 0..0,
    }
}

fn main_direct_range(family: u8, base: usize) -> std::ops::Range<usize> {
    if family == 0xe0 {
        base..base + 3
    } else {
        base..base + 2
    }
}

fn select_main_amount(
    input: &[u8],
    family: u8,
    linked: bool,
    base: usize,
) -> Result<
    (
        MaterializedGeneralJournalAmountPosition,
        MaterializedPostingCents,
    ),
    MaterializedGeneralJournalProductionRowError,
> {
    let candidates = main_prebase_range(family, linked, base)
        .filter_map(|offset| {
            bounded_token(input, offset).map(|(len, amount)| (offset, len, amount))
        })
        .collect::<Vec<_>>();
    let copied_candidates = candidates
        .iter()
        .copied()
        .filter(|(offset, len, _)| has_later_copy(input, *offset, *len))
        .collect::<Vec<_>>();
    // This order intentionally matches the independently labelled grammar:
    // grammar selection happens before duplicate attestation.  In the one
    // observed e0-linked two-token shape, the earlier token is selected by a
    // fixed discriminator even when the later candidate is also duplicated.
    let selected = match candidates.as_slice() {
        [(offset, len, amount)] => Some((*offset, *len, *amount)),
        _ if copied_candidates.len() == 1 => Some(copied_candidates[0]),
        _ if candidates.len() == 2
            && family == 0xe0
            && linked
            && candidates[0].0 + 3 == base
            && candidates[1].0 + 1 == base
            && matches!(input.get(base - 1), Some(1 | 2)) =>
        {
            Some(candidates[0])
        }
        [] => None,
        _ => {
            return Err(
                MaterializedGeneralJournalProductionRowError::AmbiguousAmountToken {
                    base,
                    count: candidates.len(),
                },
            );
        }
    };
    if let Some((offset, len, amount)) = selected {
        if !has_later_copy(input, offset, len) {
            return Err(MaterializedGeneralJournalProductionRowError::MissingAmountCopy);
        }
        return Ok((
            MaterializedGeneralJournalAmountPosition::MainPrebase,
            amount,
        ));
    }
    let direct = main_direct_range(family, base)
        .filter_map(|offset| {
            bounded_token(input, offset).map(|(len, amount)| (offset, len, amount))
        })
        .collect::<Vec<_>>();
    let copied_direct = direct
        .iter()
        .copied()
        .filter(|(offset, len, _)| has_later_copy(input, *offset, *len))
        .collect::<Vec<_>>();
    match direct.as_slice() {
        [(offset, len, amount)] if has_later_copy(input, *offset, *len) => Ok((
            MaterializedGeneralJournalAmountPosition::MainDirect,
            *amount,
        )),
        [_] => Err(MaterializedGeneralJournalProductionRowError::MissingAmountCopy),
        [] => Err(MaterializedGeneralJournalProductionRowError::NoBoundedAmountToken { base }),
        _ if copied_direct.len() == 1 => Ok((
            MaterializedGeneralJournalAmountPosition::MainDirect,
            copied_direct[0].2,
        )),
        _ if family == 0xe0
            && copied_direct.len() == 2
            && copied_direct[0].0 == base
            && copied_direct[1].0 == base + 2 =>
        {
            Ok((
                MaterializedGeneralJournalAmountPosition::MainDirect,
                copied_direct[0].2,
            ))
        }
        _ => Err(
            MaterializedGeneralJournalProductionRowError::AmbiguousAmountToken {
                base,
                count: direct.len(),
            },
        ),
    }
}

fn select_fixed_prebase_amount(
    input: &[u8],
    base: usize,
    distance: usize,
) -> Result<
    (
        MaterializedGeneralJournalAmountPosition,
        MaterializedPostingCents,
    ),
    MaterializedGeneralJournalProductionRowError,
> {
    let offset = base
        .checked_sub(distance)
        .ok_or(MaterializedGeneralJournalProductionRowError::NoBoundedAmountToken { base })?;
    let (len, amount) = bounded_token(input, offset)
        .ok_or(MaterializedGeneralJournalProductionRowError::NoBoundedAmountToken { base })?;
    if !has_later_copy(input, offset, len) {
        return Err(MaterializedGeneralJournalProductionRowError::MissingAmountCopy);
    }
    Ok((
        MaterializedGeneralJournalAmountPosition::MainPrebase,
        amount,
    ))
}

fn select_short_e4_terminal_amount(
    input: &[u8],
    base: usize,
) -> Result<
    (
        MaterializedGeneralJournalAmountPosition,
        MaterializedPostingCents,
    ),
    MaterializedGeneralJournalProductionRowError,
> {
    let primary = base
        .checked_sub(27)
        .ok_or(MaterializedGeneralJournalProductionRowError::NoBoundedAmountToken { base })?;
    let copy = base
        .checked_add(17)
        .ok_or(MaterializedGeneralJournalProductionRowError::NoBoundedAmountToken { base })?;
    let (len, amount) = bounded_token(input, primary)
        .ok_or(MaterializedGeneralJournalProductionRowError::NoBoundedAmountToken { base })?;
    if len != 3 || input.get(copy..copy + len) != input.get(primary..primary + len) {
        return Err(MaterializedGeneralJournalProductionRowError::MissingAmountCopy);
    }
    Ok((
        MaterializedGeneralJournalAmountPosition::MainPrebase,
        amount,
    ))
}

/// Parses only the complete-coverage canonical-zero branch of an otherwise
/// attested main-envelope row.  A nonzero amount is deliberately returned as
/// `None`; it must pass the ordinary posting parser instead.
fn parse_main_canonical_zero(
    input: &[u8],
) -> Result<
    Option<MaterializedGeneralJournalCanonicalZeroAmount>,
    MaterializedGeneralJournalProductionRowError,
> {
    validate_production_header(input)?;
    let family = match input[PRODUCTION_PREFIX_OFFSET] {
        0xe0 | 0xe4 | 0xe8 => input[PRODUCTION_PREFIX_OFFSET],
        _ => return Ok(None),
    };
    if input[PRODUCTION_PREFIX_REQUIRED_BYTE] != PRODUCTION_PREFIX_REQUIRED_VALUE {
        return Ok(None);
    }
    let link_marker = input[PRODUCTION_LINK_MARKER_OFFSET];
    if link_marker & 0x7f != 0x13 {
        return Ok(None);
    }
    let linked = link_marker & 0x80 != 0;
    let target_record_number = production_required_reference(input, PRODUCTION_TARGET, "target")?;
    let master_record_number = production_required_reference(input, PRODUCTION_MASTER, "master")?;
    let account_record_number =
        production_required_reference(input, PRODUCTION_ACCOUNT, "account")?;
    let date_raw = u32_at(input, PRODUCTION_DATE);
    crate::MaterializedPostingDate::from_raw_bits(date_raw).map_err(|_| {
        MaterializedGeneralJournalProductionRowError::InvalidPostingDate { raw: date_raw }
    })?;
    let base = PRODUCTION_AMOUNT_BASE
        + usize::from(family - 0xe0)
        + if linked {
            PRODUCTION_AMOUNT_LINKED_SHIFT
        } else {
            0
        };
    let (amount_position, amount) = select_main_amount(input, family, linked, base)?;
    if !amount.is_canonical_zero() {
        return Ok(None);
    }
    Ok(Some(MaterializedGeneralJournalCanonicalZeroAmount {
        target_record_number,
        master_record_number,
        account_record_number,
        date_raw,
        view_type: u16_at(input, PRODUCTION_VIEW),
        family,
        amount_position,
    }))
}

fn parse_special_posting(
    input: &[u8],
) -> Result<
    Option<MaterializedGeneralJournalPostingRow>,
    MaterializedGeneralJournalProductionRowError,
> {
    validate_production_header(input)?;
    let Some(primary) = special_primary_offset(input) else {
        return Ok(None);
    };
    // The special-prefix envelope is also used by the closed auxiliary
    // relationship chain.  A matching envelope with no bounded token at its
    // special primary offset is consequently a non-posting carrier, not a
    // malformed posting.  It remains subject to the table-wide auxiliary
    // topology validation below; callers never accept it row-by-row.
    let Some((len, amount)) = bounded_token(input, primary) else {
        return Ok(None);
    };
    if !has_later_copy(input, primary, len) {
        return Err(MaterializedGeneralJournalProductionRowError::MissingAmountCopy);
    }
    if amount.is_canonical_zero() {
        return Err(MaterializedGeneralJournalProductionRowError::CanonicalZeroPosting);
    }
    let target_record_number = production_required_reference(input, PRODUCTION_TARGET, "target")?;
    let master_record_number = production_required_reference(input, PRODUCTION_MASTER, "master")?;
    let account_record_number =
        production_required_reference(input, PRODUCTION_ACCOUNT, "account")?;
    let date_raw = u32_at(input, PRODUCTION_DATE);
    crate::MaterializedPostingDate::from_raw_bits(date_raw).map_err(|_| {
        MaterializedGeneralJournalProductionRowError::InvalidPostingDate { raw: date_raw }
    })?;
    Ok(Some(MaterializedGeneralJournalPostingRow {
        target_record_number,
        master_record_number,
        account_record_number,
        date_raw,
        view_type: u16_at(input, PRODUCTION_VIEW),
        next_target_record_number: nonzero(u32_at(input, PRODUCTION_NEXT_TARGET)),
        family: 0xe0,
        amount_position: MaterializedGeneralJournalAmountPosition::SpecialEnvelope,
        signed_cents: amount.signed_cents(),
    }))
}

/// Returns the one attested amount location for a short special envelope.
///
/// A matching envelope is not automatically a posting: its bounded token and
/// duplicate-copy requirements remain enforced by [`parse_special_posting`].
/// The classifier additionally uses the match to retain token-less carriers
/// for the closed, table-wide auxiliary topology gate.
fn special_primary_offset(input: &[u8]) -> Option<usize> {
    match input.get(4..11)? {
        [0xe0, 0x13, 0x9f, ..] => Some(0x48),
        [0xe0, 0x83, 0xff, ..] => Some(0x60),
        [0xe0, 0x93, 0x9f, ..] => Some(0x4c),
        _ => None,
    }
}

fn parse_source_link(
    input: &[u8],
) -> Result<
    Option<MaterializedGeneralJournalSourceLink>,
    MaterializedGeneralJournalProductionRowError,
> {
    validate_production_header(input)?;
    let allowed = ((input.len() == 142 || input.len() == 143)
        && input.get(4..11) == Some(&[0x60, 0x93, 0xff, 0x80, 0x40, 0x00, 0x20][..]))
        || (input.len() == 147
            && input.get(4..11) == Some(&[0x60, 0x93, 0xff, 0xc0, 0x40, 0x80, 0x20][..]))
        || (input.len() == 151
            && input.get(4..11) == Some(&[0x64, 0x93, 0xff, 0xc0, 0x40, 0x80, 0x20][..]))
        || (input.len() == 201
            && input.get(4..11) == Some(&[0x64, 0x13, 0xff, 0x80, 0x60, 0x00, 0x20][..]));
    if !allowed {
        return Ok(None);
    }
    let target_record_number =
        production_required_reference(input, SOURCE_RECORD, "source target")?;
    let master_record_number =
        production_required_reference(input, SOURCE_MASTER, "source master")?;
    let account_record_number =
        production_required_reference(input, SOURCE_ACCOUNT, "source account")?;
    let next_target_record_number = nonzero(u32_at(input, SOURCE_NEXT));
    let date_raw = u32_at(input, SOURCE_DATE);
    crate::MaterializedPostingDate::from_raw_bits(date_raw).map_err(|_| {
        MaterializedGeneralJournalProductionRowError::InvalidPostingDate { raw: date_raw }
    })?;
    Ok(Some(MaterializedGeneralJournalSourceLink {
        target_record_number,
        master_record_number,
        account_record_number,
        date_raw,
        view_type: u16_at(input, SOURCE_VIEW),
        next_target_record_number,
    }))
}

fn classify_auxiliary_link_chain(
    rows: &[Vec<u8>],
    postings: &std::collections::BTreeMap<u32, MaterializedGeneralJournalPostingRow>,
    canonical_zeroes: &std::collections::BTreeMap<
        u32,
        MaterializedGeneralJournalCanonicalZeroAmount,
    >,
    sources: &[(usize, MaterializedGeneralJournalSourceLink)],
    residual: &[usize],
    result: &mut [Option<MaterializedGeneralJournalDisposition>],
) -> Result<(), MaterializedGeneralJournalProductionRowError> {
    if residual.is_empty() {
        return Ok(());
    }
    let selected_targets = postings
        .keys()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let mut all_residual_targets = std::collections::BTreeSet::new();
    let mut groups = std::collections::BTreeMap::<(u32, u32, u16), Vec<usize>>::new();
    for index in residual {
        let row = &rows[*index];
        let target = production_required_reference(row, PRODUCTION_TARGET, "auxiliary target")?;
        if selected_targets.contains(&target) || !all_residual_targets.insert(target) {
            return Err(MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch);
        }
        groups
            .entry((
                u32_at(row, PRODUCTION_MASTER),
                u32_at(row, PRODUCTION_DATE),
                u16_at(row, PRODUCTION_VIEW),
            ))
            .or_default()
            .push(*index);
    }
    if all_residual_targets.len() != residual.len() {
        return Err(MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch);
    }
    for ((master, date, view), indices) in groups {
        if indices.len() == 1 {
            let index = indices[0];
            let row = &rows[index];
            validate_production_header(row)?;
            if row.get(4..11) != Some(&[0xe0, 0x13, 0xff, 0x80, 0x60, 0x00, 0x20][..]) {
                return Err(
                    MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch,
                );
            }
            let target = production_required_reference(row, PRODUCTION_TARGET, "metadata target")?;
            let row_master =
                production_required_reference(row, PRODUCTION_MASTER, "metadata master")?;
            let _account =
                production_required_reference(row, PRODUCTION_ACCOUNT, "metadata account")?;
            let external_account = production_required_reference(
                row,
                PRODUCTION_NEXT_TARGET,
                "metadata external account",
            )?;
            let date_raw = u32_at(row, PRODUCTION_DATE);
            crate::MaterializedPostingDate::from_raw_bits(date_raw).map_err(|_| {
                MaterializedGeneralJournalProductionRowError::InvalidPostingDate { raw: date_raw }
            })?;
            if row_master != master
                || date_raw != date
                || u16_at(row, PRODUCTION_VIEW) != view
                || all_residual_targets.contains(&external_account)
                || (0..row.len().saturating_sub(1))
                    .any(|offset| bounded_token(row, offset).is_some())
            {
                return Err(
                    MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch,
                );
            }
            let matching_accounts = postings
                .values()
                .filter(|posting| {
                    posting.master_record_number == master
                        && posting.date_raw == date
                        && posting.account_record_number == external_account
                })
                .count()
                + canonical_zeroes
                    .values()
                    .filter(|zero| {
                        zero.master_record_number == master
                            && zero.date_raw == date
                            && zero.account_record_number == external_account
                    })
                    .count();
            if matching_accounts != 1 {
                return Err(
                    MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch,
                );
            }
            let balance = postings
                .values()
                .filter(|posting| posting.master_record_number == master)
                .try_fold(0_i128, |sum, posting| {
                    sum.checked_add(i128::from(posting.signed_cents))
                })
                .ok_or(MaterializedGeneralJournalProductionRowError::AuxiliaryMasterNotBalanced)?;
            if balance != 0 {
                return Err(
                    MaterializedGeneralJournalProductionRowError::AuxiliaryMasterNotBalanced,
                );
            }
            result[index] = Some(
                MaterializedGeneralJournalDisposition::TerminalMetadataCarrier {
                    master_record_number: master,
                    target_record_number: target,
                },
            );
            continue;
        }
        if !matches!(indices.len(), 2 | 4 | 6) {
            return Err(MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch);
        }
        let group_targets = indices
            .iter()
            .map(|index| u32_at(&rows[*index], PRODUCTION_TARGET))
            .collect::<std::collections::BTreeSet<_>>();
        if group_targets.len() != indices.len() {
            return Err(MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch);
        }
        let mut linked = 0usize;
        let mut terminal = 0usize;
        let mut terminal_target = None;
        let mut outgoing = std::collections::BTreeMap::new();
        let mut incoming = group_targets
            .iter()
            .copied()
            .map(|target| (target, 0_usize))
            .collect::<std::collections::BTreeMap<_, _>>();
        for index in &indices {
            let row = &rows[*index];
            if u32_at(row, PRODUCTION_MASTER) != master
                || u32_at(row, PRODUCTION_DATE) != date
                || u16_at(row, PRODUCTION_VIEW) != view
                || u32_at(row, PRODUCTION_ACCOUNT) == 0
            {
                return Err(
                    MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch,
                );
            }
            let is_linked = row[PRODUCTION_LINK_MARKER_OFFSET] & 0x80 != 0;
            linked += usize::from(is_linked);
            terminal += usize::from(!is_linked);
            let next_target = u32_at(row, PRODUCTION_NEXT_TARGET);
            if (is_linked && !group_targets.contains(&next_target))
                || (!is_linked && (next_target == 0 || all_residual_targets.contains(&next_target)))
            {
                return Err(
                    MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch,
                );
            }
            let target = u32_at(row, PRODUCTION_TARGET);
            if is_linked {
                if outgoing.insert(target, next_target).is_some() {
                    return Err(
                        MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch,
                    );
                }
                let Some(incoming_count) = incoming.get_mut(&next_target) else {
                    return Err(
                        MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch,
                    );
                };
                *incoming_count += 1;
                if *incoming_count > 1 {
                    return Err(
                        MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch,
                    );
                }
            } else if terminal_target.replace(target).is_some() {
                return Err(
                    MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch,
                );
            }
            let family = row[PRODUCTION_PREFIX_OFFSET];
            let base = PRODUCTION_AMOUNT_BASE
                + usize::from(family - 0xe0)
                + if is_linked {
                    PRODUCTION_AMOUNT_LINKED_SHIFT
                } else {
                    0
                };
            if select_main_amount(row, family, is_linked, base).is_ok()
                || parse_special_posting(row)?.is_some()
            {
                return Err(
                    MaterializedGeneralJournalProductionRowError::AuxiliaryHasPostingAmount,
                );
            }
            let collision_offset = base + 21;
            let collision = row
                .get(collision_offset..)
                .and_then(|tail| bounded_token(tail, 0));
            match collision {
                Some((collision_len, collision))
                    if !collision.is_canonical_zero()
                        && collision.signed_cents() != 0
                        && !has_later_copy(row, collision_offset, collision_len) => {}
                None if indices.len() < 6
                    && !(PRODUCTION_FIXED_END..row.len().saturating_sub(1))
                        .any(|offset| bounded_token(row, offset).is_some()) => {}
                _ => {
                    return Err(
                        MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch,
                    );
                }
            }
        }
        if linked + 1 != indices.len() || terminal != 1 {
            return Err(MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch);
        }
        let heads = incoming
            .iter()
            .filter_map(|(target, count)| (*count == 0).then_some(*target))
            .collect::<Vec<_>>();
        if heads.len() != 1 {
            return Err(MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch);
        }
        let terminal_target = terminal_target
            .ok_or(MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch)?;
        let mut visited = std::collections::BTreeSet::new();
        let mut current = heads[0];
        loop {
            if !visited.insert(current) {
                return Err(
                    MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch,
                );
            }
            if current == terminal_target {
                break;
            }
            current = *outgoing
                .get(&current)
                .ok_or(MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch)?;
        }
        if visited.len() != indices.len() {
            return Err(MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch);
        }

        let terminal_row = indices
            .iter()
            .map(|index| &rows[*index])
            .find(|row| u32_at(row, PRODUCTION_TARGET) == terminal_target)
            .ok_or(MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch)?;
        let external_target = u32_at(terminal_row, PRODUCTION_NEXT_TARGET);
        let external_resolved = postings.get(&external_target).is_some_and(|posting| {
            posting.master_record_number == master && posting.date_raw == date
        }) || canonical_zeroes
            .get(&external_target)
            .is_some_and(|zero| zero.master_record_number == master && zero.date_raw == date)
            || sources.iter().any(|(_, source)| {
                source.target_record_number == external_target
                    && source.master_record_number == master
                    && source.date_raw == date
            })
            || external_target == master
            || indices
                .iter()
                .any(|index| u32_at(&rows[*index], PRODUCTION_ACCOUNT) == external_target)
            || postings.values().any(|posting| {
                posting.master_record_number == master
                    && posting.date_raw == date
                    && posting.account_record_number == external_target
            })
            || canonical_zeroes.values().any(|zero| {
                zero.master_record_number == master
                    && zero.date_raw == date
                    && zero.account_record_number == external_target
            });
        if !external_resolved {
            return Err(MaterializedGeneralJournalProductionRowError::AuxiliaryTopologyMismatch);
        }
        let balance = postings
            .values()
            .filter(|posting| posting.master_record_number == master)
            .try_fold(0_i128, |sum, posting| {
                sum.checked_add(i128::from(posting.signed_cents))
            })
            .ok_or(MaterializedGeneralJournalProductionRowError::AuxiliaryMasterNotBalanced)?;
        if balance != 0 {
            return Err(MaterializedGeneralJournalProductionRowError::AuxiliaryMasterNotBalanced);
        }
        for index in indices {
            result[index] = Some(MaterializedGeneralJournalDisposition::AuxiliaryLinkChain {
                master_record_number: master,
                target_record_number: u32_at(&rows[index], PRODUCTION_TARGET),
            });
        }
    }
    Ok(())
}

fn validate_production_header(
    input: &[u8],
) -> Result<(), MaterializedGeneralJournalProductionRowError> {
    if input.len() < PRODUCTION_FIXED_END {
        return Err(
            MaterializedGeneralJournalProductionRowError::SegmentTooShort {
                actual: input.len(),
                minimum: PRODUCTION_FIXED_END,
            },
        );
    }
    let declared = usize::from(u16_at(input, 0));
    if declared != input.len() {
        return Err(
            MaterializedGeneralJournalProductionRowError::DeclaredLengthMismatch {
                declared,
                actual: input.len(),
            },
        );
    }
    if input[2] != MATERIALIZED_GENERAL_JOURNAL_FLAGS {
        return Err(
            MaterializedGeneralJournalProductionRowError::UnexpectedFlags { actual: input[2] },
        );
    }
    if input[3] != MATERIALIZED_GENERAL_JOURNAL_ROW_KIND {
        return Err(
            MaterializedGeneralJournalProductionRowError::UnexpectedKind { actual: input[3] },
        );
    }
    Ok(())
}

fn production_required_reference(
    input: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<u32, MaterializedGeneralJournalProductionRowError> {
    let value = u32_at(input, offset);
    (value != 0)
        .then_some(value)
        .ok_or(MaterializedGeneralJournalProductionRowError::MissingRequiredReference { field })
}

#[cfg(test)]
mod tests {
    use super::*;
    const SAMPLE_MASTER: u32 = 0x1100;
    const SAMPLE_SOURCE: u32 = 0x1101;
    const SAMPLE_TARGET_A: u32 = 0x1102;
    const SAMPLE_TARGET_B: u32 = 0x1103;
    const SAMPLE_ACCOUNT_A: u32 = 0x2201;
    const SAMPLE_ACCOUNT_B: u32 = 0x2202;
    const SAMPLE_DATE_RAW: u32 = 0x0d5e_8000;
    fn common(row: &mut [u8], layout_marker: u8) {
        row[2] = MATERIALIZED_GENERAL_JOURNAL_FLAGS;
        row[3] = MATERIALIZED_GENERAL_JOURNAL_ROW_KIND;
        row[4..0x0b].copy_from_slice(&[0xe0, layout_marker, 0xff, 0xc0, 0x60, 0x80, 0x20]);
    }
    fn source_link() -> Vec<u8> {
        let mut row = vec![0; SOURCE_MIN_LEN];
        let length = row.len() as u16;
        row[..2].copy_from_slice(&length.to_le_bytes());
        row[2] = MATERIALIZED_GENERAL_JOURNAL_FLAGS;
        row[3] = MATERIALIZED_GENERAL_JOURNAL_ROW_KIND;
        row[4..0x0b].copy_from_slice(&SOURCE_LAYOUT_PREFIX);
        row[SOURCE_RECORD..SOURCE_RECORD + 4].copy_from_slice(&SAMPLE_SOURCE.to_le_bytes());
        row[SOURCE_MASTER..SOURCE_MASTER + 4].copy_from_slice(&SAMPLE_MASTER.to_le_bytes());
        row[SOURCE_DATE..SOURCE_DATE + 4].copy_from_slice(&SAMPLE_DATE_RAW.to_le_bytes());
        row[SOURCE_VIEW..SOURCE_VIEW + 2].copy_from_slice(&8_u16.to_le_bytes());
        row[SOURCE_NEXT..SOURCE_NEXT + 4].copy_from_slice(&SAMPLE_TARGET_A.to_le_bytes());
        row[SOURCE_ACCOUNT..SOURCE_ACCOUNT + 4].copy_from_slice(&SAMPLE_ACCOUNT_A.to_le_bytes());
        row
    }
    fn target(
        target: u32,
        account: u32,
        next: Option<u32>,
        shape: MaterializedGeneralJournalPostingTargetShape,
        amount: &[u8],
    ) -> Vec<u8> {
        let (layout_marker, amount_offset) = match shape {
            MaterializedGeneralJournalPostingTargetShape::Linked => {
                (LINKED_TARGET_LAYOUT_MARKER, LINKED_TARGET_AMOUNT)
            }
            MaterializedGeneralJournalPostingTargetShape::Terminal => {
                (TERMINAL_TARGET_LAYOUT_MARKER, TERMINAL_TARGET_AMOUNT)
            }
        };
        let mut row = vec![0; amount_offset + amount.len()];
        let length = row.len() as u16;
        row[..2].copy_from_slice(&length.to_le_bytes());
        common(&mut row, layout_marker);
        row[TARGET_RECORD..TARGET_RECORD + 4].copy_from_slice(&target.to_le_bytes());
        row[TARGET_MASTER..TARGET_MASTER + 4].copy_from_slice(&SAMPLE_MASTER.to_le_bytes());
        row[TARGET_ACCOUNT..TARGET_ACCOUNT + 4].copy_from_slice(&account.to_le_bytes());
        row[TARGET_DATE..TARGET_DATE + 4].copy_from_slice(&SAMPLE_DATE_RAW.to_le_bytes());
        row[TARGET_VIEW..TARGET_VIEW + 2].copy_from_slice(&8_u16.to_le_bytes());
        row[TARGET_NEXT..TARGET_NEXT + 4].copy_from_slice(&next.unwrap_or_default().to_le_bytes());
        row[amount_offset..amount_offset + amount.len()].copy_from_slice(amount);
        row
    }
    #[test]
    fn source_link_and_target_keep_their_distinct_field_offsets() {
        let source = MaterializedGeneralJournalSourceLinkRow::parse(&source_link()).unwrap();
        assert_eq!(source.source_link_record_number(), SAMPLE_SOURCE);
        assert_eq!(source.master_record_number(), SAMPLE_MASTER);
        assert_eq!(source.date_raw(), SAMPLE_DATE_RAW);
        assert_eq!(source.view_type(), 8);
        assert_eq!(source.next_target_record_number(), Some(SAMPLE_TARGET_A));
        assert_eq!(source.account_record_number(), SAMPLE_ACCOUNT_A);
        let posting = MaterializedGeneralJournalPostingTargetRow::parse(&target(
            SAMPLE_TARGET_A,
            SAMPLE_ACCOUNT_A,
            Some(SAMPLE_TARGET_B),
            MaterializedGeneralJournalPostingTargetShape::Linked,
            &[3, 0xbf, 57, 34, 12],
        ))
        .unwrap();
        assert_eq!(posting.target_record_number(), SAMPLE_TARGET_A);
        assert_eq!(posting.master_record_number(), SAMPLE_MASTER);
        assert_eq!(posting.account_record_number(), SAMPLE_ACCOUNT_A);
        assert_eq!(posting.date_raw(), SAMPLE_DATE_RAW);
        assert_eq!(posting.view_type(), 8);
        assert_eq!(posting.next_target_record_number(), Some(SAMPLE_TARGET_B));
        assert_eq!(posting.signed_cents(), 123_457);
        assert_eq!(
            posting.shape(),
            MaterializedGeneralJournalPostingTargetShape::Linked
        );
    }
    #[test]
    fn decodes_controlled_positive_negative_and_zero_target_amounts() {
        assert_eq!(
            MaterializedGeneralJournalPostingTargetRow::parse(&target(
                SAMPLE_TARGET_A,
                SAMPLE_ACCOUNT_A,
                Some(SAMPLE_TARGET_B),
                MaterializedGeneralJournalPostingTargetShape::Linked,
                &[2, 0xbf, 76, 98]
            ))
            .unwrap()
            .signed_cents(),
            9_876
        );
        assert_eq!(
            MaterializedGeneralJournalPostingTargetRow::parse(&target(
                SAMPLE_TARGET_B,
                SAMPLE_ACCOUNT_B,
                None,
                MaterializedGeneralJournalPostingTargetShape::Terminal,
                &[3, 0x3f, 11, 11, 11]
            ))
            .unwrap()
            .signed_cents(),
            -111_111
        );
        let zero = MaterializedGeneralJournalPostingTargetRow::parse(&target(
            SAMPLE_TARGET_B,
            SAMPLE_ACCOUNT_B,
            None,
            MaterializedGeneralJournalPostingTargetShape::Terminal,
            &[0, 0x81],
        ))
        .unwrap();
        assert!(zero.has_canonical_zero_amount());
        assert_eq!(zero.signed_cents(), 0);
    }
    #[test]
    fn rejects_cross_shape_and_uncontrolled_input() {
        let terminal = MaterializedGeneralJournalPostingTargetRow::parse(&target(
            SAMPLE_TARGET_B,
            SAMPLE_ACCOUNT_B,
            None,
            MaterializedGeneralJournalPostingTargetShape::Terminal,
            &[2, 0x3f, 19, 47],
        ))
        .unwrap();
        assert_eq!(terminal.signed_cents(), -4_719);
        assert_eq!(
            terminal.shape(),
            MaterializedGeneralJournalPostingTargetShape::Terminal
        );

        let terminal_with_link = target(
            SAMPLE_TARGET_B,
            SAMPLE_ACCOUNT_B,
            Some(SAMPLE_TARGET_A),
            MaterializedGeneralJournalPostingTargetShape::Terminal,
            &[2, 0x3f, 19, 47],
        );
        assert!(matches!(
            MaterializedGeneralJournalPostingTargetRow::parse(&terminal_with_link),
            Err(MaterializedGeneralJournalPostingRowError::UnexpectedTerminalLinkFields { .. })
        ));

        let source = source_link();
        assert!(matches!(
            MaterializedGeneralJournalPostingTargetRow::parse(&source),
            Err(MaterializedGeneralJournalPostingRowError::SegmentTooShort { .. })
        ));
        let mut bad_length = target(
            SAMPLE_TARGET_A,
            SAMPLE_ACCOUNT_A,
            None,
            MaterializedGeneralJournalPostingTargetShape::Linked,
            &[1, 0xbf, 1],
        );
        bad_length[0] = 0;
        assert!(matches!(
            MaterializedGeneralJournalPostingTargetRow::parse(&bad_length),
            Err(MaterializedGeneralJournalPostingRowError::DeclaredLengthMismatch { .. })
        ));
        let mut bad_layout = target(
            SAMPLE_TARGET_A,
            SAMPLE_ACCOUNT_A,
            None,
            MaterializedGeneralJournalPostingTargetShape::Linked,
            &[1, 0xbf, 1],
        );
        bad_layout[TARGET_LAYOUT_MARKER_OFFSET] = 0x99;
        assert!(matches!(
            MaterializedGeneralJournalPostingTargetRow::parse(&bad_layout),
            Err(
                MaterializedGeneralJournalPostingRowError::UnexpectedTargetLayoutMarker {
                    actual: 0x99
                }
            )
        ));
        let bad_marker = target(
            SAMPLE_TARGET_A,
            SAMPLE_ACCOUNT_A,
            Some(SAMPLE_TARGET_B),
            MaterializedGeneralJournalPostingTargetShape::Linked,
            &[1, 0x99, 1],
        );
        assert!(matches!(
            MaterializedGeneralJournalPostingTargetRow::parse(&bad_marker),
            Err(
                MaterializedGeneralJournalPostingRowError::UnsupportedAmountMarker { marker: 0x99 }
            )
        ));
        let missing_link = target(
            SAMPLE_TARGET_A,
            SAMPLE_ACCOUNT_A,
            None,
            MaterializedGeneralJournalPostingTargetShape::Linked,
            &[1, 0xbf, 1],
        );
        assert!(matches!(
            MaterializedGeneralJournalPostingTargetRow::parse(&missing_link),
            Err(MaterializedGeneralJournalPostingRowError::MissingLinkedTargetRecordNumber)
        ));
    }

    #[test]
    fn legacy_parsers_reject_zero_identifiers_and_trailing_data() {
        let mut zero_source = source_link();
        zero_source[SOURCE_RECORD..SOURCE_RECORD + 4].fill(0);
        assert!(matches!(
            MaterializedGeneralJournalSourceLinkRow::parse(&zero_source),
            Err(
                MaterializedGeneralJournalPostingRowError::MissingRequiredReference {
                    field: "source/link"
                }
            )
        ));

        let mut zero_target = target(
            SAMPLE_TARGET_A,
            SAMPLE_ACCOUNT_A,
            Some(SAMPLE_TARGET_B),
            MaterializedGeneralJournalPostingTargetShape::Linked,
            &[1, 0xbf, 1],
        );
        zero_target[TARGET_ACCOUNT..TARGET_ACCOUNT + 4].fill(0);
        assert!(matches!(
            MaterializedGeneralJournalPostingTargetRow::parse(&zero_target),
            Err(
                MaterializedGeneralJournalPostingRowError::MissingRequiredReference {
                    field: "account"
                }
            )
        ));

        let mut trailing_source = source_link();
        trailing_source.push(0);
        let source_length = trailing_source.len() as u16;
        trailing_source[..2].copy_from_slice(&source_length.to_le_bytes());
        assert!(matches!(
            MaterializedGeneralJournalSourceLinkRow::parse(&trailing_source),
            Err(MaterializedGeneralJournalPostingRowError::UnexpectedTrailingData { .. })
        ));

        let mut trailing_target = target(
            SAMPLE_TARGET_A,
            SAMPLE_ACCOUNT_A,
            Some(SAMPLE_TARGET_B),
            MaterializedGeneralJournalPostingTargetShape::Linked,
            &[1, 0xbf, 1],
        );
        trailing_target.push(0);
        let target_length = trailing_target.len() as u16;
        trailing_target[..2].copy_from_slice(&target_length.to_le_bytes());
        assert!(matches!(
            MaterializedGeneralJournalPostingTargetRow::parse(&trailing_target),
            Err(MaterializedGeneralJournalPostingRowError::UnexpectedTrailingData { .. })
        ));
    }

    fn production_row(amount: &[u8]) -> Vec<u8> {
        let base = PRODUCTION_AMOUNT_BASE;
        let mut row = vec![0_u8; base + amount.len() + 12];
        row[2] = MATERIALIZED_GENERAL_JOURNAL_FLAGS;
        row[3] = MATERIALIZED_GENERAL_JOURNAL_ROW_KIND;
        row[PRODUCTION_PREFIX_OFFSET] = 0xe0;
        row[PRODUCTION_LINK_MARKER_OFFSET] = 0x13;
        row[PRODUCTION_PREFIX_REQUIRED_BYTE] = PRODUCTION_PREFIX_REQUIRED_VALUE;
        row[PRODUCTION_TARGET..PRODUCTION_TARGET + 4]
            .copy_from_slice(&0x0100_0001_u32.to_le_bytes());
        row[PRODUCTION_MASTER..PRODUCTION_MASTER + 4]
            .copy_from_slice(&0x0100_0002_u32.to_le_bytes());
        row[PRODUCTION_ACCOUNT..PRODUCTION_ACCOUNT + 4]
            .copy_from_slice(&0x0100_0003_u32.to_le_bytes());
        let date = crate::MaterializedPostingDate::from_ymd(2026, 8, 27).unwrap();
        row[PRODUCTION_DATE..PRODUCTION_DATE + 4].copy_from_slice(&date.raw_bits().to_le_bytes());
        row[PRODUCTION_VIEW..PRODUCTION_VIEW + 2].copy_from_slice(&9_u16.to_le_bytes());
        let offset = base - 4;
        row[offset..offset + amount.len()].copy_from_slice(amount);
        row[base + 3..base + 3 + amount.len()].copy_from_slice(amount);
        let length = row.len() as u16;
        row[..2].copy_from_slice(&length.to_le_bytes());
        row
    }

    fn production_source(target: u32, next: u32) -> Vec<u8> {
        let mut source = vec![0_u8; 143];
        source[..2].copy_from_slice(&143_u16.to_le_bytes());
        source[2] = MATERIALIZED_GENERAL_JOURNAL_FLAGS;
        source[3] = MATERIALIZED_GENERAL_JOURNAL_ROW_KIND;
        source[4..11].copy_from_slice(&[0x60, 0x93, 0xff, 0x80, 0x40, 0x00, 0x20]);
        source[SOURCE_RECORD..SOURCE_RECORD + 4].copy_from_slice(&target.to_le_bytes());
        source[SOURCE_MASTER..SOURCE_MASTER + 4].copy_from_slice(&0x0100_0002_u32.to_le_bytes());
        let date = crate::MaterializedPostingDate::from_ymd(2026, 8, 27).unwrap();
        source[SOURCE_DATE..SOURCE_DATE + 4].copy_from_slice(&date.raw_bits().to_le_bytes());
        source[SOURCE_NEXT..SOURCE_NEXT + 4].copy_from_slice(&next.to_le_bytes());
        source[SOURCE_ACCOUNT..SOURCE_ACCOUNT + 4].copy_from_slice(&0x0100_0003_u32.to_le_bytes());
        source
    }

    #[test]
    fn production_table3078_requires_a_shape_bounded_amount_and_later_copy() {
        let row = MaterializedGeneralJournalPostingRow::parse(&production_row(&[2, 0xbf, 34, 12]))
            .unwrap();
        assert_eq!(row.signed_cents(), 1_234);
        assert_eq!(
            row.amount_position(),
            MaterializedGeneralJournalAmountPosition::MainPrebase
        );
        let mut without_copy = production_row(&[2, 0xbf, 34, 12]);
        without_copy[PRODUCTION_AMOUNT_BASE + 3] ^= 1;
        assert!(MaterializedGeneralJournalPostingRow::parse(&without_copy).is_err());
    }

    #[test]
    fn production_linked_overlap_accepts_the_count_one_discriminator() {
        let mut row = production_row(&[]);
        row.resize(0x90, 0);
        let length = row.len() as u16;
        row[..2].copy_from_slice(&length.to_le_bytes());
        row[PRODUCTION_LINK_MARKER_OFFSET] = 0x93;
        row[PRODUCTION_NEXT_TARGET..PRODUCTION_NEXT_TARGET + 4]
            .copy_from_slice(&0x0100_0004_u32.to_le_bytes());
        let base = PRODUCTION_AMOUNT_BASE + PRODUCTION_AMOUNT_LINKED_SHIFT;
        row[base - 3..base + 2].copy_from_slice(&[2, 0xbf, 1, 0x3f, 8]);
        row[base + 6..base + 10].copy_from_slice(&[2, 0xbf, 1, 0x3f]);
        row[base + 12..base + 15].copy_from_slice(&[1, 0x3f, 8]);
        assert_eq!(
            MaterializedGeneralJournalPostingRow::parse(&row)
                .unwrap()
                .signed_cents(),
            6_301
        );
    }

    #[test]
    fn main_prebase_ambiguity_requires_one_uniquely_duplicated_candidate() {
        let e4_base = PRODUCTION_AMOUNT_BASE + 4 + PRODUCTION_AMOUNT_LINKED_SHIFT;
        let mut e4 = vec![0_u8; e4_base + 24];
        e4[e4_base - 3..e4_base + 2].copy_from_slice(&[2, 0xbf, 1, 0x3f, 8]);
        e4[e4_base + 8..e4_base + 12].copy_from_slice(&[2, 0xbf, 1, 0x3f]);
        let (_, e4_amount) = select_main_amount(&e4, 0xe4, true, e4_base).unwrap();
        assert_eq!(e4_amount.signed_cents(), 6_301);

        let mut e4_ambiguous = e4.clone();
        e4_ambiguous[e4_base + 14..e4_base + 17].copy_from_slice(&[1, 0x3f, 8]);
        assert!(matches!(
            select_main_amount(&e4_ambiguous, 0xe4, true, e4_base),
            Err(MaterializedGeneralJournalProductionRowError::AmbiguousAmountToken { .. })
        ));

        let e8_base = PRODUCTION_AMOUNT_BASE + 8 + PRODUCTION_AMOUNT_LINKED_SHIFT;
        let mut e8 = vec![0_u8; e8_base + 24];
        e8[e8_base - 6..e8_base - 3].copy_from_slice(&[1, 0xbf, 7]);
        e8[e8_base - 3..e8_base].copy_from_slice(&[1, 0x3f, 8]);
        e8[e8_base + 5..e8_base + 8].copy_from_slice(&[1, 0xbf, 7]);
        let (_, e8_amount) = select_main_amount(&e8, 0xe8, true, e8_base).unwrap();
        assert_eq!(e8_amount.signed_cents(), 7);
    }

    #[test]
    fn bounded_amount_windows_include_only_the_attested_edge_extensions() {
        let cases = [
            (
                0xe0,
                true,
                2_isize,
                MaterializedGeneralJournalAmountPosition::MainDirect,
            ),
            (
                0xe0,
                false,
                2,
                MaterializedGeneralJournalAmountPosition::MainDirect,
            ),
            (
                0xe4,
                true,
                -4,
                MaterializedGeneralJournalAmountPosition::MainPrebase,
            ),
            (
                0xe8,
                false,
                -7,
                MaterializedGeneralJournalAmountPosition::MainPrebase,
            ),
            (
                0xe8,
                false,
                -8,
                MaterializedGeneralJournalAmountPosition::MainPrebase,
            ),
            (
                0xe8,
                true,
                -8,
                MaterializedGeneralJournalAmountPosition::MainPrebase,
            ),
        ];
        for (family, linked, relative_offset, expected_position) in cases {
            let base = PRODUCTION_AMOUNT_BASE
                + usize::from(family - 0xe0)
                + if linked {
                    PRODUCTION_AMOUNT_LINKED_SHIFT
                } else {
                    0
                };
            let offset = usize::try_from((base as isize) + relative_offset).unwrap();
            let mut input = vec![0_u8; base + 32];
            input[offset..offset + 3].copy_from_slice(&[1, 0xbf, 7]);
            input[base + 20..base + 23].copy_from_slice(&[1, 0xbf, 7]);
            let (position, amount) = select_main_amount(&input, family, linked, base).unwrap();
            assert_eq!(position, expected_position);
            assert_eq!(amount.signed_cents(), 7);
        }
    }

    #[test]
    fn e8_link_class_17_requires_the_normal_duplicated_amount_proof() {
        let mut row = production_row(&[]);
        row.resize(0x120, 0);
        row[..2].copy_from_slice(&0x120_u16.to_le_bytes());
        row[4..11].copy_from_slice(&[0xe8, 0x97, 0xff, 0xc0, 0x60, 0x80, 0x20]);
        row[PRODUCTION_NEXT_TARGET..PRODUCTION_NEXT_TARGET + 4]
            .copy_from_slice(&0x0100_0004_u32.to_le_bytes());
        let base = PRODUCTION_AMOUNT_BASE + 8 + PRODUCTION_AMOUNT_LINKED_SHIFT;
        row[base - 3..base].copy_from_slice(&[1, 0xbf, 7]);
        row[base + 20..base + 23].copy_from_slice(&[1, 0xbf, 7]);
        let posting = MaterializedGeneralJournalPostingRow::parse(&row).unwrap();
        assert_eq!(posting.family(), 0xe8);
        assert_eq!(posting.signed_cents(), 7);

        row[base + 20] ^= 1;
        assert!(MaterializedGeneralJournalPostingRow::parse(&row).is_err());
    }

    #[test]
    fn e4_link_class_03_requires_its_fixed_duplicated_prebase_amount() {
        let mut row = production_row(&[]);
        row.resize(197, 0);
        row[..2].copy_from_slice(&197_u16.to_le_bytes());
        row[4..11].copy_from_slice(&[0xe4, 0x83, 0xff, 0xc0, 0x60, 0x80, 0x20]);
        row[PRODUCTION_NEXT_TARGET..PRODUCTION_NEXT_TARGET + 4]
            .copy_from_slice(&0x0100_0004_u32.to_le_bytes());
        let base = PRODUCTION_AMOUNT_BASE + 4 + PRODUCTION_AMOUNT_LINKED_SHIFT;
        row[base - 8..base - 5].copy_from_slice(&[1, 0xbf, 7]);
        row[base + 20..base + 23].copy_from_slice(&[1, 0xbf, 7]);
        let posting = MaterializedGeneralJournalPostingRow::parse(&row).unwrap();
        assert_eq!(posting.family(), 0xe4);
        assert_eq!(posting.signed_cents(), 7);

        let mut without_copy = row.clone();
        without_copy[base + 20] ^= 1;
        assert!(MaterializedGeneralJournalPostingRow::parse(&without_copy).is_err());

        let mut wrong_position = row.clone();
        wrong_position[base - 8..base - 5].fill(0);
        wrong_position[base - 4..base - 1].copy_from_slice(&[1, 0xbf, 7]);
        assert!(MaterializedGeneralJournalPostingRow::parse(&wrong_position).is_err());

        let mut ordinary_e4 = row;
        ordinary_e4[PRODUCTION_LINK_MARKER_OFFSET] = 0x93;
        assert!(MaterializedGeneralJournalPostingRow::parse(&ordinary_e4).is_err());
    }

    #[test]
    fn short_e4_terminal_requires_its_exact_primary_and_copy_positions() {
        let mut row = production_row(&[]);
        row.resize(129, 0);
        row[..2].copy_from_slice(&129_u16.to_le_bytes());
        row[4..11].copy_from_slice(&[0xe4, 0x13, 0x9f, 0xc0, 0x60, 0x80, 0x20]);
        let base = PRODUCTION_AMOUNT_BASE + 4;
        row[base - 27..base - 24].copy_from_slice(&[1, 0xbf, 7]);
        row[base + 17..base + 20].copy_from_slice(&[1, 0xbf, 7]);
        let posting = MaterializedGeneralJournalPostingRow::parse(&row).unwrap();
        assert_eq!(posting.signed_cents(), 7);

        let mut changed_copy = row.clone();
        changed_copy[base + 19] ^= 1;
        assert!(MaterializedGeneralJournalPostingRow::parse(&changed_copy).is_err());

        let mut shifted = row.clone();
        shifted[base - 27..base - 24].fill(0);
        shifted[base - 26..base - 23].copy_from_slice(&[1, 0xbf, 7]);
        assert!(MaterializedGeneralJournalPostingRow::parse(&shifted).is_err());

        let mut wrong_length = row.clone();
        wrong_length.resize(130, 0);
        wrong_length[..2].copy_from_slice(&130_u16.to_le_bytes());
        assert!(MaterializedGeneralJournalPostingRow::parse(&wrong_length).is_err());

        let mut ordinary_prefix = row.clone();
        ordinary_prefix[PRODUCTION_PREFIX_REQUIRED_BYTE] = PRODUCTION_PREFIX_REQUIRED_VALUE;
        assert!(MaterializedGeneralJournalPostingRow::parse(&ordinary_prefix).is_err());

        assert!(
            validate_materialized_general_journal_master_balances(std::slice::from_ref(&posting))
                .is_err()
        );
        let mut opposite = production_row(&[1, 0x3f, 7]);
        opposite[PRODUCTION_TARGET..PRODUCTION_TARGET + 4]
            .copy_from_slice(&0x0100_0004_u32.to_le_bytes());
        let opposite = MaterializedGeneralJournalPostingRow::parse(&opposite).unwrap();
        assert_eq!(
            validate_materialized_general_journal_master_balances(&[posting, opposite]),
            Ok(())
        );
    }

    #[test]
    fn direct_e0_overlap_prefers_unique_copy_then_canonical_base() {
        let base = PRODUCTION_AMOUNT_BASE + PRODUCTION_AMOUNT_LINKED_SHIFT;
        let mut unique = vec![0_u8; base + 32];
        unique[base..base + 5].copy_from_slice(&[2, 0xbf, 1, 0x3f, 8]);
        unique[base + 10..base + 14].copy_from_slice(&[2, 0xbf, 1, 0x3f]);
        let (position, amount) = select_main_amount(&unique, 0xe0, true, base).unwrap();
        assert_eq!(
            position,
            MaterializedGeneralJournalAmountPosition::MainDirect
        );
        assert_eq!(amount.signed_cents(), 6_301);

        let mut both = unique;
        both[base + 18..base + 21].copy_from_slice(&[1, 0x3f, 8]);
        let (_, amount) = select_main_amount(&both, 0xe0, true, base).unwrap();
        assert_eq!(amount.signed_cents(), 6_301);

        let terminal_base = PRODUCTION_AMOUNT_BASE;
        let mut terminal = vec![0_u8; terminal_base + 32];
        terminal[terminal_base..terminal_base + 5].copy_from_slice(&[2, 0xbf, 1, 0x3f, 8]);
        terminal[terminal_base + 10..terminal_base + 14].copy_from_slice(&[2, 0xbf, 1, 0x3f]);
        terminal[terminal_base + 18..terminal_base + 21].copy_from_slice(&[1, 0x3f, 8]);
        let (_, amount) = select_main_amount(&terminal, 0xe0, false, terminal_base).unwrap();
        assert_eq!(amount.signed_cents(), 6_301);
    }

    #[test]
    fn production_table3078_retains_attested_zero_amount_and_absent_link_metadata() {
        let zero = production_row(&[0, 0x81]);
        assert!(matches!(
            MaterializedGeneralJournalPostingRow::parse(&zero),
            Err(MaterializedGeneralJournalProductionRowError::CanonicalZeroPosting)
        ));
        let dispositions = classify_materialized_general_journal_rows(&[zero]).unwrap();
        assert!(matches!(
            dispositions.as_slice(),
            [MaterializedGeneralJournalDisposition::CanonicalZeroAmount(amount)]
                if amount.master_record_number() == 0x0100_0002
        ));

        let mut linked = production_row(&[1, 0xbf, 7]);
        linked[PRODUCTION_LINK_MARKER_OFFSET] = 0x93;
        let linked_base = PRODUCTION_AMOUNT_BASE + PRODUCTION_AMOUNT_LINKED_SHIFT;
        linked[PRODUCTION_AMOUNT_BASE + 3..PRODUCTION_AMOUNT_BASE + 6].fill(0);
        linked[linked_base - 4..linked_base - 1].copy_from_slice(&[1, 0xbf, 7]);
        linked[linked_base + 3..linked_base + 6].copy_from_slice(&[1, 0xbf, 7]);
        assert_eq!(
            MaterializedGeneralJournalPostingRow::parse(&linked)
                .unwrap()
                .next_target_record_number(),
            None
        );
    }

    #[test]
    fn production_table3078_rejects_unbounded_tokens_and_invalid_dates() {
        let mut no_token = production_row(&[1, 0xbf, 7]);
        let base = PRODUCTION_AMOUNT_BASE;
        no_token[base - 4..base - 1].copy_from_slice(&[1, 0x99, 7]);
        no_token[base..base + 3].copy_from_slice(&[1, 0x99, 7]);
        assert!(MaterializedGeneralJournalPostingRow::parse(&no_token).is_err());

        let mut non_midnight = production_row(&[1, 0xbf, 7]);
        non_midnight[PRODUCTION_DATE..PRODUCTION_DATE + 4].copy_from_slice(&1_u32.to_le_bytes());
        assert!(matches!(
            MaterializedGeneralJournalPostingRow::parse(&non_midnight),
            Err(MaterializedGeneralJournalProductionRowError::InvalidPostingDate { .. })
        ));

        let mut terminal_link = production_row(&[1, 0xbf, 7]);
        terminal_link[PRODUCTION_NEXT_TARGET..PRODUCTION_NEXT_TARGET + 4]
            .copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            MaterializedGeneralJournalPostingRow::parse(&terminal_link)
                .unwrap()
                .next_target_record_number(),
            None
        );
    }

    #[test]
    fn special_envelope_without_its_bounded_token_remains_a_nonposting_carrier() {
        let mut auxiliary = production_row(&[]);
        auxiliary[4..11].copy_from_slice(&[0xe0, 0x13, 0x9f, 0xc0, 0x60, 0x80, 0x20]);
        assert_eq!(parse_special_posting(&auxiliary), Ok(None));
        auxiliary[4..11].copy_from_slice(&[0xe0, 0x83, 0xff, 0xc0, 0x60, 0x80, 0x20]);
        assert_eq!(parse_special_posting(&auxiliary), Ok(None));
        assert!(special_primary_offset(&auxiliary).is_some());
    }

    #[test]
    fn production_classifier_requires_source_topology_and_keeps_source_nonposting() {
        let posting = production_row(&[1, 0xbf, 7]);
        let source = production_source(0x0100_0100, 0x0100_0001);
        let dispositions =
            classify_materialized_general_journal_rows(&[posting.clone(), source.clone()]).unwrap();
        assert!(matches!(
            dispositions[0],
            MaterializedGeneralJournalDisposition::Posting(_)
        ));
        assert!(matches!(
            dispositions[1],
            MaterializedGeneralJournalDisposition::SourceOrLink(_)
        ));

        let mut terminal_source = source.clone();
        terminal_source[SOURCE_NEXT..SOURCE_NEXT + 4].fill(0);
        let terminal_dispositions =
            classify_materialized_general_journal_rows(&[posting, terminal_source.clone()])
                .unwrap();
        assert!(matches!(
            terminal_dispositions[1],
            MaterializedGeneralJournalDisposition::SourceOrLink(ref source)
                if source.next_target_record_number().is_none()
        ));
        assert!(classify_materialized_general_journal_rows(&[terminal_source]).is_err());

        let mut short_source = source.clone();
        short_source.resize(142, 0);
        short_source[..2].copy_from_slice(&142_u16.to_le_bytes());
        assert!(parse_source_link(&short_source).unwrap().is_some());
        assert!(
            classify_materialized_general_journal_rows(&[
                production_row(&[1, 0xbf, 7]),
                short_source,
            ])
            .is_ok()
        );

        let mut shifted_source = source.clone();
        shifted_source.resize(151, 0);
        shifted_source[..2].copy_from_slice(&151_u16.to_le_bytes());
        shifted_source[4..11].copy_from_slice(&[0x64, 0x93, 0xff, 0xc0, 0x40, 0x80, 0x20]);
        assert!(parse_source_link(&shifted_source).unwrap().is_some());
        assert!(
            classify_materialized_general_journal_rows(&[
                production_row(&[1, 0xbf, 7]),
                shifted_source,
            ])
            .is_ok()
        );

        let mut extended_terminal_source = source;
        extended_terminal_source.resize(201, 0);
        extended_terminal_source[..2].copy_from_slice(&201_u16.to_le_bytes());
        extended_terminal_source[4..11]
            .copy_from_slice(&[0x64, 0x13, 0xff, 0x80, 0x60, 0x00, 0x20]);
        extended_terminal_source[SOURCE_NEXT..SOURCE_NEXT + 4].fill(0);
        assert!(
            parse_source_link(&extended_terminal_source)
                .unwrap()
                .is_some()
        );
        assert!(
            classify_materialized_general_journal_rows(&[
                production_row(&[1, 0xbf, 7]),
                extended_terminal_source.clone(),
            ])
            .is_ok()
        );
        assert!(
            classify_materialized_general_journal_rows(&[extended_terminal_source.clone()])
                .is_err()
        );

        extended_terminal_source[4] ^= 1;
        assert!(
            parse_source_link(&extended_terminal_source)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn production_classifier_allows_a_proven_source_to_terminal_source_chain() {
        let posting = production_row(&[1, 0xbf, 7]);
        let upstream = production_source(0x0100_0100, 0x0100_0101);
        let terminal = production_source(0x0100_0101, 0);
        let dispositions = classify_materialized_general_journal_rows(&[
            posting.clone(),
            upstream.clone(),
            terminal.clone(),
        ])
        .unwrap();
        assert!(matches!(
            dispositions.as_slice(),
            [
                MaterializedGeneralJournalDisposition::Posting(_),
                MaterializedGeneralJournalDisposition::SourceOrLink(_),
                MaterializedGeneralJournalDisposition::SourceOrLink(_),
            ]
        ));

        assert!(
            classify_materialized_general_journal_rows(&[upstream.clone(), terminal.clone(),])
                .is_err()
        );

        let mut mismatched = terminal.clone();
        mismatched[SOURCE_MASTER..SOURCE_MASTER + 4]
            .copy_from_slice(&0x0100_0004_u32.to_le_bytes());
        assert!(
            classify_materialized_general_journal_rows(&[
                posting.clone(),
                upstream.clone(),
                mismatched,
            ])
            .is_err()
        );

        let mut cycle = terminal;
        cycle[SOURCE_NEXT..SOURCE_NEXT + 4].copy_from_slice(&0x0100_0100_u32.to_le_bytes());
        assert!(classify_materialized_general_journal_rows(&[posting, upstream, cycle]).is_err());

        let zero = production_row(&[0, 0x81]);
        let duplicate_zero_target = production_source(0x0100_0001, 0);
        assert!(matches!(
            classify_materialized_general_journal_rows(&[zero, duplicate_zero_target]),
            Err(MaterializedGeneralJournalProductionRowError::DuplicateTarget)
        ));

        let zero_only = production_row(&[0, 0x81]);
        let terminal_source = production_source(0x0100_0100, 0);
        assert!(
            classify_materialized_general_journal_rows(&[zero_only, terminal_source.clone(),])
                .is_err()
        );

        let positive = production_row(&[1, 0xbf, 7]);
        let mut negative = production_row(&[1, 0x3f, 7]);
        negative[PRODUCTION_TARGET..PRODUCTION_TARGET + 4]
            .copy_from_slice(&0x0100_0004_u32.to_le_bytes());
        assert!(
            classify_materialized_general_journal_rows(&[positive, negative, terminal_source,])
                .is_err()
        );
    }

    fn header_witness(id: u32, date_raw: u32, group: u32) -> Vec<u8> {
        let mut header = vec![0_u8; 23];
        let declared_length = header.len() as u16;
        header[..2].copy_from_slice(&declared_length.to_le_bytes());
        header[2] = MATERIALIZED_GENERAL_JOURNAL_FLAGS;
        header[3] = MATERIALIZED_GENERAL_JOURNAL_ROW_KIND;
        header[4..7].copy_from_slice(&[0xa7, 0xfe, 0]);
        header[11..15].copy_from_slice(&id.to_le_bytes());
        header[15..19].copy_from_slice(&date_raw.to_le_bytes());
        header[19..23].copy_from_slice(&group.to_le_bytes());
        header
    }

    #[test]
    fn header_metadata_family_requires_one_exact_balanced_header_witness() {
        let positive = production_row(&[1, 0xbf, 7]);
        let mut negative = production_row(&[1, 0x3f, 7]);
        negative[PRODUCTION_TARGET..PRODUCTION_TARGET + 4]
            .copy_from_slice(&0x0100_0004_u32.to_le_bytes());
        let mut source = production_source(0x0100_0100, 77);
        source.resize(151, 0);
        source[..2].copy_from_slice(&151_u16.to_le_bytes());
        source[4..11].copy_from_slice(&[0x64, 0x93, 0xff, 0xc0, 0x40, 0x80, 0x20]);
        let date_raw = u32_at(&source, SOURCE_DATE);
        let header =
            GeneralJournalHeaderMetadataWitness::parse(&header_witness(0x0100_0003, date_raw, 77))
                .unwrap();

        assert!(
            classify_materialized_general_journal_rows(&[
                positive.clone(),
                negative.clone(),
                source.clone(),
            ])
            .is_err()
        );
        let dispositions = classify_materialized_general_journal_rows_with_header_witnesses(
            &[positive.clone(), negative.clone(), source.clone()],
            &[header],
        )
        .unwrap();
        assert!(matches!(
            dispositions[2],
            MaterializedGeneralJournalDisposition::HeaderMetadataCarrier {
                master_record_number: 0x0100_0002,
                header_group: 77,
            }
        ));

        assert!(
            classify_materialized_general_journal_rows_with_header_witnesses(
                &[positive, negative, source],
                &[header, header],
            )
            .is_err()
        );
    }

    #[test]
    fn header_witness_rejects_malformed_framing_and_unbalanced_context() {
        let date = crate::MaterializedPostingDate::from_ymd(2026, 8, 27)
            .unwrap()
            .raw_bits();
        let mut malformed = header_witness(3, date, 77);
        malformed.push(0);
        assert!(GeneralJournalHeaderMetadataWitness::parse(&malformed).is_err());

        let mut source = production_source(0x0100_0100, 77);
        source.resize(151, 0);
        source[..2].copy_from_slice(&151_u16.to_le_bytes());
        source[4..11].copy_from_slice(&[0x64, 0x93, 0xff, 0xc0, 0x40, 0x80, 0x20]);
        let witness = GeneralJournalHeaderMetadataWitness::parse(&header_witness(
            0x0100_0003,
            u32_at(&source, SOURCE_DATE),
            77,
        ))
        .unwrap();
        assert!(
            classify_materialized_general_journal_rows_with_header_witnesses(
                &[production_row(&[1, 0xbf, 7]), source],
                &[witness],
            )
            .is_err()
        );
    }

    #[test]
    fn header_context_does_not_override_a_resolved_legacy_source() {
        let posting = production_row(&[1, 0xbf, 7]);
        let mut source = production_source(0x0100_0100, 0x0100_0001);
        source.resize(151, 0);
        source[..2].copy_from_slice(&151_u16.to_le_bytes());
        source[4..11].copy_from_slice(&[0x64, 0x93, 0xff, 0xc0, 0x40, 0x80, 0x20]);
        let unrelated = GeneralJournalHeaderMetadataWitness::parse(&header_witness(
            0x0100_0003,
            u32_at(&source, SOURCE_DATE),
            77,
        ))
        .unwrap();
        let dispositions = classify_materialized_general_journal_rows_with_header_witnesses(
            &[posting, source],
            &[unrelated],
        )
        .unwrap();
        assert!(matches!(
            dispositions[1],
            MaterializedGeneralJournalDisposition::SourceOrLink(_)
        ));
    }

    #[test]
    fn header_metadata_rejects_conflicting_id_and_different_date_master_posting() {
        let positive = production_row(&[1, 0xbf, 7]);
        let mut negative = production_row(&[1, 0x3f, 7]);
        negative[PRODUCTION_TARGET..PRODUCTION_TARGET + 4]
            .copy_from_slice(&0x0100_0004_u32.to_le_bytes());
        let mut source = production_source(0x0100_0100, 77);
        source.resize(151, 0);
        source[..2].copy_from_slice(&151_u16.to_le_bytes());
        source[4..11].copy_from_slice(&[0x64, 0x93, 0xff, 0xc0, 0x40, 0x80, 0x20]);
        let date_raw = u32_at(&source, SOURCE_DATE);
        let expected =
            GeneralJournalHeaderMetadataWitness::parse(&header_witness(0x0100_0003, date_raw, 77))
                .unwrap();
        let conflicting =
            GeneralJournalHeaderMetadataWitness::parse(&header_witness(0x0100_0005, date_raw, 77))
                .unwrap();
        assert!(
            classify_materialized_general_journal_rows_with_header_witnesses(
                &[positive.clone(), negative.clone(), source.clone()],
                &[expected, conflicting],
            )
            .is_err()
        );

        let duplicate_expected_id =
            GeneralJournalHeaderMetadataWitness::parse(&header_witness(0x0100_0003, date_raw, 78))
                .unwrap();
        assert!(
            classify_materialized_general_journal_rows_with_header_witnesses(
                &[positive.clone(), negative.clone(), source.clone()],
                &[expected, duplicate_expected_id],
            )
            .is_err()
        );

        let different_date = crate::MaterializedPostingDate::from_ymd(2026, 8, 28)
            .unwrap()
            .raw_bits();
        negative[PRODUCTION_DATE..PRODUCTION_DATE + 4]
            .copy_from_slice(&different_date.to_le_bytes());
        assert!(
            classify_materialized_general_journal_rows_with_header_witnesses(
                &[positive, negative, source],
                &[expected],
            )
            .is_err()
        );
    }

    fn auxiliary_row(target: u32, next: u32, linked: bool) -> Vec<u8> {
        let mut row = vec![0_u8; 0x50];
        let length = row.len() as u16;
        row[..2].copy_from_slice(&length.to_le_bytes());
        row[2] = MATERIALIZED_GENERAL_JOURNAL_FLAGS;
        row[3] = MATERIALIZED_GENERAL_JOURNAL_ROW_KIND;
        row[4..11].copy_from_slice(if linked {
            &[0xe0, 0x93, 0xff, 0x80, 0x60, 0x00, 0x20]
        } else {
            &[0xe0, 0x13, 0xff, 0x80, 0x60, 0x00, 0x20]
        });
        row[PRODUCTION_TARGET..PRODUCTION_TARGET + 4].copy_from_slice(&target.to_le_bytes());
        row[PRODUCTION_MASTER..PRODUCTION_MASTER + 4].copy_from_slice(&SAMPLE_MASTER.to_le_bytes());
        row[PRODUCTION_ACCOUNT..PRODUCTION_ACCOUNT + 4]
            .copy_from_slice(&SAMPLE_ACCOUNT_A.to_le_bytes());
        row[PRODUCTION_VIEW..PRODUCTION_VIEW + 2].copy_from_slice(&8_u16.to_le_bytes());
        row[PRODUCTION_NEXT_TARGET..PRODUCTION_NEXT_TARGET + 4]
            .copy_from_slice(&next.to_le_bytes());
        let date = (1..=28)
            .map(|day| crate::MaterializedPostingDate::from_ymd(2026, 8, day).unwrap())
            .find(|date| {
                row[PRODUCTION_DATE..PRODUCTION_DATE + 4]
                    .copy_from_slice(&date.raw_bits().to_le_bytes());
                bounded_token(&row, PRODUCTION_DATE).is_none()
            })
            .unwrap();
        row[PRODUCTION_DATE..PRODUCTION_DATE + 4].copy_from_slice(&date.raw_bits().to_le_bytes());
        row
    }

    fn balanced_postings_for_auxiliary_context(
        date_raw: u32,
        external_account: u32,
    ) -> [Vec<u8>; 2] {
        let mut positive = production_row(&[1, 0xbf, 7]);
        positive[PRODUCTION_TARGET..PRODUCTION_TARGET + 4]
            .copy_from_slice(&0x0100_0001_u32.to_le_bytes());
        positive[PRODUCTION_MASTER..PRODUCTION_MASTER + 4]
            .copy_from_slice(&SAMPLE_MASTER.to_le_bytes());
        positive[PRODUCTION_ACCOUNT..PRODUCTION_ACCOUNT + 4]
            .copy_from_slice(&external_account.to_le_bytes());
        positive[PRODUCTION_DATE..PRODUCTION_DATE + 4].copy_from_slice(&date_raw.to_le_bytes());

        let mut negative = production_row(&[1, 0x3f, 7]);
        negative[PRODUCTION_TARGET..PRODUCTION_TARGET + 4]
            .copy_from_slice(&0x0100_0002_u32.to_le_bytes());
        negative[PRODUCTION_MASTER..PRODUCTION_MASTER + 4]
            .copy_from_slice(&SAMPLE_MASTER.to_le_bytes());
        negative[PRODUCTION_ACCOUNT..PRODUCTION_ACCOUNT + 4]
            .copy_from_slice(&0x0100_0005_u32.to_le_bytes());
        negative[PRODUCTION_DATE..PRODUCTION_DATE + 4].copy_from_slice(&date_raw.to_le_bytes());
        [positive, negative]
    }

    #[test]
    fn production_classifier_accepts_only_a_corroborated_terminal_metadata_carrier() {
        let terminal = auxiliary_row(SAMPLE_TARGET_A, SAMPLE_ACCOUNT_B, false);
        let date_raw = u32_at(&terminal, PRODUCTION_DATE);
        let [positive, negative] =
            balanced_postings_for_auxiliary_context(date_raw, SAMPLE_ACCOUNT_B);
        let dispositions = classify_materialized_general_journal_rows(&[
            positive.clone(),
            negative.clone(),
            terminal.clone(),
        ])
        .unwrap();
        assert!(matches!(
            dispositions.last(),
            Some(
                MaterializedGeneralJournalDisposition::TerminalMetadataCarrier {
                    master_record_number: SAMPLE_MASTER,
                    target_record_number: SAMPLE_TARGET_A,
                }
            )
        ));

        let linked = auxiliary_row(SAMPLE_TARGET_A, SAMPLE_ACCOUNT_B, true);
        assert!(
            classify_materialized_general_journal_rows(&[
                positive.clone(),
                negative.clone(),
                linked,
            ])
            .is_err()
        );

        let zero_next = auxiliary_row(SAMPLE_TARGET_A, 0, false);
        assert!(
            classify_materialized_general_journal_rows(&[
                positive.clone(),
                negative.clone(),
                zero_next,
            ])
            .is_err()
        );

        let mut monetary = terminal.clone();
        monetary[0x40..0x43].copy_from_slice(&[1, 0xbf, 7]);
        assert!(
            classify_materialized_general_journal_rows(&[
                positive.clone(),
                negative.clone(),
                monetary,
            ])
            .is_err()
        );

        let mut no_match = positive.clone();
        no_match[PRODUCTION_ACCOUNT..PRODUCTION_ACCOUNT + 4]
            .copy_from_slice(&0x0100_0006_u32.to_le_bytes());
        assert!(
            classify_materialized_general_journal_rows(&[
                no_match,
                negative.clone(),
                terminal.clone(),
            ])
            .is_err()
        );

        let mut second_match = negative.clone();
        second_match[PRODUCTION_ACCOUNT..PRODUCTION_ACCOUNT + 4]
            .copy_from_slice(&SAMPLE_ACCOUNT_B.to_le_bytes());
        assert!(
            classify_materialized_general_journal_rows(&[
                positive.clone(),
                second_match,
                terminal.clone(),
            ])
            .is_err()
        );

        assert!(
            classify_materialized_general_journal_rows(&[positive.clone(), terminal.clone(),])
                .is_err()
        );

        let mut duplicate_target = positive;
        duplicate_target[PRODUCTION_TARGET..PRODUCTION_TARGET + 4]
            .copy_from_slice(&SAMPLE_TARGET_A.to_le_bytes());
        assert!(
            classify_materialized_general_journal_rows(&[duplicate_target, negative, terminal,])
                .is_err()
        );
    }

    #[test]
    fn production_classifier_accepts_only_a_closed_two_node_auxiliary_group() {
        let linked = auxiliary_row(SAMPLE_TARGET_A, SAMPLE_TARGET_B, true);
        let terminal = auxiliary_row(SAMPLE_TARGET_B, SAMPLE_ACCOUNT_A, false);
        let numeric_candidates = [linked.as_slice(), terminal.as_slice()]
            .into_iter()
            .map(|row| {
                (0..row.len().saturating_sub(1))
                    .filter_map(|offset| bounded_token(row, offset).map(|_| offset))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert!(
            numeric_candidates.iter().all(Vec::is_empty),
            "synthetic negative-monetary fixture had candidates {numeric_candidates:?}"
        );
        let dispositions =
            classify_materialized_general_journal_rows(&[linked.clone(), terminal]).unwrap();
        assert!(dispositions.iter().all(|disposition| matches!(
            disposition,
            MaterializedGeneralJournalDisposition::AuxiliaryLinkChain { .. }
        )));

        let broken_terminal = auxiliary_row(SAMPLE_TARGET_B, SAMPLE_TARGET_A, false);
        assert!(classify_materialized_general_journal_rows(&[linked, broken_terminal]).is_err());

        let linked = auxiliary_row(SAMPLE_TARGET_A, SAMPLE_TARGET_B, true);
        let dangling_terminal = auxiliary_row(SAMPLE_TARGET_B, 0x0100_9999, false);
        assert!(classify_materialized_general_journal_rows(&[linked, dangling_terminal]).is_err());

        let linked = auxiliary_row(SAMPLE_TARGET_A, SAMPLE_TARGET_B, true);
        let unrelated_terminal = auxiliary_row(SAMPLE_TARGET_B, 0x0100_9999, false);
        let mut unrelated_positive = production_row(&[1, 0xbf, 7]);
        unrelated_positive[PRODUCTION_ACCOUNT..PRODUCTION_ACCOUNT + 4]
            .copy_from_slice(&0x0100_9999_u32.to_le_bytes());
        let mut unrelated_negative = production_row(&[1, 0x3f, 7]);
        unrelated_negative[PRODUCTION_TARGET..PRODUCTION_TARGET + 4]
            .copy_from_slice(&0x0100_0006_u32.to_le_bytes());
        assert!(
            classify_materialized_general_journal_rows(&[
                linked,
                unrelated_terminal,
                unrelated_positive,
                unrelated_negative,
            ])
            .is_err()
        );

        let target_c = 0x1104;
        let target_d = 0x1105;
        let four_node = [
            auxiliary_row(SAMPLE_TARGET_A, SAMPLE_TARGET_B, true),
            auxiliary_row(SAMPLE_TARGET_B, target_c, true),
            auxiliary_row(target_c, target_d, true),
            auxiliary_row(target_d, SAMPLE_ACCOUNT_A, false),
        ];
        assert!(classify_materialized_general_journal_rows(&four_node).is_ok());

        let mut header_false_positive_linked =
            auxiliary_row(SAMPLE_TARGET_A, SAMPLE_TARGET_B, true);
        let mut header_false_positive_terminal =
            auxiliary_row(SAMPLE_TARGET_B, SAMPLE_ACCOUNT_A, false);
        for row in [
            &mut header_false_positive_linked,
            &mut header_false_positive_terminal,
        ] {
            row[18..20].copy_from_slice(&[0, 0x81]);
        }
        let corroborated_account = u32_at(&header_false_positive_linked, PRODUCTION_ACCOUNT);
        header_false_positive_terminal[PRODUCTION_NEXT_TARGET..PRODUCTION_NEXT_TARGET + 4]
            .copy_from_slice(&corroborated_account.to_le_bytes());
        assert!(
            classify_materialized_general_journal_rows(&[
                header_false_positive_linked.clone(),
                header_false_positive_terminal.clone(),
            ])
            .is_ok()
        );

        let mut boundary_payload = header_false_positive_terminal.clone();
        boundary_payload[PRODUCTION_FIXED_END..PRODUCTION_FIXED_END + 3]
            .copy_from_slice(&[1, 0x3f, 7]);
        assert!(
            classify_materialized_general_journal_rows(&[
                header_false_positive_linked.clone(),
                boundary_payload,
            ])
            .is_err()
        );

        header_false_positive_terminal[0x40..0x42].copy_from_slice(&[0, 0x81]);
        assert!(
            classify_materialized_general_journal_rows(&[
                header_false_positive_linked,
                header_false_positive_terminal,
            ])
            .is_err()
        );

        let disconnected_cycle = [
            auxiliary_row(SAMPLE_TARGET_A, SAMPLE_TARGET_B, true),
            auxiliary_row(SAMPLE_TARGET_B, SAMPLE_TARGET_A, true),
            auxiliary_row(target_c, target_d, true),
            auxiliary_row(target_d, SAMPLE_ACCOUNT_A, false),
        ];
        assert!(classify_materialized_general_journal_rows(&disconnected_cycle).is_err());
    }
}

//! Fail-closed parsing of a bounded, runtime-materialized Account row prefix.
//!
//! It does not decode raw QBW pages or infer current/deleted state. The Account
//! type byte is name-relative (`0x40 + name_length`), not a fixed page offset.

use thiserror::Error;

/// The observed materialized Account row kind byte.
pub const MATERIALIZED_ACCOUNT_ROW_KIND: u8 = 0x40;
const NAME_LEN: usize = 0x24;
const NAME: usize = 0x25;
const TYPE_BASE: usize = 0x40;
const POST_TYPE_METADATA_DELTA: usize = 1;
const NUMBER_LENGTH_DELTA: usize = 5;

/// Account types calibrated by controlled materialized Account rows.
///
/// The named variants are independently calibrated. [`Self::Uncalibrated`]
/// preserves a structurally valid discriminator whose QuickBooks business
/// label has not yet been independently established; callers must not assign
/// accounting semantics to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializedAccountType {
    /// Controlled Bank code 0.
    Bank,
    /// Controlled Other Current Asset code 2.
    OtherCurrentAsset,
    /// Calibrated Credit Card code 6.
    CreditCard,
    /// Controlled Other Current Liability code 7.
    OtherCurrentLiability,
    /// Controlled Expense code 12.
    Expense,
    /// Controlled Other Income code 13.
    OtherIncome,
    /// A structurally witnessed but not yet semantically calibrated code.
    Uncalibrated(u8),
}

impl MaterializedAccountType {
    /// Returns the controlled discriminator byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Bank => 0,
            Self::OtherCurrentAsset => 2,
            Self::CreditCard => 6,
            Self::OtherCurrentLiability => 7,
            Self::Expense => 12,
            Self::OtherIncome => 13,
            Self::Uncalibrated(code) => code,
        }
    }

    const fn parse(code: u8) -> Self {
        match code {
            0 => Self::Bank,
            2 => Self::OtherCurrentAsset,
            6 => Self::CreditCard,
            7 => Self::OtherCurrentLiability,
            12 => Self::Expense,
            13 => Self::OtherIncome,
            _ => Self::Uncalibrated(code),
        }
    }
}

/// Confidence state of the optional account-number/description suffix.
///
/// This applies only to the suffix after the fixed Account envelope. It does
/// not establish current, visible, or lifecycle state for the Account row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializedAccountSuffixState {
    /// No suffix length byte was present after the fixed envelope.
    Omitted,
    /// Every supplied length-prefixed field was bounded and ASCII.
    Parsed,
    /// A suffix byte was present but did not form the witnessed bounded ASCII grammar.
    OpaqueOrMalformed,
}

/// Validated fields from the witnessed materialized Account row prefix.
///
/// The post-type metadata, activity, ListID, balances, and all bytes after
/// the bounded number/description grammar remain opaque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedAccountRow<'a> {
    raw: &'a [u8],
    kind: u8,
    record_number: u32,
    created: u32,
    modified: u32,
    name: &'a str,
    account_type: MaterializedAccountType,
    account_type_offset: usize,
    post_type_metadata_raw: u32,
    suffix_state: MaterializedAccountSuffixState,
    account_number: Option<&'a str>,
    description: Option<&'a str>,
}

impl<'a> MaterializedAccountRow<'a> {
    /// Parses one already-bounded row segment, requiring exact declared length.
    pub fn parse(input: &'a [u8]) -> Result<Self, MaterializedAccountRowError> {
        if input.len() < NAME {
            return Err(MaterializedAccountRowError::SegmentTooShort {
                actual: input.len(),
                minimum: NAME,
            });
        }
        let declared = usize::from(u16::from_le_bytes([input[0], input[1]]));
        if declared != input.len() {
            return Err(MaterializedAccountRowError::DeclaredLengthMismatch {
                declared,
                actual: input.len(),
            });
        }
        if input[2] != MATERIALIZED_ACCOUNT_ROW_KIND {
            return Err(MaterializedAccountRowError::UnsupportedKind { kind: input[2] });
        }
        let name_length = usize::from(input[NAME_LEN]);
        let name_end = NAME.checked_add(name_length).ok_or(
            MaterializedAccountRowError::NameOutsideSegment {
                length: name_length,
                segment_len: input.len(),
            },
        )?;
        let name_bytes =
            input
                .get(NAME..name_end)
                .ok_or(MaterializedAccountRowError::NameOutsideSegment {
                    length: name_length,
                    segment_len: input.len(),
                })?;
        if !name_bytes.is_ascii() {
            return Err(MaterializedAccountRowError::NameNotAscii);
        }
        let name = core::str::from_utf8(name_bytes)
            .map_err(|_| MaterializedAccountRowError::NameNotAscii)?;
        let account_type_offset = TYPE_BASE.checked_add(name_length).ok_or(
            MaterializedAccountRowError::TypeOutsideSegment {
                offset: usize::MAX,
                segment_len: input.len(),
            },
        )?;
        let type_code = *input.get(account_type_offset).ok_or(
            MaterializedAccountRowError::TypeOutsideSegment {
                offset: account_type_offset,
                segment_len: input.len(),
            },
        )?;
        let metadata_offset = account_type_offset + POST_TYPE_METADATA_DELTA;
        let metadata_bytes = input.get(metadata_offset..metadata_offset + 4).ok_or(
            MaterializedAccountRowError::TrailingFieldOutsideSegment {
                field: "post-type metadata",
                offset: metadata_offset,
                segment_len: input.len(),
            },
        )?;
        let post_type_metadata_raw =
            u32::from_le_bytes(metadata_bytes.try_into().expect("four bytes"));
        let number_length_offset = account_type_offset + NUMBER_LENGTH_DELTA;
        let (suffix_state, account_number, description) =
            parse_adjacent_ascii_fields(input, number_length_offset);
        Ok(Self {
            raw: input,
            kind: input[2],
            record_number: u32::from_le_bytes(input[0x08..0x0c].try_into().expect("fixed bounds")),
            created: u32::from_le_bytes(input[0x1c..0x20].try_into().expect("fixed bounds")),
            modified: u32::from_le_bytes(input[0x20..0x24].try_into().expect("fixed bounds")),
            name,
            account_type: MaterializedAccountType::parse(type_code),
            account_type_offset,
            post_type_metadata_raw,
            suffix_state,
            account_number,
            description,
        })
    }

    /// Returns the observed row kind byte.
    #[must_use]
    pub const fn kind(&self) -> u8 {
        self.kind
    }
    /// Returns the controlled Account record number.
    #[must_use]
    pub const fn record_number(&self) -> u32 {
        self.record_number
    }
    /// Returns the raw creation value without clock semantics.
    #[must_use]
    pub const fn created_raw(&self) -> u32 {
        self.created
    }
    /// Formats the statically established ordinary Account ListID candidate.
    ///
    /// Enterprise R21's ordinary Account export path formats the account
    /// record number with bit 31 set as uppercase hexadecimal, followed by a
    /// hyphen and this row's creation value in decimal.  This construction is
    /// stable across an Account rename.  It is an *identity formatter*, not a
    /// current-row selector: callers must still establish table traversal and
    /// lifecycle state before reporting the row as an Account.
    #[must_use]
    pub fn ordinary_list_id(&self) -> String {
        format_ordinary_account_list_id(self.record_number, self.created)
    }
    /// Returns the raw modification value without version semantics.
    #[must_use]
    pub const fn modified_raw(&self) -> u32 {
        self.modified
    }
    /// Returns the validated ASCII display name.
    #[must_use]
    pub const fn name(&self) -> &'a str {
        self.name
    }
    /// Returns the calibrated type or an uncalibrated discriminator wrapper.
    #[must_use]
    pub const fn account_type(&self) -> MaterializedAccountType {
        self.account_type
    }
    /// Returns the name-relative byte offset of the type discriminator.
    #[must_use]
    pub const fn account_type_offset(&self) -> usize {
        self.account_type_offset
    }
    /// Returns the four bytes after the type as uninterpreted metadata.
    ///
    /// This field has two observed forms in the private census (all zero and
    /// a value with only its most-significant byte set), so it must not be
    /// interpreted as a parent, active, hidden, or deleted flag.
    #[must_use]
    pub const fn post_type_metadata_raw(&self) -> u32 {
        self.post_type_metadata_raw
    }
    /// Returns the optional suffix parsing state.
    #[must_use]
    pub const fn suffix_state(&self) -> MaterializedAccountSuffixState {
        self.suffix_state
    }
    /// Returns the bounded, length-prefixed account number when non-empty.
    ///
    /// `None` means absent only when [`Self::suffix_state`] is `Parsed` or
    /// `Omitted`; it means unavailable when the state is `OpaqueOrMalformed`.
    #[must_use]
    pub const fn account_number(&self) -> Option<&'a str> {
        self.account_number
    }
    /// Returns the bounded, adjacent length-prefixed description when non-empty.
    ///
    /// See [`Self::account_number`] for the meaning of `None`.
    #[must_use]
    pub const fn description(&self) -> Option<&'a str> {
        self.description
    }
    /// Returns the opaque bytes between the name and type discriminator.
    #[must_use]
    pub fn opaque_between_name_and_type(&self) -> &'a [u8] {
        &self.raw[NAME + self.name.len()..self.account_type_offset]
    }
    /// Returns all unparsed bytes after the type discriminator.
    #[must_use]
    pub fn opaque_trailing(&self) -> &'a [u8] {
        &self.raw[self.account_type_offset + 1..]
    }
    /// Returns the entire validated row segment for opaque-field consumers.
    #[must_use]
    pub const fn raw_segment(&self) -> &'a [u8] {
        self.raw
    }
}

/// Formats the statically established ordinary Account ListID candidate.
///
/// This helper is intentionally separate from lifecycle selection.  A valid
/// string does not prove that its physical row is current, visible, or an
/// exportable user Account.
#[must_use]
pub fn format_ordinary_account_list_id(record_number: u32, created_raw: u32) -> String {
    format!("{:X}-{created_raw}", record_number | 0x8000_0000)
}

fn parse_adjacent_ascii_fields(
    input: &[u8],
    first_length_offset: usize,
) -> (MaterializedAccountSuffixState, Option<&str>, Option<&str>) {
    // The fixed account envelope ends immediately before this optional
    // suffix. The controlled numeric/description framing is exposed only
    // when both a declared byte range and ASCII contents are present. Other
    // suffix dialects remain opaque rather than causing the Account envelope
    // itself to be rejected.
    let Some(&first_len) = input.get(first_length_offset) else {
        return (MaterializedAccountSuffixState::Omitted, None, None);
    };
    let first_len = usize::from(first_len);
    let first_start = first_length_offset + 1;
    let Some(first_end) = first_start.checked_add(first_len) else {
        return (
            MaterializedAccountSuffixState::OpaqueOrMalformed,
            None,
            None,
        );
    };
    let Some(first) = optional_ascii_field(input, first_start, first_end) else {
        return (
            MaterializedAccountSuffixState::OpaqueOrMalformed,
            None,
            None,
        );
    };
    let Some(&second_len) = input.get(first_end) else {
        return (MaterializedAccountSuffixState::Parsed, first, None);
    };
    let second_len = usize::from(second_len);
    let second_start = first_end + 1;
    let Some(second_end) = second_start.checked_add(second_len) else {
        return (
            MaterializedAccountSuffixState::OpaqueOrMalformed,
            None,
            None,
        );
    };
    let Some(second) = optional_ascii_field(input, second_start, second_end) else {
        return (
            MaterializedAccountSuffixState::OpaqueOrMalformed,
            None,
            None,
        );
    };
    (MaterializedAccountSuffixState::Parsed, first, second)
}

fn optional_ascii_field(input: &[u8], start: usize, end: usize) -> Option<Option<&str>> {
    let bytes = input.get(start..end)?;
    if bytes.is_empty() {
        return Some(None);
    }
    bytes
        .is_ascii()
        .then(|| core::str::from_utf8(bytes).ok())
        .flatten()
        .map(Some)
}

/// Errors returned by [`MaterializedAccountRow::parse`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MaterializedAccountRowError {
    /// The segment cannot contain the fixed prefix.
    #[error("materialized Account row is too short: {actual} bytes (need at least {minimum})")]
    SegmentTooShort {
        /// Supplied slice length.
        actual: usize,
        /// Minimum required length.
        minimum: usize,
    },
    /// The declared length did not exactly bound the input.
    #[error("materialized Account row length mismatch: declared {declared}, actual {actual}")]
    DeclaredLengthMismatch {
        /// Header length.
        declared: usize,
        /// Slice length.
        actual: usize,
    },
    /// The row kind was not the controlled Account kind.
    #[error("unsupported materialized Account row kind {kind:#04x}")]
    UnsupportedKind {
        /// Observed kind byte.
        kind: u8,
    },
    /// The name length exceeded the segment.
    #[error("materialized Account name of {length} bytes is outside a {segment_len}-byte segment")]
    NameOutsideSegment {
        /// Declared name length.
        length: usize,
        /// Segment length.
        segment_len: usize,
    },
    /// The name bytes were not ASCII.
    #[error("materialized Account name is not ASCII")]
    NameNotAscii,
    /// The relative type-byte offset exceeded the segment.
    #[error(
        "materialized Account type byte at {offset:#x} is outside a {segment_len}-byte segment"
    )]
    TypeOutsideSegment {
        /// Computed offset.
        offset: usize,
        /// Segment length.
        segment_len: usize,
    },
    /// A bounded number or description field did not fit in the segment.
    #[error("materialized Account {field} at {offset:#x} is outside a {segment_len}-byte segment")]
    TrailingFieldOutsideSegment {
        /// Structural field label.
        field: &'static str,
        /// Computed field offset.
        offset: usize,
        /// Segment length.
        segment_len: usize,
    },
    /// A bounded number or description field was not ASCII.
    #[error("materialized Account {field} is not ASCII")]
    TrailingFieldNotAscii {
        /// Structural field label.
        field: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(name: &str, recnum: u32, created: u32, modified: u32, code: u8) -> Vec<u8> {
        let mut row = vec![0_u8; 0x80];
        let length = row.len() as u16;
        row[..2].copy_from_slice(&length.to_le_bytes());
        row[2] = MATERIALIZED_ACCOUNT_ROW_KIND;
        row[8..12].copy_from_slice(&recnum.to_le_bytes());
        row[0x1c..0x20].copy_from_slice(&created.to_le_bytes());
        row[0x20..0x24].copy_from_slice(&modified.to_le_bytes());
        row[NAME_LEN] = name.len() as u8;
        row[NAME..NAME + name.len()].copy_from_slice(name.as_bytes());
        row[TYPE_BASE + name.len()] = code;
        row
    }
    #[test]
    fn parses_six_calibrated_types_at_name_relative_offsets() {
        for (name, recnum, code, ty) in [
            ("SAMPLE_Bank", 488, 0, MaterializedAccountType::Bank),
            (
                "SAMPLE_Asset",
                489,
                2,
                MaterializedAccountType::OtherCurrentAsset,
            ),
            (
                "SAMPLE_CreditCard",
                490,
                6,
                MaterializedAccountType::CreditCard,
            ),
            (
                "SAMPLE_Liability",
                491,
                7,
                MaterializedAccountType::OtherCurrentLiability,
            ),
            ("SAMPLE_Expense", 492, 12, MaterializedAccountType::Expense),
            (
                "SAMPLE_Income",
                493,
                13,
                MaterializedAccountType::OtherIncome,
            ),
        ] {
            let bytes = row(name, recnum, 10, 11, code);
            let parsed = MaterializedAccountRow::parse(&bytes).unwrap();
            assert_eq!(parsed.account_type(), ty);
            assert_eq!(parsed.account_type_offset(), TYPE_BASE + name.len());
        }
    }
    #[test]
    fn rename_fixture_changes_only_name_and_modified_value() {
        let before_bytes = row("SAMPLE_Asset_A", 489, 1_787_809_460, 1_787_809_460, 2);
        let after_bytes = row("SAMPLE_Asset_B", 489, 1_787_809_460, 1_787_812_302, 2);
        let before = MaterializedAccountRow::parse(&before_bytes).unwrap();
        let after = MaterializedAccountRow::parse(&after_bytes).unwrap();
        assert_eq!(before.record_number(), after.record_number());
        assert_eq!(before.created_raw(), after.created_raw());
        assert_eq!(before.account_type(), after.account_type());
        assert_ne!(before.name(), after.name());
        assert_ne!(before.modified_raw(), after.modified_raw());
        assert_eq!(before.ordinary_list_id(), after.ordinary_list_id());
    }
    #[test]
    fn formats_the_ordinary_uppercase_hex_and_decimal_account_id() {
        assert_eq!(format_ordinary_account_list_id(0x12ab, 42), "800012AB-42");
        assert_eq!(
            format_ordinary_account_list_id(0x8000_0001, 7),
            "80000001-7"
        );
    }
    #[test]
    fn parses_bounded_number_and_description_after_each_calibrated_type() {
        for (name, code, number, description) in [
            ("SAMPLE_Bank", 0, "1000", "sample bank"),
            ("SAMPLE_Asset", 2, "1010", "sample asset"),
            ("SAMPLE_CreditCard", 6, "2010", "sample credit card"),
            ("SAMPLE_Liability", 7, "2000", "sample liability"),
            ("SAMPLE_Expense", 12, "5000", "sample expense"),
            ("SAMPLE_Income", 13, "4000", "sample income"),
        ] {
            let mut bytes = row(name, 488, 10, 11, code);
            let number_length = TYPE_BASE + name.len() + NUMBER_LENGTH_DELTA;
            bytes[number_length] = number.len() as u8;
            bytes[number_length + 1..number_length + 1 + number.len()]
                .copy_from_slice(number.as_bytes());
            let description_length = number_length + 1 + number.len();
            bytes[description_length] = description.len() as u8;
            bytes[description_length + 1..description_length + 1 + description.len()]
                .copy_from_slice(description.as_bytes());
            let parsed = MaterializedAccountRow::parse(&bytes).unwrap();
            assert_eq!(parsed.post_type_metadata_raw(), 0);
            assert_eq!(
                parsed.suffix_state(),
                MaterializedAccountSuffixState::Parsed
            );
            assert_eq!(parsed.account_number(), Some(number));
            assert_eq!(parsed.description(), Some(description));
        }
    }
    #[test]
    fn accepts_an_omitted_optional_number_description_suffix() {
        let name = "SAMPLE_NoSuffix";
        let mut bytes = row(name, 488, 10, 10, 0);
        let suffix_start = TYPE_BASE + name.len() + NUMBER_LENGTH_DELTA;
        bytes.truncate(suffix_start);
        let length = bytes.len() as u16;
        bytes[..2].copy_from_slice(&length.to_le_bytes());
        let parsed = MaterializedAccountRow::parse(&bytes).unwrap();
        assert_eq!(
            parsed.suffix_state(),
            MaterializedAccountSuffixState::Omitted
        );
        assert_eq!(parsed.account_number(), None);
        assert_eq!(parsed.description(), None);

        let mut only_number_length = row(name, 488, 10, 10, 0);
        only_number_length[suffix_start] = 0;
        only_number_length.truncate(suffix_start + 1);
        let length = only_number_length.len() as u16;
        only_number_length[..2].copy_from_slice(&length.to_le_bytes());
        let parsed = MaterializedAccountRow::parse(&only_number_length).unwrap();
        assert_eq!(
            parsed.suffix_state(),
            MaterializedAccountSuffixState::Parsed
        );
        assert_eq!(parsed.account_number(), None);
        assert_eq!(parsed.description(), None);
    }
    #[test]
    fn rejects_bounds_and_preserves_uncalibrated_types() {
        assert!(matches!(
            MaterializedAccountRow::parse(&[0; 10]),
            Err(MaterializedAccountRowError::SegmentTooShort { .. })
        ));
        let mut bad = row("SAMPLE_Invalid", 488, 10, 10, 0);
        bad[0] = 0;
        assert!(matches!(
            MaterializedAccountRow::parse(&bad),
            Err(MaterializedAccountRowError::DeclaredLengthMismatch { .. })
        ));
        let unknown = row("SAMPLE_Uncalibrated", 488, 10, 10, 1);
        let parsed = MaterializedAccountRow::parse(&unknown).unwrap();
        assert_eq!(
            parsed.account_type(),
            MaterializedAccountType::Uncalibrated(1)
        );
    }
    #[test]
    fn preserves_an_opaque_optional_suffix_without_calling_it_absent() {
        let name = "SAMPLE_OpaqueSuffix";
        let mut bytes = row(name, 488, 10, 10, 0);
        let suffix_start = TYPE_BASE + name.len() + NUMBER_LENGTH_DELTA;
        bytes[suffix_start] = 20;
        bytes.truncate(suffix_start + 1);
        let length = bytes.len() as u16;
        bytes[..2].copy_from_slice(&length.to_le_bytes());
        let parsed = MaterializedAccountRow::parse(&bytes).unwrap();
        assert_eq!(
            parsed.suffix_state(),
            MaterializedAccountSuffixState::OpaqueOrMalformed
        );
        assert_eq!(parsed.account_number(), None);
        assert_eq!(parsed.description(), None);
    }
}

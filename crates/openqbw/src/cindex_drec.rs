//! Strict parser for the small `qbci32` sparse `drec` field grammar.
//!
//! This module deliberately parses a *record body only*.  It does not scan a
//! QBW, infer a descriptor table, decide which physical bytes are current, or
//! attach accounting meaning to a decoded field.  A caller must provide the
//! exact, revision-specific descriptor table.  The format represented here is
//! the narrow grammar established for the `qbci32` CIndex side path:
//!
//! ```text
//! flag:u8 (ordinal:u16 payload)* 0xffff:u16
//! ```
//!
//! Each ordinal selects a descriptor by zero-based index.  Omitted ordinals
//! are intentionally absent from [`DrecRecord::fields`]; defaults are applied
//! only when the caller supplied one in [`DrecDescriptor`].

use std::{collections::BTreeMap, ops::Range};

use crate::QuickBooksLegacyBalance;

/// Maximum complete `drec` byte length accepted by the proven builder path.
pub const DREC_MAX_LEN: usize = 0x7530;

/// Byte order used by a `drec` file for ordinals and fixed-width integers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DrecByteOrder {
    /// Least-significant byte first.
    Little,
    /// Most-significant byte first.
    Big,
}

impl DrecByteOrder {
    fn read_u16(self, bytes: [u8; 2]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        }
    }

    fn read_u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }

    fn write_u16(self, value: u16) -> [u8; 2] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }

    fn write_u32(self, value: u32) -> [u8; 4] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }
}

/// The established descriptor classes in the `qbci32` `drec` grammar.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DrecClass {
    /// Descriptor-array terminator (`E`).  It cannot describe a field.
    End,
    /// Bounded NUL-terminated byte string (`S`).
    String,
    /// Fixed-width opaque bytes (`B`).
    Bytes,
    /// Four-byte unsigned scalar (`F`).
    F,
    /// Four-byte unsigned scalar (`I`).
    I,
    /// Four-byte unsigned scalar (`L`).
    L,
    /// Two-byte unsigned scalar (`H`).
    H,
    /// Two-byte unsigned scalar (`U`).
    U,
    /// Six-byte [`QuickBooksLegacyBalance`] (`M`).
    LegacyBalance,
    /// Nine fixed opaque bytes (`Z`).
    Z,
    /// Pointer-sized value (`D`).
    ///
    /// Its width is not a portable on-disk property in the proven grammar, so
    /// this safe standalone implementation rejects it rather than consulting
    /// the host process pointer width.
    PointerSizedD,
}

impl DrecClass {
    /// Decodes a descriptor class byte.
    pub fn from_tag(tag: u8) -> Result<Self, DrecError> {
        match tag {
            b'E' => Ok(Self::End),
            b'S' => Ok(Self::String),
            b'B' => Ok(Self::Bytes),
            b'F' => Ok(Self::F),
            b'I' => Ok(Self::I),
            b'L' => Ok(Self::L),
            b'H' => Ok(Self::H),
            b'U' => Ok(Self::U),
            b'M' => Ok(Self::LegacyBalance),
            b'Z' => Ok(Self::Z),
            b'D' => Ok(Self::PointerSizedD),
            _ => Err(DrecError::UnknownClass { tag }),
        }
    }

    /// Returns the exact ASCII descriptor-class tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::End => b'E',
            Self::String => b'S',
            Self::Bytes => b'B',
            Self::F => b'F',
            Self::I => b'I',
            Self::L => b'L',
            Self::H => b'H',
            Self::U => b'U',
            Self::LegacyBalance => b'M',
            Self::Z => b'Z',
            Self::PointerSizedD => b'D',
        }
    }
}

/// One caller-supplied descriptor, addressed by its zero-based array index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrecDescriptor {
    /// The exact descriptor class.
    pub class: DrecClass,
    /// The proven fixed width or, for `S`, maximum bytes including its NUL.
    pub length: usize,
    /// Optional explicit caller-defined default for an omitted field.
    pub default: Option<DrecValue>,
}

impl DrecDescriptor {
    /// Creates a field descriptor with no implicit default.
    #[must_use]
    pub const fn new(class: DrecClass, length: usize) -> Self {
        Self {
            class,
            length,
            default: None,
        }
    }

    /// Adds an explicit caller-defined default for an omitted field.
    #[must_use]
    pub fn with_default(mut self, default: DrecValue) -> Self {
        self.default = Some(default);
        self
    }

    /// Creates the required terminal `E` descriptor.
    #[must_use]
    pub const fn end() -> Self {
        Self::new(DrecClass::End, 0)
    }
}

/// Revision-specific `drec` descriptors, including their final `E` marker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrecSchema {
    fields: Vec<DrecDescriptor>,
}

impl DrecSchema {
    /// Validates a descriptor array that is terminated by exactly one final
    /// `E` descriptor.
    pub fn new(mut descriptors: Vec<DrecDescriptor>) -> Result<Self, DrecError> {
        let Some(last) = descriptors.pop() else {
            return Err(DrecError::MissingDescriptorTerminator);
        };
        if last.class != DrecClass::End {
            return Err(DrecError::MissingDescriptorTerminator);
        }
        if last.length != 0 || last.default.is_some() {
            return Err(DrecError::InvalidEndDescriptor);
        }
        if descriptors.len() > usize::from(u16::MAX) {
            return Err(DrecError::SchemaTooLarge {
                field_count: descriptors.len(),
            });
        }
        for (ordinal, descriptor) in descriptors.iter().enumerate() {
            validate_descriptor(ordinal, descriptor)?;
        }
        Ok(Self {
            fields: descriptors,
        })
    }

    /// Returns the field descriptor selected by an ordinal.
    #[must_use]
    pub fn field(&self, ordinal: u16) -> Option<&DrecDescriptor> {
        self.fields.get(usize::from(ordinal))
    }

    /// Returns the number of addressable field descriptors.
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }
}

/// A parsed field value. Strings remain raw bytes to avoid inventing a text
/// encoding for a QuickBooks file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DrecValue {
    /// Bytes before the required terminating NUL in an `S` field.
    String(Vec<u8>),
    /// Exact opaque bytes from a `B` field.
    Bytes(Vec<u8>),
    /// A four-byte value from `F`, `I`, or `L`.
    U32(u32),
    /// A two-byte value from `H` or `U`.
    U16(u16),
    /// A validated six-byte QuickBooks legacy balance.
    LegacyBalance(QuickBooksLegacyBalance),
    /// Exact opaque bytes from a `Z` field.
    Z([u8; 9]),
}

/// A decoded sparse field and its exact record-relative provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrecField {
    /// The zero-based descriptor ordinal.
    pub ordinal: u16,
    /// Decoded value, without default materialization.
    pub value: DrecValue,
    /// Complete field range, including the two-byte ordinal.
    pub byte_range: Range<usize>,
    /// Value-only range, excluding the ordinal.
    pub payload_range: Range<usize>,
}

/// A parsed `drec` body with its initial flag byte and sparse fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrecRecord {
    /// Exact unclassified record flag byte.
    pub flag: u8,
    /// Fields physically present in the record, ordered by ordinal.
    pub fields: BTreeMap<u16, DrecField>,
}

impl DrecRecord {
    /// Constructs a sparse record and rejects duplicate ordinals.
    pub fn new(
        flag: u8,
        fields: impl IntoIterator<Item = (u16, DrecValue)>,
    ) -> Result<Self, DrecError> {
        let mut parsed = BTreeMap::new();
        for (ordinal, value) in fields {
            if parsed.contains_key(&ordinal) {
                return Err(DrecError::DuplicateOrdinal { ordinal });
            }
            parsed.insert(
                ordinal,
                DrecField {
                    ordinal,
                    value,
                    byte_range: 0..0,
                    payload_range: 0..0,
                },
            );
        }
        Ok(Self {
            flag,
            fields: parsed,
        })
    }

    /// Returns a copy with caller-supplied schema defaults materialized for
    /// omitted fields.  No descriptor without an explicit default is added.
    #[must_use]
    pub fn materialize_schema_defaults(&self, schema: &DrecSchema) -> Self {
        let mut record = self.clone();
        for (index, descriptor) in schema.fields.iter().enumerate() {
            let ordinal = index as u16;
            if let std::collections::btree_map::Entry::Vacant(entry) = record.fields.entry(ordinal)
                && let Some(value) = &descriptor.default
            {
                entry.insert(DrecField {
                    ordinal,
                    value: value.clone(),
                    byte_range: 0..0,
                    payload_range: 0..0,
                });
            }
        }
        record
    }
}

/// Decodes one complete `drec` body using caller-provided descriptors.
pub fn parse_drec(
    bytes: &[u8],
    schema: &DrecSchema,
    byte_order: DrecByteOrder,
) -> Result<DrecRecord, DrecError> {
    if bytes.len() > DREC_MAX_LEN {
        return Err(DrecError::RecordTooLarge {
            length: bytes.len(),
            maximum: DREC_MAX_LEN,
        });
    }
    let Some(&flag) = bytes.first() else {
        return Err(DrecError::Truncated {
            offset: 0,
            needed: 1,
            available: 0,
        });
    };
    let mut cursor = 1;
    let mut fields = BTreeMap::new();
    let mut previous_ordinal = None;
    loop {
        let ordinal_offset = cursor;
        let ordinal_bytes = take::<2>(bytes, &mut cursor)?;
        let ordinal = byte_order.read_u16(ordinal_bytes);
        if ordinal == u16::MAX {
            if cursor != bytes.len() {
                return Err(DrecError::TrailingBytes {
                    offset: cursor,
                    count: bytes.len() - cursor,
                });
            }
            return Ok(DrecRecord { flag, fields });
        }
        if let Some(previous) = previous_ordinal
            && ordinal <= previous
        {
            return Err(DrecError::NonIncreasingOrdinal { previous, ordinal });
        }
        let descriptor = schema.field(ordinal).ok_or(DrecError::OrdinalOutOfRange {
            ordinal,
            field_count: schema.field_count(),
        })?;
        if fields.contains_key(&ordinal) {
            return Err(DrecError::DuplicateOrdinal { ordinal });
        }
        let payload_start = cursor;
        let value = parse_value(bytes, &mut cursor, descriptor, byte_order)?;
        fields.insert(
            ordinal,
            DrecField {
                ordinal,
                value,
                byte_range: ordinal_offset..cursor,
                payload_range: payload_start..cursor,
            },
        );
        previous_ordinal = Some(ordinal);
    }
}

/// Encodes one sparse `drec` body.  Fields are written in increasing ordinal
/// order, making output deterministic.  It does not add schema defaults.
pub fn encode_drec(
    record: &DrecRecord,
    schema: &DrecSchema,
    byte_order: DrecByteOrder,
) -> Result<Vec<u8>, DrecError> {
    let mut encoded_len = 3usize; // flag plus terminal ordinal
    for (&ordinal, field) in &record.fields {
        let descriptor = schema.field(ordinal).ok_or(DrecError::OrdinalOutOfRange {
            ordinal,
            field_count: schema.field_count(),
        })?;
        ensure_value_matches(descriptor, &field.value)?;
        encoded_len = encoded_len
            .checked_add(2)
            .and_then(|length| length.checked_add(value_encoded_len(&field.value)))
            .ok_or(DrecError::LengthOverflow)?;
        if encoded_len > DREC_MAX_LEN {
            return Err(DrecError::RecordTooLarge {
                length: encoded_len,
                maximum: DREC_MAX_LEN,
            });
        }
    }

    let mut output = Vec::with_capacity(encoded_len);
    output.push(record.flag);
    for (&ordinal, field) in &record.fields {
        if field.ordinal != ordinal {
            return Err(DrecError::FieldOrdinalMismatch {
                key: ordinal,
                field_ordinal: field.ordinal,
            });
        }
        let descriptor = schema.field(ordinal).ok_or(DrecError::OrdinalOutOfRange {
            ordinal,
            field_count: schema.field_count(),
        })?;
        output.extend_from_slice(&byte_order.write_u16(ordinal));
        encode_value(&mut output, descriptor, &field.value, byte_order)?;
    }
    output.extend_from_slice(&byte_order.write_u16(u16::MAX));
    Ok(output)
}

fn value_encoded_len(value: &DrecValue) -> usize {
    match value {
        DrecValue::String(value) => value.len() + 1,
        DrecValue::Bytes(value) => value.len(),
        DrecValue::U32(_) => 4,
        DrecValue::U16(_) => 2,
        DrecValue::LegacyBalance(_) => 6,
        DrecValue::Z(_) => 9,
    }
}

fn validate_descriptor(ordinal: usize, descriptor: &DrecDescriptor) -> Result<(), DrecError> {
    if descriptor.class == DrecClass::End {
        return Err(DrecError::EarlyDescriptorTerminator { ordinal });
    }
    if descriptor.class == DrecClass::PointerSizedD {
        return Err(DrecError::PointerSizedFieldUnsupported { ordinal });
    }
    let valid_length = match descriptor.class {
        DrecClass::String => descriptor.length > 0,
        DrecClass::Bytes => true,
        DrecClass::F | DrecClass::I | DrecClass::L => descriptor.length == 4,
        DrecClass::H | DrecClass::U => descriptor.length == 2,
        DrecClass::LegacyBalance => descriptor.length == 6,
        DrecClass::Z => descriptor.length == 9,
        DrecClass::End | DrecClass::PointerSizedD => false,
    };
    if !valid_length {
        return Err(DrecError::InvalidDescriptorLength {
            ordinal,
            class: descriptor.class,
            length: descriptor.length,
        });
    }
    if let Some(value) = &descriptor.default {
        ensure_value_matches(descriptor, value)?;
    }
    Ok(())
}

fn parse_value(
    bytes: &[u8],
    cursor: &mut usize,
    descriptor: &DrecDescriptor,
    byte_order: DrecByteOrder,
) -> Result<DrecValue, DrecError> {
    match descriptor.class {
        DrecClass::String => {
            let start = *cursor;
            let bound_end = start
                .checked_add(descriptor.length)
                .ok_or(DrecError::LengthOverflow)?;
            let bounded = bytes
                .get(start..bound_end.min(bytes.len()))
                .ok_or_else(|| truncated(bytes, start, 1))?;
            let Some(nul) = bounded.iter().position(|&byte| byte == 0) else {
                if bound_end > bytes.len() {
                    return Err(truncated(bytes, start, descriptor.length));
                }
                return Err(DrecError::UnterminatedString {
                    offset: start,
                    bound: descriptor.length,
                });
            };
            *cursor = start + nul + 1;
            Ok(DrecValue::String(bounded[..nul].to_vec()))
        }
        DrecClass::Bytes => Ok(DrecValue::Bytes(
            take_slice(bytes, cursor, descriptor.length)?.to_vec(),
        )),
        DrecClass::F | DrecClass::I | DrecClass::L => Ok(DrecValue::U32(
            byte_order.read_u32(take::<4>(bytes, cursor)?),
        )),
        DrecClass::H | DrecClass::U => Ok(DrecValue::U16(
            byte_order.read_u16(take::<2>(bytes, cursor)?),
        )),
        DrecClass::LegacyBalance => Ok(DrecValue::LegacyBalance(
            QuickBooksLegacyBalance::from_disk_bytes(take::<6>(bytes, cursor)?)
                .map_err(DrecError::LegacyBalance)?,
        )),
        DrecClass::Z => Ok(DrecValue::Z(take::<9>(bytes, cursor)?)),
        DrecClass::End => Err(DrecError::UnexpectedEndDescriptor),
        DrecClass::PointerSizedD => Err(DrecError::PointerSizedFieldUnsupported {
            ordinal: usize::MAX,
        }),
    }
}

fn encode_value(
    output: &mut Vec<u8>,
    descriptor: &DrecDescriptor,
    value: &DrecValue,
    byte_order: DrecByteOrder,
) -> Result<(), DrecError> {
    ensure_value_matches(descriptor, value)?;
    match value {
        DrecValue::String(value) => {
            output.extend_from_slice(value);
            output.push(0);
        }
        DrecValue::Bytes(value) => output.extend_from_slice(value),
        DrecValue::U32(value) => output.extend_from_slice(&byte_order.write_u32(*value)),
        DrecValue::U16(value) => output.extend_from_slice(&byte_order.write_u16(*value)),
        DrecValue::LegacyBalance(value) => output.extend_from_slice(&value.to_disk_bytes()),
        DrecValue::Z(value) => output.extend_from_slice(value),
    }
    Ok(())
}

fn ensure_value_matches(descriptor: &DrecDescriptor, value: &DrecValue) -> Result<(), DrecError> {
    let valid = match (descriptor.class, value) {
        (DrecClass::String, DrecValue::String(value)) => {
            value.len().saturating_add(1) <= descriptor.length && !value.contains(&0)
        }
        (DrecClass::Bytes, DrecValue::Bytes(value)) => value.len() == descriptor.length,
        (DrecClass::F | DrecClass::I | DrecClass::L, DrecValue::U32(_)) => true,
        (DrecClass::H | DrecClass::U, DrecValue::U16(_)) => true,
        (DrecClass::LegacyBalance, DrecValue::LegacyBalance(_)) => true,
        (DrecClass::Z, DrecValue::Z(_)) => true,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(DrecError::ValueDoesNotMatchDescriptor {
            class: descriptor.class,
            length: descriptor.length,
        })
    }
}

fn take<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], DrecError> {
    let slice = take_slice(bytes, cursor, N)?;
    let mut output = [0; N];
    output.copy_from_slice(slice);
    Ok(output)
}

fn take_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    count: usize,
) -> Result<&'a [u8], DrecError> {
    let start = *cursor;
    let end = start.checked_add(count).ok_or(DrecError::LengthOverflow)?;
    let slice = bytes
        .get(start..end)
        .ok_or_else(|| truncated(bytes, start, count))?;
    *cursor = end;
    Ok(slice)
}

fn truncated(bytes: &[u8], offset: usize, needed: usize) -> DrecError {
    DrecError::Truncated {
        offset,
        needed,
        available: bytes.len().saturating_sub(offset),
    }
}

/// Errors from strict sparse `drec` decoding and encoding.
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum DrecError {
    /// A class byte was not one of the proven grammar classes.
    #[error("unknown drec descriptor class {tag:#04x}")]
    UnknownClass { tag: u8 },
    /// The descriptor array did not finish with a terminal `E` descriptor.
    #[error("drec descriptor array has no final E terminator")]
    MissingDescriptorTerminator,
    /// An `E` descriptor appeared before the final array position.
    #[error("drec descriptor {ordinal} is an early E terminator")]
    EarlyDescriptorTerminator { ordinal: usize },
    /// The terminal descriptor contained fields it must not contain.
    #[error("drec terminal E descriptor must have length zero and no default")]
    InvalidEndDescriptor,
    /// A descriptor had a class-incompatible length.
    #[error("drec descriptor {ordinal} class {class:?} has invalid length {length}")]
    InvalidDescriptorLength {
        ordinal: usize,
        class: DrecClass,
        length: usize,
    },
    /// A `D` value has no portable established on-disk width.
    #[error("drec descriptor {ordinal} uses unsupported pointer-sized D field")]
    PointerSizedFieldUnsupported { ordinal: usize },
    /// Input ended before the requested bytes were available.
    #[error("truncated drec at {offset}: need {needed} bytes, only {available} remain")]
    Truncated {
        offset: usize,
        needed: usize,
        available: usize,
    },
    /// A complete record exceeds the proven builder buffer bound.
    #[error("drec length {length} exceeds maximum {maximum}")]
    RecordTooLarge { length: usize, maximum: usize },
    /// A sparse ordinal was not represented by the caller schema.
    #[error("drec ordinal {ordinal} is outside schema with {field_count} fields")]
    OrdinalOutOfRange { ordinal: u16, field_count: usize },
    /// The caller supplied more descriptors than the u16 ordinal space can address.
    #[error("drec schema has {field_count} fields but at most 65535 are addressable")]
    SchemaTooLarge { field_count: usize },
    /// The same ordinal appeared more than once.
    #[error("duplicate drec ordinal {ordinal}")]
    DuplicateOrdinal { ordinal: u16 },
    /// Sparse field ordinals must occur in strictly increasing order.
    #[error("drec ordinal {ordinal} is not strictly after {previous}")]
    NonIncreasingOrdinal { previous: u16, ordinal: u16 },
    /// A caller-constructed field did not agree with its map key.
    #[error("drec field key {key} does not match field ordinal {field_ordinal}")]
    FieldOrdinalMismatch { key: u16, field_ordinal: u16 },
    /// An `S` payload did not contain a NUL within its descriptor bound.
    #[error("unterminated drec string at {offset} within {bound}-byte bound")]
    UnterminatedString { offset: usize, bound: usize },
    /// Bytes followed a valid record terminator.
    #[error("{count} trailing bytes after drec terminator at {offset}")]
    TrailingBytes { offset: usize, count: usize },
    /// A field value was incompatible with its descriptor.
    #[error("drec value does not match descriptor class {class:?} length {length}")]
    ValueDoesNotMatchDescriptor { class: DrecClass, length: usize },
    /// The descriptor array's end marker was used as a field descriptor.
    #[error("drec E descriptor cannot decode a field")]
    UnexpectedEndDescriptor,
    /// An internal size calculation overflowed `usize`.
    #[error("drec length calculation overflow")]
    LengthOverflow,
    /// The established six-byte balance envelope was invalid.
    #[error(transparent)]
    LegacyBalance(#[from] crate::QuickBooksLegacyBalanceError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> DrecSchema {
        DrecSchema::new(vec![
            DrecDescriptor::new(DrecClass::String, 8),
            DrecDescriptor::new(DrecClass::F, 4),
            DrecDescriptor::new(DrecClass::Bytes, 3),
            DrecDescriptor::new(DrecClass::LegacyBalance, 6),
            DrecDescriptor::new(DrecClass::Z, 9),
            DrecDescriptor::end(),
        ])
        .unwrap()
    }

    #[test]
    fn synthetic_little_endian_round_trip_preserves_ranges_and_balance() {
        let input = [
            0xa5, 0x00, 0x00, b'h', b'i', 0, 0x01, 0x00, 0x78, 0x56, 0x34, 0x12, 0x03, 0x00, 0x39,
            0, 0, 0, 0x04, 0xd2, 0x04, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xff, 0xff,
        ];
        let record = parse_drec(&input, &schema(), DrecByteOrder::Little).unwrap();
        assert_eq!(record.flag, 0xa5);
        assert_eq!(record.fields[&0].value, DrecValue::String(b"hi".to_vec()));
        assert_eq!(record.fields[&0].byte_range, 1..6);
        assert_eq!(record.fields[&1].value, DrecValue::U32(0x1234_5678));
        assert_eq!(record.fields[&3].payload_range, 14..20);
        assert_eq!(
            encode_drec(&record, &schema(), DrecByteOrder::Little).unwrap(),
            input
        );
    }

    #[test]
    fn synthetic_big_endian_round_trip_is_deterministic() {
        let record = DrecRecord::new(
            7,
            [
                (1, DrecValue::U32(0x0102_0304)),
                (0, DrecValue::String(b"x".to_vec())),
            ],
        )
        .unwrap();
        let bytes = encode_drec(&record, &schema(), DrecByteOrder::Big).unwrap();
        assert_eq!(bytes, [7, 0, 0, b'x', 0, 0, 1, 1, 2, 3, 4, 0xff, 0xff]);
        assert_eq!(
            parse_drec(&bytes, &schema(), DrecByteOrder::Big)
                .unwrap()
                .flag,
            7
        );
    }

    #[test]
    fn malformed_records_fail_closed() {
        let schema = schema();
        assert!(matches!(
            parse_drec(&[0], &schema, DrecByteOrder::Little),
            Err(DrecError::Truncated { .. })
        ));
        assert!(matches!(
            parse_drec(&[0, 5, 0, 0xff, 0xff], &schema, DrecByteOrder::Little),
            Err(DrecError::OrdinalOutOfRange { .. })
        ));
        assert!(matches!(
            parse_drec(
                &[
                    0, 0, 0, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', 0xff, 0xff
                ],
                &schema,
                DrecByteOrder::Little
            ),
            Err(DrecError::UnterminatedString { .. })
        ));
        assert!(matches!(
            parse_drec(&[0, 0xff, 0xff, 0], &schema, DrecByteOrder::Little),
            Err(DrecError::TrailingBytes { .. })
        ));
        assert!(matches!(
            parse_drec(
                &[0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0xff, 0xff],
                &schema,
                DrecByteOrder::Little
            ),
            Err(DrecError::NonIncreasingOrdinal { .. })
        ));
    }

    #[test]
    fn defaults_are_never_guessed() {
        let schema = DrecSchema::new(vec![
            DrecDescriptor::new(DrecClass::U, 2).with_default(DrecValue::U16(9)),
            DrecDescriptor::new(DrecClass::F, 4),
            DrecDescriptor::end(),
        ])
        .unwrap();
        let parsed = parse_drec(&[1, 0xff, 0xff], &schema, DrecByteOrder::Little).unwrap();
        assert!(parsed.fields.is_empty());
        let materialized = parsed.materialize_schema_defaults(&schema);
        assert_eq!(materialized.fields[&0].value, DrecValue::U16(9));
        assert!(!materialized.fields.contains_key(&1));
    }

    #[test]
    fn string_uses_its_nul_not_descriptor_capacity_as_physical_width() {
        let record = parse_drec(
            &[0, 0, 0, b'x', 0, 0xff, 0xff],
            &schema(),
            DrecByteOrder::Little,
        )
        .unwrap();
        assert_eq!(record.fields[&0].value, DrecValue::String(b"x".to_vec()));
        assert_eq!(record.fields[&0].payload_range, 3..5);
    }

    #[test]
    fn invalid_descriptors_and_pointer_sized_d_are_rejected() {
        assert!(matches!(
            DrecSchema::new(vec![
                DrecDescriptor::new(DrecClass::F, 3),
                DrecDescriptor::end()
            ]),
            Err(DrecError::InvalidDescriptorLength { .. })
        ));
        assert!(matches!(
            DrecSchema::new(vec![
                DrecDescriptor::new(DrecClass::PointerSizedD, 4),
                DrecDescriptor::end()
            ]),
            Err(DrecError::PointerSizedFieldUnsupported { .. })
        ));
        assert!(matches!(
            DrecClass::from_tag(b'?'),
            Err(DrecError::UnknownClass { .. })
        ));
    }

    #[test]
    fn parser_and_encoder_enforce_the_proven_record_bound() {
        assert_eq!(
            parse_drec(&vec![0; DREC_MAX_LEN + 1], &schema(), DrecByteOrder::Little)
                .unwrap_err()
                .to_string(),
            format!(
                "drec length {} exceeds maximum {}",
                DREC_MAX_LEN + 1,
                DREC_MAX_LEN
            )
        );

        let oversized_schema = DrecSchema::new(vec![
            DrecDescriptor::new(DrecClass::Bytes, DREC_MAX_LEN),
            DrecDescriptor::end(),
        ])
        .unwrap();
        let oversized = DrecRecord::new(0, [(0, DrecValue::Bytes(vec![0; DREC_MAX_LEN]))]).unwrap();
        assert!(matches!(
            encode_drec(&oversized, &oversized_schema, DrecByteOrder::Little),
            Err(DrecError::RecordTooLarge { .. })
        ));
    }
}

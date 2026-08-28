//! Bounded parser for a SQL Anywhere long-value reference envelope.
//!
//! This module parses only the fixed 14-byte locator observed in modern
//! QuickBooks catalog rows.  A locator identifies a target page and selector,
//! but it does **not** establish a target-page record layout or resolve a
//! payload.  Callers must not treat a successful parse as table ownership or
//! as a decoded long value.

/// Exact byte width of a long-value reference envelope.
pub const LONG_VALUE_REF_LEN: usize = 14;

/// Marker required by the observed long-value reference envelope.
pub const LONG_VALUE_REF_MARKER: u16 = 0x0080;

/// A validated fixed-width long-value locator.
///
/// All fields retain their on-disk values.  In particular, `reserved` and
/// `selector` are intentionally not interpreted: their target-page semantics
/// are not yet established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongValueRef {
    /// The raw envelope marker. This is always [`LONG_VALUE_REF_MARKER`] for
    /// a successfully parsed locator.
    pub marker: u16,
    /// Declared payload byte length. This module does not locate or read it.
    pub payload_len: u32,
    /// Target page number, structurally bounded by the caller's page count.
    pub target_page: u32,
    /// Raw reserved field preserved without interpretation.
    pub reserved: u16,
    /// Raw target-page selector preserved without interpretation.
    pub selector: u16,
}

/// Why a supplied long-value envelope was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LongValueRefError {
    /// The supplied slice is not exactly one fixed-width envelope.
    #[error("long-value reference must be exactly {expected} bytes, got {actual}")]
    WrongLength {
        /// Required envelope width.
        expected: usize,
        /// Actual input width.
        actual: usize,
    },
    /// The marker does not identify the supported envelope form.
    #[error("unsupported long-value reference marker 0x{marker:04x}")]
    UnsupportedMarker {
        /// Raw little-endian marker value.
        marker: u16,
    },
    /// A locator with no declared payload cannot be resolved safely.
    #[error("long-value reference payload length must be nonzero")]
    ZeroPayloadLength,
    /// Page zero or a page outside the supplied store cannot be a target.
    #[error("long-value target page {target_page} is outside page count {page_count}")]
    TargetPageOutOfRange {
        /// Raw target page number.
        target_page: u32,
        /// Caller-provided exclusive page upper bound.
        page_count: u64,
    },
}

/// Parse one fixed-width long-value locator envelope.
///
/// `page_count` is the caller's exclusive upper bound for physical page
/// numbers.  The parser validates only envelope-level invariants: exact byte
/// width, marker, nonzero payload length, and a nonzero in-range target page.
/// It does not dereference `target_page`, resolve `selector`, or decode the
/// payload.
pub fn parse_long_value_ref(
    bytes: &[u8],
    page_count: u64,
) -> Result<LongValueRef, LongValueRefError> {
    if bytes.len() != LONG_VALUE_REF_LEN {
        return Err(LongValueRefError::WrongLength {
            expected: LONG_VALUE_REF_LEN,
            actual: bytes.len(),
        });
    }

    let marker = u16::from_le_bytes([bytes[0], bytes[1]]);
    if marker != LONG_VALUE_REF_MARKER {
        return Err(LongValueRefError::UnsupportedMarker { marker });
    }
    let payload_len = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
    if payload_len == 0 {
        return Err(LongValueRefError::ZeroPayloadLength);
    }
    let target_page = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
    if target_page == 0 || u64::from(target_page) >= page_count {
        return Err(LongValueRefError::TargetPageOutOfRange {
            target_page,
            page_count,
        });
    }

    Ok(LongValueRef {
        marker,
        payload_len,
        target_page,
        reserved: u16::from_le_bytes([bytes[10], bytes[11]]),
        selector: u16::from_le_bytes([bytes[12], bytes[13]]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(payload_len: u32, target_page: u32, reserved: u16, selector: u16) -> [u8; 14] {
        let mut bytes = [0u8; LONG_VALUE_REF_LEN];
        bytes[0..2].copy_from_slice(&LONG_VALUE_REF_MARKER.to_le_bytes());
        bytes[2..6].copy_from_slice(&payload_len.to_le_bytes());
        bytes[6..10].copy_from_slice(&target_page.to_le_bytes());
        bytes[10..12].copy_from_slice(&reserved.to_le_bytes());
        bytes[12..14].copy_from_slice(&selector.to_le_bytes());
        bytes
    }

    #[test]
    fn parses_and_preserves_every_envelope_field() {
        let bytes = reference(88, 42, 0, 3);
        assert_eq!(
            parse_long_value_ref(&bytes, 100).unwrap(),
            LongValueRef {
                marker: LONG_VALUE_REF_MARKER,
                payload_len: 88,
                target_page: 42,
                reserved: 0,
                selector: 3,
            }
        );
    }

    #[test]
    fn rejects_short_and_long_inputs() {
        assert_eq!(
            parse_long_value_ref(&[0; 13], 10),
            Err(LongValueRefError::WrongLength {
                expected: LONG_VALUE_REF_LEN,
                actual: 13,
            })
        );
        assert_eq!(
            parse_long_value_ref(&[0; 15], 10),
            Err(LongValueRefError::WrongLength {
                expected: LONG_VALUE_REF_LEN,
                actual: 15,
            })
        );
    }

    #[test]
    fn rejects_unrecognized_marker_and_zero_payload() {
        let mut bytes = reference(1, 1, 0, 0);
        bytes[0..2].copy_from_slice(&0x1234u16.to_le_bytes());
        assert_eq!(
            parse_long_value_ref(&bytes, 2),
            Err(LongValueRefError::UnsupportedMarker { marker: 0x1234 })
        );
        assert_eq!(
            parse_long_value_ref(&reference(0, 1, 0, 0), 2),
            Err(LongValueRefError::ZeroPayloadLength)
        );
    }

    #[test]
    fn rejects_zero_and_out_of_range_target_pages() {
        assert_eq!(
            parse_long_value_ref(&reference(1, 0, 0, 0), 10),
            Err(LongValueRefError::TargetPageOutOfRange {
                target_page: 0,
                page_count: 10,
            })
        );
        assert_eq!(
            parse_long_value_ref(&reference(1, 10, 0, 0), 10),
            Err(LongValueRefError::TargetPageOutOfRange {
                target_page: 10,
                page_count: 10,
            })
        );
    }
}

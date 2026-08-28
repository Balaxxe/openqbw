//! Conservative discovery of observed QuickBooks tagged-field anchors.
//!
//! This module scans one already-bounded SQL Anywhere row at a time.  It does
//! not interpret row headers, null bitmaps, or table schemas, and the values it
//! returns are evidence anchors rather than a claim to generically decode a
//! SQL Anywhere row.  Callers must keep the supplied slice limited to one row.

/// Length of a QuickBooks identifier observed in tagged fields.
pub const QB_ID_LEN: usize = 16;

/// The inclusive lower bound used by [`discover_row_anchors`]'s legacy
/// corpus date heuristic.
pub const PLAUSIBLE_SA_DATE_MIN: u32 = 13_000;

/// The exclusive upper bound used by [`discover_row_anchors`]'s legacy
/// corpus date heuristic.
pub const PLAUSIBLE_SA_DATE_MAX_EXCLUSIVE: u32 = 20_000;

const F32_ONE_LE: [u8; 4] = [0x00, 0x00, 0x80, 0x3f];

/// A printable string with the observed `[tag, 0x00, length]` field header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrintableStringAnchor {
    /// Offset of the three-byte field header within the supplied row.
    pub offset: usize,
    /// The two bytes immediately before the length byte. The second byte is
    /// always zero for this conservative anchor.
    pub prefix: [u8; 2],
    /// The byte length from the field header.
    pub length: u8,
    /// The printable ASCII value.
    pub value: String,
}

/// A 16-character base-62 QuickBooks ID found after a `0x10` length marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QbIdAnchor {
    /// Offset of the three-byte field header within the supplied row.
    pub offset: usize,
    /// The two bytes immediately before the `0x10` length marker. The second
    /// byte is always zero for this conservative anchor.
    pub prefix: [u8; 2],
    /// The QuickBooks ID.
    pub value: String,
}

/// A signed amount encoding immediately following the little-endian
/// `f32(1.0)` anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedAmountAnchor {
    /// Offset of the `f32(1.0)` bytes within the supplied row.
    pub f32_one_offset: usize,
    /// Offset of the four amount bytes within the supplied row.
    pub offset: usize,
    /// The amount encoding tag (`0x01` or `0x02`).
    pub type_tag: u8,
    /// The raw `[type][u24]` bytes.
    pub raw: [u8; 4],
    /// Cents under the observed high-bit-of-the-low-byte sign convention.
    pub cents: i32,
}

/// A plausible SA-day value found in a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaDateAnchor {
    /// Offset of the little-endian `u32` within the supplied row.
    pub offset: usize,
    /// The raw SA-day value.
    pub raw: u32,
}

/// Evidence anchors found within one bounded row.
///
/// Results are deliberately independent: adjacent or overlapping candidates
/// are retained so that a later, table-specific decoder can make attribution
/// decisions without this discovery layer inventing a row layout.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RowAnchors {
    /// Printable length-prefixed strings.
    pub printable_strings: Vec<PrintableStringAnchor>,
    /// 16-character base-62 QuickBooks IDs.
    pub qb_ids: Vec<QbIdAnchor>,
    /// Amounts supported by both a known preceding `f32(1.0)` and tag.
    pub signed_amounts: Vec<SignedAmountAnchor>,
    /// Plausible SA-day values.
    pub sa_dates: Vec<SaDateAnchor>,
}

/// Discover conservative QuickBooks field anchors within exactly one row.
///
/// No result crosses the boundary of `row`.  This function intentionally does
/// not infer which candidate belongs to which SQL Anywhere column.
pub fn discover_row_anchors(row: &[u8]) -> RowAnchors {
    discover_row_anchors_in_date_range(row, PLAUSIBLE_SA_DATE_MIN, PLAUSIBLE_SA_DATE_MAX_EXCLUSIVE)
}

/// Discover field anchors while restricting date candidates to an explicit
/// half-open SA-day range.
///
/// Enterprise 24 data extends beyond the older 13,000..20,000 corpus window,
/// so table-specific decoders should derive a narrow range from their report
/// or extraction context and call this function. An empty or reversed range
/// simply yields no date candidates; other anchor classes are unaffected.
pub fn discover_row_anchors_in_date_range(
    row: &[u8],
    date_min_inclusive: u32,
    date_max_exclusive: u32,
) -> RowAnchors {
    let mut anchors = RowAnchors::default();

    for offset in 0..row.len() {
        discover_tagged_string(row, offset, &mut anchors);
        discover_amount(row, offset, &mut anchors);
        discover_date(
            row,
            offset,
            date_min_inclusive,
            date_max_exclusive,
            &mut anchors,
        );
    }

    anchors
}

fn discover_tagged_string(row: &[u8], offset: usize, anchors: &mut RowAnchors) {
    let Some(header) = row.get(offset..offset.saturating_add(3)) else {
        return;
    };
    // Every documented QB tagged string has a zero context byte between the
    // leading tag and its length. Requiring it avoids treating arbitrary
    // printable bytes inside a row as a field header.
    if header[1] != 0 {
        return;
    }
    let length = header[2] as usize;
    if length == 0 {
        return;
    }
    let value_start = offset + 3;
    let Some(value) = row.get(value_start..value_start.saturating_add(length)) else {
        return;
    };
    if !is_printable_ascii(value) {
        return;
    }

    let prefix = [header[0], header[1]];
    let value = String::from_utf8(value.to_vec()).expect("printable ASCII is valid UTF-8");
    anchors.printable_strings.push(PrintableStringAnchor {
        offset,
        prefix,
        length: length as u8,
        value: value.clone(),
    });

    if length == QB_ID_LEN && header[2] == QB_ID_LEN as u8 && is_base62(value.as_bytes()) {
        anchors.qb_ids.push(QbIdAnchor {
            offset,
            prefix,
            value,
        });
    }
}

fn discover_amount(row: &[u8], f32_one_offset: usize, anchors: &mut RowAnchors) {
    let Some(f32_one) = row.get(f32_one_offset..f32_one_offset.saturating_add(F32_ONE_LE.len()))
    else {
        return;
    };
    if f32_one != F32_ONE_LE {
        return;
    }
    let offset = f32_one_offset + F32_ONE_LE.len();
    let Some(bytes) = row.get(offset..offset.saturating_add(4)) else {
        return;
    };
    if !matches!(bytes[0], 0x01 | 0x02) {
        return;
    }
    let raw = [bytes[0], bytes[1], bytes[2], bytes[3]];
    let magnitude = ((raw[1] & 0x7f) as i32) | ((raw[2] as i32) << 8) | ((raw[3] as i32) << 16);
    let cents = if raw[1] & 0x80 == 0 {
        magnitude
    } else {
        -magnitude
    };
    anchors.signed_amounts.push(SignedAmountAnchor {
        f32_one_offset,
        offset,
        type_tag: raw[0],
        raw,
        cents,
    });
}

fn discover_date(
    row: &[u8],
    offset: usize,
    date_min_inclusive: u32,
    date_max_exclusive: u32,
    anchors: &mut RowAnchors,
) {
    let Some(bytes) = row.get(offset..offset.saturating_add(4)) else {
        return;
    };
    let raw = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if (date_min_inclusive..date_max_exclusive).contains(&raw) {
        anchors.sa_dates.push(SaDateAnchor { offset, raw });
    }
}

fn is_printable_ascii(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
}

fn is_base62(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_tagged_printable_strings_and_qb_ids_with_provenance() {
        let mut row = vec![0xff; 80];
        row[4..7].copy_from_slice(&[0x0e, 0x00, 0x10]);
        row[7..23].copy_from_slice(b"0000000000001QBm");
        row[30..33].copy_from_slice(&[0x04, 0x00, 0x05]);
        row[33..38].copy_from_slice(b"hello");

        let anchors = discover_row_anchors(&row);
        assert_eq!(
            anchors.qb_ids,
            vec![QbIdAnchor {
                offset: 4,
                prefix: [0x0e, 0x00],
                value: "0000000000001QBm".into(),
            }]
        );
        assert!(anchors.printable_strings.iter().any(|field| {
            field.offset == 30 && field.prefix == [0x04, 0x00] && field.value == "hello"
        }));
    }

    #[test]
    fn rejects_non_printable_or_truncated_tagged_values() {
        let row = [0x0e, 0x00, 0x04, b'a', 0x01, b'b', 0x04, 0x00, 0x08, b'x'];
        let anchors = discover_row_anchors(&row);
        assert!(anchors.printable_strings.is_empty());
        assert!(anchors.qb_ids.is_empty());
    }

    #[test]
    fn rejects_printable_bytes_without_the_zero_context_byte() {
        let row = [0x04, b'x', 0x03, b'f', b'o', b'o'];
        let anchors = discover_row_anchors(&row);
        assert!(anchors.printable_strings.is_empty());
    }

    #[test]
    fn amounts_require_the_immediately_preceding_f32_one_anchor() {
        let mut row = vec![0u8; 30];
        row[2..6].copy_from_slice(&F32_ONE_LE);
        row[6..10].copy_from_slice(&[0x02, 0x85, 0x01, 0x00]);
        row[16..20].copy_from_slice(&[0x01, 0x05, 0x00, 0x00]);
        row[22..26].copy_from_slice(&F32_ONE_LE);
        row[26..30].copy_from_slice(&[0x03, 0x05, 0x00, 0x00]);

        let anchors = discover_row_anchors(&row);
        assert_eq!(
            anchors.signed_amounts,
            vec![SignedAmountAnchor {
                f32_one_offset: 2,
                offset: 6,
                type_tag: 0x02,
                raw: [0x02, 0x85, 0x01, 0x00],
                cents: -261,
            }]
        );
    }

    #[test]
    fn discovers_only_conservative_sa_date_range() {
        let mut row = vec![0u8; 20];
        row[1..5].copy_from_slice(&13_000u32.to_le_bytes());
        row[9..13].copy_from_slice(&19_999u32.to_le_bytes());
        row[15..19].copy_from_slice(&20_000u32.to_le_bytes());

        let anchors = discover_row_anchors(&row);
        assert!(anchors.sa_dates.contains(&SaDateAnchor {
            offset: 1,
            raw: 13_000
        }));
        assert!(anchors.sa_dates.contains(&SaDateAnchor {
            offset: 9,
            raw: 19_999
        }));
        assert!(!anchors.sa_dates.iter().any(|date| date.raw == 20_000));
    }

    #[test]
    fn explicit_date_range_supports_enterprise_24_without_widening_default() {
        let mut row = vec![0u8; 16];
        row[2..6].copy_from_slice(&24_500u32.to_le_bytes());

        assert!(discover_row_anchors(&row).sa_dates.is_empty());
        assert_eq!(
            discover_row_anchors_in_date_range(&row, 24_000, 25_000).sa_dates,
            vec![SaDateAnchor {
                offset: 2,
                raw: 24_500,
            }]
        );
        assert!(
            discover_row_anchors_in_date_range(&row, 25_000, 24_000)
                .sa_dates
                .is_empty()
        );
    }

    #[test]
    fn short_rows_are_safe_and_empty() {
        for length in 0..4 {
            assert_eq!(
                discover_row_anchors(&vec![0; length]),
                RowAnchors::default()
            );
        }
    }
}

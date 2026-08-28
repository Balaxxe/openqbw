//! Diagnostic scanner for a recurring, opaque 16-byte page-reference tuple.
//!
//! This module deliberately makes **no** ownership, table-membership,
//! allocation, or navigation claim.  A previous account-specific experiment
//! treated a set of these tuples as a table page map.  Direct row decoding
//! disproved that inference: the resulting pages can contain unrelated table
//! rows.  The only retained fact is the local byte pattern below.
//!
//! ```text
//! +00  first page      u32 little-endian
//! +04  second page     u32 little-endian
//! +08  ordinal         u16 little-endian
//! +10  opaque          u16 little-endian
//! +12  derived page    u32 little-endian
//! ```
//!
//! A candidate is reported only where `derived_page == first_page + ordinal +
//! 1`.  It is a bounded forensic aid, not a production traversal primitive.

/// One formula-matching opaque tuple found in caller-supplied bounded bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpaquePageTuple {
    /// Byte offset of this tuple in the scanned slice.
    pub offset: usize,
    /// Raw little-endian page-like value at `+00`.
    pub first_page: u32,
    /// Raw little-endian page-like value at `+04`.
    pub second_page: u32,
    /// Raw little-endian value at `+08` used in the observed relation.
    pub ordinal: u16,
    /// Raw, uninterpreted little-endian value at `+10`.
    pub opaque: u16,
    /// Raw little-endian page-like value at `+12`.
    pub derived_page: u32,
}

fn u16le(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn u32le(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

/// Scan a caller-bounded byte slice for the observed opaque tuple relation.
///
/// The returned values must not be used to attribute pages to a table, infer a
/// tree, or select rows for accounting output.
pub fn scan_opaque_page_tuples(bytes: &[u8]) -> Vec<OpaquePageTuple> {
    let mut found = Vec::new();
    for offset in 0..bytes.len().saturating_sub(15) {
        let (Some(first_page), Some(second_page), Some(ordinal), Some(opaque), Some(derived_page)) = (
            u32le(bytes, offset),
            u32le(bytes, offset + 4),
            u16le(bytes, offset + 8),
            u16le(bytes, offset + 10),
            u32le(bytes, offset + 12),
        ) else {
            continue;
        };
        let expected = first_page
            .checked_add(u32::from(ordinal))
            .and_then(|page| page.checked_add(1));
        if first_page != 0 && second_page != 0 && expected == Some(derived_page) {
            found.push(OpaquePageTuple {
                offset,
                first_page,
                second_page,
                ordinal,
                opaque,
                derived_page,
            });
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(first: u32, second: u32, ordinal: u16) -> Vec<u8> {
        let derived = first + u32::from(ordinal) + 1;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&first.to_le_bytes());
        bytes.extend_from_slice(&second.to_le_bytes());
        bytes.extend_from_slice(&ordinal.to_le_bytes());
        bytes.extend_from_slice(&[0x34, 0x12]);
        bytes.extend_from_slice(&derived.to_le_bytes());
        bytes
    }

    #[test]
    fn finds_unaligned_observed_relation_without_claiming_semantics() {
        let mut bytes = vec![0xaa, 0xbb, 0xcc];
        bytes.extend(tuple(100, 200, 4));
        let tuples = scan_opaque_page_tuples(&bytes);
        assert_eq!(tuples.len(), 1);
        assert_eq!(tuples[0].offset, 3);
        assert_eq!(tuples[0].derived_page, 105);
        assert_eq!(tuples[0].opaque, 0x1234);
    }

    #[test]
    fn rejects_nonmatching_or_zero_values() {
        let mut bad_formula = tuple(100, 200, 4);
        bad_formula[12..16].copy_from_slice(&106_u32.to_le_bytes());
        assert!(scan_opaque_page_tuples(&bad_formula).is_empty());
        assert!(scan_opaque_page_tuples(&tuple(0, 200, 4)).is_empty());
    }
}

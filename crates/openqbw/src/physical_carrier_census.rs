//! Conservative physical carrier census for slotted QuickBooks pages.
//!
//! The census is deliberately below the record layer. It reports only page
//! geometry already validated by [`opensqlany::SlottedPage`], and the bounded
//! page-start region that the lower-level parser exposes as an unclassified
//! prefix. It neither emits payload bytes nor treats the prefix as a row
//! continuation, table, transaction, or relation to the preceding page.

use std::ops::Range;

use opensqlany::{ApModel, Page, PageStore, PageType, SlottedPage};

use crate::SlotEndian;
use crate::row_scan::{RowScanError, decode_page_for_structural_scan};

/// Maximum unclassified prefix extent reported by this primitive.
///
/// `SlottedPage` searches its directory only in the first `0x300` bytes, so
/// an unclassified-prefix provenance can never exceed this bound.
pub const MAX_CONTINUATION_PREFIX_LEN: usize = 0x300;

/// Preferred semantic name for [`MAX_CONTINUATION_PREFIX_LEN`].
pub const MAX_UNCLASSIFIED_PREFIX_LEN: usize = MAX_CONTINUATION_PREFIX_LEN;

/// Whether a page had plaintext structural geometry available to census.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PhysicalCarrierPageStatus {
    /// A non-extent page. Its payload was deliberately not interpreted.
    NotExtent,
    /// Raw bytes were classified as opaque after QB-specific recovery failed.
    OpaqueHighEntropy,
    /// An extent page was decoded and checked for a slot directory.
    DecodedExtent,
}

/// Provenance-only shape of a validated slot directory.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SlotDirectoryCensus {
    /// Byte where the parser began scanning for this directory.
    pub scan_start: usize,
    /// Byte offset of the first actual directory word.
    pub array_start: usize,
    /// Exclusive byte offset of the last directory word.
    pub array_end: usize,
    /// Number of directory entries, including zero/deleted entries.
    pub slot_count: usize,
    /// Number of non-zero entries.
    pub live_slot_count: usize,
    /// Number of zero/deleted entries.
    pub deleted_slot_count: usize,
    /// Lowest non-zero row offset, if present.
    pub min_live_slot_offset: Option<u16>,
    /// On-page byte order of the directory words.
    pub slot_endian: SlotEndian,
    /// Whether a zero sentinel immediately preceded the directory array.
    pub leading_zero: bool,
}

/// Provenance of a non-zero, semantically unclassified page-start region.
///
/// This deliberately contains no bytes and does not identify an owner. It is
/// only a bounded range on the page that follows a parser-validated directory
/// boundary.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ContinuationPrefixProvenance {
    /// Page containing the observed prefix.
    pub page_number: u64,
    /// Half-open physical byte range. It is always `0..array_start`.
    pub byte_range: Range<usize>,
    /// Cached range length for stream-friendly census consumers.
    pub byte_len: usize,
}

/// Preferred semantic name for [`ContinuationPrefixProvenance`].
pub type UnclassifiedPrefixProvenance = ContinuationPrefixProvenance;

/// Structural census for a single physical page.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PhysicalCarrierPage {
    /// Zero-based page number in the QBW page store.
    pub page_number: u64,
    /// Page type read from the page trailer.
    pub page_type: PageType,
    /// Whether physical structure could be inspected.
    pub status: PhysicalCarrierPageStatus,
    /// Validated slot-directory geometry, when one was found.
    pub directory: Option<SlotDirectoryCensus>,
    /// Non-zero page-start region before `directory.array_start`, if any.
    /// Historical field name retained for source compatibility. The observed
    /// region is semantically unclassified and is not continuation evidence.
    pub continuation_prefix: Option<ContinuationPrefixProvenance>,
}

impl PhysicalCarrierPage {
    /// Returns the non-zero page-start region as unclassified provenance.
    #[must_use]
    pub fn unclassified_prefix(&self) -> Option<&UnclassifiedPrefixProvenance> {
        self.continuation_prefix.as_ref()
    }
}

/// Aggregate, adjacency-only observations over a censused page interval.
///
/// These counters deliberately say nothing about which prior slot might own a
/// prefix. They only make page-neighbour structural patterns auditable.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct AdjacentPageStructuralSummary {
    /// Number of physically consecutive page pairs in the requested interval.
    pub consecutive_pairs: u64,
    /// Pairs where both pages had a validated slot directory.
    pub both_pages_have_directory: u64,
    /// Pairs whose right page exposed a non-zero unclassified-prefix range.
    pub right_page_has_continuation_prefix: u64,
    /// Pairs whose right page had both a directory and a prefix.
    pub right_page_has_directory_and_prefix: u64,
    /// Pairs whose left page had a directory and whose right page had a prefix.
    /// This is a structural co-occurrence only, not a join candidate.
    pub left_directory_right_prefix: u64,
}

/// Deterministic result of a physical carrier census.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PhysicalCarrierCensus {
    /// One entry per page in increasing physical page-number order.
    pub pages: Vec<PhysicalCarrierPage>,
    /// Adjacency-only aggregate of the entries in [`Self::pages`].
    pub adjacent: AdjacentPageStructuralSummary,
}

/// Census one already-decoded page without emitting or decoding payload data.
pub fn census_decoded_physical_carrier_page(page: Page<'_>) -> PhysicalCarrierPage {
    let page_number = page.index();
    let page_type = page.trailer().page_type();
    if page_type != PageType::Extent {
        return PhysicalCarrierPage {
            page_number,
            page_type,
            status: PhysicalCarrierPageStatus::NotExtent,
            directory: None,
            continuation_prefix: None,
        };
    }

    let slotted = SlottedPage::parse(page);
    let Some(directory) = slotted.directory.as_ref() else {
        return PhysicalCarrierPage {
            page_number,
            page_type,
            status: PhysicalCarrierPageStatus::DecodedExtent,
            directory: None,
            continuation_prefix: None,
        };
    };
    // Keep source compatibility with the published opensqlany 0.1.1 API. The
    // newer dependency name is semantically clearer, but both accessors expose
    // the same unclassified bytes and this layer makes no continuation claim.
    #[allow(deprecated)]
    let continuation_prefix = slotted.overflow_prefix().map(|prefix| {
        // `array_start` is discovered in SlottedPage's bounded search window.
        debug_assert!(prefix.len() <= MAX_UNCLASSIFIED_PREFIX_LEN);
        ContinuationPrefixProvenance {
            page_number,
            byte_range: 0..prefix.len(),
            byte_len: prefix.len(),
        }
    });
    PhysicalCarrierPage {
        page_number,
        page_type,
        status: PhysicalCarrierPageStatus::DecodedExtent,
        directory: Some(SlotDirectoryCensus {
            scan_start: directory.scan_start,
            array_start: directory.array_start,
            array_end: directory.end,
            slot_count: directory.slots.len(),
            live_slot_count: directory.live_count(),
            deleted_slot_count: directory.deleted_count(),
            min_live_slot_offset: directory.min_offset(),
            slot_endian: if directory.big_endian {
                SlotEndian::Big
            } else {
                SlotEndian::Little
            },
            leading_zero: directory.leading_zero,
        }),
        continuation_prefix,
    }
}

/// Census an immutable page range in physical page-number order.
///
/// The range is half-open and clamped to the store. Page zero is excluded,
/// matching the row scanner. No contents are retained in the returned census.
pub fn census_physical_carriers(
    store: &PageStore,
    model: &ApModel,
    start_page: u64,
    end_page: u64,
) -> Result<PhysicalCarrierCensus, RowScanError> {
    let page_count = store.page_count();
    let start = start_page.max(1).min(page_count);
    let end = end_page.min(page_count);
    let mut pages = Vec::with_capacity((end.saturating_sub(start)) as usize);
    for page_number in start..end {
        let raw_page = store
            .page(page_number)
            .map_err(|source| RowScanError::ReadPage {
                page_number,
                source,
            })?;
        let page_type = raw_page.trailer().page_type();
        let page = if page_type != PageType::Extent {
            PhysicalCarrierPage {
                page_number,
                page_type,
                status: PhysicalCarrierPageStatus::NotExtent,
                directory: None,
                continuation_prefix: None,
            }
        } else if let Some(plaintext) =
            decode_page_for_structural_scan(page_number, raw_page.bytes(), model, store)
        {
            census_decoded_physical_carrier_page(Page::from_bytes(page_number, &plaintext))
        } else {
            PhysicalCarrierPage {
                page_number,
                page_type,
                status: PhysicalCarrierPageStatus::OpaqueHighEntropy,
                directory: None,
                continuation_prefix: None,
            }
        };
        pages.push(page);
    }
    Ok(PhysicalCarrierCensus {
        adjacent: aggregate_adjacent_pages(&pages),
        pages,
    })
}

fn aggregate_adjacent_pages(pages: &[PhysicalCarrierPage]) -> AdjacentPageStructuralSummary {
    let mut summary = AdjacentPageStructuralSummary::default();
    for pair in pages.windows(2) {
        let left = &pair[0];
        let right = &pair[1];
        if right.page_number != left.page_number.saturating_add(1) {
            continue;
        }
        summary.consecutive_pairs += 1;
        let left_directory = left.directory.is_some();
        let right_directory = right.directory.is_some();
        let right_prefix = right.continuation_prefix.is_some();
        if left_directory && right_directory {
            summary.both_pages_have_directory += 1;
        }
        if right_prefix {
            summary.right_page_has_continuation_prefix += 1;
        }
        if right_directory && right_prefix {
            summary.right_page_has_directory_and_prefix += 1;
        }
        if left_directory && right_prefix {
            summary.left_directory_right_prefix += 1;
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded_extent(page_number: u64, directory_start: usize, prefix: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0_u8; 4096];
        bytes[..prefix.len()].copy_from_slice(prefix);
        let offsets = [
            0x0e00_u16, 0x0d00, 0x0c00, 0x0b00, 0x0a00, 0x0900, 0x0800, 0x0700,
        ];
        for (index, offset) in offsets.into_iter().enumerate() {
            let at = directory_start + index * 2;
            bytes[at..at + 2].copy_from_slice(&offset.to_le_bytes());
        }
        let end = directory_start + offsets.len() * 2;
        bytes[end..end + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        bytes[0xFF2] = b'E';
        bytes[0xFEF] = page_number as u8;
        bytes
    }

    #[test]
    fn captures_directory_and_prefix_provenance_without_payload() {
        let bytes = decoded_extent(22, 12, &[0xD1, 0xE2, 0xF3]);
        let census = census_decoded_physical_carrier_page(Page::from_bytes(22, &bytes));

        assert_eq!(census.status, PhysicalCarrierPageStatus::DecodedExtent);
        let directory = census.directory.expect("directory");
        assert_eq!(directory.array_start, 12);
        assert_eq!(directory.array_end, 28);
        assert_eq!(directory.slot_count, 8);
        assert_eq!(directory.live_slot_count, 8);
        assert_eq!(directory.deleted_slot_count, 0);
        assert_eq!(directory.slot_endian, SlotEndian::Little);
        assert_eq!(
            census.continuation_prefix,
            Some(ContinuationPrefixProvenance {
                page_number: 22,
                byte_range: 0..12,
                byte_len: 12,
            })
        );
    }

    #[test]
    fn ignores_zero_prefix_and_non_extent_payload() {
        let bytes = decoded_extent(23, 12, &[]);
        let census = census_decoded_physical_carrier_page(Page::from_bytes(23, &bytes));
        assert!(census.directory.is_some());
        assert!(census.continuation_prefix.is_none());

        let mut alloc = bytes;
        alloc[0xFF2] = b'A';
        let non_extent = census_decoded_physical_carrier_page(Page::from_bytes(24, &alloc));
        assert_eq!(non_extent.status, PhysicalCarrierPageStatus::NotExtent);
        assert!(non_extent.directory.is_none());
        assert!(non_extent.continuation_prefix.is_none());
    }

    #[test]
    fn aggregates_only_consecutive_page_geometry() {
        let left = census_decoded_physical_carrier_page(Page::from_bytes(
            40,
            &decoded_extent(40, 12, &[]),
        ));
        let right = census_decoded_physical_carrier_page(Page::from_bytes(
            41,
            &decoded_extent(41, 12, &[1]),
        ));
        let gap = census_decoded_physical_carrier_page(Page::from_bytes(
            43,
            &decoded_extent(43, 12, &[2]),
        ));
        assert_eq!(
            aggregate_adjacent_pages(&[left, right, gap]),
            AdjacentPageStructuralSummary {
                consecutive_pairs: 1,
                both_pages_have_directory: 1,
                right_page_has_continuation_prefix: 1,
                right_page_has_directory_and_prefix: 1,
                left_directory_right_prefix: 1,
            }
        );
    }
}

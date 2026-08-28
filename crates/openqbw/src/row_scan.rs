//! Provenance-preserving scan of slotted data pages.
//!
//! This module deliberately stops at the physical record boundary.  It does
//! not infer a table, a transaction type, or a field layout: those are
//! separate, higher-confidence concerns.  Its output is useful to decoders
//! because every byte slice carries the exact page, slot, byte range, page
//! type, and slot-directory byte order from which it came.

use std::collections::VecDeque;
use std::ops::Range;

use opensqlany::{ApModel, Page, PageStore, PageType, SlottedPage};
use thiserror::Error;

use crate::bv_recovery::{deobfuscate_with_bv, recover_bv_any};
use crate::opaque::is_opaque_high_entropy;

const PAGE_DATA_END: usize = 0xFF0;

/// Byte order used by the page's slot directory.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SlotEndian {
    /// Little-endian slot words.
    Little,
    /// Big-endian slot words.
    Big,
}

/// Exact physical origin of a [`RowFragment`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RowProvenance {
    /// Zero-based page number in the QBW page store.
    pub page_number: u64,
    /// Index in the on-page slot directory, including deleted slots before it.
    pub slot_index: usize,
    /// Offset stored in that directory slot.
    pub slot_offset: u16,
    /// Half-open byte range in the decoded page.
    pub byte_range: Range<usize>,
    /// Type read from the page trailer.
    pub page_type: PageType,
    /// Byte order used to decode the directory containing this slot.
    pub slot_endian: SlotEndian,
}

/// A bounded physical record fragment from a decoded data page.
///
/// A fragment is not yet a logical QuickBooks record.  It may be a complete
/// row or a storage-level fragment, so consumers must retain its provenance
/// and may not assume table ownership from it alone.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RowFragment {
    /// Physical source information for [`Self::bytes`].
    pub provenance: RowProvenance,
    /// Decoded bytes in `provenance.byte_range`.
    pub bytes: Vec<u8>,
}

/// Reason a page did not produce physical row fragments.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PageSkipReason {
    /// Only extent pages are scanned; other page types do not have this row
    /// layout contract.
    NotExtent,
    /// The raw body resembles a separately compressed or encrypted blob.
    OpaqueHighEntropy,
    /// No non-overlapping, sufficiently populated slot directory was found.
    NoSlotDirectory,
    /// A directory was present but supplied no valid live byte ranges.
    NoLiveRowRanges,
}

/// Diagnostic for one skipped page.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SkippedPage {
    /// Zero-based page number in the QBW page store.
    pub page_number: u64,
    /// Type read from the page trailer.
    pub page_type: PageType,
    /// Why no fragments were emitted for this page.
    pub reason: PageSkipReason,
}

/// Result of scanning one decoded page.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PageScanOutcome {
    /// Structurally valid fragments in increasing physical-byte order.
    Rows(Vec<RowFragment>),
    /// A page that was intentionally not interpreted as rows.
    Skipped(SkippedPage),
}

/// An event emitted during a whole-store scan.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RowScanEvent {
    /// A decoded physical fragment.
    Row(RowFragment),
    /// A page-level diagnostic.
    Skipped(SkippedPage),
}

/// Error while reading a page during a whole-store scan.
#[derive(Debug, Error)]
pub enum RowScanError {
    /// The backing page store could not provide a requested page.
    #[error("could not read page {page_number}: {source}")]
    ReadPage {
        /// Requested page number.
        page_number: u64,
        /// Underlying page-store error.
        #[source]
        source: opensqlany::Error,
    },
}

/// Scan one already-decoded page without assigning any logical ownership.
///
/// The caller must provide plaintext page bytes.  The trailer remains part of
/// the page and supplies the recorded page type; no bytes outside the data
/// body (`0..0xFF0`) are ever emitted.
pub fn scan_decoded_page(page: Page<'_>) -> PageScanOutcome {
    let page_number = page.index();
    let page_type = page.trailer().page_type();
    if page_type != PageType::Extent {
        return PageScanOutcome::Skipped(SkippedPage {
            page_number,
            page_type,
            reason: PageSkipReason::NotExtent,
        });
    }

    let slotted = SlottedPage::parse(page);
    let Some(directory) = slotted.directory.as_ref() else {
        return PageScanOutcome::Skipped(SkippedPage {
            page_number,
            page_type,
            reason: PageSkipReason::NoSlotDirectory,
        });
    };

    // Associate every offset with its actual directory position before
    // sorting by physical address.  Sorting makes output independent of
    // directory word order while retaining enough information to reconstruct
    // the exact source slot.
    let mut live: Vec<(usize, u16)> = directory
        .slots
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, offset)| *offset != 0)
        .collect();
    live.sort_unstable_by_key(|(slot_index, offset)| (*offset, *slot_index));

    let slot_endian = if directory.big_endian {
        SlotEndian::Big
    } else {
        SlotEndian::Little
    };
    let bytes = slotted.page.bytes();
    let mut rows = Vec::with_capacity(live.len());
    for (position, (slot_index, slot_offset)) in live.iter().copied().enumerate() {
        let start = usize::from(slot_offset);
        let end = live
            .get(position + 1)
            .map(|(_, next_offset)| usize::from(*next_offset))
            .unwrap_or(PAGE_DATA_END);
        // `SlottedPage` validates that the directory does not overlap its
        // first row.  Keep this local bound check too, so a future lower-level
        // parser change cannot expand an emitted fragment into the trailer.
        if start >= end || end > PAGE_DATA_END {
            continue;
        }
        rows.push(RowFragment {
            provenance: RowProvenance {
                page_number,
                slot_index,
                slot_offset,
                byte_range: start..end,
                page_type,
                slot_endian,
            },
            bytes: bytes[start..end].to_vec(),
        });
    }

    if rows.is_empty() {
        PageScanOutcome::Skipped(SkippedPage {
            page_number,
            page_type,
            reason: PageSkipReason::NoLiveRowRanges,
        })
    } else {
        PageScanOutcome::Rows(rows)
    }
}

/// Deterministic, whole-store physical row scanner.
///
/// Pages are visited in increasing page-number order.  Within a page, rows
/// are emitted in increasing physical byte offset, followed by neither
/// inferred table information nor cross-page stitching.  Skipped pages are
/// emitted as diagnostics rather than being silently discarded.  Raw entropy
/// is considered only after the QB-specific bv recovery cascade fails, so an
/// AP-obfuscated page whose ciphertext is high entropy is never discarded
/// before its decoded slot directory has had a chance to validate it.
pub struct RowScanIter<'a> {
    store: &'a PageStore,
    model: &'a ApModel,
    next_page: u64,
    page_count: u64,
    pending: VecDeque<RowScanEvent>,
}

impl<'a> RowScanIter<'a> {
    /// Create a scanner over every non-superblock page in `store`.
    pub fn new(store: &'a PageStore, model: &'a ApModel) -> Self {
        Self::page_range(store, model, 1, store.page_count())
    }

    /// Create a scanner over `start_page..end_page` in ascending page order.
    ///
    /// Bounds are clamped to the physical store; page zero is never scanned.
    /// This supports bounded structural censuses without changing the output
    /// order or provenance of the selected pages.
    pub fn page_range(
        store: &'a PageStore,
        model: &'a ApModel,
        start_page: u64,
        end_page: u64,
    ) -> Self {
        let page_count = store.page_count();
        Self {
            store,
            model,
            next_page: start_page.max(1).min(page_count),
            page_count: end_page.min(page_count),
            pending: VecDeque::new(),
        }
    }

    fn fill_pending(&mut self) -> Result<bool, RowScanError> {
        while self.pending.is_empty() && self.next_page < self.page_count {
            let page_number = self.next_page;
            self.next_page += 1;
            let raw_page =
                self.store
                    .page(page_number)
                    .map_err(|source| RowScanError::ReadPage {
                        page_number,
                        source,
                    })?;
            let page_type = raw_page.trailer().page_type();

            if page_type != PageType::Extent {
                self.pending.push_back(RowScanEvent::Skipped(SkippedPage {
                    page_number,
                    page_type,
                    reason: PageSkipReason::NotExtent,
                }));
                continue;
            }
            let Some(plaintext) = decode_page_for_structural_scan(
                page_number,
                raw_page.bytes(),
                self.model,
                self.store,
            ) else {
                self.pending.push_back(RowScanEvent::Skipped(SkippedPage {
                    page_number,
                    page_type,
                    reason: PageSkipReason::OpaqueHighEntropy,
                }));
                continue;
            };
            match scan_decoded_page(Page::from_bytes(page_number, &plaintext)) {
                PageScanOutcome::Rows(rows) => {
                    self.pending.extend(rows.into_iter().map(RowScanEvent::Row));
                }
                PageScanOutcome::Skipped(skipped) => {
                    self.pending.push_back(RowScanEvent::Skipped(skipped))
                }
            }
        }
        Ok(!self.pending.is_empty())
    }
}

/// The high-confidence decoding decision that can be made without a learned
/// store model.  Entropy is a negative classifier only after a positive QB
/// recovery attempt fails: normal AP-obfuscated rows can look statistically
/// random before decoding.
enum DecodeDecision {
    Confident(Vec<u8>),
    Opaque,
    Fallback,
}

fn decode_decision(page_number: u64, raw_page: &[u8]) -> DecodeDecision {
    if let Some(bv) = recover_bv_any(page_number, raw_page) {
        return DecodeDecision::Confident(deobfuscate_with_bv(raw_page, page_number, bv));
    }
    if is_opaque_high_entropy(raw_page) {
        DecodeDecision::Opaque
    } else {
        DecodeDecision::Fallback
    }
}

/// Decode one page for a strictly physical structural analysis.
///
/// This is intentionally crate-private: it is shared by the row scanner and
/// the physical carrier census so both apply the exact same conservative
/// QB-specific recovery sequence. `None` means that the page was classified
/// as opaque before any page structure was interpreted.
pub(crate) fn decode_page_for_structural_scan(
    page_number: u64,
    raw_page: &[u8],
    model: &ApModel,
    store: &PageStore,
) -> Option<Vec<u8>> {
    match decode_decision(page_number, raw_page) {
        DecodeDecision::Confident(plaintext) => Some(plaintext),
        DecodeDecision::Opaque => None,
        DecodeDecision::Fallback => {
            Some(model.deobfuscate_with_store(raw_page, page_number, store))
        }
    }
}

impl Iterator for RowScanIter<'_> {
    type Item = Result<RowScanEvent, RowScanError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(event) = self.pending.pop_front() {
            return Some(Ok(event));
        }
        match self.fill_pending() {
            Ok(true) => self.pending.pop_front().map(Ok),
            Ok(false) => None,
            Err(error) => Some(Err(error)),
        }
    }
}

/// Create a deterministic whole-store physical row scanner.
pub fn iter_row_fragments<'a>(store: &'a PageStore, model: &'a ApModel) -> RowScanIter<'a> {
    RowScanIter::new(store, model)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: usize = 4096;
    const TRAILER_START: usize = 0xFF0;

    fn page_with_slots(
        page_number: u64,
        offsets: &[u16],
        big_endian: bool,
        page_type: u8,
    ) -> Vec<u8> {
        let mut bytes = vec![0_u8; 4096];
        for (index, offset) in offsets.iter().enumerate() {
            let at = index * 2;
            let encoded = if big_endian {
                offset.to_be_bytes()
            } else {
                offset.to_le_bytes()
            };
            bytes[at..at + 2].copy_from_slice(&encoded);
        }
        // End the directory explicitly, rather than allowing zero-filled
        // bytes to be interpreted as deleted slots.
        let end = offsets.len() * 2;
        bytes[end..end + 2].copy_from_slice(&if big_endian {
            u16::MAX.to_be_bytes()
        } else {
            u16::MAX.to_le_bytes()
        });
        bytes[0xFF2] = page_type;
        // Put distinct marker bytes at each physical row start.
        for (index, offset) in offsets.iter().rev().enumerate() {
            bytes[usize::from(*offset)] = index as u8 + 1;
        }
        // Preserve the argument in a way that makes accidental fixed-page
        // assumptions visible in the test setup.
        bytes[0xFEF] = page_number as u8;
        bytes
    }

    #[test]
    fn emits_little_endian_rows_in_physical_order_with_slot_provenance() {
        let offsets = [
            0x0e00, 0x0d00, 0x0c00, 0x0b00, 0x0a00, 0x0900, 0x0800, 0x0700,
        ];
        let bytes = page_with_slots(42, &offsets, false, b'E');
        let PageScanOutcome::Rows(rows) = scan_decoded_page(Page::from_bytes(42, &bytes)) else {
            panic!("expected rows");
        };

        assert_eq!(rows.len(), 8);
        assert_eq!(rows[0].provenance.byte_range, 0x0700..0x0800);
        assert_eq!(rows[0].provenance.slot_index, 7);
        assert_eq!(rows[0].provenance.slot_offset, 0x0700);
        assert_eq!(rows[0].provenance.page_number, 42);
        assert_eq!(rows[0].provenance.page_type, PageType::Extent);
        assert_eq!(rows[0].provenance.slot_endian, SlotEndian::Little);
        assert_eq!(rows[7].provenance.byte_range, 0x0e00..PAGE_DATA_END);
        assert!(rows.windows(2).all(|pair| {
            pair[0].provenance.byte_range.start < pair[1].provenance.byte_range.start
        }));
    }

    #[test]
    fn preserves_big_endian_directory_provenance() {
        let offsets = [
            0x0ea1, 0x0e84, 0x0e67, 0x0e4a, 0x0e2d, 0x0e10, 0x0df3, 0x0dd6,
        ];
        let bytes = page_with_slots(3041, &offsets, true, b'e');
        let PageScanOutcome::Rows(rows) = scan_decoded_page(Page::from_bytes(3041, &bytes)) else {
            panic!("expected rows");
        };

        assert_eq!(rows.len(), 8);
        assert_eq!(rows[0].provenance.slot_endian, SlotEndian::Big);
        assert_eq!(rows[0].provenance.slot_index, 7);
        assert_eq!(rows[0].provenance.slot_offset, 0x0dd6);
    }

    #[test]
    fn reports_non_extent_pages_without_attempting_row_interpretation() {
        let bytes = page_with_slots(
            7,
            &[0x900, 0x880, 0x860, 0x840, 0x820, 0x800, 0x7e0, 0x7c0],
            false,
            b'A',
        );
        assert_eq!(
            scan_decoded_page(Page::from_bytes(7, &bytes)),
            PageScanOutcome::Skipped(SkippedPage {
                page_number: 7,
                page_type: PageType::Alloc,
                reason: PageSkipReason::NotExtent,
            })
        );
    }

    #[test]
    fn reports_missing_or_invalid_directories() {
        let mut bytes = vec![0_u8; 4096];
        bytes[0xFF2] = b'E';
        assert_eq!(
            scan_decoded_page(Page::from_bytes(88, &bytes)),
            PageScanOutcome::Skipped(SkippedPage {
                page_number: 88,
                page_type: PageType::Extent,
                reason: PageSkipReason::NoSlotDirectory,
            })
        );
    }

    fn ap_encode(plain: &[u8], page_number: u64, bv: u8, steps: [u8; 8]) -> Vec<u8> {
        let p16 = (page_number % 16) as u8;
        let bias = p16 / 2 * 4;
        let mut raw = vec![0_u8; PAGE];
        raw[TRAILER_START..].copy_from_slice(&plain[TRAILER_START..]);
        for (sector, step) in steps.into_iter().enumerate() {
            let start = sector * 512;
            let end = if sector == 7 {
                TRAILER_START
            } else {
                start + 512
            };
            let base = bv
                .wrapping_add(page_number as u8)
                .wrapping_add(sector as u8)
                .wrapping_sub(bias);
            for offset in start..end {
                raw[offset] = plain[offset]
                    .wrapping_add(base)
                    .wrapping_add(((offset - start) as u8).wrapping_mul(step));
            }
        }
        raw
    }

    #[test]
    fn high_entropy_ap_ciphertext_is_decoded_before_opaque_classification() {
        let page_number = 4242;
        let offsets = [
            0x0e00, 0x0d00, 0x0c00, 0x0b00, 0x0a00, 0x0900, 0x0800, 0x0700,
        ];
        let mut plain = page_with_slots(page_number, &offsets, false, b'E');
        // The C.36 anchor provides a positive, QB-specific recovery proof.
        plain[0x100..0x104].copy_from_slice(&[0x04, 0x00, 0xD5, 0x0B]);
        plain[TRAILER_START] = 0x04;
        let raw = ap_encode(
            &plain,
            page_number,
            0x5a,
            [29, 47, 61, 73, 97, 113, 131, 149],
        );

        assert!(
            is_opaque_high_entropy(&raw),
            "the raw AP ciphertext must exercise the previous false skip"
        );
        let DecodeDecision::Confident(decoded) = decode_decision(page_number, &raw) else {
            panic!("positive bv recovery must preempt raw entropy classification");
        };
        let PageScanOutcome::Rows(rows) =
            scan_decoded_page(Page::from_bytes(page_number, &decoded))
        else {
            panic!("decoded slotted page must yield rows");
        };
        assert_eq!(rows.len(), offsets.len());
    }

    #[test]
    fn high_entropy_page_without_confident_recovery_is_classified_opaque() {
        let mut raw = vec![0_u8; PAGE];
        let mut state = 0xDEAD_BEEFu32;
        for byte in &mut raw {
            state = state.wrapping_mul(0x85EB_CA6B).wrapping_add(1);
            *byte = (state >> 24) as u8;
        }
        raw[0xFF2] = b'E';
        assert!(is_opaque_high_entropy(&raw));
        assert!(matches!(
            decode_decision(31337, &raw),
            DecodeDecision::Opaque
        ));
    }
}

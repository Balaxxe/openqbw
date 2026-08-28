//! Whole-store, fail-closed collection of Enterprise materialized table pages.
//!
//! The scan materializes every raw physical page with an already established
//! file-wide transform key. It does not choose between structurally valid page
//! candidates.  In particular, a table-ID match is only a routing fact, never
//! evidence sufficient to collapse divergent candidates.

use std::collections::BTreeMap;

use opensqlany::PageStore;

use crate::{
    EnterpriseCandidateResolutionError, EnterpriseMaterializedTablePage,
    EnterprisePageMaterializationError, EnterprisePageTransformKey,
    materialize_enterprise_table_page_candidates_with_key, materialized_table_id,
    resolve_enterprise_table_page_candidates,
};

/// All target-table materialization candidates for one raw physical page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterpriseTablePageCandidateGroup {
    /// Zero-based raw physical QBW page number.
    pub raw_page_number: u64,
    /// Every structurally valid candidate whose physical table ID equals the
    /// requested table ID. This is never collapsed by the scanner.
    pub candidates: Vec<EnterpriseMaterializedTablePage>,
    /// Directory availability counts parallel to [`Self::candidates`].
    pub directory_counts: Vec<EnterpriseTableDirectoryCounts>,
}

/// One materialized candidate's type-4 directory availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnterpriseTableDirectoryCounts {
    /// Candidate index in its enclosing [`EnterpriseTablePageCandidateGroup`].
    pub candidate_index: usize,
    /// Nonzero directory slots resolvable as physical row records.
    pub accessible_records: u16,
    /// Zero directory slots that cannot be selected by the resolver.
    pub missing_records: u16,
}

/// A raw page whose valid materialized candidates identify different tables.
///
/// These candidates are retained outside target groups so callers can audit
/// the ambiguity. Even if one candidate names the target table, it is not
/// included as extractable target data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterpriseTableIdConflict {
    /// Zero-based raw physical QBW page number.
    pub raw_page_number: u64,
    /// Distinct nonzero physical table IDs observed among the candidates.
    pub table_ids: Vec<u32>,
    /// Every structurally valid materialized candidate for this raw page.
    pub candidates: Vec<EnterpriseMaterializedTablePage>,
}

/// Result of scanning one entire immutable page store for a physical table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterpriseTableScan {
    /// Requested nonzero physical SQL Anywhere table ID.
    pub target_table_id: u32,
    /// Target table candidates in ascending raw physical-page order.
    pub candidate_groups: Vec<EnterpriseTablePageCandidateGroup>,
    /// Materialized candidate sets with conflicting physical table identities.
    pub table_id_conflicts: Vec<EnterpriseTableIdConflict>,
    /// Complete page and directory availability census.
    pub census: EnterpriseTableScanCensus,
}

/// One-pass materialization inventory for every nonzero Enterprise table ID.
///
/// This is the batch-extraction entry point. It reads each raw page once and
/// retains table-ID-consistent candidate groups under their physical table
/// ID. Use [`Self::for_table`] to obtain the same table-scoped view exposed by
/// [`scan_enterprise_table_pages`] without re-materializing the store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterpriseTableStoreScan {
    /// Candidate groups keyed by their one agreed nonzero physical table ID.
    pub table_candidate_groups: BTreeMap<u32, Vec<EnterpriseTablePageCandidateGroup>>,
    /// Materialized candidate sets that disagreed on physical table ID.
    pub table_id_conflicts: Vec<EnterpriseTableIdConflict>,
    /// One-pass raw-page and failure census.
    pub census: EnterpriseTableStoreScanCensus,
}

impl EnterpriseTableStoreScan {
    /// Create an owned, table-specific scan view without rereading the store.
    pub fn for_table(
        &self,
        target_table_id: u32,
    ) -> Result<EnterpriseTableScan, EnterpriseTableScanError> {
        if target_table_id == 0 {
            return Err(EnterpriseTableScanError::ZeroTargetTableId);
        }
        let candidate_groups = self
            .table_candidate_groups
            .get(&target_table_id)
            .cloned()
            .unwrap_or_default();
        let mut census = EnterpriseTableScanCensus {
            raw_pages_scanned: self.census.raw_pages_scanned,
            table_id_conflict_pages: self.census.table_id_conflict_pages,
            skips: self.census.skips.clone(),
            ..EnterpriseTableScanCensus::default()
        };
        for (table_id, groups) in &self.table_candidate_groups {
            for group in groups {
                if *table_id != target_table_id {
                    census.non_target_candidate_pages += group.candidates.len() as u64;
                    continue;
                }
                census.target_raw_page_groups += 1;
                census.target_candidate_pages += group.candidates.len() as u64;
                for counts in &group.directory_counts {
                    census.target_candidate_accessible_records +=
                        u64::from(counts.accessible_records);
                    census.target_candidate_missing_records += u64::from(counts.missing_records);
                }
                if group.directory_counts.len() == 1 {
                    census.unambiguous_accessible_records +=
                        u64::from(group.directory_counts[0].accessible_records);
                    census.unambiguous_missing_records +=
                        u64::from(group.directory_counts[0].missing_records);
                }
            }
        }
        Ok(EnterpriseTableScan {
            target_table_id,
            candidate_groups,
            table_id_conflicts: self.table_id_conflicts.clone(),
            census,
        })
    }
}

/// Whole-store counts emitted by [`scan_enterprise_table_store`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnterpriseTableStoreScanCensus {
    /// Raw physical pages inspected, including page zero.
    pub raw_pages_scanned: u64,
    /// Materialized candidates retained in a single-table group.
    pub table_candidate_pages: u64,
    /// Accessible directory slots summed across every retained candidate.
    pub candidate_accessible_records: u64,
    /// Missing directory slots summed across every retained candidate.
    pub candidate_missing_records: u64,
    /// Raw pages whose valid candidates disagreed on physical table ID.
    pub table_id_conflict_pages: u64,
    /// Raw-page failures grouped by fail-closed classification.
    pub skips: BTreeMap<EnterpriseTableScanSkipReason, u64>,
}

/// Counts emitted by [`scan_enterprise_table_pages`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnterpriseTableScanCensus {
    /// Raw physical pages inspected, including page zero.
    pub raw_pages_scanned: u64,
    /// Raw pages producing one or more target-table candidates.
    pub target_raw_page_groups: u64,
    /// Target-table candidates retained across all groups.
    pub target_candidate_pages: u64,
    /// Accessible slots summed across every retained target candidate.
    ///
    /// This is a candidate observation total, not a deduplicated row count.
    pub target_candidate_accessible_records: u64,
    /// Missing slots summed across every retained target candidate.
    pub target_candidate_missing_records: u64,
    /// Accessible slots from groups containing exactly one target candidate.
    pub unambiguous_accessible_records: u64,
    /// Missing slots from groups containing exactly one target candidate.
    pub unambiguous_missing_records: u64,
    /// Valid materialized candidates that belonged to a non-target table.
    pub non_target_candidate_pages: u64,
    /// Raw pages whose valid candidates disagreed on physical table ID.
    pub table_id_conflict_pages: u64,
    /// Raw-page failures grouped by fail-closed classification.
    pub skips: BTreeMap<EnterpriseTableScanSkipReason, u64>,
}

/// Fail-closed classification of a skipped raw page.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EnterpriseTableScanSkipReason {
    /// The page did not reproduce its physical key under any header transform.
    NoHeaderCandidate,
    /// Multiple header transforms reproduced the physical key.
    AmbiguousHeaderCandidates,
    /// No candidate reconstructed a completely valid materialized type-4 page.
    NotMaterializedTablePage,
    /// Materialization reported an impossible/unsupported raw page length.
    InvalidRawPageLength,
    /// The raw page number exceeded the observed 32-bit Enterprise key range.
    PageNumberOutOfRange,
    /// A bounded sector permutation failed.
    SectorTransform,
    /// A candidate had no usable nonzero materialized table ID.
    InvalidMaterializedTableId,
}

/// Scan all pages in `store` for materialized candidates of `target_table_id`.
///
/// A target ID of zero is rejected because zero is never a usable materialized
/// table identity. Candidate groups and conflicts retain owned 4096-byte pages
/// so the caller can subsequently run a family-specific decoder without
/// reopening or rereading the source snapshot.
pub fn scan_enterprise_table_pages(
    store: &PageStore,
    transform_key: EnterprisePageTransformKey,
    target_table_id: u32,
) -> Result<EnterpriseTableScan, EnterpriseTableScanError> {
    scan_enterprise_table_store(store, transform_key)?.for_table(target_table_id)
}

/// Scan an entire page store once and group candidates by every table ID.
///
/// This never uses a target-table match to choose between candidate pages.
/// Pages with divergent candidate table IDs remain in [`EnterpriseTableStoreScan::table_id_conflicts`].
pub fn scan_enterprise_table_store(
    store: &PageStore,
    transform_key: EnterprisePageTransformKey,
) -> Result<EnterpriseTableStoreScan, EnterpriseTableScanError> {
    let mut result = EnterpriseTableStoreScan {
        table_candidate_groups: BTreeMap::new(),
        table_id_conflicts: Vec::new(),
        census: EnterpriseTableStoreScanCensus::default(),
    };

    for raw_page in store.pages() {
        result.census.raw_pages_scanned += 1;
        let raw_page_number = raw_page.index();
        let candidates = match materialize_enterprise_table_page_candidates_with_key(
            raw_page.bytes(),
            raw_page_number,
            transform_key,
        ) {
            Ok(candidates) => candidates,
            Err(error) => {
                increment_store_skip(&mut result.census, classify_materialization_error(&error));
                continue;
            }
        };

        let mut ids = Vec::with_capacity(candidates.len());
        let mut valid_ids = true;
        for candidate in &candidates {
            match materialized_table_id(candidate.bytes()) {
                Ok(table_id) => ids.push(table_id.get()),
                Err(_) => {
                    valid_ids = false;
                    break;
                }
            }
        }
        if !valid_ids {
            increment_store_skip(
                &mut result.census,
                EnterpriseTableScanSkipReason::InvalidMaterializedTableId,
            );
            continue;
        }
        ids.sort_unstable();
        ids.dedup();
        if ids.len() != 1 {
            result.census.table_id_conflict_pages += 1;
            result.table_id_conflicts.push(EnterpriseTableIdConflict {
                raw_page_number,
                table_ids: ids,
                candidates,
            });
            continue;
        }
        let directory_counts: Vec<_> = candidates
            .iter()
            .enumerate()
            .map(|(candidate_index, candidate)| directory_counts(candidate_index, candidate))
            .collect();
        result.census.table_candidate_pages += candidates.len() as u64;
        for counts in &directory_counts {
            result.census.candidate_accessible_records += u64::from(counts.accessible_records);
            result.census.candidate_missing_records += u64::from(counts.missing_records);
        }
        result
            .table_candidate_groups
            .entry(ids[0])
            .or_default()
            .push(EnterpriseTablePageCandidateGroup {
                raw_page_number,
                candidates,
                directory_counts,
            });
    }
    Ok(result)
}

/// Resolve a table-page candidate group using an independently evidenced decoder.
///
/// This is a convenience wrapper around
/// [`crate::resolve_enterprise_table_page_candidates`]. It makes no use of a
/// page's table ID or directory count to select a candidate.
pub fn resolve_enterprise_table_candidate_group<T, E, F>(
    group: &EnterpriseTablePageCandidateGroup,
    decode: F,
) -> Result<T, EnterpriseCandidateResolutionError>
where
    T: Eq,
    F: FnMut(&EnterpriseMaterializedTablePage) -> Result<T, E>,
{
    resolve_enterprise_table_page_candidates(&group.candidates, decode)
}

fn directory_counts(
    candidate_index: usize,
    candidate: &EnterpriseMaterializedTablePage,
) -> EnterpriseTableDirectoryCounts {
    let page = candidate.table_page();
    let mut accessible_records = 0_u16;
    let mut missing_records = 0_u16;
    for record_id in 0..page.record_count() {
        if page.record(record_id).is_ok() {
            accessible_records += 1;
        } else {
            // Full page validation already establishes that a failed record
            // selector can only be a zero directory slot within range.
            missing_records += 1;
        }
    }
    EnterpriseTableDirectoryCounts {
        candidate_index,
        accessible_records,
        missing_records,
    }
}

fn increment_store_skip(
    census: &mut EnterpriseTableStoreScanCensus,
    reason: EnterpriseTableScanSkipReason,
) {
    *census.skips.entry(reason).or_default() += 1;
}

fn classify_materialization_error(
    error: &EnterprisePageMaterializationError,
) -> EnterpriseTableScanSkipReason {
    match error {
        EnterprisePageMaterializationError::NoHeaderCandidate => {
            EnterpriseTableScanSkipReason::NoHeaderCandidate
        }
        EnterprisePageMaterializationError::AmbiguousHeaderCandidates { .. } => {
            EnterpriseTableScanSkipReason::AmbiguousHeaderCandidates
        }
        EnterprisePageMaterializationError::NotMaterializedTablePage => {
            EnterpriseTableScanSkipReason::NotMaterializedTablePage
        }
        EnterprisePageMaterializationError::InvalidRawPageLength { .. } => {
            EnterpriseTableScanSkipReason::InvalidRawPageLength
        }
        EnterprisePageMaterializationError::PageNumberOutOfRange { .. } => {
            EnterpriseTableScanSkipReason::PageNumberOutOfRange
        }
        EnterprisePageMaterializationError::SectorTransform(_) => {
            EnterpriseTableScanSkipReason::SectorTransform
        }
        // Candidate-returning materialization never invokes this selection
        // error, but retain a stable census category if that implementation
        // changes without widening this scanner's acceptance behavior.
        EnterprisePageMaterializationError::AmbiguousMaterializedPages { .. }
        | EnterprisePageMaterializationError::InsufficientTransformKeyWitnesses { .. }
        | EnterprisePageMaterializationError::ConflictingTransformKeyWitnesses { .. } => {
            EnterpriseTableScanSkipReason::NotMaterializedTablePage
        }
    }
}

/// Input validation failures from [`scan_enterprise_table_pages`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EnterpriseTableScanError {
    /// The requested table identifier was zero.
    #[error("Enterprise table scan requires a nonzero target table ID")]
    ZeroTargetTableId,
}

#[cfg(test)]
mod tests {
    use opensqlany::{MATERIALIZED_TABLE_PAGE_LEN, PageStore, permute_sector_in_place};

    use super::*;

    const HIGH_WORD: u16 = 0x019f;

    fn page(
        page_key: u32,
        table_id: u32,
        slots: &[Option<u16>],
    ) -> [u8; MATERIALIZED_TABLE_PAGE_LEN] {
        let mut page = [0_u8; MATERIALIZED_TABLE_PAGE_LEN];
        page[..4].copy_from_slice(&page_key.to_le_bytes());
        page[0x10] = 4;
        page[0x18..0x1c].copy_from_slice(&table_id.to_le_bytes());
        page[0x16..0x18].copy_from_slice(&(slots.len() as u16).to_le_bytes());
        for (record_id, start) in slots.iter().enumerate() {
            let entry = 0x1c + record_id * 2;
            if let Some(start) = start {
                let offset = usize::from(*start);
                page[entry..entry + 2]
                    .copy_from_slice(&u16::try_from(offset - 0x1c).unwrap().to_le_bytes());
                page[offset..offset + 2].copy_from_slice(&4_u16.to_le_bytes());
                page[offset + 2] = 0x40;
            }
        }
        page
    }

    fn relocate(page: &mut [u8; MATERIALIZED_TABLE_PAGE_LEN]) {
        let trailer: [u8; 12] = page[0xff0..0xffc].try_into().unwrap();
        let header_06: [u8; 6] = page[0x06..0x0c].try_into().unwrap();
        let header_0c: [u8; 4] = page[0x0c..0x10].try_into().unwrap();
        let header_12: [u8; 2] = page[0x12..0x14].try_into().unwrap();
        page[0x06..0x0c].copy_from_slice(&trailer[2..8]);
        page[0x0c..0x10].copy_from_slice(&trailer[8..12]);
        page[0x12..0x14].copy_from_slice(&trailer[0..2]);
        page[0xff0..0xff2].copy_from_slice(&header_12);
        page[0xff2..0xff8].copy_from_slice(&header_06);
        page[0xff8..0xffc].copy_from_slice(&header_0c);
    }

    fn raw(
        mut materialized: [u8; MATERIALIZED_TABLE_PAGE_LEN],
        key: u32,
    ) -> [u8; MATERIALIZED_TABLE_PAGE_LEN] {
        relocate(&mut materialized);
        for sector in 0..8 {
            let start = sector * 512;
            let tail = if sector == 7 { 16 } else { 0 };
            permute_sector_in_place(
                &mut materialized[start..start + 512],
                0,
                tail,
                -(key.wrapping_sub(sector as u32) as i32),
            )
            .unwrap();
        }
        materialized
    }

    #[test]
    fn returns_ordered_target_groups_and_candidate_directory_counts() {
        let target = 3_047;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0; MATERIALIZED_TABLE_PAGE_LEN]);
        bytes.extend_from_slice(&raw(
            page(1, target, &[Some(0x300), None, Some(0x200)]),
            0x019f_5a01,
        ));
        bytes.extend_from_slice(&raw(page(2, 3_042, &[Some(0x300)]), 0x019f_5a02));
        let store = PageStore::from_bytes(bytes).unwrap();
        let all_tables = scan_enterprise_table_store(
            &store,
            EnterprisePageTransformKey::from_high_word(HIGH_WORD),
        )
        .unwrap();
        assert_eq!(all_tables.table_candidate_groups.len(), 2);
        assert_eq!(all_tables.census.table_candidate_pages, 4);
        assert_eq!(all_tables.census.candidate_accessible_records, 6);
        let scan = all_tables.for_table(target).unwrap();
        assert_eq!(scan.candidate_groups.len(), 1);
        assert_eq!(scan.candidate_groups[0].raw_page_number, 1);
        assert_eq!(
            scan.candidate_groups[0].directory_counts,
            vec![
                EnterpriseTableDirectoryCounts {
                    candidate_index: 0,
                    accessible_records: 2,
                    missing_records: 1,
                },
                EnterpriseTableDirectoryCounts {
                    candidate_index: 1,
                    accessible_records: 2,
                    missing_records: 1,
                },
            ]
        );
        // The keyed transform deliberately retained two candidates. The scan
        // reports candidate observations rather than silently deduplicating
        // their directory counts.
        assert_eq!(scan.census.target_candidate_accessible_records, 4);
        assert_eq!(scan.census.target_candidate_missing_records, 2);
        assert_eq!(scan.census.unambiguous_accessible_records, 0);
        assert_eq!(scan.census.non_target_candidate_pages, 2);
        assert_eq!(scan.census.raw_pages_scanned, 3);
        assert_eq!(
            resolve_enterprise_table_candidate_group(&scan.candidate_groups[0], |candidate| Ok::<
                _,
                (),
            >(
                candidate.table_page().record_count()
            )),
            Ok(3)
        );
    }

    #[test]
    fn rejects_zero_target_without_reading_the_store() {
        let store = PageStore::from_bytes(vec![0; MATERIALIZED_TABLE_PAGE_LEN]).unwrap();
        assert_eq!(
            scan_enterprise_table_pages(
                &store,
                EnterprisePageTransformKey::from_high_word(HIGH_WORD),
                0
            ),
            Err(EnterpriseTableScanError::ZeroTargetTableId)
        );
    }
}

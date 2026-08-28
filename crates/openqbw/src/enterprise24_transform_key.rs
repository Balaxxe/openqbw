//! Semantic Enterprise 24 R21 transform-key resolution.
//!
//! Structural page witnesses may identify several file-wide high words. This
//! module never chooses by witness count. It retains only candidates that
//! independently reproduce the supported, cross-attested R21 schema manifest
//! and the required accounting-table page inventory, then requires one unique
//! result.

use std::collections::BTreeSet;

use opensqlany::PageStore;
use thiserror::Error;

use crate::{
    ENTERPRISE24_R21_SCHEMA_MANIFEST, EnterprisePageTransformKey, MATERIALIZED_SYSCOLUMN_TABLE_ID,
    MATERIALIZED_SYSTABLE_TABLE_ID, MaterializedSysColumnCollection,
    MaterializedSysTableCollection, attest_enterprise24_r21_catalog,
    collect_materialized_syscolumns, collect_materialized_systables,
    discover_enterprise_page_transform_key_candidates_in_store, scan_enterprise_table_store,
};

/// One transform key proven by the supported R21 schema-manifest contract.
#[derive(Clone, Debug)]
pub struct Enterprise24R21TransformKeyAttestation {
    transform_key: EnterprisePageTransformKey,
    tables: MaterializedSysTableCollection,
    columns: MaterializedSysColumnCollection,
}

impl Enterprise24R21TransformKeyAttestation {
    /// The uniquely selected file-wide transform key.
    #[must_use]
    pub const fn transform_key(&self) -> EnterprisePageTransformKey {
        self.transform_key
    }

    /// The materialized SYSTABLE catalog used to attest the supported tables.
    #[must_use]
    pub const fn tables(&self) -> &MaterializedSysTableCollection {
        &self.tables
    }

    /// The materialized SYSCOLUMN catalog used to attest the supported schema.
    #[must_use]
    pub const fn columns(&self) -> &MaterializedSysColumnCollection {
        &self.columns
    }

    /// Consume the attestation and return its reusable parts.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        EnterprisePageTransformKey,
        MaterializedSysTableCollection,
        MaterializedSysColumnCollection,
    ) {
        (self.transform_key, self.tables, self.columns)
    }
}

/// Sanitized transform-key resolution failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum Enterprise24R21TransformKeyResolutionError {
    /// Structural discovery did not produce any witnessed candidate.
    #[error("no independently witnessed Enterprise transform-key candidate was available")]
    StructuralDiscoveryFailed,
    /// No structural candidate reproduced the supported semantic schema manifest.
    #[error(
        "none of {structural_candidates} structural transform-key candidates satisfied the Enterprise 24 R21 supported schema-manifest contract"
    )]
    NoSemanticCandidate {
        /// Number of structurally witnessed candidates considered.
        structural_candidates: usize,
    },
    /// Several high words reproduced the full semantic contract, so none was selected.
    #[error(
        "{semantic_candidates} transform-key candidates satisfied the Enterprise 24 R21 supported schema-manifest contract"
    )]
    AmbiguousSemanticCandidates {
        /// Number of semantically valid candidates retained.
        semantic_candidates: usize,
    },
}

/// Resolve one unique R21 transform key by supported-schema attestation.
pub fn discover_enterprise24_r21_transform_key_in_store(
    store: &PageStore,
) -> Result<Enterprise24R21TransformKeyAttestation, Enterprise24R21TransformKeyResolutionError> {
    let structural_candidates =
        discover_enterprise_page_transform_key_candidates_in_store(store)
            .map_err(|_| Enterprise24R21TransformKeyResolutionError::StructuralDiscoveryFailed)?;
    let structural_count = structural_candidates.len();
    let semantic_candidates = structural_candidates
        .into_iter()
        .filter_map(|transform_key| attest_candidate(store, transform_key).ok())
        .collect::<Vec<_>>();
    require_unique_semantic_candidate(structural_count, semantic_candidates)
}

fn attest_candidate(
    store: &PageStore,
    transform_key: EnterprisePageTransformKey,
) -> Result<Enterprise24R21TransformKeyAttestation, CandidateRejection> {
    let tables = collect_materialized_systables(store, transform_key)
        .map_err(|_| CandidateRejection::SysTableCollection)?;
    let mut required_table_ids = ENTERPRISE24_R21_SCHEMA_MANIFEST
        .iter()
        .map(|entry| entry.table_id)
        .collect::<Vec<_>>();
    required_table_ids.extend([
        MATERIALIZED_SYSTABLE_TABLE_ID,
        MATERIALIZED_SYSCOLUMN_TABLE_ID,
    ]);
    let missing_tables = required_table_ids
        .iter()
        .copied()
        .filter(|table_id| tables.table(*table_id).is_none())
        .collect::<Vec<_>>();
    if !missing_tables.is_empty() {
        return Err(CandidateRejection::RequiredTables);
    }
    attest_required_tables(&tables, &required_table_ids)?;

    let syscolumn_table = tables
        .table(MATERIALIZED_SYSCOLUMN_TABLE_ID)
        .ok_or(CandidateRejection::MissingSysColumnTable)?;
    let columns = collect_materialized_syscolumns(store, transform_key)
        .map_err(|_| CandidateRejection::SysColumnCollection)?;
    attest_supported_syscolumn_conflicts(&columns)?;
    let expected_syscolumn_pages = syscolumn_table
        .table_page_count
        .checked_add(syscolumn_table.ext_page_count)
        .ok_or(CandidateRejection::PageCountOverflow)?;
    if columns.carrier_pages < u64::from(expected_syscolumn_pages) {
        return Err(CandidateRejection::SysColumnCrossAttestation);
    }
    attest_enterprise24_r21_catalog(&columns.columns)
        .map_err(|_| CandidateRejection::SchemaManifest)?;

    let scan = scan_enterprise_table_store(store, transform_key)
        .map_err(|_| CandidateRejection::TableScan)?;
    let required = required_table_ids.into_iter().collect::<BTreeSet<_>>();
    if scan
        .table_id_conflicts
        .iter()
        .any(|conflict| conflict.table_ids.iter().any(|id| required.contains(id)))
    {
        return Err(CandidateRejection::RequiredTableIdConflict);
    }
    for manifest in ENTERPRISE24_R21_SCHEMA_MANIFEST {
        let table = tables
            .table(manifest.table_id)
            .ok_or(CandidateRejection::MissingManifestTable)?;
        let expected_pages = table
            .table_page_count
            .checked_add(table.ext_page_count)
            .and_then(|count| usize::try_from(count).ok())
            .ok_or(CandidateRejection::PageCountOverflow)?;
        let observed_pages = scan
            .table_candidate_groups
            .get(&manifest.table_id)
            .map_or(0, Vec::len);
        if observed_pages < expected_pages {
            return Err(CandidateRejection::AccountingPageFloor);
        }
    }

    Ok(Enterprise24R21TransformKeyAttestation {
        transform_key,
        tables,
        columns,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateRejection {
    SysTableCollection,
    RequiredTables,
    RequiredTableAmbiguity,
    MissingSysColumnTable,
    SysColumnCollection,
    SysColumnRequiredConflict,
    SysColumnUnboundedCarrier,
    SysColumnDuplicateRows,
    SysColumnCrossAttestation,
    SchemaManifest,
    TableScan,
    RequiredTableIdConflict,
    MissingManifestTable,
    PageCountOverflow,
    AccountingPageFloor,
}

/// Ensure every table used by semantic selection has one unambiguous,
/// independently declared SYSTABLE expectation. This includes the two catalog
/// carriers as well as every supported application table: accepting an
/// unparsed bounded SYSTABLE record for any of them could otherwise let a
/// conflicting catalog declaration influence transform-key selection.
fn attest_required_tables(
    tables: &MaterializedSysTableCollection,
    required_table_ids: &[u32],
) -> Result<(), CandidateRejection> {
    tables
        .require_unambiguous_tables(required_table_ids)
        .map(|_| ())
        .map_err(|_| CandidateRejection::RequiredTableAmbiguity)
}

/// Reject any unparsed catalog row that could occupy a supported manifest
/// ordinal. Short records are allowed only when they are physically unable to
/// carry the table/column prefix; complete self-bounded rows outside the
/// supported ordinal ranges remain irrelevant to this targeted contract.
fn attest_supported_syscolumn_conflicts(
    columns: &MaterializedSysColumnCollection,
) -> Result<(), CandidateRejection> {
    if columns.unparsed_without_fixed_prefix != 0 {
        return Err(CandidateRejection::SysColumnUnboundedCarrier);
    }
    if columns.columns.len()
        != usize::try_from(columns.carrier_parsed_records).expect("u64 fits supported host")
    {
        return Err(CandidateRejection::SysColumnDuplicateRows);
    }
    for manifest in ENTERPRISE24_R21_SCHEMA_MANIFEST {
        if columns
            .unparsed_fixed_prefix_columns
            .keys()
            .any(|(table_id, column_id)| {
                *table_id == manifest.table_id && (1..=manifest.column_count).contains(column_id)
            })
        {
            return Err(CandidateRejection::SysColumnRequiredConflict);
        }
    }
    Ok(())
}

fn require_unique_semantic_candidate<T>(
    structural_candidates: usize,
    mut semantic_candidates: Vec<T>,
) -> Result<T, Enterprise24R21TransformKeyResolutionError> {
    match semantic_candidates.len() {
        0 => Err(
            Enterprise24R21TransformKeyResolutionError::NoSemanticCandidate {
                structural_candidates,
            },
        ),
        1 => Ok(semantic_candidates.pop().expect("one checked candidate")),
        semantic_candidates => Err(
            Enterprise24R21TransformKeyResolutionError::AmbiguousSemanticCandidates {
                semantic_candidates,
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{
        MaterializedSysColumnSkippedPages, MaterializedSysTableSkippedPages, SysTableEntry,
    };

    fn synthetic_table(table_id: u32) -> SysTableEntry {
        SysTableEntry {
            table_id,
            object_id: u64::from(table_id),
            row_length: 0,
            row_flags: 0,
            dbspace_id: 0,
            row_count: 0,
            creator: 0,
            table_page_count: 0,
            ext_page_count: 0,
            commit_action: 0,
            share_type: 0,
            last_modified_raw: 0,
            name: format!("synthetic_{table_id}"),
            table_type: 0,
            replicate: 0,
            server_type: 0,
            post_name_layout_byte: 0,
            tab_page_list: None,
            ext_page_list: None,
            magic: [0; 4],
            col_count: None,
            data_root_page: None,
            last_page: None,
            data_root_raw: None,
            last_page_raw: None,
            page_number: 0,
            row_offset: 0,
            tag_offset: 0,
            truncated_prefix_bytes: None,
        }
    }

    fn synthetic_tables(required: &[u32]) -> MaterializedSysTableCollection {
        MaterializedSysTableCollection {
            tables: required.iter().copied().map(synthetic_table).collect(),
            carrier_pages: 0,
            carrier_directory_slots: 0,
            carrier_missing_records: 0,
            carrier_parsed_records: 0,
            carrier_unparsed_records: 0,
            unparsed_fixed_prefix_table_ids: BTreeMap::new(),
            unparsed_self_length_fixed_prefix_records: 0,
            unparsed_shorter_than_fixed_prefix_records: 0,
            unparsed_without_fixed_prefix: 0,
            skipped_pages: MaterializedSysTableSkippedPages::default(),
        }
    }

    fn synthetic_columns() -> MaterializedSysColumnCollection {
        MaterializedSysColumnCollection {
            columns: Vec::new(),
            carrier_pages: 0,
            carrier_directory_slots: 0,
            carrier_missing_records: 0,
            carrier_parsed_records: 0,
            carrier_unparsed_records: 0,
            unparsed_fixed_prefix_columns: BTreeMap::new(),
            unparsed_self_length_fixed_prefix_records: 0,
            unparsed_shorter_than_fixed_prefix_records: 0,
            unparsed_without_fixed_prefix: 0,
            skipped_pages: MaterializedSysColumnSkippedPages::default(),
        }
    }

    #[test]
    fn semantic_selection_requires_exactly_one_candidate() {
        assert_eq!(
            require_unique_semantic_candidate::<u8>(3, Vec::new()),
            Err(
                Enterprise24R21TransformKeyResolutionError::NoSemanticCandidate {
                    structural_candidates: 3,
                }
            )
        );
        assert_eq!(require_unique_semantic_candidate(3, vec![7]), Ok(7));
        assert_eq!(
            require_unique_semantic_candidate(3, vec![7, 8]),
            Err(
                Enterprise24R21TransformKeyResolutionError::AmbiguousSemanticCandidates {
                    semantic_candidates: 2,
                }
            )
        );
    }

    #[test]
    fn required_systable_attestation_rejects_unparsed_required_prefix() {
        let required = [
            MATERIALIZED_SYSTABLE_TABLE_ID,
            MATERIALIZED_SYSCOLUMN_TABLE_ID,
            77,
        ];
        let mut tables = synthetic_tables(&required);
        tables.unparsed_fixed_prefix_table_ids.insert(77, 1);

        assert_eq!(
            attest_required_tables(&tables, &required),
            Err(CandidateRejection::RequiredTableAmbiguity)
        );
    }

    #[test]
    fn required_systable_attestation_allows_unparsed_unrelated_prefix() {
        let required = [
            MATERIALIZED_SYSTABLE_TABLE_ID,
            MATERIALIZED_SYSCOLUMN_TABLE_ID,
            77,
        ];
        let mut tables = synthetic_tables(&required);
        tables.unparsed_fixed_prefix_table_ids.insert(88, 1);

        assert_eq!(attest_required_tables(&tables, &required), Ok(()));
    }

    #[test]
    fn supported_syscolumn_attestation_rejects_only_possible_manifest_conflicts() {
        let manifest = ENTERPRISE24_R21_SCHEMA_MANIFEST[0];
        let mut columns = synthetic_columns();
        columns
            .unparsed_fixed_prefix_columns
            .insert((manifest.table_id, 1), 1);
        assert_eq!(
            attest_supported_syscolumn_conflicts(&columns),
            Err(CandidateRejection::SysColumnRequiredConflict)
        );

        columns.unparsed_fixed_prefix_columns.clear();
        columns
            .unparsed_fixed_prefix_columns
            .insert((manifest.table_id, manifest.column_count + 1), 1);
        columns.unparsed_shorter_than_fixed_prefix_records = 1;
        assert_eq!(attest_supported_syscolumn_conflicts(&columns), Ok(()));

        columns.unparsed_without_fixed_prefix = 1;
        assert_eq!(
            attest_supported_syscolumn_conflicts(&columns),
            Err(CandidateRejection::SysColumnUnboundedCarrier)
        );
    }

    #[test]
    fn supported_syscolumn_attestation_rejects_duplicate_parsed_rows() {
        let mut columns = synthetic_columns();
        columns.carrier_parsed_records = 1;
        assert_eq!(
            attest_supported_syscolumn_conflicts(&columns),
            Err(CandidateRejection::SysColumnDuplicateRows)
        );
    }
}

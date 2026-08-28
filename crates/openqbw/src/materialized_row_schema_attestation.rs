//! Fail-closed row-storage attestation for complete materialized table schemas.
//!
//! `SYSCOLUMN` identifies a table's logical columns, but it does not by
//! itself establish every physical choice needed by the SQL Anywhere row
//! decoder.  This module turns a *complete* catalog and a *complete bounded
//! row corpus into evidence: it tries only the finite layouts supported by
//! the decoder and accepts a layout only when every supplied physical row is
//! decoded exactly.  It deliberately does not infer compression, overflow
//! pointer widths, or a catalog prefix from a successful subset.

use std::collections::BTreeSet;

use opensqlany::{
    BooleanTailLayout, ColumnType, DecodedRow, EnumLayout, MaterializedRowRecord,
    NullBitmapCoverage, NullBitmapLayout, NumericLayout, RowPrefixLayout, RowSchema,
    VariableLengthLayout, VariableOverflowLayout, decode_row_exact,
};
use thiserror::Error;

use crate::{
    CatalogCoverageAttestation, CatalogDefaultAttestation, CatalogDefaultEnvelope,
    EnterpriseMaterializedTablePage, EnterpriseTablePageCandidateGroup, EnterpriseTableScan,
    RowStorageAttestation, SchemaAdapterError, SysColumn, adapt_complete_schema,
};

/// Caller-attested coverage of all bounded materialized records for one table.
///
/// The count must be obtained from the materialized page/record census rather
/// than from rows which happened to decode.  This makes a missing carrier row
/// an error before layout selection can begin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaterializedRowCoverageAttestation {
    table_id: u32,
    record_count: u64,
}

impl MaterializedRowCoverageAttestation {
    /// Create an attestation for one nonzero physical table id and row count.
    pub fn new(
        table_id: u32,
        record_count: u64,
    ) -> Result<Self, MaterializedRowSchemaAttestationError> {
        if table_id == 0 {
            return Err(MaterializedRowSchemaAttestationError::ZeroTableId);
        }
        Ok(Self {
            table_id,
            record_count,
        })
    }

    /// The physical table id covered by this attestation.
    pub const fn table_id(self) -> u32 {
        self.table_id
    }

    /// Exact number of bounded records established by the carrier census.
    pub const fn record_count(self) -> u64 {
        self.record_count
    }
}

/// A candidate layout rejected because at least one bounded row did not decode
/// with complete consumption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedRowStorageLayout {
    /// The finite physical layout that was attempted.
    pub storage: RowStorageAttestation,
    /// Zero-based indexes in the supplied complete row corpus that failed.
    ///
    /// This intentionally retains only corpus coordinates, never application
    /// row bytes or identifying content.
    pub unparsed_row_indexes: Vec<usize>,
}

/// A complete row schema accepted from an exact materialized row corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedMaterializedRowSchema {
    /// Physical table id shared by catalog and record coverage attestations.
    pub table_id: u32,
    /// Number of exact `SYSCOLUMN` rows used to construct [`Self::schema`].
    pub catalog_column_count: u32,
    /// Number of bounded records independently counted in the carrier.
    pub attested_record_count: u64,
    /// Number of bounded records supplied to and exactly decoded by this run.
    pub decoded_record_count: u64,
    /// The unique storage facts selected by the full corpus.
    pub row_storage: RowStorageAttestation,
    /// Typed schema built using the exact catalog-default envelopes.
    pub schema: RowSchema,
}

/// Independent complete-coverage facts for a table-wide candidate scan.
///
/// `logical_row_count` excludes missing directory slots and reference rows:
/// neither is a self-contained direct row available to [`decode_row_exact`]. Both
/// remain visible in the returned resolution rather than being folded into a
/// successful logical-row total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaterializedTableCoverageAttestation {
    table_id: u32,
    logical_page_count: u64,
    logical_row_count: u64,
}

impl MaterializedTableCoverageAttestation {
    /// Create coverage facts established independently of layout selection.
    pub fn new(
        table_id: u32,
        logical_page_count: u64,
        logical_row_count: u64,
    ) -> Result<Self, MaterializedRowSchemaAttestationError> {
        if table_id == 0 {
            return Err(MaterializedRowSchemaAttestationError::ZeroTableId);
        }
        Ok(Self {
            table_id,
            logical_page_count,
            logical_row_count,
        })
    }

    /// Physical table id covered by this attestation.
    pub const fn table_id(self) -> u32 {
        self.table_id
    }

    /// Number of target raw-page candidate groups expected for this table.
    pub const fn logical_page_count(self) -> u64 {
        self.logical_page_count
    }

    /// Number of self-contained, non-reference rows expected for this table.
    pub const fn logical_row_count(self) -> u64 {
        self.logical_row_count
    }
}

/// One exactly decoded self-contained row selected from a page candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMaterializedTableRow {
    /// Page-local directory record identifier.
    pub record_id: u16,
    /// Complete typed row decoded from the bounded physical record.
    pub decoded: DecodedRow,
}

/// One candidate group resolved by an attested schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMaterializedTablePage {
    /// Raw physical QBW page number.
    pub raw_page_number: u64,
    /// Exactly decoded self-contained rows, ordered by directory id.
    pub rows: Vec<ResolvedMaterializedTableRow>,
    /// Zero directory slots explicitly observed on the selected candidate.
    pub missing_record_ids: Vec<u16>,
    /// Directory rows marked as SA row-reference artifacts.
    ///
    /// They are not followed and do not count as logical rows.
    pub reference_record_ids: Vec<u16>,
}

/// Result of attesting a schema while resolving every scanned page candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedAndResolvedMaterializedTableSchema {
    /// Full-corpus row schema and storage facts.
    pub attested_schema: AttestedMaterializedRowSchema,
    /// Every target page group resolved by that exact schema.
    pub pages: Vec<ResolvedMaterializedTablePage>,
    /// Missing directory slots across selected target pages.
    pub missing_record_count: u64,
    /// SA row-reference artifacts across selected target pages.
    pub reference_artifact_count: u64,
}

/// A storage layout rejected during table-wide candidate resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedTableRowStorageLayout {
    /// Layout attempted against every candidate of every target page group.
    pub storage: RowStorageAttestation,
    /// Raw target page groups for which no candidate decoded or candidate
    /// outcomes disagreed.
    pub unresolved_raw_page_numbers: Vec<u64>,
    /// Resolved self-contained row count, when every group resolved.
    pub resolved_logical_row_count: Option<u64>,
}

/// Attest one complete row schema and resolve every target-table candidate
/// group in an [`EnterpriseTableScan`].
///
/// This is the table-wide counterpart to [`attest_materialized_row_schema`].
/// It never calibrates on the scan's unambiguous groups alone: every finite
/// storage layout is run against every candidate in every group.  A group is
/// selected only when exactly one candidate succeeds, or all successful
/// candidate outcomes are equal.  Missing slots and row-reference artifacts
/// are retained explicitly and are excluded from the independently attested
/// self-contained logical-row count.
pub fn attest_and_resolve_materialized_table_schema(
    columns: &[SysColumn],
    catalog_coverage: CatalogCoverageAttestation,
    scan: &EnterpriseTableScan,
    table_coverage: MaterializedTableCoverageAttestation,
    tested_overflow_pointer_widths: &[u8],
) -> Result<AttestedAndResolvedMaterializedTableSchema, MaterializedRowSchemaAttestationError> {
    if catalog_coverage.table_id() != table_coverage.table_id()
        || scan.target_table_id != table_coverage.table_id()
    {
        return Err(
            MaterializedRowSchemaAttestationError::TableCoverageIdMismatch {
                catalog_table_id: catalog_coverage.table_id(),
                scan_table_id: scan.target_table_id,
                coverage_table_id: table_coverage.table_id(),
            },
        );
    }
    let target_conflicts: Vec<u64> = scan
        .table_id_conflicts
        .iter()
        .filter(|conflict| {
            conflict
                .table_ids
                .binary_search(&scan.target_table_id)
                .is_ok()
        })
        .map(|conflict| conflict.raw_page_number)
        .collect();
    if !target_conflicts.is_empty() {
        return Err(
            MaterializedRowSchemaAttestationError::TargetTableIdConflicts {
                table_id: scan.target_table_id,
                raw_page_numbers: target_conflicts,
            },
        );
    }
    let scanned_pages = u64::try_from(scan.candidate_groups.len()).expect("usize always fits u64");
    if scanned_pages != table_coverage.logical_page_count() {
        return Err(
            MaterializedRowSchemaAttestationError::TablePageCoverageCountMismatch {
                table_id: scan.target_table_id,
                attested: table_coverage.logical_page_count(),
                scanned: scanned_pages,
            },
        );
    }
    if scan.candidate_groups.is_empty() {
        return Err(MaterializedRowSchemaAttestationError::EmptyTableCorpus {
            table_id: scan.target_table_id,
        });
    }

    let default_envelopes = exact_default_envelopes(columns);
    let defaults = CatalogDefaultAttestation {
        envelopes: &default_envelopes,
    };
    let layouts = supported_storage_layouts(columns, tested_overflow_pointer_widths)?;
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for storage in layouts {
        let schema = adapt_complete_schema(columns, catalog_coverage, storage, defaults)?;
        let mut pages = Vec::with_capacity(scan.candidate_groups.len());
        let mut unresolved_raw_page_numbers = Vec::new();
        for group in &scan.candidate_groups {
            match resolve_group_with_schema(group, &schema) {
                Some(page) => pages.push(page),
                None => unresolved_raw_page_numbers.push(group.raw_page_number),
            }
        }
        if !unresolved_raw_page_numbers.is_empty() {
            rejected.push(RejectedTableRowStorageLayout {
                storage,
                unresolved_raw_page_numbers,
                resolved_logical_row_count: None,
            });
            continue;
        }
        let logical_rows = pages.iter().map(|page| page.rows.len() as u64).sum();
        if logical_rows != table_coverage.logical_row_count() {
            rejected.push(RejectedTableRowStorageLayout {
                storage,
                unresolved_raw_page_numbers: Vec::new(),
                resolved_logical_row_count: Some(logical_rows),
            });
            continue;
        }
        accepted.push((storage, schema, pages));
    }
    match accepted.len() {
        0 => Err(
            MaterializedRowSchemaAttestationError::NoTableLayoutMatched {
                table_id: scan.target_table_id,
                expected_logical_row_count: table_coverage.logical_row_count(),
                rejected,
            },
        ),
        1 => {
            let (row_storage, schema, pages) = accepted.pop().expect("length checked");
            let missing_record_count = pages
                .iter()
                .map(|page| page.missing_record_ids.len() as u64)
                .sum();
            let reference_artifact_count = pages
                .iter()
                .map(|page| page.reference_record_ids.len() as u64)
                .sum();
            Ok(AttestedAndResolvedMaterializedTableSchema {
                attested_schema: AttestedMaterializedRowSchema {
                    table_id: scan.target_table_id,
                    catalog_column_count: catalog_coverage.column_count(),
                    attested_record_count: table_coverage.logical_row_count(),
                    decoded_record_count: table_coverage.logical_row_count(),
                    row_storage,
                    schema,
                },
                pages,
                missing_record_count,
                reference_artifact_count,
            })
        }
        _ => Err(
            MaterializedRowSchemaAttestationError::AmbiguousTableLayouts {
                table_id: scan.target_table_id,
                layouts: accepted
                    .into_iter()
                    .map(|(storage, _, _)| storage)
                    .collect(),
            },
        ),
    }
}

fn resolve_group_with_schema(
    group: &EnterpriseTablePageCandidateGroup,
    schema: &RowSchema,
) -> Option<ResolvedMaterializedTablePage> {
    let successful: Vec<_> = group
        .candidates
        .iter()
        .filter_map(|candidate| decode_candidate_page(candidate, group.raw_page_number, schema))
        .collect();
    let first = successful.first()?.clone();
    if successful.iter().skip(1).any(|page| page != &first) {
        return None;
    }
    Some(first)
}

fn decode_candidate_page(
    candidate: &EnterpriseMaterializedTablePage,
    raw_page_number: u64,
    schema: &RowSchema,
) -> Option<ResolvedMaterializedTablePage> {
    let page = candidate.table_page();
    let mut rows = Vec::new();
    let mut missing_record_ids = Vec::new();
    let reference_record_ids = Vec::new();
    for record_id in 0..page.record_count() {
        let record = match page.record(record_id) {
            Ok(record) => record,
            Err(_) => {
                missing_record_ids.push(record_id);
                continue;
            }
        };
        let decoded = decode_row_exact(record.bytes(), schema).ok()?;
        rows.push(ResolvedMaterializedTableRow { record_id, decoded });
    }
    Some(ResolvedMaterializedTablePage {
        raw_page_number,
        rows,
        missing_record_ids,
        reference_record_ids,
    })
}

/// Attest a complete materialized row schema from exact catalog and row facts.
///
/// `catalog_coverage` and `row_coverage` are independent completeness
/// statements.  The function verifies their table ids and counts before
/// decoding.  `tested_overflow_pointer_widths` may contain only widths which
/// were independently tested for this table; zero is rejected.  Unsupported
/// overflow is always tried as the conservative baseline.
///
/// Numeric columns are always decoded as `EnterpriseMaterializedRaw`.  Enum
/// scalar decoding is enabled only if domain 19 is present.  Boolean storage
/// layouts are varied only when Boolean columns are present; otherwise their
/// choice is observationally irrelevant and is canonicalized to `Bytes`.  The same
/// canonicalization avoids artificial ambiguity for overflow choices when the
/// table has no variable columns.
pub fn attest_materialized_row_schema(
    columns: &[SysColumn],
    catalog_coverage: CatalogCoverageAttestation,
    rows: &[MaterializedRowRecord<'_>],
    row_coverage: MaterializedRowCoverageAttestation,
    tested_overflow_pointer_widths: &[u8],
) -> Result<AttestedMaterializedRowSchema, MaterializedRowSchemaAttestationError> {
    if catalog_coverage.table_id() != row_coverage.table_id() {
        return Err(
            MaterializedRowSchemaAttestationError::CoverageTableMismatch {
                catalog_table_id: catalog_coverage.table_id(),
                row_table_id: row_coverage.table_id(),
            },
        );
    }
    let supplied = u64::try_from(rows.len()).expect("usize always fits u64");
    if supplied != row_coverage.record_count() {
        return Err(
            MaterializedRowSchemaAttestationError::RowCoverageCountMismatch {
                table_id: row_coverage.table_id(),
                attested: row_coverage.record_count(),
                supplied,
            },
        );
    }
    if rows.is_empty() {
        return Err(MaterializedRowSchemaAttestationError::EmptyRowCorpus {
            table_id: row_coverage.table_id(),
        });
    }

    let default_envelopes = exact_default_envelopes(columns);
    let defaults = CatalogDefaultAttestation {
        envelopes: &default_envelopes,
    };

    let layouts = supported_storage_layouts(columns, tested_overflow_pointer_widths)?;

    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for storage in layouts {
        let schema = match adapt_complete_schema(columns, catalog_coverage, storage, defaults) {
            Ok(schema) => schema,
            Err(error) => {
                return Err(MaterializedRowSchemaAttestationError::Schema(error));
            }
        };
        let unparsed_row_indexes = rows
            .iter()
            .enumerate()
            .filter_map(|(index, record)| {
                decode_row_exact(record.bytes(), &schema)
                    .err()
                    .map(|_| index)
            })
            .collect::<Vec<_>>();
        if unparsed_row_indexes.is_empty() {
            accepted.push((storage, schema));
        } else {
            rejected.push(RejectedRowStorageLayout {
                storage,
                unparsed_row_indexes,
            });
        }
    }

    match accepted.len() {
        0 => Err(MaterializedRowSchemaAttestationError::NoLayoutMatched {
            table_id: row_coverage.table_id(),
            rejected,
        }),
        1 => {
            let (row_storage, schema) = accepted.pop().expect("length checked");
            Ok(AttestedMaterializedRowSchema {
                table_id: row_coverage.table_id(),
                catalog_column_count: catalog_coverage.column_count(),
                attested_record_count: row_coverage.record_count(),
                decoded_record_count: supplied,
                row_storage,
                schema,
            })
        }
        _ => Err(MaterializedRowSchemaAttestationError::AmbiguousLayouts {
            table_id: row_coverage.table_id(),
            layouts: accepted.into_iter().map(|(storage, _)| storage).collect(),
        }),
    }
}

fn exact_default_envelopes(columns: &[SysColumn]) -> Vec<CatalogDefaultEnvelope<'_>> {
    columns
        .iter()
        .filter(|column| column.row_flags != 0 || !column.post_name_bytes.is_empty())
        .map(|column| CatalogDefaultEnvelope {
            column_id: column.column_id,
            row_flags: column.row_flags,
            post_name_bytes: &column.post_name_bytes,
        })
        .collect()
}

fn supported_storage_layouts(
    columns: &[SysColumn],
    tested_overflow_pointer_widths: &[u8],
) -> Result<Vec<RowStorageAttestation>, MaterializedRowSchemaAttestationError> {
    let has_boolean = columns
        .iter()
        .any(|column| ColumnType::from_domain_id(column.domain_id) == Some(ColumnType::Boolean));
    let has_enum = columns
        .iter()
        .any(|column| ColumnType::from_domain_id(column.domain_id) == Some(ColumnType::Enum));
    let has_variable = columns.iter().any(|column| {
        matches!(
            ColumnType::from_domain_id(column.domain_id),
            Some(ColumnType::Char | ColumnType::Char2 | ColumnType::Text | ColumnType::Text2)
        )
    });
    let has_nullable = columns.iter().any(|column| column.nulls == b'Y');
    let boolean_layouts: &[BooleanTailLayout] = if has_boolean {
        &[
            BooleanTailLayout::InlineBytes,
            BooleanTailLayout::InlinePackedRunsMsbFirst,
            BooleanTailLayout::InlinePackedRunsLsbFirst,
            BooleanTailLayout::Bytes,
            BooleanTailLayout::PackedMsbFirst,
        ]
    } else {
        &[BooleanTailLayout::Bytes]
    };
    let enum_layouts: &[EnumLayout] = if has_enum {
        &[EnumLayout::FixedWidthUnsigned]
    } else {
        &[EnumLayout::Unsupported]
    };
    let overflow_layouts = overflow_layouts(has_variable, tested_overflow_pointer_widths)?;
    let null_bitmap_layouts: &[NullBitmapLayout] = if has_nullable {
        &[
            NullBitmapLayout::MsbPresent,
            NullBitmapLayout::LsbPresent,
            NullBitmapLayout::MsbNull,
            NullBitmapLayout::LsbNull,
        ]
    } else {
        &[NullBitmapLayout::MsbPresent]
    };
    let null_bitmap_coverages: &[NullBitmapCoverage] = if has_nullable {
        &[
            NullBitmapCoverage::NullableColumns,
            NullBitmapCoverage::AllColumns,
        ]
    } else {
        &[NullBitmapCoverage::NullableColumns]
    };
    let row_prefix_layouts = [
        RowPrefixLayout::None,
        RowPrefixLayout::OneByteCarrier,
        RowPrefixLayout::TwoByteCarrier,
        RowPrefixLayout::ThreeByteCarrier,
    ];
    let variable_length_layouts: &[VariableLengthLayout] = if has_variable {
        &[
            VariableLengthLayout::U8,
            VariableLengthLayout::U16Le,
            VariableLengthLayout::DeclaredWidth {
                wide_at_or_above: 255,
            },
            VariableLengthLayout::DeclaredWidth {
                wide_at_or_above: 256,
            },
            VariableLengthLayout::DeclaredWidth {
                wide_at_or_above: 512,
            },
            VariableLengthLayout::DeclaredWidth {
                wide_at_or_above: 4096,
            },
        ]
    } else {
        &[VariableLengthLayout::U8]
    };
    let mut out = Vec::new();
    for &boolean_tail in boolean_layouts {
        for &enum_layout in enum_layouts {
            for &variable_overflow_layout in &overflow_layouts {
                for &null_bitmap_layout in null_bitmap_layouts {
                    for &null_bitmap_coverage in null_bitmap_coverages {
                        for row_prefix_layout in row_prefix_layouts {
                            for &variable_length_layout in variable_length_layouts {
                                out.push(RowStorageAttestation {
                                    uncompressed: true,
                                    boolean_tail,
                                    numeric_layout: NumericLayout::EnterpriseMaterializedRaw,
                                    enum_layout,
                                    variable_overflow_layout,
                                    variable_length_layout,
                                    null_bitmap_layout,
                                    null_bitmap_coverage,
                                    row_prefix_layout,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

fn overflow_layouts(
    has_variable: bool,
    tested_widths: &[u8],
) -> Result<Vec<VariableOverflowLayout>, MaterializedRowSchemaAttestationError> {
    if !has_variable {
        return Ok(vec![VariableOverflowLayout::Unsupported]);
    }
    let mut unique = BTreeSet::new();
    for &width in tested_widths {
        if width == 0 {
            return Err(MaterializedRowSchemaAttestationError::ZeroOverflowPointerWidth);
        }
        unique.insert(width);
    }
    let mut layouts = vec![VariableOverflowLayout::Unsupported];
    layouts.extend(
        unique
            .into_iter()
            .map(|width| VariableOverflowLayout::Pointer { width }),
    );
    Ok(layouts)
}

/// Reasons a full-corpus materialized row schema cannot be attested.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MaterializedRowSchemaAttestationError {
    /// The row coverage used table id zero.
    #[error("materialized-row coverage attestation has table id zero")]
    ZeroTableId,
    /// Catalog and row corpus asserted different physical table ids.
    #[error("catalog table {catalog_table_id} does not match row table {row_table_id}")]
    CoverageTableMismatch {
        /// Physical table id asserted by the catalog coverage.
        catalog_table_id: u32,
        /// Physical table id asserted by the row coverage.
        row_table_id: u32,
    },
    /// Catalog, scan, and expected table coverage identified different tables.
    #[error(
        "catalog table {catalog_table_id}, scan table {scan_table_id}, and coverage table {coverage_table_id} do not agree"
    )]
    TableCoverageIdMismatch {
        /// Catalog coverage table id.
        catalog_table_id: u32,
        /// Scan target table id.
        scan_table_id: u32,
        /// Table coverage table id.
        coverage_table_id: u32,
    },
    /// A raw page had candidate materializations for the target and another table.
    #[error("table {table_id}: target-table identity conflicts on {raw_page_numbers:?}")]
    TargetTableIdConflicts {
        /// Target table id.
        table_id: u32,
        /// Raw physical pages whose candidates included the target and another table.
        raw_page_numbers: Vec<u64>,
    },
    /// Target candidate groups did not equal independently expected pages.
    #[error("table {table_id}: scanned {scanned} target pages, attested {attested}")]
    TablePageCoverageCountMismatch {
        /// Target table id.
        table_id: u32,
        /// Expected target page groups.
        attested: u64,
        /// Retained target page groups.
        scanned: u64,
    },
    /// No target page groups were available for a schema attestation.
    #[error("table {table_id}: cannot attest schema from an empty table scan")]
    EmptyTableCorpus {
        /// Target table id.
        table_id: u32,
    },
    /// The complete record corpus count did not match its independent census.
    #[error("table {table_id}: supplied {supplied} records, attested {attested}")]
    RowCoverageCountMismatch {
        /// Physical table id.
        table_id: u32,
        /// Independently attested complete corpus count.
        attested: u64,
        /// Bounded records supplied to this call.
        supplied: u64,
    },
    /// No bounded rows were supplied, so storage cannot be evidenced.
    #[error("table {table_id}: cannot attest row storage from an empty corpus")]
    EmptyRowCorpus {
        /// Physical table id.
        table_id: u32,
    },
    /// A caller supplied the nonsensical zero-byte overflow-pointer option.
    #[error("overflow pointer widths must be nonzero")]
    ZeroOverflowPointerWidth,
    /// Exact catalog rows could not be adapted into a typed schema.
    #[error(transparent)]
    Schema(#[from] SchemaAdapterError),
    /// Every finite supported layout left one or more rows unparsed.
    #[error("table {table_id}: no supported row-storage layout decoded every bounded row")]
    NoLayoutMatched {
        /// Physical table id.
        table_id: u32,
        /// Every attempted layout and its non-decoding corpus coordinates.
        rejected: Vec<RejectedRowStorageLayout>,
    },
    /// Every supported layout failed a page-group or expected-row coverage gate.
    #[error("table {table_id}: no supported layout resolved the complete table corpus")]
    NoTableLayoutMatched {
        /// Target table id.
        table_id: u32,
        /// Expected self-contained logical rows.
        expected_logical_row_count: u64,
        /// Results for every finite attempted layout.
        rejected: Vec<RejectedTableRowStorageLayout>,
    },
    /// More than one materially different supported layout decoded every row.
    #[error("table {table_id}: multiple supported row-storage layouts decoded every bounded row")]
    AmbiguousLayouts {
        /// Physical table id.
        table_id: u32,
        /// All full-corpus layouts; a caller must add non-circular evidence.
        layouts: Vec<RowStorageAttestation>,
    },
    /// More than one supported layout resolved every candidate group and count.
    #[error("table {table_id}: multiple supported layouts resolved the complete table corpus")]
    AmbiguousTableLayouts {
        /// Target table id.
        table_id: u32,
        /// Layouts with complete candidate-group resolution.
        layouts: Vec<RowStorageAttestation>,
    },
}

#[cfg(test)]
mod tests {
    use opensqlany::{
        MATERIALIZED_TABLE_PAGE_LEN, MaterializedTablePage, PageStore, permute_sector_in_place,
    };

    use super::*;
    use crate::{EnterprisePageTransformKey, scan_enterprise_table_pages};

    fn column(id: u32, domain_id: u16, width: u32) -> SysColumn {
        SysColumn {
            name: format!("c_{id}"),
            table_id: 9001,
            column_id: id,
            domain_id,
            marker: 1,
            nulls: b'N',
            width,
            scale: 0,
            object_id: 0,
            max_identity: 0,
            post_name_bytes: vec![],
            row_length: 0,
            row_flags: 0,
            page_number: 0,
            trailer_page_type_raw: None,
            row_offset: 0,
            tag_offset: 0,
        }
    }

    fn record_page(row: &[u8]) -> [u8; 4096] {
        let mut page = [0_u8; 4096];
        page[0x10] = 4;
        page[0x16..0x18].copy_from_slice(&1_u16.to_le_bytes());
        let offset = 100_usize;
        page[0x1c..0x1e].copy_from_slice(&u16::try_from(offset - 0x1c).unwrap().to_le_bytes());
        page[offset..offset + row.len()].copy_from_slice(row);
        page
    }

    fn row(payload: &[u8]) -> Vec<u8> {
        let mut row = u16::try_from(payload.len() + 3)
            .unwrap()
            .to_le_bytes()
            .to_vec();
        row.push(0);
        row.extend_from_slice(payload);
        row
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

    fn raw_page(
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

    fn scanned_page_with_missing_and_reference() -> EnterpriseTableScan {
        let mut materialized = [0_u8; MATERIALIZED_TABLE_PAGE_LEN];
        materialized[..4].copy_from_slice(&1_u32.to_le_bytes());
        materialized[0x10] = 4;
        materialized[0x18..0x1c].copy_from_slice(&9001_u32.to_le_bytes());
        materialized[0x16..0x18].copy_from_slice(&3_u16.to_le_bytes());
        // The checked materialized directory stores records in descending
        // physical offsets as in a real page allocation.
        let first = 0x300_usize;
        let third = 0x200_usize;
        materialized[0x1c..0x1e]
            .copy_from_slice(&u16::try_from(first - 0x1c).unwrap().to_le_bytes());
        materialized[0x20..0x22]
            .copy_from_slice(&u16::try_from(third - 0x1c).unwrap().to_le_bytes());
        materialized[first..first + 5].copy_from_slice(&[5, 0, 0, 9, 0]);
        materialized[third..third + 5].copy_from_slice(&[5, 0, 0, 9, 0]);
        let mut source = vec![0_u8; MATERIALIZED_TABLE_PAGE_LEN];
        source.extend_from_slice(&raw_page(materialized, 0x019f_5a01));
        scan_enterprise_table_pages(
            &PageStore::from_bytes(source).unwrap(),
            EnterprisePageTransformKey::from_high_word(0x019f),
            9001,
        )
        .unwrap()
    }

    #[test]
    fn full_corpus_selects_byte_boolean_tail_and_enterprise_numeric() {
        let columns = vec![
            column(1, 2, 4),
            column(2, 24, 0),
            column(3, 3, 20),
            column(4, 24, 0),
        ];
        // The first Boolean's byte is physically occupied by the numeric
        // length under the sidecar layout.  It is a canonical Boolean value
        // only if the inline grammar is assumed, but that assumption then
        // makes the following numeric marker invalid.  This fixture therefore
        // supplies discriminating evidence instead of selecting between two
        // grammars merely because both can consume a Boolean suffix.
        let page = record_page(&row(&[7, 0, 0, 0, 1, 0xbf, 5, 1, 0]));
        let parsed = MaterializedTablePage::parse(&page).unwrap();
        let rows = [parsed.record(0).unwrap()];
        let result = attest_materialized_row_schema(
            &columns,
            CatalogCoverageAttestation::new(9001, 4).unwrap(),
            &rows,
            MaterializedRowCoverageAttestation::new(9001, 1).unwrap(),
            &[],
        )
        .unwrap();
        assert_eq!(result.decoded_record_count, 1);
        assert_eq!(result.row_storage.boolean_tail, BooleanTailLayout::Bytes);
        assert_eq!(
            result.row_storage.numeric_layout,
            NumericLayout::EnterpriseMaterializedRaw
        );
    }

    #[test]
    fn overflow_pointer_width_is_not_selected_when_other_layouts_are_equivalent() {
        let columns = vec![column(1, 10, 0), column(2, 2, 2)];
        let page = record_page(&row(&[0xff, 1, 2, 3, 4, 9, 0]));
        let parsed = MaterializedTablePage::parse(&page).unwrap();
        let rows = [parsed.record(0).unwrap()];
        assert!(matches!(
            attest_materialized_row_schema(
                &columns,
                CatalogCoverageAttestation::new(9001, 2).unwrap(),
                &rows,
                MaterializedRowCoverageAttestation::new(9001, 1).unwrap(),
                &[4],
            ),
            Err(MaterializedRowSchemaAttestationError::AmbiguousLayouts { .. })
        ));
    }

    #[test]
    fn fails_closed_when_no_layout_consumes_every_record() {
        let columns = vec![column(1, 10, 0)];
        let page = record_page(&row(&[0xff]));
        let parsed = MaterializedTablePage::parse(&page).unwrap();
        let rows = [parsed.record(0).unwrap()];
        assert!(matches!(
            attest_materialized_row_schema(
                &columns,
                CatalogCoverageAttestation::new(9001, 1).unwrap(),
                &rows,
                MaterializedRowCoverageAttestation::new(9001, 1).unwrap(),
                &[],
            ),
            Err(MaterializedRowSchemaAttestationError::NoLayoutMatched { .. })
        ));
    }

    #[test]
    fn coverage_count_is_not_inferred_from_the_decodable_subset() {
        let columns = vec![column(1, 2, 2)];
        let page = record_page(&row(&[9, 0]));
        let parsed = MaterializedTablePage::parse(&page).unwrap();
        let rows = [parsed.record(0).unwrap()];
        assert!(matches!(
            attest_materialized_row_schema(
                &columns,
                CatalogCoverageAttestation::new(9001, 1).unwrap(),
                &rows,
                MaterializedRowCoverageAttestation::new(9001, 2).unwrap(),
                &[],
            ),
            Err(MaterializedRowSchemaAttestationError::RowCoverageCountMismatch { .. })
        ));
    }

    #[test]
    fn equivalent_overflow_options_are_reported_as_ambiguous_without_a_witness() {
        let columns = vec![column(1, 10, 0)];
        // No overflow marker appears in this corpus, so a separately tested
        // pointer width has no non-circular on-row witness distinguishing it
        // from the conservative unsupported layout.
        let page = record_page(&row(&[1, b'x']));
        let parsed = MaterializedTablePage::parse(&page).unwrap();
        let rows = [parsed.record(0).unwrap()];
        assert!(matches!(
            attest_materialized_row_schema(
                &columns,
                CatalogCoverageAttestation::new(9001, 1).unwrap(),
                &rows,
                MaterializedRowCoverageAttestation::new(9001, 1).unwrap(),
                &[4],
            ),
            Err(MaterializedRowSchemaAttestationError::AmbiguousLayouts { .. })
        ));
    }

    #[test]
    fn exact_catalog_default_envelope_is_preserved_when_building_schema() {
        let mut columns = vec![column(1, 2, 2)];
        columns[0].row_flags = 0x80;
        columns[0].post_name_bytes = vec![0x02, b'D', b'F'];
        let page = record_page(&row(&[9, 0]));
        let parsed = MaterializedTablePage::parse(&page).unwrap();
        let rows = [parsed.record(0).unwrap()];
        assert!(
            attest_materialized_row_schema(
                &columns,
                CatalogCoverageAttestation::new(9001, 1).unwrap(),
                &rows,
                MaterializedRowCoverageAttestation::new(9001, 1).unwrap(),
                &[],
            )
            .is_ok()
        );
    }

    #[test]
    fn table_scan_attestation_resolves_all_groups_and_accounts_for_artifacts() {
        let result = attest_and_resolve_materialized_table_schema(
            &[column(1, 2, 2)],
            CatalogCoverageAttestation::new(9001, 1).unwrap(),
            &scanned_page_with_missing_and_reference(),
            MaterializedTableCoverageAttestation::new(9001, 1, 2).unwrap(),
            &[],
        )
        .unwrap();
        assert_eq!(result.pages.len(), 1);
        assert_eq!(result.pages[0].rows.len(), 2);
        assert_eq!(result.missing_record_count, 1);
        assert_eq!(result.reference_artifact_count, 0);
    }
}

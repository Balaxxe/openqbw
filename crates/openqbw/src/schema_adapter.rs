//! Conservative adapter from recovered catalog columns to typed row schemas.
//!
//! This module bridges only catalog metadata.  It does **not** establish the
//! physical Enterprise 24 application-row grammar, row ownership, overflow
//! handling, current-state semantics, or a decoder for any QBW user table.
//! Callers may construct a [`opensqlany::RowSchema`] here only after supplying
//! explicit evidence that the catalog recovery is complete and that the row
//! storage is uncompressed.

use opensqlany::{
    BooleanTailLayout, ColumnDef, ColumnType, EnumLayout, NullBitmapCoverage, NullBitmapLayout,
    NumericLayout, RowPrefixLayout, RowSchema, VariableLengthLayout, VariableOverflowLayout,
};
use thiserror::Error;

use crate::SysColumn;

/// Caller-supplied evidence for a complete recovered table catalog.
///
/// This is deliberately not inferred from a partial vector of recovered rows:
/// the expected number must come from an independent, table-specific catalog
/// audit.  It prevents a prefix of columns from being silently used as a row
/// schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogCoverageAttestation {
    table_id: u32,
    column_count: u32,
}

impl CatalogCoverageAttestation {
    /// Records the independently audited physical table id and column count.
    pub fn new(table_id: u32, column_count: u32) -> Result<Self, SchemaAdapterError> {
        if table_id == 0 {
            return Err(SchemaAdapterError::ZeroTableId);
        }
        if column_count == 0 {
            return Err(SchemaAdapterError::ZeroColumnCount);
        }
        Ok(Self {
            table_id,
            column_count,
        })
    }

    /// Returns the physical `SYSTABLE.table_id` covered by this attestation.
    pub fn table_id(self) -> u32 {
        self.table_id
    }

    /// Returns the independently audited complete column count.
    pub fn column_count(self) -> u32 {
        self.column_count
    }
}

/// Explicit storage facts that catalog rows alone cannot prove.
///
/// Enterprise 24 user-row compression has not been recovered.  Therefore
/// production callers must not use this adapter until they have independently
/// proven `uncompressed` for the particular table and row representation.
/// The numeric dialect is equally explicit because the legacy SQL Anywhere
/// decoder and Enterprise materialized rows use different base-100 ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowStorageAttestation {
    /// Whether the particular row representation was independently proven not
    /// to use compression.
    pub uncompressed: bool,
    /// Explicit Boolean storage layout for the particular row representation.
    ///
    /// The legacy `Bytes` and `PackedMsbFirst` forms use a tail sidecar;
    /// `InlineBytes` consumes a byte at each Boolean column ordinal.
    pub boolean_tail: BooleanTailLayout,
    /// Explicit physical representation for catalog `NUMERIC` columns.
    pub numeric_layout: NumericLayout,
    /// Explicit physical encoding for catalog domain-19 `ENUM` fields.
    pub enum_layout: EnumLayout,
    /// Explicit handling for variable-value overflow markers.
    pub variable_overflow_layout: VariableOverflowLayout,
    /// Explicit length-prefix representation for variable columns.
    pub variable_length_layout: VariableLengthLayout,
    /// Explicit bit ordering and polarity for the nullable-column bitmap.
    pub null_bitmap_layout: NullBitmapLayout,
    /// Which logical columns consume null-bitmap positions.
    pub null_bitmap_coverage: NullBitmapCoverage,
    /// Explicit optional prefix between a direct row length and its null map.
    /// Materialized-row carrier bytes are handled separately by OpenSQLAnywhere.
    pub row_prefix_layout: RowPrefixLayout,
}

/// One exact catalog-default envelope independently accepted for a column.
///
/// The bytes are deliberately not parsed as SQL here. `SYSCOLUMN` preserves
/// them losslessly; an adapter may use the column's type metadata only when a
/// caller has independently attested the exact nonzero envelope observed for
/// that ordinal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogDefaultEnvelope<'a> {
    /// One-based column ordinal carrying the envelope.
    pub column_id: u32,
    /// Exact `SYSCOLUMN` physical row flags.
    pub row_flags: u8,
    /// Exact bytes after the identifier and before the fixed trailing tag.
    pub post_name_bytes: &'a [u8],
}

/// Explicit catalog-default evidence separate from user-row storage facts.
///
/// A `SYSCOLUMN` row flag or post-name bytes describe catalog metadata; they
/// are not evidence that application rows use compression. Keeping this
/// attestation separate prevents a default expression from being silently
/// dropped or misclassified as a row-storage feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogDefaultAttestation<'a> {
    /// Exact envelopes accepted by the caller.
    pub envelopes: &'a [CatalogDefaultEnvelope<'a>],
}

impl CatalogDefaultAttestation<'static> {
    /// An attestation that permits no nonempty catalog-default envelopes.
    pub const fn none() -> Self {
        Self { envelopes: &[] }
    }
}

/// Convert complete, unambiguous catalog metadata into an OpenSQLAnywhere row schema.
///
/// The resulting schema is only a typed metadata object.  It is not evidence
/// that [`opensqlany::decode_row`] is applicable to Enterprise 24 user rows.
/// In particular, this function refuses unknown domains, un-attested ENUM
/// domains, un-attested catalog-default envelopes, non-contiguous ordinals,
/// conflicting rows, unbounded widths, and any row storage not explicitly
/// attested as uncompressed.
pub fn adapt_complete_schema(
    columns: &[SysColumn],
    coverage: CatalogCoverageAttestation,
    storage: RowStorageAttestation,
    defaults: CatalogDefaultAttestation<'_>,
) -> Result<RowSchema, SchemaAdapterError> {
    if !storage.uncompressed {
        return Err(SchemaAdapterError::CompressionNotProven {
            table_id: coverage.table_id,
        });
    }
    if columns.len() != usize::try_from(coverage.column_count).expect("u32 always fits usize") {
        return Err(SchemaAdapterError::CoverageCountMismatch {
            table_id: coverage.table_id,
            attested: coverage.column_count,
            recovered: columns.len(),
        });
    }

    let mut ordered: Vec<&SysColumn> = columns.iter().collect();
    ordered.sort_by_key(|column| column.column_id);
    let mut definitions: Vec<ColumnDef> = Vec::with_capacity(ordered.len());
    for (offset, column) in ordered.into_iter().enumerate() {
        if column.table_id != coverage.table_id {
            return Err(SchemaAdapterError::WrongTable {
                expected: coverage.table_id,
                found: column.table_id,
                column_id: column.column_id,
            });
        }
        let expected_id = u32::try_from(offset + 1).expect("attested u32 count bounds offset");
        if column.column_id != expected_id {
            if offset > 0 && column.column_id == definitions.last().expect("previous definition").id
            {
                return Err(SchemaAdapterError::DuplicateOrdinal {
                    table_id: coverage.table_id,
                    column_id: column.column_id,
                });
            }
            return Err(SchemaAdapterError::NonContiguousOrdinal {
                table_id: coverage.table_id,
                expected: expected_id,
                found: column.column_id,
            });
        }
        if column.marker != 0x01 || !matches!(column.nulls, b'N' | b'Y') {
            return Err(SchemaAdapterError::InvalidCatalogMetadata {
                table_id: coverage.table_id,
                column_id: column.column_id,
            });
        }
        if column.row_flags != 0 || !column.post_name_bytes.is_empty() {
            let attested = defaults.envelopes.iter().any(|envelope| {
                envelope.column_id == column.column_id
                    && envelope.row_flags == column.row_flags
                    && envelope.post_name_bytes == column.post_name_bytes
            });
            if !attested {
                return Err(SchemaAdapterError::CatalogDefaultNotAttested {
                    table_id: coverage.table_id,
                    column_id: column.column_id,
                    flags: column.row_flags,
                    post_name_bytes: column.post_name_bytes.len(),
                });
            }
        }
        if column.name.is_empty() {
            return Err(SchemaAdapterError::EmptyColumnName {
                table_id: coverage.table_id,
                column_id: column.column_id,
            });
        }
        let column_type = ColumnType::from_domain_id(column.domain_id).ok_or(
            SchemaAdapterError::UnknownDomain {
                table_id: coverage.table_id,
                column_id: column.column_id,
                domain_id: column.domain_id,
            },
        )?;
        if column_type == ColumnType::Enum && storage.enum_layout == EnumLayout::Unsupported {
            return Err(SchemaAdapterError::EnumDomainUnsupported {
                table_id: coverage.table_id,
                column_id: column.column_id,
            });
        }
        let width = validate_width(column, column_type, coverage.table_id)?;
        definitions.push(ColumnDef::new(
            column.column_id,
            &column.name,
            column_type,
            width,
            column.nulls == b'Y',
        ));
    }
    let mut schema = RowSchema::new(definitions);
    schema.boolean_tail = storage.boolean_tail;
    schema.numeric_layout = storage.numeric_layout;
    schema.enum_layout = storage.enum_layout;
    schema.variable_overflow_layout = storage.variable_overflow_layout;
    schema.variable_length_layout = storage.variable_length_layout;
    schema.null_bitmap_layout = storage.null_bitmap_layout;
    schema.null_bitmap_coverage = storage.null_bitmap_coverage;
    schema.row_prefix_layout = storage.row_prefix_layout;
    Ok(schema)
}

fn validate_width(
    column: &SysColumn,
    column_type: ColumnType,
    table_id: u32,
) -> Result<u16, SchemaAdapterError> {
    let width = u16::try_from(column.width).map_err(|_| SchemaAdapterError::WidthOutOfBounds {
        table_id,
        column_id: column.column_id,
        width: column.width,
    })?;
    let valid = match column_type {
        ColumnType::SmallInt => width == 2,
        ColumnType::Integer | ColumnType::Integer2 => matches!(width, 1 | 2 | 4 | 8),
        ColumnType::UInt64 | ColumnType::Int64 => width == 8,
        ColumnType::UInt32 => width == 4,
        ColumnType::Date => width == 4,
        ColumnType::DateTime => width == 8,
        // The decoder's variable and Boolean layouts do not consume this
        // catalog width.  A finite u16 conversion above is still required.
        ColumnType::Char
        | ColumnType::Char2
        | ColumnType::Text
        | ColumnType::Text2
        | ColumnType::Boolean => true,
        // Numeric precision must be positive; scale is a catalog fact and is
        // not interpreted as an on-row byte width by this adapter.
        ColumnType::Numeric => {
            width != 0 && column.scale >= 0 && u32::from(width) >= column.scale as u32
        }
        ColumnType::Enum => matches!(width, 1 | 2 | 4 | 8),
    };
    if !valid {
        return Err(SchemaAdapterError::InvalidWidth {
            table_id,
            column_id: column.column_id,
            width: column.width,
            domain_id: column.domain_id,
        });
    }
    Ok(width)
}

/// Reasons catalog metadata cannot safely become a typed row schema.
#[allow(missing_docs)] // Variant fields repeat the documented error payload.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SchemaAdapterError {
    /// The attestation used table id zero.
    #[error("catalog coverage attestation has table id zero")]
    ZeroTableId,
    /// The attestation used a zero column count.
    #[error("catalog coverage attestation has zero columns")]
    ZeroColumnCount,
    /// User-row compression was not independently ruled out.
    #[error("table {table_id}: row compression is not proven absent")]
    CompressionNotProven { table_id: u32 },
    /// Recovered rows do not equal the independently attested count.
    #[error("table {table_id}: recovered {recovered} columns, attested {attested}")]
    CoverageCountMismatch {
        table_id: u32,
        attested: u32,
        recovered: usize,
    },
    /// A row belongs to a different physical table.
    #[error("table {expected}: column {column_id} belongs to table {found}")]
    WrongTable {
        expected: u32,
        found: u32,
        column_id: u32,
    },
    /// Two recovered rows used the same ordinal.
    #[error("table {table_id}: duplicate column ordinal {column_id}")]
    DuplicateOrdinal { table_id: u32, column_id: u32 },
    /// Ordinals were not exactly the complete one-based sequence.
    #[error("table {table_id}: expected column ordinal {expected}, found {found}")]
    NonContiguousOrdinal {
        table_id: u32,
        expected: u32,
        found: u32,
    },
    /// A catalog row's marker or nullability byte is invalid.
    #[error("table {table_id}: column {column_id} has invalid catalog metadata")]
    InvalidCatalogMetadata { table_id: u32, column_id: u32 },
    /// A nonempty catalog-default envelope was not accepted exactly by the
    /// caller-supplied default attestation.
    #[error(
        "table {table_id}: column {column_id} has unattested catalog default flags {flags:#04x} and {post_name_bytes} post-name bytes"
    )]
    CatalogDefaultNotAttested {
        table_id: u32,
        column_id: u32,
        flags: u8,
        post_name_bytes: usize,
    },
    /// A column name was absent.
    #[error("table {table_id}: column {column_id} has an empty name")]
    EmptyColumnName { table_id: u32, column_id: u32 },
    /// The catalog domain has no supported physical mapping.
    #[error("table {table_id}: column {column_id} has unknown domain {domain_id}")]
    UnknownDomain {
        table_id: u32,
        column_id: u32,
        domain_id: u16,
    },
    /// Enum needs an independently recovered scalar layout.
    #[error("table {table_id}: column {column_id} uses unsupported enum domain")]
    EnumDomainUnsupported { table_id: u32, column_id: u32 },
    /// Catalog width cannot fit the typed schema representation.
    #[error("table {table_id}: column {column_id} width {width} exceeds the supported bound")]
    WidthOutOfBounds {
        table_id: u32,
        column_id: u32,
        width: u32,
    },
    /// Catalog width conflicts with the known domain mapping.
    #[error("table {table_id}: column {column_id} width {width} is invalid for domain {domain_id}")]
    InvalidWidth {
        table_id: u32,
        column_id: u32,
        width: u32,
        domain_id: u16,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn column(id: u32, domain_id: u16, width: u32) -> SysColumn {
        SysColumn {
            name: format!("c_{id}"),
            table_id: 3026,
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

    fn complete_storage() -> RowStorageAttestation {
        RowStorageAttestation {
            uncompressed: true,
            boolean_tail: BooleanTailLayout::PackedMsbFirst,
            numeric_layout: NumericLayout::LegacyForward,
            enum_layout: EnumLayout::Unsupported,
            variable_overflow_layout: VariableOverflowLayout::Unsupported,
            variable_length_layout: VariableLengthLayout::U8,
            null_bitmap_layout: NullBitmapLayout::MsbPresent,
            null_bitmap_coverage: NullBitmapCoverage::NullableColumns,
            row_prefix_layout: RowPrefixLayout::None,
        }
    }

    #[test]
    fn complete_synthetic_schema_succeeds_only_with_explicit_storage_facts() {
        let columns = vec![column(1, 2, 4), column(2, 8, 64), column(3, 24, 0)];
        let schema = adapt_complete_schema(
            &columns,
            CatalogCoverageAttestation::new(3026, 3).unwrap(),
            complete_storage(),
            CatalogDefaultAttestation::none(),
        )
        .unwrap();
        assert_eq!(schema.columns.len(), 3);
        assert_eq!(schema.columns[0].column_type, ColumnType::Integer);
        assert!(schema.columns[2].column_type == ColumnType::Boolean);
        assert_eq!(schema.boolean_tail, BooleanTailLayout::PackedMsbFirst);
    }

    #[test]
    fn explicit_inline_boolean_storage_is_preserved_in_adapted_schema() {
        let columns = vec![column(1, 2, 4), column(2, 24, 0)];
        let mut storage = complete_storage();
        storage.boolean_tail = BooleanTailLayout::InlineBytes;
        let schema = adapt_complete_schema(
            &columns,
            CatalogCoverageAttestation::new(3026, 2).unwrap(),
            storage,
            CatalogDefaultAttestation::none(),
        )
        .unwrap();
        assert_eq!(schema.boolean_tail, BooleanTailLayout::InlineBytes);
    }

    #[test]
    fn current_partial_account_schema_is_rejected_by_coverage_contract() {
        let columns: Vec<_> = (1..=28).map(|id| column(id, 2, 4)).collect();
        assert!(matches!(
            adapt_complete_schema(
                &columns,
                CatalogCoverageAttestation::new(3026, 36).unwrap(),
                complete_storage(),
                CatalogDefaultAttestation::none(),
            ),
            Err(SchemaAdapterError::CoverageCountMismatch { .. })
        ));
    }

    #[test]
    fn current_partial_general_journal_schema_is_rejected_by_coverage_contract() {
        let mut columns: Vec<_> = (1..=42).map(|id| column(id, 2, 4)).collect();
        for value in &mut columns {
            value.table_id = 3078;
        }
        assert!(matches!(
            adapt_complete_schema(
                &columns,
                CatalogCoverageAttestation::new(3078, 67).unwrap(),
                complete_storage(),
                CatalogDefaultAttestation::none(),
            ),
            Err(SchemaAdapterError::CoverageCountMismatch { .. })
        ));
    }

    #[test]
    fn exact_default_envelope_is_explicitly_attested_without_claiming_compression() {
        let mut columns = vec![column(1, 2, 4), column(2, 2, 4)];
        columns[1].row_flags = 0x80;
        columns[1].post_name_bytes = vec![0x02, b'X', b'Y'];
        let envelopes = [CatalogDefaultEnvelope {
            column_id: 2,
            row_flags: 0x80,
            post_name_bytes: &[0x02, b'X', b'Y'],
        }];
        let schema = adapt_complete_schema(
            &columns,
            CatalogCoverageAttestation::new(3026, 2).unwrap(),
            complete_storage(),
            CatalogDefaultAttestation {
                envelopes: &envelopes,
            },
        )
        .unwrap();
        assert_eq!(schema.columns.len(), 2);
    }

    #[test]
    fn rejects_duplicates_gaps_unknown_enum_unattested_defaults_and_compression() {
        let coverage = CatalogCoverageAttestation::new(3026, 2).unwrap();
        let duplicate = vec![column(1, 2, 4), column(1, 2, 4)];
        assert!(matches!(
            adapt_complete_schema(
                &duplicate,
                coverage,
                complete_storage(),
                CatalogDefaultAttestation::none(),
            ),
            Err(SchemaAdapterError::DuplicateOrdinal { .. })
        ));
        let gap = vec![column(1, 2, 4), column(3, 2, 4)];
        assert!(matches!(
            adapt_complete_schema(
                &gap,
                coverage,
                complete_storage(),
                CatalogDefaultAttestation::none(),
            ),
            Err(SchemaAdapterError::NonContiguousOrdinal { .. })
        ));
        let unknown = vec![column(1, 99, 4), column(2, 2, 4)];
        assert!(matches!(
            adapt_complete_schema(
                &unknown,
                coverage,
                complete_storage(),
                CatalogDefaultAttestation::none(),
            ),
            Err(SchemaAdapterError::UnknownDomain { .. })
        ));
        let enums = vec![column(1, 19, 2), column(2, 2, 4)];
        assert!(matches!(
            adapt_complete_schema(
                &enums,
                coverage,
                complete_storage(),
                CatalogDefaultAttestation::none(),
            ),
            Err(SchemaAdapterError::EnumDomainUnsupported { .. })
        ));
        let mut post_name = vec![column(1, 2, 4), column(2, 2, 4)];
        post_name[0].post_name_bytes.push(1);
        assert!(matches!(
            adapt_complete_schema(
                &post_name,
                coverage,
                complete_storage(),
                CatalogDefaultAttestation::none(),
            ),
            Err(SchemaAdapterError::CatalogDefaultNotAttested { .. })
        ));
        assert!(matches!(
            adapt_complete_schema(
                &[column(1, 2, 4), column(2, 2, 4)],
                coverage,
                RowStorageAttestation {
                    uncompressed: false,
                    boolean_tail: BooleanTailLayout::Bytes,
                    numeric_layout: NumericLayout::LegacyForward,
                    enum_layout: EnumLayout::Unsupported,
                    variable_overflow_layout: VariableOverflowLayout::Unsupported,
                    variable_length_layout: VariableLengthLayout::U8,
                    null_bitmap_layout: NullBitmapLayout::MsbPresent,
                    null_bitmap_coverage: NullBitmapCoverage::NullableColumns,
                    row_prefix_layout: RowPrefixLayout::None,
                },
                CatalogDefaultAttestation::none(),
            ),
            Err(SchemaAdapterError::CompressionNotProven { .. })
        ));
    }
}

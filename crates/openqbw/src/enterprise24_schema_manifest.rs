//! Empirical Enterprise 24 R21 catalog allowlist.
//!
//! This is a versioned compatibility manifest, not a claim about SQL
//! Anywhere's generic SYSTABLE semantics or materialized application-row
//! framing. Its canonical fingerprints cover the schema-semantic
//! `SYSCOLUMN` fields for the named tables. Per-file catalog provenance
//! (object ids, maximum identity values, physical row lengths and page
//! placement) is deliberately not a compatibility input because it can vary
//! with a company's history without changing its Enterprise 24 R21 schema.
//! Runtime callers must reject a file whose recovered schema semantics differ.

use crate::{CatalogDefaultEnvelope, SysColumn};
use thiserror::Error;

/// One sanitized, version-specific table schema fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enterprise24R21SchemaTableManifest {
    /// Physical QBW table id.
    pub table_id: u32,
    /// Exact count of one-based catalog columns.
    pub column_count: u32,
    /// Stable FNV-1 fingerprint of canonical schema metadata.
    ///
    /// The legacy byte stream covers ordinal, identifier, domain, width,
    /// scale, marker, nullability, row flags, and bounded post-name/default
    /// bytes. It deliberately omits per-file catalog provenance such as
    /// object identifiers, maximum identity values, physical row lengths, and
    /// page placement. It contains no application-row values, file paths, or
    /// table names.
    pub canonical_fingerprint: u64,
}

/// Sanitized empirically validated Enterprise 24 R21 schema allowlist.
///
/// These fingerprints were identical across the approved local Enterprise 24
/// QBW corpus. They deliberately cover schema semantics only; passing this
/// manifest does not attest per-file catalog provenance, application-row
/// compression, null-map framing, overflow handling, Boolean tail layout, or
/// numeric storage.
pub const ENTERPRISE24_R21_SCHEMA_MANIFEST: [Enterprise24R21SchemaTableManifest; 12] = [
    Enterprise24R21SchemaTableManifest {
        table_id: 3025,
        column_count: 29,
        canonical_fingerprint: 0xfe25_0d5c_12c3_0811,
    },
    Enterprise24R21SchemaTableManifest {
        table_id: 3026,
        column_count: 36,
        canonical_fingerprint: 0x364f_2259_d208_de18,
    },
    Enterprise24R21SchemaTableManifest {
        table_id: 3038,
        column_count: 35,
        canonical_fingerprint: 0x0294_bd79_9d0e_cb5b,
    },
    Enterprise24R21SchemaTableManifest {
        table_id: 3039,
        column_count: 52,
        canonical_fingerprint: 0x3b68_deaf_59e0_ab4c,
    },
    Enterprise24R21SchemaTableManifest {
        table_id: 3040,
        column_count: 37,
        canonical_fingerprint: 0x0456_a786_95fe_5ed2,
    },
    Enterprise24R21SchemaTableManifest {
        table_id: 3042,
        column_count: 86,
        canonical_fingerprint: 0xb662_5a05_e4b4_e63c,
    },
    Enterprise24R21SchemaTableManifest {
        table_id: 3045,
        column_count: 42,
        canonical_fingerprint: 0x2f85_24f0_5ab8_c7b3,
    },
    Enterprise24R21SchemaTableManifest {
        table_id: 3047,
        column_count: 90,
        canonical_fingerprint: 0x1049_39a5_ea2c_c3ec,
    },
    Enterprise24R21SchemaTableManifest {
        table_id: 3068,
        column_count: 31,
        canonical_fingerprint: 0x3d26_e040_8c67_9b6d,
    },
    Enterprise24R21SchemaTableManifest {
        table_id: 3069,
        column_count: 52,
        canonical_fingerprint: 0x362c_519d_1ec1_4079,
    },
    Enterprise24R21SchemaTableManifest {
        table_id: 3076,
        column_count: 32,
        canonical_fingerprint: 0x2378_8b47_385a_b4a3,
    },
    Enterprise24R21SchemaTableManifest {
        table_id: 3078,
        column_count: 67,
        canonical_fingerprint: 0x531e_caae_d5f2_ce08,
    },
];

/// A complete Enterprise 24 R21 `SYSCOLUMN` catalog that matched the
/// versioned compatibility manifest.
///
/// This attestation establishes only that the recovered catalog metadata
/// matches the supported R21 manifest. In particular, any default envelope
/// yielded from it remains opaque catalog metadata: it does not imply an
/// application-row default, compression rule, or physical row layout.
#[derive(Debug, Clone, Copy)]
pub struct Enterprise24R21ValidatedCatalog<'a> {
    columns: &'a [SysColumn],
}

impl<'a> Enterprise24R21ValidatedCatalog<'a> {
    /// Return the exact nonempty catalog-default envelopes for one manifest
    /// table.
    ///
    /// The returned references borrow the validated catalog, preserving the
    /// original `row_flags` and post-name bytes without parsing or changing
    /// them. A caller can pass these envelopes to `adapt_complete_schema`.
    pub fn default_envelopes(
        self,
        table_id: u32,
    ) -> Result<Vec<CatalogDefaultEnvelope<'a>>, Enterprise24R21SchemaManifestError> {
        default_envelopes_for_manifest(self.columns, &ENTERPRISE24_R21_SCHEMA_MANIFEST, table_id)
    }
}

/// Validate the complete recovered `SYSCOLUMN` catalog against the Enterprise
/// 24 R21 manifest before allowing its opaque catalog-default envelopes to be
/// reused for schema adaptation.
///
/// This intentionally validates every required manifest table, not merely the
/// table currently being adapted. It is therefore safe for a shared CLI
/// schema-builder to call once before building any application-row schema.
pub fn attest_enterprise24_r21_catalog(
    columns: &[SysColumn],
) -> Result<Enterprise24R21ValidatedCatalog<'_>, Enterprise24R21SchemaManifestError> {
    validate_enterprise24_r21_schema_manifest(columns)?;
    Ok(Enterprise24R21ValidatedCatalog { columns })
}

/// Validate recovered catalog metadata against the R21 empirical allowlist.
pub fn validate_enterprise24_r21_schema_manifest(
    columns: &[SysColumn],
) -> Result<(), Enterprise24R21SchemaManifestError> {
    validate_schema_manifest(columns, &ENTERPRISE24_R21_SCHEMA_MANIFEST)
}

fn validate_schema_manifest(
    columns: &[SysColumn],
    manifest: &[Enterprise24R21SchemaTableManifest],
) -> Result<(), Enterprise24R21SchemaManifestError> {
    for expected in manifest {
        let mut table_columns: Vec<_> = columns
            .iter()
            .filter(|column| column.table_id == expected.table_id)
            .collect();
        table_columns.sort_by_key(|column| (column.column_id, &column.name));
        if table_columns.len() != usize::try_from(expected.column_count).expect("u32 fits usize") {
            return Err(Enterprise24R21SchemaManifestError::ColumnCountMismatch {
                table_id: expected.table_id,
                expected: expected.column_count,
                actual: table_columns.len(),
            });
        }
        for (offset, column) in table_columns.iter().enumerate() {
            let ordinal = u32::try_from(offset + 1).expect("manifest count bounds ordinal");
            if column.column_id != ordinal {
                return Err(Enterprise24R21SchemaManifestError::OrdinalMismatch {
                    table_id: expected.table_id,
                    expected: ordinal,
                    actual: column.column_id,
                });
            }
        }
        let actual = enterprise24_r21_schema_fingerprint(&table_columns);
        if actual != expected.canonical_fingerprint {
            return Err(Enterprise24R21SchemaManifestError::FingerprintMismatch {
                table_id: expected.table_id,
                expected: expected.canonical_fingerprint,
                actual,
            });
        }
    }
    Ok(())
}

fn default_envelopes_for_manifest<'a>(
    columns: &'a [SysColumn],
    manifest: &[Enterprise24R21SchemaTableManifest],
    table_id: u32,
) -> Result<Vec<CatalogDefaultEnvelope<'a>>, Enterprise24R21SchemaManifestError> {
    if !manifest.iter().any(|entry| entry.table_id == table_id) {
        return Err(Enterprise24R21SchemaManifestError::TableNotInManifest { table_id });
    }
    Ok(columns
        .iter()
        .filter(|column| {
            column.table_id == table_id
                && (column.row_flags != 0 || !column.post_name_bytes.is_empty())
        })
        .map(|column| CatalogDefaultEnvelope {
            column_id: column.column_id,
            row_flags: column.row_flags,
            post_name_bytes: &column.post_name_bytes,
        })
        .collect())
}

/// Compute the legacy canonical schema fingerprint used by the R21 allowlist.
///
/// This is FNV-1 (multiply then XOR), not FNV-1a. The constants above were
/// empirically recorded with this exact legacy framing, so changing its
/// ordering, delimiter treatment, or hash family requires a new manifest
/// version and a fresh private-corpus validation. The stream is intentionally
/// not a cryptographic integrity primitive.
pub fn enterprise24_r21_schema_fingerprint(columns: &[&SysColumn]) -> u64 {
    let mut state = 0xcbf2_9ce4_8422_2325_u64;
    for column in columns {
        for byte in column.column_id.to_le_bytes() {
            state = state.wrapping_mul(0x100_0000_01b3) ^ u64::from(byte);
        }
        for byte in column.name.bytes() {
            state = state.wrapping_mul(0x100_0000_01b3) ^ u64::from(byte);
        }
        for byte in column.domain_id.to_le_bytes() {
            state = state.wrapping_mul(0x100_0000_01b3) ^ u64::from(byte);
        }
        for byte in column.width.to_le_bytes() {
            state = state.wrapping_mul(0x100_0000_01b3) ^ u64::from(byte);
        }
        for byte in column.scale.to_le_bytes() {
            state = state.wrapping_mul(0x100_0000_01b3) ^ u64::from(byte);
        }
        for byte in [column.nulls, column.marker, column.row_flags] {
            state = state.wrapping_mul(0x100_0000_01b3) ^ u64::from(byte);
        }
        for byte in &column.post_name_bytes {
            state = state.wrapping_mul(0x100_0000_01b3) ^ u64::from(*byte);
        }
    }
    state
}

/// Manifest validation failures.
#[derive(Debug, Error, PartialEq, Eq)]
#[allow(missing_docs)] // Variant fields repeat the documented error payload.
pub enum Enterprise24R21SchemaManifestError {
    /// The caller requested a table outside the validated compatibility manifest.
    #[error("Enterprise 24 R21 table {table_id} is not in the schema manifest")]
    TableNotInManifest { table_id: u32 },
    /// A required table did not have the versioned number of columns.
    #[error("Enterprise 24 R21 table {table_id} recovered {actual} columns, expected {expected}")]
    ColumnCountMismatch {
        table_id: u32,
        expected: u32,
        actual: usize,
    },
    /// A required table's ordinals did not form the complete one-based range.
    #[error("Enterprise 24 R21 table {table_id} expected ordinal {expected}, found {actual}")]
    OrdinalMismatch {
        table_id: u32,
        expected: u32,
        actual: u32,
    },
    /// Canonical catalog metadata differs from the versioned allowlist.
    #[error(
        "Enterprise 24 R21 table {table_id} metadata fingerprint {actual:#018x} differs from {expected:#018x}"
    )]
    FingerprintMismatch {
        table_id: u32,
        expected: u64,
        actual: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn column(id: u32, name: &str) -> SysColumn {
        SysColumn {
            name: name.to_owned(),
            table_id: 3026,
            column_id: id,
            domain_id: 2,
            marker: 1,
            nulls: b'N',
            width: 4,
            scale: 0,
            object_id: 0,
            max_identity: 0,
            post_name_bytes: Vec::new(),
            row_length: 0,
            row_flags: 0,
            page_number: 0,
            trailer_page_type_raw: None,
            row_offset: 0,
            tag_offset: 0,
        }
    }

    #[test]
    fn canonical_fingerprint_changes_with_catalog_metadata() {
        let first = column(1, "account_id");
        let mut changed = first.clone();
        changed.width = 8;
        assert_ne!(
            enterprise24_r21_schema_fingerprint(&[&first]),
            enterprise24_r21_schema_fingerprint(&[&changed])
        );
    }

    #[test]
    fn canonical_fingerprint_covers_each_schema_semantic_field() {
        let base = column(1, "account_id");
        let baseline = enterprise24_r21_schema_fingerprint(&[&base]);
        let mut variants = Vec::new();

        let mut changed = base.clone();
        changed.column_id = 2;
        variants.push(changed);
        let mut changed = base.clone();
        changed.name = "account_name".to_owned();
        variants.push(changed);
        let mut changed = base.clone();
        changed.domain_id = 3;
        variants.push(changed);
        let mut changed = base.clone();
        changed.marker = 2;
        variants.push(changed);
        let mut changed = base.clone();
        changed.nulls = b'Y';
        variants.push(changed);
        let mut changed = base.clone();
        changed.width = 8;
        variants.push(changed);
        let mut changed = base.clone();
        changed.scale = 1;
        variants.push(changed);
        let mut changed = base.clone();
        changed.row_flags = 1;
        variants.push(changed);
        let mut changed = base.clone();
        changed.post_name_bytes = vec![1, 2, 3];
        variants.push(changed);

        for variant in &variants {
            assert_ne!(baseline, enterprise24_r21_schema_fingerprint(&[variant]));
        }
    }

    #[test]
    fn manifest_contains_the_twelve_distinct_expected_table_ids() {
        let ids: Vec<_> = ENTERPRISE24_R21_SCHEMA_MANIFEST
            .iter()
            .map(|entry| entry.table_id)
            .collect();
        assert_eq!(
            ids,
            vec![
                3025, 3026, 3038, 3039, 3040, 3042, 3045, 3047, 3068, 3069, 3076, 3078,
            ]
        );
        assert_eq!(ids.len(), 12);
    }

    #[test]
    fn manifest_rejects_missing_required_table() {
        assert!(matches!(
            validate_enterprise24_r21_schema_manifest(&[]),
            Err(Enterprise24R21SchemaManifestError::ColumnCountMismatch { table_id: 3025, .. })
        ));
    }

    #[test]
    fn manifest_mismatch_cannot_produce_default_envelopes() {
        let mut sample = column(1, "SAMPLE_COLUMN");
        sample.row_flags = 0x80;
        sample.post_name_bytes = vec![0x02, b'S'];
        assert!(attest_enterprise24_r21_catalog(&[sample]).is_err());
    }

    #[test]
    fn validated_manifest_helper_preserves_exact_opaque_default_envelope() {
        let mut sample = column(1, "SAMPLE_COLUMN");
        sample.table_id = 77;
        sample.row_flags = 0x80;
        sample.post_name_bytes = vec![0x02, b'S', b'A', b'M', b'P', b'L', b'E'];
        let manifest = [Enterprise24R21SchemaTableManifest {
            table_id: 77,
            column_count: 1,
            canonical_fingerprint: enterprise24_r21_schema_fingerprint(&[&sample]),
        }];

        let columns = [sample];
        validate_schema_manifest(&columns, &manifest).unwrap();
        let envelopes = default_envelopes_for_manifest(&columns, &manifest, 77).unwrap();
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].column_id, 1);
        assert_eq!(envelopes[0].row_flags, 0x80);
        assert_eq!(
            envelopes[0].post_name_bytes,
            &[0x02, b'S', b'A', b'M', b'P', b'L', b'E']
        );
    }
}

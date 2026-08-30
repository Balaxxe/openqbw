//! `SYSCOLUMN` catalog row parser (Phase 6, WP-6A).
//!
//! Each compact Enterprise 24 `SYSCOLUMN` record is self-length-delimited.
//! Its following layout was recovered from independently bounded rows on page
//! 730 (and then cross-checked on further catalog pages):
//!
//! ```text
//! <row_len low24 | flags high8 u32 LE>      -- exact full record length + flags
//! <table_id u32 LE>                        -- physical SYSTABLE.table_id
//! <column_id u32 LE>                       -- ordinal within the table
//! <domain_id u16 LE> <marker u8> <nulls ASCII N/Y>
//! <width u32 LE> <scale i16 LE> <object_id u64 LE> <max_identity i64 LE>
//! <name_len u8> <identifier>
//! <post_name_bytes...>                     -- bounded, preserved opaque
//! 01 52 00 01 00 00 00 00                  -- exact trailing tag
//! ```
//!
//! The physical identifier joins directly to [`crate::SysTableEntry::table_id`].
//! It is not a page number and should not be attributed through the
//! `SYSOBJECT` heuristic. A live aggregate audit on the Enterprise 24
//! fixture found this direct relationship for the overwhelming majority of
//! recovered catalog rows.

use std::collections::BTreeMap;
use std::iter::FusedIterator;

use opensqlany::{ApModel, MaterializedTablePage, PageStore, PageType, Result as SaResult};
use thiserror::Error;

use crate::bv_recovery::{
    AffineKnownPlaintextWitness, affine_known_plaintext_witnesses, deobfuscate_with_bv,
};
use crate::{
    EnterprisePageMaterializationError, EnterprisePageTransformKey, SysTableEntry,
    materialize_enterprise_table_page_candidates_with_key, materialized_table_id,
};

/// Physical table id of the materialized Enterprise 24 `SYSCOLUMN` carrier.
///
/// This identity is established by the exact bounded catalog grammar across
/// the carrier's pages. A caller must still supply the matching Enterprise
/// transform-key context for the opened local file.
pub const MATERIALIZED_SYSCOLUMN_TABLE_ID: u32 = 2;

/// Fixed 8-byte anchor that precedes the numeric portion of every
/// `SYSCOLUMN` row body.
pub const SYSCOLUMN_TAG: [u8; 8] = [0x01, 0x52, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];

/// SQL Anywhere's catalog `column_name` allows up to 128 bytes.
const NAME_LEN_MAX: usize = 128;
const PAGE_BODY_LEN: usize = 0xFF0;
const ROW_LEN_BYTES: usize = 4;
const FIXED_PREFIX_LEN: usize = 12;
const FIXED_BYTES_AFTER_LENGTH: usize = 34;
const NAME_LEN_OFFSET: usize = ROW_LEN_BYTES + FIXED_BYTES_AFTER_LENGTH;
const MIN_ROW_LEN: usize = NAME_LEN_OFFSET + 1 + SYSCOLUMN_TAG.len();

/// One parsed `SYSCOLUMN` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysColumn {
    /// Column name (ASCII identifier).
    pub name: String,
    /// Physical `SYSTABLE.table_id` of the owning table.
    pub table_id: u32,
    /// Ordinal position of this column inside its owning table.
    pub column_id: u32,
    /// SQL Anywhere catalog domain identifier.
    ///
    /// This is the recovered physical `domain_id` field, encoded as a little-
    /// endian `u16`.  It maps to a type name through `SYSDOMAIN`; callers must
    /// still independently prove that this compact QBW catalog record has the
    /// expected row-storage semantics before using it to decode application
    /// data.
    pub domain_id: u16,
    /// Raw marker byte located between `domain_id` and `nulls`.
    ///
    /// It is `0x01` in the recovered Enterprise 24 corpus.  Its semantic role
    /// has not been established, so it is retained rather than discarded.
    pub marker: u8,
    /// Whether the column allows nulls (`b'N'` or `b'Y'`).
    ///
    /// This placement and meaning are corroborated by the SQL Anywhere 17
    /// `SYSTABCOL` / compatibility `SYSCOLUMN` definitions: `domain_id`
    /// precedes a one-character `nulls` field and `width` follows it.
    pub nulls: u8,
    /// Raw catalog width/precision value (its units remain domain-dependent and
    /// unproven for Enterprise 24).
    pub width: u32,
    /// Raw catalog scale. Its interpretation is domain dependent.
    pub scale: i16,
    /// The record's 64-bit catalog object identifier, little-endian on disk.
    ///
    /// This has not been proven to join the 64-bit `SYSTABLE.object_id` field,
    /// so it is retained as provenance rather than used for ownership.
    pub object_id: u64,
    /// Catalog maximum identity value. It is retained as raw catalog
    /// provenance; only identity domains give it a higher-level meaning.
    pub max_identity: i64,
    /// Bytes after the column name and before the exact trailing tag.
    ///
    /// Some catalog rows carry a default expression or another variable
    /// field here.  Their individual grammar is not yet proven, so this is
    /// retained verbatim rather than shifted into a neighboring row or
    /// assigned a speculative meaning.
    pub post_name_bytes: Vec<u8>,
    /// Exact physical record length declared at `row_offset`.
    pub row_length: u32,
    /// High byte of the on-disk row header. It is catalog provenance; no
    /// current-row/tombstone semantics are assigned without separate proof.
    pub row_flags: u8,
    /// Page on which this row was found.
    pub page_number: u64,
    /// Original trailer byte at offset `0xFF2` of the source page.
    ///
    /// This preserves the physical page-kind/case provenance (`E` versus
    /// `e`, for example) even though [`PageType`] is case-insensitive.  It is
    /// absent only when [`scan_page`] receives a body-only test buffer rather
    /// than a complete decoded page.
    pub trailer_page_type_raw: Option<u8>,
    /// Byte offset of the complete row within the decoded page body.
    pub row_offset: usize,
    /// Byte offset of the trailing tag within the decoded page body.
    pub tag_offset: usize,
}

/// Aggregate result of a fail-closed materialized `SYSCOLUMN` collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedSysColumnCollection {
    /// Distinct catalog rows, ordered by `(table_id, column_id, name)`.
    pub columns: Vec<SysColumn>,
    /// Materialized physical catalog pages selected by the exact carrier id.
    pub carrier_pages: u64,
    /// Directory slots declared by the selected catalog pages.
    pub carrier_directory_slots: u64,
    /// Selected directory slots unavailable at materialization time.
    pub carrier_missing_records: u64,
    /// Accessible selected records that passed the complete `SYSCOLUMN`
    /// envelope parser.
    pub carrier_parsed_records: u64,
    /// Accessible selected records not accepted as complete `SYSCOLUMN` rows.
    ///
    /// This is not silently discarded: callers that require a complete
    /// catalog-carrier classification must account for it explicitly.
    pub carrier_unparsed_records: u64,
    /// Self-length-bounded unparsed records keyed by their safely readable
    /// `(table_id, column_id)` fixed prefix.
    pub unparsed_fixed_prefix_columns: BTreeMap<(u32, u32), u64>,
    /// Unparsed records whose exact self length established the fixed prefix.
    pub unparsed_self_length_fixed_prefix_records: u64,
    /// Unparsed records physically too short to carry table and column ids.
    pub unparsed_shorter_than_fixed_prefix_records: u64,
    /// Unparsed records long enough for the prefix but lacking exact
    /// self-length bounds. Targeted schema attestation must reject these.
    pub unparsed_without_fixed_prefix: u64,
    /// Raw pages that had no usable materialized type-4 representation.
    pub skipped_pages: MaterializedSysColumnSkippedPages,
}

/// Aggregate non-catalog materialization outcomes retained as provenance.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaterializedSysColumnSkippedPages {
    /// Pages without a unique header transform.
    pub no_header: u64,
    /// Pages with several possible header transforms.
    pub ambiguous_header: u64,
    /// Pages that did not validate as type-4 table pages.
    pub not_type4: u64,
    /// Pages with no otherwise classified materialization result.
    pub other: u64,
}

/// Cross-catalog proof that the materialized `SYSCOLUMN` carrier was fully
/// recovered.
///
/// It compares the bounded materialized carrier census against the independent
/// bounded materialized `SYSTABLE` row for physical table 2. Once both counts
/// agree, accessible carrier records outside the `SYSCOLUMN` grammar cannot
/// be silently missing logical catalog rows: they are physical artifacts or a
/// separately classified carrier class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaterializedSysColumnCompletenessAttestation {
    /// Independently declared logical `SYSCOLUMN` row count.
    pub row_count: u64,
    /// Independently declared materialized carrier-page count.
    pub page_count: u32,
}

/// Failure while collecting a materialized Enterprise `SYSCOLUMN` catalog.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MaterializedSysColumnCollectionError {
    /// The supplied SYSTABLE entry was not the physical SYSCOLUMN carrier.
    #[error(
        "materialized SYSTABLE entry {actual_table_id} is not SYSCOLUMN table {expected_table_id}"
    )]
    WrongCarrierTableId {
        /// Required physical table id.
        expected_table_id: u32,
        /// Entry table id supplied by the caller.
        actual_table_id: u32,
    },
    /// Materialized carrier pages did not equal the independent SYSTABLE
    /// declaration.
    #[error(
        "materialized SYSCOLUMN carrier recovered {actual} pages, SYSTABLE declares {expected}"
    )]
    CarrierPageCountMismatch {
        /// Independently declared page count.
        expected: u32,
        /// Materialized selected-page count.
        actual: u64,
    },
    /// SYSTABLE's base and external carrier-page counts overflowed their domain.
    #[error("materialized SYSCOLUMN SYSTABLE page counts overflowed")]
    CarrierPageCountOverflow,
    /// Complete parsed catalog records did not equal the independent
    /// SYSTABLE logical row count.
    #[error("materialized SYSCOLUMN carrier parsed {actual} rows, SYSTABLE declares {expected}")]
    CarrierRowCountMismatch {
        /// Independently declared logical row count.
        expected: u64,
        /// Parsed complete SYSCOLUMN record count.
        actual: u64,
    },
    /// Parsed physical rows and distinct logical catalog rows disagreed.
    #[error(
        "materialized SYSCOLUMN carrier parsed {parsed} rows but retained {distinct} distinct rows"
    )]
    CarrierDuplicateRows {
        /// Parsed physical record count.
        parsed: u64,
        /// Retained unique logical-row count.
        distinct: usize,
    },
    /// A target-specific schema was requested with no independent count.
    #[error("materialized schema table {table_id} has zero expected columns")]
    ZeroExpectedTargetColumnCount {
        /// Target physical table id.
        table_id: u32,
    },
    /// Recovered target rows did not match the independently attested count.
    #[error("materialized schema table {table_id} recovered {actual} columns, expected {expected}")]
    TargetCountMismatch {
        /// Target physical table id.
        table_id: u32,
        /// Independently attested count.
        expected: u32,
        /// Distinct recovered catalog rows for the target table.
        actual: usize,
    },
    /// Recovered target ordinals were not the exact one-based sequence.
    #[error("materialized schema table {table_id} expected ordinal {expected}, found {actual}")]
    TargetOrdinalMismatch {
        /// Target physical table id.
        table_id: u32,
        /// Required one-based ordinal.
        expected: u32,
        /// Recovered ordinal at that position.
        actual: u32,
    },
    /// Accessible catalog-carrier records were not classified as complete
    /// `SYSCOLUMN` envelopes.
    #[error("materialized SYSCOLUMN carrier retained {count} unparsed accessible records")]
    UnparsedCarrierRecords {
        /// Number of accessible carrier records left unclassified.
        count: u64,
    },
    /// Two materialized candidates for one raw page yielded different catalog
    /// schemas, so neither can be selected.
    #[error("materialized SYSCOLUMN candidates diverged on physical page {page_number}")]
    DivergentCandidates {
        /// Raw physical page number.
        page_number: u64,
    },
    /// Materialization candidates for a raw page disagreed about the physical
    /// catalog carrier identity.
    ///
    /// A table-id match may identify pages for later decoding, but it is not
    /// evidence for choosing one transform candidate over another. Refuse the
    /// entire raw page rather than silently treating only its table-2 view as
    /// the `SYSCOLUMN` carrier.
    #[error(
        "materialized candidates disagree about catalog carrier identity on physical page {page_number}"
    )]
    AmbiguousCarrierIdentity {
        /// Raw physical page number.
        page_number: u64,
    },
    /// The same logical schema identity decoded to conflicting values.
    #[error(
        "materialized SYSCOLUMN identity ({table_id}, {column_id}, {name}) conflicted across pages"
    )]
    ConflictingRow {
        /// Owning physical table id.
        table_id: u32,
        /// One-based column ordinal.
        column_id: u32,
        /// Column identifier.
        name: String,
    },
}

impl MaterializedSysColumnCollection {
    /// Require an explicit classification for every accessible carrier row.
    ///
    /// The generic collector preserves unparsed rows as an aggregate instead
    /// of guessing their class. A caller that needs a complete catalog
    /// attestation may use this gate only after proving there are none (or
    /// after performing a stricter, table-specific classification externally).
    pub fn require_no_unparsed_carrier_records(
        &self,
    ) -> Result<(), MaterializedSysColumnCollectionError> {
        if self.carrier_unparsed_records == 0 {
            Ok(())
        } else {
            Err(
                MaterializedSysColumnCollectionError::UnparsedCarrierRecords {
                    count: self.carrier_unparsed_records,
                },
            )
        }
    }

    /// Return one independently attested complete target-table schema.
    ///
    /// `expected_count` must come from an independent SYSTABLE/catalog audit
    /// or version manifest, never from the largest observed ordinal. The
    /// global carrier may contain additional, intentionally unclassified row
    /// classes; those rows do not weaken this target-specific proof because
    /// every requested ordinal is required exactly once and no extra ordinal
    /// is accepted for this table.
    pub fn complete_materialized_schema_columns(
        &self,
        table_id: u32,
        expected_count: u32,
    ) -> Result<Vec<SysColumn>, MaterializedSysColumnCollectionError> {
        if expected_count == 0 {
            return Err(
                MaterializedSysColumnCollectionError::ZeroExpectedTargetColumnCount { table_id },
            );
        }
        let mut columns: Vec<_> = self
            .columns
            .iter()
            .filter(|column| column.table_id == table_id)
            .cloned()
            .collect();
        columns.sort_by_key(|column| (column.column_id, column.name.clone()));
        if columns.len() != usize::try_from(expected_count).expect("u32 fits usize") {
            return Err(MaterializedSysColumnCollectionError::TargetCountMismatch {
                table_id,
                expected: expected_count,
                actual: columns.len(),
            });
        }
        for (offset, column) in columns.iter().enumerate() {
            let expected = u32::try_from(offset + 1).expect("expected count bounds offset");
            if column.column_id != expected {
                return Err(
                    MaterializedSysColumnCollectionError::TargetOrdinalMismatch {
                        table_id,
                        expected,
                        actual: column.column_id,
                    },
                );
            }
        }
        Ok(columns)
    }

    /// Cross-check the complete materialized catalog against its independent
    /// materialized SYSTABLE entry.
    ///
    /// This is the authoritative completeness gate for target-table schema
    /// cardinality: it uses SYSTABLE's logical row/page counts, rather than an
    /// observed maximum target ordinal. It does not require every physical
    /// table-2 directory record to be a SYSCOLUMN row.
    pub fn attest_against_materialized_systable(
        &self,
        systable: &SysTableEntry,
    ) -> Result<MaterializedSysColumnCompletenessAttestation, MaterializedSysColumnCollectionError>
    {
        if systable.table_id != MATERIALIZED_SYSCOLUMN_TABLE_ID {
            return Err(MaterializedSysColumnCollectionError::WrongCarrierTableId {
                expected_table_id: MATERIALIZED_SYSCOLUMN_TABLE_ID,
                actual_table_id: systable.table_id,
            });
        }
        let expected_pages = systable
            .table_page_count
            .checked_add(systable.ext_page_count)
            .ok_or(MaterializedSysColumnCollectionError::CarrierPageCountOverflow)?;
        if self.carrier_pages != u64::from(expected_pages) {
            return Err(
                MaterializedSysColumnCollectionError::CarrierPageCountMismatch {
                    expected: expected_pages,
                    actual: self.carrier_pages,
                },
            );
        }
        if self.carrier_parsed_records != systable.row_count {
            return Err(
                MaterializedSysColumnCollectionError::CarrierRowCountMismatch {
                    expected: systable.row_count,
                    actual: self.carrier_parsed_records,
                },
            );
        }
        if self.columns.len()
            != usize::try_from(self.carrier_parsed_records)
                .expect("u64 fits usize on supported host")
        {
            return Err(MaterializedSysColumnCollectionError::CarrierDuplicateRows {
                parsed: self.carrier_parsed_records,
                distinct: self.columns.len(),
            });
        }
        Ok(MaterializedSysColumnCompletenessAttestation {
            row_count: systable.row_count,
            page_count: expected_pages,
        })
    }
}

impl SysColumn {
    /// Compatibility accessor for the historical, incorrect `nulls_flag`
    /// field name.  The old byte was actually the low byte of `domain_id`.
    #[deprecated(note = "use domain_id; the historical nulls_flag was a mislabelled domain byte")]
    pub fn nulls_flag(&self) -> u8 {
        self.domain_id as u8
    }

    /// Compatibility accessor for the historical, incorrect `domain_char`
    /// field name.  The old byte is the catalog's N/Y nullability flag.
    #[deprecated(note = "use nulls; the historical domain_char was the nullability flag")]
    pub fn domain_char(&self) -> u8 {
        self.nulls
    }
    /// Historical name for [`Self::table_id`].
    ///
    /// The field was originally mislabeled as an SA object identifier.
    /// New callers must use [`Self::table_id`].
    #[deprecated(note = "SYSCOLUMN stores SYSTABLE.table_id; use table_id")]
    pub fn owner_object_id(&self) -> u32 {
        self.table_id
    }
}

/// Parse a complete, self-length-delimited `SYSCOLUMN` row at `row_offset`.
///
/// The row must fit in the supplied page body and terminate in the fixed tag.
/// This deliberately rejects a tag plus fields from the next physical fragment:
/// page 730 has a witnessed tag exactly at a fragment end.
fn parse_row_at(page: &[u8], row_offset: usize, pn: u64) -> Option<SysColumn> {
    let length_bytes = page.get(row_offset..row_offset + ROW_LEN_BYTES)?;
    let row_header = u32::from_le_bytes(length_bytes.try_into().ok()?);
    let row_len = (row_header & 0x00ff_ffff) as usize;
    let row_flags = (row_header >> 24) as u8;
    if !(MIN_ROW_LEN..=PAGE_BODY_LEN).contains(&row_len)
        || row_offset.checked_add(row_len)? > page.len()
    {
        return None;
    }
    let row = &page[row_offset..row_offset + row_len];
    let name_len = usize::from(*row.get(NAME_LEN_OFFSET)?);
    if !(1..=NAME_LEN_MAX).contains(&name_len) {
        return None;
    }
    let name_start = NAME_LEN_OFFSET + 1;
    let name_end = name_start.checked_add(name_len)?;
    let tag_start = row_len.checked_sub(SYSCOLUMN_TAG.len())?;
    if name_end > tag_start {
        return None;
    }
    let name_bytes = &row[name_start..name_end];
    if !name_bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_')
        || !matches!(name_bytes.first(), Some(b) if b.is_ascii_alphabetic() || *b == b'_')
        || row[row_len - SYSCOLUMN_TAG.len()..] != SYSCOLUMN_TAG
    {
        return None;
    }
    let marker = row[14];
    let nulls = row[15];
    if marker != 0x01 || !matches!(nulls, b'N' | b'Y') {
        return None;
    }
    Some(SysColumn {
        name: name_bytes.iter().map(|&b| b as char).collect(),
        table_id: u32::from_le_bytes(row[4..8].try_into().ok()?),
        column_id: u32::from_le_bytes(row[8..12].try_into().ok()?),
        domain_id: u16::from_le_bytes(row[12..14].try_into().ok()?),
        marker,
        nulls,
        width: u32::from_le_bytes(row[16..20].try_into().ok()?),
        scale: i16::from_le_bytes(row[20..22].try_into().ok()?),
        object_id: u64::from_le_bytes(row[22..30].try_into().ok()?),
        max_identity: i64::from_le_bytes(row[30..38].try_into().ok()?),
        post_name_bytes: row[name_end..tag_start].to_vec(),
        row_length: row_len as u32,
        row_flags,
        page_number: pn,
        trailer_page_type_raw: None,
        row_offset,
        tag_offset: row_offset + row_len - SYSCOLUMN_TAG.len(),
    })
}

/// Parse one complete `SYSCOLUMN` physical record from a runtime-materialized
/// type-4 page.
///
/// Materialized page directories bound each record with a little-endian
/// 16-bit length.  The observed Enterprise 24 catalog carrier retains the
/// compact `SYSCOLUMN` row header and trailing tag inside that exact record.
/// This function requires both independent lengths to agree and never scans
/// into a neighboring materialized record. `record_offset` is the resolved
/// byte offset within the materialized page, retained as provenance in the
/// returned value.
///
/// It is intentionally a single-record parser rather than a table decoder:
/// callers must independently identify and enumerate the catalog carrier.
pub fn parse_materialized_syscolumn_record(
    record: &[u8],
    page_number: u64,
    record_offset: usize,
) -> Option<SysColumn> {
    let declared = usize::from(u16::from_le_bytes(record.get(..2)?.try_into().ok()?));
    if declared != record.len() {
        return None;
    }
    let mut column = parse_row_at(record, 0, page_number)?;
    if column.row_length as usize != record.len() {
        return None;
    }
    column.row_offset = record_offset;
    column.tag_offset = record_offset.checked_add(column.tag_offset)?;
    Some(column)
}

fn self_length_bounded_syscolumn_fixed_prefix(record: &[u8]) -> Option<(u32, u32)> {
    if record.len() < FIXED_PREFIX_LEN {
        return None;
    }
    let header = u32::from_le_bytes(record[..4].try_into().ok()?);
    if usize::try_from(header & 0x00ff_ffff).ok()? != record.len() {
        return None;
    }
    Some((
        u32::from_le_bytes(record[4..8].try_into().ok()?),
        u32::from_le_bytes(record[8..12].try_into().ok()?),
    ))
}

/// Recover every fully bounded `SYSCOLUMN` record from one already identified
/// runtime-materialized catalog page.
///
/// The page's table identity is intentionally caller-owned: a valid catalog
/// row grammar by itself does not establish ownership of an arbitrary type-4
/// page. Missing directory entries and records that fail the exact catalog
/// envelope are omitted rather than read across their physical boundaries.
pub fn scan_materialized_syscolumn_records(
    page: MaterializedTablePage<'_>,
    page_number: u64,
) -> Vec<SysColumn> {
    let mut columns = Vec::new();
    for record_id in 0..page.record_count() {
        let Ok(record) = page.record(record_id) else {
            continue;
        };
        if let Some(column) =
            parse_materialized_syscolumn_record(record.bytes(), page_number, record.byte_offset())
        {
            columns.push(column);
        }
    }
    columns
}

/// Collect the complete bounded `SYSCOLUMN` catalog from a local Enterprise
/// materialized-page store.
///
/// Only pages whose proven physical table id equals
/// [`MATERIALIZED_SYSCOLUMN_TABLE_ID`] participate. If a raw page has several
/// structurally valid materializations, every carrier candidate must produce
/// the same semantic catalog set; otherwise collection fails instead of
/// choosing by candidate order. The result retains only exact semantic
/// duplicates and rejects conflicts for the same `(table_id, column_id, name)`
/// identity.
pub fn collect_materialized_syscolumns(
    store: &PageStore,
    key: EnterprisePageTransformKey,
) -> Result<MaterializedSysColumnCollection, MaterializedSysColumnCollectionError> {
    let mut carrier_pages = 0_u64;
    let mut carrier_directory_slots = 0_u64;
    let mut carrier_missing_records = 0_u64;
    let mut carrier_parsed_records = 0_u64;
    let mut carrier_unparsed_records = 0_u64;
    let mut unparsed_fixed_prefix_columns = BTreeMap::<(u32, u32), u64>::new();
    let mut unparsed_self_length_fixed_prefix_records = 0_u64;
    let mut unparsed_shorter_than_fixed_prefix_records = 0_u64;
    let mut unparsed_without_fixed_prefix = 0_u64;
    let mut skipped_pages = MaterializedSysColumnSkippedPages::default();
    let mut rows = BTreeMap::<(u32, u32, String), SysColumn>::new();

    for raw in store.pages() {
        let page_number = raw.index();
        let candidates = match materialize_enterprise_table_page_candidates_with_key(
            raw.bytes(),
            page_number,
            key,
        ) {
            Ok(candidates) => candidates,
            Err(error) => {
                record_materialized_catalog_skip(&mut skipped_pages, error);
                continue;
            }
        };
        let mut candidate_table_ids = BTreeMap::new();
        for (candidate_index, candidate) in candidates.iter().enumerate() {
            let Ok(table_id) = materialized_table_id(candidate.bytes()) else {
                // `EnterpriseMaterializedTablePage` has already satisfied the
                // page contract, but an unusable table id must never be used
                // to select a catalog carrier.
                continue;
            };
            candidate_table_ids.insert(candidate_index, table_id.get());
        }
        let carrier_candidate_count = candidate_table_ids
            .values()
            .filter(|&&table_id| table_id == MATERIALIZED_SYSCOLUMN_TABLE_ID)
            .count();
        if carrier_candidate_count == 0 {
            continue;
        }
        if carrier_candidate_count != candidates.len()
            || candidate_table_ids.len() != candidates.len()
        {
            return Err(
                MaterializedSysColumnCollectionError::AmbiguousCarrierIdentity { page_number },
            );
        }

        let mut decoded = Vec::new();
        for candidate in candidates {
            let table_page = candidate.table_page();
            let mut rows = Vec::new();
            let mut missing = 0_u64;
            let mut unparsed = 0_u64;
            let mut unparsed_prefixes = BTreeMap::<(u32, u32), u64>::new();
            let mut unparsed_self_length_prefixes = 0_u64;
            let mut unparsed_short_prefixes = 0_u64;
            let mut unparsed_without_prefix = 0_u64;
            for record_id in 0..table_page.record_count() {
                let Ok(record) = table_page.record(record_id) else {
                    missing += 1;
                    continue;
                };
                if let Some(column) = parse_materialized_syscolumn_record(
                    record.bytes(),
                    page_number,
                    record.byte_offset(),
                ) {
                    rows.push(column);
                } else {
                    unparsed += 1;
                    if record.bytes().len() < FIXED_PREFIX_LEN {
                        unparsed_short_prefixes += 1;
                    } else if let Some(prefix) =
                        self_length_bounded_syscolumn_fixed_prefix(record.bytes())
                    {
                        *unparsed_prefixes.entry(prefix).or_default() += 1;
                        unparsed_self_length_prefixes += 1;
                    } else {
                        unparsed_without_prefix += 1;
                    }
                }
            }
            decoded.push((
                rows,
                u64::from(table_page.record_count()),
                missing,
                unparsed,
                unparsed_prefixes,
                unparsed_self_length_prefixes,
                unparsed_short_prefixes,
                unparsed_without_prefix,
            ));
        }
        if decoded.is_empty() {
            continue;
        }
        let semantic: Vec<BTreeMap<SysColumnSemanticKey, SysColumn>> = decoded
            .iter()
            .map(|(rows, _, _, _, _, _, _, _)| {
                rows.iter()
                    .map(|row| (SysColumnSemanticKey::from(row), row.clone()))
                    .collect()
            })
            .collect();
        if semantic
            .windows(2)
            .any(|pair| pair[0].keys().ne(pair[1].keys()))
            || decoded.windows(2).any(|pair| {
                (
                    pair[0].1, pair[0].2, pair[0].3, &pair[0].4, pair[0].5, pair[0].6, pair[0].7,
                ) != (
                    pair[1].1, pair[1].2, pair[1].3, &pair[1].4, pair[1].5, pair[1].6, pair[1].7,
                )
            })
        {
            return Err(MaterializedSysColumnCollectionError::DivergentCandidates { page_number });
        }
        carrier_pages += 1;
        carrier_directory_slots += decoded[0].1;
        carrier_missing_records += decoded[0].2;
        carrier_parsed_records += u64::try_from(decoded[0].0.len()).expect("usize fits u64");
        carrier_unparsed_records += decoded[0].3;
        for (&prefix, &count) in &decoded[0].4 {
            *unparsed_fixed_prefix_columns.entry(prefix).or_default() += count;
        }
        unparsed_self_length_fixed_prefix_records += decoded[0].5;
        unparsed_shorter_than_fixed_prefix_records += decoded[0].6;
        unparsed_without_fixed_prefix += decoded[0].7;
        // Equal semantic candidate sets may differ only in physical placement.
        // Select a stable placement after equality is established.
        for row in semantic[0].values() {
            let key = (row.table_id, row.column_id, row.name.clone());
            if let Some(existing) = rows.get(&key) {
                if SysColumnSemanticKey::from(existing) != SysColumnSemanticKey::from(row) {
                    return Err(MaterializedSysColumnCollectionError::ConflictingRow {
                        table_id: row.table_id,
                        column_id: row.column_id,
                        name: row.name.clone(),
                    });
                }
                continue;
            }
            rows.insert(key, row.clone());
        }
    }
    Ok(MaterializedSysColumnCollection {
        columns: rows.into_values().collect(),
        carrier_pages,
        carrier_directory_slots,
        carrier_missing_records,
        carrier_parsed_records,
        carrier_unparsed_records,
        unparsed_fixed_prefix_columns,
        unparsed_self_length_fixed_prefix_records,
        unparsed_shorter_than_fixed_prefix_records,
        unparsed_without_fixed_prefix,
        skipped_pages,
    })
}

fn record_materialized_catalog_skip(
    skipped: &mut MaterializedSysColumnSkippedPages,
    error: EnterprisePageMaterializationError,
) {
    match error {
        EnterprisePageMaterializationError::NoHeaderCandidate => skipped.no_header += 1,
        EnterprisePageMaterializationError::AmbiguousHeaderCandidates { .. } => {
            skipped.ambiguous_header += 1
        }
        EnterprisePageMaterializationError::NotMaterializedTablePage => skipped.not_type4 += 1,
        _ => skipped.other += 1,
    }
}

/// Parse all complete length-delimited `SYSCOLUMN` rows in a page body.
fn parse_rows_in_body(body: &[u8], pn: u64, out: &mut Vec<SysColumn>) {
    if body.len() < MIN_ROW_LEN {
        return;
    }
    for row_offset in 0..=body.len() - MIN_ROW_LEN {
        if let Some(row) = parse_row_at(body, row_offset, pn) {
            out.push(row);
        }
    }
}

/// Return true when an AP-obfuscated page body contains the fixed SYSCOLUMN
/// anchor entirely inside one 512-byte cipher sector.
///
/// The AP stream adds an affine `base + offset * step` value to each byte.
/// Taking adjacent-byte differences cancels the unknown base; one observed
/// difference determines `step`, and the rest of the anchor verifies it. This
/// is a *lossless prefilter* for anchors that do not cross a sector boundary.
/// Catalog anchors are normally stored inside a row body, but callers retain a
/// slow exhaustive path for the exceptional cross-sector case.
#[cfg(test)]
fn has_obfuscated_tag_in_sector(raw: &[u8]) -> bool {
    // `pn` affects only the final BV inversion. The in-sector affine
    // relation itself is independent of it.
    !affine_known_plaintext_witnesses(0, raw, &SYSCOLUMN_TAG).is_empty()
}

/// Evidence and decision for exact SYSCOLUMN-tag BV recovery on one page.
///
/// More than one verified BV deliberately selects no value. Picking one by
/// scan order would manufacture catalog provenance from an ambiguous pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysColumnTagBvRecovery {
    /// Byte-for-byte known-plaintext tag witnesses in the raw page.
    pub witnesses: Vec<AffineKnownPlaintextWitness>,
    /// Distinct BVs algebraically implied by `witnesses`.
    pub candidate_bvs: Vec<u8>,
    /// Candidates that also produce an exact self-length SYSCOLUMN row at a
    /// tag position witnessed for that candidate.
    pub verified_bvs: Vec<u8>,
    /// The only selected candidate, if exactly one candidate verified.
    pub bv: Option<u8>,
}

/// Recover a page BV from exact, in-sector SYSCOLUMN tag witnesses.
///
/// This intentionally has no generic recovery or model fallback: the raw
/// witness establishes the sector step and base, then the decoded page must
/// independently pass the physical row gate. The resulting selection is
/// deterministic and fail-closed under conflicts.
pub fn recover_bv_from_syscolumn_tag(pn: u64, raw: &[u8]) -> SysColumnTagBvRecovery {
    let witnesses = affine_known_plaintext_witnesses(pn, raw, &SYSCOLUMN_TAG);
    let mut candidate_bvs: Vec<u8> = witnesses.iter().map(|w| w.bv).collect();
    candidate_bvs.sort_unstable();
    candidate_bvs.dedup();

    let mut verified_bvs = Vec::new();
    for bv in candidate_bvs.iter().copied() {
        let plain = deobfuscate_with_bv(raw, pn, bv);
        let mut witness_offsets: Vec<usize> = witnesses
            .iter()
            .filter(|w| w.bv == bv)
            .map(|w| w.offset)
            .collect();
        witness_offsets.sort_unstable();
        if (0..PAGE_BODY_LEN).any(|row_offset| {
            parse_row_at(&plain[..PAGE_BODY_LEN], row_offset, pn)
                .is_some_and(|row| witness_offsets.binary_search(&row.tag_offset).is_ok())
        }) {
            verified_bvs.push(bv);
        }
    }
    let bv = (verified_bvs.len() == 1).then(|| verified_bvs[0]);
    SysColumnTagBvRecovery {
        witnesses,
        candidate_bvs,
        verified_bvs,
        bv,
    }
}

/// A complete catalog-row value excluding physical page placement.
///
/// This is deliberately stricter than the logical identity
/// `(table_id,column_id,name)`: an ambiguous-BV page may contribute a row only
/// if every verified decode agrees on every recovered schema field.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SysColumnSemanticKey {
    name: String,
    table_id: u32,
    column_id: u32,
    domain_id: u16,
    marker: u8,
    nulls: u8,
    width: u32,
    scale: i16,
    object_id: u64,
    max_identity: i64,
    post_name_bytes: Vec<u8>,
    row_length: u32,
    row_flags: u8,
}

impl From<&SysColumn> for SysColumnSemanticKey {
    fn from(row: &SysColumn) -> Self {
        Self {
            name: row.name.clone(),
            table_id: row.table_id,
            column_id: row.column_id,
            domain_id: row.domain_id,
            marker: row.marker,
            nulls: row.nulls,
            width: row.width,
            scale: row.scale,
            object_id: row.object_id,
            max_identity: row.max_identity,
            post_name_bytes: row.post_name_bytes.clone(),
            row_length: row.row_length,
            row_flags: row.row_flags,
        }
    }
}

/// Decode SYSCOLUMN rows using only exact-tag BV evidence.
///
/// For one verified BV, returns that page's accepted self-length rows. When
/// multiple BVs verify, returns the set intersection of their complete schema
/// values. Physical placement is intentionally selected deterministically
/// *after* semantic agreement, rather than selecting a page BV by row count
/// or any other heuristic. No rows are returned if no BV verifies.
pub fn scan_page_from_syscolumn_tag(
    pn: u64,
    raw: &[u8],
    out: &mut Vec<SysColumn>,
) -> SysColumnTagBvRecovery {
    let recovery = recover_bv_from_syscolumn_tag(pn, raw);
    if recovery.verified_bvs.is_empty() {
        return recovery;
    }
    let mut candidates = Vec::new();
    for bv in recovery.verified_bvs.iter().copied() {
        let mut rows = Vec::new();
        scan_page(&deobfuscate_with_bv(raw, pn, bv), pn, &mut rows);
        candidates.push(rows);
    }
    if candidates.len() == 1 {
        out.append(&mut candidates.pop().expect("one candidate"));
        return recovery;
    }

    let mut common: BTreeMap<SysColumnSemanticKey, SysColumn> = candidates[0]
        .iter()
        .map(|row| (SysColumnSemanticKey::from(row), row.clone()))
        .collect();
    for rows in candidates.iter().skip(1) {
        let keys: std::collections::BTreeSet<_> =
            rows.iter().map(SysColumnSemanticKey::from).collect();
        common.retain(|key, _| keys.contains(key));
    }
    // This selects only a stable location for already-agreed semantics; it is
    // never used to select a BV.  `page_number` is the same for every row.
    for key in common.keys() {
        let row = candidates
            .iter()
            .flat_map(|rows| rows.iter())
            .filter(|row| SysColumnSemanticKey::from(*row) == *key)
            .min_by_key(|row| (row.row_offset, row.tag_offset))
            .expect("key originated from a candidate")
            .clone();
        out.push(row);
    }
    recovery
}

/// Scan a single decoded page for physically bounded `SYSCOLUMN` candidates.
///
/// Records are self-length-delimited, so physical directory fragments are used
/// only as optional coarse containers; they are not assumed to be logical rows.
pub fn scan_page(plain: &[u8], pn: u64, out: &mut Vec<SysColumn>) {
    let start = out.len();
    parse_rows_in_body(&plain[..plain.len().min(PAGE_BODY_LEN)], pn, out);
    // AP deobfuscation copies the physical trailer verbatim.  Keep its raw
    // case-sensitive type byte as row provenance; body-only unit fixtures do
    // not have a trailer and deliberately retain `None`.
    let trailer_type = plain.get(PAGE_BODY_LEN + 2).copied();
    for row in &mut out[start..] {
        row.trailer_page_type_raw = trailer_type;
    }
}

/// Iterate every `SYSCOLUMN` row recovered from `store`.
pub fn iter_syscolumns<'a>(
    store: &'a PageStore,
    // Kept only for API compatibility with the other catalog iterators. It
    // must not be used as a silent decode oracle for SYSCOLUMN rows.
    _model: &'a ApModel,
) -> impl Iterator<Item = SysColumn> + 'a {
    SysColumnIter::new(store)
}

/// Deduplicate `SYSCOLUMN` rows by `(table_id, column_id, name)`
/// and return them ordered by `(table_id, column_id)`.
pub fn collect_unique(store: &PageStore, model: &ApModel) -> Vec<SysColumn> {
    let mut uniq: BTreeMap<(u32, u32, String), SysColumn> = BTreeMap::new();
    for c in iter_syscolumns(store, model) {
        uniq.entry((c.table_id, c.column_id, c.name.clone()))
            .or_insert(c);
    }
    uniq.into_values().collect()
}

/// Return all recovered columns for the table named `table_name`, ordered by
/// `column_id`.
///
/// This resolves the table name to exactly one physical `SYSTABLE.table_id`
/// and joins that value directly to [`SysColumn::table_id`]. It returns an
/// empty vector when the table is unknown, ambiguous, or no catalog column
/// rows were recovered. An
/// empty result does not establish that the physical table has no columns.
pub fn schema_for(store: &PageStore, model: &ApModel, table_name: &str) -> Vec<SysColumn> {
    let tables = crate::collect_unique(store, model);
    let mut matches = tables.into_iter().filter(|table| table.name == table_name);
    let Some(table) = matches.next() else {
        return Vec::new();
    };
    if matches.next().is_some() {
        return Vec::new();
    }
    let mut cols: Vec<SysColumn> = collect_unique(store, model)
        .into_iter()
        .filter(|c| c.table_id == table.table_id)
        .collect();
    cols.sort_by_key(|c| c.column_id);
    cols.dedup_by(|a, b| a.column_id == b.column_id && a.name == b.name);
    cols
}

struct SysColumnIter<'a> {
    store: &'a PageStore,
    pn: u64,
    n_pages: u64,
    buffer: Vec<SysColumn>,
}

impl<'a> SysColumnIter<'a> {
    fn new(store: &'a PageStore) -> Self {
        Self {
            store,
            pn: 1,
            n_pages: store.page_count(),
            buffer: Vec::new(),
        }
    }

    fn fill_buffer(&mut self) -> SaResult<bool> {
        while self.buffer.is_empty() && self.pn < self.n_pages {
            let pn = self.pn;
            self.pn += 1;
            let page = self.store.page(pn)?;
            // The all-trailer census found 41 exact, schema-consistent rows
            // on one uppercase A page, with no disagreement against E-page
            // values.  No other non-extent kind yielded a row.  Preserve the
            // raw trailer byte in `SysColumn` so callers can retain this
            // provenance instead of flattening A/E/e into a page-number-only
            // source.
            if !matches!(
                page.trailer().page_type(),
                PageType::Extent | PageType::Alloc
            ) {
                continue;
            }
            let raw = page.bytes();
            // Cross-sector tags are intentionally not asserted absent; they
            // need a separately proven multi-sector solver before production
            // use. Avoid any generic recovery on pages without a witness.
            let mut found = Vec::new();
            let recovery = scan_page_from_syscolumn_tag(pn, raw, &mut found);
            if recovery.witnesses.is_empty() {
                continue;
            }
            for c in found.into_iter().rev() {
                self.buffer.push(c);
            }
        }
        Ok(!self.buffer.is_empty())
    }
}

impl Iterator for SysColumnIter<'_> {
    type Item = SysColumn;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(c) = self.buffer.pop() {
                return Some(c);
            }
            match self.fill_buffer() {
                Ok(true) => continue,
                _ => return None,
            }
        }
    }
}

impl FusedIterator for SysColumnIter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an exact self-length-delimited catalog row.
    #[allow(clippy::too_many_arguments)]
    fn synth_row(
        name: &str,
        owner: u32,
        col_id: u32,
        domain_id: u16,
        nulls: u8,
        width: u32,
        scale: i16,
        object_id: u64,
    ) -> Vec<u8> {
        let mut v = vec![0; ROW_LEN_BYTES];
        v.extend_from_slice(&owner.to_le_bytes());
        v.extend_from_slice(&col_id.to_le_bytes());
        v.extend_from_slice(&domain_id.to_le_bytes());
        v.push(0x01);
        v.push(nulls);
        v.extend_from_slice(&width.to_le_bytes());
        v.extend_from_slice(&scale.to_le_bytes());
        v.extend_from_slice(&object_id.to_le_bytes());
        v.extend_from_slice(&0_i64.to_le_bytes());
        v.push(name.len() as u8);
        v.extend_from_slice(name.as_bytes());
        v.extend_from_slice(&SYSCOLUMN_TAG);
        let row_len = v.len() as u32;
        v[..ROW_LEN_BYTES].copy_from_slice(&row_len.to_le_bytes());
        v
    }

    fn with_post_name_bytes(mut row: Vec<u8>, bytes: &[u8]) -> Vec<u8> {
        let tag_at = row.len() - SYSCOLUMN_TAG.len();
        row.splice(tag_at..tag_at, bytes.iter().copied());
        let row_len = row.len() as u32;
        row[..ROW_LEN_BYTES].copy_from_slice(&row_len.to_le_bytes());
        row
    }

    fn with_flags(mut row: Vec<u8>, flags: u8) -> Vec<u8> {
        let len = u32::from_le_bytes(row[..ROW_LEN_BYTES].try_into().unwrap());
        let header = (len & 0x00ff_ffff) | (u32::from(flags) << 24);
        row[..ROW_LEN_BYTES].copy_from_slice(&header.to_le_bytes());
        row
    }

    #[test]
    fn parses_single_exact_row() {
        let body = synth_row("account_id", 3680, 1, 2, b'N', 4, 0, 0x1672);
        let mut out = Vec::new();
        parse_rows_in_body(&body, 42, &mut out);
        assert_eq!(out.len(), 1);
        let c = &out[0];
        assert_eq!(c.name, "account_id");
        assert_eq!(c.table_id, 3680);
        assert_eq!(c.column_id, 1);
        assert_eq!(c.domain_id, 2);
        assert_eq!(c.marker, 0x01);
        assert_eq!(c.nulls, b'N');
        assert_eq!(c.width, 4);
        assert_eq!(c.scale, 0);
        assert_eq!(c.object_id, 0x1672);
        assert_eq!(c.max_identity, 0);
        assert_eq!(c.row_length as usize, body.len());
        assert_eq!(c.row_flags, 0);
        assert_eq!(c.row_offset, 0);
        assert_eq!(c.tag_offset + SYSCOLUMN_TAG.len(), body.len());
        assert!(c.post_name_bytes.is_empty());
        assert_eq!(c.page_number, 42);
        assert_eq!(c.trailer_page_type_raw, None);
    }

    #[test]
    fn parses_one_bounded_materialized_record_and_rebases_provenance() {
        let row = synth_row("account_id", 3680, 1, 2, b'N', 4, 0, 0x1672);
        let parsed = parse_materialized_syscolumn_record(&row, 42, 0x3d8).unwrap();
        assert_eq!(parsed.table_id, 3680);
        assert_eq!(parsed.column_id, 1);
        assert_eq!(parsed.row_offset, 0x3d8);
        assert_eq!(parsed.tag_offset, 0x3d8 + row.len() - SYSCOLUMN_TAG.len());
    }

    #[test]
    fn materialized_record_requires_its_u16_and_compact_lengths_to_agree() {
        let mut row = synth_row("account_id", 3680, 1, 2, b'N', 4, 0, 0x1672);
        let wrong_len = u16::try_from(row.len() - 1).unwrap();
        row[..2].copy_from_slice(&wrong_len.to_le_bytes());
        assert!(parse_materialized_syscolumn_record(&row, 42, 0x3d8).is_none());
    }

    #[test]
    fn unparsed_fixed_prefix_requires_exact_self_length_bounds() {
        let mut row = synth_row("account_id", 3026, 1, 2, b'N', 4, 0, 0x1672);
        row[14] = 0;
        assert!(parse_materialized_syscolumn_record(&row, 42, 0x3d8).is_none());
        assert_eq!(
            self_length_bounded_syscolumn_fixed_prefix(&row),
            Some((3026, 1))
        );

        let mut wrong_length = row.clone();
        wrong_length[0] ^= 1;
        assert_eq!(
            self_length_bounded_syscolumn_fixed_prefix(&wrong_length),
            None
        );
        assert_eq!(
            self_length_bounded_syscolumn_fixed_prefix(&row[..FIXED_PREFIX_LEN - 1]),
            None
        );
    }

    #[test]
    fn scans_only_complete_records_from_an_identified_materialized_page() {
        let row = synth_row("account_id", 3680, 1, 2, b'N', 4, 0, 0x1672);
        let mut page = vec![0_u8; 4096];
        page[0x10] = 4;
        page[0x16..0x18].copy_from_slice(&2_u16.to_le_bytes());
        page[0x1c..0x1e].copy_from_slice(&4_u16.to_le_bytes());
        // The second directory slot is deliberately unavailable.
        page[0x20..0x20 + row.len()].copy_from_slice(&row);
        let page = MaterializedTablePage::parse(&page).unwrap();
        let columns = scan_materialized_syscolumn_records(page, 42);
        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].name, "account_id");
        assert_eq!(columns[0].row_offset, 0x20);
    }

    #[test]
    fn complete_carrier_gate_refuses_unclassified_accessible_records() {
        let collection = MaterializedSysColumnCollection {
            columns: Vec::new(),
            carrier_pages: 1,
            carrier_directory_slots: 2,
            carrier_missing_records: 0,
            carrier_parsed_records: 1,
            carrier_unparsed_records: 1,
            unparsed_fixed_prefix_columns: BTreeMap::new(),
            unparsed_self_length_fixed_prefix_records: 0,
            unparsed_shorter_than_fixed_prefix_records: 0,
            unparsed_without_fixed_prefix: 1,
            skipped_pages: MaterializedSysColumnSkippedPages::default(),
        };
        assert_eq!(
            collection.require_no_unparsed_carrier_records(),
            Err(MaterializedSysColumnCollectionError::UnparsedCarrierRecords { count: 1 })
        );
    }

    #[test]
    fn target_schema_gate_requires_independent_count_and_exact_ordinals() {
        let first = parse_materialized_syscolumn_record(
            &synth_row("account_id", 3026, 1, 2, b'N', 4, 0, 1),
            1,
            0x20,
        )
        .unwrap();
        let second = parse_materialized_syscolumn_record(
            &synth_row("name", 3026, 2, 9, b'Y', 32, 0, 2),
            1,
            0x40,
        )
        .unwrap();
        let collection = MaterializedSysColumnCollection {
            columns: vec![first, second],
            carrier_pages: 1,
            carrier_directory_slots: 2,
            carrier_missing_records: 0,
            carrier_parsed_records: 2,
            carrier_unparsed_records: 1,
            unparsed_fixed_prefix_columns: BTreeMap::new(),
            unparsed_self_length_fixed_prefix_records: 0,
            unparsed_shorter_than_fixed_prefix_records: 1,
            unparsed_without_fixed_prefix: 0,
            skipped_pages: MaterializedSysColumnSkippedPages::default(),
        };
        assert_eq!(
            collection
                .complete_materialized_schema_columns(3026, 2)
                .unwrap()
                .len(),
            2
        );
        assert!(matches!(
            collection.complete_materialized_schema_columns(3026, 3),
            Err(MaterializedSysColumnCollectionError::TargetCountMismatch { .. })
        ));
    }

    #[test]
    fn scan_page_preserves_raw_case_sensitive_trailer_type() {
        let row = synth_row("account_id", 3680, 1, 2, b'N', 4, 0, 0x1672);
        let mut page = vec![0; PAGE_BODY_LEN + 16];
        page[..row.len()].copy_from_slice(&row);
        page[PAGE_BODY_LEN + 2] = b'a';
        let mut out = Vec::new();
        scan_page(&page, 42, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].trailer_page_type_raw, Some(b'a'));
    }

    #[test]
    fn parses_multiple_rows_concatenated() {
        let mut body = synth_row("amount_amt", 100, 7, 3, b'N', 8, 2, 11);
        body.extend(synth_row("memo", 100, 8, 10, b'Y', 64, 0, 12));
        let mut out = Vec::new();
        parse_rows_in_body(&body, 0, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name, "amount_amt");
        assert_eq!(out[1].name, "memo");
        assert_eq!(out[1].width, 64);
    }

    #[test]
    fn preserves_signed_scale_and_max_identity() {
        let mut body = synth_row("identity_id", 9, 3, 2, b'N', 8, -2, 41);
        body[30..38].copy_from_slice(&(-7_i64).to_le_bytes());
        let mut out = Vec::new();
        parse_rows_in_body(&body, 0, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].scale, -2);
        assert_eq!(out[0].object_id, 41);
        assert_eq!(out[0].max_identity, -7);
    }

    #[test]
    fn parses_flagged_length_delimited_row() {
        let body = with_flags(synth_row("flagged", 9, 3, 2, b'N', 8, 0, 41), 0x80);
        let mut out = Vec::new();
        parse_rows_in_body(&body, 0, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].row_length as usize, body.len());
        assert_eq!(out[0].row_flags, 0x80);
    }

    #[test]
    fn rejects_header_with_zero_low24_length_even_when_flags_are_set() {
        let mut body = synth_row("flagged", 9, 3, 2, b'N', 8, 0, 41);
        body[..ROW_LEN_BYTES].copy_from_slice(&0x7f00_0000_u32.to_le_bytes());
        let mut out = Vec::new();
        parse_rows_in_body(&body, 0, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn accepts_official_maximum_length_column_name() {
        let name = format!("a{}", "b".repeat(127));
        let body = synth_row(&name, 9, 3, 2, b'N', 8, 0, 41);
        let mut out = Vec::new();
        parse_rows_in_body(&body, 0, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, name);
    }

    #[test]
    fn preserves_length_prefixed_default_expression_without_guessing_its_semantics() {
        let body = with_post_name_bytes(
            synth_row("identity_id", 9, 3, 2, b'N', 8, 0, 41),
            b"\x0dautoincrement",
        );
        let mut out = Vec::new();
        parse_rows_in_body(&body, 0, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "identity_id");
        assert_eq!(out[0].post_name_bytes, b"\x0dautoincrement");
    }

    #[test]
    fn preserves_arbitrary_bounded_post_name_bytes() {
        let body = with_post_name_bytes(
            synth_row("column", 9, 3, 2, b'N', 8, 0, 41),
            &[0, 0xff, 0x71, 0x42],
        );
        let mut out = Vec::new();
        parse_rows_in_body(&body, 0, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].post_name_bytes, [0, 0xff, 0x71, 0x42]);
    }

    #[test]
    fn handles_underscore_and_digits_in_name() {
        let body = synth_row("col_42_xy", 5, 1, 0, b'N', 1, 0, 1);
        let mut out = Vec::new();
        parse_rows_in_body(&body, 0, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "col_42_xy");
    }

    #[test]
    fn rejects_bad_marker() {
        let mut body = synth_row("good", 1, 1, 2, b'N', 4, 0, 1);
        // Corrupt the marker between domain_id and nulls.
        body[14] = 0x00;
        let mut out = Vec::new();
        parse_rows_in_body(&body, 0, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn rejects_non_nullability_flag() {
        let body = synth_row("col", 1, 1, 2, 0xFF, 4, 0, 1);
        let mut out = Vec::new();
        parse_rows_in_body(&body, 0, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn rejects_a_row_length_that_overruns_available_bytes() {
        let mut body = synth_row("id", 3026, 42, 2, b'N', 4, 0, 1);
        let bad_length = body.len() as u32 + 1;
        body[..4].copy_from_slice(&bad_length.to_le_bytes());
        let mut out = Vec::new();
        parse_rows_in_body(&body, 0, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn rejects_unrelated_adjacent_identifiers() {
        // This shape is ambiguous without a physical-row directory: `other`
        // can be an inline default or prior-record value. The parser must not
        // manufacture a pairing for `current`.
        let mut body = Vec::new();
        body.push(5);
        body.extend_from_slice(b"other");
        body.push(7);
        body.extend_from_slice(b"current");
        body.extend(synth_row("ignored", 1, 1, 2, b'N', 4, 0, 1)[7..].iter());
        // Rebuild the suffix precisely: the first tag follows `current`, and
        // the numeric tail has a valid record envelope.
        let tag_at = 1 + 5 + 1 + 7;
        body.truncate(tag_at);
        body.extend_from_slice(&SYSCOLUMN_TAG);
        body.extend_from_slice(&0_u32.to_le_bytes());
        body.extend_from_slice(&1_u32.to_le_bytes());
        body.extend_from_slice(&1_u32.to_le_bytes());
        body.extend_from_slice(&2_u16.to_le_bytes());
        body.push(1);
        body.push(b'N');
        body.push(4);
        let mut out = Vec::new();
        parse_rows_in_body(&body, 0, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn finds_anchor_under_ap_affine_obfuscation() {
        let mut raw = vec![0xA5; 4096];
        let start = 137usize;
        let base = 0x39u8;
        let step = 0x17u8;
        for (i, byte) in SYSCOLUMN_TAG.iter().enumerate() {
            raw[start + i] = byte
                .wrapping_add(base)
                .wrapping_add(((start + i) as u8).wrapping_mul(step));
        }
        assert!(has_obfuscated_tag_in_sector(&raw));
    }

    fn encode_ap_page(pn: u64, bv: u8, plain: &[u8]) -> Vec<u8> {
        assert_eq!(plain.len(), 4096);
        let p16 = (pn % 16) as u8;
        let bias = p16 / 2 * 4;
        let mut raw = vec![0u8; 4096];
        raw[PAGE_BODY_LEN..].copy_from_slice(&plain[PAGE_BODY_LEN..]);
        for sector in 0..8usize {
            let start = sector * 512;
            let end = if sector == 7 {
                PAGE_BODY_LEN
            } else {
                start + 512
            };
            let base = bv
                .wrapping_add(pn as u8)
                .wrapping_add(sector as u8)
                .wrapping_sub(bias);
            for offset in start..end {
                raw[offset] = plain[offset].wrapping_add(base);
            }
        }
        raw
    }

    #[test]
    fn exact_tag_recovery_requires_a_witnessed_self_length_row() {
        let pn = 730u64;
        let bv = 0x3bu8;
        let row = synth_row("amount_amt", 3078, 41, 3, b'N', 20, 5, 0x1234);
        let row_offset = 137usize;
        let mut plain = vec![0u8; 4096];
        plain[row_offset..row_offset + row.len()].copy_from_slice(&row);
        plain[PAGE_BODY_LEN + 2] = b'E';
        let raw = encode_ap_page(pn, bv, &plain);

        let recovery = recover_bv_from_syscolumn_tag(pn, &raw);
        assert_eq!(recovery.candidate_bvs, vec![bv]);
        assert_eq!(recovery.verified_bvs, vec![bv]);
        assert_eq!(recovery.bv, Some(bv));
        assert_eq!(recovery.witnesses.len(), 1);
        assert_eq!(
            recovery.witnesses[0].offset,
            row_offset + row.len() - SYSCOLUMN_TAG.len()
        );
    }

    #[test]
    fn exact_tag_recovery_fails_closed_for_two_verified_bvs() {
        let pn = 730u64;
        let row_a = synth_row("account_id", 3026, 1, 2, b'N', 4, 0, 1);
        let row_b = synth_row("amount_amt", 3078, 41, 3, b'N', 20, 5, 2);
        let offset_a = 80usize;
        let offset_b = 512 + 80;
        let mut plain = vec![0u8; 4096];
        plain[offset_a..offset_a + row_a.len()].copy_from_slice(&row_a);
        plain[offset_b..offset_b + row_b.len()].copy_from_slice(&row_b);
        plain[PAGE_BODY_LEN + 2] = b'E';

        // Deliberately construct an impossible mixed-BV page. Both local
        // rows are exact witnesses, so the decoder must report ambiguity
        // instead of choosing one according to page/sector scan order.
        let mut raw = encode_ap_page(pn, 0x11, &plain);
        let raw_b = encode_ap_page(pn, 0x77, &plain);
        raw[512..1024].copy_from_slice(&raw_b[512..1024]);
        let recovery = recover_bv_from_syscolumn_tag(pn, &raw);
        assert_eq!(recovery.verified_bvs, vec![0x11, 0x77]);
        assert_eq!(recovery.bv, None);
    }

    #[test]
    fn conflicting_bvs_salvage_only_complete_schema_intersection() {
        let pn = 730u64;
        let row = synth_row("account_id", 3026, 1, 2, b'N', 4, 0, 1);
        let mut plain = vec![0u8; 4096];
        plain[80..80 + row.len()].copy_from_slice(&row);
        plain[512 + 80..512 + 80 + row.len()].copy_from_slice(&row);
        plain[PAGE_BODY_LEN + 2] = b'E';
        let mut raw = encode_ap_page(pn, 0x11, &plain);
        let raw_b = encode_ap_page(pn, 0x77, &plain);
        raw[512..1024].copy_from_slice(&raw_b[512..1024]);

        let mut rows = Vec::new();
        let recovery = scan_page_from_syscolumn_tag(pn, &raw, &mut rows);
        assert_eq!(recovery.verified_bvs, vec![0x11, 0x77]);
        assert_eq!(recovery.bv, None);
        assert_eq!(rows.len(), 1, "same schema must survive intersection");
        assert_eq!(rows[0].name, "account_id");
        assert_eq!(rows[0].table_id, 3026);
        assert_eq!(rows[0].column_id, 1);
    }

    #[test]
    fn rejects_unrelated_raw_bytes() {
        assert!(!has_obfuscated_tag_in_sector(&vec![0xA5; 4096]));
    }

    #[test]
    fn name_back_walk_skips_into_garbage_prefix() {
        // Garbage prefix followed by a valid row.
        let mut body = vec![0xAA, 0xBB, 0xCC, 0xDD];
        body.extend(synth_row("real_name", 1, 1, 2, b'N', 4, 0, 1));
        let mut out = Vec::new();
        parse_rows_in_body(&body, 0, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "real_name");
    }
}

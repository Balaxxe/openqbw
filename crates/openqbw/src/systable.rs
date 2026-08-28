//! SYSTABLE catalog row parser (Phase 4.3).
//!
//! The SA17 `SYSTABLE` system catalog stores one row per table in the
//! database. On Enterprise 24, each tag is 34 bytes into a length-delimited
//! physical row:
//!
//! ```text
//! <length: low 24 bits, flags: high 8 bits> <table_id u32 LE> ...
//! <share_type u32 LE> <object_id u64 LE> <last_modified_at raw u64 LE>
//! <name_len u8> <name> <table_type u8> <replicate u8> <server_type u8>
//! <raw layout/null byte u8> <tab_page_list locator?>
//! <ext_page_list locator?> ...
//! ```
//!
//! The low four bytes of `last_modified` were previously treated as a
//! file-specific magic. We rely on the surrounding zero markers, the name-length sanity
//! check, and the ASCII validity of the table name to disambiguate.
//!
//! The historical parser read the tag's object id as a table id and then
//! treated arbitrary following bytes as a trailer. The modern parser exposes
//! only fields proven to fit within the declared physical-row boundary.
//!
//! Rows are scanned across every decoded `E`-type page of the QBW file. The
//! same QB-specific AP-cipher recovery is used as for line-item extraction
//! (`recover_bv_qb_data` with fallback to the generic `ApModel`).
//!
//! `scan_page` accepts a tag only after proving the entire physical row fits
//! in the decoded page data region; it never reads beyond that boundary.

use std::collections::BTreeMap;
use std::iter::FusedIterator;

use opensqlany::{ApModel, MaterializedTablePage, PageStore, PageType, Result as SaResult};
use thiserror::Error;

use crate::bv_recovery::{affine_known_plaintext_witnesses, deobfuscate_with_bv};
use crate::long_value_ref::{LONG_VALUE_REF_LEN, LongValueRef, parse_long_value_ref};
use crate::{
    EnterprisePageMaterializationError, EnterprisePageTransformKey,
    materialize_enterprise_table_page_candidates_with_key, materialized_table_id,
};

const PAGE_DATA_END: usize = 0xFF0;
const NAME_LEN_MIN: u8 = 4;
const NAME_LEN_MAX: u8 = 64;
const PHYSICAL_PREFIX_LEN: usize = 34;
const TAG_MIN_LEN: usize = 21;
/// Physical table id of the materialized Enterprise 24 `SYSTABLE` carrier.
pub const MATERIALIZED_SYSTABLE_TABLE_ID: u32 = 1;
/// The three documented scalar fields plus one unclassified physical byte
/// immediately following the length-prefixed table name.
///
/// SAP's logical SYSTAB order places `encrypted` *after* `tab_page_list`,
/// `ext_page_list`, and further fields.  The fourth physical byte therefore
/// cannot be called `encrypted`.  It is retained as raw evidence only: it
/// may be a null/layout bitmap, but that bit-level interpretation has not
/// been established for Enterprise 24.
const POST_NAME_PREFIX_LEN: usize = 4;
const TABLE_TYPE_OFF: usize = 0;
const REPLICATE_OFF: usize = 1;
const SERVER_TYPE_OFF: usize = 2;
const LAYOUT_BYTE_OFF: usize = 3;
/// `tab_page_list` starts after the three scalar bytes and the one observed
/// physical layout/null byte.
const TAB_PAGE_LIST_OFF: usize = POST_NAME_PREFIX_LEN;
/// `ext_page_list` is the next 14-byte locator, when materialized in the
/// physical row. A missing or all-zero field remains `None`.
const EXT_PAGE_LIST_OFF: usize = TAB_PAGE_LIST_OFF + LONG_VALUE_REF_LEN;
/// A modern physical SYSTAB row contains this fixed little-endian share-type
/// word at the tag offset.  It is deliberately the *only* known plaintext
/// used to recover catalog pages: table names are private corpus content and
/// must never become a decryption oracle.
const SYSTAB_SHARE_TYPE_WITNESS: [u8; 4] = [0x05, 0x00, 0x00, 0x00];

/// A single parsed `SYSTABLE` row.
#[derive(Debug, Clone)]
pub struct SysTableEntry {
    /// Table id (SA internal `table_id`).
    pub table_id: u32,
    /// Object id stored in the recognizable tag. Distinct from `table_id` on
    /// modern SYSTABLE rows.
    pub object_id: u64,
    /// Declared physical row length (low 24 bits of the first u32).
    pub row_length: u32,
    /// Physical-row flags (high 8 bits of the first u32).
    pub row_flags: u8,
    /// Database space identifier at physical row offset +8.
    pub dbspace_id: u16,
    /// Persisted row count at physical row offset +10.
    pub row_count: u64,
    /// Creating user/object identifier at physical row offset +18.
    pub creator: u32,
    /// Logical table page count at physical row offset +22.
    pub table_page_count: u32,
    /// External table page count at physical row offset +26.
    pub ext_page_count: u32,
    /// Commit action at physical row offset +30.
    pub commit_action: u32,
    /// SYSTABLE share type. Enterprise 24 observations use value 5.
    pub share_type: u32,
    /// Raw SYSTABLE last-modified value at physical row offset +46.
    ///
    /// This is the on-disk representation of documented
    /// `last_modified_at`. It is intentionally left raw: no Enterprise 24
    /// timestamp epoch/scale conversion has been proven.
    pub last_modified_raw: u64,
    /// Table name (ASCII).
    pub name: String,
    /// Raw one-byte `table_type` immediately after `name`.
    pub table_type: u8,
    /// Raw one-byte `replicate` flag immediately after `table_type`.
    pub replicate: u8,
    /// Raw one-byte `server_type` immediately after `replicate`.
    pub server_type: u8,
    /// Unclassified raw physical byte immediately after `server_type`.
    ///
    /// This is deliberately not named `encrypted`: in the documented logical
    /// SYSTAB schema, that field occurs after the long-VARBIT page lists.
    /// It may encode null/layout metadata, but no bit semantics are claimed.
    pub post_name_layout_byte: u8,
    /// Direct 14-byte `tab_page_list` locator, if the entire envelope fits
    /// in this declared row and passes envelope-level validation.
    ///
    /// The locator is not dereferenced here. Its target-page selector and
    /// payload encoding remain deliberately uninterpreted.
    pub tab_page_list: Option<LongValueRef>,
    /// Direct 14-byte `ext_page_list` locator, under the same bounds and
    /// validation rules as [`Self::tab_page_list`].
    pub ext_page_list: Option<LongValueRef>,
    /// Low four bytes of [`Self::last_modified_raw`], retained for source
    /// compatibility with earlier diagnostics.
    pub magic: [u8; 4],
    /// Number of columns, if established by a dialect-specific parser.
    /// Enterprise 24 leaves this unset: its former offset could cross the
    /// physical row boundary.
    pub col_count: Option<u8>,
    /// Validated legacy candidate at trailer +34.
    ///
    /// This is `None` unless the value is non-zero, in-range for the opened
    /// store, and names an extent page. It must not be treated as a B-tree
    /// root on Enterprise 24 solely because it passed those structural gates.
    pub data_root_page: Option<u32>,
    /// Validated legacy candidate at trailer +50.
    ///
    /// As with [`Self::data_root_page`], this is only a structurally valid
    /// extent-page reference, not proof of rightmost-leaf semantics.
    pub last_page: Option<u32>,
    /// Raw u32 trailer value at +34 before page-reference validation.
    ///
    /// This is retained to support dialect diagnostics. Enterprise 24 has
    /// been observed to carry values larger than the database page count.
    pub data_root_raw: Option<u32>,
    /// Raw u32 trailer value at +50 before page-reference validation.
    pub last_page_raw: Option<u32>,
    /// Page on which this row was found.
    pub page_number: u64,
    /// Byte offset of the physical row within the decoded page body.
    pub row_offset: usize,
    /// Byte offset of the recognizable SYSTABLE tag within the decoded page.
    pub tag_offset: usize,
    /// Safe parsed rows have a complete physical prefix, hence `None`.
    /// This allows a future diagnostic-only partial-row mode without making
    /// its output look like a usable catalog entry.
    pub truncated_prefix_bytes: Option<u8>,
}

/// Independent logical expectations declared by one materialized `SYSTABLE`
/// entry for a physical application table.
///
/// These counts are catalog metadata, not observations made while decoding
/// the application table.  A table decoder can use them to reject a partial
/// directory scan rather than treating its own recovered count as proof of
/// completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaterializedTableLogicalExpectation {
    /// Physical `SYSTABLE.table_id` of the application table.
    pub table_id: u32,
    /// Independently declared logical row count.
    pub row_count: u64,
    /// Independently declared primary table-page count.
    pub table_page_count: u32,
    /// Independently declared external table-page count.
    pub ext_page_count: u32,
}

/// Aggregate result of a fail-closed materialized `SYSTABLE` collection.
#[derive(Debug, Clone)]
pub struct MaterializedSysTableCollection {
    /// Distinct logical catalog rows ordered by physical table id.
    pub tables: Vec<SysTableEntry>,
    /// Materialized physical catalog pages selected by the exact carrier id.
    pub carrier_pages: u64,
    /// Directory slots declared by the selected catalog pages.
    pub carrier_directory_slots: u64,
    /// Selected directory slots unavailable at materialization time.
    pub carrier_missing_records: u64,
    /// Accessible selected records accepted as complete `SYSTABLE` rows.
    pub carrier_parsed_records: u64,
    /// Accessible selected records not accepted as complete `SYSTABLE` rows.
    ///
    /// These records are retained as an aggregate rather than silently
    /// discarded. Callers that need a complete catalog must classify them or
    /// use [`Self::require_no_unparsed_carrier_records`].
    pub carrier_unparsed_records: u64,
    /// Accessible unparsed records that still prove the normal bounded
    /// SYSTABLE fixed prefix and its physical table id, grouped by that id.
    ///
    /// This is intentionally aggregate-only: it contains no names, row
    /// bytes, page numbers, or offsets.  It lets a caller prove that an
    /// unsupported catalog dialect cannot be a second/conflicting entry for
    /// a required application table.
    pub unparsed_fixed_prefix_table_ids: BTreeMap<u32, u64>,
    /// Unparsed records with a self-length-delimited normal fixed prefix.
    pub unparsed_self_length_fixed_prefix_records: u64,
    /// Unparsed carrier records physically shorter than the normal 34-byte
    /// SYSTABLE fixed prefix.
    ///
    /// They cannot contain the +4 table-id field in that grammar, so they
    /// cannot duplicate a required normal-prefix table entry. They remain
    /// counted as physical artifacts rather than being decoded as catalog
    /// rows.
    pub unparsed_shorter_than_fixed_prefix_records: u64,
    /// Accessible unparsed records without a bounded normal fixed prefix.
    ///
    /// Their table identity is not established, so they prevent a required
    /// table attestation from claiming that no conflicting catalog entry
    /// exists.
    pub unparsed_without_fixed_prefix: u64,
    /// Raw pages that had no usable materialized type-4 representation.
    pub skipped_pages: MaterializedSysTableSkippedPages,
}

/// Aggregate non-catalog materialization outcomes retained as provenance.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaterializedSysTableSkippedPages {
    /// Pages without a unique header transform.
    pub no_header: u64,
    /// Pages with several possible header transforms.
    pub ambiguous_header: u64,
    /// Pages that did not validate as type-4 table pages.
    pub not_type4: u64,
    /// Pages with no otherwise classified materialization result.
    pub other: u64,
}

/// Failure while collecting the materialized Enterprise `SYSTABLE` catalog.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MaterializedSysTableCollectionError {
    /// Accessible catalog-carrier records were not classified as complete
    /// `SYSTABLE` envelopes.
    #[error("materialized SYSTABLE carrier retained {count} unparsed accessible records")]
    UnparsedCarrierRecords {
        /// Number of accessible carrier records left unclassified.
        count: u64,
    },
    /// Materialization candidates for one raw page disagreed about whether it
    /// was the physical SYSTABLE carrier.
    #[error(
        "materialized candidates disagree about catalog carrier identity on physical page {page_number}"
    )]
    AmbiguousCarrierIdentity {
        /// Raw physical page number.
        page_number: u64,
    },
    /// Candidates for one selected raw page yielded different catalog rows.
    #[error("materialized SYSTABLE candidates diverged on physical page {page_number}")]
    DivergentCandidates {
        /// Raw physical page number.
        page_number: u64,
    },
    /// The same physical table id decoded to conflicting catalog metadata.
    #[error("materialized SYSTABLE table id {table_id} conflicted across pages")]
    ConflictingTable {
        /// Physical SYSTABLE table id.
        table_id: u32,
    },
    /// No complete materialized SYSTABLE entry exists for the requested
    /// physical table id.
    #[error("materialized SYSTABLE has no complete entry for table id {table_id}")]
    UnknownTableId {
        /// Requested physical table id.
        table_id: u32,
    },
    /// An unsupported but bounded normal-prefix catalog record names a table
    /// that the caller requires for extraction.
    #[error(
        "materialized SYSTABLE has {count} unsupported bounded-prefix records for required table id {table_id}"
    )]
    RequiredTableMayConflict {
        /// Required physical table id that the unsupported record names.
        table_id: u32,
        /// Number of unparsed bounded-prefix records naming it.
        count: u64,
    },
    /// An unsupported catalog record was long enough to contain the normal
    /// fixed prefix but did not prove it, so its physical table id is unknown.
    #[error(
        "materialized SYSTABLE has {count} unparsed records without a bounded fixed-prefix table id"
    )]
    UnidentifiedUnparsedCarrierRecords {
        /// Number of records with no safe fixed-prefix table-id evidence.
        count: u64,
    },
}

impl MaterializedSysTableCollection {
    /// Require every accessible carrier record to have a complete bounded
    /// SYSTABLE classification.
    pub fn require_no_unparsed_carrier_records(
        &self,
    ) -> Result<(), MaterializedSysTableCollectionError> {
        if self.carrier_unparsed_records == 0 {
            Ok(())
        } else {
            Err(
                MaterializedSysTableCollectionError::UnparsedCarrierRecords {
                    count: self.carrier_unparsed_records,
                },
            )
        }
    }

    /// Look up one complete catalog entry by its physical table id.
    pub fn table(&self, table_id: u32) -> Option<&SysTableEntry> {
        self.tables
            .binary_search_by_key(&table_id, |entry| entry.table_id)
            .ok()
            .map(|index| &self.tables[index])
    }

    /// Return independent row/page expectations for one physical table.
    pub fn logical_expectation(
        &self,
        table_id: u32,
    ) -> Result<MaterializedTableLogicalExpectation, MaterializedSysTableCollectionError> {
        let entry = self
            .table(table_id)
            .ok_or(MaterializedSysTableCollectionError::UnknownTableId { table_id })?;
        Ok(MaterializedTableLogicalExpectation {
            table_id: entry.table_id,
            row_count: entry.row_count,
            table_page_count: entry.table_page_count,
            ext_page_count: entry.ext_page_count,
        })
    }

    /// Require unambiguous, independently declared expectations for the
    /// application tables needed by one decoder.
    ///
    /// Unlike [`Self::require_no_unparsed_carrier_records`], this targeted
    /// gate does not require unsupported SYSTABLE dialects for unrelated
    /// tables to be decoded. Every requested id must have exactly one
    /// complete catalog entry; every unparsed record that is long enough to
    /// contain the normal fixed prefix must prove its table id; and none may
    /// name a requested table. Shorter carrier artifacts are explicitly
    /// permitted because they are physically incapable of containing that
    /// normal-prefix table id. Thus an unparsed record cannot silently
    /// duplicate or conflict with any expectation returned for the requested
    /// tables.
    pub fn require_unambiguous_tables(
        &self,
        table_ids: &[u32],
    ) -> Result<Vec<MaterializedTableLogicalExpectation>, MaterializedSysTableCollectionError> {
        let mut required = table_ids.to_vec();
        required.sort_unstable();
        required.dedup();
        for &table_id in &required {
            // Confirm availability before accepting unrelated unparsed rows.
            self.table(table_id)
                .ok_or(MaterializedSysTableCollectionError::UnknownTableId { table_id })?;
        }
        if self.unparsed_without_fixed_prefix != 0 {
            return Err(
                MaterializedSysTableCollectionError::UnidentifiedUnparsedCarrierRecords {
                    count: self.unparsed_without_fixed_prefix,
                },
            );
        }
        for &table_id in &required {
            if let Some(&count) = self.unparsed_fixed_prefix_table_ids.get(&table_id) {
                return Err(
                    MaterializedSysTableCollectionError::RequiredTableMayConflict {
                        table_id,
                        count,
                    },
                );
            }
        }
        required
            .into_iter()
            .map(|table_id| self.logical_expectation(table_id))
            .collect()
    }
}

impl SysTableEntry {
    /// Return the raw on-disk value of documented `last_modified_at`.
    ///
    /// Kept as a method as well as the historical `last_modified_raw` field
    /// so callers do not accidentally imply that it has already been
    /// converted to a wall-clock timestamp.
    pub const fn last_modified_at_raw(&self) -> u64 {
        self.last_modified_raw
    }
}

/// Privacy-safe aggregate evidence for the Enterprise 24 post-name layout.
///
/// The maps expose only byte-value frequencies and locator presence; they do
/// not expose table names, payload bytes, or decoded long values. This is
/// suitable for a corpus-level diagnostic without turning a locator into a
/// claimed table-page mapping.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SysTablePostNameDiagnostics {
    /// Number of complete SYSTAB physical rows examined.
    pub rows: u64,
    /// Rows with a structurally valid, in-store `tab_page_list` locator.
    pub tab_page_list_refs: u64,
    /// Rows with a structurally valid, in-store `ext_page_list` locator.
    pub ext_page_list_refs: u64,
    /// Frequency of each raw documented `table_type` byte.
    pub table_type_values: BTreeMap<u8, u64>,
    /// Frequency of each raw documented `replicate` byte.
    pub replicate_values: BTreeMap<u8, u64>,
    /// Frequency of each raw documented `server_type` byte.
    pub server_type_values: BTreeMap<u8, u64>,
    /// Frequency of the unclassified physical byte after `server_type`.
    pub post_name_layout_byte_values: BTreeMap<u8, u64>,
}

/// Aggregate post-name SYSTAB diagnostics from complete parsed rows.
///
/// This deliberately accepts entries rather than a file path so tooling may
/// choose its own deobfuscation/provenance policy. The usual live path is
/// `aggregate_post_name_diagnostics(iter_systable_entries(&store, &model))`.
pub fn aggregate_post_name_diagnostics(
    entries: impl IntoIterator<Item = SysTableEntry>,
) -> SysTablePostNameDiagnostics {
    let mut result = SysTablePostNameDiagnostics::default();
    for entry in entries {
        result.rows += 1;
        result.tab_page_list_refs += u64::from(entry.tab_page_list.is_some());
        result.ext_page_list_refs += u64::from(entry.ext_page_list.is_some());
        *result
            .table_type_values
            .entry(entry.table_type)
            .or_default() += 1;
        *result.replicate_values.entry(entry.replicate).or_default() += 1;
        *result
            .server_type_values
            .entry(entry.server_type)
            .or_default() += 1;
        *result
            .post_name_layout_byte_values
            .entry(entry.post_name_layout_byte)
            .or_default() += 1;
    }
    result
}

/// Scan a decoded page body for `SYSTABLE` row tags and append parsed
/// entries to `out`. Matches every occurrence of the 16-byte framed tag
/// followed by a plausible name-length byte; the file-specific 4-byte
/// magic is accepted as wildcard.
pub fn scan_page(body: &[u8], pn: u64, out: &mut Vec<SysTableEntry>) {
    if body.len() < TAG_MIN_LEN {
        return;
    }
    let end = body.len().min(PAGE_DATA_END);
    if end < TAG_MIN_LEN {
        return;
    }
    let limit = end - TAG_MIN_LEN;
    let mut pos = 0usize;
    while pos <= limit {
        // Match the fixed share-type word. The next eight bytes are the
        // complete u64 object id, so neither half may be assumed zero.
        if body[pos] != 0x05
            || body[pos + 1] != 0x00
            || body[pos + 2] != 0x00
            || body[pos + 3] != 0x00
        {
            pos += 1;
            continue;
        }
        // Bytes +12..+19 are the full u64 `last_modified` value; they are
        // deliberately unconstrained here.
        if pos + TAG_MIN_LEN > end {
            break;
        }
        let name_len = body[pos + 20];
        if !(NAME_LEN_MIN..=NAME_LEN_MAX).contains(&name_len) {
            pos += 1;
            continue;
        }
        let name_start = pos + TAG_MIN_LEN;
        let name_end = name_start + name_len as usize;
        if name_end > end {
            pos += 1;
            continue;
        }
        let name_bytes = &body[name_start..name_end];
        if !name_bytes.iter().all(|&b| (32..127).contains(&b)) {
            pos += 1;
            continue;
        }

        // A modern SYSTABLE tag is not a row start. Reject a truncated
        // prefix rather than guessing a table id from the object id.
        let Some(row_start) = pos.checked_sub(PHYSICAL_PREFIX_LEN) else {
            pos += 1;
            continue;
        };
        let row_header = read_u32_le(body, row_start).expect("row start is in bounds");
        let row_length = row_header & 0x00ff_ffff;
        let row_flags = (row_header >> 24) as u8;
        let Some(row_end) = row_start.checked_add(row_length as usize) else {
            pos += 1;
            continue;
        };
        if (row_length as usize)
            < PHYSICAL_PREFIX_LEN + TAG_MIN_LEN + name_len as usize + POST_NAME_PREFIX_LEN
            || row_end > end
            || name_end > row_end
        {
            pos += 1;
            continue;
        }
        let table_id = read_u32_le(body, row_start + 4).expect("physical prefix fits row");
        let dbspace_id = read_u16_le(body, row_start + 8).expect("physical row fits name");
        let row_count = read_u64_le(body, row_start + 10).expect("physical row fits name");
        let creator = read_u32_le(body, row_start + 18).expect("physical row fits name");
        let table_page_count = read_u32_le(body, row_start + 22).expect("physical row fits name");
        let ext_page_count = read_u32_le(body, row_start + 26).expect("physical row fits name");
        let commit_action = read_u32_le(body, row_start + 30).expect("physical row fits name");
        let share_type = read_u32_le(body, pos).expect("tag fits row");
        let object_id = read_u64_le(body, pos + 4).expect("tag object id fits row");
        let last_modified_raw = read_u64_le(body, pos + 12).expect("tag fits row");
        let magic = [
            body[pos + 12],
            body[pos + 13],
            body[pos + 14],
            body[pos + 15],
        ];
        let name = std::str::from_utf8(name_bytes)
            .expect("name guarded by printable-ASCII check")
            .to_owned();

        // The post-name layout is independently bounded by `row_end`, not
        // merely the page body. This is essential because physical SYSTAB
        // rows are adjacent and a short row's next bytes may resemble a
        // valid long-value envelope belonging to the following row.
        let post_name_start = name_end;
        let post_name = &body[post_name_start..row_end];
        let table_type = post_name
            .get(TABLE_TYPE_OFF)
            .copied()
            .expect("row-length check leaves the post-name prefix");
        let replicate = post_name
            .get(REPLICATE_OFF)
            .copied()
            .expect("row-length check leaves the post-name prefix");
        let server_type = post_name
            .get(SERVER_TYPE_OFF)
            .copied()
            .expect("row-length check leaves the post-name prefix");
        let post_name_layout_byte = post_name
            .get(LAYOUT_BYTE_OFF)
            .copied()
            .expect("row-length check leaves the post-name prefix");
        let tab_page_list = parse_post_name_ref(post_name, TAB_PAGE_LIST_OFF);
        let ext_page_list = parse_post_name_ref(post_name, EXT_PAGE_LIST_OFF);

        out.push(SysTableEntry {
            table_id,
            object_id,
            row_length,
            row_flags,
            dbspace_id,
            row_count,
            creator,
            table_page_count,
            ext_page_count,
            commit_action,
            share_type,
            last_modified_raw,
            name,
            table_type,
            replicate,
            server_type,
            post_name_layout_byte,
            tab_page_list,
            ext_page_list,
            magic,
            col_count: None,
            data_root_page: None,
            last_page: None,
            data_root_raw: None,
            last_page_raw: None,
            page_number: pn,
            row_offset: row_start,
            tag_offset: pos,
            truncated_prefix_bytes: None,
        });
        pos = row_end;
    }
}

/// Parse one fully bounded materialized `SYSTABLE` record.
///
/// The caller must already have identified the materialized carrier page.
/// This requires exactly one existing strict SYSTABLE row whose compact
/// declared length fills the directory-bounded physical record; it does not
/// search across neighboring records.
pub fn parse_materialized_systable_record(
    record: &[u8],
    page_number: u64,
    record_offset: usize,
) -> Option<SysTableEntry> {
    let mut entries = Vec::new();
    scan_page(record, page_number, &mut entries);
    let mut entries = entries.into_iter().filter(|entry| {
        entry.row_offset == 0 && usize::try_from(entry.row_length).ok() == Some(record.len())
    });
    let mut entry = entries.next()?;
    if entries.next().is_some() {
        return None;
    }
    entry.row_offset = record_offset;
    entry.tag_offset = record_offset.checked_add(entry.tag_offset)?;
    Some(entry)
}

/// Recover a physical table id from the normal bounded SYSTABLE fixed prefix
/// without claiming that the record's variable catalog dialect is understood.
///
/// The directory provides the outer record boundary. This requires a complete
/// 34-byte fixed prefix and an exact self-length declaration, which proves
/// the +4 table-id field belongs to this record. It intentionally does not
/// parse names, tags, or post-prefix fields and does not create a catalog row.
fn self_length_bounded_systable_fixed_prefix_table_id(record: &[u8]) -> Option<u32> {
    if record.len() < PHYSICAL_PREFIX_LEN {
        return None;
    }
    let header = read_u32_le(record, 0)?;
    let declared = usize::try_from(header & 0x00ff_ffff).ok()?;
    if declared != record.len() {
        return None;
    }
    read_u32_le(record, 4)
}

/// Scan exact bounded `SYSTABLE` records from one identified materialized
/// carrier page.
pub fn scan_materialized_systable_records(
    page: MaterializedTablePage<'_>,
    page_number: u64,
) -> Vec<SysTableEntry> {
    let mut entries = Vec::new();
    for record_id in 0..page.record_count() {
        let Ok(record) = page.record(record_id) else {
            continue;
        };
        if let Some(entry) =
            parse_materialized_systable_record(record.bytes(), page_number, record.byte_offset())
        {
            entries.push(entry);
        }
    }
    entries
}

/// Collect the complete bounded `SYSTABLE` catalog from a local Enterprise
/// materialized-page store.
///
/// Only pages whose proven physical table id equals
/// [`MATERIALIZED_SYSTABLE_TABLE_ID`] participate. When a raw page has
/// multiple structurally valid materializations, each candidate must identify
/// the page as SYSTABLE and decode the same complete semantic catalog set;
/// otherwise collection fails instead of choosing a transform candidate by
/// order. Repeated physical catalog records are accepted only when their
/// complete logical metadata agrees exactly.
///
/// The returned [`MaterializedSysTableCollection::logical_expectation`] is
/// intended for application-table decoders: its row/page counts come from
/// SYSTABLE, independently of the application-page scan being checked.
pub fn collect_materialized_systables(
    store: &PageStore,
    key: EnterprisePageTransformKey,
) -> Result<MaterializedSysTableCollection, MaterializedSysTableCollectionError> {
    let mut carrier_pages = 0_u64;
    let mut carrier_directory_slots = 0_u64;
    let mut carrier_missing_records = 0_u64;
    let mut carrier_parsed_records = 0_u64;
    let mut carrier_unparsed_records = 0_u64;
    let mut unparsed_fixed_prefix_table_ids = BTreeMap::<u32, u64>::new();
    let mut unparsed_self_length_fixed_prefix_records = 0_u64;
    let mut unparsed_shorter_than_fixed_prefix_records = 0_u64;
    let mut unparsed_without_fixed_prefix = 0_u64;
    let mut skipped_pages = MaterializedSysTableSkippedPages::default();
    let mut tables = BTreeMap::<u32, SysTableEntry>::new();

    for raw in store.pages() {
        let page_number = raw.index();
        let candidates = match materialize_enterprise_table_page_candidates_with_key(
            raw.bytes(),
            page_number,
            key,
        ) {
            Ok(candidates) => candidates,
            Err(error) => {
                record_materialized_systable_skip(&mut skipped_pages, error);
                continue;
            }
        };
        let mut candidate_table_ids = BTreeMap::new();
        for (candidate_index, candidate) in candidates.iter().enumerate() {
            if let Ok(table_id) = materialized_table_id(candidate.bytes()) {
                candidate_table_ids.insert(candidate_index, table_id.get());
            }
        }
        let carrier_candidate_count = candidate_table_ids
            .values()
            .filter(|&&table_id| table_id == MATERIALIZED_SYSTABLE_TABLE_ID)
            .count();
        if carrier_candidate_count == 0 {
            continue;
        }
        if carrier_candidate_count != candidates.len()
            || candidate_table_ids.len() != candidates.len()
        {
            return Err(
                MaterializedSysTableCollectionError::AmbiguousCarrierIdentity { page_number },
            );
        }

        let mut decoded = Vec::new();
        for candidate in candidates {
            let table_page = candidate.table_page();
            let mut parsed = Vec::new();
            let mut missing = 0_u64;
            let mut unparsed = 0_u64;
            let mut unparsed_table_ids = BTreeMap::<u32, u64>::new();
            let mut unparsed_without_prefix = 0_u64;
            let mut unparsed_self_length_fixed_prefix = 0_u64;
            let mut unparsed_shorter_than_fixed_prefix = 0_u64;
            for record_id in 0..table_page.record_count() {
                let Ok(record) = table_page.record(record_id) else {
                    missing += 1;
                    continue;
                };
                if let Some(entry) = parse_materialized_systable_record(
                    record.bytes(),
                    page_number,
                    record.byte_offset(),
                ) {
                    parsed.push(entry);
                } else {
                    unparsed += 1;
                    if record.bytes().len() < PHYSICAL_PREFIX_LEN {
                        unparsed_shorter_than_fixed_prefix += 1;
                    } else if let Some(table_id) =
                        self_length_bounded_systable_fixed_prefix_table_id(record.bytes())
                    {
                        *unparsed_table_ids.entry(table_id).or_default() += 1;
                        unparsed_self_length_fixed_prefix += 1;
                    } else {
                        unparsed_without_prefix += 1;
                    }
                }
            }
            decoded.push((
                parsed,
                u64::from(table_page.record_count()),
                missing,
                unparsed,
                unparsed_table_ids,
                unparsed_without_prefix,
                unparsed_self_length_fixed_prefix,
                unparsed_shorter_than_fixed_prefix,
            ));
        }
        let mut semantic = Vec::new();
        for (entries, _, _, _, _, _, _, _) in &decoded {
            let mut per_candidate = BTreeMap::new();
            for entry in entries {
                match per_candidate.get(&entry.table_id) {
                    Some(existing) if !systab_entry_semantic_equal(existing, entry) => {
                        // A single transform candidate already contains two
                        // incompatible values for a table-id identity. It is
                        // unsafe even if no second transform candidate exists.
                        return Err(MaterializedSysTableCollectionError::ConflictingTable {
                            table_id: entry.table_id,
                        });
                    }
                    Some(_) => {}
                    None => {
                        per_candidate.insert(entry.table_id, entry.clone());
                    }
                }
            }
            semantic.push(per_candidate);
        }
        if semantic.windows(2).any(|pair| {
            pair[0].len() != pair[1].len()
                || pair[0]
                    .iter()
                    .any(|(table_id, entry)| match pair[1].get(table_id) {
                        Some(other) => !systab_entry_semantic_equal(entry, other),
                        None => true,
                    })
        }) || decoded.windows(2).any(|pair| {
            (
                pair[0].1, pair[0].2, pair[0].3, &pair[0].4, pair[0].5, pair[0].6, pair[0].7,
            ) != (
                pair[1].1, pair[1].2, pair[1].3, &pair[1].4, pair[1].5, pair[1].6, pair[1].7,
            )
        }) {
            return Err(MaterializedSysTableCollectionError::DivergentCandidates { page_number });
        }
        carrier_pages += 1;
        carrier_directory_slots += decoded[0].1;
        carrier_missing_records += decoded[0].2;
        carrier_parsed_records += u64::try_from(decoded[0].0.len()).expect("usize fits u64");
        carrier_unparsed_records += decoded[0].3;
        for (&table_id, &count) in &decoded[0].4 {
            *unparsed_fixed_prefix_table_ids.entry(table_id).or_default() += count;
        }
        unparsed_without_fixed_prefix += decoded[0].5;
        unparsed_self_length_fixed_prefix_records += decoded[0].6;
        unparsed_shorter_than_fixed_prefix_records += decoded[0].7;
        for entry in semantic[0].values() {
            match tables.get(&entry.table_id) {
                Some(existing) if !systab_entry_semantic_equal(existing, entry) => {
                    return Err(MaterializedSysTableCollectionError::ConflictingTable {
                        table_id: entry.table_id,
                    });
                }
                Some(_) => {}
                None => {
                    tables.insert(entry.table_id, entry.clone());
                }
            }
        }
    }
    Ok(MaterializedSysTableCollection {
        tables: tables.into_values().collect(),
        carrier_pages,
        carrier_directory_slots,
        carrier_missing_records,
        carrier_parsed_records,
        carrier_unparsed_records,
        unparsed_fixed_prefix_table_ids,
        unparsed_self_length_fixed_prefix_records,
        unparsed_shorter_than_fixed_prefix_records,
        unparsed_without_fixed_prefix,
        skipped_pages,
    })
}

fn record_materialized_systable_skip(
    skipped: &mut MaterializedSysTableSkippedPages,
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

/// Recover complete SYSTAB rows from one raw extent page using only the
/// fixed share-type affine witness.
///
/// The generic AP recovery cascade contains a zero-density fallback which is
/// useful for exploratory page work but is not adequate provenance for the
/// catalog that identifies accounting tables.  Here every candidate page BV
/// is algebraically derived from a full four-byte affine witness.  A
/// candidate is productive only if [`scan_page`] proves the row's low-24-bit
/// physical length, prefix, name, and post-name prefix all fit within the
/// page.  If more than one productive BV remains, only byte-for-byte
/// identical parsed entries are retained.  This is intentionally fail-closed
/// against short-witness collisions.
///
/// The return tuple is `(candidate_bvs, productive_bvs, accepted_rows)`. The
/// two counts are diagnostic evidence; callers must use only `accepted_rows`
/// as catalog data.
pub fn scan_raw_page_with_affine_witness(
    raw: &[u8],
    pn: u64,
) -> (Vec<u8>, Vec<u8>, Vec<SysTableEntry>) {
    let mut candidate_bvs: Vec<u8> =
        affine_known_plaintext_witnesses(pn, raw, &SYSTAB_SHARE_TYPE_WITNESS)
            .into_iter()
            .map(|w| w.bv)
            .collect();
    candidate_bvs.sort_unstable();
    candidate_bvs.dedup();

    let mut decoded: Vec<(u8, Vec<SysTableEntry>)> = Vec::new();
    for bv in &candidate_bvs {
        let plain = deobfuscate_with_bv(raw, pn, *bv);
        let mut entries = Vec::new();
        scan_page(&plain, pn, &mut entries);
        if !entries.is_empty() {
            decoded.push((*bv, entries));
        }
    }
    let productive_bvs = decoded.iter().map(|(bv, _)| *bv).collect();
    let accepted_rows = match decoded.len() {
        0 => Vec::new(),
        1 => decoded.pop().expect("one decoded candidate").1,
        _ => {
            // Retain an entry only if its complete parsed representation is
            // identical for every productive candidate.  Matching merely a
            // table name or id would let a false decryption bless locators.
            let first = &decoded[0].1;
            first
                .iter()
                .filter(|entry| {
                    decoded.iter().skip(1).all(|(_, other)| {
                        other
                            .iter()
                            .any(|candidate| systab_entry_equal(entry, candidate))
                    })
                })
                .cloned()
                .collect()
        }
    };
    (candidate_bvs, productive_bvs, accepted_rows)
}

/// Full parsed-row equality used only for intersection of independently
/// witnessed decryptions. Keep this explicit rather than comparing a reduced
/// identity tuple: page-list locators are part of the security boundary.
fn systab_entry_equal(left: &SysTableEntry, right: &SysTableEntry) -> bool {
    left.table_id == right.table_id
        && left.object_id == right.object_id
        && left.row_length == right.row_length
        && left.row_flags == right.row_flags
        && left.dbspace_id == right.dbspace_id
        && left.row_count == right.row_count
        && left.creator == right.creator
        && left.table_page_count == right.table_page_count
        && left.ext_page_count == right.ext_page_count
        && left.commit_action == right.commit_action
        && left.share_type == right.share_type
        && left.last_modified_raw == right.last_modified_raw
        && left.name == right.name
        && left.table_type == right.table_type
        && left.replicate == right.replicate
        && left.server_type == right.server_type
        && left.post_name_layout_byte == right.post_name_layout_byte
        && left.tab_page_list == right.tab_page_list
        && left.ext_page_list == right.ext_page_list
        && left.magic == right.magic
        && left.col_count == right.col_count
        && left.data_root_page == right.data_root_page
        && left.last_page == right.last_page
        && left.data_root_raw == right.data_root_raw
        && left.last_page_raw == right.last_page_raw
        && left.page_number == right.page_number
        && left.row_offset == right.row_offset
        && left.tag_offset == right.tag_offset
        && left.truncated_prefix_bytes == right.truncated_prefix_bytes
}

/// Complete logical SYSTABLE equality for the materialized carrier.
///
/// Physical page/record coordinates deliberately do not participate: two
/// exact materialization candidates can represent the same catalog row at a
/// different byte placement. Every catalog field that can affect a decoder's
/// expectation does participate, so this is not merely a table-id match.
fn systab_entry_semantic_equal(left: &SysTableEntry, right: &SysTableEntry) -> bool {
    left.table_id == right.table_id
        && left.object_id == right.object_id
        && left.row_length == right.row_length
        && left.row_flags == right.row_flags
        && left.dbspace_id == right.dbspace_id
        && left.row_count == right.row_count
        && left.creator == right.creator
        && left.table_page_count == right.table_page_count
        && left.ext_page_count == right.ext_page_count
        && left.commit_action == right.commit_action
        && left.share_type == right.share_type
        && left.last_modified_raw == right.last_modified_raw
        && left.name == right.name
        && left.table_type == right.table_type
        && left.replicate == right.replicate
        && left.server_type == right.server_type
        && left.post_name_layout_byte == right.post_name_layout_byte
        && left.tab_page_list == right.tab_page_list
        && left.ext_page_list == right.ext_page_list
        && left.magic == right.magic
        && left.col_count == right.col_count
        && left.data_root_page == right.data_root_page
        && left.last_page == right.last_page
        && left.data_root_raw == right.data_root_raw
        && left.last_page_raw == right.last_page_raw
        && left.truncated_prefix_bytes == right.truncated_prefix_bytes
}

/// Parse a direct post-name long locator without dereferencing it.
///
/// `scan_page` does not receive a `PageStore`, so no target page can be
/// proved in-range at this layer. Passing the largest possible bound retains
/// the envelope's exact-width, marker, nonzero-length, and nonzero-target
/// checks. `iter_systable_entries` subsequently clears locators whose target
/// is not an extent page in the opened store.
fn parse_post_name_ref(post_name: &[u8], offset: usize) -> Option<LongValueRef> {
    let bytes = post_name.get(offset..offset.checked_add(LONG_VALUE_REF_LEN)?)?;
    parse_long_value_ref(bytes, u64::MAX).ok()
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    if buf.len() < off + 4 {
        return None;
    }
    Some(u32::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
    ]))
}

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(buf.get(off..off + 2)?.try_into().ok()?))
}

fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(buf.get(off..off + 8)?.try_into().ok()?))
}

/// Clear candidate SYSTABLE page references that cannot name an extent page
/// in `store`. The legacy offsets are not stable across every QuickBooks
/// dialect; retaining raw values separately prevents invalid metadata from
/// becoming an attribution anchor.
fn validate_page_references(entry: &mut SysTableEntry, store: &PageStore) {
    entry.data_root_page = validated_extent_page(entry.data_root_raw, store);
    entry.last_page = validated_extent_page(entry.last_page_raw, store);
    entry.tab_page_list = validated_long_value_ref(entry.tab_page_list, store);
    entry.ext_page_list = validated_long_value_ref(entry.ext_page_list, store);
}

/// Retain a SYSTAB long-value locator only when its target names a physically
/// present extent page. This validates no payload/selector semantics.
fn validated_long_value_ref(
    value: Option<LongValueRef>,
    store: &PageStore,
) -> Option<LongValueRef> {
    let value = value?;
    validated_extent_page(Some(value.target_page), store).map(|_| value)
}

fn validated_extent_page(candidate: Option<u32>, store: &PageStore) -> Option<u32> {
    let page = candidate?;
    if page == 0 || u64::from(page) >= store.page_count() {
        return None;
    }
    store
        .page(u64::from(page))
        .ok()
        .filter(|p| p.trailer().page_type() == PageType::Extent)
        .map(|_| page)
}

/// Iterate every `SYSTABLE` row recovered from `store`.
///
/// Pages without an exact four-byte share-type affine witness, or whose
/// witnessed decryptions remain ambiguous, are silently skipped. Rows are
/// yielded in the order they are encountered; callers wanting a canonical
/// catalog should call [`collect_unique`] instead.
pub fn iter_systable_entries<'a>(
    store: &'a PageStore,
    _model: &'a ApModel,
) -> impl Iterator<Item = SysTableEntry> + 'a {
    SysTableIter::new(store)
}

/// Collect a deduplicated catalog keyed by `(table_id, name)`, choosing
/// the first occurrence found.
pub fn collect_unique(store: &PageStore, model: &ApModel) -> Vec<SysTableEntry> {
    let mut uniq: BTreeMap<(u32, String), SysTableEntry> = BTreeMap::new();
    for entry in iter_systable_entries(store, model) {
        uniq.entry((entry.table_id, entry.name.clone()))
            .or_insert(entry);
    }
    uniq.into_values().collect()
}

struct SysTableIter<'a> {
    store: &'a PageStore,
    pn: u64,
    n_pages: u64,
    buffer: Vec<SysTableEntry>,
}

impl<'a> SysTableIter<'a> {
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
            if page.trailer().page_type() != PageType::Extent {
                continue;
            }
            let raw = page.bytes();
            let (_, _, found) = scan_raw_page_with_affine_witness(raw, pn);
            // Reverse so we pop in source order.
            for mut entry in found.into_iter().rev() {
                validate_page_references(&mut entry, self.store);
                self.buffer.push(entry);
            }
        }
        Ok(!self.buffer.is_empty())
    }
}

impl Iterator for SysTableIter<'_> {
    type Item = SysTableEntry;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(entry) = self.buffer.pop() {
                return Some(entry);
            }
            match self.fill_buffer() {
                Ok(true) => continue,
                _ => return None,
            }
        }
    }
}

impl FusedIterator for SysTableIter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn ap_encode_with_bv(plain: &[u8], pn: u64, bv: u8) -> Vec<u8> {
        assert_eq!(plain.len(), 4096);
        let bias = ((pn % 16) as u8 / 2) * 4;
        let mut raw = plain.to_vec();
        for sector in 0..8usize {
            let start = sector * 512;
            let end = if sector == 7 {
                PAGE_DATA_END
            } else {
                start + 512
            };
            let base = bv
                .wrapping_add(pn as u8)
                .wrapping_add(sector as u8)
                .wrapping_sub(bias);
            // Zero step keeps the synthetic page easy to audit. The decoder
            // still derives its step from the raw bytes, rather than trusting
            // this helper.
            for byte in &mut raw[start..end] {
                *byte = byte.wrapping_add(base);
            }
        }
        raw
    }

    /// Build a complete modern SYSTABLE physical row.
    fn synth_row(tid: u32, object_id: u64, flags: u8, magic: [u8; 4], name: &str) -> Vec<u8> {
        let mut out = vec![0u8; PHYSICAL_PREFIX_LEN];
        out[4..8].copy_from_slice(&tid.to_le_bytes());
        out.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]);
        out.extend_from_slice(&object_id.to_le_bytes());
        out.extend_from_slice(&magic);
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        // Default system-table form: the fixed post-name prefix and a
        // NULL/absent `tab_page_list` envelope. Live Enterprise 24 catalog
        // rows have at least these 18 bytes after the name.
        // table_type, replicate, server_type, then an unclassified
        // null/layout byte.  The latter is not the documented `encrypted`
        // field, which follows the page-list columns logically.
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&[0; LONG_VALUE_REF_LEN]);
        let header = (out.len() as u32) | ((flags as u32) << 24);
        out[..4].copy_from_slice(&header.to_le_bytes());
        out
    }

    fn materialized_entry(table_id: u32, name: &str) -> SysTableEntry {
        let mut row = synth_row(table_id, u64::from(table_id) + 100, 0, [1, 2, 3, 4], name);
        row[10..18].copy_from_slice(&42_u64.to_le_bytes());
        row[22..26].copy_from_slice(&7_u32.to_le_bytes());
        row[26..30].copy_from_slice(&2_u32.to_le_bytes());
        parse_materialized_systable_record(&row, 17, 0x40).expect("synthetic bounded row")
    }

    #[test]
    fn materialized_collection_exposes_independent_table_expectation() {
        let entry = materialized_entry(3026, "sample_account");
        let collection = MaterializedSysTableCollection {
            tables: vec![entry],
            carrier_pages: 1,
            carrier_directory_slots: 1,
            carrier_missing_records: 0,
            carrier_parsed_records: 1,
            carrier_unparsed_records: 0,
            unparsed_fixed_prefix_table_ids: BTreeMap::new(),
            unparsed_self_length_fixed_prefix_records: 0,
            unparsed_shorter_than_fixed_prefix_records: 0,
            unparsed_without_fixed_prefix: 0,
            skipped_pages: MaterializedSysTableSkippedPages::default(),
        };
        assert_eq!(collection.table(3026).unwrap().name, "sample_account");
        assert_eq!(
            collection.logical_expectation(3026).unwrap(),
            MaterializedTableLogicalExpectation {
                table_id: 3026,
                row_count: 42,
                table_page_count: 7,
                ext_page_count: 2,
            }
        );
        assert_eq!(
            collection.logical_expectation(9999),
            Err(MaterializedSysTableCollectionError::UnknownTableId { table_id: 9999 })
        );
    }

    #[test]
    fn materialized_collection_requires_explicit_unparsed_record_classification() {
        let collection = MaterializedSysTableCollection {
            tables: Vec::new(),
            carrier_pages: 1,
            carrier_directory_slots: 2,
            carrier_missing_records: 0,
            carrier_parsed_records: 1,
            carrier_unparsed_records: 1,
            unparsed_fixed_prefix_table_ids: BTreeMap::new(),
            unparsed_self_length_fixed_prefix_records: 0,
            unparsed_shorter_than_fixed_prefix_records: 0,
            unparsed_without_fixed_prefix: 1,
            skipped_pages: MaterializedSysTableSkippedPages::default(),
        };
        assert_eq!(
            collection.require_no_unparsed_carrier_records(),
            Err(MaterializedSysTableCollectionError::UnparsedCarrierRecords { count: 1 })
        );
    }

    #[test]
    fn required_table_gate_allows_only_unrelated_identified_dialect_records() {
        let entry = materialized_entry(3026, "sample_account");
        let collection = MaterializedSysTableCollection {
            tables: vec![entry],
            carrier_pages: 1,
            carrier_directory_slots: 2,
            carrier_missing_records: 0,
            carrier_parsed_records: 1,
            carrier_unparsed_records: 1,
            unparsed_fixed_prefix_table_ids: BTreeMap::from([(9999, 1)]),
            unparsed_self_length_fixed_prefix_records: 1,
            unparsed_shorter_than_fixed_prefix_records: 0,
            unparsed_without_fixed_prefix: 0,
            skipped_pages: MaterializedSysTableSkippedPages::default(),
        };
        assert_eq!(
            collection
                .require_unambiguous_tables(&[3026, 3026])
                .unwrap(),
            vec![MaterializedTableLogicalExpectation {
                table_id: 3026,
                row_count: 42,
                table_page_count: 7,
                ext_page_count: 2,
            }]
        );
    }

    #[test]
    fn required_table_gate_rejects_conflict_or_unknown_unparsed_identity() {
        let entry = materialized_entry(3026, "sample_account");
        let mut collection = MaterializedSysTableCollection {
            tables: vec![entry],
            carrier_pages: 1,
            carrier_directory_slots: 2,
            carrier_missing_records: 0,
            carrier_parsed_records: 1,
            carrier_unparsed_records: 1,
            unparsed_fixed_prefix_table_ids: BTreeMap::from([(3026, 1)]),
            unparsed_self_length_fixed_prefix_records: 1,
            unparsed_shorter_than_fixed_prefix_records: 0,
            unparsed_without_fixed_prefix: 0,
            skipped_pages: MaterializedSysTableSkippedPages::default(),
        };
        assert_eq!(
            collection.require_unambiguous_tables(&[3026]),
            Err(
                MaterializedSysTableCollectionError::RequiredTableMayConflict {
                    table_id: 3026,
                    count: 1,
                }
            )
        );
        collection.unparsed_fixed_prefix_table_ids.clear();
        collection.unparsed_without_fixed_prefix = 1;
        assert_eq!(
            collection.require_unambiguous_tables(&[3026]),
            Err(
                MaterializedSysTableCollectionError::UnidentifiedUnparsedCarrierRecords {
                    count: 1,
                }
            )
        );
    }

    #[test]
    fn fixed_prefix_identity_requires_a_complete_self_length_delimited_prefix() {
        let row = synth_row(3026, 4126, 0, [0; 4], "sample_account");
        assert_eq!(
            self_length_bounded_systable_fixed_prefix_table_id(&row),
            Some(3026)
        );
        let mut wrong_length = row;
        wrong_length[..4].copy_from_slice(&99_u32.to_le_bytes());
        assert_eq!(
            self_length_bounded_systable_fixed_prefix_table_id(&wrong_length),
            None
        );
        assert_eq!(
            self_length_bounded_systable_fixed_prefix_table_id(&wrong_length[..33]),
            None
        );
    }

    #[test]
    fn materialized_systable_semantic_equality_ignores_coordinates_only() {
        let first = materialized_entry(3026, "sample_account");
        let mut same = first.clone();
        same.page_number = 19;
        same.row_offset = 0x80;
        same.tag_offset = 0xa2;
        assert!(systab_entry_semantic_equal(&first, &same));
        same.row_count += 1;
        assert!(!systab_entry_semantic_equal(&first, &same));
    }

    #[test]
    fn scan_finds_single_row() {
        let mut body = vec![0u8; 0x100];
        let mut row = synth_row(
            5887,
            0x0000_0001_0000_1771,
            3,
            [0xb1, 0x0d, 0x19, 0x0d],
            "abmc_invoice_header",
        );
        row[8..10].copy_from_slice(&7u16.to_le_bytes());
        row[10..18].copy_from_slice(&123_456u64.to_le_bytes());
        row[18..22].copy_from_slice(&99u32.to_le_bytes());
        row[22..26].copy_from_slice(&44u32.to_le_bytes());
        row[26..30].copy_from_slice(&11u32.to_le_bytes());
        row[30..34].copy_from_slice(&2u32.to_le_bytes());
        row[46..54].copy_from_slice(&0x1122_3344_0d19_0db1u64.to_le_bytes());
        body[0x20..0x20 + row.len()].copy_from_slice(&row);
        let mut out = Vec::new();
        scan_page(&body, 42, &mut out);
        assert_eq!(out.len(), 1);
        let e = &out[0];
        assert_eq!(e.table_id, 5887);
        assert_eq!(e.object_id, 0x0000_0001_0000_1771);
        assert_eq!(e.row_flags, 3);
        assert_eq!(e.dbspace_id, 7);
        assert_eq!(e.row_count, 123_456);
        assert_eq!(e.creator, 99);
        assert_eq!(e.table_page_count, 44);
        assert_eq!(e.ext_page_count, 11);
        assert_eq!(e.commit_action, 2);
        assert_eq!(e.share_type, 5);
        assert_eq!(e.last_modified_raw, 0x1122_3344_0d19_0db1);
        assert_eq!(e.last_modified_at_raw(), 0x1122_3344_0d19_0db1);
        assert_eq!(e.table_type, 0);
        assert_eq!(e.replicate, 0);
        assert_eq!(e.server_type, 0);
        assert_eq!(e.post_name_layout_byte, 0);
        assert_eq!(e.tab_page_list, None);
        assert_eq!(e.ext_page_list, None);
        assert_eq!(e.name, "abmc_invoice_header");
        assert_eq!(e.magic, [0xb1, 0x0d, 0x19, 0x0d]);
        assert_eq!(e.page_number, 42);
        assert_eq!(e.row_offset, 0x20);
        assert_eq!(e.tag_offset, 0x20 + PHYSICAL_PREFIX_LEN);
    }

    #[test]
    fn strict_affine_witness_recovers_complete_catalog_row_without_generic_bv() {
        let pn = 42;
        let bv = 91;
        let mut plain = vec![0u8; 4096];
        let row = synth_row(3026, 4014, 0, [0; 4], "abmc_account_user");
        plain[0x20..0x20 + row.len()].copy_from_slice(&row);
        let raw = ap_encode_with_bv(&plain, pn, bv);

        let (candidates, productive, rows) = scan_raw_page_with_affine_witness(&raw, pn);
        assert!(candidates.contains(&bv));
        assert_eq!(productive, vec![bv]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].table_id, 3026);
        assert_eq!(rows[0].name, "abmc_account_user");
    }

    #[test]
    fn scan_finds_multiple_rows_with_different_magic() {
        let mut body = vec![0u8; 0x400];
        let r1 = synth_row(100, 110, 0, [0xb1, 0x0d, 0x19, 0x0d], "alpha_table");
        let r2 = synth_row(200, 210, 0, [0x59, 0x2a, 0x16, 0x0d], "beta_table");
        body[0x20..0x20 + r1.len()].copy_from_slice(&r1);
        let r2_off = 0x20 + r1.len() + 16;
        body[r2_off..r2_off + r2.len()].copy_from_slice(&r2);
        let mut out = Vec::new();
        scan_page(&body, 1, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name, "alpha_table");
        assert_eq!(out[1].name, "beta_table");
        assert_eq!(out[1].magic, [0x59, 0x2a, 0x16, 0x0d]);
    }

    #[test]
    fn observed_system_and_base_table_layouts_use_the_same_pre_name_offsets() {
        // Privacy-safe aggregate observations from the Enterprise 24 corpus.
        // The declared lengths differ, but the fixed pre-name layout does not.
        let cases = [
            ("SYSTAB", 501, 1537, 79usize),
            ("SYSTABLE", 1002, 1745, 81),
            ("SYSINDEX", 1004, 1788, 81),
            ("abmc_account_user", 3026, 4014, 118),
        ];
        let mut body = vec![0u8; 0x800];
        let mut at = 0x20;
        for (name, table_id, object_id, declared_len) in cases {
            let mut row = synth_row(table_id, object_id, 0, [0; 4], name);
            row.resize(declared_len, 0);
            row[..4].copy_from_slice(&(declared_len as u32).to_le_bytes());
            body[at..at + row.len()].copy_from_slice(&row);
            at += row.len();
        }

        let mut out = Vec::new();
        scan_page(&body, 7, &mut out);
        assert_eq!(out.len(), cases.len());
        for (entry, (name, table_id, object_id, declared_len)) in out.iter().zip(cases) {
            assert_eq!(entry.name, name);
            assert_eq!(entry.table_id, table_id);
            assert_eq!(entry.object_id, object_id);
            assert_eq!(entry.row_length as usize, declared_len);
            assert_eq!(entry.share_type, 5);
        }
    }

    #[test]
    fn scan_rejects_implausible_name_len() {
        let mut body = vec![0u8; 0x100];
        let mut row = synth_row(1, 2, 0, [0; 4], "abcd");
        // Override name_len to 0.
        row[PHYSICAL_PREFIX_LEN + 20] = 0;
        body[0x20..0x20 + row.len()].copy_from_slice(&row);
        let mut out = Vec::new();
        scan_page(&body, 0, &mut out);
        assert!(out.is_empty());

        let mut row = synth_row(1, 2, 0, [0; 4], "abcd");
        row[PHYSICAL_PREFIX_LEN + 20] = 100; // > NAME_LEN_MAX (64)
        body[0x40..0x40 + row.len()].copy_from_slice(&row);
        let mut out = Vec::new();
        scan_page(&body, 0, &mut out);
        // No row matched.
        assert!(out.is_empty());
    }

    #[test]
    fn scan_rejects_non_ascii_name() {
        let mut body = vec![0u8; 0x100];
        let mut row = synth_row(7, 8, 0, [0; 4], "abcd");
        // Replace 'a' with 0xff (non-printable).
        let name_off = PHYSICAL_PREFIX_LEN + 21;
        row[name_off] = 0xff;
        body[0x10..0x10 + row.len()].copy_from_slice(&row);
        let mut out = Vec::new();
        scan_page(&body, 0, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn scan_does_not_read_past_declared_physical_row() {
        let mut body = vec![0u8; 0x200];
        let row = synth_row(
            5887,
            6001,
            0,
            [0xb1, 0x0d, 0x19, 0x0d],
            "abmc_invoice_header",
        );
        let row_off = 0x20;
        body[row_off..row_off + row.len()].copy_from_slice(&row);
        // Bytes after the row deliberately look like old trailer fields.
        // They belong to another record and must not be exposed.
        let after = row_off + row.len();
        body[after + 6] = 20;
        body[after + 34..after + 38].copy_from_slice(&3628u32.to_le_bytes());

        let mut out = Vec::new();
        scan_page(&body, 0, &mut out);
        assert_eq!(out.len(), 1);
        let e = &out[0];
        assert_eq!(e.col_count, None);
        assert_eq!(e.data_root_page, None);
        assert_eq!(e.last_page_raw, None);
    }

    #[test]
    fn scan_maps_post_name_prefix_and_two_direct_long_locators() {
        let mut body = vec![0u8; 0x400];
        let mut row = synth_row(3026, 4014, 0, [0; 4], "abmc_account_user");
        let first_post_name = PHYSICAL_PREFIX_LEN + TAG_MIN_LEN + "abmc_account_user".len();
        row[first_post_name..first_post_name + POST_NAME_PREFIX_LEN].copy_from_slice(&[7, 1, 3, 1]);

        let tab = [
            0x80, 0x00, // marker
            0x40, 0x00, 0x00, 0x00, // payload length
            0x2a, 0x00, 0x00, 0x00, // target
            0x00, 0x00, // reserved
            0x03, 0x00, // selector
        ];
        row[first_post_name + TAB_PAGE_LIST_OFF
            ..first_post_name + TAB_PAGE_LIST_OFF + LONG_VALUE_REF_LEN]
            .copy_from_slice(&tab);
        let ext = [
            0x80, 0x00, // marker
            0x20, 0x00, 0x00, 0x00, // payload length
            0x2b, 0x00, 0x00, 0x00, // target
            0x01, 0x00, // reserved
            0x04, 0x00, // selector
        ];
        row.extend_from_slice(&ext);
        let row_len = row.len() as u32;
        row[..4].copy_from_slice(&row_len.to_le_bytes());
        body[0x20..0x20 + row.len()].copy_from_slice(&row);

        let mut out = Vec::new();
        scan_page(&body, 7, &mut out);
        assert_eq!(out.len(), 1);
        let entry = &out[0];
        assert_eq!(
            [
                entry.table_type,
                entry.replicate,
                entry.server_type,
                entry.post_name_layout_byte
            ],
            [7, 1, 3, 1]
        );
        assert_eq!(
            entry.tab_page_list,
            Some(LongValueRef {
                marker: 0x0080,
                payload_len: 64,
                target_page: 42,
                reserved: 0,
                selector: 3,
            })
        );
        assert_eq!(
            entry.ext_page_list,
            Some(LongValueRef {
                marker: 0x0080,
                payload_len: 32,
                target_page: 43,
                reserved: 1,
                selector: 4,
            })
        );
    }

    #[test]
    fn scan_never_uses_next_row_as_missing_ext_page_list() {
        let mut body = vec![0u8; 0x400];
        let row = synth_row(1002, 1745, 0, [0; 4], "SYSTABLE");
        // This row has only a single, all-zero `tab_page_list` envelope.
        // A valid-looking locator immediately after it belongs to an
        // unrelated record and must not become `ext_page_list`.
        let row_off = 0x20;
        body[row_off..row_off + row.len()].copy_from_slice(&row);
        let after = row_off + row.len();
        body[after..after + LONG_VALUE_REF_LEN]
            .copy_from_slice(&[0x80, 0x00, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]);

        let mut out = Vec::new();
        scan_page(&body, 1, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tab_page_list, None);
        assert_eq!(out[0].ext_page_list, None);
    }

    #[test]
    fn aggregate_post_name_diagnostics_is_content_free_and_exact() {
        let mut body = vec![0u8; 0x300];
        let mut first = synth_row(1, 2, 0, [0; 4], "first_table");
        let first_post = PHYSICAL_PREFIX_LEN + TAG_MIN_LEN + "first_table".len();
        first[first_post..first_post + POST_NAME_PREFIX_LEN].copy_from_slice(&[2, 1, 0, 1]);
        let first_ref = [0x80, 0x00, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        first[first_post + TAB_PAGE_LIST_OFF..first_post + TAB_PAGE_LIST_OFF + LONG_VALUE_REF_LEN]
            .copy_from_slice(&first_ref);
        let mut second = synth_row(3, 4, 0, [0; 4], "second_table");
        let second_post = PHYSICAL_PREFIX_LEN + TAG_MIN_LEN + "second_table".len();
        second[second_post..second_post + POST_NAME_PREFIX_LEN].copy_from_slice(&[2, 0, 4, 0]);
        let second_off = 0x20 + first.len();
        body[0x20..0x20 + first.len()].copy_from_slice(&first);
        body[second_off..second_off + second.len()].copy_from_slice(&second);
        let mut entries = Vec::new();
        scan_page(&body, 1, &mut entries);

        let diagnostic = aggregate_post_name_diagnostics(entries);
        assert_eq!(diagnostic.rows, 2);
        // The scan-only layer validates the fixed envelope but deliberately
        // cannot establish target-page existence; the iterator adds that
        // final physical-page validation before a live aggregate is emitted.
        assert_eq!(diagnostic.tab_page_list_refs, 1);
        assert_eq!(diagnostic.ext_page_list_refs, 0);
        assert_eq!(diagnostic.table_type_values, BTreeMap::from([(2, 2)]));
        assert_eq!(
            diagnostic.replicate_values,
            BTreeMap::from([(0, 1), (1, 1)])
        );
        assert_eq!(
            diagnostic.server_type_values,
            BTreeMap::from([(0, 1), (4, 1)])
        );
        assert_eq!(
            diagnostic.post_name_layout_byte_values,
            BTreeMap::from([(0, 1), (1, 1)])
        );
    }

    #[test]
    fn scan_rejects_tag_when_declared_row_ends_before_its_name() {
        let mut body = vec![0u8; 0x200];
        let mut row = synth_row(1002, 1745, 0, [0; 4], "SYSTABLE");
        // Preserve the tag and page bytes, but make the physical row end in
        // the middle of the name. A page-wide scan must not accept it.
        let short_len = (PHYSICAL_PREFIX_LEN + TAG_MIN_LEN + 3) as u32;
        row[..4].copy_from_slice(&short_len.to_le_bytes());
        body[0x20..0x20 + row.len()].copy_from_slice(&row);

        let mut out = Vec::new();
        scan_page(&body, 0, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn validation_rejects_non_page_and_non_extent_references() {
        let mut bytes = vec![0u8; 4 * 4096];
        // Page 1 is an extent page; page 2 is an allocation page.
        bytes[4096 + 0xff2] = b'E';
        bytes[2 * 4096 + 0xff2] = b'A';
        let store = PageStore::from_bytes(bytes).expect("synthetic page store");
        let mut entry = SysTableEntry {
            table_id: 1,
            object_id: 2,
            row_length: 0,
            row_flags: 0,
            dbspace_id: 0,
            row_count: 0,
            creator: 0,
            table_page_count: 0,
            ext_page_count: 0,
            commit_action: 0,
            share_type: 5,
            last_modified_raw: 0,
            name: "test".into(),
            table_type: 0,
            replicate: 0,
            server_type: 0,
            post_name_layout_byte: 0,
            tab_page_list: None,
            ext_page_list: None,
            magic: [0; 4],
            col_count: None,
            data_root_page: Some(99),
            last_page: Some(2),
            data_root_raw: Some(99),
            last_page_raw: Some(2),
            page_number: 0,
            row_offset: 0,
            tag_offset: 0,
            truncated_prefix_bytes: None,
        };

        validate_page_references(&mut entry, &store);

        assert_eq!(
            entry.data_root_page, None,
            "out-of-range value is not a page"
        );
        assert_eq!(
            entry.last_page, None,
            "allocation page is not an extent page"
        );
        assert_eq!(entry.data_root_raw, Some(99));
        assert_eq!(entry.last_page_raw, Some(2));
    }

    #[test]
    fn scan_skips_trailer_region() {
        // A row whose tag falls inside the trailer (>= 0xFF0) must not match.
        let mut body = vec![0u8; 0x1000];
        let row = synth_row(99, 100, 0, [0; 4], "trail_table");
        // Place row tag at 0xFF8 (well inside the 12-byte trailer).
        let row_off = 0xFF8;
        if row_off + row.len() <= body.len() {
            body[row_off..row_off + row.len()].copy_from_slice(&row);
        }
        let mut out = Vec::new();
        scan_page(&body, 0, &mut out);
        assert!(out.is_empty());
    }
}

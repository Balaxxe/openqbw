//! `SYSINDEX` catalog row parser and attribution cross-validator (Phase 6, WP-6Z.3).
//!
//! The SA17 `SYSINDEX` system catalog stores one row per index. Enterprise 24
//! observations establish an owning catalog object and a page-like u32 field,
//! but do **not** establish that field as a B-tree root or navigation pointer.
//!
//! ```text
//! [2B flags] [2B creator = 01 46] [4B catalog page candidate u32_LE]
//! [4B zeros] [8B owner_object_id u64_LE]
//! [1B nlen]  [nlen bytes ASCII name]
//! ```
//!
//! `catalog_page_candidate` is a structurally page-like catalog value only:
//! it is not proof of table ownership, index-root status, B-tree navigation,
//! or even a particular page type. `owner_object_id` joins back into [`crate::SysTableEntry::object_id`]
//! and that catalog row supplies the physical `table_id`. Index names that start
//! with `fkey_` correspond to foreign-key indexes (the dominant kind on
//! QuickBooks files); other names are primary-key or secondary indexes
//! managed by the engine.
//!
//! # Legacy diagnostic comparison
//!
//! [`CrossValidation::run`] compares this unproven catalog value to the
//! position heuristic only as a legacy diagnostic. It is not a validation of
//! either table ownership or navigation.
//! [`crate::PageAttribution`]: for every distinct
//! `(table_id, catalog_page_candidate)` pair recovered from SYSINDEX, it checks
//! whether the position heuristic attributes `catalog_page_candidate` to a table
//! with the matching `table_id`. Disagreements indicate cases where
//! the position heuristic returns the same table. The counts are diagnostic
//! only and must not be used to infer index or data-page structure.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::iter::FusedIterator;

use opensqlany::{ApModel, PageStore, PageType, Result as SaResult};

use crate::bv_recovery::{deobfuscate_with_bv, recover_bv_any};
use crate::page_attribution::PageAttribution;
use crate::systable::SysTableEntry;

/// Two-byte creator id appearing at row offset +2 of every SYSINDEX row.
/// Empirically constant across all QBW files inspected so far (C.30).
pub const SYSINDEX_CREATOR: [u8; 2] = [0x01, 0x46];

const NAME_LEN_MIN: usize = 1;
const NAME_LEN_MAX: usize = 128;
const PREAMBLE_LEN: usize = 22; // 2 flags + 2 creator + 4 candidate + 4 zero + 8 owner + 1 nlen + 1 first name byte
const ROW_PREFIX_LEN: usize = 5; // 4-byte declared length/flags, then one byte
const PAGE_DATA_END: usize = 0xFF0;

/// One parsed `SYSINDEX` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysIndexEntry {
    /// Owning catalog object id (joins to [`SysTableEntry::object_id`]).
    pub owner_object_id: u64,
    /// Declared physical row length (low 24 bits of the row header).
    pub row_length: u32,
    /// Physical-row flags/ordinal (high 8 bits of the row header).
    pub row_flags: u8,
    /// Structurally page-like catalog value; its semantic role is unproven.
    pub catalog_page_candidate: u32,
    /// Index name (ASCII).
    pub name: String,
    /// Page on which this row was found.
    pub page_number: u64,
    /// Byte offset of the physical row within the decoded page body.
    pub row_offset: usize,
    /// Byte offset of the recognizable SYSINDEX preamble within the decoded page.
    pub preamble_offset: usize,
}

impl SysIndexEntry {
    /// True when the index name follows the `fkey_*` convention used
    /// by SA17 for foreign-key indexes.
    pub fn is_foreign_key(&self) -> bool {
        self.name.starts_with("fkey_")
    }
}

fn is_printable_ascii(b: u8) -> bool {
    (0x20..0x7F).contains(&b)
}

/// Scan a single decoded page body for `SYSINDEX` rows.
///
/// Matches occurrences of `?? ?? 01 46 <candidate> 0000 0000 <owner u64>
/// <nlen> <name>`. On Enterprise 24 that preamble is five bytes into a
/// physical row: a declared-length/flags u32 and one-byte prefix precede it.
/// The name must end exactly at the declared row boundary.
pub fn scan_page(body: &[u8], pn: u64, out: &mut Vec<SysIndexEntry>) {
    let end = body.len().min(PAGE_DATA_END);
    if end < PREAMBLE_LEN {
        return;
    }
    let mut pos = 0usize;
    let limit = end - PREAMBLE_LEN;
    while pos <= limit {
        // Match creator at +2.
        if body[pos + 2] != SYSINDEX_CREATOR[0] || body[pos + 3] != SYSINDEX_CREATOR[1] {
            pos += 1;
            continue;
        }
        // The four bytes between the candidate and owner are zero on Enterprise 24.
        if body[pos + 8] != 0 || body[pos + 9] != 0 || body[pos + 10] != 0 || body[pos + 11] != 0 {
            pos += 1;
            continue;
        }
        let catalog_page_candidate =
            u32::from_le_bytes([body[pos + 4], body[pos + 5], body[pos + 6], body[pos + 7]]);
        let owner_object_id = u64::from_le_bytes([
            body[pos + 12],
            body[pos + 13],
            body[pos + 14],
            body[pos + 15],
            body[pos + 16],
            body[pos + 17],
            body[pos + 18],
            body[pos + 19],
        ]);
        if catalog_page_candidate == 0 || owner_object_id == 0 {
            pos += 1;
            continue;
        }
        let nlen = body[pos + 20] as usize;
        if !(NAME_LEN_MIN..=NAME_LEN_MAX).contains(&nlen) {
            pos += 1;
            continue;
        }
        let name_start = pos + 21;
        let name_end = name_start + nlen;
        if name_end > end {
            pos += 1;
            continue;
        }
        let Some(row_start) = pos.checked_sub(ROW_PREFIX_LEN) else {
            pos += 1;
            continue;
        };
        let row_header = u32::from_le_bytes(
            body[row_start..row_start + 4]
                .try_into()
                .expect("row header is in bounds"),
        );
        let row_length = row_header & 0x00ff_ffff;
        let row_flags = (row_header >> 24) as u8;
        let Some(row_end) = row_start.checked_add(row_length as usize) else {
            pos += 1;
            continue;
        };
        if (row_length as usize) < ROW_PREFIX_LEN + PREAMBLE_LEN
            || row_end > end
            || name_end != row_end
        {
            pos += 1;
            continue;
        }
        let name_bytes = &body[name_start..name_end];
        if !name_bytes.iter().copied().all(is_printable_ascii) {
            pos += 1;
            continue;
        }
        let name = std::str::from_utf8(name_bytes)
            .expect("name guarded by printable-ASCII check")
            .to_owned();
        out.push(SysIndexEntry {
            owner_object_id,
            row_length,
            row_flags,
            catalog_page_candidate,
            name,
            page_number: pn,
            row_offset: row_start,
            preamble_offset: pos,
        });
        pos = name_end;
    }
}

/// Iterate every `SYSINDEX` row recovered from `store`.
///
/// Mirrors the bv-recovery strategy used by [`crate::iter_systable_entries`]
/// and [`crate::iter_syscolumns`].
pub fn iter_sysindex<'a>(
    store: &'a PageStore,
    model: &'a ApModel,
) -> impl Iterator<Item = SysIndexEntry> + 'a {
    SysIndexIter::new(store, model)
}

/// Collect a deduplicated set of SYSINDEX entries keyed by
/// `(owner_object_id, catalog_page_candidate, name)`, preferring the first sighting.
pub fn collect_unique(store: &PageStore, model: &ApModel) -> Vec<SysIndexEntry> {
    let mut uniq: BTreeMap<(u64, u32, String), SysIndexEntry> = BTreeMap::new();
    for e in iter_sysindex(store, model) {
        uniq.entry((e.owner_object_id, e.catalog_page_candidate, e.name.clone()))
            .or_insert(e);
    }
    uniq.into_values().collect()
}

struct SysIndexIter<'a> {
    store: &'a PageStore,
    model: &'a ApModel,
    pn: u64,
    n_pages: u64,
    buffer: Vec<SysIndexEntry>,
}

impl<'a> SysIndexIter<'a> {
    fn new(store: &'a PageStore, model: &'a ApModel) -> Self {
        Self {
            store,
            model,
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
            let plain = if let Some(bv) = recover_bv_any(pn, raw) {
                deobfuscate_with_bv(raw, pn, bv)
            } else {
                self.model.deobfuscate_with_store(raw, pn, self.store)
            };
            let mut found = Vec::new();
            scan_page(&plain, pn, &mut found);
            for e in found.into_iter().rev() {
                self.buffer.push(e);
            }
        }
        Ok(!self.buffer.is_empty())
    }
}

impl Iterator for SysIndexIter<'_> {
    type Item = SysIndexEntry;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(e) = self.buffer.pop() {
                return Some(e);
            }
            match self.fill_buffer() {
                Ok(true) => continue,
                _ => return None,
            }
        }
    }
}

impl FusedIterator for SysIndexIter<'_> {}

/// Outcome of a legacy diagnostic comparison of a resolved SYSINDEX candidate
/// with a position-heuristic [`PageAttribution`]. It is not ownership validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    /// Position heuristic returns the same table for `catalog_page_candidate`.
    Agree,
    /// Position heuristic returns a different table for `catalog_page_candidate`.
    Disagree,
    /// Position heuristic returns no attribution for `catalog_page_candidate`.
    Missing,
    /// SYSINDEX's owner object id does not appear in the SYSTABLE catalog
    /// (orphaned index row, usually a catalog index for an internal
    /// table).
    OrphanIndex,
    /// More than one physical table is registered for this owner object id.
    AmbiguousOwner,
}

/// Legacy diagnostic comparison counts; not a B-tree or ownership validator.
#[derive(Debug, Clone, Default)]
pub struct CrossValidation {
    /// Total SYSINDEX rows audited.
    pub total: usize,
    /// Distinct (resolved table_id, catalog_page_candidate) pairs audited (deduplicated input).
    pub distinct_candidates: usize,
    /// Pairs where the position heuristic returned the resolved owner table.
    pub agree: usize,
    /// Pairs where the position heuristic returned a different table.
    pub disagree: usize,
    /// Pairs where the position heuristic returned no attribution.
    pub missing: usize,
    /// Pairs whose `table_id` could not be resolved against SYSTABLE.
    pub orphan_index: usize,
    /// Pairs whose owner object id resolved to multiple physical table rows.
    pub ambiguous_owner: usize,
    /// First few disagreements, kept for diagnostic printing.
    /// Tuple is `(table_id, sysindex_table_name, position_table_name, catalog_page_candidate, index_name)`.
    pub disagree_samples: Vec<(u32, String, String, u32, String)>,
}

/// Maximum disagreement samples retained in [`CrossValidation::disagree_samples`].
pub const DISAGREE_SAMPLE_LIMIT: usize = 16;

impl CrossValidation {
    /// Compare the given `entries` against the position-heuristic as a legacy
    /// diagnostic only; this does not validate ownership or navigation. Resolve
    /// `owner_object_id` through
    /// `SYSTABLE.object_id` to the physical table id/name.
    pub fn run(
        entries: &[SysIndexEntry],
        position: &PageAttribution,
        tables: &[SysTableEntry],
    ) -> Self {
        let mut tables_by_owner: HashMap<u64, BTreeSet<(u32, String)>> = HashMap::new();
        for t in tables {
            tables_by_owner
                .entry(t.object_id)
                .or_default()
                .insert((t.table_id, t.name.clone()));
        }
        let mut seen: BTreeSet<(u32, u32)> = BTreeSet::new();
        let mut stats = CrossValidation {
            total: entries.len(),
            ..Default::default()
        };
        for e in entries {
            let Some(owners) = tables_by_owner.get(&e.owner_object_id) else {
                stats.orphan_index += 1;
                continue;
            };
            if owners.len() != 1 {
                stats.ambiguous_owner += 1;
                continue;
            }
            let (table_id, sysindex_name) = owners.iter().next().expect("one owner");
            if !seen.insert((*table_id, e.catalog_page_candidate)) {
                continue;
            }
            stats.distinct_candidates += 1;
            let pos_name = position
                .attribute(u64::from(e.catalog_page_candidate))
                .map(|t| t.name.clone());
            let outcome = classify(Some(sysindex_name.as_str()), pos_name.as_deref());
            match outcome {
                AuditOutcome::Agree => stats.agree += 1,
                AuditOutcome::Disagree => {
                    stats.disagree += 1;
                    if stats.disagree_samples.len() < DISAGREE_SAMPLE_LIMIT {
                        stats.disagree_samples.push((
                            *table_id,
                            sysindex_name.clone(),
                            pos_name.unwrap_or_else(|| "<none>".into()),
                            e.catalog_page_candidate,
                            e.name.clone(),
                        ));
                    }
                }
                AuditOutcome::Missing => stats.missing += 1,
                AuditOutcome::OrphanIndex => stats.orphan_index += 1,
                AuditOutcome::AmbiguousOwner => stats.ambiguous_owner += 1,
            }
        }
        stats
    }

    /// Agreement rate over distinct (table_id, catalog_page_candidate) pairs that
    /// have a known SYSTABLE table_id (i.e. excluding orphans).
    pub fn agreement_rate(&self) -> f64 {
        let resolvable = self.agree + self.disagree + self.missing;
        if resolvable == 0 {
            0.0
        } else {
            self.agree as f64 / resolvable as f64
        }
    }
}

fn classify(sysindex_name: Option<&str>, pos_name: Option<&str>) -> AuditOutcome {
    match (sysindex_name, pos_name) {
        (None, _) => AuditOutcome::OrphanIndex,
        (Some(_), None) => AuditOutcome::Missing,
        (Some(a), Some(b)) if a == b => AuditOutcome::Agree,
        (Some(_), Some(_)) => AuditOutcome::Disagree,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a complete Enterprise 24 SYSINDEX physical row.
    fn synth_row(owner_object_id: u64, candidate: u32, name: &str) -> Vec<u8> {
        let mut v = vec![0u8; ROW_PREFIX_LEN];
        v.extend_from_slice(&[0x00, 0x00]); // flags
        v.extend_from_slice(&SYSINDEX_CREATOR);
        v.extend_from_slice(&candidate.to_le_bytes());
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        v.extend_from_slice(&owner_object_id.to_le_bytes());
        v.push(name.len() as u8);
        v.extend_from_slice(name.as_bytes());
        let header = v.len() as u32;
        v[..4].copy_from_slice(&header.to_le_bytes());
        v
    }

    fn table(tid: u32, object_id: u64, name: &str, data_page: u32, last: u32) -> SysTableEntry {
        SysTableEntry {
            table_id: tid,
            object_id,
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
            name: name.into(),
            table_type: 0,
            replicate: 0,
            server_type: 0,
            post_name_layout_byte: 0,
            tab_page_list: None,
            ext_page_list: None,
            magic: [0; 4],
            col_count: None,
            data_root_page: Some(data_page),
            last_page: Some(last),
            data_root_raw: Some(data_page),
            last_page_raw: Some(last),
            page_number: 0,
            row_offset: 0,
            tag_offset: 0,
            truncated_prefix_bytes: None,
        }
    }

    #[test]
    fn scan_finds_single_row() {
        let mut body = vec![0u8; 0x200];
        let row = synth_row(0x0000_0001_0000_16ff, 8418, "fkey_invoice_customer");
        body[0x40..0x40 + row.len()].copy_from_slice(&row);
        let mut out = Vec::new();
        scan_page(&body, 99, &mut out);
        assert_eq!(out.len(), 1);
        let e = &out[0];
        assert_eq!(e.owner_object_id, 0x0000_0001_0000_16ff);
        assert_eq!(e.catalog_page_candidate, 8418);
        assert_eq!(e.name, "fkey_invoice_customer");
        assert_eq!(e.page_number, 99);
        assert_eq!(e.row_offset, 0x40);
        assert_eq!(e.preamble_offset, 0x40 + ROW_PREFIX_LEN);
        assert!(e.is_foreign_key());
    }

    #[test]
    fn scan_rejects_zero_candidate_or_zero_owner() {
        let mut body = vec![0u8; 0x100];
        let row = synth_row(0, 100, "bogus");
        body[0..row.len()].copy_from_slice(&row);
        let mut out = Vec::new();
        scan_page(&body, 0, &mut out);
        assert!(out.is_empty());

        let mut body2 = vec![0u8; 0x100];
        let row2 = synth_row(5, 0, "bogus2");
        body2[0..row2.len()].copy_from_slice(&row2);
        let mut out2 = Vec::new();
        scan_page(&body2, 0, &mut out2);
        assert!(out2.is_empty());
    }

    #[test]
    fn scan_rejects_non_ascii_name() {
        let mut body = vec![0u8; 0x100];
        let mut row = synth_row(5, 100, "x");
        // Replace the printable 'x' with a non-printable byte.
        let last = row.len() - 1;
        row[last] = 0x01;
        body[0..row.len()].copy_from_slice(&row);
        let mut out = Vec::new();
        scan_page(&body, 0, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn scan_requires_name_to_end_at_declared_row_boundary() {
        let mut body = vec![0u8; 0x100];
        let mut row = synth_row(5, 100, "pk");
        // A plausible preamble embedded in a longer physical row is not a
        // SYSINDEX row under the Enterprise 24 layout.
        let longer = (row.len() + 1) as u32;
        row[..4].copy_from_slice(&longer.to_le_bytes());
        body[0x20..0x20 + row.len()].copy_from_slice(&row);
        let mut out = Vec::new();
        scan_page(&body, 0, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn scan_emits_multiple_back_to_back() {
        let mut body = vec![0u8; 0x300];
        let r1 = synth_row(1, 100, "pk_a");
        let r2 = synth_row(2, 200, "fkey_b_a");
        body[0x10..0x10 + r1.len()].copy_from_slice(&r1);
        body[0x80..0x80 + r2.len()].copy_from_slice(&r2);
        let mut out = Vec::new();
        scan_page(&body, 1, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name, "pk_a");
        assert_eq!(out[1].name, "fkey_b_a");
        assert!(!out[0].is_foreign_key());
        assert!(out[1].is_foreign_key());
    }

    #[test]
    fn cross_validation_agree_disagree_missing_orphan() {
        let tables = vec![
            table(10, 110, "alpha", 100, 200),
            table(20, 120, "beta", 300, 400),
        ];
        let position = PageAttribution::from_catalog(tables.clone());
        let entries = vec![
            // Diagnostic match: candidate=150 lands in alpha's window.
            SysIndexEntry {
                owner_object_id: 110,
                row_length: 0,
                row_flags: 0,
                catalog_page_candidate: 150,
                name: "pk".into(),
                page_number: 0,
                row_offset: 0,
                preamble_offset: 0,
            },
            // Diagnostic mismatch: candidate=350 lands in beta's window.
            SysIndexEntry {
                owner_object_id: 110,
                row_length: 0,
                row_flags: 0,
                catalog_page_candidate: 350,
                name: "fkey_x".into(),
                page_number: 0,
                row_offset: 0,
                preamble_offset: 0,
            },
            // No position match: candidate=500 is beyond beta's last_page.
            SysIndexEntry {
                owner_object_id: 120,
                row_length: 0,
                row_flags: 0,
                catalog_page_candidate: 500,
                name: "pk".into(),
                page_number: 0,
                row_offset: 0,
                preamble_offset: 0,
            },
            // Orphan: tid=99 (unknown table).
            SysIndexEntry {
                owner_object_id: 199,
                row_length: 0,
                row_flags: 0,
                catalog_page_candidate: 150,
                name: "pk".into(),
                page_number: 0,
                row_offset: 0,
                preamble_offset: 0,
            },
            // Duplicate of the first agree row (should be dedup-counted).
            SysIndexEntry {
                owner_object_id: 110,
                row_length: 0,
                row_flags: 0,
                catalog_page_candidate: 150,
                name: "pk".into(),
                page_number: 0,
                row_offset: 0,
                preamble_offset: 0,
            },
        ];
        let v = CrossValidation::run(&entries, &position, &tables);
        assert_eq!(v.total, 5);
        // The unresolved owner is a diagnostic, not a resolved table/candidate
        // pair, so it is deliberately outside this count.
        assert_eq!(v.distinct_candidates, 3);
        assert_eq!(v.agree, 1);
        assert_eq!(v.disagree, 1);
        assert_eq!(v.missing, 1);
        assert_eq!(v.orphan_index, 1);
        let resolvable = v.agree + v.disagree + v.missing;
        assert_eq!(resolvable, 3);
        assert!((v.agreement_rate() - 1.0 / 3.0).abs() < 1e-9);
        assert_eq!(v.disagree_samples.len(), 1);
        let (tid, sn, pn, candidate, idx) = &v.disagree_samples[0];
        assert_eq!(*tid, 10);
        assert_eq!(sn, "alpha");
        assert_eq!(pn, "beta");
        assert_eq!(*candidate, 350);
        assert_eq!(idx, "fkey_x");
    }

    #[test]
    fn classify_orphan_when_table_unknown_even_with_position() {
        assert_eq!(classify(None, Some("alpha")), AuditOutcome::OrphanIndex);
        assert_eq!(classify(None, None), AuditOutcome::OrphanIndex);
    }

    #[test]
    fn cross_validation_reports_ambiguous_owner_object() {
        let tables = vec![
            table(10, 110, "alpha", 100, 200),
            table(20, 110, "alpha_shadow", 300, 400),
        ];
        let entries = vec![SysIndexEntry {
            owner_object_id: 110,
            row_length: 0,
            row_flags: 0,
            catalog_page_candidate: 150,
            name: "pk".into(),
            page_number: 0,
            row_offset: 0,
            preamble_offset: 0,
        }];
        let validation = CrossValidation::run(
            &entries,
            &PageAttribution::from_catalog(tables.clone()),
            &tables,
        );
        assert_eq!(validation.ambiguous_owner, 1);
        assert_eq!(validation.distinct_candidates, 0);
    }
}

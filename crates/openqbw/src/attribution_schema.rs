//! Schema-aware page attribution validator (Phase 6, WP-6Z).
//!
//! Prior phases established that there is no on-disk per-table tag in
//! SA17 page headers (WP-3A, WP-4C refuted) and no walkable per-table
//! B-tree of interior nodes (WP-4B refuted: I-pages are empty in QBW).
//! The position-based [`crate::page_attribution::PageAttribution`]
//! (C.47 nearest-lower-`data_root` heuristic) therefore remains the
//! only available attribution signal, and is known to be noisy
//! (line items disperse across 86 distinct `source_table` buckets on
//! Rock Castle).
//!
//! This module adds an orthogonal *validation* signal derived from the
//! SYSCOLUMN catalog (Phase 6 WP-6A). For each table we precompute a
//! plausible **row-width band** from the declared column widths and
//! domain identifiers, then check each candidate page against that band
//! using the median row body length from its slot directory.
//!
//! ## What it is and is not
//!
//! `SchemaAttribution` is a *validator*, not a re-attributer. Given a
//! page already attributed to table `T` by position, it answers
//! "does the page's row layout look like it belongs to `T`?". The
//! production line-item exporter is unchanged; downstream callers can
//! use the [`SchemaAttribution::validate`] method to flag suspicious
//! attributions and `--strict-attribution` consumers can require
//! validation before counting a page's rows.
//!
//! The width band is intentionally lenient. Variable-width columns
//! (`Y`, `V`, `C`, `A`) contribute an upper-bound allowance per
//! column rather than an exact width; fixed-width columns (`N`, `F`,
//! `I`, `D`, `T`) contribute their declared width. A page passes
//! validation when its median row body length is within `[low, high]`.

use std::collections::BTreeMap;

use opensqlany::{ApModel, Page, PageStore, PageType, SlottedPage};

use crate::bv_recovery::{deobfuscate_with_bv, recover_bv_qb_data};
use crate::syscolumn::{SysColumn, collect_unique};
use crate::systable::collect_unique as collect_unique_systables;

/// Per-column variable-width allowance (bytes) added to the upper bound
/// when the column's domain is variable-length.  No Enterprise 24 domain
/// has yet been proven fixed or variable for physical row decoding.
pub const VARIABLE_COLUMN_UPPER_ALLOWANCE: u32 = 64;

/// Minimum row body length any plausible row must clear, regardless of
/// schema. SA17 rows include a small row header that is not modelled
/// per-column.
pub const MIN_ROW_BODY_BYTES: u32 = 4;

/// A row-width band derived from a table's SYSCOLUMN schema.
#[derive(Debug, Clone, Copy)]
pub struct WidthBand {
    /// Physical `SYSTABLE.table_id` that owns these recovered columns.
    pub table_id: u32,
    /// Lower bound on plausible row body length.
    pub low: u32,
    /// Upper bound on plausible row body length.
    pub high: u32,
    /// Number of recovered catalog columns counted in the band.
    ///
    /// This is not a claim that every physical table column was recovered.
    pub recovered_column_count: u32,
}

/// Schema-aware width-validator built from SYSCOLUMN + SYSTABLE.
#[derive(Debug, Clone)]
pub struct SchemaAttribution {
    /// Map from table name to width band.
    bands: BTreeMap<String, WidthBand>,
}

/// Summary of [`SchemaAttribution::validate_corpus`] over a page set.
#[derive(Debug, Default, Clone, Copy)]
pub struct ValidationStats {
    /// Pages with a position attribution that have a width band and pass it.
    pub pass: u64,
    /// Pages with a position attribution that have a width band but fail it.
    pub fail: u64,
    /// Pages with a position attribution whose table has no width band.
    pub no_band: u64,
    /// Pages whose row body could not be measured (no slot directory or no rows).
    pub unmeasured: u64,
}

impl ValidationStats {
    /// Total pages observed.
    pub fn total(&self) -> u64 {
        self.pass + self.fail + self.no_band + self.unmeasured
    }
}

/// Whether an Enterprise 24 raw catalog domain has a proven fixed physical
/// width.  None do yet: direct catalog observations show `N` and `Y` beside
/// semantically different columns, and the width byte's units are not
/// established.  Returning false keeps schema attribution diagnostic-only
/// instead of turning a partial catalog into an unsafe row decoder.
fn is_fixed_width_domain(_domain_id: u16) -> bool {
    false
}

impl SchemaAttribution {
    /// Build the width-band index by scanning SYSTABLE + SYSCOLUMN.
    pub fn build(store: &PageStore, model: &ApModel) -> Self {
        let entries = collect_unique_systables(store, model);
        let columns: Vec<SysColumn> = collect_unique(store, model);

        // SYSCOLUMN.table_id joins directly to SYSTABLE.table_id. Do not use
        // SYSOBJECT as a primary identity bridge: that heuristic can attach
        // a recovered column to the wrong physical table.
        let mut cols_by_table_id: BTreeMap<u32, Vec<SysColumn>> = BTreeMap::new();
        for c in columns {
            cols_by_table_id.entry(c.table_id).or_default().push(c);
        }
        let mut tables_by_id: BTreeMap<u32, &crate::SysTableEntry> = BTreeMap::new();
        for e in &entries {
            tables_by_id.entry(e.table_id).or_insert(e);
        }

        let mut bands = BTreeMap::new();
        for (table_id, cols) in &cols_by_table_id {
            let Some(table) = tables_by_id.get(table_id) else {
                continue;
            };
            if cols.is_empty() {
                continue;
            }
            // A row-width band is only meaningful when the recovered catalog
            // set is complete. Do not turn a partial set of columns into an
            // apparently authoritative table schema.
            if let Some(declared) = table.col_count
                && cols.len() != declared as usize
            {
                continue;
            }
            let mut low: u32 = MIN_ROW_BODY_BYTES;
            let mut high: u32 = MIN_ROW_BODY_BYTES;
            for c in cols {
                let w = c.width;
                if is_fixed_width_domain(c.domain_id) {
                    low = low.saturating_add(w);
                    high = high.saturating_add(w);
                } else {
                    low = low.saturating_add(1);
                    high = high.saturating_add(w.max(VARIABLE_COLUMN_UPPER_ALLOWANCE));
                }
            }
            bands.insert(
                table.name.clone(),
                WidthBand {
                    table_id: *table_id,
                    low,
                    high,
                    recovered_column_count: cols.len() as u32,
                },
            );
        }
        Self { bands }
    }

    /// Look up the width band for `table_name`.
    pub fn band(&self, table_name: &str) -> Option<&WidthBand> {
        self.bands.get(table_name)
    }

    /// Number of tables with computed bands.
    pub fn len(&self) -> usize {
        self.bands.len()
    }

    /// True when no bands were computed (catalog unparseable).
    pub fn is_empty(&self) -> bool {
        self.bands.is_empty()
    }

    /// Return `true` if `observed_row_body` falls within `table_name`'s
    /// width band. Returns `false` when the table has no band.
    pub fn validate_observed(&self, table_name: &str, observed_row_body: u32) -> bool {
        let Some(b) = self.bands.get(table_name) else {
            return false;
        };
        observed_row_body >= b.low && observed_row_body <= b.high
    }

    /// Compute the median live row body length for `page_number`. Returns
    /// `None` when the page cannot be decoded, has no slot directory, or
    /// has no live rows.
    pub fn measure_page(
        &self,
        store: &PageStore,
        model: &ApModel,
        page_number: u64,
    ) -> Option<u32> {
        median_row_body(store, model, page_number)
    }

    /// Validate that a page already attributed to `table_name` plausibly
    /// belongs to that table.
    pub fn validate(
        &self,
        store: &PageStore,
        model: &ApModel,
        page_number: u64,
        table_name: &str,
    ) -> Option<bool> {
        let observed = median_row_body(store, model, page_number)?;
        Some(self.validate_observed(table_name, observed))
    }

    /// Validate every entry in `(page_number, table_name)` and return
    /// aggregate statistics.
    pub fn validate_corpus<I, S>(
        &self,
        store: &PageStore,
        model: &ApModel,
        pages: I,
    ) -> ValidationStats
    where
        I: IntoIterator<Item = (u64, S)>,
        S: AsRef<str>,
    {
        let mut s = ValidationStats::default();
        for (pn, name) in pages {
            let name = name.as_ref();
            if !self.bands.contains_key(name) {
                s.no_band += 1;
                continue;
            }
            match median_row_body(store, model, pn) {
                None => s.unmeasured += 1,
                Some(m) => {
                    if self.validate_observed(name, m) {
                        s.pass += 1;
                    } else {
                        s.fail += 1;
                    }
                }
            }
        }
        s
    }
}

/// Decode `page_number` and return the median row body length across
/// live slots. Returns `None` when the page cannot be decoded, has no
/// slot directory, or has no live rows.
fn median_row_body(store: &PageStore, model: &ApModel, page_number: u64) -> Option<u32> {
    let page = store.page(page_number).ok()?;
    if page.trailer().page_type() != PageType::Extent {
        return None;
    }
    let raw = page.bytes();
    let plain = if let Some(bv) = recover_bv_qb_data(page_number, raw) {
        deobfuscate_with_bv(raw, page_number, bv)
    } else {
        model.deobfuscate_with_store(raw, page_number, store)
    };
    let p = Page::from_bytes(page_number, &plain);
    let sp = SlottedPage::parse(p);
    sp.directory.as_ref()?;
    let rows = sp.row_bytes();
    if rows.is_empty() {
        return None;
    }
    let mut lens: Vec<u32> = rows.iter().map(|(_, b)| b.len() as u32).collect();
    lens.sort_unstable();
    Some(lens[lens.len() / 2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unproven_catalog_domains_do_not_claim_fixed_width() {
        for d in [1, 2, 3, 4, 6, 8, 9, 10, 11, 13, 19, 20, 21, 23] {
            assert!(!is_fixed_width_domain(d));
        }
    }

    #[test]
    fn empty_attribution_validates_nothing() {
        let sa = SchemaAttribution {
            bands: BTreeMap::new(),
        };
        assert!(sa.is_empty());
        assert!(!sa.validate_observed("anything", 32));
    }

    #[test]
    fn observed_inside_band_passes() {
        let mut bands = BTreeMap::new();
        bands.insert(
            "t".to_string(),
            WidthBand {
                table_id: 1,
                low: 16,
                high: 64,
                recovered_column_count: 3,
            },
        );
        let sa = SchemaAttribution { bands };
        assert!(sa.validate_observed("t", 32));
        assert!(!sa.validate_observed("t", 8));
        assert!(!sa.validate_observed("t", 200));
        assert!(sa.validate_observed("t", 16));
        assert!(sa.validate_observed("t", 64));
    }

    #[test]
    fn validation_stats_total_sums_components() {
        let s = ValidationStats {
            pass: 4,
            fail: 1,
            no_band: 2,
            unmeasured: 3,
        };
        assert_eq!(s.total(), 10);
    }

    #[test]
    fn unknown_table_does_not_validate() {
        let sa = SchemaAttribution {
            bands: BTreeMap::new(),
        };
        assert!(!sa.validate_observed("missing", 10));
    }
}

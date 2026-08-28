//! Nullability metadata from Enterprise 24 `SYSCOLUMN` rows.
//!
//! The compact recovered tail is `[domain_id u16][marker][nulls][width]`.
//! `nulls` is an ASCII `N`/`Y` flag, matching SQL Anywhere 17's documented
//! `SYSTABCOL.nulls` field. The preceding numeric value was formerly called
//! `nulls_flag`; it is the low byte of `domain_id`, not a null/default bitmap.

use std::collections::BTreeMap;

use opensqlany::{ApModel, PageStore};

use crate::collect_unique_syscolumns;

/// One nullability code in the recovered catalog.
#[derive(Debug, Clone)]
pub struct NullabilityBucket {
    /// ASCII `N` (not nullable) or `Y` (nullable).
    pub nulls: u8,
    /// Number of uniquely recovered catalog rows with this code.
    pub count: usize,
    /// Up to four column names that share this byte, for context.
    pub sample_columns: Vec<String>,
}

/// Historical type name retained for source compatibility.
#[deprecated(note = "use NullabilityBucket")]
pub type NullsFlagBucket = NullabilityBucket;

/// Build an `N`/`Y` nullability histogram across uniquely recovered catalog
/// rows. Counts describe recovery coverage only; they do not prove that every
/// physical column was recovered.
pub fn histogram(store: &PageStore, model: &ApModel) -> Vec<NullabilityBucket> {
    let mut counts: BTreeMap<u8, (usize, Vec<String>)> = BTreeMap::new();
    for c in collect_unique_syscolumns(store, model) {
        let entry = counts.entry(c.nulls).or_insert((0, Vec::new()));
        entry.0 += 1;
        if entry.1.len() < 4 && !entry.1.contains(&c.name) {
            entry.1.push(c.name);
        }
    }
    counts
        .into_iter()
        .map(|(nulls, (count, sample_columns))| NullabilityBucket {
            nulls,
            count,
            sample_columns,
        })
        .collect()
}

/// Historical function name retained for source compatibility.
#[deprecated(note = "use histogram; it now reports actual N/Y nullability")]
pub fn nulls_flag_histogram(store: &PageStore, model: &ApModel) -> Vec<NullabilityBucket> {
    histogram(store, model)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `NullabilityBucket` is purely a value type; the only real test we
    /// can run here is that the field destructuring is stable.
    #[test]
    fn bucket_fields_round_trip() {
        let b = NullabilityBucket {
            nulls: b'Y',
            count: 42,
            sample_columns: vec!["is_build".into(), "is_receipt".into()],
        };
        assert_eq!(b.nulls, b'Y');
        assert_eq!(b.count, 42);
        assert_eq!(b.sample_columns.len(), 2);
    }
}

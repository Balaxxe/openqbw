//! Legacy diagnostic grouping of catalog page candidates by owner table.
//!
//! `SYSTABLE` identifies the tables known to the database and `SYSINDEX`
//! records a page-like candidate and owning catalog object. This module joins
//! those catalogs for diagnostics only. It does not establish B-tree roots,
//! page ownership, or navigable structure; the historical names are retained
//! for API compatibility.

use std::collections::{BTreeMap, BTreeSet};

use opensqlany::{ApModel, PageStore, PageType};

use crate::{SysIndexEntry, SysTableEntry, collect_unique, collect_unique_sysindex};

/// Legacy diagnostic grouping for an E-page-filtered catalog candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexRoot {
    /// Page number of an E-page candidate. It is not proven to be an index root.
    pub page_number: u32,
    /// Deduplicated, lexically ordered index names for this root.
    pub index_names: Vec<String>,
}

/// Legacy diagnostic candidate groups belonging to one unambiguous table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableIndexRoots {
    /// SQL Anywhere's resolved physical table identifier.
    pub table_id: u32,
    /// The table name recorded by `SYSTABLE`.
    pub table_name: String,
    /// Distinct E-page-filtered candidates, ordered by page number.
    pub roots: Vec<IndexRoot>,
}

/// A `SYSINDEX` row whose owner object id did not resolve in `SYSTABLE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanIndexRoot {
    /// The unresolvable catalog row.
    pub entry: SysIndexEntry,
}

/// A `SYSINDEX` row excluded by this legacy map's in-range E-page filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidIndexRoot {
    /// The rejected catalog row.
    pub entry: SysIndexEntry,
}

/// An owner object id which maps to more than one physical SYSTABLE row.
///
/// Such a table id is intentionally excluded from [`IndexRootMap::tables`]
/// so callers cannot silently attach roots to the wrong table name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbiguousOwnerObjectId {
    /// The duplicate owner object id.
    pub owner_object_id: u64,
    /// Distinct physical table ids/names seen for this owner, in lexical order.
    pub tables: Vec<(u32, String)>,
}

/// Legacy, diagnostic-only table-to-catalog-candidate map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexRootMap {
    tables: BTreeMap<(u32, String), TableIndexRoots>,
    orphans: Vec<OrphanIndexRoot>,
    invalid_roots: Vec<InvalidIndexRoot>,
    ambiguous_owner_object_ids: Vec<AmbiguousOwnerObjectId>,
}

impl IndexRootMap {
    /// Read both system catalogs and build the legacy E-page-filtered
    /// diagnostic map. This must not be used for B-tree navigation.
    pub fn from_store(store: &PageStore, model: &ApModel) -> Self {
        let tables = collect_unique(store, model);
        let indexes = collect_unique_sysindex(store, model);
        Self::from_catalogs(tables, indexes, |page_number| {
            page_number != 0
                && u64::from(page_number) < store.page_count()
                && store
                    .page(u64::from(page_number))
                    .map(|page| page.trailer().page_type() == PageType::Extent)
                    .unwrap_or(false)
        })
    }

    /// Join parsed catalogs using the supplied legacy E-page filter.
    ///
    /// This lower-level constructor is useful when catalog pages have already
    /// been collected, and makes validation independently testable.  The
    /// validator must return `true` only for a non-zero, readable E page. An
    /// E-page result does not prove index-root semantics.
    pub fn from_catalogs<T, I, F>(tables: T, indexes: I, mut is_extent_page: F) -> Self
    where
        T: IntoIterator<Item = SysTableEntry>,
        I: IntoIterator<Item = SysIndexEntry>,
        F: FnMut(u32) -> bool,
    {
        let mut tables_by_owner: BTreeMap<u64, BTreeSet<(u32, String)>> = BTreeMap::new();
        for table in tables {
            tables_by_owner
                .entry(table.object_id)
                .or_default()
                .insert((table.table_id, table.name));
        }

        let mut map = Self::default();
        let mut unique_tables = BTreeMap::new();
        for (owner_object_id, tables) in tables_by_owner {
            if tables.len() == 1 {
                unique_tables.insert(
                    owner_object_id,
                    tables.into_iter().next().expect("one table"),
                );
            } else {
                map.ambiguous_owner_object_ids.push(AmbiguousOwnerObjectId {
                    owner_object_id,
                    tables: tables.into_iter().collect(),
                });
            }
        }

        // A set prevents repeated recovery of the same SYSINDEX row from
        // producing duplicate diagnostics or names.
        let mut seen = BTreeSet::new();
        let mut roots: BTreeMap<(u32, String, u32), BTreeSet<String>> = BTreeMap::new();
        for entry in indexes {
            let identity = (
                entry.owner_object_id,
                entry.catalog_page_candidate,
                entry.name.clone(),
            );
            if !seen.insert(identity) {
                continue;
            }
            let Some((table_id, table_name)) = unique_tables.get(&entry.owner_object_id) else {
                map.orphans.push(OrphanIndexRoot { entry });
                continue;
            };
            if !is_extent_page(entry.catalog_page_candidate) {
                map.invalid_roots.push(InvalidIndexRoot { entry });
                continue;
            }
            roots
                .entry((*table_id, table_name.clone(), entry.catalog_page_candidate))
                .or_default()
                .insert(entry.name);
        }

        for ((table_id, table_name, page_number), index_names) in roots {
            let key = (table_id, table_name.clone());
            let table = map.tables.entry(key).or_insert_with(|| TableIndexRoots {
                table_id,
                table_name,
                roots: Vec::new(),
            });
            table.roots.push(IndexRoot {
                page_number,
                index_names: index_names.into_iter().collect(),
            });
        }
        map
    }

    /// Find legacy candidate groups for an exact `(table_id, table_name)` key.
    pub fn get(&self, table_id: u32, table_name: &str) -> Option<&TableIndexRoots> {
        self.tables.get(&(table_id, table_name.to_owned()))
    }

    /// Iterate mapped tables in `(table_id, table_name)` order.
    pub fn tables(&self) -> impl Iterator<Item = &TableIndexRoots> {
        self.tables.values()
    }

    /// SYSINDEX rows whose owner object id was absent or ambiguous in SYSTABLE.
    pub fn orphans(&self) -> &[OrphanIndexRoot] {
        &self.orphans
    }

    /// SYSINDEX rows excluded by the legacy E-page filter.
    pub fn invalid_roots(&self) -> &[InvalidIndexRoot] {
        &self.invalid_roots
    }

    /// Duplicate/conflicting SYSTABLE owner-object entries retained as diagnostics.
    pub fn ambiguous_owner_object_ids(&self) -> &[AmbiguousOwnerObjectId] {
        &self.ambiguous_owner_object_ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(table_id: u32, object_id: u64, name: &str) -> SysTableEntry {
        SysTableEntry {
            table_id,
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

    fn index(owner_object_id: u64, catalog_page_candidate: u32, name: &str) -> SysIndexEntry {
        SysIndexEntry {
            owner_object_id,
            row_length: 0,
            row_flags: 0,
            catalog_page_candidate,
            name: name.into(),
            page_number: 0,
            row_offset: 0,
            preamble_offset: 0,
        }
    }

    #[test]
    fn maps_deduplicated_roots_and_names() {
        let map = IndexRootMap::from_catalogs(
            vec![table(7, 70, "account")],
            vec![
                index(70, 40, "pk_account"),
                index(70, 40, "fkey_owner"),
                index(70, 40, "pk_account"),
                index(70, 12, "fkey_type"),
            ],
            |page| matches!(page, 12 | 40),
        );
        let account = map.get(7, "account").expect("mapped account");
        assert_eq!(account.roots.len(), 2);
        assert_eq!(account.roots[0].page_number, 12);
        assert_eq!(account.roots[0].index_names, ["fkey_type"]);
        assert_eq!(account.roots[1].page_number, 40);
        assert_eq!(account.roots[1].index_names, ["fkey_owner", "pk_account"]);
        assert!(map.orphans().is_empty());
        assert!(map.invalid_roots().is_empty());
    }

    #[test]
    fn retains_orphan_and_invalid_catalog_rows() {
        let map = IndexRootMap::from_catalogs(
            vec![table(7, 70, "account")],
            vec![index(90, 20, "pk_orphan"), index(70, 21, "bad_root")],
            |page| page == 20,
        );
        assert_eq!(map.orphans().len(), 1);
        assert_eq!(map.orphans()[0].entry.name, "pk_orphan");
        assert_eq!(map.invalid_roots().len(), 1);
        assert_eq!(map.invalid_roots()[0].entry.catalog_page_candidate, 21);
        assert_eq!(map.tables().count(), 0);
    }

    #[test]
    fn rejects_ambiguous_owner_object_ids_without_losing_diagnostic() {
        let map = IndexRootMap::from_catalogs(
            vec![table(7, 70, "account"), table(8, 70, "account_old")],
            vec![index(70, 20, "pk_account")],
            |page| page == 20,
        );
        assert!(map.get(7, "account").is_none());
        assert_eq!(map.ambiguous_owner_object_ids().len(), 1);
        assert_eq!(
            map.ambiguous_owner_object_ids()[0].tables,
            [(7, "account".to_owned()), (8, "account_old".to_owned())]
        );
        assert_eq!(map.orphans().len(), 1);
    }
}

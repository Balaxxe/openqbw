//! Physical table identity from a validated materialized SA17 type-4 page.
//!
//! Enterprise 24 observations establish a nonzero little-endian `u32` at
//! page offset `0x18` as the physical SQL Anywhere table ID.  This module
//! only reads that header field after the complete type-4 page and every
//! nonzero directory entry have passed [`opensqlany::MaterializedTablePage`]
//! validation.  It does not resolve names, infer row grammar, or select a
//! current row version.

use opensqlany::{MaterializedPageError, MaterializedTablePage};

const TABLE_ID_OFFSET: usize = 0x18;
const TABLE_ID_END: usize = TABLE_ID_OFFSET + size_of::<u32>();

/// Validated physical SQL Anywhere table identifier carried by a materialized
/// Enterprise 24 type-4 table page.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MaterializedTableId(u32);

impl MaterializedTableId {
    /// Returns the nonzero physical table ID.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Extracts the physical table ID from one fully validated materialized page.
///
/// The input must be the post-materialization 4096-byte representation, not
/// a raw QBW page.  A zero value is rejected because it is not a usable SQL
/// Anywhere table identifier and would otherwise allow an unclassified page
/// to enter a table-specific decoder.
pub fn materialized_table_id(
    materialized_page_bytes: &[u8],
) -> Result<MaterializedTableId, MaterializedTableIdError> {
    MaterializedTablePage::parse(materialized_page_bytes)
        .map_err(MaterializedTableIdError::InvalidMaterializedTablePage)?;
    let bytes: [u8; size_of::<u32>()] = materialized_page_bytes[TABLE_ID_OFFSET..TABLE_ID_END]
        .try_into()
        .expect("validated materialized pages have a fixed 4096-byte length");
    let table_id = u32::from_le_bytes(bytes);
    if table_id == 0 {
        return Err(MaterializedTableIdError::ZeroTableId);
    }
    Ok(MaterializedTableId(table_id))
}

/// Failure while extracting [`MaterializedTableId`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterializedTableIdError {
    /// The input was not a fully valid materialized type-4 page.
    InvalidMaterializedTablePage(MaterializedPageError),
    /// Header field `u32le(page + 0x18)` was zero.
    ZeroTableId,
}

impl std::fmt::Display for MaterializedTableIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMaterializedTablePage(source) => {
                write!(f, "invalid materialized table page: {source}")
            }
            Self::ZeroTableId => f.write_str("materialized table page has zero table id"),
        }
    }
}

impl std::error::Error for MaterializedTableIdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidMaterializedTablePage(source) => Some(source),
            Self::ZeroTableId => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(table_id: u32) -> [u8; 4096] {
        let mut bytes = [0_u8; 4096];
        bytes[0x10] = 4;
        bytes[TABLE_ID_OFFSET..TABLE_ID_END].copy_from_slice(&table_id.to_le_bytes());
        bytes
    }

    #[test]
    fn reads_table_id_only_after_full_type4_validation() {
        assert_eq!(materialized_table_id(&page(42)).unwrap().get(), 42);

        let mut invalid = page(42);
        invalid[0x10] = 3;
        assert_eq!(
            materialized_table_id(&invalid),
            Err(MaterializedTableIdError::InvalidMaterializedTablePage(
                MaterializedPageError::WrongPageType { actual: 3 }
            ))
        );
    }

    #[test]
    fn rejects_zero_table_id() {
        assert_eq!(
            materialized_table_id(&page(0)),
            Err(MaterializedTableIdError::ZeroTableId)
        );
    }
}

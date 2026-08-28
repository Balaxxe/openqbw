//! Safe lookup helpers for bounded schema-prefix decodes.
//!
//! A [`opensqlany::PartialDecodedRow`] intentionally contains only fields
//! whose physical grammar is known plus the independently located Boolean
//! tail.  These helpers preserve that boundary: a lookup never falls back to
//! a later schema column merely because its name is known.

use opensqlany::{PartialDecodedRow, RowSchema, Value};
use thiserror::Error;

/// Retrieves one prefix value by its catalog column identifier.
///
/// `None` means the identifier was not part of the decoded prefix.  It is
/// distinct from `Some(Value::Null)`, which is a positively decoded SQL NULL.
#[must_use]
pub fn prefix_value_by_column_id(row: &PartialDecodedRow, column_id: u32) -> Option<&Value> {
    row.prefix_values
        .iter()
        .find(|value| value.column_id == column_id)
        .map(|value| &value.value)
}

/// Retrieves one Boolean-tail value by its catalog column identifier.
///
/// `None` means the Boolean was not present in the physical row (or was not
/// decoded); it is not coerced to `false`.
#[must_use]
pub fn boolean_value_by_column_id(row: &PartialDecodedRow, column_id: u32) -> Option<&Value> {
    row.boolean_values
        .iter()
        .find(|value| value.column_id == column_id)
        .map(|value| &value.value)
}

/// Resolves an exactly named prefix field through a supplied schema.
///
/// The schema is used only to bind a spelling to a catalog id/index.  The
/// helper rejects duplicate spellings and a row/schema provenance mismatch.
pub fn prefix_value_by_column_name<'a>(
    schema: &RowSchema,
    row: &'a PartialDecodedRow,
    name: &str,
) -> Result<Option<&'a Value>, PartialRowLookupError> {
    value_by_name(schema, row, name, false)
}

/// Resolves an exactly named Boolean-tail field through a supplied schema.
pub fn boolean_value_by_column_name<'a>(
    schema: &RowSchema,
    row: &'a PartialDecodedRow,
    name: &str,
) -> Result<Option<&'a Value>, PartialRowLookupError> {
    value_by_name(schema, row, name, true)
}

fn value_by_name<'a>(
    schema: &RowSchema,
    row: &'a PartialDecodedRow,
    name: &str,
    boolean: bool,
) -> Result<Option<&'a Value>, PartialRowLookupError> {
    let mut found = schema
        .columns
        .iter()
        .enumerate()
        .filter(|(_, column)| column.name == name);
    let Some((column_index, column)) = found.next() else {
        return Ok(None);
    };
    if found.next().is_some() {
        return Err(PartialRowLookupError::AmbiguousColumnName {
            name: name.to_owned(),
        });
    }
    let values = if boolean {
        &row.boolean_values
    } else {
        &row.prefix_values
    };
    let Some(value) = values.iter().find(|value| value.column_id == column.id) else {
        return Ok(None);
    };
    if value.column_index != column_index {
        return Err(PartialRowLookupError::SchemaProvenanceMismatch {
            name: name.to_owned(),
            expected_index: column_index,
            actual_index: value.column_index,
        });
    }
    Ok(Some(&value.value))
}

/// Failure while binding a partial row to schema names.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PartialRowLookupError {
    /// The supplied schema defines the exact name more than once.
    #[error("partial-row schema has duplicate column name {name}")]
    AmbiguousColumnName {
        /// Duplicate exact name.
        name: String,
    },
    /// The decoded row's id/index provenance does not match the supplied
    /// schema, so the value must not be interpreted under that schema.
    #[error("partial-row field {name} has index {actual_index}; expected {expected_index}")]
    SchemaProvenanceMismatch {
        /// Exact schema name.
        name: String,
        /// Index from supplied schema.
        expected_index: usize,
        /// Index retained in the partial row.
        actual_index: usize,
    },
}

#[cfg(test)]
mod tests {
    use opensqlany::{ColumnDef, ColumnType, PartialRowValue};

    use super::*;

    fn row() -> PartialDecodedRow {
        PartialDecodedRow {
            declared_size: 18,
            flags: 0,
            through_ordinal: 1,
            prefix_values: vec![PartialRowValue {
                column_index: 0,
                column_id: 7,
                value: Value::Integer(12),
            }],
            boolean_values: vec![PartialRowValue {
                column_index: 1,
                column_id: 8,
                value: Value::Boolean(true),
            }],
            opaque_middle_len: 4,
        }
    }

    #[test]
    fn keeps_absent_distinct_from_decoded_null_and_binds_names_to_provenance() {
        let schema = RowSchema::new(vec![
            ColumnDef::new(7, "prefix", ColumnType::Integer, 4, false),
            ColumnDef::new(8, "tail", ColumnType::Boolean, 1, false),
        ]);
        let partial = row();
        assert_eq!(
            prefix_value_by_column_id(&partial, 7),
            Some(&Value::Integer(12))
        );
        assert_eq!(
            boolean_value_by_column_id(&partial, 8),
            Some(&Value::Boolean(true))
        );
        assert_eq!(
            prefix_value_by_column_name(&schema, &partial, "prefix").unwrap(),
            Some(&Value::Integer(12))
        );
        assert_eq!(
            boolean_value_by_column_name(&schema, &partial, "tail").unwrap(),
            Some(&Value::Boolean(true))
        );
        assert_eq!(
            prefix_value_by_column_name(&schema, &partial, "tail").unwrap(),
            None
        );
    }
}

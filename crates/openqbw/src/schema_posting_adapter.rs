//! Table-bound adapter from complete schema-decoded rows to posting fields.
//!
//! This module intentionally consumes only named catalog columns from an
//! already complete [`opensqlany::RowSchema`].  It neither guesses columns by
//! position nor treats arbitrary numeric fields as money.  It is an
//! intermediate bridge: current-version selection, header joins, and ledger
//! construction remain separate gates.

use opensqlany::{ColumnType, DecodedRow, NumericLayout, PartialDecodedRow, RowSchema, Value};
use thiserror::Error;

use crate::{
    AccountingDate, Enterprise24AccountingTable, MaterializedBillPostingRow,
    MaterializedBillTransactionKind, MaterializedCheckPostingRow,
    MaterializedGeneralJournalPostingRow, MaterializedPostingDate, boolean_value_by_column_name,
    materialized_numeric::MaterializedPostingCents, prefix_value_by_column_name,
};

/// A native QuickBooks transaction label carried by a normalized posting.
///
/// These are deliberately report-facing labels, rather than physical table
/// identifiers.  The Bill physical family is exceptional: its view value is
/// required to distinguish a Bill from QuickBooks' native `Credit` display
/// type, so it can only be assigned by the dedicated Bill decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterprisePostingTransactionType {
    /// Native QuickBooks `Bill Pmt-Check` transaction type.
    BillPaymentCheck,
    /// Native QuickBooks `Bill` transaction type.
    Bill,
    /// A vendor credit, displayed as `Credit` by native QuickBooks reports.
    VendorCredit,
    /// Native QuickBooks `Check` transaction type.
    Check,
    /// Native QuickBooks `Deposit` transaction type.
    Deposit,
    /// Native QuickBooks `General Journal` transaction type.
    GeneralJournal,
}

impl EnterprisePostingTransactionType {
    /// Stable native-style text emitted in GL CSV, JSON, and SQLite output.
    #[must_use]
    pub const fn source_label(self) -> &'static str {
        match self {
            Self::BillPaymentCheck => "Bill Pmt-Check",
            Self::Bill => "Bill",
            Self::VendorCredit => "Credit",
            Self::Check => "Check",
            Self::Deposit => "Deposit",
            Self::GeneralJournal => "General Journal",
        }
    }

    fn fixed_for_table(table: Enterprise24AccountingTable) -> Option<Self> {
        match table {
            Enterprise24AccountingTable::BillPaymentCheckLine => Some(Self::BillPaymentCheck),
            Enterprise24AccountingTable::CheckLine => Some(Self::Check),
            Enterprise24AccountingTable::DepositLine => Some(Self::Deposit),
            Enterprise24AccountingTable::GeneralJournalLine => Some(Self::GeneralJournal),
            Enterprise24AccountingTable::BillLine => None,
            _ => None,
        }
    }

    fn from_bill_kind(kind: MaterializedBillTransactionKind) -> Self {
        match kind {
            MaterializedBillTransactionKind::Bill => Self::Bill,
            MaterializedBillTransactionKind::VendorCredit => Self::VendorCredit,
        }
    }
}

/// Adapts one validated, bounded table-3042 Bill posting row.
///
/// The Bill collector has already excluded only its counted non-row artifact;
/// this adapter derives every normalized posting field from the closed
/// physical grammar rather than a partial schema prefix.
pub fn adapt_materialized_bill_posting_row(
    row: &MaterializedBillPostingRow,
) -> Result<EnterprisePostingAdaptation, EnterprisePostingAdapterError> {
    let target_id = u64::from(row.target_record_number());
    let transaction_id = u64::from(row.master_record_number());
    let account_id = u64::from(row.account_record_number());
    let transaction_date = row
        .posting_date()
        .map(|date| date.accounting_date())
        .map_err(|_| EnterprisePostingAdapterError::InvalidPostingDate {
            name: "transaction_date".to_owned(),
            raw_minutes: i32::from_le_bytes(row.date_raw().to_le_bytes()),
        })?;
    let transaction_type = row
        .transaction_kind()
        .map(EnterprisePostingTransactionType::from_bill_kind)
        .ok_or(EnterprisePostingAdapterError::UnknownBillTransactionView {
            view_type: row.view_type(),
        })?;
    if row.has_canonical_zero_amount() {
        return Ok(EnterprisePostingAdaptation::Excluded(
            EnterprisePostingExclusion::CanonicalZeroAmount {
                target_id,
                transaction_id,
                account_id,
                transaction_date,
                transaction_type,
            },
        ));
    }
    Ok(EnterprisePostingAdaptation::Posting(EnterprisePostingRow {
        table: Enterprise24AccountingTable::BillLine,
        transaction_type,
        target_id,
        transaction_id,
        account_id,
        transaction_date,
        amount_cents: row.signed_cents(),
        is_source: None,
        is_split: None,
    }))
}

/// Adapts a table-wide-attested General Journal monetary carrier.  Source and
/// auxiliary rows are intentionally excluded by the table collector before
/// this function can be called.
pub fn adapt_materialized_general_journal_posting_row(
    row: &MaterializedGeneralJournalPostingRow,
) -> Result<EnterprisePostingAdaptation, EnterprisePostingAdapterError> {
    let target_id = u64::from(row.target_record_number());
    let transaction_id = u64::from(row.master_record_number());
    if row.is_no_post() {
        return Ok(EnterprisePostingAdaptation::Excluded(
            EnterprisePostingExclusion::NoPost {
                target_id,
                transaction_id,
            },
        ));
    }
    if row.is_memorized_transaction() {
        return Ok(EnterprisePostingAdaptation::Excluded(
            EnterprisePostingExclusion::MemorizedTransaction {
                target_id,
                transaction_id,
            },
        ));
    }
    let transaction_date = row
        .posting_date()
        .map(|date| date.accounting_date())
        .map_err(|_| EnterprisePostingAdapterError::InvalidPostingDate {
            name: "transaction_date".to_owned(),
            raw_minutes: i32::from_le_bytes(row.date_raw().to_le_bytes()),
        })?;
    if row.signed_cents() == 0 {
        return Err(EnterprisePostingAdapterError::InvalidPostingAmount {
            name: "amount_amt".to_owned(),
        });
    }
    Ok(EnterprisePostingAdaptation::Posting(EnterprisePostingRow {
        table: Enterprise24AccountingTable::GeneralJournalLine,
        transaction_type: EnterprisePostingTransactionType::GeneralJournal,
        target_id: u64::from(row.target_record_number()),
        transaction_id: u64::from(row.master_record_number()),
        account_id: u64::from(row.account_record_number()),
        transaction_date,
        amount_cents: row.signed_cents(),
        is_source: None,
        is_split: None,
    }))
}

/// Adapts one validated, bounded table-3047 Check posting row.
///
/// Unlike the schema-prefix bridge, this follows the closed physical Check
/// grammar.  It deliberately does not infer values from a generic row schema:
/// account, master, target, date, and amount are all established by
/// [`MaterializedCheckPostingRow`].  Void/current selection remains the
/// table-wide lifecycle gate owned by the extraction pipeline.
pub fn adapt_materialized_check_posting_row(
    row: &MaterializedCheckPostingRow,
) -> Result<EnterprisePostingAdaptation, EnterprisePostingAdapterError> {
    let target_id = u64::from(row.target_record_number());
    let transaction_id = u64::from(row.master_record_number());
    let account_id = u64::from(row.account_record_number());
    let transaction_date = row
        .posting_date()
        .map(|date| date.accounting_date())
        .map_err(|_| EnterprisePostingAdapterError::InvalidPostingDate {
            name: "transaction_date".to_owned(),
            raw_minutes: i32::from_le_bytes(row.date_raw().to_le_bytes()),
        })?;
    let transaction_type = EnterprisePostingTransactionType::Check;
    if row.has_canonical_zero_amount() {
        return Ok(EnterprisePostingAdaptation::Excluded(
            EnterprisePostingExclusion::CanonicalZeroAmount {
                target_id,
                transaction_id,
                account_id,
                transaction_date,
                transaction_type,
            },
        ));
    }
    Ok(EnterprisePostingAdaptation::Posting(EnterprisePostingRow {
        table: Enterprise24AccountingTable::CheckLine,
        transaction_type,
        target_id,
        transaction_id,
        account_id,
        transaction_date,
        amount_cents: row.signed_cents(),
        is_source: None,
        is_split: None,
    }))
}

/// A normalized, schema-decoded Enterprise posting line before ledger joins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterprisePostingRow {
    /// Physical line table supplying this row.
    pub table: Enterprise24AccountingTable,
    /// Native QuickBooks transaction category established by the decoder.
    pub transaction_type: EnterprisePostingTransactionType,
    /// Stable logical line identity from `target_id`.
    pub target_id: u64,
    /// Stable logical transaction identity from `transaction_id`.
    pub transaction_id: u64,
    /// Stable logical account identity from `account_id`.
    pub account_id: u64,
    /// Strict midnight business date, normalized to SA epoch days.
    pub transaction_date: AccountingDate,
    /// Signed controlled materialized amount in cents.
    pub amount_cents: i64,
    /// Whether this line is marked as a source line.
    pub is_source: Option<bool>,
    /// Whether this line is marked as a split line.
    pub is_split: Option<bool>,
}

/// A line which was deliberately excluded before it could become a posting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterprisePostingExclusion {
    /// QuickBooks marks the row as non-posting.
    NoPost {
        /// Logical line identity retained for audit/provenance.
        target_id: u64,
        /// Logical transaction identity retained for audit/provenance.
        transaction_id: u64,
    },
    /// QuickBooks marks the row as part of a memorized transaction.
    MemorizedTransaction {
        /// Logical line identity retained for audit/provenance.
        target_id: u64,
        /// Logical transaction identity retained for audit/provenance.
        transaction_id: u64,
    },
    /// The line carries the exact observed canonical zero amount token.
    ///
    /// This legacy exclusion is valid only after independent lifecycle
    /// evidence establishes a void/tombstone. Production adapters do not infer
    /// it from the zero token alone. Source identifiers remain available for
    /// lifecycle reconciliation.
    CanonicalZeroVoided {
        /// Logical line identity retained for audit/provenance.
        target_id: u64,
        /// Logical transaction identity retained for audit/provenance.
        transaction_id: u64,
    },
    /// A fully validated monetary-line carrier has the exact canonical zero
    /// amount token. This is not a lifecycle claim: callers must still apply
    /// any table-family current-state policy before excluding it.
    CanonicalZeroAmount {
        /// Logical line identity retained for audit/provenance.
        target_id: u64,
        /// Logical transaction identity retained for audit/provenance.
        transaction_id: u64,
        /// Validated physical account reference, which callers must resolve.
        account_id: u64,
        /// Validated posting date retained to prevent a zero branch bypass.
        transaction_date: AccountingDate,
        /// Established transaction family/view retained to prevent guessing.
        transaction_type: EnterprisePostingTransactionType,
    },
    /// A proven source/link row carries no `amount_amt` value.
    ///
    /// Source rows can carry relationship metadata without a standalone
    /// posting amount. A nonzero source amount remains a normal candidate
    /// posting and is not excluded by this disposition.
    SourceOrLink {
        /// Logical line identity retained for audit/provenance.
        target_id: u64,
        /// Logical transaction identity retained for audit/provenance.
        transaction_id: u64,
    },
}

/// Result of adapting one fully schema-decoded line row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnterprisePostingAdaptation {
    /// A field-complete candidate posting line.
    Posting(EnterprisePostingRow),
    /// A positively identified logical exclusion.
    Excluded(EnterprisePostingExclusion),
}

/// Map one complete Enterprise 24 line-table row by its exact catalog names.
///
/// Only the observed `amount_amt` column is accepted as money, and only when
/// its decoded value is an Enterprise materialized numeric token.  Required
/// identifiers must be nonzero and the date must pass the strict posting-date
/// codec.  The function deliberately rejects a header/non-accounting table,
/// a partial/malformed schema-row pair, duplicate column names, unknown name
/// variants, and incorrect physical domains.
pub fn adapt_enterprise_posting_row(
    table: Enterprise24AccountingTable,
    schema: &RowSchema,
    row: DecodedRow,
) -> Result<EnterprisePostingAdaptation, EnterprisePostingAdapterError> {
    let layout = PostingColumnLayout::for_table(table)?;
    if schema.columns.len() != row.values.len() {
        return Err(EnterprisePostingAdapterError::SchemaValueCountMismatch {
            columns: schema.columns.len(),
            values: row.values.len(),
        });
    }
    if row.declared_size != row.consumed_size {
        return Err(EnterprisePostingAdapterError::RowNotExactlyDecoded {
            declared_size: row.declared_size,
            consumed_size: row.consumed_size,
        });
    }

    let target_id = required_id(schema, &row, layout.target_id)?;
    let transaction_id = required_id(schema, &row, layout.transaction_id)?;

    if required_bool(schema, &row, layout.is_no_post_bool)? {
        return Ok(EnterprisePostingAdaptation::Excluded(
            EnterprisePostingExclusion::NoPost {
                target_id,
                transaction_id,
            },
        ));
    }
    if required_bool(schema, &row, layout.is_memorized_transaction_bool)? {
        return Ok(EnterprisePostingAdaptation::Excluded(
            EnterprisePostingExclusion::MemorizedTransaction {
                target_id,
                transaction_id,
            },
        ));
    }

    let is_source = optional_bool(schema, &row, layout.is_source_bool)?;
    if is_source == Some(true) && amount_is_sql_null(schema, &row, layout.amount_amt)? {
        return Ok(EnterprisePostingAdaptation::Excluded(
            EnterprisePostingExclusion::SourceOrLink {
                target_id,
                transaction_id,
            },
        ));
    }
    let account_id = required_id(schema, &row, layout.account_id)?;
    let transaction_date = required_date(schema, &row, layout.transaction_date)?;
    let transaction_type = EnterprisePostingTransactionType::fixed_for_table(table)
        .ok_or(EnterprisePostingAdapterError::TransactionTypeRequiresDedicatedDecoder { table })?;
    let is_split = optional_bool(schema, &row, layout.is_split_bool)?;
    let amount = required_amount(schema, &row, layout.amount_amt)?;
    if amount.canonical_zero {
        return Ok(EnterprisePostingAdaptation::Excluded(
            EnterprisePostingExclusion::CanonicalZeroAmount {
                target_id,
                transaction_id,
                account_id,
                transaction_date,
                transaction_type,
            },
        ));
    }
    Ok(EnterprisePostingAdaptation::Posting(EnterprisePostingRow {
        table,
        transaction_type,
        target_id,
        transaction_id,
        account_id,
        transaction_date,
        amount_cents: amount.cents,
        is_source,
        is_split,
    }))
}

/// Maps a bounded schema prefix plus independently decoded Boolean storage.
///
/// Unlike [`adapt_enterprise_posting_row`], this path does not claim that the
/// supplied schema consumes the physical row.  It reads only exact named
/// fields that are actually present in `partial`: non-Boolean values must be
/// in the decoded prefix and Boolean gates must be in the separately decoded
/// tail.  Missing fields are rejected instead of being inferred from a
/// physical layout or later opaque bytes.
pub fn adapt_enterprise_posting_row_partial(
    table: Enterprise24AccountingTable,
    schema: &RowSchema,
    partial: &PartialDecodedRow,
) -> Result<EnterprisePostingAdaptation, EnterprisePostingAdapterError> {
    let layout = PostingColumnLayout::for_table(table)?;
    let target_id = partial_required_id(schema, partial, layout.target_id)?;
    let transaction_id = partial_required_id(schema, partial, layout.transaction_id)?;
    if partial_required_bool(schema, partial, layout.is_no_post_bool)? {
        return Ok(EnterprisePostingAdaptation::Excluded(
            EnterprisePostingExclusion::NoPost {
                target_id,
                transaction_id,
            },
        ));
    }
    if partial_required_bool(schema, partial, layout.is_memorized_transaction_bool)? {
        return Ok(EnterprisePostingAdaptation::Excluded(
            EnterprisePostingExclusion::MemorizedTransaction {
                target_id,
                transaction_id,
            },
        ));
    }
    let is_source = partial_optional_bool(schema, partial, layout.is_source_bool)?;
    if is_source == Some(true) && partial_amount_is_sql_null(schema, partial, layout.amount_amt)? {
        return Ok(EnterprisePostingAdaptation::Excluded(
            EnterprisePostingExclusion::SourceOrLink {
                target_id,
                transaction_id,
            },
        ));
    }
    let transaction_type = EnterprisePostingTransactionType::fixed_for_table(table)
        .ok_or(EnterprisePostingAdapterError::TransactionTypeRequiresDedicatedDecoder { table })?;
    let account_id = partial_required_id(schema, partial, layout.account_id)?;
    let transaction_date = partial_required_date(schema, partial, layout.transaction_date)?;
    let is_split = partial_optional_bool(schema, partial, layout.is_split_bool)?;
    let amount = partial_required_amount(schema, partial, layout.amount_amt)?;
    if amount.canonical_zero {
        return Ok(EnterprisePostingAdaptation::Excluded(
            EnterprisePostingExclusion::CanonicalZeroAmount {
                target_id,
                transaction_id,
                account_id,
                transaction_date,
                transaction_type,
            },
        ));
    }
    Ok(EnterprisePostingAdaptation::Posting(EnterprisePostingRow {
        table,
        transaction_type,
        target_id,
        transaction_id,
        account_id,
        transaction_date,
        amount_cents: amount.cents,
        is_source,
        is_split,
    }))
}

fn partial_named_column<'a>(
    schema: &'a RowSchema,
    row: &'a PartialDecodedRow,
    names: &[&str],
) -> Result<Option<(&'a str, &'a opensqlany::ColumnDef, &'a Value)>, EnterprisePostingAdapterError>
{
    let mut found = None;
    let mut matched_schema_name = false;
    for column in &schema.columns {
        if names.contains(&column.name.as_str()) {
            if matched_schema_name {
                return Err(EnterprisePostingAdapterError::AmbiguousColumn {
                    accepted: names.join(" or "),
                });
            }
            matched_schema_name = true;
            let value = if column.column_type == ColumnType::Boolean {
                boolean_value_by_column_name(schema, row, &column.name)
            } else {
                prefix_value_by_column_name(schema, row, &column.name)
            }
            .map_err(|_| EnterprisePostingAdapterError::PartialSchemaProvenance {
                name: column.name.clone(),
            })?;
            if let Some(value) = value {
                found = Some((column.name.as_str(), column, value));
            }
        }
    }
    Ok(found)
}

fn partial_required_column<'a>(
    schema: &'a RowSchema,
    row: &'a PartialDecodedRow,
    names: &[&str],
) -> Result<(&'a str, &'a opensqlany::ColumnDef, &'a Value), EnterprisePostingAdapterError> {
    partial_named_column(schema, row, names)?.ok_or_else(|| {
        EnterprisePostingAdapterError::PartialValueUnavailable {
            accepted: names.join(" or "),
        }
    })
}

fn partial_required_id(
    schema: &RowSchema,
    row: &PartialDecodedRow,
    names: &[&str],
) -> Result<u64, EnterprisePostingAdapterError> {
    let (name, column, value) = partial_required_column(schema, row, names)?;
    id_value(name, column.column_type, value)
}

fn partial_required_date(
    schema: &RowSchema,
    row: &PartialDecodedRow,
    names: &[&str],
) -> Result<AccountingDate, EnterprisePostingAdapterError> {
    let (name, column, value) = partial_required_column(schema, row, names)?;
    date_value(name, column.column_type, value)
}

fn partial_required_amount(
    schema: &RowSchema,
    row: &PartialDecodedRow,
    names: &[&str],
) -> Result<DecodedPostingAmount, EnterprisePostingAdapterError> {
    let (name, column, value) = partial_required_column(schema, row, names)?;
    amount_value(schema, name, column.column_type, value)
}

fn partial_amount_is_sql_null(
    schema: &RowSchema,
    row: &PartialDecodedRow,
    names: &[&str],
) -> Result<bool, EnterprisePostingAdapterError> {
    let (name, column, value) = partial_required_column(schema, row, names)?;
    numeric_null_value(name, column.column_type, value)
}

fn partial_required_bool(
    schema: &RowSchema,
    row: &PartialDecodedRow,
    names: &[&str],
) -> Result<bool, EnterprisePostingAdapterError> {
    let (name, column, value) = partial_required_column(schema, row, names)?;
    bool_value(name, column.column_type, value)
}

fn partial_optional_bool(
    schema: &RowSchema,
    row: &PartialDecodedRow,
    names: &[&str],
) -> Result<Option<bool>, EnterprisePostingAdapterError> {
    match partial_named_column(schema, row, names)? {
        Some((name, column, value)) => bool_value(name, column.column_type, value).map(Some),
        None => Ok(None),
    }
}

/// Exact catalog-name policy for a proven Enterprise posting family.
///
/// Family-specific definitions are separate even where they currently use the
/// same spelling.  A future verified spelling change must be added to just
/// that family's explicit policy; generic fuzzy matching is intentionally not
/// available.
#[derive(Clone, Copy)]
struct PostingColumnLayout {
    target_id: &'static [&'static str],
    transaction_id: &'static [&'static str],
    account_id: &'static [&'static str],
    transaction_date: &'static [&'static str],
    amount_amt: &'static [&'static str],
    is_no_post_bool: &'static [&'static str],
    is_memorized_transaction_bool: &'static [&'static str],
    is_source_bool: &'static [&'static str],
    is_split_bool: &'static [&'static str],
}

impl PostingColumnLayout {
    fn for_table(
        table: Enterprise24AccountingTable,
    ) -> Result<Self, EnterprisePostingAdapterError> {
        if !table.is_posting_table() {
            return Err(EnterprisePostingAdapterError::NotPostingTable { table });
        }
        // These are exact Enterprise 24 catalog spellings.  Each family has
        // its own policy slot even though the recovered spellings currently
        // agree; no aliases are inferred from a partial catalog.
        const CORE: PostingColumnLayout = PostingColumnLayout {
            target_id: &["target_id"],
            transaction_id: &["transaction_id"],
            account_id: &["account_id"],
            transaction_date: &["transaction_date"],
            amount_amt: &["amount_amt"],
            is_no_post_bool: &["is_no_post_bool"],
            is_memorized_transaction_bool: &["is_memorized_transaction_bool"],
            is_source_bool: &["is_source_bool"],
            is_split_bool: &["is_split_bool"],
        };
        match table {
            Enterprise24AccountingTable::BillPaymentCheckLine
            | Enterprise24AccountingTable::BillLine
            | Enterprise24AccountingTable::CheckLine
            | Enterprise24AccountingTable::DepositLine
            | Enterprise24AccountingTable::GeneralJournalLine => Ok(CORE),
            _ => unreachable!("posting table checked above"),
        }
    }
}

fn required_id(
    schema: &RowSchema,
    row: &DecodedRow,
    names: &[&str],
) -> Result<u64, EnterprisePostingAdapterError> {
    let (name, column, value) = required_column(schema, row, names)?;
    id_value(name, column.column_type, value)
}

fn id_value(
    name: &str,
    column_type: ColumnType,
    value: &Value,
) -> Result<u64, EnterprisePostingAdapterError> {
    if !matches!(
        column_type,
        ColumnType::Integer
            | ColumnType::Integer2
            | ColumnType::UInt32
            | ColumnType::UInt64
            | ColumnType::Int64
    ) {
        return Err(EnterprisePostingAdapterError::UnexpectedColumnType {
            name: name.to_owned(),
            expected: "integer identifier",
            actual: column_type,
        });
    }
    let value = match value {
        Value::Integer(value) => u64::try_from(*value).map_err(|_| {
            EnterprisePostingAdapterError::NegativeIdentifier {
                name: name.to_owned(),
            }
        })?,
        Value::Unsigned(value) => *value,
        _ => {
            return Err(EnterprisePostingAdapterError::UnexpectedValueType {
                name: name.to_owned(),
                expected: "integer identifier",
            });
        }
    };
    if value == 0 {
        return Err(EnterprisePostingAdapterError::ZeroIdentifier {
            name: name.to_owned(),
        });
    }
    Ok(value)
}

fn required_date(
    schema: &RowSchema,
    row: &DecodedRow,
    names: &[&str],
) -> Result<AccountingDate, EnterprisePostingAdapterError> {
    let (name, column, value) = required_column(schema, row, names)?;
    date_value(name, column.column_type, value)
}

fn date_value(
    name: &str,
    column_type: ColumnType,
    value: &Value,
) -> Result<AccountingDate, EnterprisePostingAdapterError> {
    if column_type != ColumnType::Date {
        return Err(EnterprisePostingAdapterError::UnexpectedColumnType {
            name: name.to_owned(),
            expected: "date",
            actual: column_type,
        });
    }
    let Value::Date(value) = value else {
        return Err(EnterprisePostingAdapterError::UnexpectedValueType {
            name: name.to_owned(),
            expected: "date",
        });
    };
    MaterializedPostingDate::from_raw_minutes(value.raw_minutes)
        .map(|date| date.accounting_date())
        .map_err(|_| EnterprisePostingAdapterError::InvalidPostingDate {
            name: name.to_owned(),
            raw_minutes: value.raw_minutes,
        })
}

fn required_amount(
    schema: &RowSchema,
    row: &DecodedRow,
    names: &[&str],
) -> Result<DecodedPostingAmount, EnterprisePostingAdapterError> {
    let (name, column, value) = required_column(schema, row, names)?;
    amount_value(schema, name, column.column_type, value)
}

fn amount_value(
    schema: &RowSchema,
    name: &str,
    column_type: ColumnType,
    value: &Value,
) -> Result<DecodedPostingAmount, EnterprisePostingAdapterError> {
    if column_type != ColumnType::Numeric {
        return Err(EnterprisePostingAdapterError::UnexpectedColumnType {
            name: name.to_owned(),
            expected: "numeric amount",
            actual: column_type,
        });
    }
    if schema.numeric_layout != NumericLayout::EnterpriseMaterializedRaw {
        return Err(EnterprisePostingAdapterError::UnexpectedNumericLayout);
    }
    let Value::EnterpriseNumeric(token) = value else {
        return Err(EnterprisePostingAdapterError::UnexpectedValueType {
            name: name.to_owned(),
            expected: "Enterprise numeric amount",
        });
    };
    MaterializedPostingCents::from_enterprise_token(token)
        .map(|amount| DecodedPostingAmount {
            cents: amount.signed_cents(),
            canonical_zero: amount.is_canonical_zero(),
        })
        .map_err(|_| EnterprisePostingAdapterError::InvalidPostingAmount {
            name: name.to_owned(),
        })
}

#[derive(Clone, Copy)]
struct DecodedPostingAmount {
    cents: i64,
    canonical_zero: bool,
}

fn amount_is_sql_null(
    schema: &RowSchema,
    row: &DecodedRow,
    names: &[&str],
) -> Result<bool, EnterprisePostingAdapterError> {
    let (name, column, value) = required_column(schema, row, names)?;
    numeric_null_value(name, column.column_type, value)
}

fn numeric_null_value(
    name: &str,
    column_type: ColumnType,
    value: &Value,
) -> Result<bool, EnterprisePostingAdapterError> {
    if column_type != ColumnType::Numeric {
        return Err(EnterprisePostingAdapterError::UnexpectedColumnType {
            name: name.to_owned(),
            expected: "numeric amount",
            actual: column_type,
        });
    }
    Ok(matches!(value, Value::Null))
}

fn required_bool(
    schema: &RowSchema,
    row: &DecodedRow,
    names: &[&str],
) -> Result<bool, EnterprisePostingAdapterError> {
    let (name, column, value) = required_column(schema, row, names)?;
    bool_value(name, column.column_type, value)
}

fn optional_bool(
    schema: &RowSchema,
    row: &DecodedRow,
    names: &[&str],
) -> Result<Option<bool>, EnterprisePostingAdapterError> {
    match named_column(schema, row, names)? {
        Some((name, column, value)) => bool_value(name, column.column_type, value).map(Some),
        None => Ok(None),
    }
}

fn bool_value(
    name: &str,
    column_type: ColumnType,
    value: &Value,
) -> Result<bool, EnterprisePostingAdapterError> {
    if column_type != ColumnType::Boolean {
        return Err(EnterprisePostingAdapterError::UnexpectedColumnType {
            name: name.to_owned(),
            expected: "boolean",
            actual: column_type,
        });
    }
    match value {
        Value::Boolean(value) => Ok(*value),
        _ => Err(EnterprisePostingAdapterError::UnexpectedValueType {
            name: name.to_owned(),
            expected: "boolean",
        }),
    }
}

fn required_column<'a>(
    schema: &'a RowSchema,
    row: &'a DecodedRow,
    names: &[&str],
) -> Result<(&'a str, &'a opensqlany::ColumnDef, &'a Value), EnterprisePostingAdapterError> {
    named_column(schema, row, names)?.ok_or_else(|| EnterprisePostingAdapterError::MissingColumn {
        accepted: names.join(" or "),
    })
}

fn named_column<'a>(
    schema: &'a RowSchema,
    row: &'a DecodedRow,
    names: &[&str],
) -> Result<Option<(&'a str, &'a opensqlany::ColumnDef, &'a Value)>, EnterprisePostingAdapterError>
{
    let mut found = None;
    for (column, value) in schema.columns.iter().zip(&row.values) {
        if names.contains(&column.name.as_str()) {
            if found.is_some() {
                return Err(EnterprisePostingAdapterError::AmbiguousColumn {
                    accepted: names.join(" or "),
                });
            }
            found = Some((column.name.as_str(), column, value));
        }
    }
    Ok(found)
}

/// Reasons a schema-decoded row cannot safely become a posting candidate.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum EnterprisePostingAdapterError {
    /// A partial row's retained id/index provenance did not match the schema
    /// used to resolve a named field.
    #[error("partial posting value for column {name} does not match schema provenance")]
    PartialSchemaProvenance {
        /// Exact catalog name.
        name: String,
    },
    /// A required exact catalog field exists in the schema but was not
    /// included in the bounded prefix or Boolean storage.
    #[error(
        "required posting value is unavailable in the bounded partial row; accepted names: {accepted}"
    )]
    PartialValueUnavailable {
        /// Exact accepted catalog names.
        accepted: String,
    },
    /// The supplied Enterprise table is not a posting-line table.
    #[error("table {table:?} is not an Enterprise posting table")]
    NotPostingTable {
        /// Supplied physical table identity.
        table: Enterprise24AccountingTable,
    },
    /// Schema metadata did not align one-to-one with decoded values.
    #[error("schema has {columns} columns but row has {values} values")]
    SchemaValueCountMismatch {
        /// Number of schema columns.
        columns: usize,
        /// Number of decoded values.
        values: usize,
    },
    /// The row was decoded permissively rather than exactly.
    #[error(
        "row was not exactly decoded: declared {declared_size} bytes, consumed {consumed_size}"
    )]
    RowNotExactlyDecoded {
        /// Header-declared row byte length.
        declared_size: usize,
        /// Byte length actually decoded.
        consumed_size: usize,
    },
    /// The schema does not explicitly select the materialized numeric dialect.
    #[error("posting schema does not declare Enterprise materialized numeric tokens")]
    UnexpectedNumericLayout,
    /// A required exact catalog name was absent.
    #[error("required posting column is missing; accepted names: {accepted}")]
    MissingColumn {
        /// Exact accepted catalog names.
        accepted: String,
    },
    /// More than one matching exact catalog name was present.
    #[error("posting column name is ambiguous; accepted names: {accepted}")]
    AmbiguousColumn {
        /// Exact accepted catalog names.
        accepted: String,
    },
    /// A named column had a catalog domain incompatible with its role.
    #[error("column {name} has type {actual:?}; expected {expected}")]
    UnexpectedColumnType {
        /// Catalog column name.
        name: String,
        /// Required semantic physical domain.
        expected: &'static str,
        /// Actual catalog physical domain.
        actual: ColumnType,
    },
    /// A named column's decoded value did not match its schema role.
    #[error("column {name} has an incompatible decoded value; expected {expected}")]
    UnexpectedValueType {
        /// Catalog column name.
        name: String,
        /// Required decoded value class.
        expected: &'static str,
    },
    /// An identifier used a signed negative value.
    #[error("identifier column {name} is negative")]
    NegativeIdentifier {
        /// Catalog column name.
        name: String,
    },
    /// A required logical identifier was zero.
    #[error("identifier column {name} is zero")]
    ZeroIdentifier {
        /// Catalog column name.
        name: String,
    },
    /// A date was not a strict midnight materialized business date.
    #[error("posting date column {name} is not a strict midnight date ({raw_minutes})")]
    InvalidPostingDate {
        /// Catalog column name.
        name: String,
        /// Source SQL Anywhere minute count.
        raw_minutes: i32,
    },
    /// An amount token did not use the controlled materialized cents grammar.
    #[error("posting amount column {name} is not a controlled Enterprise cents token")]
    InvalidPostingAmount {
        /// Catalog column name.
        name: String,
    },
    /// The Bill family needs its bounded physical view field to select a
    /// native transaction type; a generic schema adapter cannot guess it.
    #[error("table {table:?} requires its dedicated transaction-type decoder")]
    TransactionTypeRequiresDedicatedDecoder {
        /// Physical table identity.
        table: Enterprise24AccountingTable,
    },
    /// A materialized Bill row had no attested transaction-view meaning.
    #[error("materialized Bill view {view_type} has no attested transaction type")]
    UnknownBillTransactionView {
        /// Opaque raw `transaction_view_type` value.
        view_type: u16,
    },
}

#[cfg(test)]
mod tests {
    use opensqlany::{ColumnDef, EnterpriseNumericToken, PartialRowValue, SaDate};

    use super::*;

    fn schema(source_and_split: bool) -> RowSchema {
        let mut columns = vec![
            ColumnDef::new(1, "target_id", ColumnType::Integer, 4, false),
            ColumnDef::new(2, "transaction_id", ColumnType::Integer, 4, false),
            ColumnDef::new(3, "account_id", ColumnType::Integer, 4, true),
            ColumnDef::new(4, "transaction_date", ColumnType::Date, 4, true),
            ColumnDef::new(5, "amount_amt", ColumnType::Numeric, 20, true),
            ColumnDef::new(6, "is_no_post_bool", ColumnType::Boolean, 1, false),
            ColumnDef::new(
                7,
                "is_memorized_transaction_bool",
                ColumnType::Boolean,
                1,
                false,
            ),
        ];
        if source_and_split {
            columns.push(ColumnDef::new(
                8,
                "is_source_bool",
                ColumnType::Boolean,
                1,
                false,
            ));
            columns.push(ColumnDef::new(
                9,
                "is_split_bool",
                ColumnType::Boolean,
                1,
                false,
            ));
        }
        let mut schema = RowSchema::new(columns);
        schema.numeric_layout = opensqlany::NumericLayout::EnterpriseMaterializedRaw;
        schema
    }

    fn row(no_post: bool, memorized: bool) -> DecodedRow {
        DecodedRow {
            declared_size: 0,
            consumed_size: 0,
            flags: 0,
            values: vec![
                Value::Integer(7),
                Value::Integer(11),
                Value::Integer(13),
                Value::Date(SaDate {
                    raw_minutes: 194_516_640,
                }),
                Value::EnterpriseNumeric(EnterpriseNumericToken {
                    marker: 0xbf,
                    digits: vec![41, 37],
                }),
                Value::Boolean(no_post),
                Value::Boolean(memorized),
                Value::Boolean(true),
                Value::Boolean(false),
            ],
        }
    }

    fn partial(no_post: bool, memorized: bool) -> PartialDecodedRow {
        let complete = row(no_post, memorized);
        PartialDecodedRow {
            declared_size: 100,
            flags: 0,
            through_ordinal: 5,
            prefix_values: complete
                .values
                .iter()
                .take(5)
                .cloned()
                .enumerate()
                .map(|(column_index, value)| PartialRowValue {
                    column_index,
                    column_id: (column_index + 1) as u32,
                    value,
                })
                .collect(),
            boolean_values: complete
                .values
                .iter()
                .enumerate()
                .skip(5)
                .map(|(column_index, value)| PartialRowValue {
                    column_index,
                    column_id: (column_index + 1) as u32,
                    value: value.clone(),
                })
                .collect(),
            opaque_middle_len: 11,
        }
    }

    #[test]
    fn maps_only_named_posting_fields_from_a_complete_synthetic_schema() {
        let posting = adapt_enterprise_posting_row(
            Enterprise24AccountingTable::CheckLine,
            &schema(true),
            row(false, false),
        )
        .unwrap();
        assert_eq!(
            posting,
            EnterprisePostingAdaptation::Posting(EnterprisePostingRow {
                table: Enterprise24AccountingTable::CheckLine,
                transaction_type: EnterprisePostingTransactionType::Check,
                target_id: 7,
                transaction_id: 11,
                account_id: 13,
                transaction_date: 135_081,
                amount_cents: 3_741,
                is_source: Some(true),
                is_split: Some(false),
            })
        );
    }

    #[test]
    fn gates_no_post_and_memorized_rows_before_exposing_fields() {
        let mut no_post = row(true, false);
        // Excluded rows need only their provenance and gate fields. Their
        // nullable accounting fields must not block a closed exclusion.
        no_post.values[4] = Value::Null;
        assert_eq!(
            adapt_enterprise_posting_row(
                Enterprise24AccountingTable::BillLine,
                &schema(true),
                no_post
            )
            .unwrap(),
            EnterprisePostingAdaptation::Excluded(EnterprisePostingExclusion::NoPost {
                target_id: 7,
                transaction_id: 11,
            })
        );
        let mut memorized = row(false, true);
        memorized.values[4] = Value::Null;
        assert_eq!(
            adapt_enterprise_posting_row(
                Enterprise24AccountingTable::BillLine,
                &schema(true),
                memorized
            )
            .unwrap(),
            EnterprisePostingAdaptation::Excluded(
                EnterprisePostingExclusion::MemorizedTransaction {
                    target_id: 7,
                    transaction_id: 11,
                }
            )
        );
    }

    #[test]
    fn partial_adapter_uses_only_named_prefix_and_boolean_tail_fields() {
        assert_eq!(
            adapt_enterprise_posting_row_partial(
                Enterprise24AccountingTable::CheckLine,
                &schema(true),
                &partial(false, false),
            )
            .unwrap(),
            EnterprisePostingAdaptation::Posting(EnterprisePostingRow {
                table: Enterprise24AccountingTable::CheckLine,
                transaction_type: EnterprisePostingTransactionType::Check,
                target_id: 7,
                transaction_id: 11,
                account_id: 13,
                transaction_date: 135_081,
                amount_cents: 3_741,
                is_source: Some(true),
                is_split: Some(false),
            })
        );
        let mut voided = partial(false, false);
        voided.prefix_values[4].value = Value::EnterpriseNumeric(EnterpriseNumericToken {
            marker: 0x81,
            digits: Vec::new(),
        });
        assert!(matches!(
            adapt_enterprise_posting_row_partial(
                Enterprise24AccountingTable::CheckLine,
                &schema(true),
                &voided,
            ),
            Ok(EnterprisePostingAdaptation::Excluded(
                EnterprisePostingExclusion::CanonicalZeroAmount {
                    target_id: 7,
                    transaction_id: 11,
                    account_id: 13,
                    transaction_date: 135_081,
                    transaction_type: EnterprisePostingTransactionType::Check,
                }
            ))
        ));
        let mut source_link = partial(false, false);
        source_link.prefix_values[4].value = Value::Null;
        assert!(matches!(
            adapt_enterprise_posting_row_partial(
                Enterprise24AccountingTable::DepositLine,
                &schema(true),
                &source_link,
            ),
            Ok(EnterprisePostingAdaptation::Excluded(
                EnterprisePostingExclusion::SourceOrLink { .. }
            ))
        ));
        let mut no_post = partial(true, false);
        no_post.prefix_values[4].value = Value::Null;
        assert!(matches!(
            adapt_enterprise_posting_row_partial(
                Enterprise24AccountingTable::BillLine,
                &schema(true),
                &no_post,
            ),
            Ok(EnterprisePostingAdaptation::Excluded(
                EnterprisePostingExclusion::NoPost { .. }
            ))
        ));
    }

    #[test]
    fn assigns_stable_native_types_to_fixed_posting_families() {
        for (table, expected) in [
            (
                Enterprise24AccountingTable::BillPaymentCheckLine,
                EnterprisePostingTransactionType::BillPaymentCheck,
            ),
            (
                Enterprise24AccountingTable::CheckLine,
                EnterprisePostingTransactionType::Check,
            ),
            (
                Enterprise24AccountingTable::DepositLine,
                EnterprisePostingTransactionType::Deposit,
            ),
            (
                Enterprise24AccountingTable::GeneralJournalLine,
                EnterprisePostingTransactionType::GeneralJournal,
            ),
        ] {
            let EnterprisePostingAdaptation::Posting(posting) =
                adapt_enterprise_posting_row(table, &schema(true), row(false, false)).unwrap()
            else {
                panic!("SAMPLE posting was unexpectedly excluded");
            };
            assert_eq!(posting.transaction_type, expected);
        }
        assert_eq!(
            EnterprisePostingTransactionType::BillPaymentCheck.source_label(),
            "Bill Pmt-Check"
        );
        assert_eq!(
            EnterprisePostingTransactionType::VendorCredit.source_label(),
            "Credit"
        );
    }

    #[test]
    fn rejects_schema_only_bill_rows_without_an_attested_view_type() {
        assert_eq!(
            adapt_enterprise_posting_row(
                Enterprise24AccountingTable::BillLine,
                &schema(true),
                row(false, false),
            ),
            Err(
                EnterprisePostingAdapterError::TransactionTypeRequiresDedicatedDecoder {
                    table: Enterprise24AccountingTable::BillLine,
                }
            )
        );
    }

    #[test]
    fn partial_adapter_rejects_unavailable_named_prefix_values() {
        let mut partial = partial(false, false);
        partial.prefix_values.retain(|value| value.column_id != 5);
        assert!(matches!(
            adapt_enterprise_posting_row_partial(
                Enterprise24AccountingTable::CheckLine,
                &schema(true),
                &partial,
            ),
            Err(EnterprisePostingAdapterError::PartialValueUnavailable { .. })
        ));
    }

    #[test]
    fn canonical_zero_is_neutral_only_after_all_monetary_fields_validate() {
        let mut voided = row(false, false);
        voided.values[4] = Value::EnterpriseNumeric(EnterpriseNumericToken {
            marker: 0x81,
            digits: Vec::new(),
        });
        assert_eq!(
            adapt_enterprise_posting_row(
                Enterprise24AccountingTable::CheckLine,
                &schema(true),
                voided,
            )
            .unwrap(),
            EnterprisePostingAdaptation::Excluded(
                EnterprisePostingExclusion::CanonicalZeroAmount {
                    target_id: 7,
                    transaction_id: 11,
                    account_id: 13,
                    transaction_date: 135_081,
                    transaction_type: EnterprisePostingTransactionType::Check,
                }
            )
        );

        let mut missing_account = row(false, false);
        missing_account.values[4] = Value::EnterpriseNumeric(EnterpriseNumericToken {
            marker: 0x81,
            digits: Vec::new(),
        });
        missing_account.values[2] = Value::Null;
        assert!(matches!(
            adapt_enterprise_posting_row(
                Enterprise24AccountingTable::CheckLine,
                &schema(true),
                missing_account,
            ),
            Err(EnterprisePostingAdapterError::UnexpectedValueType { .. })
        ));

        let mut invalid_date = row(false, false);
        invalid_date.values[4] = Value::EnterpriseNumeric(EnterpriseNumericToken {
            marker: 0x81,
            digits: Vec::new(),
        });
        invalid_date.values[3] = Value::Date(SaDate { raw_minutes: 1 });
        assert!(matches!(
            adapt_enterprise_posting_row(
                Enterprise24AccountingTable::CheckLine,
                &schema(true),
                invalid_date,
            ),
            Err(EnterprisePostingAdapterError::InvalidPostingDate { .. })
        ));

        let mut missing_partial_account = partial(false, false);
        missing_partial_account.prefix_values[4].value =
            Value::EnterpriseNumeric(EnterpriseNumericToken {
                marker: 0x81,
                digits: Vec::new(),
            });
        missing_partial_account
            .prefix_values
            .retain(|value| value.column_id != 3);
        assert!(matches!(
            adapt_enterprise_posting_row_partial(
                Enterprise24AccountingTable::CheckLine,
                &schema(true),
                &missing_partial_account,
            ),
            Err(EnterprisePostingAdapterError::PartialValueUnavailable { .. })
        ));

        let mut generic_bill_zero = row(false, false);
        generic_bill_zero.values[4] = Value::EnterpriseNumeric(EnterpriseNumericToken {
            marker: 0x81,
            digits: Vec::new(),
        });
        assert!(matches!(
            adapt_enterprise_posting_row(
                Enterprise24AccountingTable::BillLine,
                &schema(true),
                generic_bill_zero,
            ),
            Err(EnterprisePostingAdapterError::TransactionTypeRequiresDedicatedDecoder { .. })
        ));
    }

    #[test]
    fn gates_a_null_amount_only_when_the_row_is_a_proven_source_link() {
        let mut source_link = row(false, false);
        source_link.values[4] = Value::Null;
        source_link.values[7] = Value::Boolean(true);
        assert_eq!(
            adapt_enterprise_posting_row(
                Enterprise24AccountingTable::DepositLine,
                &schema(true),
                source_link,
            )
            .unwrap(),
            EnterprisePostingAdaptation::Excluded(EnterprisePostingExclusion::SourceOrLink {
                target_id: 7,
                transaction_id: 11,
            })
        );

        let mut non_source = row(false, false);
        non_source.values[4] = Value::Null;
        non_source.values[7] = Value::Boolean(false);
        assert!(matches!(
            adapt_enterprise_posting_row(
                Enterprise24AccountingTable::DepositLine,
                &schema(true),
                non_source,
            ),
            Err(EnterprisePostingAdapterError::UnexpectedValueType { .. })
        ));
    }

    #[test]
    fn rejects_non_posting_partial_and_unproven_value_shapes() {
        assert!(matches!(
            adapt_enterprise_posting_row(
                Enterprise24AccountingTable::CheckHeader,
                &schema(true),
                row(false, false)
            ),
            Err(EnterprisePostingAdapterError::NotPostingTable { .. })
        ));
        let mut missing_amount = schema(false);
        missing_amount
            .columns
            .retain(|column| column.name != "amount_amt");
        let mut short = row(false, false);
        short.values.remove(4);
        short.values.truncate(missing_amount.columns.len());
        assert!(matches!(
            adapt_enterprise_posting_row(
                Enterprise24AccountingTable::CheckLine,
                &missing_amount,
                short
            ),
            Err(EnterprisePostingAdapterError::MissingColumn { .. })
        ));
        let mut zero = row(false, false);
        zero.values[0] = Value::Integer(0);
        assert!(matches!(
            adapt_enterprise_posting_row(
                Enterprise24AccountingTable::CheckLine,
                &schema(true),
                zero
            ),
            Err(EnterprisePostingAdapterError::ZeroIdentifier { .. })
        ));
        let mut non_midnight = row(false, false);
        non_midnight.values[3] = Value::Date(SaDate { raw_minutes: 1 });
        assert!(matches!(
            adapt_enterprise_posting_row(
                Enterprise24AccountingTable::CheckLine,
                &schema(true),
                non_midnight
            ),
            Err(EnterprisePostingAdapterError::InvalidPostingDate { .. })
        ));
    }
}

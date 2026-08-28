//! Schema-driven adapter for Enterprise 24 Account (`3026`) rows.
//!
//! This layer intentionally separates three facts which are easy to conflate:
//! a row's physical SQL Anywhere representation, its QuickBooks ListID, and
//! whether it is a current user-facing account.  The catalog establishes the
//! first; a bounded [`MaterializedAccountRow`] establishes the ordinary
//! ListID; lifecycle flags establish the last.  No account-name convention is
//! used for selection.

use std::collections::BTreeSet;

use opensqlany::{
    DecodedRow, MaterializedRowRecord, PartialDecodedRow, RowSchema, Value, decode_row_exact,
};
use thiserror::Error;

use crate::{
    Account, AccountActivity, AccountId, AccountType, AccountingError, CatalogCoverageAttestation,
    CatalogDefaultAttestation, MaterializedAccountRow, RowStorageAttestation, SchemaAdapterError,
    SysColumn, adapt_complete_schema, boolean_value_by_column_id, prefix_value_by_column_id,
};

/// Enterprise 24's user-facing Account table identifier.
pub const ENTERPRISE24_ACCOUNT_TABLE_ID: u32 = 3026;
/// Independently recovered contiguous Account-table catalog cardinality.
pub const ENTERPRISE24_ACCOUNT_COLUMN_COUNT: usize = 36;

const ID: usize = 0;
const NAME: usize = 5;
const IS_HIDDEN: usize = 6;
const IS_DELETED: usize = 7;
const IS_DELETE_PENDING: usize = 8;
const PARENT: usize = 11;
const TYPE: usize = 17;
const ACCOUNT_NUM: usize = 21;
const DESCRIPTION: usize = 23;
const ACCOUNT_TYPE: usize = 34;
const CURRENCY: usize = 35;

/// Resolves an Enterprise Account ordinal-18 value using the calibrated
/// materialized Account-code evidence.
///
/// Unknown, uncalibrated, negative, and out-of-byte-range values return
/// `None`; callers must not turn them into a Trial Balance category.
#[must_use]
pub fn resolve_enterprise24_account_type18(raw: i64) -> Option<AccountType> {
    u8::try_from(raw)
        .ok()
        .and_then(|code| crate::map_materialized_account_type_code(code).ok())
        .map(crate::QuickBooksAccountClassification::trial_balance_type)
}

/// Builds the complete table-3026 schema from its recovered catalog rows.
///
/// Defaults and physical-storage choices stay caller-attested: catalog
/// metadata alone cannot prove either. The returned schema is additionally
/// checked against the Account fields consumed by this adapter.
pub fn adapt_complete_account_schema(
    columns: &[SysColumn],
    storage: RowStorageAttestation,
    defaults: CatalogDefaultAttestation<'_>,
) -> Result<RowSchema, SchemaAccountAdapterError> {
    let coverage = CatalogCoverageAttestation::new(
        ENTERPRISE24_ACCOUNT_TABLE_ID,
        ENTERPRISE24_ACCOUNT_COLUMN_COUNT as u32,
    )
    .expect("nonzero fixed Account catalog facts");
    let schema = adapt_complete_schema(columns, coverage, storage, defaults)
        .map_err(SchemaAccountAdapterError::Schema)?;
    validate_account_row_schema(&schema)?;
    Ok(schema)
}

/// A caller-attested current-state classification for one physical row.
///
/// `internal` is deliberately supplied rather than inferred from a display
/// name.  It may only be true when a table-level census has proven that the
/// row is an internal carrier rather than an exportable Account.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct AccountRowStateEvidence {
    /// Independently proven internal carrier status.
    pub internal: bool,
}

/// Current-state disposition of a physical Account row.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AccountRowDisposition {
    /// A user-facing account, including an inactive/hidden account.
    Included,
    /// A row explicitly marked deleted.
    Deleted,
    /// A row explicitly marked delete-pending.
    DeletePending,
    /// A separately proven internal carrier.
    Internal,
}

/// Lifecycle information preserved alongside a normalized account.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct AccountLifecycle {
    /// The source `is_hidden` flag. It is not rewritten as deletion.
    pub hidden: bool,
    /// Selection result for this physical row.
    pub disposition: AccountRowDisposition,
}

impl AccountLifecycle {
    fn from_flags(hidden: bool, deleted: bool, delete_pending: bool, internal: bool) -> Self {
        let disposition = if deleted {
            AccountRowDisposition::Deleted
        } else if delete_pending {
            AccountRowDisposition::DeletePending
        } else if internal {
            AccountRowDisposition::Internal
        } else {
            AccountRowDisposition::Included
        };
        Self {
            hidden,
            disposition,
        }
    }

    /// Returns whether the row is a selected user-facing Account.
    #[must_use]
    pub const fn is_included(self) -> bool {
        matches!(self.disposition, AccountRowDisposition::Included)
    }

    /// Maps the explicit hidden flag to the closest normalized activity state.
    ///
    /// QuickBooks' list UI uses hidden rows for inactive accounts. The raw
    /// flag remains available above, so consumers never mistake inactivity for
    /// deletion.
    #[must_use]
    pub const fn activity(self) -> AccountActivity {
        if self.hidden {
            AccountActivity::Inactive
        } else {
            AccountActivity::Active
        }
    }
}

/// A normalized Account plus the source lifecycle facts that selected it.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SchemaAccountRow {
    /// Normalized Account identity and chart metadata.
    pub account: Account,
    /// Source lifecycle facts.
    pub lifecycle: AccountLifecycle,
    /// Raw `type` (ordinal 18), used only through a caller-supplied,
    /// independently calibrated business-type resolver.
    pub type_raw: Option<i64>,
    /// Raw `account_type` (ordinal 35), retained as metadata. It has not been
    /// proven to be the bounded Account parser's business discriminator.
    pub account_type_raw: Option<i64>,
    /// Raw `currency` account reference (ordinal 36), retained as provenance.
    pub currency_raw: Option<i64>,
    /// Decoded description (ordinal 24), deliberately not copied into
    /// [`Account`] because the normalized model has no description field.
    pub description: Option<String>,
    /// Whether the optional bespoke materialized suffix agreed with the
    /// schema-derived account number and description.
    ///
    /// `None` means that suffix grammar was not independently parsed. A
    /// `false` result is diagnostic only: the complete catalog row remains
    /// authoritative for these fields.
    pub materialized_suffix_matches_schema: Option<bool>,
}

/// Aggregate evidence that the lifecycle rule retained all usable Accounts
/// while its active subset matched the exported ordinary identities.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct AccountSelectionAudit {
    /// Number of physical Account rows presented to the selection rule.
    pub physical_rows: usize,
    /// Number of selected physical Account rows.
    pub selected_rows: usize,
    /// Number of distinct selected ordinary ListIDs.
    pub unique_selected_ids: usize,
    /// Number of distinct active ordinary ListIDs compared with the active
    /// reference export. Hidden/inactive accounts remain selected above but
    /// are intentionally outside that export comparison.
    pub unique_active_selected_ids: usize,
}

/// Verifies an Account-table lifecycle result without retaining
/// or emitting any company-specific Account identifiers.
///
/// This is a development/reconciliation gate, not a runtime SDK dependency:
/// callers provide only the already-local *active* ordinary ListID set
/// produced by a reference export and the independently censused number of
/// physical rows. Hidden/inactive accounts remain in the selected collection
/// for retained-history/TB use but are not required to appear in that active
/// export. This prevents a prefix or convenient subset from being accepted
/// without baking snapshot-specific counts into production behavior.
pub fn audit_account_selection(
    rows: &[Option<SchemaAccountRow>],
    expected_physical_rows: usize,
    reference_ids: &BTreeSet<AccountId>,
) -> Result<AccountSelectionAudit, SchemaAccountAdapterError> {
    if rows.len() != expected_physical_rows {
        return Err(SchemaAccountAdapterError::PhysicalSelectionCount {
            actual: rows.len(),
            expected: expected_physical_rows,
        });
    }
    let selected = rows
        .iter()
        .flatten()
        .map(|row| row.account.id.clone())
        .collect::<BTreeSet<_>>();
    let active_selected = rows
        .iter()
        .flatten()
        .filter(|row| row.account.activity == AccountActivity::Active)
        .map(|row| row.account.id.clone())
        .collect::<BTreeSet<_>>();
    if active_selected.len() != reference_ids.len() {
        return Err(SchemaAccountAdapterError::SelectedIdentityCount {
            actual: active_selected.len(),
            expected: reference_ids.len(),
        });
    }
    if &active_selected != reference_ids {
        return Err(SchemaAccountAdapterError::ReferenceIdentityMismatch);
    }
    Ok(AccountSelectionAudit {
        physical_rows: rows.len(),
        selected_rows: rows.iter().flatten().count(),
        unique_selected_ids: selected.len(),
        unique_active_selected_ids: active_selected.len(),
    })
}

/// Checks that a complete Account schema has the field domains needed here.
///
/// The caller still owns complete catalog coverage and storage attestations;
/// this function prevents a schema for another table or a reordered partial
/// schema from being used as an Account decoder.
pub fn validate_account_row_schema(schema: &RowSchema) -> Result<(), SchemaAccountAdapterError> {
    if schema.columns.len() != ENTERPRISE24_ACCOUNT_COLUMN_COUNT {
        return Err(SchemaAccountAdapterError::WrongColumnCount {
            actual: schema.columns.len(),
        });
    }
    for (ordinal, index, name, domain, width, nullable) in [
        (1, ID, "account_id", 2, 4, false),
        (6, NAME, "name", 9, 32, true),
        (7, IS_HIDDEN, "is_hidden_bool", 24, 1, false),
        (8, IS_DELETED, "is_deleted_bool", 24, 1, false),
        (9, IS_DELETE_PENDING, "is_delete_pending_bool", 24, 1, false),
        (12, PARENT, "parent_id", 2, 4, true),
        (18, TYPE, "type", 1, 2, true),
        (22, ACCOUNT_NUM, "account_num", 9, 8, true),
        (24, DESCRIPTION, "description", 9, 201, true),
        (35, ACCOUNT_TYPE, "account_type", 1, 2, true),
        (36, CURRENCY, "currency_id", 2, 4, true),
    ] {
        let column = schema.columns.get(index).expect("column count checked");
        if column.id != ordinal
            || column.name != name
            || column.column_type as u16 != domain
            || column.width != width
            || column.nullable != nullable
        {
            return Err(SchemaAccountAdapterError::UnexpectedColumn {
                ordinal,
                actual_id: column.id,
                actual_domain: column.column_type as u16,
            });
        }
    }
    Ok(())
}

/// Decodes one complete Account physical row and selects it only from its
/// lifecycle fields and separately-attested internal status.
///
/// The same bytes must parse as [`MaterializedAccountRow`]; this binds the
/// schema row's `id` to the independently established ordinary QuickBooks
/// ListID formatter instead of inventing an identifier from `id` alone.
pub fn decode_schema_account_row_exact(
    record: MaterializedRowRecord<'_>,
    schema: &RowSchema,
    state: AccountRowStateEvidence,
    parent_identity: impl Fn(u32) -> Option<AccountId>,
    business_type: impl Fn(i64) -> Option<AccountType>,
) -> Result<Option<SchemaAccountRow>, SchemaAccountAdapterError> {
    validate_account_row_schema(schema)?;
    let decoded =
        decode_row_exact(record.bytes(), schema).map_err(SchemaAccountAdapterError::Decode)?;
    let identity = MaterializedAccountRow::parse(record.bytes())
        .map_err(SchemaAccountAdapterError::Identity)?;
    decode_account_values(&decoded, identity, state, parent_identity, business_type)
}

/// Adapts the proven Account prefix and Boolean storage without selecting a
/// complete physical layout.
///
/// The partial row must have been decoded through ordinal 24 by
/// [`opensqlany::decode_row_prefix_and_boolean_tail`]. Thus this function
/// consumes only identity, name, lifecycle booleans, parent, the explicitly
/// caller-resolved ordinal-18 type, account number, and description.  It
/// deliberately does not inspect ordinal 35/36 or infer any later variable
/// field.  `identity` is separately parsed from the bounded materialized
/// Account envelope and cross-checks the record number, display name, type,
/// and—when its suffix grammar is parsed—the number and description.
pub fn decode_schema_account_row_partial(
    partial: &PartialDecodedRow,
    schema: &RowSchema,
    identity: MaterializedAccountRow<'_>,
    state: AccountRowStateEvidence,
    parent_identity: impl Fn(u32) -> Option<AccountId>,
    business_type: impl Fn(i64) -> Option<AccountType>,
) -> Result<Option<SchemaAccountRow>, SchemaAccountAdapterError> {
    validate_account_row_schema(schema)?;
    if partial.through_ordinal < DESCRIPTION as u32 + 1 {
        return Err(SchemaAccountAdapterError::PartialPrefixTooShort {
            actual: partial.through_ordinal,
            required: DESCRIPTION as u32 + 1,
        });
    }
    let id = partial_required_integer(partial, 1)?;
    let id =
        u32::try_from(id).map_err(|_| SchemaAccountAdapterError::IdOutOfRange { value: id })?;
    if identity.record_number() != id {
        return Err(SchemaAccountAdapterError::IdentityDoesNotMatchId {
            id,
            record_number: identity.record_number(),
        });
    }
    let hidden = partial_required_bool(partial, 7)?;
    let deleted = partial_required_bool(partial, 8)?;
    let delete_pending = partial_required_bool(partial, 9)?;
    let lifecycle = AccountLifecycle::from_flags(hidden, deleted, delete_pending, state.internal);
    if !lifecycle.is_included() {
        return Ok(None);
    }
    let name = partial_required_text(partial, 6)?;
    if identity.name() != name {
        return Err(SchemaAccountAdapterError::IdentityNameDoesNotMatch);
    }
    let account_number = partial_optional_text(partial, 22)?;
    let description = partial_optional_text(partial, 24)?;
    // The bespoke suffix is a bounded diagnostic, not an authoritative
    // grammar for the complete Account table. Keep a disagreement visible
    // without rejecting a catalog-backed number/description.
    let materialized_suffix_matches_schema = if matches!(
        identity.suffix_state(),
        crate::MaterializedAccountSuffixState::Parsed
    ) {
        Some(
            identity.account_number().map(str::to_owned) == account_number
                && identity.description().map(str::to_owned) == description,
        )
    } else {
        None
    };
    let parent = partial_optional_integer(partial, 12)?
        .filter(|value| *value != 0)
        .map(|value| {
            u32::try_from(value).map_err(|_| SchemaAccountAdapterError::ParentOutOfRange { value })
        })
        .transpose()?;
    let parent_account_id = parent
        .map(|record_number| {
            parent_identity(record_number)
                .ok_or(SchemaAccountAdapterError::ParentIdentityUnavailable { record_number })
        })
        .transpose()?;
    let type_raw = partial_optional_integer(partial, 18)?;
    let resolved_type = type_raw
        .and_then(&business_type)
        .ok_or(SchemaAccountAdapterError::BusinessTypeUnresolved { type_raw })?;
    let materialized_type = i64::from(identity.account_type().code());
    if type_raw != Some(materialized_type) {
        return Err(SchemaAccountAdapterError::IdentityTypeDoesNotMatch {
            schema_type: type_raw,
            materialized_type,
        });
    }
    let account = Account::new(
        AccountId::new(identity.ordinary_list_id())?,
        name,
        resolved_type,
        !hidden,
    )?
    .with_activity(lifecycle.activity())
    // The equality above ties this source classification to the catalog row
    // actually consumed by the adapter. Never derive it from the broad Trial
    // Balance category or an Account display name.
    .with_quickbooks_classification(
        crate::map_materialized_account_type_code(identity.account_type().code())
            .map_err(|_| SchemaAccountAdapterError::BusinessTypeUnresolved { type_raw })?,
    )
    .with_hierarchy(account_number, parent_account_id)?;
    Ok(Some(SchemaAccountRow {
        account,
        lifecycle,
        type_raw,
        account_type_raw: None,
        currency_raw: None,
        description,
        materialized_suffix_matches_schema,
    }))
}

fn partial_value(
    partial: &PartialDecodedRow,
    ordinal: u32,
) -> Result<&Value, SchemaAccountAdapterError> {
    prefix_value_by_column_id(partial, ordinal)
        .or_else(|| boolean_value_by_column_id(partial, ordinal))
        .ok_or(SchemaAccountAdapterError::MissingValue { ordinal })
}

fn partial_required_integer(
    partial: &PartialDecodedRow,
    ordinal: u32,
) -> Result<i64, SchemaAccountAdapterError> {
    match partial_value(partial, ordinal)? {
        Value::Integer(value) => Ok(*value),
        Value::Null => Err(SchemaAccountAdapterError::RequiredValueIsNull { ordinal }),
        _ => Err(SchemaAccountAdapterError::WrongValueKind { ordinal }),
    }
}

fn partial_optional_integer(
    partial: &PartialDecodedRow,
    ordinal: u32,
) -> Result<Option<i64>, SchemaAccountAdapterError> {
    match partial_value(partial, ordinal)? {
        Value::Integer(value) => Ok(Some(*value)),
        Value::Null => Ok(None),
        _ => Err(SchemaAccountAdapterError::WrongValueKind { ordinal }),
    }
}

fn partial_required_bool(
    partial: &PartialDecodedRow,
    ordinal: u32,
) -> Result<bool, SchemaAccountAdapterError> {
    match partial_value(partial, ordinal)? {
        Value::Boolean(value) => Ok(*value),
        Value::Null => Err(SchemaAccountAdapterError::RequiredValueIsNull { ordinal }),
        _ => Err(SchemaAccountAdapterError::WrongValueKind { ordinal }),
    }
}

fn partial_required_text(
    partial: &PartialDecodedRow,
    ordinal: u32,
) -> Result<String, SchemaAccountAdapterError> {
    partial_optional_text(partial, ordinal)?
        .filter(|value| !value.trim().is_empty())
        .ok_or(SchemaAccountAdapterError::RequiredValueIsNull { ordinal })
}

fn partial_optional_text(
    partial: &PartialDecodedRow,
    ordinal: u32,
) -> Result<Option<String>, SchemaAccountAdapterError> {
    match partial_value(partial, ordinal)? {
        Value::Bytes(value) => core::str::from_utf8(value)
            .map(|value| Some(value.to_owned()))
            .map_err(|_| SchemaAccountAdapterError::TextNotUtf8 { ordinal }),
        Value::Null => Ok(None),
        _ => Err(SchemaAccountAdapterError::WrongValueKind { ordinal }),
    }
}

fn decode_account_values(
    decoded: &DecodedRow,
    identity: MaterializedAccountRow<'_>,
    state: AccountRowStateEvidence,
    parent_identity: impl Fn(u32) -> Option<AccountId>,
    business_type: impl Fn(i64) -> Option<AccountType>,
) -> Result<Option<SchemaAccountRow>, SchemaAccountAdapterError> {
    let id = required_integer(decoded, ID, 1)?;
    let id =
        u32::try_from(id).map_err(|_| SchemaAccountAdapterError::IdOutOfRange { value: id })?;
    if identity.record_number() != id {
        return Err(SchemaAccountAdapterError::IdentityDoesNotMatchId {
            id,
            record_number: identity.record_number(),
        });
    }
    let hidden = required_bool(decoded, IS_HIDDEN, 7)?;
    let deleted = required_bool(decoded, IS_DELETED, 8)?;
    let delete_pending = required_bool(decoded, IS_DELETE_PENDING, 9)?;
    let lifecycle = AccountLifecycle::from_flags(hidden, deleted, delete_pending, state.internal);
    if !lifecycle.is_included() {
        return Ok(None);
    }

    let name = required_text(decoded, NAME, 6)?;
    let account_number = optional_text(decoded, ACCOUNT_NUM, 22)?;
    let description = optional_text(decoded, DESCRIPTION, 24)?;
    let parent = optional_integer(decoded, PARENT, 12)?
        .filter(|value| *value != 0)
        .map(|value| {
            u32::try_from(value).map_err(|_| SchemaAccountAdapterError::ParentOutOfRange { value })
        })
        .transpose()?;
    let parent_account_id = parent
        .map(|record_number| {
            parent_identity(record_number)
                .ok_or(SchemaAccountAdapterError::ParentIdentityUnavailable { record_number })
        })
        .transpose()?;
    let type_raw = optional_integer(decoded, TYPE, 18)?;
    let resolved_type = type_raw
        .and_then(&business_type)
        .ok_or(SchemaAccountAdapterError::BusinessTypeUnresolved { type_raw })?;
    let materialized_type = i64::from(identity.account_type().code());
    if type_raw != Some(materialized_type) {
        return Err(SchemaAccountAdapterError::IdentityTypeDoesNotMatch {
            schema_type: type_raw,
            materialized_type,
        });
    }
    let account = Account::new(
        AccountId::new(identity.ordinary_list_id())?,
        name,
        resolved_type,
        !hidden,
    )?
    .with_activity(lifecycle.activity())
    .with_quickbooks_classification(
        crate::map_materialized_account_type_code(identity.account_type().code())
            .map_err(|_| SchemaAccountAdapterError::BusinessTypeUnresolved { type_raw })?,
    )
    .with_hierarchy(account_number, parent_account_id)?;
    Ok(Some(SchemaAccountRow {
        account,
        lifecycle,
        type_raw,
        account_type_raw: optional_integer(decoded, ACCOUNT_TYPE, 35)?,
        currency_raw: optional_integer(decoded, CURRENCY, 36)?,
        description,
        materialized_suffix_matches_schema: None,
    }))
}

fn value(
    decoded: &DecodedRow,
    index: usize,
    ordinal: u32,
) -> Result<&Value, SchemaAccountAdapterError> {
    decoded
        .values
        .get(index)
        .ok_or(SchemaAccountAdapterError::MissingValue { ordinal })
}
fn required_integer(
    decoded: &DecodedRow,
    index: usize,
    ordinal: u32,
) -> Result<i64, SchemaAccountAdapterError> {
    match value(decoded, index, ordinal)? {
        Value::Integer(value) => Ok(*value),
        Value::Null => Err(SchemaAccountAdapterError::RequiredValueIsNull { ordinal }),
        _ => Err(SchemaAccountAdapterError::WrongValueKind { ordinal }),
    }
}
fn optional_integer(
    decoded: &DecodedRow,
    index: usize,
    ordinal: u32,
) -> Result<Option<i64>, SchemaAccountAdapterError> {
    match value(decoded, index, ordinal)? {
        Value::Integer(value) => Ok(Some(*value)),
        Value::Null => Ok(None),
        _ => Err(SchemaAccountAdapterError::WrongValueKind { ordinal }),
    }
}
fn required_bool(
    decoded: &DecodedRow,
    index: usize,
    ordinal: u32,
) -> Result<bool, SchemaAccountAdapterError> {
    match value(decoded, index, ordinal)? {
        Value::Boolean(value) => Ok(*value),
        Value::Null => Err(SchemaAccountAdapterError::RequiredValueIsNull { ordinal }),
        _ => Err(SchemaAccountAdapterError::WrongValueKind { ordinal }),
    }
}
fn required_text(
    decoded: &DecodedRow,
    index: usize,
    ordinal: u32,
) -> Result<String, SchemaAccountAdapterError> {
    optional_text(decoded, index, ordinal)?
        .filter(|value| !value.trim().is_empty())
        .ok_or(SchemaAccountAdapterError::RequiredValueIsNull { ordinal })
}
fn optional_text(
    decoded: &DecodedRow,
    index: usize,
    ordinal: u32,
) -> Result<Option<String>, SchemaAccountAdapterError> {
    match value(decoded, index, ordinal)? {
        Value::Bytes(value) => core::str::from_utf8(value)
            .map(|value| Some(value.to_owned()))
            .map_err(|_| SchemaAccountAdapterError::TextNotUtf8 { ordinal }),
        Value::Null => Ok(None),
        _ => Err(SchemaAccountAdapterError::WrongValueKind { ordinal }),
    }
}

/// Failure while adapting a complete Account row.
#[allow(missing_docs)] // Field names repeat their documented error payload.
#[derive(Debug, Error)]
pub enum SchemaAccountAdapterError {
    /// A bounded prefix did not reach the final Account field this adapter is
    /// allowed to consume.
    #[error("account partial prefix ends at ordinal {actual}; ordinal {required} is required")]
    PartialPrefixTooShort { actual: u32, required: u32 },
    /// The controlled audit did not receive all physical Account rows.
    #[error("account lifecycle audit received {actual} physical rows; expected {expected}")]
    PhysicalSelectionCount { actual: usize, expected: usize },
    /// The lifecycle rule selected an unexpected number of distinct identities.
    #[error("account lifecycle audit selected {actual} distinct IDs; expected {expected}")]
    SelectedIdentityCount { actual: usize, expected: usize },
    /// The selected and reference identity sets differed. IDs are intentionally
    /// omitted so company identifiers never appear in error text.
    #[error("account lifecycle audit selected IDs do not equal the local reference IDs")]
    ReferenceIdentityMismatch,
    /// The supplied schema does not include all 36 Account columns.
    #[error("account schema has {actual} columns; expected {ENTERPRISE24_ACCOUNT_COLUMN_COUNT}")]
    WrongColumnCount { actual: usize },
    /// A required Account field does not have its catalog ordinal/domain.
    #[error("account schema ordinal {ordinal} was id {actual_id} domain {actual_domain}")]
    UnexpectedColumn {
        ordinal: u32,
        actual_id: u32,
        actual_domain: u16,
    },
    /// The complete physical row did not decode exactly.
    #[error("account row decoder failed: {0}")]
    Decode(#[source] opensqlany::DecodeError),
    /// Catalog metadata or an unproven storage choice could not form a safe
    /// complete Account schema.
    #[error("account schema adaptation failed: {0}")]
    Schema(#[source] SchemaAdapterError),
    /// The same row could not establish its ordinary QuickBooks ListID.
    #[error("account ListID envelope failed: {0}")]
    Identity(#[source] crate::MaterializedAccountRowError),
    /// A required decoded field is absent.
    #[error("account ordinal {ordinal} has no decoded value")]
    MissingValue { ordinal: u32 },
    /// A required decoded field was SQL NULL.
    #[error("account ordinal {ordinal} is unexpectedly NULL")]
    RequiredValueIsNull { ordinal: u32 },
    /// A decoded field did not have the catalog-implied value kind.
    #[error("account ordinal {ordinal} has an unexpected value kind")]
    WrongValueKind { ordinal: u32 },
    /// Account text was not valid UTF-8 under the caller's selected encoding.
    #[error("account ordinal {ordinal} is not valid UTF-8")]
    TextNotUtf8 { ordinal: u32 },
    /// The Account primary key is outside the established u32 record-number range.
    #[error("account id {value} is outside u32 range")]
    IdOutOfRange { value: i64 },
    /// Schema primary key and bounded ListID envelope disagree.
    #[error("account id {id} does not match ListID record number {record_number}")]
    IdentityDoesNotMatchId { id: u32, record_number: u32 },
    /// Bounded materialized name and schema-prefix name disagree.
    #[error("account materialized identity name does not match the schema prefix")]
    IdentityNameDoesNotMatch,
    /// The independently decoded ordinal-18 value disagrees with the
    /// bounded materialized Account type byte.
    #[error(
        "account ordinal-18 type {schema_type:?} does not match materialized type {materialized_type}"
    )]
    IdentityTypeDoesNotMatch {
        schema_type: Option<i64>,
        materialized_type: i64,
    },
    /// Parent primary key is outside the established u32 range.
    #[error("account parent {value} is outside u32 range")]
    ParentOutOfRange { value: i64 },
    /// A non-null parent cannot be represented until its ordinary ListID has
    /// been resolved from that parent's bounded Account row.
    #[error("parent record {record_number} has no resolved ordinary ListID")]
    ParentIdentityUnavailable { record_number: u32 },
    /// No business-type mapping has been independently established for the
    /// decoded ordinal-18 value.
    #[error("account business type is unresolved for raw ordinal-18 value {type_raw:?}")]
    BusinessTypeUnresolved { type_raw: Option<i64> },
    /// Normalized accounting metadata was invalid.
    #[error("normalized account is invalid: {0}")]
    Accounting(#[from] AccountingError),
}

#[cfg(test)]
mod tests {
    use opensqlany::{ColumnDef, ColumnType, PartialDecodedRow, PartialRowValue, RowSchema};

    use super::*;

    fn schema() -> RowSchema {
        let mut columns = (1..=ENTERPRISE24_ACCOUNT_COLUMN_COUNT)
            .map(|id| {
                ColumnDef::new(
                    id as u32,
                    format!("opaque_{id}"),
                    ColumnType::Integer,
                    4,
                    false,
                )
            })
            .collect::<Vec<_>>();
        for (ordinal, index, name, kind, width, nullable) in [
            (1, ID, "account_id", ColumnType::Integer, 4, false),
            (6, NAME, "name", ColumnType::Char2, 32, true),
            (
                7,
                IS_HIDDEN,
                "is_hidden_bool",
                ColumnType::Boolean,
                1,
                false,
            ),
            (
                8,
                IS_DELETED,
                "is_deleted_bool",
                ColumnType::Boolean,
                1,
                false,
            ),
            (
                9,
                IS_DELETE_PENDING,
                "is_delete_pending_bool",
                ColumnType::Boolean,
                1,
                false,
            ),
            (12, PARENT, "parent_id", ColumnType::Integer, 4, true),
            (18, TYPE, "type", ColumnType::SmallInt, 2, true),
            (22, ACCOUNT_NUM, "account_num", ColumnType::Char2, 8, true),
            (24, DESCRIPTION, "description", ColumnType::Char2, 201, true),
            (
                35,
                ACCOUNT_TYPE,
                "account_type",
                ColumnType::SmallInt,
                2,
                true,
            ),
            (36, CURRENCY, "currency_id", ColumnType::Integer, 4, true),
        ] {
            columns[index] = ColumnDef::new(ordinal, name, kind, width, nullable);
        }
        RowSchema::new(columns)
    }

    fn materialized_account() -> Vec<u8> {
        let name = b"Expense";
        let number = b"400";
        let description = b"sample";
        let type_offset = 0x40 + name.len();
        let number_length_offset = type_offset + 5;
        let mut bytes = vec![0; number_length_offset + 1 + number.len() + 1 + description.len()];
        bytes[2] = crate::MATERIALIZED_ACCOUNT_ROW_KIND;
        bytes[8..12].copy_from_slice(&7_u32.to_le_bytes());
        bytes[0x1c..0x20].copy_from_slice(&42_u32.to_le_bytes());
        bytes[0x24] = name.len() as u8;
        bytes[0x25..0x25 + name.len()].copy_from_slice(name);
        bytes[type_offset] = 12;
        bytes[number_length_offset] = number.len() as u8;
        let number_start = number_length_offset + 1;
        bytes[number_start..number_start + number.len()].copy_from_slice(number);
        let description_len = number_start + number.len();
        bytes[description_len] = description.len() as u8;
        bytes[description_len + 1..description_len + 1 + description.len()]
            .copy_from_slice(description);
        let declared_len = bytes.len() as u16;
        bytes[..2].copy_from_slice(&declared_len.to_le_bytes());
        bytes
    }

    fn partial_account() -> PartialDecodedRow {
        let prefix = [
            (ID, Value::Integer(7)),
            (NAME, Value::Bytes(b"Expense".to_vec())),
            (PARENT, Value::Null),
            (TYPE, Value::Integer(12)),
            (ACCOUNT_NUM, Value::Bytes(b"400".to_vec())),
            (DESCRIPTION, Value::Bytes(b"sample".to_vec())),
        ]
        .into_iter()
        .map(|(column_index, value)| PartialRowValue {
            column_index,
            column_id: (column_index + 1) as u32,
            value,
        })
        .collect();
        let boolean_values = [
            (IS_HIDDEN, false),
            (IS_DELETED, false),
            (IS_DELETE_PENDING, false),
        ]
        .into_iter()
        .map(|(column_index, value)| PartialRowValue {
            column_index,
            column_id: (column_index + 1) as u32,
            value: Value::Boolean(value),
        })
        .collect();
        PartialDecodedRow {
            declared_size: 120,
            flags: 0,
            through_ordinal: 24,
            prefix_values: prefix,
            boolean_values,
            opaque_middle_len: 51,
        }
    }

    #[test]
    fn requires_complete_named_and_ordinal_account_schema() {
        let valid = schema();
        assert!(validate_account_row_schema(&valid).is_ok());
        let mut reordered = valid;
        reordered.columns[NAME].name = "not_name".into();
        assert!(matches!(
            validate_account_row_schema(&reordered),
            Err(SchemaAccountAdapterError::UnexpectedColumn { ordinal: 6, .. })
        ));
    }

    #[test]
    fn type18_resolver_exposes_only_calibrated_categories() {
        assert_eq!(
            resolve_enterprise24_account_type18(12),
            Some(AccountType::Expense)
        );
        assert_eq!(
            resolve_enterprise24_account_type18(11),
            Some(AccountType::CostOfGoodsSold)
        );
        assert_eq!(resolve_enterprise24_account_type18(-1), None);
    }

    #[test]
    fn lifecycle_is_driven_only_by_explicit_state_not_a_name() {
        let visible = AccountLifecycle::from_flags(false, false, false, false);
        assert!(visible.is_included());
        assert_eq!(visible.activity(), AccountActivity::Active);

        let hidden = AccountLifecycle::from_flags(true, false, false, false);
        assert!(hidden.is_included());
        assert_eq!(hidden.activity(), AccountActivity::Inactive);

        for lifecycle in [
            AccountLifecycle::from_flags(false, true, false, false),
            AccountLifecycle::from_flags(false, false, true, false),
            AccountLifecycle::from_flags(false, false, false, true),
        ] {
            assert!(!lifecycle.is_included());
        }
    }

    #[test]
    fn partial_account_adapter_uses_prefix_and_lifecycle_tail_with_identity_cross_checks() {
        let raw = materialized_account();
        let identity = MaterializedAccountRow::parse(&raw).unwrap();
        let adapted = decode_schema_account_row_partial(
            &partial_account(),
            &schema(),
            identity,
            AccountRowStateEvidence::default(),
            |_| None,
            |code| (code == 12).then_some(AccountType::Expense),
        )
        .unwrap()
        .unwrap();
        assert_eq!(adapted.account.name, "Expense");
        assert_eq!(adapted.account.account_number.as_deref(), Some("400"));
        assert_eq!(adapted.description.as_deref(), Some("sample"));
        assert_eq!(adapted.type_raw, Some(12));
        assert_eq!(adapted.account_type_raw, None);
        assert_eq!(adapted.currency_raw, None);
        assert_eq!(adapted.materialized_suffix_matches_schema, Some(true));

        let mut suffix_conflict = partial_account();
        suffix_conflict.prefix_values[4].value = Value::Bytes(b"401".to_vec());
        let identity = MaterializedAccountRow::parse(&raw).unwrap();
        let adapted = decode_schema_account_row_partial(
            &suffix_conflict,
            &schema(),
            identity,
            AccountRowStateEvidence::default(),
            |_| None,
            |code| (code == 12).then_some(AccountType::Expense),
        )
        .unwrap()
        .unwrap();
        assert_eq!(adapted.account.account_number.as_deref(), Some("401"));
        assert_eq!(adapted.materialized_suffix_matches_schema, Some(false));

        let mut conflicting = partial_account();
        conflicting.prefix_values[1].value = Value::Bytes(b"Other".to_vec());
        let identity = MaterializedAccountRow::parse(&raw).unwrap();
        assert!(matches!(
            decode_schema_account_row_partial(
                &conflicting,
                &schema(),
                identity,
                AccountRowStateEvidence::default(),
                |_| None,
                |_| Some(AccountType::Expense),
            ),
            Err(SchemaAccountAdapterError::IdentityNameDoesNotMatch)
        ));
    }

    #[test]
    fn attested_code_five_is_retained_as_accounts_payable_source_metadata() {
        let mut raw = materialized_account();
        raw[0x40 + b"Expense".len()] = 5;
        let identity = MaterializedAccountRow::parse(&raw).unwrap();
        let mut partial = partial_account();
        partial
            .prefix_values
            .iter_mut()
            .find(|value| value.column_index == TYPE)
            .expect("sample carries type ordinal")
            .value = Value::Integer(5);
        let adapted = decode_schema_account_row_partial(
            &partial,
            &schema(),
            identity,
            AccountRowStateEvidence::default(),
            |_| None,
            |code| (code == 5).then_some(AccountType::Liability),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            adapted.account.quickbooks_classification,
            Some(crate::QuickBooksAccountClassification::AccountsPayable)
        );
        assert_eq!(adapted.account.account_type, AccountType::Liability);
    }

    #[test]
    fn aggregate_audit_requires_full_physical_and_reference_identity_sets() {
        let lifecycle = AccountLifecycle::from_flags(false, false, false, false);
        let selected = (0..3)
            .map(|ordinal| {
                let id = AccountId::new(format!("SYNTHETIC-{ordinal}")).unwrap();
                let account =
                    Account::new(id, "Synthetic", crate::AccountType::Asset, true).unwrap();
                Some(SchemaAccountRow {
                    account,
                    lifecycle,
                    type_raw: None,
                    account_type_raw: None,
                    currency_raw: None,
                    description: None,
                    materialized_suffix_matches_schema: None,
                })
            })
            .collect::<Vec<_>>();
        let reference_ids = selected
            .iter()
            .flatten()
            .map(|row| row.account.id.clone())
            .collect::<BTreeSet<_>>();
        let mut physical = selected;
        let inactive_id = AccountId::new("SYNTHETIC-INACTIVE").unwrap();
        let inactive = Account::new(
            inactive_id,
            "Synthetic Inactive",
            crate::AccountType::Asset,
            false,
        )
        .unwrap()
        .with_activity(AccountActivity::Inactive);
        physical.push(Some(SchemaAccountRow {
            account: inactive,
            lifecycle: AccountLifecycle::from_flags(true, false, false, false),
            type_raw: None,
            account_type_raw: None,
            currency_raw: None,
            description: None,
            materialized_suffix_matches_schema: None,
        }));
        physical.resize_with(5, || None);
        let audit = audit_account_selection(&physical, 5, &reference_ids).unwrap();
        assert_eq!(audit.physical_rows, 5);
        assert_eq!(audit.selected_rows, 4);
        assert_eq!(audit.unique_selected_ids, 4);
        assert_eq!(audit.unique_active_selected_ids, 3);
        assert!(matches!(
            audit_account_selection(&physical, 6, &reference_ids),
            Err(SchemaAccountAdapterError::PhysicalSelectionCount {
                actual: 5,
                expected: 6,
            })
        ));
    }
}

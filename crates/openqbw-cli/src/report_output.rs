//! Deterministic machine-readable accounting report encoders.
//!
//! The module deliberately accepts only already-normalized `openqbw` reports.
//! It does not read QBW files or perform accounting aggregation, so callers can
//! validate their decoder before any artifact is written.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use openqbw::{Account, AccountActivity, AccountType, CurrentState, GeneralLedger, TrialBalance};
use rusqlite::{Connection, Transaction, params};

/// Caller-supplied provenance that accompanies every emitted report row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportMetadata {
    /// Stable, caller-defined identity of the source company file.
    pub entity_id: String,
    /// Source QBW path or other non-secret file identity.
    pub source_file: String,
    /// Version of the parser/decoder that produced the normalized report.
    pub parser_version: String,
    /// ISO-8601 timestamp supplied by the caller; never inferred from the host clock.
    pub generated_at: String,
    /// Explicit policy facts for a QuickBooks accrual Trial Balance. General
    /// Ledger output leaves this absent because it has no fiscal roll-forward.
    pub trial_balance_policy: Option<TrialBalancePolicyProvenance>,
}

/// Sanitized policy provenance for a QuickBooks accrual Trial Balance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrialBalancePolicyProvenance {
    /// The literal `explicit`: no company preference is guessed by the CLI.
    pub source: String,
    /// Strict ISO fiscal-year boundary supplied by the caller.
    pub fiscal_year_start: String,
    /// Strict ISO report-end date supplied by the caller.
    pub as_of: String,
    /// Stable normalized Retained Earnings account identifier.
    pub retained_earnings_account_id: String,
    /// Optional explicitly supplied native report label for the selected
    /// Retained Earnings account. This is presentation policy, never decoded
    /// chart metadata.
    pub retained_earnings_report_name: Option<String>,
}

impl ReportMetadata {
    /// Validates required, caller-controlled provenance.
    pub fn validate(&self) -> Result<(), ReportOutputError> {
        for (field, value) in [
            ("entity_id", &self.entity_id),
            ("source_file", &self.source_file),
            ("parser_version", &self.parser_version),
            ("generated_at", &self.generated_at),
        ] {
            if value.trim().is_empty() {
                return Err(ReportOutputError::EmptyMetadata(field));
            }
        }
        if let Some(policy) = &self.trial_balance_policy
            && (policy.source != "explicit"
                || policy.fiscal_year_start.trim().is_empty()
                || policy.as_of.trim().is_empty()
                || policy.retained_earnings_account_id.trim().is_empty()
                || policy
                    .retained_earnings_report_name
                    .as_deref()
                    .is_some_and(|value| value.trim().is_empty()))
        {
            return Err(ReportOutputError::InvalidTrialBalancePolicyMetadata);
        }
        Ok(())
    }
}

/// One or both report types to persist in one atomic SQLite operation.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReportBundle<'a> {
    pub trial_balance: Option<&'a TrialBalance>,
    pub general_ledger: Option<&'a GeneralLedger>,
}

/// Output validation or persistence failure.
#[derive(Debug)]
pub enum ReportOutputError {
    EmptyMetadata(&'static str),
    InvalidTrialBalancePolicyMetadata,
    EmptyBundle,
    InconsistentAsOfDays {
        trial_balance: i32,
        general_ledger: i32,
    },
    UnbalancedTrialBalance {
        debit_minor_units: i128,
        credit_minor_units: i128,
    },
    InconsistentTrialBalanceRow {
        account_id: String,
    },
    UnbalancedTransaction {
        transaction_id: String,
        net_minor_units: i128,
    },
    DuplicateAccountId(String),
    ConflictingAccountMetadata(String),
    MissingParentAccount {
        account_id: String,
        parent_account_id: String,
    },
    AccountHierarchyCycle {
        account_id: String,
    },
    DuplicatePostingId(String),
    DuplicateSourceRow(String),
    PostingAccountMismatch {
        posting_id: String,
        posting_account_id: String,
        entry_account_id: String,
    },
    NonCurrentPosting {
        posting_id: String,
    },
    ZeroPosting(String),
    NonDisplayablePostingAmount(String),
    PostingAfterAsOf {
        posting_id: String,
        posting_day: i32,
        as_of_day: i32,
    },
    TrialBalanceGeneralLedgerMismatch {
        account_id: String,
        trial_balance_minor_units: i64,
        general_ledger_minor_units: i128,
    },
    Sqlite(rusqlite::Error),
}

impl fmt::Display for ReportOutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMetadata(field) => write!(f, "required metadata {field} was empty"),
            Self::InvalidTrialBalancePolicyMetadata => write!(
                f,
                "Trial Balance policy metadata must be explicit and contain nonempty ISO dates and a Retained Earnings account id"
            ),
            Self::EmptyBundle => write!(f, "refusing to create an empty report bundle"),
            Self::InconsistentAsOfDays {
                trial_balance,
                general_ledger,
            } => write!(
                f,
                "trial balance as-of day {trial_balance} differs from general ledger as-of day {general_ledger}"
            ),
            Self::UnbalancedTrialBalance {
                debit_minor_units,
                credit_minor_units,
            } => write!(
                f,
                "trial balance is not balanced: debit {debit_minor_units}, credit {credit_minor_units}"
            ),
            Self::InconsistentTrialBalanceRow { account_id } => write!(
                f,
                "trial balance row for account {account_id} has inconsistent signed, debit, or credit values"
            ),
            Self::UnbalancedTransaction {
                transaction_id,
                net_minor_units,
            } => write!(
                f,
                "transaction {transaction_id} is not balanced: {net_minor_units} minor units"
            ),
            Self::DuplicateAccountId(id) => write!(f, "duplicate account identifier {id}"),
            Self::ConflictingAccountMetadata(id) => write!(
                f,
                "account {id} has conflicting metadata across report rows"
            ),
            Self::MissingParentAccount {
                account_id,
                parent_account_id,
            } => write!(
                f,
                "account {account_id} names missing parent account {parent_account_id}"
            ),
            Self::AccountHierarchyCycle { account_id } => write!(
                f,
                "account hierarchy contains a cycle at account {account_id}"
            ),
            Self::DuplicatePostingId(id) => write!(f, "duplicate posting identifier {id}"),
            Self::DuplicateSourceRow(source_row) => {
                write!(f, "duplicate posting provenance source row {source_row}")
            }
            Self::PostingAccountMismatch {
                posting_id,
                posting_account_id,
                entry_account_id,
            } => write!(
                f,
                "posting {posting_id} names account {posting_account_id}, but its General Ledger entry names {entry_account_id}"
            ),
            Self::NonCurrentPosting { posting_id } => {
                write!(
                    f,
                    "General Ledger includes non-current posting {posting_id}"
                )
            }
            Self::ZeroPosting(posting_id) => {
                write!(f, "General Ledger includes zero-value posting {posting_id}")
            }
            Self::NonDisplayablePostingAmount(posting_id) => write!(
                f,
                "General Ledger posting {posting_id} cannot be represented in debit/credit display columns"
            ),
            Self::PostingAfterAsOf {
                posting_id,
                posting_day,
                as_of_day,
            } => write!(
                f,
                "posting {posting_id} day {posting_day} is after report as-of day {as_of_day}"
            ),
            Self::TrialBalanceGeneralLedgerMismatch {
                account_id,
                trial_balance_minor_units,
                general_ledger_minor_units,
            } => write!(
                f,
                "trial balance account {account_id} has {trial_balance_minor_units} minor units, but General Ledger has {general_ledger_minor_units}"
            ),
            Self::Sqlite(error) => error.fmt(f),
        }
    }
}

impl Error for ReportOutputError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for ReportOutputError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// Encodes a Trial Balance as RFC 4180-compatible deterministic CSV.
#[allow(dead_code)]
pub fn trial_balance_csv(
    report: &TrialBalance,
    metadata: &ReportMetadata,
) -> Result<String, ReportOutputError> {
    trial_balance_csv_with_account_catalog(report, metadata, &[])
}

/// Uses the complete decoded chart to retain parent names even when a parent
/// has a zero balance and is omitted from the Trial Balance rows.
pub fn trial_balance_csv_with_account_catalog(
    report: &TrialBalance,
    metadata: &ReportMetadata,
    account_catalog: &[Account],
) -> Result<String, ReportOutputError> {
    validate_trial_balance(report)?;
    metadata.validate()?;
    let mut out = String::from(
        "entity_id,as_of_day,account_id,account_number,account_name,account_full_name,account_display_name,parent_account_id,account_type,quickbooks_classification,active,activity,debit_cents,debit,credit_cents,credit,net_cents,net,source_file,parser_version,generated_at,tb_policy_source,tb_policy_as_of,tb_policy_fiscal_year_start,tb_policy_retained_earnings_account_id,tb_policy_retained_earnings_report_name\n",
    );
    let account_full_names = account_full_names_with_catalog(
        account_catalog,
        report.rows.iter().map(|row| &row.account),
    )?;
    let account_display_names = account_display_names_with_catalog(
        account_catalog,
        report.rows.iter().map(|row| &row.account),
        &account_full_names,
    )?;
    let mut rows: Vec<_> = report.rows.iter().collect();
    rows.sort_by(|left, right| left.account.id.as_str().cmp(right.account.id.as_str()));
    let as_of_day = report.as_of.to_string();
    for row in rows {
        let debit_cents = row.debit_minor_units.map(|value| value.to_string());
        let debit = row.debit_minor_units.map(format_cents);
        let credit_cents = row.credit_minor_units.map(|value| value.to_string());
        let credit = row.credit_minor_units.map(format_cents);
        let net_cents = row.signed_minor_units.to_string();
        let net = format_cents(row.signed_minor_units);
        let account_display_name = trial_balance_account_display_name(
            account_display_name(&account_display_names, &row.account)?,
            metadata,
            &row.account,
        );
        csv_row(
            &mut out,
            &[
                Some(metadata.entity_id.as_str()),
                Some(&as_of_day),
                Some(row.account.id.as_str()),
                row.account.account_number.as_deref(),
                Some(row.account.name.as_str()),
                Some(account_full_name(&account_full_names, &row.account)?),
                Some(&account_display_name),
                row.account.parent_account_id.as_ref().map(|id| id.as_str()),
                Some(account_type_name(&row.account.account_type)),
                row.account
                    .quickbooks_classification
                    .map(openqbw::QuickBooksAccountClassification::source_label),
                csv_legacy_active(row.account.activity),
                Some(row.account.activity.as_str()),
                debit_cents.as_deref(),
                debit.as_deref(),
                credit_cents.as_deref(),
                credit.as_deref(),
                Some(&net_cents),
                Some(&net),
                Some(metadata.source_file.as_str()),
                Some(metadata.parser_version.as_str()),
                Some(metadata.generated_at.as_str()),
                metadata
                    .trial_balance_policy
                    .as_ref()
                    .map(|policy| policy.source.as_str()),
                metadata
                    .trial_balance_policy
                    .as_ref()
                    .map(|policy| policy.as_of.as_str()),
                metadata
                    .trial_balance_policy
                    .as_ref()
                    .map(|policy| policy.fiscal_year_start.as_str()),
                metadata
                    .trial_balance_policy
                    .as_ref()
                    .map(|policy| policy.retained_earnings_account_id.as_str()),
                metadata
                    .trial_balance_policy
                    .as_ref()
                    .and_then(|policy| policy.retained_earnings_report_name.as_deref()),
            ],
        );
    }
    Ok(out)
}

/// Applies the caller-attested QuickBooks retained-equity presentation to
/// only the selected Trial Balance row. Decoded chart metadata and descendant
/// hierarchy paths remain untouched.
fn trial_balance_account_display_name(
    decoded_display_name: String,
    metadata: &ReportMetadata,
    account: &Account,
) -> String {
    metadata
        .trial_balance_policy
        .as_ref()
        .filter(|policy| policy.retained_earnings_account_id == account.id.as_str())
        .and_then(|policy| policy.retained_earnings_report_name.clone())
        .unwrap_or(decoded_display_name)
}

/// Encodes a General Ledger as RFC 4180-compatible deterministic CSV.
#[allow(dead_code)]
pub fn general_ledger_csv(
    report: &GeneralLedger,
    metadata: &ReportMetadata,
) -> Result<String, ReportOutputError> {
    general_ledger_csv_with_account_catalog(report, metadata, &[])
}

/// Uses the complete decoded chart to form hierarchy-qualified account names.
pub fn general_ledger_csv_with_account_catalog(
    report: &GeneralLedger,
    metadata: &ReportMetadata,
    account_catalog: &[Account],
) -> Result<String, ReportOutputError> {
    validate_general_ledger(report)?;
    metadata.validate()?;
    let mut out = String::from(
        "entity_id,as_of_day,posting_day,transaction_id,posting_id,account_id,account_number,account_name,account_full_name,account_display_name,parent_account_id,account_type,quickbooks_classification,active,activity,debit_cents,debit,credit_cents,credit,net_cents,net,transaction_type,memo,source_row,page_number,slot_number,decoder,source_file,parser_version,generated_at\n",
    );
    let account_full_names = account_full_names_with_catalog(
        account_catalog,
        report.entries.iter().map(|entry| &entry.account),
    )?;
    let account_display_names = account_display_names_with_catalog(
        account_catalog,
        report.entries.iter().map(|entry| &entry.account),
        &account_full_names,
    )?;
    for entry in sorted_entries(report) {
        let posting = &entry.posting;
        let as_of_day = report.as_of.to_string();
        let posting_day = posting.date.to_string();
        let debit_cents = posting.debit_minor_units().map(|value| value.to_string());
        let debit = posting.debit_minor_units().map(format_cents);
        let credit_cents = posting.credit_minor_units().map(|value| value.to_string());
        let credit = posting.credit_minor_units().map(format_cents);
        let net_cents = posting.signed_minor_units.to_string();
        let net = format_cents(posting.signed_minor_units);
        let account_display_name = account_display_name(&account_display_names, &entry.account)?;
        let page_number = posting
            .provenance
            .page_number
            .map(|value| value.to_string());
        let slot_number = posting
            .provenance
            .slot_number
            .map(|value| value.to_string());
        csv_row(
            &mut out,
            &[
                Some(metadata.entity_id.as_str()),
                Some(&as_of_day),
                Some(&posting_day),
                Some(posting.transaction_id.as_str()),
                Some(posting.id.as_str()),
                Some(entry.account.id.as_str()),
                entry.account.account_number.as_deref(),
                Some(entry.account.name.as_str()),
                Some(account_full_name(&account_full_names, &entry.account)?),
                Some(&account_display_name),
                entry
                    .account
                    .parent_account_id
                    .as_ref()
                    .map(|id| id.as_str()),
                Some(account_type_name(&entry.account.account_type)),
                entry
                    .account
                    .quickbooks_classification
                    .map(openqbw::QuickBooksAccountClassification::source_label),
                csv_legacy_active(entry.account.activity),
                Some(entry.account.activity.as_str()),
                debit_cents.as_deref(),
                debit.as_deref(),
                credit_cents.as_deref(),
                credit.as_deref(),
                Some(&net_cents),
                Some(&net),
                posting.transaction_type.as_deref(),
                posting.memo.as_deref(),
                Some(posting.provenance.source_row.as_str()),
                page_number.as_deref(),
                slot_number.as_deref(),
                Some(posting.provenance.decoder.as_str()),
                Some(metadata.source_file.as_str()),
                Some(metadata.parser_version.as_str()),
                Some(metadata.generated_at.as_str()),
            ],
        );
    }
    Ok(out)
}

/// Encodes a Trial Balance as deterministic JSON without a serialization dependency.
#[allow(dead_code)]
pub fn trial_balance_json(
    report: &TrialBalance,
    metadata: &ReportMetadata,
) -> Result<String, ReportOutputError> {
    trial_balance_json_with_account_catalog(report, metadata, &[])
}

/// JSON variant that uses the complete decoded chart for full account names.
pub fn trial_balance_json_with_account_catalog(
    report: &TrialBalance,
    metadata: &ReportMetadata,
    account_catalog: &[Account],
) -> Result<String, ReportOutputError> {
    validate_trial_balance(report)?;
    metadata.validate()?;
    let account_full_names = account_full_names_with_catalog(
        account_catalog,
        report.rows.iter().map(|row| &row.account),
    )?;
    let account_display_names = account_display_names_with_catalog(
        account_catalog,
        report.rows.iter().map(|row| &row.account),
        &account_full_names,
    )?;
    let mut rows: Vec<_> = report.rows.iter().collect();
    rows.sort_by(|left, right| left.account.id.as_str().cmp(right.account.id.as_str()));
    let mut out = format!(
        "{{\"report_type\":\"trial_balance\",\"metadata\":{},\"as_of_day\":{},\"rows\":[",
        json_metadata(metadata, true),
        report.as_of
    );
    for (index, row) in rows.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        out.push_str("{\"account\":");
        json_account(
            &mut out,
            &row.account,
            &account_full_names,
            &account_display_names,
        )?;
        json_amounts(
            &mut out,
            row.debit_minor_units,
            row.credit_minor_units,
            row.signed_minor_units,
        );
        out.push('}');
    }
    out.push_str("]}");
    Ok(out)
}

/// Encodes a General Ledger as deterministic JSON without a serialization dependency.
#[allow(dead_code)]
pub fn general_ledger_json(
    report: &GeneralLedger,
    metadata: &ReportMetadata,
) -> Result<String, ReportOutputError> {
    general_ledger_json_with_account_catalog(report, metadata, &[])
}

/// JSON variant that uses the complete decoded chart for full account names.
pub fn general_ledger_json_with_account_catalog(
    report: &GeneralLedger,
    metadata: &ReportMetadata,
    account_catalog: &[Account],
) -> Result<String, ReportOutputError> {
    validate_general_ledger(report)?;
    metadata.validate()?;
    let account_full_names = account_full_names_with_catalog(
        account_catalog,
        report.entries.iter().map(|entry| &entry.account),
    )?;
    let account_display_names = account_display_names_with_catalog(
        account_catalog,
        report.entries.iter().map(|entry| &entry.account),
        &account_full_names,
    )?;
    let entries = sorted_entries(report);
    let mut out = format!(
        "{{\"report_type\":\"general_ledger\",\"metadata\":{},\"as_of_day\":{},\"entries\":[",
        json_metadata(metadata, false),
        report.as_of
    );
    for (index, entry) in entries.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        let posting = &entry.posting;
        out.push_str("{\"account\":");
        json_account(
            &mut out,
            &entry.account,
            &account_full_names,
            &account_display_names,
        )?;
        out.push_str(",\"posting_day\":");
        out.push_str(&posting.date.to_string());
        json_key_string(&mut out, "transaction_id", posting.transaction_id.as_str());
        json_key_string(&mut out, "posting_id", posting.id.as_str());
        json_amounts(
            &mut out,
            posting.debit_minor_units(),
            posting.credit_minor_units(),
            posting.signed_minor_units,
        );
        json_key_optional_string(
            &mut out,
            "transaction_type",
            posting.transaction_type.as_deref(),
        );
        json_key_optional_string(&mut out, "memo", posting.memo.as_deref());
        out.push_str(",\"provenance\":{");
        json_key_string_no_prefix(&mut out, "source_row", &posting.provenance.source_row);
        json_key_optional_number(
            &mut out,
            "page_number",
            posting.provenance.page_number.map(i64::from),
        );
        json_key_optional_number(
            &mut out,
            "slot_number",
            posting.provenance.slot_number.map(i64::from),
        );
        json_key_string(&mut out, "decoder", &posting.provenance.decoder);
        out.push_str("}}");
    }
    out.push_str("]}");
    Ok(out)
}

/// Creates normalized report tables and writes the supplied reports atomically.
///
/// All validation happens before the transaction starts.  If a SQLite statement
/// fails, the transaction is rolled back, leaving the previous output intact.
#[cfg(test)]
pub fn write_sqlite(
    connection: &mut Connection,
    metadata: &ReportMetadata,
    bundle: ReportBundle<'_>,
) -> Result<(), ReportOutputError> {
    write_sqlite_with_account_catalog(connection, metadata, bundle, &[])
}

/// SQLite variant that uses the complete decoded chart for full account names.
pub fn write_sqlite_with_account_catalog(
    connection: &mut Connection,
    metadata: &ReportMetadata,
    bundle: ReportBundle<'_>,
    account_catalog: &[Account],
) -> Result<(), ReportOutputError> {
    metadata.validate()?;
    validate_bundle(bundle)?;
    let account_full_names = account_full_names_for_bundle_with_catalog(bundle, account_catalog)?;
    let account_display_names = account_display_names_for_bundle_with_catalog(
        bundle,
        account_catalog,
        &account_full_names,
    )?;
    let transaction = connection.transaction()?;
    create_schema(&transaction)?;
    if let Some(report) = bundle.trial_balance {
        write_trial_balance(
            &transaction,
            metadata,
            report,
            &account_full_names,
            &account_display_names,
        )?;
    }
    if let Some(report) = bundle.general_ledger {
        write_general_ledger(
            &transaction,
            metadata,
            report,
            &account_full_names,
            &account_display_names,
        )?;
    }
    transaction.commit()?;
    Ok(())
}

fn validate_bundle(bundle: ReportBundle<'_>) -> Result<(), ReportOutputError> {
    if bundle.trial_balance.is_none() && bundle.general_ledger.is_none() {
        return Err(ReportOutputError::EmptyBundle);
    }
    if let Some(report) = bundle.trial_balance {
        validate_trial_balance(report)?;
    }
    if let Some(report) = bundle.general_ledger {
        validate_general_ledger(report)?;
    }
    if let (Some(trial_balance), Some(general_ledger)) =
        (bundle.trial_balance, bundle.general_ledger)
        && trial_balance.as_of != general_ledger.as_of
    {
        return Err(ReportOutputError::InconsistentAsOfDays {
            trial_balance: trial_balance.as_of,
            general_ledger: general_ledger.as_of,
        });
    }
    validate_account_metadata_consistency(bundle)?;
    if let (Some(trial_balance), Some(general_ledger)) =
        (bundle.trial_balance, bundle.general_ledger)
    {
        validate_trial_balance_matches_general_ledger(trial_balance, general_ledger)?;
    }
    Ok(())
}

fn validate_trial_balance(report: &TrialBalance) -> Result<(), ReportOutputError> {
    let mut ids = BTreeSet::new();
    for row in &report.rows {
        if !ids.insert(row.account.id.as_str()) {
            return Err(ReportOutputError::DuplicateAccountId(
                row.account.id.as_str().to_owned(),
            ));
        }
        let display_matches_signed = match row.signed_minor_units.cmp(&0) {
            std::cmp::Ordering::Greater => {
                row.debit_minor_units == Some(row.signed_minor_units)
                    && row.credit_minor_units.is_none()
            }
            std::cmp::Ordering::Less => {
                row.debit_minor_units.is_none()
                    && row.credit_minor_units.map(i128::from)
                        == Some(-i128::from(row.signed_minor_units))
            }
            std::cmp::Ordering::Equal => {
                row.debit_minor_units.is_none() && row.credit_minor_units.is_none()
            }
        };
        if !display_matches_signed {
            return Err(ReportOutputError::InconsistentTrialBalanceRow {
                account_id: row.account.id.as_str().to_owned(),
            });
        }
    }
    let debit = report.total_debit_minor_units();
    let credit = report.total_credit_minor_units();
    if debit != credit {
        return Err(ReportOutputError::UnbalancedTrialBalance {
            debit_minor_units: debit,
            credit_minor_units: credit,
        });
    }
    Ok(())
}

fn validate_general_ledger(report: &GeneralLedger) -> Result<(), ReportOutputError> {
    let mut posting_ids = BTreeSet::new();
    let mut source_rows = BTreeSet::new();
    let mut transaction_totals: BTreeMap<&str, i128> = BTreeMap::new();
    for entry in &report.entries {
        let posting = &entry.posting;
        if !posting_ids.insert(posting.id.as_str()) {
            return Err(ReportOutputError::DuplicatePostingId(
                posting.id.as_str().to_owned(),
            ));
        }
        if !source_rows.insert(posting.provenance.source_row.as_str()) {
            return Err(ReportOutputError::DuplicateSourceRow(
                posting.provenance.source_row.clone(),
            ));
        }
        if posting.account_id != entry.account.id {
            return Err(ReportOutputError::PostingAccountMismatch {
                posting_id: posting.id.as_str().to_owned(),
                posting_account_id: posting.account_id.as_str().to_owned(),
                entry_account_id: entry.account.id.as_str().to_owned(),
            });
        }
        if posting.current_state != CurrentState::Current {
            return Err(ReportOutputError::NonCurrentPosting {
                posting_id: posting.id.as_str().to_owned(),
            });
        }
        if posting.signed_minor_units == 0 {
            return Err(ReportOutputError::ZeroPosting(
                posting.id.as_str().to_owned(),
            ));
        }
        if posting.signed_minor_units == i64::MIN {
            return Err(ReportOutputError::NonDisplayablePostingAmount(
                posting.id.as_str().to_owned(),
            ));
        }
        if posting.date > report.as_of {
            return Err(ReportOutputError::PostingAfterAsOf {
                posting_id: posting.id.as_str().to_owned(),
                posting_day: posting.date,
                as_of_day: report.as_of,
            });
        }
        *transaction_totals
            .entry(posting.transaction_id.as_str())
            .or_default() += i128::from(posting.signed_minor_units);
    }
    for (transaction_id, net_minor_units) in transaction_totals {
        if net_minor_units != 0 {
            return Err(ReportOutputError::UnbalancedTransaction {
                transaction_id: transaction_id.to_owned(),
                net_minor_units,
            });
        }
    }
    Ok(())
}

/// A bundle containing both reports must be one coherent ledger snapshot.
/// Zero-balance account rows are optional, so an omitted GL account is only
/// valid when its aggregate is zero; every nonzero balance must agree exactly.
fn validate_trial_balance_matches_general_ledger(
    trial_balance: &TrialBalance,
    general_ledger: &GeneralLedger,
) -> Result<(), ReportOutputError> {
    let mut general_ledger_balances: BTreeMap<&str, i128> = BTreeMap::new();
    for entry in &general_ledger.entries {
        *general_ledger_balances
            .entry(entry.account.id.as_str())
            .or_default() += i128::from(entry.posting.signed_minor_units);
    }
    let mut trial_balance_balances: BTreeMap<&str, i64> = BTreeMap::new();
    for row in &trial_balance.rows {
        trial_balance_balances.insert(row.account.id.as_str(), row.signed_minor_units);
    }
    for account_id in trial_balance_balances
        .keys()
        .chain(general_ledger_balances.keys())
        .collect::<BTreeSet<_>>()
    {
        let trial_balance_minor_units = *trial_balance_balances.get(account_id).unwrap_or(&0);
        let general_ledger_minor_units = *general_ledger_balances.get(account_id).unwrap_or(&0);
        if i128::from(trial_balance_minor_units) != general_ledger_minor_units {
            return Err(ReportOutputError::TrialBalanceGeneralLedgerMismatch {
                account_id: (*account_id).to_owned(),
                trial_balance_minor_units,
                general_ledger_minor_units,
            });
        }
    }
    Ok(())
}

/// Ensures SQLite's entity/account upsert cannot silently choose one of two
/// incompatible descriptions for the same normalized account identifier.
fn validate_account_metadata_consistency(
    bundle: ReportBundle<'_>,
) -> Result<(), ReportOutputError> {
    let mut accounts: BTreeMap<&str, &Account> = BTreeMap::new();
    if let Some(report) = bundle.trial_balance {
        for row in &report.rows {
            accounts.insert(row.account.id.as_str(), &row.account);
        }
    }
    if let Some(report) = bundle.general_ledger {
        for entry in &report.entries {
            let account_id = entry.account.id.as_str();
            if let Some(existing) = accounts.get(account_id) {
                if *existing != &entry.account {
                    return Err(ReportOutputError::ConflictingAccountMetadata(
                        account_id.to_owned(),
                    ));
                }
            } else {
                accounts.insert(account_id, &entry.account);
            }
        }
    }
    Ok(())
}

/// Builds QuickBooks-style hierarchy-qualified names (`Parent:Child`) from
/// normalized IDs.  This intentionally needs every referenced parent in the
/// report bundle: falling back to a leaf name would make reconciliation
/// ambiguous when duplicate subaccount leaves exist.
fn account_full_names<'a>(
    accounts: impl IntoIterator<Item = &'a Account>,
) -> Result<BTreeMap<String, String>, ReportOutputError> {
    let mut by_id = BTreeMap::<&str, &Account>::new();
    for account in accounts {
        match by_id.get(account.id.as_str()) {
            Some(existing) if *existing != account => {
                return Err(ReportOutputError::ConflictingAccountMetadata(
                    account.id.as_str().to_owned(),
                ));
            }
            Some(_) => {}
            None => {
                by_id.insert(account.id.as_str(), account);
            }
        }
    }

    let mut result = BTreeMap::new();
    for account_id in by_id.keys().copied() {
        let mut current_id = account_id;
        let mut seen = BTreeSet::new();
        let mut components = Vec::new();
        loop {
            if !seen.insert(current_id) {
                return Err(ReportOutputError::AccountHierarchyCycle {
                    account_id: current_id.to_owned(),
                });
            }
            let account = by_id.get(current_id).copied().ok_or_else(|| {
                // `current_id` is a parent reference only after the first
                // loop iteration; preserve the account that declared it.
                ReportOutputError::MissingParentAccount {
                    account_id: account_id.to_owned(),
                    parent_account_id: current_id.to_owned(),
                }
            })?;
            components.push(account.name.as_str());
            match &account.parent_account_id {
                Some(parent) => current_id = parent.as_str(),
                None => break,
            }
        }
        components.reverse();
        result.insert(account_id.to_owned(), components.join(":"));
    }
    Ok(result)
}

pub(crate) fn account_full_names_with_catalog<'a>(
    account_catalog: &'a [Account],
    report_accounts: impl IntoIterator<Item = &'a Account>,
) -> Result<BTreeMap<String, String>, ReportOutputError> {
    account_full_names(account_catalog.iter().chain(report_accounts))
}

fn account_full_names_for_bundle_with_catalog(
    bundle: ReportBundle<'_>,
    account_catalog: &[Account],
) -> Result<BTreeMap<String, String>, ReportOutputError> {
    let mut accounts = Vec::new();
    if let Some(report) = bundle.trial_balance {
        accounts.extend(report.rows.iter().map(|row| &row.account));
    }
    if let Some(report) = bundle.general_ledger {
        accounts.extend(report.entries.iter().map(|entry| &entry.account));
    }
    account_full_names_with_catalog(account_catalog, accounts)
}

/// Builds QuickBooks-style display labels separately from number-free full
/// names. A child with no own number inherits the nearest numbered ancestor's
/// presentation prefix; its normalized `account_number` remains `None`.
pub(crate) fn account_display_names_with_catalog<'a>(
    account_catalog: &'a [Account],
    report_accounts: impl IntoIterator<Item = &'a Account>,
    full_names: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, ReportOutputError> {
    account_display_names(account_catalog.iter().chain(report_accounts), full_names)
}

fn account_display_names_for_bundle_with_catalog(
    bundle: ReportBundle<'_>,
    account_catalog: &[Account],
    full_names: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, ReportOutputError> {
    let mut accounts = Vec::new();
    if let Some(report) = bundle.trial_balance {
        accounts.extend(report.rows.iter().map(|row| &row.account));
    }
    if let Some(report) = bundle.general_ledger {
        accounts.extend(report.entries.iter().map(|entry| &entry.account));
    }
    account_display_names_with_catalog(account_catalog, accounts, full_names)
}

fn account_display_names<'a>(
    accounts: impl IntoIterator<Item = &'a Account>,
    full_names: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, ReportOutputError> {
    let mut by_id = BTreeMap::new();
    for account in accounts {
        match by_id.get(account.id.as_str()) {
            Some(existing) if *existing != account => {
                return Err(ReportOutputError::ConflictingAccountMetadata(
                    account.id.as_str().to_owned(),
                ));
            }
            Some(_) => {}
            None => {
                by_id.insert(account.id.as_str(), account);
            }
        }
    }
    let mut result = BTreeMap::new();
    for (&account_id, account) in &by_id {
        let mut current = *account;
        let mut seen = BTreeSet::new();
        let number = loop {
            if !seen.insert(current.id.as_str()) {
                return Err(ReportOutputError::AccountHierarchyCycle {
                    account_id: account_id.to_owned(),
                });
            }
            if let Some(number) = current.account_number.as_deref() {
                break Some(number);
            }
            let Some(parent_id) = current.parent_account_id.as_ref() else {
                break None;
            };
            current = by_id.get(parent_id.as_str()).copied().ok_or_else(|| {
                ReportOutputError::MissingParentAccount {
                    account_id: account_id.to_owned(),
                    parent_account_id: parent_id.as_str().to_owned(),
                }
            })?;
        };
        let full_name =
            full_names
                .get(account_id)
                .ok_or_else(|| ReportOutputError::MissingParentAccount {
                    account_id: account_id.to_owned(),
                    parent_account_id: "<account missing from report>".to_owned(),
                })?;
        let label = match number {
            Some(number) => format!("{number} · {full_name}"),
            None => full_name.clone(),
        };
        result.insert(account_id.to_owned(), label);
    }
    Ok(result)
}

fn account_full_name<'a>(
    names: &'a BTreeMap<String, String>,
    account: &Account,
) -> Result<&'a str, ReportOutputError> {
    names
        .get(account.id.as_str())
        .map(String::as_str)
        .ok_or_else(|| ReportOutputError::MissingParentAccount {
            account_id: account.id.as_str().to_owned(),
            parent_account_id: "<account missing from report>".to_owned(),
        })
}

/// Retrieves the already-derived native-style display label. The presentation
/// layer may inherit a numbered ancestor's prefix; `account_number` itself
/// remains the account's own stored value, and `account_full_name` stays
/// number-free for stable reconciliation.
fn account_display_name(
    names: &BTreeMap<String, String>,
    account: &Account,
) -> Result<String, ReportOutputError> {
    account_full_name(names, account).map(str::to_owned)
}

fn create_schema(transaction: &Transaction<'_>) -> Result<(), rusqlite::Error> {
    transaction.execute_batch("\
        CREATE TABLE IF NOT EXISTS report_metadata (\
            entity_id TEXT NOT NULL, report_type TEXT NOT NULL, as_of_day INTEGER NOT NULL,\
            source_file TEXT NOT NULL, parser_version TEXT NOT NULL, generated_at TEXT NOT NULL,\
            PRIMARY KEY (entity_id, report_type, as_of_day)\
        ) STRICT;\
        CREATE TABLE IF NOT EXISTS accounts (\
            entity_id TEXT NOT NULL, account_id TEXT NOT NULL, account_number TEXT, account_name TEXT NOT NULL, account_full_name TEXT NOT NULL, account_display_name TEXT NOT NULL,\
            parent_account_id TEXT, account_type TEXT NOT NULL, quickbooks_classification TEXT, active INTEGER CHECK(active IN (0,1)),\
            activity TEXT NOT NULL CHECK(activity IN ('active','inactive','unknown')),\
            PRIMARY KEY (entity_id, account_id)\
        ) STRICT;\
        CREATE TABLE IF NOT EXISTS trial_balance_policy_metadata (\
            entity_id TEXT NOT NULL, as_of_day INTEGER NOT NULL, source TEXT NOT NULL,\
            fiscal_year_start TEXT NOT NULL, as_of_iso TEXT NOT NULL, retained_earnings_account_id TEXT NOT NULL,\
            retained_earnings_report_name TEXT,\
            PRIMARY KEY (entity_id, as_of_day)\
        ) STRICT;\
        CREATE TABLE IF NOT EXISTS trial_balance_rows (\
            entity_id TEXT NOT NULL, as_of_day INTEGER NOT NULL, account_id TEXT NOT NULL,\
            debit_cents INTEGER, credit_cents INTEGER, net_cents INTEGER NOT NULL,\
            PRIMARY KEY (entity_id, as_of_day, account_id)\
        ) STRICT;\
        CREATE TABLE IF NOT EXISTS general_ledger_entries (\
            entity_id TEXT NOT NULL, as_of_day INTEGER NOT NULL, posting_id TEXT NOT NULL, transaction_id TEXT NOT NULL,\
            posting_day INTEGER NOT NULL, account_id TEXT NOT NULL, debit_cents INTEGER, credit_cents INTEGER, net_cents INTEGER NOT NULL,\
            transaction_type TEXT, memo TEXT, source_row TEXT NOT NULL, page_number INTEGER, slot_number INTEGER, decoder TEXT NOT NULL,\
            PRIMARY KEY (entity_id, as_of_day, posting_id)\
        ) STRICT;")?;
    migrate_accounts_schema(transaction)?;
    migrate_trial_balance_policy_schema(transaction)
}

/// Upgrades the original two-valued accounts table without reinterpreting its
/// historical values.  Older `active=0/1` values remain explicitly inactive or
/// active; only newly decoded unproven values are written as `NULL` plus
/// `activity='unknown'`.
fn migrate_accounts_schema(transaction: &Transaction<'_>) -> Result<(), rusqlite::Error> {
    let mut statement = transaction.prepare("PRAGMA table_info(accounts)")?;
    let columns = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, i64>(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let has_activity = columns.iter().any(|(name, _)| name == "activity");
    let has_full_name = columns.iter().any(|(name, _)| name == "account_full_name");
    let has_display_name = columns
        .iter()
        .any(|(name, _)| name == "account_display_name");
    let has_quickbooks_classification = columns
        .iter()
        .any(|(name, _)| name == "quickbooks_classification");
    let active_is_not_null = columns
        .iter()
        .find(|(name, _)| name == "active")
        .is_some_and(|(_, not_null)| *not_null != 0);
    if !has_activity || !has_full_name || !has_display_name || active_is_not_null {
        let activity_source = if has_activity {
            "activity"
        } else {
            "CASE active WHEN 1 THEN 'active' ELSE 'inactive' END"
        };
        let full_name_source = if has_full_name {
            "account_full_name"
        } else {
            "account_name"
        };
        let display_name_source = if has_display_name {
            "account_display_name"
        } else if has_full_name {
            "account_full_name"
        } else {
            "account_name"
        };
        transaction.execute_batch(&format!(
            "ALTER TABLE accounts RENAME TO accounts_legacy_activity_migration;\
             CREATE TABLE accounts (\
                 entity_id TEXT NOT NULL, account_id TEXT NOT NULL, account_number TEXT, account_name TEXT NOT NULL, account_full_name TEXT NOT NULL, account_display_name TEXT NOT NULL,\
                 parent_account_id TEXT, account_type TEXT NOT NULL, quickbooks_classification TEXT, active INTEGER CHECK(active IN (0,1)),\
                 activity TEXT NOT NULL CHECK(activity IN ('active','inactive','unknown')),\
                 PRIMARY KEY (entity_id, account_id)\
             ) STRICT;\
             INSERT INTO accounts(entity_id,account_id,account_number,account_name,account_full_name,account_display_name,parent_account_id,account_type,quickbooks_classification,active,activity) \
             SELECT entity_id,account_id,account_number,account_name,{full_name_source},{display_name_source},parent_account_id,account_type,NULL,active,{activity_source} \
             FROM accounts_legacy_activity_migration;\
             DROP TABLE accounts_legacy_activity_migration;"
        ))?;
    } else if !has_quickbooks_classification {
        transaction
            .execute_batch("ALTER TABLE accounts ADD COLUMN quickbooks_classification TEXT;")?;
    }
    Ok(())
}

/// Add optional report-label provenance without changing historical policy
/// rows. This is an additive migration because the account identifier remains
/// the authoritative accounting key.
fn migrate_trial_balance_policy_schema(
    transaction: &Transaction<'_>,
) -> Result<(), rusqlite::Error> {
    let mut statement = transaction.prepare("PRAGMA table_info(trial_balance_policy_metadata)")?;
    let has_report_name = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|name| name == "retained_earnings_report_name");
    if !has_report_name {
        transaction.execute_batch(
            "ALTER TABLE trial_balance_policy_metadata ADD COLUMN retained_earnings_report_name TEXT;",
        )?;
    }
    Ok(())
}

fn write_trial_balance(
    transaction: &Transaction<'_>,
    metadata: &ReportMetadata,
    report: &TrialBalance,
    account_full_names: &BTreeMap<String, String>,
    account_display_names: &BTreeMap<String, String>,
) -> Result<(), ReportOutputError> {
    transaction.execute(
        "DELETE FROM trial_balance_rows WHERE entity_id=?1 AND as_of_day=?2",
        params![metadata.entity_id, report.as_of],
    )?;
    upsert_metadata(transaction, metadata, "trial_balance", report.as_of)?;
    transaction.execute(
        "DELETE FROM trial_balance_policy_metadata WHERE entity_id=?1 AND as_of_day=?2",
        params![metadata.entity_id, report.as_of],
    )?;
    if let Some(policy) = &metadata.trial_balance_policy {
        transaction.execute(
            "INSERT INTO trial_balance_policy_metadata(entity_id,as_of_day,source,fiscal_year_start,as_of_iso,retained_earnings_account_id,retained_earnings_report_name) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![metadata.entity_id, report.as_of, policy.source, policy.fiscal_year_start, policy.as_of, policy.retained_earnings_account_id, policy.retained_earnings_report_name],
        )?;
    }
    let mut rows: Vec<_> = report.rows.iter().collect();
    rows.sort_by(|a, b| a.account.id.as_str().cmp(b.account.id.as_str()));
    for row in rows {
        upsert_account(
            transaction,
            &metadata.entity_id,
            &row.account,
            account_full_name(account_full_names, &row.account)?,
            &account_display_name(account_display_names, &row.account)?,
        )?;
        transaction.execute("INSERT INTO trial_balance_rows(entity_id,as_of_day,account_id,debit_cents,credit_cents,net_cents) VALUES(?1,?2,?3,?4,?5,?6)", params![metadata.entity_id, report.as_of, row.account.id.as_str(), row.debit_minor_units, row.credit_minor_units, row.signed_minor_units])?;
    }
    Ok(())
}

fn write_general_ledger(
    transaction: &Transaction<'_>,
    metadata: &ReportMetadata,
    report: &GeneralLedger,
    account_full_names: &BTreeMap<String, String>,
    account_display_names: &BTreeMap<String, String>,
) -> Result<(), ReportOutputError> {
    transaction.execute(
        "DELETE FROM general_ledger_entries WHERE entity_id=?1 AND as_of_day=?2",
        params![metadata.entity_id, report.as_of],
    )?;
    upsert_metadata(transaction, metadata, "general_ledger", report.as_of)?;
    for entry in sorted_entries(report) {
        let posting = &entry.posting;
        upsert_account(
            transaction,
            &metadata.entity_id,
            &entry.account,
            account_full_name(account_full_names, &entry.account)?,
            &account_display_name(account_display_names, &entry.account)?,
        )?;
        transaction.execute("INSERT INTO general_ledger_entries(entity_id,as_of_day,posting_id,transaction_id,posting_day,account_id,debit_cents,credit_cents,net_cents,transaction_type,memo,source_row,page_number,slot_number,decoder) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)", params![metadata.entity_id, report.as_of, posting.id.as_str(), posting.transaction_id.as_str(), posting.date, entry.account.id.as_str(), posting.debit_minor_units(), posting.credit_minor_units(), posting.signed_minor_units, posting.transaction_type, posting.memo, posting.provenance.source_row, posting.provenance.page_number, posting.provenance.slot_number, posting.provenance.decoder])?;
    }
    Ok(())
}

fn upsert_metadata(
    transaction: &Transaction<'_>,
    metadata: &ReportMetadata,
    report_type: &str,
    as_of_day: i32,
) -> Result<(), rusqlite::Error> {
    transaction.execute("INSERT INTO report_metadata(entity_id,report_type,as_of_day,source_file,parser_version,generated_at) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(entity_id,report_type,as_of_day) DO UPDATE SET source_file=excluded.source_file,parser_version=excluded.parser_version,generated_at=excluded.generated_at", params![metadata.entity_id, report_type, as_of_day, metadata.source_file, metadata.parser_version, metadata.generated_at])?;
    Ok(())
}

fn upsert_account(
    transaction: &Transaction<'_>,
    entity_id: &str,
    account: &Account,
    account_full_name: &str,
    account_display_name: &str,
) -> Result<(), rusqlite::Error> {
    transaction.execute("INSERT INTO accounts(entity_id,account_id,account_number,account_name,account_full_name,account_display_name,parent_account_id,account_type,quickbooks_classification,active,activity) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) ON CONFLICT(entity_id,account_id) DO UPDATE SET account_number=excluded.account_number,account_name=excluded.account_name,account_full_name=excluded.account_full_name,account_display_name=excluded.account_display_name,parent_account_id=excluded.parent_account_id,account_type=excluded.account_type,quickbooks_classification=excluded.quickbooks_classification,active=excluded.active,activity=excluded.activity", params![entity_id, account.id.as_str(), account.account_number, account.name, account_full_name, account_display_name, account.parent_account_id.as_ref().map(|id| id.as_str()), account_type_name(&account.account_type), account.quickbooks_classification.map(openqbw::QuickBooksAccountClassification::source_label), account.activity.known_bool().map(i64::from), account.activity.as_str()])?;
    Ok(())
}

fn sorted_entries(report: &GeneralLedger) -> Vec<&openqbw::GeneralLedgerEntry> {
    let mut entries: Vec<_> = report.entries.iter().collect();
    entries.sort_by(|left, right| {
        (
            &left.posting.date,
            left.account.id.as_str(),
            left.posting.transaction_id.as_str(),
            left.posting.id.as_str(),
        )
            .cmp(&(
                &right.posting.date,
                right.account.id.as_str(),
                right.posting.transaction_id.as_str(),
                right.posting.id.as_str(),
            ))
    });
    entries
}

fn account_type_name(value: &AccountType) -> &str {
    match value {
        AccountType::Asset => "asset",
        AccountType::Liability => "liability",
        AccountType::Equity => "equity",
        AccountType::Income => "income",
        AccountType::Expense => "expense",
        AccountType::CostOfGoodsSold => "cost_of_goods_sold",
        AccountType::Other(value) => value,
    }
}

/// Preserves the existing CSV `active` column while leaving it blank when
/// activity was not proven.  The adjacent `activity` column is authoritative.
fn csv_legacy_active(activity: AccountActivity) -> Option<&'static str> {
    match activity {
        AccountActivity::Active => Some("true"),
        AccountActivity::Inactive => Some("false"),
        AccountActivity::Unknown => None,
    }
}

fn format_cents(cents: i64) -> String {
    let value = i128::from(cents);
    let sign = if value < 0 { "-" } else { "" };
    let absolute = value.abs();
    format!("{sign}{}.{:02}", absolute / 100, absolute % 100)
}

fn csv_row(out: &mut String, fields: &[Option<&str>]) {
    for (index, value) in fields.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        if let Some(value) = value {
            csv_field(out, value);
        }
    }
    out.push('\n');
}
fn csv_field(out: &mut String, value: &str) {
    if value.contains([',', '"', '\r', '\n']) {
        out.push('"');
        out.push_str(&value.replace('"', "\"\""));
        out.push('"');
    } else {
        out.push_str(value);
    }
}

fn json_metadata(metadata: &ReportMetadata, include_trial_balance_policy: bool) -> String {
    let mut out = String::from("{");
    json_key_string_no_prefix(&mut out, "entity_id", &metadata.entity_id);
    json_key_string(&mut out, "source_file", &metadata.source_file);
    json_key_string(&mut out, "parser_version", &metadata.parser_version);
    json_key_string(&mut out, "generated_at", &metadata.generated_at);
    if include_trial_balance_policy && let Some(policy) = &metadata.trial_balance_policy {
        out.push_str(",\"trial_balance_policy\":{");
        json_key_string_no_prefix(&mut out, "source", &policy.source);
        json_key_string(&mut out, "as_of", &policy.as_of);
        json_key_string(&mut out, "fiscal_year_start", &policy.fiscal_year_start);
        json_key_string(
            &mut out,
            "retained_earnings_account_id",
            &policy.retained_earnings_account_id,
        );
        json_key_optional_string(
            &mut out,
            "retained_earnings_report_name",
            policy.retained_earnings_report_name.as_deref(),
        );
        out.push('}');
    }
    out.push('}');
    out
}
fn json_account(
    out: &mut String,
    account: &Account,
    account_full_names: &BTreeMap<String, String>,
    account_display_names: &BTreeMap<String, String>,
) -> Result<(), ReportOutputError> {
    out.push('{');
    json_key_string_no_prefix(out, "account_id", account.id.as_str());
    json_key_optional_string(out, "account_number", account.account_number.as_deref());
    json_key_string(out, "account_name", &account.name);
    json_key_string(
        out,
        "account_full_name",
        account_full_name(account_full_names, account)?,
    );
    json_key_string(
        out,
        "account_display_name",
        &account_display_name(account_display_names, account)?,
    );
    json_key_optional_string(
        out,
        "parent_account_id",
        account.parent_account_id.as_ref().map(|id| id.as_str()),
    );
    json_key_string(
        out,
        "account_type",
        account_type_name(&account.account_type),
    );
    json_key_optional_string(
        out,
        "quickbooks_classification",
        account
            .quickbooks_classification
            .map(openqbw::QuickBooksAccountClassification::source_label),
    );
    out.push_str(",\"active\":");
    match account.activity.known_bool() {
        Some(value) => out.push_str(if value { "true" } else { "false" }),
        None => out.push_str("null"),
    }
    json_key_string(out, "activity", account.activity.as_str());
    out.push('}');
    Ok(())
}
fn json_amounts(out: &mut String, debit: Option<i64>, credit: Option<i64>, net: i64) {
    json_key_optional_number(out, "debit_cents", debit);
    json_key_optional_string(out, "debit", debit.map(format_cents).as_deref());
    json_key_optional_number(out, "credit_cents", credit);
    json_key_optional_string(out, "credit", credit.map(format_cents).as_deref());
    json_key_number(out, "net_cents", i128::from(net));
    json_key_string(out, "net", &format_cents(net));
}
fn json_key_string_no_prefix(out: &mut String, key: &str, value: &str) {
    json_string(out, key);
    out.push(':');
    json_string(out, value);
}
fn json_key_string(out: &mut String, key: &str, value: &str) {
    out.push(',');
    json_key_string_no_prefix(out, key, value);
}
fn json_key_optional_string(out: &mut String, key: &str, value: Option<&str>) {
    out.push(',');
    json_string(out, key);
    out.push(':');
    if let Some(value) = value {
        json_string(out, value);
    } else {
        out.push_str("null");
    }
}
fn json_key_optional_number(out: &mut String, key: &str, value: Option<i64>) {
    out.push(',');
    json_string(out, key);
    out.push(':');
    if let Some(value) = value {
        out.push_str(&value.to_string());
    } else {
        out.push_str("null");
    }
}
fn json_key_number(out: &mut String, key: &str, value: i128) {
    out.push(',');
    json_string(out, key);
    out.push(':');
    out.push_str(&value.to_string());
}
fn json_string(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            value if value <= '\u{1F}' => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", value as u32);
            }
            value => out.push(value),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use openqbw::{
        AccountActivity, AccountId, AccountType, CurrentState, DebitCredit, DebitCreditAmount,
        GeneralLedgerEntry, Posting, PostingId, PostingProvenance, QuickBooksAccountClassification,
        TransactionId, TrialBalanceRow,
    };

    fn metadata() -> ReportMetadata {
        ReportMetadata {
            entity_id: "entity-1".into(),
            source_file: "company.qbw".into(),
            parser_version: "test-1".into(),
            generated_at: "2026-08-26T00:00:00Z".into(),
            trial_balance_policy: None,
        }
    }
    fn account(id: &str, name: &str, kind: AccountType) -> Account {
        Account::new(AccountId::new(id).unwrap(), name, kind, true).unwrap()
    }

    #[test]
    fn child_display_name_inherits_nearest_numbered_ancestor() {
        let parent = account("sample-parent", "SAMPLE Parent", AccountType::Asset)
            .with_hierarchy(Some("1000".into()), None)
            .unwrap();
        let child = account("sample-child", "SAMPLE Child", AccountType::Asset)
            .with_hierarchy(None, Some(parent.id.clone()))
            .unwrap();
        let full_names = account_full_names([&parent, &child]).unwrap();
        let display_names = account_display_names([&parent, &child], &full_names).unwrap();
        assert_eq!(child.account_number, None);
        assert_eq!(
            account_display_name(&display_names, &child).unwrap(),
            "1000 · SAMPLE Parent:SAMPLE Child"
        );
        assert_eq!(
            account_display_name(&display_names, &parent).unwrap(),
            "1000 · SAMPLE Parent"
        );
    }

    fn reports() -> (TrialBalance, GeneralLedger) {
        let cash = account("cash", "Cash, \"main\"", AccountType::Asset);
        let income = account("income", "Income", AccountType::Income);
        let debit = Posting::new(
            TransactionId::new("txn-1").unwrap(),
            PostingId::new("post-1").unwrap(),
            cash.id.clone(),
            20,
            DebitCreditAmount::new(DebitCredit::Debit, 125).unwrap(),
            CurrentState::Current,
            PostingProvenance::new("r,1", Some(2), Some(3), "decoder").unwrap(),
            Some("Journal".into()),
            Some("line\nbreak".into()),
        );
        let credit = Posting::new(
            TransactionId::new("txn-1").unwrap(),
            PostingId::new("post-2").unwrap(),
            income.id.clone(),
            20,
            DebitCreditAmount::new(DebitCredit::Credit, 125).unwrap(),
            CurrentState::Current,
            PostingProvenance::new("r2", None, None, "decoder").unwrap(),
            None,
            None,
        );
        let trial_balance = TrialBalance {
            as_of: 20,
            rows: vec![
                TrialBalanceRow {
                    account: income.clone(),
                    signed_minor_units: -125,
                    debit_minor_units: None,
                    credit_minor_units: Some(125),
                },
                TrialBalanceRow {
                    account: cash.clone(),
                    signed_minor_units: 125,
                    debit_minor_units: Some(125),
                    credit_minor_units: None,
                },
            ],
        };
        (
            trial_balance,
            GeneralLedger {
                as_of: 20,
                entries: vec![
                    GeneralLedgerEntry {
                        account: income,
                        posting: credit,
                    },
                    GeneralLedgerEntry {
                        account: cash,
                        posting: debit,
                    },
                ],
            },
        )
    }
    #[test]
    fn csv_is_sorted_escaped_and_uses_fixed_cents() {
        let (tb, _) = reports();
        let csv = trial_balance_csv(&tb, &metadata()).unwrap();
        assert!(csv.contains("\"Cash, \"\"main\"\"\""));
        assert!(csv.contains("1.25"));
        assert!(csv.find("cash").unwrap() < csv.find("income").unwrap());
    }

    #[test]
    fn trial_balance_policy_provenance_is_emitted_without_affecting_gl() {
        let (tb, gl) = reports();
        let mut metadata = metadata();
        metadata.trial_balance_policy = Some(TrialBalancePolicyProvenance {
            source: "explicit".into(),
            fiscal_year_start: "2026-01-01".into(),
            as_of: "2026-08-26".into(),
            retained_earnings_account_id: "cash".into(),
            retained_earnings_report_name: Some("SAMPLE Members Equity".into()),
        });
        let csv = trial_balance_csv(&tb, &metadata).unwrap();
        assert!(csv.contains("tb_policy_fiscal_year_start"));
        assert!(csv.contains("2026-01-01"));
        assert!(csv.contains("SAMPLE Members Equity"));
        // The presentation override must not replace decoded chart metadata.
        assert!(csv.contains("\"Cash, \"\"main\"\"\""));
        let json = trial_balance_json(&tb, &metadata).unwrap();
        assert!(json.contains("\"trial_balance_policy\""));
        let gl_json = general_ledger_json(&gl, &metadata).unwrap();
        assert!(!gl_json.contains("\"trial_balance_policy\""));

        let mut connection = Connection::open_in_memory().unwrap();
        write_sqlite(
            &mut connection,
            &metadata,
            ReportBundle {
                trial_balance: Some(&tb),
                general_ledger: None,
            },
        )
        .unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT source, fiscal_year_start, as_of_iso, retained_earnings_account_id, retained_earnings_report_name FROM trial_balance_policy_metadata",
                    [],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?)),
                )
                .unwrap(),
            ("explicit".into(), "2026-01-01".into(), "2026-08-26".into(), "cash".into(), "SAMPLE Members Equity".into())
        );
    }
    #[test]
    fn general_ledger_csv_is_sorted_and_retains_provenance() {
        let (_, gl) = reports();
        let csv = general_ledger_csv(&gl, &metadata()).unwrap();
        assert!(csv.find("post-1").unwrap() < csv.find("post-2").unwrap());
        assert!(csv.contains("r,1"));
        assert!(csv.contains("decoder"));
    }
    #[test]
    fn json_is_deterministic_and_escaped() {
        let (_, gl) = reports();
        let json = general_ledger_json(&gl, &metadata()).unwrap();
        assert!(json.contains("\"memo\":\"line\\nbreak\""));
        assert!(json.contains("\"debit\":\"1.25\""));
        assert!(json.find("post-1").unwrap() < json.find("post-2").unwrap());
    }
    #[test]
    fn unknown_account_activity_is_not_exported_as_false() {
        let (mut tb, mut gl) = reports();
        for row in &mut tb.rows {
            row.account = row.account.clone().with_activity(AccountActivity::Unknown);
        }
        for entry in &mut gl.entries {
            entry.account = entry
                .account
                .clone()
                .with_activity(AccountActivity::Unknown);
        }
        let csv = trial_balance_csv(&tb, &metadata()).unwrap();
        assert!(csv.lines().next().unwrap().contains("active,activity"));
        assert!(csv.contains(",,unknown,"));
        let json = general_ledger_json(&gl, &metadata()).unwrap();
        assert!(json.contains("\"active\":null,\"activity\":\"unknown\""));

        let mut connection = Connection::open_in_memory().unwrap();
        write_sqlite(
            &mut connection,
            &metadata(),
            ReportBundle {
                trial_balance: Some(&tb),
                general_ledger: Some(&gl),
            },
        )
        .unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT active IS NULL, activity FROM accounts WHERE account_id='cash'",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .unwrap(),
            (1, "unknown".into())
        );
    }

    #[test]
    fn source_classification_is_consistent_across_csv_json_and_sqlite() {
        let (mut tb, mut gl) = reports();
        for row in &mut tb.rows {
            row.account = row
                .account
                .clone()
                .with_quickbooks_classification(QuickBooksAccountClassification::AccountsPayable);
        }
        for entry in &mut gl.entries {
            entry.account = entry
                .account
                .clone()
                .with_quickbooks_classification(QuickBooksAccountClassification::AccountsPayable);
        }
        assert!(
            trial_balance_csv(&tb, &metadata())
                .unwrap()
                .contains("quickbooks_classification")
        );
        assert!(
            general_ledger_json(&gl, &metadata())
                .unwrap()
                .contains("\"quickbooks_classification\":\"AccountsPayable\"")
        );
        let mut connection = Connection::open_in_memory().unwrap();
        write_sqlite(
            &mut connection,
            &metadata(),
            ReportBundle {
                trial_balance: Some(&tb),
                general_ledger: Some(&gl),
            },
        )
        .unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT quickbooks_classification FROM accounts WHERE account_id='cash'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "AccountsPayable"
        );
    }

    #[test]
    fn legacy_sqlite_accounts_are_migrated_without_changing_known_activity() {
        let (_, gl) = reports();
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE accounts (entity_id TEXT NOT NULL, account_id TEXT NOT NULL, account_number TEXT, account_name TEXT NOT NULL, parent_account_id TEXT, account_type TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1)), PRIMARY KEY (entity_id, account_id)) STRICT;\
                 INSERT INTO accounts VALUES ('old','known',NULL,'Known',NULL,'asset',1);",
            )
            .unwrap();
        write_sqlite(
            &mut connection,
            &metadata(),
            ReportBundle {
                trial_balance: None,
                general_ledger: Some(&gl),
            },
        )
        .unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT active, activity, quickbooks_classification IS NULL FROM accounts WHERE entity_id='old' AND account_id='known'",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?)),
                )
                .unwrap(),
            (1, "active".into(), 1)
        );
    }
    #[test]
    fn sqlite_writes_all_normalized_tables_atomically() {
        let (tb, gl) = reports();
        let mut connection = Connection::open_in_memory().unwrap();
        write_sqlite(
            &mut connection,
            &metadata(),
            ReportBundle {
                trial_balance: Some(&tb),
                general_ledger: Some(&gl),
            },
        )
        .unwrap();
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM accounts", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM general_ledger_entries", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn hierarchy_qualified_names_disambiguate_duplicate_leaf_accounts_everywhere() {
        let parent = account("sample-parent", "SAMPLE Parent", AccountType::Asset);
        let child = account("sample-child", "Retained Earnings", AccountType::Asset)
            .with_hierarchy(None, Some(AccountId::new("sample-parent").unwrap()))
            .unwrap();
        let root = account("sample-root", "Retained Earnings", AccountType::Equity);
        let report = TrialBalance {
            as_of: 20,
            rows: vec![
                TrialBalanceRow {
                    account: parent,
                    signed_minor_units: 0,
                    debit_minor_units: None,
                    credit_minor_units: None,
                },
                TrialBalanceRow {
                    account: child,
                    signed_minor_units: 125,
                    debit_minor_units: Some(125),
                    credit_minor_units: None,
                },
                TrialBalanceRow {
                    account: root,
                    signed_minor_units: -125,
                    debit_minor_units: None,
                    credit_minor_units: Some(125),
                },
            ],
        };
        let csv = trial_balance_csv(&report, &metadata()).unwrap();
        assert!(csv.lines().next().unwrap().contains("account_full_name"));
        assert!(csv.contains("SAMPLE Parent:Retained Earnings"));
        let json = trial_balance_json(&report, &metadata()).unwrap();
        assert!(json.contains("\"account_full_name\":\"SAMPLE Parent:Retained Earnings\""));

        let mut connection = Connection::open_in_memory().unwrap();
        write_sqlite(
            &mut connection,
            &metadata(),
            ReportBundle {
                trial_balance: Some(&report),
                general_ledger: None,
            },
        )
        .unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT account_full_name FROM accounts WHERE account_id='sample-child'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "SAMPLE Parent:Retained Earnings"
        );
    }

    #[test]
    fn report_output_refuses_missing_parent_and_cycles() {
        let missing = account("sample-child", "SAMPLE Child", AccountType::Asset)
            .with_hierarchy(None, Some(AccountId::new("sample-missing").unwrap()))
            .unwrap();
        let report = TrialBalance {
            as_of: 1,
            rows: vec![TrialBalanceRow {
                account: missing,
                signed_minor_units: 0,
                debit_minor_units: None,
                credit_minor_units: None,
            }],
        };
        assert!(matches!(
            trial_balance_csv(&report, &metadata()),
            Err(ReportOutputError::MissingParentAccount { .. })
        ));

        let first = account("sample-a", "SAMPLE A", AccountType::Asset)
            .with_hierarchy(None, Some(AccountId::new("sample-b").unwrap()))
            .unwrap();
        let second = account("sample-b", "SAMPLE B", AccountType::Asset)
            .with_hierarchy(None, Some(AccountId::new("sample-a").unwrap()))
            .unwrap();
        let report = TrialBalance {
            as_of: 1,
            rows: vec![
                TrialBalanceRow {
                    account: first,
                    signed_minor_units: 0,
                    debit_minor_units: None,
                    credit_minor_units: None,
                },
                TrialBalanceRow {
                    account: second,
                    signed_minor_units: 0,
                    debit_minor_units: None,
                    credit_minor_units: None,
                },
            ],
        };
        assert!(matches!(
            trial_balance_json(&report, &metadata()),
            Err(ReportOutputError::AccountHierarchyCycle { .. })
        ));
    }

    #[test]
    fn complete_catalog_preserves_a_zero_omitted_parent_name() {
        let parent = account("sample-parent", "SAMPLE Parent", AccountType::Asset);
        let child = account("sample-child", "SAMPLE Child", AccountType::Asset)
            .with_hierarchy(None, Some(AccountId::new("sample-parent").unwrap()))
            .unwrap();
        let equity = account("sample-equity", "SAMPLE Equity", AccountType::Equity);
        let report = TrialBalance {
            as_of: 1,
            rows: vec![
                TrialBalanceRow {
                    account: child.clone(),
                    signed_minor_units: 100,
                    debit_minor_units: Some(100),
                    credit_minor_units: None,
                },
                TrialBalanceRow {
                    account: equity.clone(),
                    signed_minor_units: -100,
                    debit_minor_units: None,
                    credit_minor_units: Some(100),
                },
            ],
        };
        assert!(matches!(
            trial_balance_csv(&report, &metadata()),
            Err(ReportOutputError::MissingParentAccount { .. })
        ));
        let csv =
            trial_balance_csv_with_account_catalog(&report, &metadata(), &[parent, child, equity])
                .unwrap();
        assert!(csv.contains("SAMPLE Parent:SAMPLE Child"));
    }

    #[test]
    fn complete_catalog_applies_parent_number_to_child_display_output() {
        let parent = account("sample-parent", "SAMPLE Parent", AccountType::Asset)
            .with_hierarchy(Some("1000".into()), None)
            .unwrap();
        let child = account("sample-child", "SAMPLE Child", AccountType::Asset)
            .with_hierarchy(None, Some(parent.id.clone()))
            .unwrap();
        let equity = account("sample-equity", "SAMPLE Equity", AccountType::Equity);
        let report = TrialBalance {
            as_of: 1,
            rows: vec![
                TrialBalanceRow {
                    account: child,
                    signed_minor_units: 1,
                    debit_minor_units: Some(1),
                    credit_minor_units: None,
                },
                TrialBalanceRow {
                    account: equity,
                    signed_minor_units: -1,
                    debit_minor_units: None,
                    credit_minor_units: Some(1),
                },
            ],
        };
        let csv = trial_balance_csv_with_account_catalog(&report, &metadata(), &[parent]).unwrap();
        assert!(csv.contains("1000 · SAMPLE Parent:SAMPLE Child"));
        assert!(csv.contains(
            ",,SAMPLE Child,SAMPLE Parent:SAMPLE Child,1000 · SAMPLE Parent:SAMPLE Child,"
        ));
    }
    #[test]
    fn rejects_unbalanced_before_sqlite_write() {
        let (mut tb, _) = reports();
        tb.rows[0].signed_minor_units = -124;
        tb.rows[0].credit_minor_units = Some(124);
        let mut connection = Connection::open_in_memory().unwrap();
        assert!(matches!(
            write_sqlite(
                &mut connection,
                &metadata(),
                ReportBundle {
                    trial_balance: Some(&tb),
                    general_ledger: None
                }
            ),
            Err(ReportOutputError::UnbalancedTrialBalance { .. })
        ));
        assert!(connection.prepare("SELECT * FROM report_metadata").is_err());
    }
    #[test]
    fn rejects_internally_inconsistent_trial_balance_row() {
        let (mut tb, _) = reports();
        tb.rows[0].debit_minor_units = Some(125);
        let error = trial_balance_json(&tb, &metadata()).unwrap_err();
        assert!(matches!(
            error,
            ReportOutputError::InconsistentTrialBalanceRow { .. }
        ));
    }
    #[test]
    fn zero_trial_balance_rows_must_have_blank_display_columns() {
        let (mut tb, _) = reports();
        tb.rows[0].signed_minor_units = 0;
        tb.rows[0].credit_minor_units = Some(125);
        let error = trial_balance_csv(&tb, &metadata()).unwrap_err();
        assert!(matches!(
            error,
            ReportOutputError::InconsistentTrialBalanceRow { .. }
        ));
    }
    #[test]
    fn rejects_conflicting_account_metadata_across_reports() {
        let (tb, mut gl) = reports();
        gl.entries[0].account.name = "Conflicting name".into();
        let mut connection = Connection::open_in_memory().unwrap();
        let error = write_sqlite(
            &mut connection,
            &metadata(),
            ReportBundle {
                trial_balance: Some(&tb),
                general_ledger: Some(&gl),
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ReportOutputError::ConflictingAccountMetadata(_)
        ));
        assert!(connection.prepare("SELECT * FROM report_metadata").is_err());
    }

    #[test]
    fn rejects_bundle_when_trial_balance_does_not_match_general_ledger() {
        let (mut tb, gl) = reports();
        let cash = tb
            .rows
            .iter_mut()
            .find(|row| row.account.id.as_str() == "cash")
            .unwrap();
        cash.signed_minor_units = 124;
        cash.debit_minor_units = Some(124);
        let income = tb
            .rows
            .iter_mut()
            .find(|row| row.account.id.as_str() == "income")
            .unwrap();
        income.signed_minor_units = -124;
        income.credit_minor_units = Some(124);
        let mut connection = Connection::open_in_memory().unwrap();
        let error = write_sqlite(
            &mut connection,
            &metadata(),
            ReportBundle {
                trial_balance: Some(&tb),
                general_ledger: Some(&gl),
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ReportOutputError::TrialBalanceGeneralLedgerMismatch { .. }
        ));
        assert!(connection.prepare("SELECT * FROM report_metadata").is_err());
    }

    #[test]
    fn rejects_gl_entry_that_disagrees_with_its_posting_account() {
        let (_, mut gl) = reports();
        gl.entries[0].account = account("cash", "Cash, \"main\"", AccountType::Asset);
        let error = general_ledger_json(&gl, &metadata()).unwrap_err();
        assert!(matches!(
            error,
            ReportOutputError::PostingAccountMismatch { .. }
        ));
    }

    #[test]
    fn rejects_noncurrent_or_duplicate_provenance_gl_entries() {
        let (_, mut gl) = reports();
        gl.entries[0].posting.current_state = CurrentState::Deleted;
        assert!(matches!(
            general_ledger_csv(&gl, &metadata()),
            Err(ReportOutputError::NonCurrentPosting { .. })
        ));

        let (_, mut gl) = reports();
        gl.entries[1].posting.provenance.source_row =
            gl.entries[0].posting.provenance.source_row.clone();
        assert!(matches!(
            general_ledger_csv(&gl, &metadata()),
            Err(ReportOutputError::DuplicateSourceRow(_))
        ));
    }
    #[test]
    fn formats_i64_min_without_overflow() {
        assert_eq!(format_cents(i64::MIN), "-92233720368547758.08");
    }
}

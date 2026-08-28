//! Normalized, decoder-independent accounting types and report aggregation.
//!
//! This module deliberately knows nothing about QBW pages or record layouts.
//! Decoders must produce a complete [`Ledger`] before a report can be built;
//! this keeps a partly decoded file from being presented as an accounting
//! result.

use std::collections::{BTreeMap, BTreeSet};

/// A calendar date represented as a monotonic, timezone-free day number.
///
/// QBW decoders may use SA-days directly, or convert them before constructing
/// a posting.  Only ordering is relevant to the accounting operations here.
pub type AccountingDate = i32;

/// A stable normalized account identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AccountId(String);

impl AccountId {
    /// Creates an account identifier, rejecting an empty value.
    pub fn new(value: impl Into<String>) -> Result<Self, AccountingError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(AccountingError::EmptyIdentifier { kind: "account" });
        }
        Ok(Self(value))
    }

    /// Returns the decoder-supplied identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A stable normalized transaction identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TransactionId(String);

impl TransactionId {
    /// Creates a transaction identifier, rejecting an empty value.
    pub fn new(value: impl Into<String>) -> Result<Self, AccountingError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(AccountingError::EmptyIdentifier {
                kind: "transaction",
            });
        }
        Ok(Self(value))
    }

    /// Returns the decoder-supplied identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A stable normalized posting identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PostingId(String);

impl PostingId {
    /// Creates a posting identifier, rejecting an empty value.
    pub fn new(value: impl Into<String>) -> Result<Self, AccountingError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(AccountingError::EmptyIdentifier { kind: "posting" });
        }
        Ok(Self(value))
    }

    /// Returns the decoder-supplied identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A broad account classification retained from the source system.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccountType {
    /// Asset account.
    Asset,
    /// Liability account.
    Liability,
    /// Equity account.
    Equity,
    /// Income account.
    Income,
    /// Expense account.
    Expense,
    /// Cost of goods sold account.
    CostOfGoodsSold,
    /// Any source-specific account type not yet classified.
    Other(String),
}

/// The evidence-backed activity state of an account at extraction time.
///
/// `Unknown` is intentional: a decoded account row can be sufficient to
/// identify and classify an account without proving its current QuickBooks
/// active/inactive flag.  Consumers must not treat it as inactive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountActivity {
    /// The source explicitly identified the account as active.
    Active,
    /// The source explicitly identified the account as inactive.
    Inactive,
    /// The decoder did not establish the source activity state.
    Unknown,
}

impl AccountActivity {
    /// Returns the stable lower-case representation used by report outputs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Unknown => "unknown",
        }
    }

    /// Returns a legacy boolean only when the state was proven.
    pub fn known_bool(self) -> Option<bool> {
        match self {
            Self::Active => Some(true),
            Self::Inactive => Some(false),
            Self::Unknown => None,
        }
    }
}

/// The conventional balance side for a classified account type.
///
/// This is descriptive metadata for diagnostics and presentation; postings
/// always retain their actual debit/credit side.  A contra account may
/// therefore legitimately carry a balance opposite its normal side.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalBalance {
    /// Debit-normal categories, such as assets and expenses.
    Debit,
    /// Credit-normal categories, such as liabilities and income.
    Credit,
}

impl AccountType {
    /// Returns the conventional normal balance side when the type is known.
    /// Source-specific `Other` values are deliberately left unclassified
    /// rather than guessed from their display name.
    pub fn normal_balance(&self) -> Option<NormalBalance> {
        match self {
            Self::Asset | Self::Expense | Self::CostOfGoodsSold => Some(NormalBalance::Debit),
            Self::Liability | Self::Equity | Self::Income => Some(NormalBalance::Credit),
            Self::Other(_) => None,
        }
    }
}

/// One chart-of-accounts row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account {
    /// Stable account identifier.
    pub id: AccountId,
    /// Optional source account number, preserved without using it as identity.
    pub account_number: Option<String>,
    /// Human-readable account name.
    pub name: String,
    /// Optional parent account for a QuickBooks subaccount.
    pub parent_account_id: Option<AccountId>,
    /// Source account classification.
    pub account_type: AccountType,
    /// QuickBooks' source-granularity classification when the decoder has
    /// attested its materialized Account discriminator.
    ///
    /// `None` is deliberate for generic importers and for rows whose source
    /// discriminator was not proven. Consumers must not infer this from the
    /// broader [`Self::account_type`] grouping.
    pub quickbooks_classification: Option<crate::QuickBooksAccountClassification>,
    /// Legacy boolean account activity.
    ///
    /// New decoder code should use [`Self::activity`].  This value is retained
    /// for source compatibility and is `false` for an unknown state, so it
    /// must not be used to distinguish inactive from unknown.
    pub active: bool,
    /// Evidence-backed account activity at extraction time.
    pub activity: AccountActivity,
}

impl Account {
    /// Validates and creates an account.
    pub fn new(
        id: AccountId,
        name: impl Into<String>,
        account_type: AccountType,
        active: bool,
    ) -> Result<Self, AccountingError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(AccountingError::EmptyAccountName { account_id: id });
        }
        Ok(Self {
            id,
            account_number: None,
            name,
            parent_account_id: None,
            account_type,
            quickbooks_classification: None,
            active,
            activity: if active {
                AccountActivity::Active
            } else {
                AccountActivity::Inactive
            },
        })
    }

    /// Creates an account whose activity state was not established by the
    /// decoder.
    pub fn new_with_unknown_activity(
        id: AccountId,
        name: impl Into<String>,
        account_type: AccountType,
    ) -> Result<Self, AccountingError> {
        let mut account = Self::new(id, name, account_type, false)?;
        account.activity = AccountActivity::Unknown;
        Ok(account)
    }

    /// Replaces account activity with an explicitly evidenced state.
    ///
    /// The legacy [`Self::active`] field remains synchronized for known
    /// states and is false when the state is unknown.
    pub fn with_activity(mut self, activity: AccountActivity) -> Self {
        self.active = activity.known_bool().unwrap_or(false);
        self.activity = activity;
        self
    }

    /// Adds a source-granularity QuickBooks account classification.
    ///
    /// This is intentionally a decoder-attested field, not a name-based
    /// heuristic. Generic callers normally leave it as `None`.
    #[must_use]
    pub fn with_quickbooks_classification(
        mut self,
        classification: crate::QuickBooksAccountClassification,
    ) -> Self {
        self.quickbooks_classification = Some(classification);
        self
    }

    /// Adds optional source account-number and subaccount hierarchy metadata.
    ///
    /// Parent existence and loop checks require the entire chart, and are
    /// therefore performed by [`Ledger::new`].
    pub fn with_hierarchy(
        mut self,
        account_number: Option<String>,
        parent_account_id: Option<AccountId>,
    ) -> Result<Self, AccountingError> {
        if account_number
            .as_deref()
            .is_some_and(|number| number.trim().is_empty())
        {
            return Err(AccountingError::EmptyAccountNumber {
                account_id: self.id.clone(),
            });
        }
        self.account_number = account_number;
        self.parent_account_id = parent_account_id;
        Ok(self)
    }
}

/// The side of a double-entry posting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DebitCredit {
    /// Debit, normalized to a positive signed amount.
    Debit,
    /// Credit, normalized to a negative signed amount.
    Credit,
}

/// A non-zero amount and its debit/credit side, expressed in minor units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DebitCreditAmount {
    /// The debit or credit side.
    pub side: DebitCredit,
    /// Absolute amount in minor units (for example, cents).
    pub minor_units: i64,
}

impl DebitCreditAmount {
    /// Creates a non-zero debit or credit amount.
    pub fn new(side: DebitCredit, minor_units: i64) -> Result<Self, AccountingError> {
        if minor_units <= 0 {
            return Err(AccountingError::InvalidMinorUnits { minor_units });
        }
        Ok(Self { side, minor_units })
    }

    /// Converts to the module's signed convention: debit positive, credit negative.
    pub fn signed_minor_units(self) -> i64 {
        match self.side {
            DebitCredit::Debit => self.minor_units,
            DebitCredit::Credit => -self.minor_units,
        }
    }
}

/// Decoder evidence for a row used to construct a normalized posting.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PostingProvenance {
    /// A stable, file-local row locator chosen by the decoder.
    pub source_row: String,
    /// Optional physical page number.
    pub page_number: Option<u32>,
    /// Optional row/slot number within the page.
    pub slot_number: Option<u16>,
    /// Name and version of the decoder that interpreted the row.
    pub decoder: String,
}

impl PostingProvenance {
    /// Creates provenance and rejects empty row locators or decoder names.
    pub fn new(
        source_row: impl Into<String>,
        page_number: Option<u32>,
        slot_number: Option<u16>,
        decoder: impl Into<String>,
    ) -> Result<Self, AccountingError> {
        let source_row = source_row.into();
        let decoder = decoder.into();
        if source_row.trim().is_empty() || decoder.trim().is_empty() {
            return Err(AccountingError::InvalidProvenance);
        }
        Ok(Self {
            source_row,
            page_number,
            slot_number,
            decoder,
        })
    }
}

/// Current-state resolution for an on-disk posting candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CurrentState {
    /// This is the one current row for the logical posting.
    Current,
    /// An older row superseded by a newer row.
    Superseded,
    /// A deleted or voided row that must not enter the current ledger.
    Deleted,
    /// The decoder found conflicting candidates and cannot select one safely.
    Ambiguous,
}

/// One normalized double-entry posting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Posting {
    /// Logical transaction containing this posting.
    pub transaction_id: TransactionId,
    /// Unique posting identifier within the extracted ledger.
    pub id: PostingId,
    /// Account affected by this posting.
    pub account_id: AccountId,
    /// Effective accounting date.
    pub date: AccountingDate,
    /// Debit-positive, credit-negative amount in minor units.
    pub signed_minor_units: i64,
    /// Whether the candidate is current, obsolete, or unresolved.
    pub current_state: CurrentState,
    /// Physical/source evidence for auditing and duplicate detection.
    pub provenance: PostingProvenance,
    /// Optional source transaction type, retained for General Ledger display.
    pub transaction_type: Option<String>,
    /// Optional source memo, retained for General Ledger display.
    pub memo: Option<String>,
}

impl Posting {
    /// Creates a posting and applies debit/credit normalization.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transaction_id: TransactionId,
        id: PostingId,
        account_id: AccountId,
        date: AccountingDate,
        amount: DebitCreditAmount,
        current_state: CurrentState,
        provenance: PostingProvenance,
        transaction_type: Option<String>,
        memo: Option<String>,
    ) -> Self {
        Self {
            transaction_id,
            id,
            account_id,
            date,
            signed_minor_units: amount.signed_minor_units(),
            current_state,
            provenance,
            transaction_type,
            memo,
        }
    }

    /// Returns the display debit amount, if this is a debit posting.
    pub fn debit_minor_units(&self) -> Option<i64> {
        (self.signed_minor_units > 0).then_some(self.signed_minor_units)
    }

    /// Returns the display credit amount, if this is a credit posting.
    pub fn credit_minor_units(&self) -> Option<i64> {
        (self.signed_minor_units < 0).then_some(-self.signed_minor_units)
    }
}

/// Whether the decoder has enough supported data for financial reporting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerCompleteness {
    /// Every supported current row has been decoded and state-resolved.
    Complete,
    /// A required data set could not be decoded completely.
    Incomplete {
        /// Concise decoder-supplied reason.
        reason: String,
    },
    /// The file contains an accounting feature the decoder does not support.
    Unsupported {
        /// Concise decoder-supplied feature name or reason.
        feature: String,
    },
}

/// A validated normalized chart of accounts and posting stream.
#[derive(Clone, Debug)]
pub struct Ledger {
    accounts: BTreeMap<AccountId, Account>,
    postings: Vec<Posting>,
    completeness: LedgerCompleteness,
}

impl Ledger {
    /// Builds a ledger. Structural issues are rejected immediately; report-only
    /// conditions such as incompleteness are retained and rejected on report creation.
    pub fn new(
        accounts: impl IntoIterator<Item = Account>,
        postings: impl IntoIterator<Item = Posting>,
        completeness: LedgerCompleteness,
    ) -> Result<Self, AccountingError> {
        let mut account_map = BTreeMap::new();
        for account in accounts {
            if account_map
                .insert(account.id.clone(), account.clone())
                .is_some()
            {
                return Err(AccountingError::DuplicateAccount {
                    account_id: account.id,
                });
            }
        }
        validate_account_hierarchy(&account_map)?;

        let postings: Vec<_> = postings.into_iter().collect();
        let mut posting_ids = BTreeSet::new();
        let mut source_rows = BTreeSet::new();
        for posting in &postings {
            if posting.signed_minor_units == 0 {
                return Err(AccountingError::ZeroPosting {
                    posting_id: posting.id.clone(),
                });
            }
            if !account_map.contains_key(&posting.account_id) {
                return Err(AccountingError::UnknownAccount {
                    posting_id: posting.id.clone(),
                    account_id: posting.account_id.clone(),
                });
            }
            if !posting_ids.insert(posting.id.clone()) {
                return Err(AccountingError::DuplicatePosting {
                    posting_id: posting.id.clone(),
                });
            }
            if !source_rows.insert(posting.provenance.source_row.clone()) {
                return Err(AccountingError::DuplicateProvenance {
                    source_row: posting.provenance.source_row.clone(),
                });
            }
        }

        Ok(Self {
            accounts: account_map,
            postings,
            completeness,
        })
    }

    /// Returns the normalized accounts in stable identifier order.
    pub fn accounts(&self) -> impl Iterator<Item = &Account> {
        self.accounts.values()
    }

    /// Returns all candidates, including deleted and superseded rows.
    pub fn postings(&self) -> impl Iterator<Item = &Posting> {
        self.postings.iter()
    }

    /// Produces a deterministic current-state General Ledger through `as_of`.
    pub fn general_ledger_as_of(
        &self,
        as_of: AccountingDate,
    ) -> Result<GeneralLedger, AccountingError> {
        let entries = self.current_postings_as_of(as_of)?;
        self.assert_balanced_by_transaction(&entries)?;
        Ok(GeneralLedger { as_of, entries })
    }

    /// Produces a deterministic, cents-exact Trial Balance through `as_of`.
    pub fn trial_balance_as_of(
        &self,
        as_of: AccountingDate,
        options: TrialBalanceOptions,
    ) -> Result<TrialBalance, AccountingError> {
        let general_ledger = self.general_ledger_as_of(as_of)?;
        let mut balances: BTreeMap<AccountId, i128> = BTreeMap::new();
        for entry in &general_ledger.entries {
            *balances
                .entry(entry.posting.account_id.clone())
                .or_default() += i128::from(entry.posting.signed_minor_units);
        }

        self.trial_balance_from_balances(as_of, options, balances)
    }

    /// Produces an accrual Trial Balance using QuickBooks' fiscal-year
    /// presentation of profit-and-loss accounts.
    ///
    /// Income, expense, and cost-of-goods-sold balances dated before
    /// [`QuickBooksAccrualTrialBalancePolicy::fiscal_year_start`] are not
    /// displayed on their individual accounts.  Their net signed balance is
    /// instead added to the supplied Retained Earnings account.  Current
    /// fiscal-year profit-and-loss activity remains on its source accounts.
    /// Direct postings to Retained Earnings are always included, regardless
    /// of date.
    ///
    /// The fiscal-year boundary and the Retained Earnings account are company
    /// settings, not values that can be inferred safely from account names or
    /// transaction data.  A QBW decoder must therefore provide both from
    /// decoded company metadata (or an explicit, audited caller setting).
    /// This method deliberately does not invent a calendar-year default.
    pub fn quickbooks_accrual_trial_balance_as_of(
        &self,
        as_of: AccountingDate,
        options: TrialBalanceOptions,
        policy: &QuickBooksAccrualTrialBalancePolicy,
    ) -> Result<TrialBalance, AccountingError> {
        if policy.fiscal_year_start > as_of {
            return Err(AccountingError::FiscalYearStartAfterAsOf {
                fiscal_year_start: policy.fiscal_year_start,
                as_of,
            });
        }
        let retained_earnings = self
            .accounts
            .get(&policy.retained_earnings_account_id)
            .ok_or_else(|| AccountingError::UnknownRetainedEarningsAccount {
                account_id: policy.retained_earnings_account_id.clone(),
            })?;
        if retained_earnings.account_type != AccountType::Equity {
            return Err(AccountingError::RetainedEarningsAccountNotEquity {
                account_id: retained_earnings.id.clone(),
            });
        }

        let general_ledger = self.general_ledger_as_of(as_of)?;
        let mut balances: BTreeMap<AccountId, i128> = BTreeMap::new();
        for entry in &general_ledger.entries {
            let amount = i128::from(entry.posting.signed_minor_units);
            if entry.posting.date < policy.fiscal_year_start
                && entry.account.account_type.is_profit_and_loss()
            {
                // Debit-positive / credit-negative convention means the
                // historical net income amount is already in the direction
                // required to preserve the Trial Balance's zero net total.
                *balances
                    .entry(policy.retained_earnings_account_id.clone())
                    .or_default() += amount;
            } else {
                *balances
                    .entry(entry.posting.account_id.clone())
                    .or_default() += amount;
            }
        }

        self.trial_balance_from_balances(as_of, options, balances)
    }

    fn trial_balance_from_balances(
        &self,
        as_of: AccountingDate,
        options: TrialBalanceOptions,
        balances: BTreeMap<AccountId, i128>,
    ) -> Result<TrialBalance, AccountingError> {
        let mut rows = Vec::new();
        for account in self.accounts.values() {
            let signed = *balances.get(&account.id).unwrap_or(&0);
            if signed == 0 && !options.include_zero_balance_accounts {
                continue;
            }
            let signed_minor_units =
                i64::try_from(signed).map_err(|_| AccountingError::BalanceOverflow {
                    account_id: account.id.clone(),
                })?;
            rows.push(TrialBalanceRow::from_signed(
                account.clone(),
                signed_minor_units,
            )?);
        }

        let net: i128 = rows
            .iter()
            .map(|row| i128::from(row.signed_minor_units))
            .sum();
        if net != 0 {
            return Err(AccountingError::UnbalancedLedger {
                net_minor_units: net,
            });
        }
        Ok(TrialBalance { as_of, rows })
    }

    fn current_postings_as_of(
        &self,
        as_of: AccountingDate,
    ) -> Result<Vec<GeneralLedgerEntry>, AccountingError> {
        match &self.completeness {
            LedgerCompleteness::Complete => {}
            LedgerCompleteness::Incomplete { reason } => {
                return Err(AccountingError::IncompleteData {
                    reason: reason.clone(),
                });
            }
            LedgerCompleteness::Unsupported { feature } => {
                return Err(AccountingError::UnsupportedData {
                    feature: feature.clone(),
                });
            }
        }

        let mut entries = Vec::new();
        for posting in &self.postings {
            match posting.current_state {
                CurrentState::Current if posting.date <= as_of => {
                    entries.push(GeneralLedgerEntry {
                        account: self.accounts[&posting.account_id].clone(),
                        posting: posting.clone(),
                    })
                }
                // QuickBooks reports are date-bounded.  An unresolved row whose
                // effective date is after the requested as-of date cannot change
                // that historical balance; it remains excluded.  An unresolved
                // row on or before the cutoff does block reporting because it can.
                CurrentState::Ambiguous if posting.date <= as_of => {
                    return Err(AccountingError::AmbiguousCurrentState {
                        posting_id: posting.id.clone(),
                    });
                }
                CurrentState::Current
                | CurrentState::Superseded
                | CurrentState::Deleted
                | CurrentState::Ambiguous => {}
            }
        }
        entries.sort_by(|left, right| {
            (
                left.posting.date,
                &left.account.id,
                &left.posting.transaction_id,
                &left.posting.id,
            )
                .cmp(&(
                    right.posting.date,
                    &right.account.id,
                    &right.posting.transaction_id,
                    &right.posting.id,
                ))
        });
        Ok(entries)
    }

    fn assert_balanced_by_transaction(
        &self,
        entries: &[GeneralLedgerEntry],
    ) -> Result<(), AccountingError> {
        let mut totals: BTreeMap<TransactionId, i128> = BTreeMap::new();
        for entry in entries {
            *totals
                .entry(entry.posting.transaction_id.clone())
                .or_default() += i128::from(entry.posting.signed_minor_units);
        }
        for (transaction_id, net_minor_units) in totals {
            if net_minor_units != 0 {
                return Err(AccountingError::UnbalancedTransaction {
                    transaction_id,
                    net_minor_units,
                });
            }
        }
        Ok(())
    }
}

impl AccountType {
    fn is_profit_and_loss(&self) -> bool {
        matches!(self, Self::Income | Self::Expense | Self::CostOfGoodsSold)
    }
}

fn validate_account_hierarchy(
    accounts: &BTreeMap<AccountId, Account>,
) -> Result<(), AccountingError> {
    for account in accounts.values() {
        let Some(parent_id) = &account.parent_account_id else {
            continue;
        };
        if parent_id == &account.id {
            return Err(AccountingError::SelfParentAccount {
                account_id: account.id.clone(),
            });
        }
        if !accounts.contains_key(parent_id) {
            return Err(AccountingError::UnknownParentAccount {
                account_id: account.id.clone(),
                parent_account_id: parent_id.clone(),
            });
        }

        let mut visited = BTreeSet::new();
        let mut cursor = account.id.clone();
        while let Some(next_parent) = &accounts[&cursor].parent_account_id {
            if !visited.insert(cursor.clone()) || next_parent == &account.id {
                return Err(AccountingError::AccountHierarchyCycle {
                    account_id: account.id.clone(),
                });
            }
            cursor = next_parent.clone();
        }
    }
    Ok(())
}

/// A General Ledger report, ordered by date, account, transaction, then posting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneralLedger {
    /// Inclusive report end date.
    pub as_of: AccountingDate,
    /// Current, dated posting entries in deterministic order.
    pub entries: Vec<GeneralLedgerEntry>,
}

/// A General Ledger entry paired with its normalized account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneralLedgerEntry {
    /// Account affected by the posting.
    pub account: Account,
    /// Source posting and provenance.
    pub posting: Posting,
}

/// Options controlling Trial Balance presentation, not accounting math.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrialBalanceOptions {
    /// Include accounts whose signed balance is zero.
    pub include_zero_balance_accounts: bool,
}

/// Required company-level inputs for a QuickBooks-style accrual Trial Balance.
///
/// `fiscal_year_start` is the first day of the fiscal year containing the
/// requested report `as_of` date, expressed in [`AccountingDate`] units.  It
/// is intentionally an exact boundary rather than a guessed month/day rule:
/// the normalized accounting layer does not own company-preference decoding or
/// calendar conversion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuickBooksAccrualTrialBalancePolicy {
    /// First day of the fiscal year containing the report date.
    pub fiscal_year_start: AccountingDate,
    /// The decoded, stable identity of the company's Retained Earnings account.
    pub retained_earnings_account_id: AccountId,
}

impl QuickBooksAccrualTrialBalancePolicy {
    /// Creates a policy from explicit, audited company metadata.
    pub const fn new(
        fiscal_year_start: AccountingDate,
        retained_earnings_account_id: AccountId,
    ) -> Self {
        Self {
            fiscal_year_start,
            retained_earnings_account_id,
        }
    }
}

/// A Trial Balance report with debit-positive, credit-negative signed totals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrialBalance {
    /// Inclusive report end date.
    pub as_of: AccountingDate,
    /// Account rows in stable account identifier order.
    pub rows: Vec<TrialBalanceRow>,
}

impl TrialBalance {
    /// Returns the exact sum of all debit columns in minor units.
    ///
    /// Report totals may exceed the range of one account balance, so this is
    /// deliberately wider than the per-row `i64` representation.
    pub fn total_debit_minor_units(&self) -> i128 {
        self.rows
            .iter()
            .filter_map(|row| row.debit_minor_units)
            .map(i128::from)
            .sum()
    }

    /// Returns the exact sum of all credit columns in minor units.
    ///
    /// Report totals may exceed the range of one account balance, so this is
    /// deliberately wider than the per-row `i64` representation.
    pub fn total_credit_minor_units(&self) -> i128 {
        self.rows
            .iter()
            .filter_map(|row| row.credit_minor_units)
            .map(i128::from)
            .sum()
    }
}

/// One Trial Balance account row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrialBalanceRow {
    /// Source account information.
    pub account: Account,
    /// Debit-positive, credit-negative account balance.
    pub signed_minor_units: i64,
    /// Debit display amount, present only for debit balances.
    pub debit_minor_units: Option<i64>,
    /// Credit display amount, present only for credit balances.
    pub credit_minor_units: Option<i64>,
}

impl TrialBalanceRow {
    fn from_signed(account: Account, signed_minor_units: i64) -> Result<Self, AccountingError> {
        // `i64::MIN` is a valid signed integer but its absolute credit display
        // amount is not representable in this API's i64 minor-unit column.
        // Refuse it rather than wrapping to a negative "credit" value.
        let credit_minor_units = if signed_minor_units < 0 {
            Some(signed_minor_units.checked_neg().ok_or_else(|| {
                AccountingError::BalanceOverflow {
                    account_id: account.id.clone(),
                }
            })?)
        } else {
            None
        };
        Ok(Self {
            account,
            signed_minor_units,
            debit_minor_units: (signed_minor_units > 0).then_some(signed_minor_units),
            credit_minor_units,
        })
    }
}

/// Errors that prevent a financial report from being emitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccountingError {
    /// An identifier required for deterministic reconciliation was empty.
    EmptyIdentifier {
        /// Identifier category.
        kind: &'static str,
    },
    /// An account name was empty.
    EmptyAccountName {
        /// Account with the invalid name.
        account_id: AccountId,
    },
    /// An explicitly supplied account number was empty.
    EmptyAccountNumber {
        /// Account with the invalid number.
        account_id: AccountId,
    },
    /// A subaccount points to an account absent from the extracted chart.
    UnknownParentAccount {
        /// Child account.
        account_id: AccountId,
        /// Missing parent account.
        parent_account_id: AccountId,
    },
    /// An account was declared as its own parent.
    SelfParentAccount {
        /// Self-parenting account.
        account_id: AccountId,
    },
    /// Parent links form a cycle, which cannot be represented as a chart hierarchy.
    AccountHierarchyCycle {
        /// Account from whose chain the cycle was observed.
        account_id: AccountId,
    },
    /// A debit or credit amount was zero or negative before normalization.
    InvalidMinorUnits {
        /// Invalid absolute amount.
        minor_units: i64,
    },
    /// Decoder evidence was not auditable.
    InvalidProvenance,
    /// More than one chart account had the same identifier.
    DuplicateAccount {
        /// Repeated account identifier.
        account_id: AccountId,
    },
    /// A posting refers to no extracted account.
    UnknownAccount {
        /// Posting with the bad foreign key.
        posting_id: PostingId,
        /// Unresolved account identifier.
        account_id: AccountId,
    },
    /// More than one posting had the same logical identifier.
    DuplicatePosting {
        /// Repeated posting identifier.
        posting_id: PostingId,
    },
    /// More than one posting used the same physical source row.
    DuplicateProvenance {
        /// Repeated source locator.
        source_row: String,
    },
    /// A normalized posting had no debit or credit value.
    ZeroPosting {
        /// Posting with a zero amount.
        posting_id: PostingId,
    },
    /// Current-state resolution could not select a row safely.
    AmbiguousCurrentState {
        /// Posting whose state was ambiguous.
        posting_id: PostingId,
    },
    /// Required data was not fully decoded.
    IncompleteData {
        /// Decoder-supplied reason.
        reason: String,
    },
    /// A source feature has no supported decoder.
    UnsupportedData {
        /// Decoder-supplied feature.
        feature: String,
    },
    /// A transaction's included postings did not net to zero.
    UnbalancedTransaction {
        /// Unbalanced transaction.
        transaction_id: TransactionId,
        /// Debit-positive net in minor units.
        net_minor_units: i128,
    },
    /// Account aggregation overflowed a signed 64-bit minor-unit balance.
    BalanceOverflow {
        /// Account whose balance overflowed.
        account_id: AccountId,
    },
    /// The report-level debit and credit totals did not agree.
    UnbalancedLedger {
        /// Debit-positive net in minor units.
        net_minor_units: i128,
    },
    /// The supplied fiscal-year boundary cannot describe a report before it.
    FiscalYearStartAfterAsOf {
        /// First day of the supplied fiscal year.
        fiscal_year_start: AccountingDate,
        /// Requested inclusive report date.
        as_of: AccountingDate,
    },
    /// The policy did not identify an account in the decoded chart.
    UnknownRetainedEarningsAccount {
        /// Unresolved account identity.
        account_id: AccountId,
    },
    /// The supplied Retained Earnings account was not decoded as equity.
    RetainedEarningsAccountNotEquity {
        /// Incorrectly classified account.
        account_id: AccountId,
    },
}

impl std::fmt::Display for AccountingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AccountingError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::QuickBooksAccountClassification;

    fn id(value: &str) -> AccountId {
        AccountId::new(value).unwrap()
    }
    fn tx(value: &str) -> TransactionId {
        TransactionId::new(value).unwrap()
    }
    fn posting_id(value: &str) -> PostingId {
        PostingId::new(value).unwrap()
    }
    fn account(value: &str, name: &str) -> Account {
        Account::new(id(value), name, AccountType::Asset, true).unwrap()
    }

    #[test]
    fn generic_accounts_have_no_source_specific_quickbooks_classification() {
        let account = account("SAMPLE-ASSET", "SAMPLE Asset");
        assert_eq!(account.quickbooks_classification, None);
        assert_eq!(
            account
                .with_quickbooks_classification(QuickBooksAccountClassification::AccountsPayable,)
                .quickbooks_classification,
            Some(QuickBooksAccountClassification::AccountsPayable)
        );
    }
    fn typed_account(value: &str, account_type: AccountType, active: bool) -> Account {
        Account::new(id(value), value, account_type, active).unwrap()
    }
    fn provenance(value: &str) -> PostingProvenance {
        PostingProvenance::new(value, Some(1), Some(2), "synthetic-v1").unwrap()
    }
    fn posting(
        transaction: &str,
        posting: &str,
        account: &str,
        date: AccountingDate,
        side: DebitCredit,
        amount: i64,
        state: CurrentState,
    ) -> Posting {
        Posting::new(
            tx(transaction),
            posting_id(posting),
            id(account),
            date,
            DebitCreditAmount::new(side, amount).unwrap(),
            state,
            provenance(posting),
            None,
            None,
        )
    }

    #[test]
    fn debit_credit_normalization_is_exact_in_minor_units() {
        assert_eq!(
            DebitCreditAmount::new(DebitCredit::Debit, 125)
                .unwrap()
                .signed_minor_units(),
            125
        );
        assert_eq!(
            DebitCreditAmount::new(DebitCredit::Credit, 125)
                .unwrap()
                .signed_minor_units(),
            -125
        );
        assert_eq!(
            DebitCreditAmount::new(DebitCredit::Debit, 0),
            Err(AccountingError::InvalidMinorUnits { minor_units: 0 })
        );
    }

    #[test]
    fn account_categories_expose_normal_balance_without_reorienting_postings() {
        assert_eq!(
            AccountType::Asset.normal_balance(),
            Some(NormalBalance::Debit)
        );
        assert_eq!(
            AccountType::Expense.normal_balance(),
            Some(NormalBalance::Debit)
        );
        assert_eq!(
            AccountType::CostOfGoodsSold.normal_balance(),
            Some(NormalBalance::Debit)
        );
        assert_eq!(
            AccountType::Liability.normal_balance(),
            Some(NormalBalance::Credit)
        );
        assert_eq!(
            AccountType::Equity.normal_balance(),
            Some(NormalBalance::Credit)
        );
        assert_eq!(
            AccountType::Income.normal_balance(),
            Some(NormalBalance::Credit)
        );
        assert_eq!(
            AccountType::Other("unclassified".into()).normal_balance(),
            None
        );
    }

    #[test]
    fn unknown_account_activity_is_explicit_and_does_not_claim_inactive() {
        let account = Account::new_with_unknown_activity(
            id("unproven"),
            "Unproven activity",
            AccountType::Asset,
        )
        .unwrap();
        assert_eq!(account.activity, AccountActivity::Unknown);
        assert_eq!(account.activity.known_bool(), None);
        // Retained only for old callers; output code must consult `activity`.
        assert!(!account.active);

        let inactive = account.clone().with_activity(AccountActivity::Inactive);
        assert_eq!(inactive.activity.known_bool(), Some(false));
        let active = account.with_activity(AccountActivity::Active);
        assert_eq!(active.activity.known_bool(), Some(true));
        assert!(active.active);
    }

    #[test]
    fn trial_balance_is_exact_and_orders_accounts_by_identifier() {
        let ledger = Ledger::new(
            [
                account("cash", "Cash"),
                account("income", "Income"),
                account("unused", "Unused"),
            ],
            [
                posting(
                    "t1",
                    "p2",
                    "income",
                    10,
                    DebitCredit::Credit,
                    12_345,
                    CurrentState::Current,
                ),
                posting(
                    "t1",
                    "p1",
                    "cash",
                    10,
                    DebitCredit::Debit,
                    12_345,
                    CurrentState::Current,
                ),
            ],
            LedgerCompleteness::Complete,
        )
        .unwrap();
        let report = ledger
            .trial_balance_as_of(10, TrialBalanceOptions::default())
            .unwrap();
        assert_eq!(
            report
                .rows
                .iter()
                .map(|r| r.account.id.as_str())
                .collect::<Vec<_>>(),
            ["cash", "income"]
        );
        assert_eq!(report.rows[0].debit_minor_units, Some(12_345));
        assert_eq!(report.rows[1].credit_minor_units, Some(12_345));
        assert_eq!(
            report.total_debit_minor_units(),
            report.total_credit_minor_units()
        );
    }

    #[test]
    fn as_of_date_is_inclusive_and_general_ledger_is_deterministic() {
        let ledger = Ledger::new(
            [account("a", "A"), account("b", "B")],
            [
                posting(
                    "later",
                    "later-credit",
                    "b",
                    11,
                    DebitCredit::Credit,
                    100,
                    CurrentState::Current,
                ),
                posting(
                    "boundary",
                    "boundary-debit",
                    "a",
                    10,
                    DebitCredit::Debit,
                    100,
                    CurrentState::Current,
                ),
                posting(
                    "later",
                    "later-debit",
                    "a",
                    11,
                    DebitCredit::Debit,
                    100,
                    CurrentState::Current,
                ),
                posting(
                    "boundary",
                    "boundary-credit",
                    "b",
                    10,
                    DebitCredit::Credit,
                    100,
                    CurrentState::Current,
                ),
            ],
            LedgerCompleteness::Complete,
        )
        .unwrap();
        let gl = ledger.general_ledger_as_of(10).unwrap();
        assert_eq!(gl.entries.len(), 2);
        assert!(gl.entries.iter().all(|e| e.posting.date == 10));
        assert_eq!(gl.entries[0].account.id.as_str(), "a");
        assert_eq!(gl.entries[1].account.id.as_str(), "b");
    }

    #[test]
    fn unbalanced_transaction_fails_loudly_even_when_other_transactions_cancel_it() {
        let ledger = Ledger::new(
            [account("a", "A"), account("b", "B")],
            [
                posting(
                    "bad-debit",
                    "p1",
                    "a",
                    1,
                    DebitCredit::Debit,
                    100,
                    CurrentState::Current,
                ),
                posting(
                    "bad-credit",
                    "p2",
                    "b",
                    1,
                    DebitCredit::Credit,
                    100,
                    CurrentState::Current,
                ),
            ],
            LedgerCompleteness::Complete,
        )
        .unwrap();
        assert!(
            matches!(ledger.trial_balance_as_of(1, TrialBalanceOptions::default()),
            Err(AccountingError::UnbalancedTransaction { transaction_id, net_minor_units: -100 })
            if transaction_id.as_str() == "bad-credit")
        );
    }

    #[test]
    fn non_current_rows_are_excluded_but_ambiguous_rows_block_reporting() {
        let accounts = [account("a", "A"), account("b", "B")];
        let ledger = Ledger::new(
            accounts.clone(),
            [
                posting(
                    "t",
                    "p1",
                    "a",
                    1,
                    DebitCredit::Debit,
                    50,
                    CurrentState::Current,
                ),
                posting(
                    "t",
                    "p2",
                    "b",
                    1,
                    DebitCredit::Credit,
                    50,
                    CurrentState::Current,
                ),
                posting(
                    "old",
                    "p3",
                    "a",
                    1,
                    DebitCredit::Debit,
                    99,
                    CurrentState::Deleted,
                ),
            ],
            LedgerCompleteness::Complete,
        )
        .unwrap();
        assert_eq!(ledger.general_ledger_as_of(1).unwrap().entries.len(), 2);
        let ambiguous = Ledger::new(
            accounts,
            [
                posting(
                    "t",
                    "p1",
                    "a",
                    1,
                    DebitCredit::Debit,
                    50,
                    CurrentState::Current,
                ),
                posting(
                    "t",
                    "p2",
                    "b",
                    1,
                    DebitCredit::Credit,
                    50,
                    CurrentState::Current,
                ),
                posting(
                    "u",
                    "p3",
                    "a",
                    2,
                    DebitCredit::Debit,
                    1,
                    CurrentState::Ambiguous,
                ),
            ],
            LedgerCompleteness::Complete,
        )
        .unwrap();
        // A future unresolved candidate cannot affect a historical report.
        assert_eq!(ambiguous.general_ledger_as_of(1).unwrap().entries.len(), 2);
        // It must block once it falls within the requested reporting window.
        assert!(matches!(
            ambiguous.general_ledger_as_of(2),
            Err(AccountingError::AmbiguousCurrentState { .. })
        ));
    }

    #[test]
    fn account_hierarchy_preserves_optional_metadata_and_rejects_bad_links() {
        let parent = account("parent", "Parent")
            .with_hierarchy(Some("100".into()), None)
            .unwrap();
        let child = account("child", "Child")
            .with_hierarchy(Some("110".into()), Some(id("parent")))
            .unwrap();
        let ledger = Ledger::new(
            [parent.clone(), child.clone()],
            [],
            LedgerCompleteness::Complete,
        )
        .unwrap();
        let accounts = ledger.accounts().collect::<Vec<_>>();
        assert_eq!(accounts[0].account_number.as_deref(), Some("110"));
        assert_eq!(
            accounts[0].parent_account_id.as_ref().unwrap().as_str(),
            "parent"
        );

        let missing_parent = account("orphan", "Orphan")
            .with_hierarchy(None, Some(id("missing")))
            .unwrap();
        assert!(matches!(
            Ledger::new([missing_parent], [], LedgerCompleteness::Complete),
            Err(AccountingError::UnknownParentAccount { .. })
        ));

        let self_parent = account("self", "Self")
            .with_hierarchy(None, Some(id("self")))
            .unwrap();
        assert!(matches!(
            Ledger::new([self_parent], [], LedgerCompleteness::Complete),
            Err(AccountingError::SelfParentAccount { .. })
        ));

        let first = account("first", "First")
            .with_hierarchy(None, Some(id("second")))
            .unwrap();
        let second = account("second", "Second")
            .with_hierarchy(None, Some(id("first")))
            .unwrap();
        assert!(matches!(
            Ledger::new([first, second], [], LedgerCompleteness::Complete),
            Err(AccountingError::AccountHierarchyCycle { .. })
        ));
    }

    #[test]
    fn incomplete_and_unsupported_ledgers_cannot_report() {
        let accounts = [account("a", "A"), account("b", "B")];
        let postings = [
            posting(
                "t",
                "p1",
                "a",
                1,
                DebitCredit::Debit,
                1,
                CurrentState::Current,
            ),
            posting(
                "t",
                "p2",
                "b",
                1,
                DebitCredit::Credit,
                1,
                CurrentState::Current,
            ),
        ];
        let incomplete = Ledger::new(
            accounts.clone(),
            postings.clone(),
            LedgerCompleteness::Incomplete {
                reason: "missing Bill rows".into(),
            },
        )
        .unwrap();
        assert!(matches!(
            incomplete.general_ledger_as_of(1),
            Err(AccountingError::IncompleteData { .. })
        ));
        let unsupported = Ledger::new(
            accounts,
            postings,
            LedgerCompleteness::Unsupported {
                feature: "inventory assemblies".into(),
            },
        )
        .unwrap();
        assert!(matches!(
            unsupported.general_ledger_as_of(1),
            Err(AccountingError::UnsupportedData { .. })
        ));
    }

    #[test]
    fn duplicate_logical_or_physical_rows_are_rejected() {
        let accounts = [account("a", "A"), account("b", "B")];
        let duplicate_id = Ledger::new(
            accounts.clone(),
            [
                posting(
                    "t",
                    "same",
                    "a",
                    1,
                    DebitCredit::Debit,
                    1,
                    CurrentState::Current,
                ),
                posting(
                    "t",
                    "same",
                    "b",
                    1,
                    DebitCredit::Credit,
                    1,
                    CurrentState::Current,
                ),
            ],
            LedgerCompleteness::Complete,
        );
        assert!(matches!(
            duplicate_id,
            Err(AccountingError::DuplicatePosting { .. })
        ));
        let first = posting(
            "t",
            "p1",
            "a",
            1,
            DebitCredit::Debit,
            1,
            CurrentState::Current,
        );
        let mut second = posting(
            "t",
            "p2",
            "b",
            1,
            DebitCredit::Credit,
            1,
            CurrentState::Current,
        );
        second.provenance = first.provenance.clone();
        let duplicate_source = Ledger::new(accounts, [first, second], LedgerCompleteness::Complete);
        assert!(matches!(
            duplicate_source,
            Err(AccountingError::DuplicateProvenance { .. })
        ));
    }

    #[test]
    fn zero_accounts_are_optional_in_trial_balance() {
        let ledger = Ledger::new(
            [
                account("a", "A"),
                account("b", "B"),
                account("zero", "Zero"),
            ],
            [
                posting(
                    "t",
                    "p1",
                    "a",
                    1,
                    DebitCredit::Debit,
                    1,
                    CurrentState::Current,
                ),
                posting(
                    "t",
                    "p2",
                    "b",
                    1,
                    DebitCredit::Credit,
                    1,
                    CurrentState::Current,
                ),
            ],
            LedgerCompleteness::Complete,
        )
        .unwrap();
        let report = ledger
            .trial_balance_as_of(
                1,
                TrialBalanceOptions {
                    include_zero_balance_accounts: true,
                },
            )
            .unwrap();
        assert_eq!(report.rows.len(), 3);
        assert_eq!(report.rows[2].account.id.as_str(), "zero");
        assert_eq!(report.rows[2].debit_minor_units, None);
        assert_eq!(report.rows[2].credit_minor_units, None);
    }

    #[test]
    fn quickbooks_accrual_trial_balance_rolls_prior_profit_and_loss_into_retained_earnings() {
        let ledger = Ledger::new(
            [
                typed_account("cash", AccountType::Asset, true),
                typed_account("inventory", AccountType::Asset, true),
                typed_account("payable", AccountType::Liability, true),
                typed_account("retained", AccountType::Equity, true),
                typed_account("income", AccountType::Income, true),
                typed_account("expense", AccountType::Expense, true),
                typed_account("cogs", AccountType::CostOfGoodsSold, true),
            ],
            [
                posting(
                    "prior-revenue",
                    "p1",
                    "cash",
                    99,
                    DebitCredit::Debit,
                    1_000,
                    CurrentState::Current,
                ),
                posting(
                    "prior-revenue",
                    "p2",
                    "income",
                    99,
                    DebitCredit::Credit,
                    1_000,
                    CurrentState::Current,
                ),
                posting(
                    "prior-expense",
                    "p3",
                    "expense",
                    99,
                    DebitCredit::Debit,
                    300,
                    CurrentState::Current,
                ),
                posting(
                    "prior-expense",
                    "p4",
                    "payable",
                    99,
                    DebitCredit::Credit,
                    300,
                    CurrentState::Current,
                ),
                posting(
                    "prior-cogs",
                    "p5",
                    "cogs",
                    99,
                    DebitCredit::Debit,
                    100,
                    CurrentState::Current,
                ),
                posting(
                    "prior-cogs",
                    "p6",
                    "inventory",
                    99,
                    DebitCredit::Credit,
                    100,
                    CurrentState::Current,
                ),
                // This direct equity entry must remain in Retained Earnings in
                // addition to the calculated prior-year net income transfer.
                posting(
                    "direct-equity",
                    "p7",
                    "cash",
                    99,
                    DebitCredit::Debit,
                    500,
                    CurrentState::Current,
                ),
                posting(
                    "direct-equity",
                    "p8",
                    "retained",
                    99,
                    DebitCredit::Credit,
                    500,
                    CurrentState::Current,
                ),
                posting(
                    "current-revenue",
                    "p9",
                    "cash",
                    100,
                    DebitCredit::Debit,
                    200,
                    CurrentState::Current,
                ),
                posting(
                    "current-revenue",
                    "p10",
                    "income",
                    100,
                    DebitCredit::Credit,
                    200,
                    CurrentState::Current,
                ),
                posting(
                    "current-expense",
                    "p11",
                    "expense",
                    101,
                    DebitCredit::Debit,
                    50,
                    CurrentState::Current,
                ),
                posting(
                    "current-expense",
                    "p12",
                    "cash",
                    101,
                    DebitCredit::Credit,
                    50,
                    CurrentState::Current,
                ),
            ],
            LedgerCompleteness::Complete,
        )
        .unwrap();
        let policy = QuickBooksAccrualTrialBalancePolicy::new(100, id("retained"));

        let report = ledger
            .quickbooks_accrual_trial_balance_as_of(101, TrialBalanceOptions::default(), &policy)
            .unwrap();
        let balances = report
            .rows
            .iter()
            .map(|row| (row.account.id.as_str(), row.signed_minor_units))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(balances.get("cash"), Some(&1_650));
        assert_eq!(balances.get("inventory"), Some(&-100));
        assert_eq!(balances.get("payable"), Some(&-300));
        // -500 direct equity, -1_000 prior income, +300 prior expense,
        // and +100 prior cost of goods sold.
        assert_eq!(balances.get("retained"), Some(&-1_100));
        assert_eq!(balances.get("income"), Some(&-200));
        assert_eq!(balances.get("expense"), Some(&50));
        assert!(!balances.contains_key("cogs"));
        assert_eq!(
            report.total_debit_minor_units(),
            report.total_credit_minor_units()
        );
    }

    #[test]
    fn quickbooks_accrual_trial_balance_zero_and_inactive_accounts_are_presentation_only() {
        let ledger = Ledger::new(
            [
                typed_account("cash", AccountType::Asset, true),
                typed_account("retained", AccountType::Equity, true),
                typed_account("inactive-zero", AccountType::Asset, false),
            ],
            [
                posting(
                    "t",
                    "p1",
                    "cash",
                    100,
                    DebitCredit::Debit,
                    1,
                    CurrentState::Current,
                ),
                posting(
                    "t",
                    "p2",
                    "retained",
                    100,
                    DebitCredit::Credit,
                    1,
                    CurrentState::Current,
                ),
            ],
            LedgerCompleteness::Complete,
        )
        .unwrap();
        let policy = QuickBooksAccrualTrialBalancePolicy::new(100, id("retained"));

        let hidden = ledger
            .quickbooks_accrual_trial_balance_as_of(100, TrialBalanceOptions::default(), &policy)
            .unwrap();
        assert!(
            hidden
                .rows
                .iter()
                .all(|row| row.account.id.as_str() != "inactive-zero")
        );

        let shown = ledger
            .quickbooks_accrual_trial_balance_as_of(
                100,
                TrialBalanceOptions {
                    include_zero_balance_accounts: true,
                },
                &policy,
            )
            .unwrap();
        let inactive = shown
            .rows
            .iter()
            .find(|row| row.account.id.as_str() == "inactive-zero")
            .unwrap();
        assert!(!inactive.account.active);
        assert_eq!(inactive.signed_minor_units, 0);
    }

    #[test]
    fn quickbooks_accrual_trial_balance_requires_explicit_validated_company_metadata() {
        let ledger = Ledger::new(
            [account("cash", "Cash"), account("not-equity", "Not Equity")],
            [
                posting(
                    "t",
                    "p1",
                    "cash",
                    1,
                    DebitCredit::Debit,
                    1,
                    CurrentState::Current,
                ),
                posting(
                    "t",
                    "p2",
                    "not-equity",
                    1,
                    DebitCredit::Credit,
                    1,
                    CurrentState::Current,
                ),
            ],
            LedgerCompleteness::Complete,
        )
        .unwrap();

        assert!(matches!(
            ledger.quickbooks_accrual_trial_balance_as_of(
                1,
                TrialBalanceOptions::default(),
                &QuickBooksAccrualTrialBalancePolicy::new(1, id("missing")),
            ),
            Err(AccountingError::UnknownRetainedEarningsAccount { .. })
        ));
        assert!(matches!(
            ledger.quickbooks_accrual_trial_balance_as_of(
                1,
                TrialBalanceOptions::default(),
                &QuickBooksAccrualTrialBalancePolicy::new(1, id("not-equity")),
            ),
            Err(AccountingError::RetainedEarningsAccountNotEquity { .. })
        ));
        assert!(matches!(
            ledger.quickbooks_accrual_trial_balance_as_of(
                1,
                TrialBalanceOptions::default(),
                &QuickBooksAccrualTrialBalancePolicy::new(2, id("not-equity")),
            ),
            Err(AccountingError::FiscalYearStartAfterAsOf { .. })
        ));
    }
}

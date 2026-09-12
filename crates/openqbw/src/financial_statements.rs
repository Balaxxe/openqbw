//! Accrual statements derived exclusively from the validated accounting ledger.
//!
//! Account rows contain direct account activity, never descendant rollups.
//! Subtotals and calculated rows are explicitly separate from source accounts.
//! Amounts use each statement section's presentation sign, while account rows
//! also retain the ledger's debit-positive signed amount for reconciliation.

use std::collections::BTreeMap;

use thiserror::Error;

use crate::{
    Account, AccountId, AccountType, AccountingDate, AccountingError, Ledger,
    QuickBooksAccountClassification, QuickBooksAccrualTrialBalancePolicy, TrialBalanceOptions,
};

/// Supported accrual statements derived from existing ledger facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinancialStatementKind {
    /// Income and expenses over an inclusive date range.
    ProfitAndLoss,
    /// Assets, liabilities and equity at an inclusive cutoff.
    BalanceSheet,
}

impl FinancialStatementKind {
    /// Stable identifier used in machine-readable output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProfitAndLoss => "profit_and_loss",
            Self::BalanceSheet => "balance_sheet",
        }
    }
}

/// An immutable validated statement; only ledger methods can construct one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinancialStatement {
    kind: FinancialStatementKind,
    from: Option<AccountingDate>,
    as_of: AccountingDate,
    policy: Option<QuickBooksAccrualTrialBalancePolicy>,
    accounts: Vec<Account>,
    rows: Vec<FinancialStatementRow>,
}

impl FinancialStatement {
    /// Statement type.
    pub const fn kind(&self) -> FinancialStatementKind {
        self.kind
    }

    /// Inclusive period start for P&L, absent for an as-of Balance Sheet.
    pub const fn from(&self) -> Option<AccountingDate> {
        self.from
    }

    /// Inclusive reporting cutoff.
    pub const fn as_of(&self) -> AccountingDate {
        self.as_of
    }

    /// Explicit fiscal policy used by a Balance Sheet.
    pub fn policy(&self) -> Option<&QuickBooksAccrualTrialBalancePolicy> {
        self.policy.as_ref()
    }

    /// Complete source chart, including zero-balance parents omitted from rows.
    pub fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    /// Ordered account, subtotal, and calculated rows.
    pub fn rows(&self) -> &[FinancialStatementRow] {
        &self.rows
    }
}

/// One statement row. Summing account rows and their subtotals double-counts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinancialStatementRow {
    /// Stable key: `account:<source id>` or a named calculated/total key.
    pub key: String,
    /// `account`, `subtotal`, or `calculated`.
    pub kind: &'static str,
    /// Statement grouping, independent of account names.
    pub section: &'static str,
    /// Source account name or the derived row's presentation label.
    pub label: String,
    /// Source account metadata, absent for totals and derived net income.
    pub account: Option<Account>,
    /// Debit-positive source amount, absent for non-account rows.
    pub signed_minor_units: Option<i64>,
    /// Presentation amount: revenue/assets/expenses/liabilities/equity positive
    /// on their conventional side; contra balances and losses remain negative.
    pub amount_minor_units: i64,
}

/// A report cannot be formed without a complete ledger and proven categories.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum FinancialStatementError {
    /// Existing ledger validation failed.
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    /// The inclusive date range is reversed.
    #[error("statement period starts after its reporting cutoff")]
    InvalidPeriod,
    /// No supported accounting category is established for a chart account.
    #[error("statement requires a classified account")]
    UnclassifiedAccount {
        /// Account that requires a proven category.
        account_id: AccountId,
    },
    /// Broad and source-granularity classifications disagree.
    #[error("statement account classifications disagree")]
    ConflictingClassification {
        /// Account with incompatible classification evidence.
        account_id: AccountId,
    },
    /// A balance or total cannot be represented exactly in output minor units.
    #[error("statement amount exceeds signed 64-bit minor units")]
    AmountOverflow,
    /// Derived Balance Sheet amounts do not satisfy the accounting equation.
    #[error("statement assets do not equal liabilities plus equity")]
    UnbalancedBalanceSheet,
}

impl Ledger {
    /// Derives an accrual P&L from current, validated GL postings in the
    /// inclusive range. No fiscal reset or retained-earnings adjustment applies
    /// to a requested P&L period, including a period crossing fiscal years.
    pub fn profit_and_loss(
        &self,
        from: AccountingDate,
        through: AccountingDate,
        options: TrialBalanceOptions,
    ) -> Result<FinancialStatement, FinancialStatementError> {
        if from > through {
            return Err(FinancialStatementError::InvalidPeriod);
        }
        let accounts = validated_accounts(self)?;
        let general_ledger = self.general_ledger_as_of(through)?;
        let mut balances = BTreeMap::<AccountId, i128>::new();
        for entry in general_ledger.entries {
            if entry.posting.date >= from {
                *balances.entry(entry.account.id).or_default() +=
                    i128::from(entry.posting.signed_minor_units);
            }
        }
        let mut report = FinancialStatement {
            kind: FinancialStatementKind::ProfitAndLoss,
            from: Some(from),
            as_of: through,
            policy: None,
            accounts,
            rows: Vec::new(),
        };
        let income = append_section(&mut report, &balances, "income", options)?;
        append_total(
            &mut report,
            "income",
            "total_income",
            "Total Income",
            income,
        )?;
        let cogs = append_section(&mut report, &balances, "cost_of_goods_sold", options)?;
        append_total(
            &mut report,
            "cost_of_goods_sold",
            "total_cost_of_goods_sold",
            "Total Cost of Goods Sold",
            cogs,
        )?;
        append_calculated(
            &mut report,
            "profit",
            "gross_profit",
            "Gross Profit",
            income - cogs,
        )?;
        let expense = append_section(&mut report, &balances, "expense", options)?;
        append_total(
            &mut report,
            "expense",
            "total_expense",
            "Total Expense",
            expense,
        )?;
        append_calculated(
            &mut report,
            "profit",
            "net_operating_income",
            "Net Operating Income",
            income - cogs - expense,
        )?;
        let other_income = append_section(&mut report, &balances, "other_income", options)?;
        append_total(
            &mut report,
            "other_income",
            "total_other_income",
            "Total Other Income",
            other_income,
        )?;
        let other_expense = append_section(&mut report, &balances, "other_expense", options)?;
        append_total(
            &mut report,
            "other_expense",
            "total_other_expense",
            "Total Other Expense",
            other_expense,
        )?;
        append_calculated(
            &mut report,
            "profit",
            "net_other_income",
            "Net Other Income",
            other_income - other_expense,
        )?;
        append_calculated(
            &mut report,
            "profit",
            "net_income",
            "Net Income",
            income - cogs - expense + other_income - other_expense,
        )?;
        Ok(report)
    }

    /// Derives an accrual Balance Sheet from the existing fiscal-policy TB.
    /// Prior-year P&L is already folded into retained earnings by that TB.
    /// Current-year P&L becomes one calculated equity row, never a fabricated
    /// source account or a second retained-earnings posting.
    pub fn balance_sheet_as_of(
        &self,
        as_of: AccountingDate,
        options: TrialBalanceOptions,
        policy: &QuickBooksAccrualTrialBalancePolicy,
    ) -> Result<FinancialStatement, FinancialStatementError> {
        let accounts = validated_accounts(self)?;
        let trial_balance = self.quickbooks_accrual_trial_balance_as_of(as_of, options, policy)?;
        let mut balances = BTreeMap::new();
        let mut current_income = 0_i128;
        for row in trial_balance.rows {
            let amount = i128::from(row.signed_minor_units);
            if matches!(
                row.account.account_type,
                AccountType::Income | AccountType::Expense | AccountType::CostOfGoodsSold
            ) {
                current_income -= amount;
            } else {
                balances.insert(row.account.id, amount);
            }
        }
        let mut report = FinancialStatement {
            kind: FinancialStatementKind::BalanceSheet,
            from: None,
            as_of,
            policy: Some(policy.clone()),
            accounts,
            rows: Vec::new(),
        };
        let assets = append_section(&mut report, &balances, "assets", options)?;
        append_total(
            &mut report,
            "assets",
            "total_assets",
            "Total Assets",
            assets,
        )?;
        let liabilities = append_section(&mut report, &balances, "liabilities", options)?;
        append_total(
            &mut report,
            "liabilities",
            "total_liabilities",
            "Total Liabilities",
            liabilities,
        )?;
        let equity = append_section(&mut report, &balances, "equity", options)?;
        append_calculated(
            &mut report,
            "equity",
            "current_year_net_income",
            "Current Year Net Income",
            current_income,
        )?;
        append_total(
            &mut report,
            "equity",
            "total_equity",
            "Total Equity",
            equity + current_income,
        )?;
        append_total(
            &mut report,
            "liabilities_and_equity",
            "total_liabilities_and_equity",
            "Total Liabilities and Equity",
            liabilities + equity + current_income,
        )?;
        if assets != liabilities + equity + current_income {
            return Err(FinancialStatementError::UnbalancedBalanceSheet);
        }
        Ok(report)
    }
}

fn validated_accounts(ledger: &Ledger) -> Result<Vec<Account>, FinancialStatementError> {
    ledger
        .accounts()
        .map(|account| {
            if matches!(account.account_type, AccountType::Other(_))
                || account.quickbooks_classification.is_none()
            {
                return Err(FinancialStatementError::UnclassifiedAccount {
                    account_id: account.id.clone(),
                });
            }
            if account
                .quickbooks_classification
                .is_some_and(|classification| {
                    classification.trial_balance_type() != account.account_type
                })
            {
                return Err(FinancialStatementError::ConflictingClassification {
                    account_id: account.id.clone(),
                });
            }
            Ok(account.clone())
        })
        .collect()
}

fn section_for(account: &Account) -> &'static str {
    match account.quickbooks_classification {
        Some(QuickBooksAccountClassification::OtherIncome) => "other_income",
        Some(QuickBooksAccountClassification::OtherExpense) => "other_expense",
        _ => match account.account_type {
            AccountType::Asset => "assets",
            AccountType::Liability => "liabilities",
            AccountType::Equity => "equity",
            AccountType::Income => "income",
            AccountType::CostOfGoodsSold => "cost_of_goods_sold",
            AccountType::Expense => "expense",
            AccountType::Other(_) => unreachable!("validated chart"),
        },
    }
}

fn append_section(
    report: &mut FinancialStatement,
    balances: &BTreeMap<AccountId, i128>,
    section: &'static str,
    options: TrialBalanceOptions,
) -> Result<i128, FinancialStatementError> {
    let mut total = 0_i128;
    for account in &report.accounts {
        if section_for(account) != section {
            continue;
        }
        let signed = balances.get(&account.id).copied().unwrap_or_default();
        let amount = if matches!(
            account.account_type,
            AccountType::Income | AccountType::Liability | AccountType::Equity
        ) {
            -signed
        } else {
            signed
        };
        total += amount;
        if signed == 0 && !options.include_zero_balance_accounts {
            continue;
        }
        report.rows.push(FinancialStatementRow {
            key: format!("account:{}", account.id.as_str()),
            kind: "account",
            section,
            label: account.name.clone(),
            account: Some(account.clone()),
            signed_minor_units: Some(exact_amount(signed)?),
            amount_minor_units: exact_amount(amount)?,
        });
    }
    Ok(total)
}

fn append_total(
    report: &mut FinancialStatement,
    section: &'static str,
    key: &str,
    label: &str,
    amount: i128,
) -> Result<(), FinancialStatementError> {
    append_derived(report, "subtotal", section, key, label, amount)
}

fn append_calculated(
    report: &mut FinancialStatement,
    section: &'static str,
    key: &str,
    label: &str,
    amount: i128,
) -> Result<(), FinancialStatementError> {
    append_derived(report, "calculated", section, key, label, amount)
}

fn append_derived(
    report: &mut FinancialStatement,
    kind: &'static str,
    section: &'static str,
    key: &str,
    label: &str,
    amount: i128,
) -> Result<(), FinancialStatementError> {
    report.rows.push(FinancialStatementRow {
        key: key.to_owned(),
        kind,
        section,
        label: label.to_owned(),
        account: None,
        signed_minor_units: None,
        amount_minor_units: exact_amount(amount)?,
    });
    Ok(())
}

fn exact_amount(value: i128) -> Result<i64, FinancialStatementError> {
    i64::try_from(value).map_err(|_| FinancialStatementError::AmountOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CurrentState, LedgerCompleteness, Posting, PostingId, PostingProvenance, TransactionId,
    };

    fn account(id: &str, classification: QuickBooksAccountClassification) -> Account {
        Account::new(
            AccountId::new(id).unwrap(),
            id,
            classification.trial_balance_type(),
            true,
        )
        .unwrap()
        .with_quickbooks_classification(classification)
    }

    fn posting(txn: usize, account: &str, date: i32, amount: i64) -> Posting {
        let key = format!("{txn}:{account}");
        Posting {
            transaction_id: TransactionId::new(txn.to_string()).unwrap(),
            id: PostingId::new(&key).unwrap(),
            account_id: AccountId::new(account).unwrap(),
            date,
            signed_minor_units: amount,
            current_state: CurrentState::Current,
            provenance: PostingProvenance::new(key, None, None, "synthetic").unwrap(),
            transaction_type: None,
            memo: None,
        }
    }

    fn fixture() -> Ledger {
        use QuickBooksAccountClassification::*;
        let mut accounts = vec![
            account("cash", Bank),
            account("capital", Equity),
            account("retained", Equity),
            account("income", Income),
            account("child_income", Income)
                .with_hierarchy(None, Some(AccountId::new("income").unwrap()))
                .unwrap(),
            account("expense", Expense),
            account("cogs", CostOfGoodsSold),
            account("other_income", OtherIncome),
            account("other_expense", OtherExpense),
            account("fixed", FixedAsset),
            account("contra_asset", FixedAsset),
            account("loan", LongTermLiability),
            account("zero_expense", Expense),
        ];
        accounts.last_mut().unwrap().activity = crate::AccountActivity::Unknown;
        accounts.last_mut().unwrap().active = false;
        let transactions = [
            (90, "cash", "capital", 10000),
            (99, "cash", "income", 3000),
            (100, "cash", "income", 2000),
            (110, "expense", "cash", 600),
            (110, "cogs", "cash", 400),
            (115, "cash", "other_income", 100),
            (115, "other_expense", "cash", 50),
            (118, "income", "cash", 200),
            (120, "cash", "child_income", 500),
            (115, "cash", "retained", 700),
            (112, "fixed", "loan", 2000),
            (119, "expense", "contra_asset", 100),
            (121, "cash", "income", 900),
        ];
        let mut postings = Vec::new();
        for (index, (date, debit, credit, amount)) in transactions.iter().enumerate() {
            postings.push(posting(index, debit, *date, *amount));
            postings.push(posting(index, credit, *date, -*amount));
        }
        for state in [CurrentState::Deleted, CurrentState::Superseded] {
            let txn = postings.len();
            for (id, amount) in [("cash", 50000), ("income", -50000)] {
                let mut row = posting(txn, id, 116, amount);
                row.current_state = state.clone();
                postings.push(row);
            }
        }
        Ledger::new(accounts, postings, LedgerCompleteness::Complete).unwrap()
    }

    fn policy() -> QuickBooksAccrualTrialBalancePolicy {
        QuickBooksAccrualTrialBalancePolicy::new(100, AccountId::new("retained").unwrap())
    }

    fn amount(report: &FinancialStatement, key: &str) -> i64 {
        report
            .rows()
            .iter()
            .find(|row| row.key == key)
            .unwrap()
            .amount_minor_units
    }

    #[test]
    fn pnl_reconciles_every_account_to_gl_with_inclusive_boundaries_and_known_totals() {
        let ledger = fixture();
        let report = ledger
            .profit_and_loss(100, 120, TrialBalanceOptions::default())
            .unwrap();
        assert_eq!(amount(&report, "total_income"), 2300);
        assert_eq!(amount(&report, "gross_profit"), 1900);
        assert_eq!(amount(&report, "net_operating_income"), 1200);
        assert_eq!(amount(&report, "net_other_income"), 50);
        assert_eq!(amount(&report, "net_income"), 1250);
        assert_eq!(amount(&report, "account:income"), 1800);
        assert_eq!(amount(&report, "account:child_income"), 500);
        let gl = ledger.general_ledger_as_of(120).unwrap();
        for row in report.rows().iter().filter(|row| row.account.is_some()) {
            let account = row.account.as_ref().unwrap();
            let source: i64 = gl
                .entries
                .iter()
                .filter(|entry| entry.account.id == account.id && entry.posting.date >= 100)
                .map(|entry| entry.posting.signed_minor_units)
                .sum();
            assert_eq!(row.signed_minor_units, Some(source));
        }
        let last_day = ledger
            .profit_and_loss(120, 120, TrialBalanceOptions::default())
            .unwrap();
        assert_eq!(amount(&last_day, "net_income"), 500);
        let crossing_year = ledger
            .profit_and_loss(99, 100, TrialBalanceOptions::default())
            .unwrap();
        assert_eq!(amount(&crossing_year, "net_income"), 5000);
    }

    #[test]
    fn balance_sheet_ties_to_tb_and_pnl_without_double_counting_earnings() {
        let ledger = fixture();
        let report = ledger
            .balance_sheet_as_of(120, TrialBalanceOptions::default(), &policy())
            .unwrap();
        assert_eq!(amount(&report, "account:retained"), 3700);
        assert_eq!(amount(&report, "current_year_net_income"), 1250);
        assert_eq!(amount(&report, "account:contra_asset"), -100);
        assert_eq!(amount(&report, "total_assets"), 16950);
        assert_eq!(amount(&report, "total_liabilities"), 2000);
        assert_eq!(amount(&report, "total_equity"), 14950);
        assert_eq!(
            amount(&report, "total_assets"),
            amount(&report, "total_liabilities_and_equity")
        );
        let tb = ledger
            .quickbooks_accrual_trial_balance_as_of(120, TrialBalanceOptions::default(), &policy())
            .unwrap();
        for row in report.rows().iter().filter(|row| row.account.is_some()) {
            let source = tb
                .rows
                .iter()
                .find(|source| source.account.id == row.account.as_ref().unwrap().id)
                .unwrap();
            assert_eq!(row.signed_minor_units, Some(source.signed_minor_units));
        }
        let pnl = ledger
            .profit_and_loss(100, 120, TrialBalanceOptions::default())
            .unwrap();
        assert_eq!(
            amount(&report, "current_year_net_income"),
            amount(&pnl, "net_income")
        );
        assert!(!report.rows().iter().any(|row| row.key == "account:income"));
        assert!(
            report
                .rows()
                .iter()
                .find(|row| row.key == "current_year_net_income")
                .unwrap()
                .account
                .is_none()
        );
        let next_year =
            QuickBooksAccrualTrialBalancePolicy::new(121, AccountId::new("retained").unwrap());
        let next = ledger
            .balance_sheet_as_of(121, TrialBalanceOptions::default(), &next_year)
            .unwrap();
        assert_eq!(amount(&next, "account:retained"), 4950);
        assert_eq!(amount(&next, "current_year_net_income"), 900);
    }

    #[test]
    fn losses_zero_accounts_and_empty_periods_are_preserved() {
        let ledger = fixture();
        let loss = ledger
            .profit_and_loss(110, 110, TrialBalanceOptions::default())
            .unwrap();
        assert_eq!(amount(&loss, "net_income"), -1000);
        let empty = ledger
            .profit_and_loss(130, 140, TrialBalanceOptions::default())
            .unwrap();
        assert_eq!(amount(&empty, "net_income"), 0);
        assert!(!empty.rows().iter().any(|row| row.account.is_some()));
        let included = ledger
            .profit_and_loss(
                130,
                140,
                TrialBalanceOptions {
                    include_zero_balance_accounts: true,
                },
            )
            .unwrap();
        assert_eq!(amount(&included, "account:zero_expense"), 0);
        assert_eq!(
            included
                .rows()
                .iter()
                .find(|row| row.key == "account:zero_expense")
                .unwrap()
                .account
                .as_ref()
                .unwrap()
                .activity,
            crate::AccountActivity::Unknown
        );
    }

    #[test]
    fn statements_retain_completeness_current_state_and_balance_gates() {
        let source = fixture();
        for completeness in [
            LedgerCompleteness::Incomplete {
                reason: "synthetic".into(),
            },
            LedgerCompleteness::Unsupported {
                feature: "synthetic".into(),
            },
        ] {
            let ledger = Ledger::new(
                source.accounts().cloned(),
                source.postings().cloned(),
                completeness,
            )
            .unwrap();
            assert!(
                ledger
                    .profit_and_loss(100, 120, TrialBalanceOptions::default())
                    .is_err()
            );
            assert!(
                ledger
                    .balance_sheet_as_of(120, TrialBalanceOptions::default(), &policy())
                    .is_err()
            );
        }
        for ambiguous in [false, true] {
            let mut rows: Vec<_> = source.postings().cloned().collect();
            if ambiguous {
                rows[0].current_state = CurrentState::Ambiguous;
            } else {
                rows[0].signed_minor_units += 1;
            }
            let ledger = Ledger::new(
                source.accounts().cloned(),
                rows,
                LedgerCompleteness::Complete,
            )
            .unwrap();
            assert!(
                ledger
                    .profit_and_loss(100, 120, TrialBalanceOptions::default())
                    .is_err()
            );
            assert!(
                ledger
                    .balance_sheet_as_of(120, TrialBalanceOptions::default(), &policy())
                    .is_err()
            );
        }
        assert_eq!(
            source
                .profit_and_loss(121, 120, TrialBalanceOptions::default())
                .unwrap_err(),
            FinancialStatementError::InvalidPeriod
        );
        assert!(
            source
                .balance_sheet_as_of(99, TrialBalanceOptions::default(), &policy())
                .is_err()
        );
    }

    #[test]
    fn unknown_or_conflicting_classifications_are_never_guessed() {
        let source = fixture();
        for mode in 0..3 {
            let mut accounts: Vec<_> = source.accounts().cloned().collect();
            match mode {
                0 => accounts[0].quickbooks_classification = None,
                1 => accounts[0].account_type = AccountType::Other("unclassified".into()),
                _ => accounts[0].account_type = AccountType::Expense,
            }
            let ledger = Ledger::new(
                accounts,
                source.postings().cloned(),
                LedgerCompleteness::Complete,
            )
            .unwrap();
            assert!(
                ledger
                    .profit_and_loss(100, 120, TrialBalanceOptions::default())
                    .is_err()
            );
            assert!(
                ledger
                    .balance_sheet_as_of(120, TrialBalanceOptions::default(), &policy())
                    .is_err()
            );
        }
    }

    #[test]
    fn subtotal_overflow_fails_even_when_individual_accounts_fit() {
        use QuickBooksAccountClassification::*;
        let accounts = [
            account("cash", Bank),
            account("income", Income),
            account("other_revenue", Income),
        ];
        let rows = [
            posting(0, "cash", 100, i64::MAX),
            posting(0, "income", 100, -i64::MAX),
            posting(1, "cash", 100, 1),
            posting(1, "other_revenue", 100, -1),
        ];
        let ledger = Ledger::new(accounts, rows, LedgerCompleteness::Complete).unwrap();
        assert_eq!(
            ledger
                .profit_and_loss(100, 100, TrialBalanceOptions::default())
                .unwrap_err(),
            FinancialStatementError::AmountOverflow
        );
    }

    #[test]
    fn reversing_input_order_does_not_change_statements() {
        let source = fixture();
        let mut accounts: Vec<_> = source.accounts().cloned().collect();
        let mut postings: Vec<_> = source.postings().cloned().collect();
        accounts.reverse();
        postings.reverse();
        let reversed = Ledger::new(accounts, postings, LedgerCompleteness::Complete).unwrap();
        assert_eq!(
            source
                .profit_and_loss(100, 120, TrialBalanceOptions::default())
                .unwrap(),
            reversed
                .profit_and_loss(100, 120, TrialBalanceOptions::default())
                .unwrap()
        );
        assert_eq!(
            source
                .balance_sheet_as_of(120, TrialBalanceOptions::default(), &policy())
                .unwrap(),
            reversed
                .balance_sheet_as_of(120, TrialBalanceOptions::default(), &policy())
                .unwrap()
        );
    }
}

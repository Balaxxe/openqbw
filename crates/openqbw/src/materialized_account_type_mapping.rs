//! Fail-closed presentation mapping for calibrated materialized Account codes.
//!
//! This module is deliberately separate from the row parser: a byte can be
//! structurally present in a valid Account row without being safe to use for a
//! Trial Balance classification.  The supported discriminators were
//! corroborated by a one-to-one ordinary-ListID join to a local, controlled
//! Account-query oracle. Only codes with one Oracle Account type across all
//! joined rows are accepted. The installed SDK's Account-type domain is only
//! a label vocabulary: its enum's numeric values are not QBW materialized
//! codes, so this module never treats their positions as interchangeable. The
//! oracle is development-only and is not read by this library at runtime.
//!
//! Evidence boundary: the controlled corpus produced 442 distinct ordinary
//! ListIDs, and all 442 joined exactly one materialized row. Each accepted
//! code joined exactly one AccountQuery `AccountType`; no accepted code had a
//! conflicting label.
//!
//! Codes `6` and `11` have a separate, stronger calibration path. The installed
//! Enterprise 24 `qblist32` static Account-type label table is a contiguous
//! zero-based sequence whose surrounding labels exactly agree with the
//! independently joined materialized codes `0..=5` and `7..=14`.  Its ordinal
//! 6 label is `Credit Card`, between `Accounts Payable` (5) and
//! `Other Current Liability` (7); ordinal 11 is `Cost of Goods Sold`, between
//! `Income` (10) and `Expense` (12).
//! A private aggregate-only B3 corpus check also found one structurally valid
//! code-11 Account row with one bounded ordinary identity; it had no current
//! Account Listing representative, so no name, identifier, or company data is
//! embedded here.  That lifecycle absence is not evidence for a different
//! type, and the static table's complete ordinal alignment uniquely identifies
//! code 11.  The oracle is development-only and is never read at runtime.

use thiserror::Error;

use crate::AccountType;

/// A calibrated QuickBooks Account classification.
///
/// The variant is kept at QuickBooks' source granularity while
/// [`Self::trial_balance_type`] supplies the normalized presentation grouping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuickBooksAccountClassification {
    /// Cash or bank account.
    Bank,
    /// Trade receivable account.
    AccountsReceivable,
    /// Other current asset.
    OtherCurrentAsset,
    /// Fixed asset.
    FixedAsset,
    /// Other non-current asset.
    OtherAsset,
    /// Trade payable account.
    AccountsPayable,
    /// Credit-card liability account.
    CreditCard,
    /// Other current liability.
    OtherCurrentLiability,
    /// Long-term liability.
    LongTermLiability,
    /// Equity.
    Equity,
    /// Operating income.
    Income,
    /// Cost of goods sold.
    CostOfGoodsSold,
    /// Operating expense.
    Expense,
    /// Other income.
    OtherIncome,
    /// Other expense.
    OtherExpense,
}

impl QuickBooksAccountClassification {
    /// Returns the raw, name-relative materialized Account discriminator.
    #[must_use]
    pub const fn materialized_code(self) -> u8 {
        match self {
            Self::Bank => 0,
            Self::AccountsReceivable => 1,
            Self::OtherCurrentAsset => 2,
            Self::FixedAsset => 3,
            Self::OtherAsset => 4,
            Self::AccountsPayable => 5,
            Self::CreditCard => 6,
            Self::OtherCurrentLiability => 7,
            Self::LongTermLiability => 8,
            Self::Equity => 9,
            Self::Income => 10,
            Self::CostOfGoodsSold => 11,
            Self::Expense => 12,
            Self::OtherIncome => 13,
            Self::OtherExpense => 14,
        }
    }

    /// Returns QuickBooks' stable source label for diagnostics and exports.
    #[must_use]
    pub const fn source_label(self) -> &'static str {
        match self {
            Self::Bank => "Bank",
            Self::AccountsReceivable => "AccountsReceivable",
            Self::OtherCurrentAsset => "OtherCurrentAsset",
            Self::FixedAsset => "FixedAsset",
            Self::OtherAsset => "OtherAsset",
            Self::AccountsPayable => "AccountsPayable",
            Self::CreditCard => "CreditCard",
            Self::OtherCurrentLiability => "OtherCurrentLiability",
            Self::LongTermLiability => "LongTermLiability",
            Self::Equity => "Equity",
            Self::Income => "Income",
            Self::CostOfGoodsSold => "CostOfGoodsSold",
            Self::Expense => "Expense",
            Self::OtherIncome => "OtherIncome",
            Self::OtherExpense => "OtherExpense",
        }
    }

    /// Returns the normalized Account type used for Trial Balance presentation.
    #[must_use]
    pub fn trial_balance_type(self) -> AccountType {
        match self {
            Self::Bank
            | Self::AccountsReceivable
            | Self::OtherCurrentAsset
            | Self::FixedAsset
            | Self::OtherAsset => AccountType::Asset,
            Self::AccountsPayable
            | Self::CreditCard
            | Self::OtherCurrentLiability
            | Self::LongTermLiability => AccountType::Liability,
            Self::Equity => AccountType::Equity,
            Self::Income | Self::OtherIncome => AccountType::Income,
            Self::CostOfGoodsSold => AccountType::CostOfGoodsSold,
            Self::Expense | Self::OtherExpense => AccountType::Expense,
        }
    }
}

/// Returns the calibrated classification for one materialized Account code.
///
/// Code `15` remains intentionally rejected because it has no calibration
/// path sufficient for accounting output. Codes `6` and `11` are accepted
/// under the complete static-label-table ordinal alignment documented at this
/// module's evidence boundary.
pub const fn map_materialized_account_type_code(
    code: u8,
) -> Result<QuickBooksAccountClassification, MaterializedAccountTypeMappingError> {
    match code {
        0 => Ok(QuickBooksAccountClassification::Bank),
        1 => Ok(QuickBooksAccountClassification::AccountsReceivable),
        2 => Ok(QuickBooksAccountClassification::OtherCurrentAsset),
        3 => Ok(QuickBooksAccountClassification::FixedAsset),
        4 => Ok(QuickBooksAccountClassification::OtherAsset),
        5 => Ok(QuickBooksAccountClassification::AccountsPayable),
        6 => Ok(QuickBooksAccountClassification::CreditCard),
        7 => Ok(QuickBooksAccountClassification::OtherCurrentLiability),
        8 => Ok(QuickBooksAccountClassification::LongTermLiability),
        9 => Ok(QuickBooksAccountClassification::Equity),
        10 => Ok(QuickBooksAccountClassification::Income),
        11 => Ok(QuickBooksAccountClassification::CostOfGoodsSold),
        12 => Ok(QuickBooksAccountClassification::Expense),
        13 => Ok(QuickBooksAccountClassification::OtherIncome),
        14 => Ok(QuickBooksAccountClassification::OtherExpense),
        _ => Err(MaterializedAccountTypeMappingError::UncalibratedCode { code }),
    }
}

/// Error returned when a structural Account type code lacks semantic evidence.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum MaterializedAccountTypeMappingError {
    /// No accounting classification is calibrated for this discriminator.
    #[error("materialized Account type code {code:#04x} is not calibrated for Trial Balance use")]
    UncalibratedCode {
        /// Raw materialized discriminator.
        code: u8,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_only_explicitly_calibrated_codes_at_source_granularity() {
        let cases = [
            (0, QuickBooksAccountClassification::Bank, AccountType::Asset),
            (
                1,
                QuickBooksAccountClassification::AccountsReceivable,
                AccountType::Asset,
            ),
            (
                2,
                QuickBooksAccountClassification::OtherCurrentAsset,
                AccountType::Asset,
            ),
            (
                3,
                QuickBooksAccountClassification::FixedAsset,
                AccountType::Asset,
            ),
            (
                4,
                QuickBooksAccountClassification::OtherAsset,
                AccountType::Asset,
            ),
            (
                5,
                QuickBooksAccountClassification::AccountsPayable,
                AccountType::Liability,
            ),
            (
                6,
                QuickBooksAccountClassification::CreditCard,
                AccountType::Liability,
            ),
            (
                7,
                QuickBooksAccountClassification::OtherCurrentLiability,
                AccountType::Liability,
            ),
            (
                8,
                QuickBooksAccountClassification::LongTermLiability,
                AccountType::Liability,
            ),
            (
                9,
                QuickBooksAccountClassification::Equity,
                AccountType::Equity,
            ),
            (
                10,
                QuickBooksAccountClassification::Income,
                AccountType::Income,
            ),
            (
                11,
                QuickBooksAccountClassification::CostOfGoodsSold,
                AccountType::CostOfGoodsSold,
            ),
            (
                12,
                QuickBooksAccountClassification::Expense,
                AccountType::Expense,
            ),
            (
                13,
                QuickBooksAccountClassification::OtherIncome,
                AccountType::Income,
            ),
            (
                14,
                QuickBooksAccountClassification::OtherExpense,
                AccountType::Expense,
            ),
        ];
        for (code, expected, trial_balance_type) in cases {
            let actual = map_materialized_account_type_code(code).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(actual.materialized_code(), code);
            assert_eq!(actual.trial_balance_type(), trial_balance_type);
            assert!(!actual.source_label().is_empty());
        }
    }

    #[test]
    fn rejects_unobserved_or_unknown_codes_instead_of_guessing() {
        for code in [15, u8::MAX] {
            assert_eq!(
                map_materialized_account_type_code(code),
                Err(MaterializedAccountTypeMappingError::UncalibratedCode { code })
            );
        }
    }
}

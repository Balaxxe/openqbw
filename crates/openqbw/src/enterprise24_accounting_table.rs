//! QuickBooks Enterprise 24 physical accounting-table identities.
//!
//! These identifiers are schema identities, not page guesses. They were
//! corroborated by materialized page headers and the Enterprise 24 catalog.
//! The list is deliberately limited to the account and transaction families
//! needed by the current accrual Trial Balance pipeline. A non-listed table
//! must remain unsupported until independently classified.

use thiserror::Error;

/// A physical Enterprise 24 table used by the accounting extractor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum Enterprise24AccountingTable {
    /// Internal Account lifecycle/identity rows paired with user accounts.
    AccountInternal = 3025,
    /// User-facing Chart of Accounts rows.
    AccountUser = 3026,
    /// Bill-Payment-Check transaction headers.
    BillPaymentCheckHeader = 3038,
    /// Bill-Payment-Check accounting lines.
    BillPaymentCheckLine = 3039,
    /// Bill transaction headers.
    BillHeader = 3040,
    /// Bill accounting lines.
    BillLine = 3042,
    /// Check transaction headers.
    CheckHeader = 3045,
    /// Check accounting lines.
    CheckLine = 3047,
    /// Deposit transaction headers.
    DepositHeader = 3068,
    /// Deposit accounting lines.
    DepositLine = 3069,
    /// General Journal transaction headers.
    GeneralJournalHeader = 3076,
    /// General Journal accounting lines.
    GeneralJournalLine = 3078,
}

impl Enterprise24AccountingTable {
    /// Returns the catalog/materialized-header table identifier.
    #[must_use]
    pub const fn id(self) -> u32 {
        self as u32
    }

    /// Returns whether rows from this table can carry normalized postings.
    #[must_use]
    pub const fn is_posting_table(self) -> bool {
        matches!(
            self,
            Self::BillPaymentCheckLine
                | Self::BillLine
                | Self::CheckLine
                | Self::DepositLine
                | Self::GeneralJournalLine
        )
    }

    /// Returns whether rows from this table are transaction-header carriers.
    #[must_use]
    pub const fn is_transaction_header_table(self) -> bool {
        matches!(
            self,
            Self::BillPaymentCheckHeader
                | Self::BillHeader
                | Self::CheckHeader
                | Self::DepositHeader
                | Self::GeneralJournalHeader
        )
    }
}

impl TryFrom<u32> for Enterprise24AccountingTable {
    type Error = UnsupportedEnterprise24AccountingTable;

    fn try_from(table_id: u32) -> Result<Self, Self::Error> {
        match table_id {
            3025 => Ok(Self::AccountInternal),
            3026 => Ok(Self::AccountUser),
            3038 => Ok(Self::BillPaymentCheckHeader),
            3039 => Ok(Self::BillPaymentCheckLine),
            3040 => Ok(Self::BillHeader),
            3042 => Ok(Self::BillLine),
            3045 => Ok(Self::CheckHeader),
            3047 => Ok(Self::CheckLine),
            3068 => Ok(Self::DepositHeader),
            3069 => Ok(Self::DepositLine),
            3076 => Ok(Self::GeneralJournalHeader),
            3078 => Ok(Self::GeneralJournalLine),
            table_id => Err(UnsupportedEnterprise24AccountingTable { table_id }),
        }
    }
}

/// A table ID without a proven role in the Enterprise 24 accounting pipeline.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("Enterprise 24 table {table_id} is not a supported accounting table")]
pub struct UnsupportedEnterprise24AccountingTable {
    /// Unclassified physical table identifier.
    pub table_id: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_only_the_explicit_enterprise24_accounting_surface() {
        assert_eq!(
            Enterprise24AccountingTable::try_from(3026),
            Ok(Enterprise24AccountingTable::AccountUser)
        );
        assert!(Enterprise24AccountingTable::BillLine.is_posting_table());
        assert!(Enterprise24AccountingTable::CheckHeader.is_transaction_header_table());
        assert_eq!(
            Enterprise24AccountingTable::try_from(9999),
            Err(UnsupportedEnterprise24AccountingTable { table_id: 9999 })
        );
    }
}

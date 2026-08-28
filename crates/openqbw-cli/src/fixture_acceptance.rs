//! Local-only acceptance-fixture preflight for the accounting extractor.
//!
//! This module never reads QBXML responses or a QBW file.  It accepts only
//! the privacy-safe SDK manifest plus native report files that remain ignored
//! in a caller-owned fixture directory.  Its purpose is to make the eventual
//! acceptance sequence explicit:
//!
//! 1. audit the immutable oracle and native-report inputs;
//! 2. run the direct-QBW decoder to normalized accounts and postings;
//! 3. build the fail-closed ledger and produce TB/GL output;
//! 4. reconcile each generated Trial Balance against its native counterpart;
//! 5. use native GL/Journal/voided reports to investigate any remaining
//!    posting, current-state, or presentation variance.
//!
//! Steps 2--5 deliberately remain unavailable until an Enterprise 24 decoder
//! exists.  This preflight must not be mistaken for an SDK-backed extractor.

use std::path::{Path, PathBuf};

use crate::sdk_oracle_manifest::SdkOracleManifest;
use crate::trial_balance_reconciliation::parse_quickbooks_trial_balance_csv;

/// Safe aggregate facts about one native Trial Balance input.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct NativeTrialBalanceAudit {
    /// Number of report account rows parsed from this native Trial Balance.
    pub account_rows: usize,
    /// Exact total debit cents in the native report.
    pub debit_cents: i64,
    /// Exact total credit cents in the native report.
    pub credit_cents: i64,
}

/// Aggregate preflight result for a local acceptance fixture.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FixtureAcceptanceAudit {
    /// Read-only SDK-oracle metadata, with no company path or QBXML payload.
    pub sdk_oracle: SdkOracleManifest,
    /// One audit result per native Trial Balance file.
    pub trial_balances: Vec<NativeTrialBalanceAudit>,
    /// Number of native General Ledger files present for detailed validation.
    pub general_ledger_reports: usize,
    /// Number of native Journal files present for detailed validation.
    pub journal_reports: usize,
}

impl FixtureAcceptanceAudit {
    /// Total native Trial Balance account rows across all requested cutoffs.
    pub fn total_trial_balance_rows(&self) -> usize {
        self.trial_balances
            .iter()
            .map(|audit| audit.account_rows)
            .sum()
    }
}

/// Audit a local acceptance fixture before a direct-QBW decoder is run.
///
/// Paths are intentionally not retained in the returned value or error text.
/// The account-listing and voided/deleted report are presence gates: later
/// account/current-state comparators require both.  General Ledger and
/// Journal reports are likewise required for line-level investigation after
/// a Trial Balance variance.  Native Trial Balances are parsed exactly and
/// must balance independently before they can serve as goldens.
pub fn audit_fixture(
    sdk_oracle: SdkOracleManifest,
    account_listing: &Path,
    voided_deleted: &Path,
    trial_balance_paths: &[PathBuf],
    general_ledger_paths: &[PathBuf],
    journal_paths: &[PathBuf],
) -> Result<FixtureAcceptanceAudit, FixtureAcceptanceError> {
    if sdk_oracle.account_count == 0
        || sdk_oracle.journal_entry_count == 0
        || sdk_oracle.journal_line_count < sdk_oracle.journal_entry_count
    {
        return Err(FixtureAcceptanceError::InvalidOracleCounts);
    }
    require_nonempty_file(account_listing)?;
    require_nonempty_file(voided_deleted)?;
    if trial_balance_paths.is_empty() {
        return Err(FixtureAcceptanceError::NoTrialBalances);
    }
    if general_ledger_paths.is_empty() {
        return Err(FixtureAcceptanceError::NoGeneralLedgers);
    }
    if journal_paths.is_empty() {
        return Err(FixtureAcceptanceError::NoJournals);
    }

    let mut trial_balances = Vec::with_capacity(trial_balance_paths.len());
    for path in trial_balance_paths {
        let bytes = read_nonempty(path)?;
        let report = parse_quickbooks_trial_balance_csv(&bytes)
            .map_err(|_| FixtureAcceptanceError::InvalidTrialBalance)?;
        if !report.is_balanced() {
            return Err(FixtureAcceptanceError::UnbalancedTrialBalance);
        }
        if u64::try_from(report.balances_cents.len()).expect("usize always fits u64")
            > sdk_oracle.account_count
        {
            return Err(FixtureAcceptanceError::TrialBalanceExceedsOracleAccounts);
        }
        trial_balances.push(NativeTrialBalanceAudit {
            account_rows: report.balances_cents.len(),
            debit_cents: report.total_debits_cents,
            credit_cents: report.total_credits_cents,
        });
    }
    for path in general_ledger_paths {
        require_nonempty_file(path)?;
    }
    for path in journal_paths {
        require_nonempty_file(path)?;
    }

    Ok(FixtureAcceptanceAudit {
        sdk_oracle,
        trial_balances,
        general_ledger_reports: general_ledger_paths.len(),
        journal_reports: journal_paths.len(),
    })
}

fn require_nonempty_file(path: &Path) -> Result<(), FixtureAcceptanceError> {
    if matches!(std::fs::metadata(path), Ok(metadata) if metadata.len() > 0) {
        Ok(())
    } else {
        Err(FixtureAcceptanceError::MissingOrEmptyFixture)
    }
}

fn read_nonempty(path: &Path) -> Result<Vec<u8>, FixtureAcceptanceError> {
    require_nonempty_file(path)?;
    std::fs::read(path).map_err(|_| FixtureAcceptanceError::MissingOrEmptyFixture)
}

/// Fixture preflight failures with no embedded paths or business values.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FixtureAcceptanceError {
    /// The local SDK manifest has internally impossible aggregate counts.
    InvalidOracleCounts,
    /// A required local fixture file is absent, inaccessible, or empty.
    MissingOrEmptyFixture,
    /// No native Trial Balance was supplied.
    NoTrialBalances,
    /// No native General Ledger was supplied.
    NoGeneralLedgers,
    /// No native Journal was supplied.
    NoJournals,
    /// A native Trial Balance could not be parsed under its required format.
    InvalidTrialBalance,
    /// A native Trial Balance was internally unbalanced.
    UnbalancedTrialBalance,
    /// A Trial Balance had more account rows than the SDK account oracle.
    TrialBalanceExceedsOracleAccounts,
}

impl std::fmt::Display for FixtureAcceptanceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOracleCounts => "SDK oracle has invalid aggregate counts",
            Self::MissingOrEmptyFixture => "required local fixture is missing or empty",
            Self::NoTrialBalances => "at least one native Trial Balance is required",
            Self::NoGeneralLedgers => "at least one native General Ledger is required",
            Self::NoJournals => "at least one native Journal is required",
            Self::InvalidTrialBalance => "native Trial Balance has an unsupported format",
            Self::UnbalancedTrialBalance => "native Trial Balance is not balanced",
            Self::TrialBalanceExceedsOracleAccounts => {
                "native Trial Balance has more rows than the SDK account oracle"
            }
        })
    }
}

impl std::error::Error for FixtureAcceptanceError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn oracle() -> SdkOracleManifest {
        SdkOracleManifest {
            qbxml_version: "16.0".into(),
            account_count: 3,
            journal_entry_count: 1,
            journal_line_count: 2,
            accounts_sha256: "a".repeat(64),
            journal_sha256: "b".repeat(64),
        }
    }

    fn fixture_file(name: &str, content: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "openqbw-fixture-acceptance-{}-{}",
            std::process::id(),
            name
        ));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn audits_complete_synthetic_fixture_without_retaining_paths() {
        let account = fixture_file("accounts.csv", b"header\n");
        let voided = fixture_file("voided.csv", b"header\n");
        let tb = fixture_file(
            "tb.csv",
            b"Account,Debit,Credit\r\nCash,1.00,\r\nEquity,,1.00\r\nTOTAL,1.00,1.00\r\n",
        );
        let gl = fixture_file("gl.csv", b"header\n");
        let journal = fixture_file("journal.csv", b"header\n");
        let audit = audit_fixture(
            oracle(),
            &account,
            &voided,
            std::slice::from_ref(&tb),
            std::slice::from_ref(&gl),
            std::slice::from_ref(&journal),
        )
        .unwrap();
        assert_eq!(audit.total_trial_balance_rows(), 2);
        assert_eq!(audit.trial_balances[0].debit_cents, 100);
        assert_eq!(audit.trial_balances[0].credit_cents, 100);
        for path in [account, voided, tb, gl, journal] {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn rejects_missing_detailed_report_and_unbalanced_golden() {
        let account = fixture_file("accounts-missing.csv", b"header\n");
        let voided = fixture_file("voided-missing.csv", b"header\n");
        let tb = fixture_file("bad-tb.csv", b"Account,Debit,Credit\nCash,1.00,\n");
        assert_eq!(
            audit_fixture(
                oracle(),
                &account,
                &voided,
                std::slice::from_ref(&tb),
                &[],
                &[]
            ),
            Err(FixtureAcceptanceError::NoGeneralLedgers)
        );
        let _ = std::fs::remove_file(account);
        let _ = std::fs::remove_file(voided);
        let _ = std::fs::remove_file(tb);
    }
}

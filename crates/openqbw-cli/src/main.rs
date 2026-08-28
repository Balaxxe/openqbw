//! `openqbw` command-line tool.
//!
//! Subcommands:
//!
//! ```text
//! openqbw export    <input.qbw> <output.db>   # multi-transaction SQLite export
//! openqbw catalog   <input.qbw>               # SYSTABLE listing
//! openqbw verify    <input.qbw>               # validation summary
//! openqbw indexes   <input.qbw>               # SYSINDEX listing + attribution audit
//! openqbw migrate   <input.qbw> --format=...  # data-liberation export (csv/sqlite/iif)
//! openqbw forensics <input.qbw>               # file-level discovery summary
//! openqbw batch-extract <inputs...>           # deterministic fail-closed batch scaffold
//! openqbw reconcile-trial-balance <reference.csv> <actual.csv>
//! openqbw reconcile-qbw-trial-balance --qbw <input.qbw> --native-tb <reference.csv> ...
//! ```

#[cfg(feature = "research-tools")]
mod account_delta_probe;
mod batch_extract;
mod batch_trial_balance;
#[cfg(feature = "research-tools")]
mod fixture_acceptance;
mod general_ledger_reconciliation;
#[cfg(feature = "research-tools")]
mod posting_delta_probe;
#[cfg(feature = "research-tools")]
mod record_number_bridge_probe;
#[cfg(feature = "research-tools")]
mod rename_structural_probe;
mod report_output;
#[cfg(feature = "research-tools")]
mod sdk_oracle_manifest;
#[cfg(feature = "research-tools")]
mod sdk_oracle_normalization;
#[cfg(feature = "research-tools")]
mod sentinel_identifier_probe;
#[cfg(feature = "research-tools")]
mod snapshot_compare;
mod trial_balance_reconciliation;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::path::PathBuf;

#[cfg(feature = "research-tools")]
use account_delta_probe::{
    ap_aware_to_json as account_delta_ap_aware_probe_to_json, probe_account_delta,
    probe_account_delta_allow_existing, probe_account_delta_ap_aware,
    probe_account_delta_ap_aware_allow_existing, to_json as account_delta_probe_to_json,
};
use anyhow::{Context, Result};
use batch_extract::{MAX_WORKERS, inspect_files as inspect_batch_files, to_json as batch_to_json};
use batch_trial_balance::{parse_manifest_csv, run_batch_trial_balance};
use clap::{Parser, Subcommand};
#[cfg(feature = "research-tools")]
use fixture_acceptance::audit_fixture;
use general_ledger_reconciliation::{
    parse_generated_general_ledger_csv, parse_quickbooks_general_ledger_csv,
    reconcile_general_ledger_postings, resolve_native_account_sections_with_chart,
};
use openqbw::{
    AccountId, AmountType, AttributionGap, CatalogCoverageAttestation, CatalogDefaultAttestation,
    ContentAttribution, CrossValidation, ENTERPRISE24_R21_PARTIAL_TABLE_POLICIES,
    ENTERPRISE24_R21_SCHEMA_MANIFEST, Enterprise24AccountingTable, LineItem,
    MaterializedPostingDate, PageAttribution, QuickBooksAccrualTrialBalancePolicy,
    SourceSnapshotId, SysIndexEntry, SysTableEntry, TransactionHeader, adapt_complete_schema,
    attest_enterprise24_r21_catalog, build_enterprise24_accounting_pipeline,
    collect_enterprise24_bill_table_rows, collect_enterprise24_check_prefix_table_rows,
    collect_enterprise24_general_journal_table_rows, collect_enterprise24_partial_table_rows,
    collect_materialized_syscolumns, collect_materialized_systables,
    discover_enterprise_page_transform_key_in_store, iter_lineitems_with_attribution,
    iter_transaction_headers, scan_enterprise_table_store,
};
use opensqlany::{ApModel, PageStore};
#[cfg(feature = "research-tools")]
use posting_delta_probe::{
    ap_aware_to_json as posting_delta_ap_aware_probe_to_json, parse_marker_argument,
    probe_posting_delta, probe_posting_delta_ap_aware, probe_posting_removal,
    probe_posting_removal_ap_aware, removal_ap_aware_to_json, removal_to_json,
    to_json as posting_delta_probe_to_json,
};
#[cfg(feature = "research-tools")]
use record_number_bridge_probe::{
    probe_record_number_bridge, to_json as record_number_bridge_probe_to_json,
};
#[cfg(feature = "research-tools")]
use rename_structural_probe::{
    probe_account_rename_structure, to_json as rename_structural_probe_to_json,
};
use report_output::{
    ReportBundle, ReportMetadata, TrialBalancePolicyProvenance, account_display_names_with_catalog,
    account_full_names_with_catalog, general_ledger_csv_with_account_catalog,
    general_ledger_json_with_account_catalog, trial_balance_csv_with_account_catalog,
    trial_balance_json_with_account_catalog, write_sqlite_with_account_catalog,
};
use rusqlite::{Connection, Transaction, params};
#[cfg(feature = "research-tools")]
use sdk_oracle_manifest::parse_sdk_oracle_manifest;
#[cfg(feature = "research-tools")]
use sdk_oracle_normalization::normalize_sdk_oracle;
#[cfg(feature = "research-tools")]
use sentinel_identifier_probe::{
    probe_sentinel_identifiers, to_json as sentinel_identifier_probe_to_json,
};
#[cfg(feature = "research-tools")]
use snapshot_compare::{compare_snapshots, to_json as snapshot_compare_to_json};
use trial_balance_reconciliation::{
    parse_quickbooks_trial_balance_csv, parse_trial_balance_csv, reconcile_trial_balances,
    reconciliation_diagnostic_lines,
};

const PHASE5_INVOICE_TOTAL_CENTS: i64 = 39_991_479_278;
const PHASE5_INVOICE_COUNT: i64 = 13_375;

#[derive(Parser, Debug)]
#[command(
    name = "openqbw",
    version,
    about = "QuickBooks .qbw inspector and exporter"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

/// Converts pipeline blockers into a deliberately coarse, privacy-safe
/// diagnostic.  Accounting-report callers need to know which evidence gate is
/// still closed, but must never receive a local page number, record identifier,
/// decoded row value, or source-file path as part of routine CLI output.
fn accounting_blocker_summary(
    blockers: &[openqbw::Enterprise24AccountingPipelineBlocker],
) -> String {
    let mut counts = BTreeMap::<String, u64>::new();
    for blocker in blockers {
        let label = match blocker {
            openqbw::Enterprise24AccountingPipelineBlocker::UnsupportedTable { table_id } => {
                format!("unsupported-table-{table_id}")
            }
            openqbw::Enterprise24AccountingPipelineBlocker::SchemaManifestValidationFailed => {
                "schema-manifest-validation-failed".to_owned()
            }
            openqbw::Enterprise24AccountingPipelineBlocker::SchemaStorageMismatch { table_id } => {
                format!("schema-storage-mismatch-table-{table_id}")
            }
            openqbw::Enterprise24AccountingPipelineBlocker::IncompleteTableCoverage {
                table_id,
            } => {
                format!("incomplete-table-coverage-{table_id}")
            }
            openqbw::Enterprise24AccountingPipelineBlocker::AccountAdaptationFailed { .. } => {
                "account-adaptation-failed".to_owned()
            }
            openqbw::Enterprise24AccountingPipelineBlocker::PostingAdaptationFailed {
                table_id,
                ..
            } => format!("posting-adaptation-failed-table-{table_id}"),
            openqbw::Enterprise24AccountingPipelineBlocker::PostingAccountIdentityUnavailable {
                table_id,
                ..
            } => format!("posting-account-identity-unavailable-table-{table_id}"),
            openqbw::Enterprise24AccountingPipelineBlocker::UnbalancedPostingMasters {
                table_id,
            } => format!("unbalanced-posting-masters-table-{table_id}"),
            openqbw::Enterprise24AccountingPipelineBlocker::LedgerContractRejected => {
                "ledger-contract-rejected".to_owned()
            }
        };
        *counts.entry(label).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(label, count)| format!("{label}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Sanitized coverage evidence for a failed local accounting extraction.
/// Counts describe decoder progress only; no QBW row contents or locations are
/// included.
fn accounting_coverage_summary(
    coverage: &openqbw::Enterprise24AccountingCoverageDiagnostics,
) -> String {
    coverage
        .tables
        .iter()
        .map(|(table_id, table)| {
            format!(
                "table-{table_id}[expected_rows={:?},resolved_rows={},expected_pages={:?},pages={},unresolved={},decode_failures={},directory_disagreements={}]",
                table.expected_logical_records,
                table.resolved_records,
                table.expected_table_pages,
                table.candidate_page_groups,
                table.unresolved_records,
                table.decode_failures,
                table.candidate_directory_disagreements,
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Export transactions and line items to SQLite, attributing each
    /// line item to its source table via SYSTABLE.
    Export {
        /// Input QBW file.
        input: PathBuf,
        /// Output SQLite database (will be overwritten).
        output: PathBuf,
    },
    /// List the SYSTABLE catalog (physical/object IDs and row/page counts)
    /// recovered directly from the QBW file.
    Catalog {
        /// Input QBW file.
        input: PathBuf,
        /// Show only user-looking tables (skip SYS*/ISYS*/RS_*/dbo*).
        #[arg(long)]
        user_only: bool,
    },
    /// Validate an export against known invariants (invoice regression,
    /// journal sum-to-zero, per-table coverage).
    Verify {
        /// Input QBW file.
        input: PathBuf,
        /// Optional output SQLite path. Defaults to a temp file.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Also build a content-signature attribution map and report
        /// per-page agreement against the default position-based
        /// attribution.
        #[arg(long)]
        strict_attribution: bool,
    },
    /// Print recovered columns of a table. SYSCOLUMN.table_id joins
    /// directly to SYSTABLE.table_id.
    Schema {
        /// Input QBW file.
        input: PathBuf,
        /// Table name to inspect.
        table: String,
    },
    /// Print heuristic foreign-key edges inferred from column names
    /// matching `*_id` / `*_id_h` (Phase 6, WP-6B).
    Fkgraph {
        /// Input QBW file.
        input: PathBuf,
        /// Only print edges that resolved to a target table.
        #[arg(long)]
        resolved_only: bool,
    },
    /// Print recovered SYSCOLUMN N/Y nullability counts with sample columns
    /// (Phase 6, WP-6D).
    Nulls {
        /// Input QBW file.
        input: PathBuf,
    },
    /// Validate position-based page attribution against per-table
    /// row-width bands derived from SYSCOLUMN (Phase 6, WP-6Z).
    ValidateAttribution {
        /// Input QBW file.
        input: PathBuf,
    },
    /// List the SYSINDEX catalog and cross-validate the position
    /// legacy comparison against unproven SYSINDEX catalog page candidates
    /// (Phase 6, WP-6Z.3).
    Indexes {
        /// Input QBW file.
        input: PathBuf,
        /// Show only foreign-key indexes (names starting with `fkey_`).
        #[arg(long)]
        fk_only: bool,
        /// Show only the cross-validation summary (no per-index rows).
        #[arg(long)]
        summary_only: bool,
    },
    /// Data-liberation export: emit line items and transaction
    /// headers in a portable format suitable for handing to a
    /// different accounting product or for archival.
    Migrate {
        /// Input QBW file.
        input: PathBuf,
        /// Output destination. For `csv` this is a directory and
        /// will be created if it does not exist; for `sqlite` and
        /// `iif` it is a single output file.
        #[arg(long)]
        out: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = MigrateFormat::Csv)]
        format: MigrateFormat,
    },
    /// File-level forensic discovery summary: size, page-type
    /// histogram, table inventory, and high-level signals useful
    /// for triage in audit or litigation contexts.
    Forensics {
        /// Input QBW file.
        input: PathBuf,
    },
    /// Compare a native QuickBooks Trial Balance CSV with either another
    /// native export or normalized `accounting-report --format csv` output,
    /// exactly account by account and cent by cent.
    ReconcileTrialBalance {
        /// Native QuickBooks Trial Balance CSV used as the golden reference.
        reference: PathBuf,
        /// Trial Balance CSV generated by the extractor.
        actual: PathBuf,
    },
    /// Read a local QBW directly, build an accrual Trial Balance, and compare
    /// it to a native QuickBooks Trial Balance CSV. This is the no-SDK,
    /// no-GUI end-to-end reconciliation workflow; it fails closed if the
    /// installed decoder cannot yet establish a complete ledger.
    ReconcileQbwTrialBalance {
        /// Local QBW input, opened read-only.
        #[arg(long)]
        qbw: PathBuf,
        /// Native QuickBooks Trial Balance CSV used as the golden reference.
        #[arg(long)]
        native_tb: PathBuf,
        /// Inclusive report end date as strict ISO `YYYY-MM-DD`.
        #[arg(long)]
        as_of: String,
        /// First day of the fiscal year containing --as-of.
        #[arg(long)]
        fiscal_year_start: String,
        /// Stable decoded Retained Earnings account identifier.
        #[arg(long)]
        retained_earnings_account_id: String,
        /// Explicit native report label for the selected Retained Earnings
        /// account when company-specific QuickBooks presentation differs from
        /// its chart-of-accounts name. This affects reconciliation identity
        /// only; it never changes the decoded chart.
        #[arg(long)]
        retained_earnings_report_name: Option<String>,
        /// Opaque immutable snapshot label, such as a local content hash.
        #[arg(long)]
        snapshot_id: String,
    },
    /// Read a local QBW directly, serialize its normalized General Ledger,
    /// and reconcile every dated debit/credit movement with a native
    /// QuickBooks Desktop General Ledger CSV. No SDK, GUI, COM, or ODBC is
    /// used. Transaction type/number are reported as unavailable rather than
    /// guessed until their on-disk fields are independently established.
    ReconcileQbwGeneralLedger {
        /// Local QBW input, opened read-only.
        #[arg(long)]
        qbw: PathBuf,
        /// Native QuickBooks Desktop General Ledger CSV used as the golden reference.
        #[arg(long)]
        native_gl: PathBuf,
        /// Inclusive report start as strict ISO YYYY-MM-DD.
        #[arg(long)]
        from: String,
        /// Inclusive report end as strict ISO YYYY-MM-DD.
        #[arg(long)]
        through: String,
        /// Opaque immutable snapshot label, such as a local content hash.
        #[arg(long)]
        snapshot_id: String,
    },
    /// Extract one validated normalized accounting report directly from a local
    /// QBW file. This path is read-only and has no SDK, COM, GUI, or ODBC use.
    AccountingReport {
        /// Input QBW file, opened read-only.
        input: PathBuf,
        /// Report to emit.
        #[arg(long, value_enum)]
        report: AccountingReportKind,
        /// Inclusive report end date as strict ISO `YYYY-MM-DD`.
        #[arg(long)]
        as_of: String,
        /// Required only for a QuickBooks accrual Trial Balance: first day of
        /// the fiscal year containing --as-of.
        #[arg(long)]
        fiscal_year_start: Option<String>,
        /// Required only for a QuickBooks accrual Trial Balance: stable decoded
        /// Retained Earnings account identifier.
        #[arg(long)]
        retained_earnings_account_id: Option<String>,
        /// Optional explicit native report label for the selected Retained
        /// Earnings account. Applies only to Trial Balance presentation.
        #[arg(long)]
        retained_earnings_report_name: Option<String>,
        /// Include zero-balance accounts in a Trial Balance output.
        #[arg(long)]
        include_zero_balance_accounts: bool,
        /// Caller-controlled, non-secret entity label stored in the output.
        #[arg(long)]
        entity_id: String,
        /// Caller-controlled source label; never defaults to the local path.
        #[arg(long)]
        source_label: String,
        /// Caller-controlled generation timestamp (ISO-8601); never inferred
        /// from the host clock.
        #[arg(long)]
        generated_at: String,
        /// Opaque immutable snapshot label, such as a local content hash.
        #[arg(long)]
        snapshot_id: String,
        /// Output format.
        #[arg(long, value_enum)]
        format: AccountingReportFormat,
        /// New output file. Existing files are never overwritten.
        #[arg(long)]
        out: PathBuf,
    },
    #[cfg(feature = "research-tools")]
    /// Inspect a controlled SDK-oracle manifest without parsing or printing
    /// QBXML/company data. This is research-only and is not a QBW extractor.
    InspectSdkOracleManifest {
        /// JSON manifest emitted by the read-only disposable-fixture harness.
        manifest: PathBuf,
    },
    #[cfg(feature = "research-tools")]
    /// Validate controlled SDK artifacts and create private local TSV fixtures
    /// for research probes. No QBXML or normalized rows are printed.
    NormalizeSdkOracle {
        /// JSON manifest emitted by the read-only disposable-fixture harness.
        manifest: PathBuf,
        /// Local AccountQueryRs QBXML response.
        accounts: PathBuf,
        /// Local JournalEntryQueryRs QBXML response.
        journal: PathBuf,
        /// Private local directory for new TSV files; existing outputs are never overwritten.
        #[arg(long)]
        out_dir: PathBuf,
    },
    #[cfg(feature = "research-tools")]
    /// Audit a local native-report/SDK-oracle fixture before direct-QBW
    /// accounting acceptance. It neither reads QBXML payloads nor decodes QBW.
    FixtureAudit {
        /// Privacy-safe JSON manifest emitted by the read-only SDK oracle.
        #[arg(long)]
        sdk_manifest: PathBuf,
        /// Native QuickBooks Account Listing report.
        #[arg(long)]
        account_listing: PathBuf,
        /// Native QuickBooks voided/deleted transaction-detail report.
        #[arg(long)]
        voided_deleted: PathBuf,
        /// One or more native accrual Trial Balance reports.
        #[arg(long, required = true, num_args = 1..)]
        trial_balance: Vec<PathBuf>,
        /// One or more native accrual General Ledger reports.
        #[arg(long, required = true, num_args = 1..)]
        general_ledger: Vec<PathBuf>,
        /// One or more native accrual Journal reports.
        #[arg(long, required = true, num_args = 1..)]
        journal: Vec<PathBuf>,
    },
    /// Inspect multiple copied QBW files in parallel with deterministic,
    /// machine-readable per-file results. Accounting extraction is currently
    /// fail-closed as unsupported until decoder coverage is complete.
    BatchExtract {
        /// Input files. Each is read independently and never modified.
        #[arg(required = true, num_args = 1..)]
        inputs: Vec<PathBuf>,
        /// Maximum simultaneous file readers (1 through 8).
        #[arg(long, default_value_t = default_batch_workers())]
        workers: usize,
    },
    /// Produce one all-or-nothing consolidated SQLite Trial Balance database
    /// from a private local CSV manifest. Every input is decoded directly and
    /// read-only; no QuickBooks SDK, COM, GUI, or ODBC service is used.
    BatchTrialBalance {
        /// CSV manifest with exactly entity_id,qbw_path,snapshot_id,
        /// fiscal_year_start,retained_earnings_account_id,
        /// retained_earnings_report_name columns.
        #[arg(long)]
        manifest: PathBuf,
        /// Inclusive report end date as strict ISO YYYY-MM-DD.
        #[arg(long)]
        as_of: String,
        /// Maximum simultaneous local QBW readers (1 through 8).
        #[arg(long, default_value_t = default_batch_workers())]
        workers: usize,
        /// Caller-supplied ISO-8601 generation timestamp retained in report metadata.
        #[arg(long)]
        generated_at: String,
        /// New consolidated SQLite output. Existing paths are never opened or overwritten.
        #[arg(long)]
        out: PathBuf,
    },
    #[cfg(feature = "research-tools")]
    /// Compare two immutable, page-aligned QBW snapshots without emitting
    /// company contents, paths, page offsets, or page numbers. This is a
    /// controlled-delta research tool, not an accounting extractor.
    CompareSnapshots {
        /// Earlier local QBW snapshot.
        before: PathBuf,
        /// Later local QBW snapshot with exactly the same byte length.
        after: PathBuf,
        /// Optional JSON from a prior no-op/control comparison. Its opaque
        /// page hash transitions are subtracted only on exact hash-pair match.
        #[arg(long)]
        control_noise_manifest: Option<PathBuf>,
        /// Explicit caller label to include for the before input. Paths are
        /// never emitted.
        #[arg(long, requires = "after_source_identifier")]
        before_source_identifier: Option<String>,
        /// Explicit caller label to include for the after input. Paths are
        /// never emitted.
        #[arg(long, requires = "before_source_identifier")]
        after_source_identifier: Option<String>,
        /// Write the JSON manifest to a new file instead of stdout. Existing
        /// files are never overwritten.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    #[cfg(feature = "research-tools")]
    /// Scan only caller-supplied synthetic account markers in the net effect
    /// of a controlled account-creation delta. It emits aggregate evidence,
    /// never page positions, paths, contextual bytes, or other company data.
    ProbeAccountDelta {
        /// Earlier local QBW snapshot.
        before: PathBuf,
        /// Later local QBW snapshot with exactly the same byte length.
        after: PathBuf,
        /// Required no-edit control manifest from `compare-snapshots`.
        #[arg(long)]
        control_noise_manifest: PathBuf,
        /// Known synthetic ASCII marker. Pass each sentinel account number,
        /// name, and description explicitly; no wildcard/regex is supported.
        #[arg(long = "literal", required = true, num_args = 1..)]
        literals: Vec<String>,
        /// Also attempt the QuickBooks SA17 AP transform. This remains a
        /// sentinel-only research probe, not an account decoder.
        #[arg(long)]
        ap_aware: bool,
        /// Permit approved synthetic markers already present in the before
        /// snapshot. This is only for controlled mutations of a previously
        /// created sentinel account (for example, a rename); it weakens the
        /// creation probe's collision guard and never establishes identity.
        #[arg(long)]
        allow_existing_literals: bool,
        /// Write the JSON result to a new file instead of stdout. Existing
        /// files are never overwritten.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    #[cfg(feature = "research-tools")]
    /// Pair only caller-supplied synthetic account-rename markers. The result
    /// is aggregate structural evidence, never account rows or fields.
    ProbeAccountRenameStructure {
        /// Earlier local snapshot containing the old synthetic account name.
        before: PathBuf,
        /// Later local snapshot containing the new synthetic account name.
        after: PathBuf,
        /// Required no-edit control manifest from `compare-snapshots`.
        #[arg(long)]
        control_noise_manifest: PathBuf,
        /// Old synthetic account name.
        #[arg(long)]
        old_name: String,
        /// New synthetic account name.
        #[arg(long)]
        new_name: String,
        /// Stable synthetic value, such as the account number or description.
        #[arg(long = "stable-literal", required = true, num_args = 1..)]
        stable_literals: Vec<String>,
        /// Write JSON to a new file; existing files are never overwritten.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    #[cfg(feature = "research-tools")]
    /// Scan only caller-supplied synthetic transaction markers in one
    /// controlled posting delta. It is evidence collection, not a posting
    /// decoder; dates, IDs, amounts, and current-state fields remain unproven.
    ProbePostingDelta {
        /// Earlier local QBW snapshot.
        before: PathBuf,
        /// Later local QBW snapshot with exactly the same byte length.
        after: PathBuf,
        /// Required no-edit control manifest from `compare-snapshots`.
        #[arg(long)]
        control_noise_manifest: PathBuf,
        /// Synthetic marker as `lowercase-role=ASCII-literal`. Roles are
        /// labels such as line-memo-1 through line-memo-4, document-number,
        /// or account. The controlled JE fixture has no header memo marker.
        #[arg(long = "marker", required = true, num_args = 1..)]
        markers: Vec<String>,
        /// Opt in to candidate-only SA17 AP recovery. The full before image
        /// remains collision-checked for new transaction markers; only
        /// `account` / `account-*` synthetic roles may already exist.
        #[arg(long)]
        ap_aware: bool,
        /// Treat the chronological pair as a controlled deletion. Non-account
        /// markers must be present before and absent after; account controls
        /// may preexist in both. This is explicit removal analysis, never a
        /// creation probe with input order reversed.
        #[arg(long)]
        removal: bool,
        /// Write the JSON result to a new file instead of stdout. Existing
        /// files are never overwritten.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    #[cfg(feature = "research-tools")]
    /// Search only aggregate, mechanically derived representations of the
    /// one TxnID and four TxnLineIDs in a controlled synthetic oracle.
    ProbeSentinelIdentifiers {
        before: PathBuf,
        after: PathBuf,
        #[arg(long)]
        control_noise_manifest: PathBuf,
        /// Local, read-only JournalEntryQuery response for the synthetic JE.
        #[arg(long)]
        journal_oracle: PathBuf,
        /// Exact synthetic document number that selects the single JE.
        #[arg(long)]
        document_number: String,
        /// Synthetic marker used only for aggregate page co-location.
        #[arg(long = "marker", required = true, num_args = 1..)]
        markers: Vec<String>,
        /// Write JSON to a new file; existing files are never overwritten.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    #[cfg(feature = "research-tools")]
    /// Test bounded numeric encodings of controlled QBXML record-number
    /// components. Output is aggregate-only; it never emits IDs, values,
    /// bytes, paths, offsets, or page locations.
    ProbeRecordNumberBridge {
        before: PathBuf,
        after: PathBuf,
        #[arg(long)]
        control_noise_manifest: PathBuf,
        #[arg(long)]
        journal_oracle: PathBuf,
        #[arg(long)]
        account_oracle: PathBuf,
        #[arg(long)]
        document_number: String,
        #[arg(long)]
        account_marker: String,
        #[arg(long = "marker", required = true, num_args = 1..)]
        markers: Vec<String>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum MigrateFormat {
    /// One CSV file per output kind into a directory.
    Csv,
    /// A single SQLite database file (equivalent to `openqbw export`).
    Sqlite,
    /// Intuit Interchange Format (IIF), a tab-separated text format
    /// importable by many accounting products.
    Iif,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum AccountingReportKind {
    /// QuickBooks-style accrual Trial Balance, including prior-period P&L
    /// roll-forward into the explicitly named Retained Earnings account.
    TrialBalance,
    /// Transaction-level General Ledger through the requested as-of day.
    GeneralLedger,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum AccountingReportFormat {
    Csv,
    Json,
    Sqlite,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Export { input, output } => run_export(input, output).map(|_| ()),
        Cmd::Catalog { input, user_only } => run_catalog(input, user_only),
        Cmd::Verify {
            input,
            output,
            strict_attribution,
        } => run_verify(input, output, strict_attribution),
        Cmd::Schema { input, table } => run_schema(input, table),
        Cmd::Fkgraph {
            input,
            resolved_only,
        } => run_fkgraph(input, resolved_only),
        Cmd::Nulls { input } => run_nulls(input),
        Cmd::ValidateAttribution { input } => run_validate_attribution(input),
        Cmd::Indexes {
            input,
            fk_only,
            summary_only,
        } => run_indexes(input, fk_only, summary_only),
        Cmd::Migrate { input, out, format } => run_migrate(input, out, format),
        Cmd::Forensics { input } => run_forensics(input),
        Cmd::ReconcileTrialBalance { reference, actual } => {
            run_reconcile_trial_balance(reference, actual)
        }
        Cmd::ReconcileQbwTrialBalance {
            qbw,
            native_tb,
            as_of,
            fiscal_year_start,
            retained_earnings_account_id,
            retained_earnings_report_name,
            snapshot_id,
        } => run_reconcile_qbw_trial_balance(
            qbw,
            native_tb,
            as_of,
            fiscal_year_start,
            retained_earnings_account_id,
            retained_earnings_report_name,
            snapshot_id,
        ),
        Cmd::ReconcileQbwGeneralLedger {
            qbw,
            native_gl,
            from,
            through,
            snapshot_id,
        } => run_reconcile_qbw_general_ledger(qbw, native_gl, from, through, snapshot_id),
        Cmd::AccountingReport {
            input,
            report,
            as_of,
            fiscal_year_start,
            retained_earnings_account_id,
            retained_earnings_report_name,
            include_zero_balance_accounts,
            entity_id,
            source_label,
            generated_at,
            snapshot_id,
            format,
            out,
        } => run_accounting_report(
            input,
            report,
            as_of,
            fiscal_year_start,
            retained_earnings_account_id,
            retained_earnings_report_name,
            include_zero_balance_accounts,
            entity_id,
            source_label,
            generated_at,
            snapshot_id,
            format,
            out,
        ),
        #[cfg(feature = "research-tools")]
        Cmd::InspectSdkOracleManifest { manifest } => run_inspect_sdk_oracle_manifest(manifest),
        #[cfg(feature = "research-tools")]
        Cmd::NormalizeSdkOracle {
            manifest,
            accounts,
            journal,
            out_dir,
        } => run_normalize_sdk_oracle(manifest, accounts, journal, out_dir),
        #[cfg(feature = "research-tools")]
        Cmd::FixtureAudit {
            sdk_manifest,
            account_listing,
            voided_deleted,
            trial_balance,
            general_ledger,
            journal,
        } => run_fixture_audit(
            sdk_manifest,
            account_listing,
            voided_deleted,
            trial_balance,
            general_ledger,
            journal,
        ),
        Cmd::BatchExtract { inputs, workers } => run_batch_extract(inputs, workers),
        Cmd::BatchTrialBalance {
            manifest,
            as_of,
            workers,
            generated_at,
            out,
        } => run_batch_trial_balance_command(manifest, as_of, workers, generated_at, out),
        #[cfg(feature = "research-tools")]
        Cmd::CompareSnapshots {
            before,
            after,
            control_noise_manifest,
            before_source_identifier,
            after_source_identifier,
            output,
        } => run_compare_snapshots(
            before,
            after,
            control_noise_manifest,
            before_source_identifier,
            after_source_identifier,
            output,
        ),
        #[cfg(feature = "research-tools")]
        Cmd::ProbeAccountDelta {
            before,
            after,
            control_noise_manifest,
            literals,
            ap_aware,
            allow_existing_literals,
            output,
        } => run_probe_account_delta(
            before,
            after,
            control_noise_manifest,
            literals,
            ap_aware,
            allow_existing_literals,
            output,
        ),
        #[cfg(feature = "research-tools")]
        Cmd::ProbeAccountRenameStructure {
            before,
            after,
            control_noise_manifest,
            old_name,
            new_name,
            stable_literals,
            output,
        } => run_probe_account_rename_structure(
            before,
            after,
            control_noise_manifest,
            old_name,
            new_name,
            stable_literals,
            output,
        ),
        #[cfg(feature = "research-tools")]
        Cmd::ProbePostingDelta {
            before,
            after,
            control_noise_manifest,
            markers,
            ap_aware,
            removal,
            output,
        } => run_probe_posting_delta(
            before,
            after,
            control_noise_manifest,
            markers,
            ap_aware,
            removal,
            output,
        ),
        #[cfg(feature = "research-tools")]
        Cmd::ProbeSentinelIdentifiers {
            before,
            after,
            control_noise_manifest,
            journal_oracle,
            document_number,
            markers,
            output,
        } => run_probe_sentinel_identifiers(
            before,
            after,
            control_noise_manifest,
            journal_oracle,
            document_number,
            markers,
            output,
        ),
        #[cfg(feature = "research-tools")]
        Cmd::ProbeRecordNumberBridge {
            before,
            after,
            control_noise_manifest,
            journal_oracle,
            account_oracle,
            document_number,
            account_marker,
            markers,
            output,
        } => run_probe_record_number_bridge(
            before,
            after,
            control_noise_manifest,
            journal_oracle,
            account_oracle,
            document_number,
            account_marker,
            markers,
            output,
        ),
    }
}

fn default_batch_workers() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .clamp(1, MAX_WORKERS.min(8))
}

fn run_batch_extract(inputs: Vec<PathBuf>, workers: usize) -> Result<()> {
    let run = inspect_batch_files(inputs, workers).map_err(anyhow::Error::msg)?;
    println!("{}", batch_to_json(&run));
    Ok(())
}

fn run_batch_trial_balance_command(
    manifest: PathBuf,
    as_of: String,
    workers: usize,
    generated_at: String,
    out: PathBuf,
) -> Result<()> {
    // Parse before opening any company file. Errors intentionally omit the
    // manifest path and private values such as local paths and company labels.
    let bytes =
        std::fs::read(&manifest).map_err(|_| anyhow::anyhow!("reading batch manifest failed"))?;
    let inputs = parse_manifest_csv(&bytes).map_err(anyhow::Error::msg)?;
    run_batch_trial_balance(
        inputs,
        &as_of,
        workers,
        &generated_at,
        &out,
        build_local_enterprise24_ledger,
    )
    .map_err(anyhow::Error::msg)?;
    println!("consolidated Trial Balance written (local read-only extraction)");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_accounting_report(
    input: PathBuf,
    report_kind: AccountingReportKind,
    as_of: String,
    fiscal_year_start: Option<String>,
    retained_earnings_account_id: Option<String>,
    retained_earnings_report_name: Option<String>,
    include_zero_balance_accounts: bool,
    entity_id: String,
    source_label: String,
    generated_at: String,
    snapshot_id: String,
    format: AccountingReportFormat,
    out: PathBuf,
) -> Result<()> {
    if out.exists() {
        anyhow::bail!("refusing to overwrite existing report output");
    }
    let as_of = MaterializedPostingDate::parse_iso_date(&as_of)
        .context("parsing --as-of as strict ISO YYYY-MM-DD")?;
    let as_of_day = as_of.accounting_date();
    let mut metadata = ReportMetadata {
        entity_id,
        source_file: source_label,
        parser_version: env!("CARGO_PKG_VERSION").to_owned(),
        generated_at,
        trial_balance_policy: None,
    };
    metadata.validate().map_err(anyhow::Error::msg)?;
    let ledger = build_local_enterprise24_ledger(&input, snapshot_id)?;
    let account_catalog = ledger.accounts().cloned().collect::<Vec<_>>();

    match report_kind {
        AccountingReportKind::TrialBalance => {
            let fiscal_year_start = fiscal_year_start.context(
                "--fiscal-year-start is required for a QuickBooks accrual Trial Balance",
            )?;
            let fiscal_year_start = MaterializedPostingDate::parse_iso_date(&fiscal_year_start)
                .context("parsing --fiscal-year-start as strict ISO YYYY-MM-DD")?;
            if fiscal_year_start.accounting_date() > as_of_day {
                anyhow::bail!("--fiscal-year-start must not be after --as-of");
            }
            let retained_earnings_account_id = retained_earnings_account_id.context(
                "--retained-earnings-account-id is required for a QuickBooks accrual Trial Balance",
            )?;
            let retained_earnings_account_id = AccountId::new(retained_earnings_account_id)
                .context("invalid --retained-earnings-account-id")?;
            let policy = QuickBooksAccrualTrialBalancePolicy::new(
                fiscal_year_start.accounting_date(),
                retained_earnings_account_id.clone(),
            );
            metadata.trial_balance_policy = Some(TrialBalancePolicyProvenance {
                source: "explicit".to_owned(),
                fiscal_year_start: fiscal_year_start.to_iso_date(),
                as_of: as_of.to_iso_date(),
                retained_earnings_account_id: retained_earnings_account_id.as_str().to_owned(),
                retained_earnings_report_name: retained_earnings_report_name.clone(),
            });
            let trial_balance = ledger
                .quickbooks_accrual_trial_balance_as_of(
                    as_of_day,
                    openqbw::TrialBalanceOptions {
                        include_zero_balance_accounts,
                    },
                    &policy,
                )
                .context("building validated QuickBooks accrual Trial Balance")?;
            if retained_earnings_report_name
                .as_deref()
                .is_some_and(|name| name.trim().is_empty())
            {
                anyhow::bail!("--retained-earnings-report-name must not be empty");
            }
            match format {
                AccountingReportFormat::Csv => write_new_report(
                    &out,
                    &trial_balance_csv_with_account_catalog(
                        &trial_balance,
                        &metadata,
                        &account_catalog,
                    )
                    .map_err(anyhow::Error::msg)?,
                )?,
                AccountingReportFormat::Json => write_new_report(
                    &out,
                    &trial_balance_json_with_account_catalog(
                        &trial_balance,
                        &metadata,
                        &account_catalog,
                    )
                    .map_err(anyhow::Error::msg)?,
                )?,
                AccountingReportFormat::Sqlite => write_report_sqlite(
                    &out,
                    &metadata,
                    ReportBundle {
                        trial_balance: Some(&trial_balance),
                        general_ledger: None,
                    },
                    &account_catalog,
                )?,
            }
        }
        AccountingReportKind::GeneralLedger => {
            if fiscal_year_start.is_some()
                || retained_earnings_account_id.is_some()
                || retained_earnings_report_name.is_some()
                || include_zero_balance_accounts
            {
                anyhow::bail!("Trial Balance policy options apply only to --report trial-balance");
            }
            let general_ledger = ledger
                .general_ledger_as_of(as_of_day)
                .context("building validated General Ledger")?;
            match format {
                AccountingReportFormat::Csv => write_new_report(
                    &out,
                    &general_ledger_csv_with_account_catalog(
                        &general_ledger,
                        &metadata,
                        &account_catalog,
                    )
                    .map_err(anyhow::Error::msg)?,
                )?,
                AccountingReportFormat::Json => write_new_report(
                    &out,
                    &general_ledger_json_with_account_catalog(
                        &general_ledger,
                        &metadata,
                        &account_catalog,
                    )
                    .map_err(anyhow::Error::msg)?,
                )?,
                AccountingReportFormat::Sqlite => write_report_sqlite(
                    &out,
                    &metadata,
                    ReportBundle {
                        trial_balance: None,
                        general_ledger: Some(&general_ledger),
                    },
                    &account_catalog,
                )?,
            }
        }
    }
    println!("accounting report written (local read-only extraction)");
    Ok(())
}

fn write_new_report(path: &std::path::Path, contents: &str) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating report output {path:?}"))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("writing report output {path:?}"))
}

fn write_report_sqlite(
    path: &std::path::Path,
    metadata: &ReportMetadata,
    bundle: ReportBundle<'_>,
    account_catalog: &[openqbw::Account],
) -> Result<()> {
    // Reserve the destination first with create_new so a preexisting report is
    // never opened or modified by SQLite.
    std::fs::File::create_new(path)
        .with_context(|| format!("creating SQLite report output {path:?}"))?;
    let connection = Connection::open(path)
        .with_context(|| format!("opening new SQLite report output {path:?}"))?;
    let mut connection = connection;
    write_sqlite_with_account_catalog(&mut connection, metadata, bundle, account_catalog)
        .map_err(anyhow::Error::msg)
}

fn build_local_enterprise24_ledger(
    input: &std::path::Path,
    snapshot_id: String,
) -> Result<openqbw::Ledger> {
    let store = PageStore::open(input).context("opening local QBW input")?;
    let transform_key = discover_enterprise_page_transform_key_in_store(&store)
        .context("discovering Enterprise page materialization key")?;
    let catalog = collect_materialized_syscolumns(&store, transform_key)
        .context("collecting bounded Enterprise SYSCOLUMN catalog")?;
    // Validate the whole compatibility catalog before adapting any table. The
    // resulting envelope bytes remain opaque `SYSCOLUMN` metadata; this does
    // not make any claim about application-row defaults or compression.
    let validated_catalog = attest_enterprise24_r21_catalog(&catalog.columns)
        .context("validating complete Enterprise 24 R21 SYSCOLUMN manifest")?;
    let tables = collect_materialized_systables(&store, transform_key)
        .context("collecting bounded Enterprise SYSTABLE catalog")?;
    let required_table_ids: Vec<_> = ENTERPRISE24_R21_SCHEMA_MANIFEST
        .iter()
        .map(|entry| entry.table_id)
        .collect();
    tables
        .require_unambiguous_tables(&required_table_ids)
        .context("attesting unambiguous materialized SYSTABLE expectations for required tables")?;
    let scan = scan_enterprise_table_store(&store, transform_key)
        .context("scanning local QBW accounting table carriers")?;
    let mut schemas = BTreeMap::new();
    let mut account_rows = None;
    let mut posting_rows = Vec::new();

    for policy in ENTERPRISE24_R21_PARTIAL_TABLE_POLICIES {
        let expectation_entry = tables.table(policy.table.id()).with_context(|| {
            format!(
                "missing independent SYSTABLE expectation for table {}",
                policy.table.id()
            )
        })?;
        let expectation = openqbw::Enterprise24TableCoverageExpectation::from(expectation_entry);
        let table_scan = scan
            .for_table(policy.table.id())
            .with_context(|| format!("selecting materialized table {}", policy.table.id()))?;
        let rows = match policy.table {
            Enterprise24AccountingTable::BillLine => {
                collect_enterprise24_bill_table_rows(&table_scan, expectation)
                    .context("collecting dedicated Bill table carriers")?
            }
            Enterprise24AccountingTable::CheckLine => {
                let storage = policy.storage.with_context(
                    || "dedicated Check prefix collector requires a proven storage policy",
                )?;
                let expected_count = ENTERPRISE24_R21_SCHEMA_MANIFEST
                    .iter()
                    .find(|manifest| manifest.table_id == policy.table.id())
                    .context("missing schema manifest for Check table")?
                    .column_count;
                let columns = catalog
                    .complete_materialized_schema_columns(policy.table.id(), expected_count)
                    .context("attesting complete schema for Check table")?;
                let default_envelopes = validated_catalog
                    .default_envelopes(policy.table.id())
                    .context("collecting manifest-bound catalog defaults for Check table")?;
                let schema = adapt_complete_schema(
                    &columns,
                    CatalogCoverageAttestation::new(policy.table.id(), expected_count)?,
                    storage,
                    CatalogDefaultAttestation {
                        envelopes: &default_envelopes,
                    },
                )
                .context("building schema for Check table")?;
                schemas.insert(policy.table.id(), schema.clone());
                collect_enterprise24_check_prefix_table_rows(&table_scan, &schema, expectation)
                    .context("collecting dedicated Check prefix table carriers")?
            }
            Enterprise24AccountingTable::GeneralJournalLine => {
                collect_enterprise24_general_journal_table_rows(&table_scan, expectation)
                    .context("collecting dedicated General Journal table carriers")?
            }
            _ => {
                let storage = policy.storage.with_context(|| {
                    format!(
                        "generic accounting collector has no proven storage policy for table {}",
                        policy.table.id()
                    )
                })?;
                let expected_count = ENTERPRISE24_R21_SCHEMA_MANIFEST
                    .iter()
                    .find(|manifest| manifest.table_id == policy.table.id())
                    .with_context(|| {
                        format!("missing schema manifest for table {}", policy.table.id())
                    })?
                    .column_count;
                let columns = catalog
                    .complete_materialized_schema_columns(policy.table.id(), expected_count)
                    .with_context(|| {
                        format!("attesting complete schema for table {}", policy.table.id())
                    })?;
                let default_envelopes = validated_catalog
                    .default_envelopes(policy.table.id())
                    .with_context(|| {
                        format!(
                            "collecting manifest-bound catalog defaults for table {}",
                            policy.table.id()
                        )
                    })?;
                let schema = adapt_complete_schema(
                    &columns,
                    CatalogCoverageAttestation::new(policy.table.id(), expected_count)?,
                    storage,
                    CatalogDefaultAttestation {
                        envelopes: &default_envelopes,
                    },
                )
                .with_context(|| format!("building schema for table {}", policy.table.id()))?;
                schemas.insert(policy.table.id(), schema.clone());
                collect_enterprise24_partial_table_rows(&table_scan, policy, &schema, expectation)
                    .with_context(|| format!("collecting accounting table {}", policy.table.id()))?
            }
        };
        if policy.table == Enterprise24AccountingTable::AccountUser {
            account_rows = Some(rows);
        } else {
            posting_rows.push(rows);
        }
    }
    let account_rows = account_rows.context("Enterprise account table policy missing")?;
    let snapshot = SourceSnapshotId::new(snapshot_id).context("invalid --snapshot-id")?;
    let result = build_enterprise24_accounting_pipeline(
        snapshot,
        &catalog.columns,
        &account_rows,
        &posting_rows,
        &schemas,
    );
    result.ledger.with_context(|| {
        format!(
            "accounting extraction is incomplete; {} fail-closed blocker(s): {}; coverage: {}",
            result.diagnostics.blockers.len(),
            accounting_blocker_summary(&result.diagnostics.blockers),
            accounting_coverage_summary(&result.diagnostics),
        )
    })
}

#[cfg(feature = "research-tools")]
fn run_compare_snapshots(
    before: PathBuf,
    after: PathBuf,
    control_noise_manifest: Option<PathBuf>,
    before_source_identifier: Option<String>,
    after_source_identifier: Option<String>,
    output: Option<PathBuf>,
) -> Result<()> {
    let comparison = compare_snapshots(&before, &after, control_noise_manifest.as_deref())
        .map_err(anyhow::Error::msg)?;
    let json = snapshot_compare_to_json(
        &comparison,
        before_source_identifier.as_deref(),
        after_source_identifier.as_deref(),
    );
    if let Some(path) = output {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("creating snapshot comparison output {path:?}"))?;
        file.write_all(json.as_bytes())
            .with_context(|| format!("writing snapshot comparison output {path:?}"))?;
    } else {
        println!("{json}");
    }
    Ok(())
}

#[cfg(feature = "research-tools")]
fn run_probe_account_delta(
    before: PathBuf,
    after: PathBuf,
    control_noise_manifest: PathBuf,
    literals: Vec<String>,
    ap_aware: bool,
    allow_existing_literals: bool,
    output: Option<PathBuf>,
) -> Result<()> {
    let json = if ap_aware {
        let probe = if allow_existing_literals {
            probe_account_delta_ap_aware_allow_existing(
                &before,
                &after,
                &control_noise_manifest,
                &literals,
            )
        } else {
            probe_account_delta_ap_aware(&before, &after, &control_noise_manifest, &literals)
        }
        .map_err(anyhow::Error::msg)?;
        account_delta_ap_aware_probe_to_json(&probe)
    } else {
        let probe = if allow_existing_literals {
            probe_account_delta_allow_existing(&before, &after, &control_noise_manifest, &literals)
        } else {
            probe_account_delta(&before, &after, &control_noise_manifest, &literals)
        }
        .map_err(anyhow::Error::msg)?;
        account_delta_probe_to_json(&probe)
    };
    if let Some(path) = output {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("creating account delta probe output {path:?}"))?;
        file.write_all(json.as_bytes())
            .with_context(|| format!("writing account delta probe output {path:?}"))?;
    } else {
        println!("{json}");
    }
    Ok(())
}

#[cfg(feature = "research-tools")]
fn run_probe_account_rename_structure(
    before: PathBuf,
    after: PathBuf,
    control_noise_manifest: PathBuf,
    old_name: String,
    new_name: String,
    stable_literals: Vec<String>,
    output: Option<PathBuf>,
) -> Result<()> {
    let probe = probe_account_rename_structure(
        &before,
        &after,
        &control_noise_manifest,
        &old_name,
        &new_name,
        &stable_literals,
    )
    .map_err(anyhow::Error::msg)?;
    let json = rename_structural_probe_to_json(&probe);
    if let Some(path) = output {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("creating rename structural probe output {path:?}"))?;
        file.write_all(json.as_bytes())
            .with_context(|| format!("writing rename structural probe output {path:?}"))?;
    } else {
        println!("{json}");
    }
    Ok(())
}

#[cfg(feature = "research-tools")]
fn run_probe_posting_delta(
    before: PathBuf,
    after: PathBuf,
    control_noise_manifest: PathBuf,
    markers: Vec<String>,
    ap_aware: bool,
    removal: bool,
    output: Option<PathBuf>,
) -> Result<()> {
    let markers = markers
        .iter()
        .map(|marker| parse_marker_argument(marker))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(anyhow::Error::msg)?;
    let json = if removal && ap_aware {
        let probe =
            probe_posting_removal_ap_aware(&before, &after, &control_noise_manifest, &markers)
                .map_err(anyhow::Error::msg)?;
        removal_ap_aware_to_json(&probe)
    } else if removal {
        let probe = probe_posting_removal(&before, &after, &control_noise_manifest, &markers)
            .map_err(anyhow::Error::msg)?;
        removal_to_json(&probe)
    } else if ap_aware {
        let probe =
            probe_posting_delta_ap_aware(&before, &after, &control_noise_manifest, &markers)
                .map_err(anyhow::Error::msg)?;
        posting_delta_ap_aware_probe_to_json(&probe)
    } else {
        let probe = probe_posting_delta(&before, &after, &control_noise_manifest, &markers)
            .map_err(anyhow::Error::msg)?;
        posting_delta_probe_to_json(&probe)
    };
    if let Some(path) = output {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("creating posting delta probe output {path:?}"))?;
        file.write_all(json.as_bytes())
            .with_context(|| format!("writing posting delta probe output {path:?}"))?;
    } else {
        println!("{json}");
    }
    Ok(())
}

#[cfg(feature = "research-tools")]
fn run_probe_sentinel_identifiers(
    before: PathBuf,
    after: PathBuf,
    control_noise_manifest: PathBuf,
    journal_oracle: PathBuf,
    document_number: String,
    markers: Vec<String>,
    output: Option<PathBuf>,
) -> Result<()> {
    let probe = probe_sentinel_identifiers(
        &before,
        &after,
        &control_noise_manifest,
        &journal_oracle,
        &document_number,
        &markers,
    )
    .map_err(anyhow::Error::msg)?;
    let json = sentinel_identifier_probe_to_json(&probe);
    if let Some(path) = output {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("creating sentinel identifier probe output {path:?}"))?;
        file.write_all(json.as_bytes())
            .with_context(|| format!("writing sentinel identifier probe output {path:?}"))?;
    } else {
        println!("{json}");
    }
    Ok(())
}

#[cfg(feature = "research-tools")]
#[allow(clippy::too_many_arguments)]
fn run_probe_record_number_bridge(
    before: PathBuf,
    after: PathBuf,
    control_noise_manifest: PathBuf,
    journal_oracle: PathBuf,
    account_oracle: PathBuf,
    document_number: String,
    account_marker: String,
    markers: Vec<String>,
    output: Option<PathBuf>,
) -> Result<()> {
    let probe = probe_record_number_bridge(
        &before,
        &after,
        &control_noise_manifest,
        &journal_oracle,
        &account_oracle,
        &document_number,
        &account_marker,
        &markers,
    )
    .map_err(anyhow::Error::msg)?;
    let json = record_number_bridge_probe_to_json(&probe);
    if let Some(path) = output {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("creating record-number bridge output {path:?}"))?;
        file.write_all(json.as_bytes())
            .with_context(|| format!("writing record-number bridge output {path:?}"))?;
    } else {
        println!("{json}");
    }
    Ok(())
}

#[cfg(feature = "research-tools")]
fn run_inspect_sdk_oracle_manifest(manifest: PathBuf) -> Result<()> {
    let bytes = std::fs::read(manifest).context("reading SDK oracle manifest")?;
    let summary = parse_sdk_oracle_manifest(&bytes).context("parsing SDK oracle manifest")?;
    // Do not print the manifest's company_file path or load QBXML artifacts.
    println!(
        "sdk_oracle_manifest read_only=true qbxml_version={} account_count={} journal_entry_count={} journal_line_count={} accounts_sha256={} journal_sha256={}",
        summary.qbxml_version,
        summary.account_count,
        summary.journal_entry_count,
        summary.journal_line_count,
        summary.accounts_sha256,
        summary.journal_sha256,
    );
    Ok(())
}

#[cfg(feature = "research-tools")]
fn run_normalize_sdk_oracle(
    manifest: PathBuf,
    accounts: PathBuf,
    journal: PathBuf,
    out_dir: PathBuf,
) -> Result<()> {
    let manifest_bytes = std::fs::read(manifest).context("reading SDK oracle manifest")?;
    let accounts_xml = std::fs::read(accounts).context("reading SDK oracle account artifact")?;
    let journal_xml = std::fs::read(journal).context("reading SDK oracle journal artifact")?;
    let summary = normalize_sdk_oracle(&manifest_bytes, &accounts_xml, &journal_xml, &out_dir)
        .context("normalizing SDK oracle artifacts")?;
    // Intentionally do not print paths, company metadata, XML, or TSV rows.
    println!(
        "sdk_oracle_normalized account_rows={} journal_entry_rows={} journal_source_line_rows={} journal_posting_rows={} accounts_output={} journal_output={} local_only=true production_dependency=false",
        summary.account_rows,
        summary.journal_entry_rows,
        summary.journal_source_line_rows,
        summary.journal_line_rows,
        summary.accounts_output_name,
        summary.journal_output_name,
    );
    Ok(())
}

#[cfg(feature = "research-tools")]
fn run_fixture_audit(
    sdk_manifest: PathBuf,
    account_listing: PathBuf,
    voided_deleted: PathBuf,
    trial_balance: Vec<PathBuf>,
    general_ledger: Vec<PathBuf>,
    journal: Vec<PathBuf>,
) -> Result<()> {
    let bytes = std::fs::read(sdk_manifest).context("reading SDK oracle manifest")?;
    let oracle = parse_sdk_oracle_manifest(&bytes).context("parsing SDK oracle manifest")?;
    let audit = audit_fixture(
        oracle,
        &account_listing,
        &voided_deleted,
        &trial_balance,
        &general_ledger,
        &journal,
    )
    .context("auditing local acceptance fixture")?;
    // Never print paths, report cells, QBXML contents, account names, or IDs.
    println!(
        "fixture_audit PASS qbxml_version={} oracle_accounts={} oracle_journal_entries={} oracle_journal_lines={} native_trial_balances={} native_trial_balance_rows={} native_general_ledgers={} native_journals={}",
        audit.sdk_oracle.qbxml_version,
        audit.sdk_oracle.account_count,
        audit.sdk_oracle.journal_entry_count,
        audit.sdk_oracle.journal_line_count,
        audit.trial_balances.len(),
        audit.total_trial_balance_rows(),
        audit.general_ledger_reports,
        audit.journal_reports,
    );
    Ok(())
}

fn run_reconcile_trial_balance(reference: PathBuf, actual: PathBuf) -> Result<()> {
    let reference_bytes = std::fs::read(&reference)
        .with_context(|| format!("reading reference Trial Balance {:?}", reference))?;
    let actual_bytes = std::fs::read(&actual)
        .with_context(|| format!("reading generated Trial Balance {:?}", actual))?;
    let reference_tb = parse_quickbooks_trial_balance_csv(&reference_bytes)
        .with_context(|| format!("parsing reference Trial Balance {:?}", reference))?;
    let actual_tb = parse_trial_balance_csv(&actual_bytes)
        .with_context(|| format!("parsing generated Trial Balance {:?}", actual))?;
    run_trial_balance_reconciliation(&reference_tb, &actual_tb)
}

fn run_reconcile_qbw_trial_balance(
    qbw: PathBuf,
    native_tb: PathBuf,
    as_of: String,
    fiscal_year_start: String,
    retained_earnings_account_id: String,
    retained_earnings_report_name: Option<String>,
    snapshot_id: String,
) -> Result<()> {
    let as_of = MaterializedPostingDate::parse_iso_date(&as_of)
        .context("parsing --as-of as strict ISO YYYY-MM-DD")?;
    let fiscal_year_start = MaterializedPostingDate::parse_iso_date(&fiscal_year_start)
        .context("parsing --fiscal-year-start as strict ISO YYYY-MM-DD")?;
    if fiscal_year_start.accounting_date() > as_of.accounting_date() {
        anyhow::bail!("--fiscal-year-start must not be after --as-of");
    }
    let retained_earnings_account_id = AccountId::new(retained_earnings_account_id)
        .context("invalid --retained-earnings-account-id")?;
    let reference_bytes = std::fs::read(&native_tb)
        .with_context(|| format!("reading native Trial Balance {:?}", native_tb))?;
    let reference_tb = parse_quickbooks_trial_balance_csv(&reference_bytes)
        .with_context(|| format!("parsing native Trial Balance {:?}", native_tb))?;

    let ledger = build_local_enterprise24_ledger(&qbw, snapshot_id)?;
    let account_catalog = ledger.accounts().cloned().collect::<Vec<_>>();
    let policy = QuickBooksAccrualTrialBalancePolicy::new(
        fiscal_year_start.accounting_date(),
        retained_earnings_account_id.clone(),
    );
    let report = ledger
        .quickbooks_accrual_trial_balance_as_of(
            as_of.accounting_date(),
            openqbw::TrialBalanceOptions::default(),
            &policy,
        )
        .context("building validated QuickBooks accrual Trial Balance")?;
    if retained_earnings_report_name
        .as_deref()
        .is_some_and(|name| name.trim().is_empty())
    {
        anyhow::bail!("--retained-earnings-report-name must not be empty");
    }
    // Route through the public normalized report serialization/parser rather
    // than a second in-memory adapter. This proves the exact bytes emitted by
    // `accounting-report --format csv` are what reconciliation compares.
    let metadata = ReportMetadata {
        entity_id: "reconciliation".to_owned(),
        source_file: "local-qbw".to_owned(),
        parser_version: env!("CARGO_PKG_VERSION").to_owned(),
        generated_at: "reconciliation".to_owned(),
        trial_balance_policy: Some(TrialBalancePolicyProvenance {
            source: "explicit".to_owned(),
            fiscal_year_start: fiscal_year_start.to_iso_date(),
            as_of: as_of.to_iso_date(),
            retained_earnings_account_id: retained_earnings_account_id.as_str().to_owned(),
            retained_earnings_report_name,
        }),
    };
    let generated_csv =
        trial_balance_csv_with_account_catalog(&report, &metadata, &account_catalog)
            .map_err(anyhow::Error::msg)?;
    let actual_tb = parse_trial_balance_csv(generated_csv.as_bytes())
        .context("parsing normalized in-memory Trial Balance CSV")?;
    run_trial_balance_reconciliation(&reference_tb, &actual_tb)
}

fn run_reconcile_qbw_general_ledger(
    qbw: PathBuf,
    native_gl: PathBuf,
    from: String,
    through: String,
    snapshot_id: String,
) -> Result<()> {
    let from = MaterializedPostingDate::parse_iso_date(&from)
        .context("parsing --from as strict ISO YYYY-MM-DD")?;
    let through = MaterializedPostingDate::parse_iso_date(&through)
        .context("parsing --through as strict ISO YYYY-MM-DD")?;
    if from.accounting_date() > through.accounting_date() {
        anyhow::bail!("--from must not be after --through");
    }
    let native_bytes = std::fs::read(&native_gl).context("reading native General Ledger")?;
    let parsed_native = parse_quickbooks_general_ledger_csv(
        &native_bytes,
        from.accounting_date(),
        through.accounting_date(),
    )
    .context("parsing native QuickBooks General Ledger")?;
    let native_neutral_zero_rows = parsed_native.neutral_zero_rows;
    let mut native = parsed_native.postings;
    let ledger = build_local_enterprise24_ledger(&qbw, snapshot_id)?;
    let account_catalog = ledger.accounts().cloned().collect::<Vec<_>>();
    let generated_report = ledger
        .general_ledger_as_of(through.accounting_date())
        .context("building validated General Ledger through --through")?;
    let generated_report = openqbw::GeneralLedger {
        as_of: generated_report.as_of,
        entries: generated_report
            .entries
            .into_iter()
            .filter(|entry| entry.posting.date >= from.accounting_date())
            .collect(),
    };
    if generated_report.entries.is_empty() {
        anyhow::bail!("direct-QBW General Ledger has no postings in requested range");
    }
    let metadata = ReportMetadata {
        entity_id: "reconciliation".to_owned(),
        source_file: "local-qbw".to_owned(),
        parser_version: env!("CARGO_PKG_VERSION").to_owned(),
        generated_at: "reconciliation".to_owned(),
        trial_balance_policy: None,
    };
    let generated_csv =
        general_ledger_csv_with_account_catalog(&generated_report, &metadata, &account_catalog)
            .map_err(anyhow::Error::msg)?;
    let generated = parse_generated_general_ledger_csv(
        generated_csv.as_bytes(),
        from.accounting_date(),
        through.accounting_date(),
    )
    .context("parsing normalized in-memory General Ledger CSV")?;
    let decoded_full_names_by_account_id =
        account_full_names_with_catalog(&account_catalog, std::iter::empty())
            .map_err(anyhow::Error::msg)?;
    let decoded_full_names = decoded_full_names_by_account_id
        .values()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let decoded_display_names_by_account_id = account_display_names_with_catalog(
        &account_catalog,
        std::iter::empty(),
        &decoded_full_names_by_account_id,
    )
    .map_err(anyhow::Error::msg)?;
    resolve_native_account_sections_with_chart(
        &mut native,
        &decoded_full_names,
        &account_catalog,
        &decoded_full_names_by_account_id,
        &decoded_display_names_by_account_id,
        &generated_report.entries,
    )
    .context("resolving native General Ledger account sections against decoded chart identities")?;
    let reconciliation = reconcile_general_ledger_postings(
        &native,
        generated.postings,
        generated.transaction_type_complete,
        false,
    );
    println!("{}", reconciliation.status_line());
    println!(
        "postings compared={} generated={} matched={} date_amount_matched={} shared_accounts={} native_only_accounts={} generated_only_accounts={} missing={} extra={} native_neutral_zero_rows={} semantic_fields_unavailable={}",
        reconciliation.native_postings,
        reconciliation.generated_postings,
        reconciliation.matching_postings,
        reconciliation.matching_date_amount_postings,
        reconciliation.shared_account_identities,
        reconciliation.native_only_account_identities,
        reconciliation.generated_only_account_identities,
        reconciliation.missing_postings,
        reconciliation.extra_postings,
        native_neutral_zero_rows,
        if reconciliation.unavailable_semantic_fields.is_empty() {
            "none".to_owned()
        } else {
            reconciliation.unavailable_semantic_fields.join(",")
        },
    );
    if !reconciliation.passes_posting_multiset() {
        // Business labels and document numbers are intentionally not emitted
        // by the production command.  The caller may investigate its own
        // local artifacts with explicit diagnostic tooling.
        anyhow::bail!("General Ledger posting reconciliation failed");
    }
    Ok(())
}

fn run_trial_balance_reconciliation(
    reference_tb: &trial_balance_reconciliation::TrialBalance,
    actual_tb: &trial_balance_reconciliation::TrialBalance,
) -> Result<()> {
    if !reference_tb.is_balanced() {
        anyhow::bail!("reference Trial Balance is not internally balanced");
    }
    if !actual_tb.is_balanced() {
        anyhow::bail!("generated Trial Balance is not internally balanced");
    }
    let result = reconcile_trial_balances(reference_tb, actual_tb);
    finish_trial_balance_reconciliation(reference_tb, actual_tb, result)
}

fn finish_trial_balance_reconciliation(
    reference_tb: &trial_balance_reconciliation::TrialBalance,
    actual_tb: &trial_balance_reconciliation::TrialBalance,
    result: trial_balance_reconciliation::TrialBalanceReconciliation,
) -> Result<()> {
    println!("{}", result.status_line());
    println!(
        "accounts compared={} missing={} extra={} mismatched={} max_variance_cents={}",
        reference_tb.balances_cents.len(),
        result.missing_accounts.len(),
        result.extra_accounts.len(),
        result.mismatched_accounts.len(),
        result.max_account_variance_cents,
    );
    if !result.passes() {
        for line in reconciliation_diagnostic_lines(reference_tb, actual_tb, &result) {
            eprintln!("{line}");
        }
        anyhow::bail!("Trial Balance reconciliation failed");
    }
    Ok(())
}

/// Print a diagnostic to stderr when page-to-table attribution has no
/// usable entries, explaining why rather than leaving it to show up as
/// silently-empty/unattributed output downstream.
fn warn_on_attribution_gap(attribution: &PageAttribution) {
    match attribution.gap() {
        None => {}
        Some(AttributionGap::NoCatalogRows) => {
            eprintln!("warning: no SYSTABLE rows found; page-to-table attribution is unavailable");
        }
        Some(AttributionGap::AllRootsZeroed) => {
            eprintln!(
                "warning: SYSTABLE rows were found, but legacy position attribution has no \
                 validated catalog anchor. Enterprise 24 does not expose a proven B-tree root \
                 through the compatibility fields used by that diagnostic. Attribution-dependent \
                 output below will be empty; the table listing itself is unaffected."
            );
        }
    }
}

fn run_export(input: PathBuf, output: PathBuf) -> Result<ExportStats> {
    if output.exists() {
        std::fs::remove_file(&output).with_context(|| format!("removing existing {:?}", output))?;
    }

    let store = PageStore::open(&input).with_context(|| format!("opening {:?}", input))?;
    let model = ApModel::learn(&store);
    let attribution = PageAttribution::build(&store, &model);
    warn_on_attribution_gap(&attribution);

    let mut items: Vec<LineItem> =
        iter_lineitems_with_attribution(&store, &model, &attribution).collect();
    items.sort_by_key(|li| (li.page_number, li.page_offset));

    let mut headers: Vec<TransactionHeader> =
        iter_transaction_headers(&store, &model, &attribution).collect();
    headers.sort_by_key(|h| (h.page_number, h.page_offset));

    let mut conn = Connection::open(&output).with_context(|| format!("opening {:?}", output))?;
    create_schema(&conn)?;

    {
        let tx = conn.transaction()?;
        let header_map = insert_transaction_headers(&tx, &headers)?;
        insert_synthesized_transactions(&tx, &items, &header_map)?;
        insert_transaction_line_items(&tx, &items)?;
        tx.commit()?;
    }

    let stats = collect_export_stats(&conn, &store, &items, &headers)?;
    println!("{}", stats.summary());
    Ok(stats)
}

fn run_catalog(input: PathBuf, user_only: bool) -> Result<()> {
    let store = PageStore::open(&input).with_context(|| format!("opening {:?}", input))?;
    let model = ApModel::learn(&store);

    let mut entries: Vec<SysTableEntry> = openqbw::collect_unique(&store, &model);
    entries.sort_by_key(|e| e.table_id);
    warn_on_attribution_gap(&PageAttribution::from_catalog(entries.clone()));

    let total = entries.len();
    let user: Vec<&SysTableEntry> = entries
        .iter()
        .filter(|e| !is_system_name(&e.name))
        .collect();

    println!(
        "file: {}  pages={}  unique_tables={}  user_tables={}",
        input.file_name().and_then(|s| s.to_str()).unwrap_or("?"),
        store.page_count(),
        total,
        user.len(),
    );
    println!(
        "{:>6}  {:>8}  {:>10}  {:>7}  {:>5}  name",
        "tid", "object", "rows", "pages", "flags"
    );
    let iter: Box<dyn Iterator<Item = &SysTableEntry>> = if user_only {
        Box::new(user.into_iter())
    } else {
        Box::new(entries.iter())
    };
    for e in iter {
        println!(
            "{:>6}  {:>8}  {:>10}  {:>7}  0x{:02x}  {}",
            e.table_id, e.object_id, e.row_count, e.table_page_count, e.row_flags, e.name
        );
    }
    Ok(())
}

fn run_schema(input: PathBuf, table: String) -> Result<()> {
    let store = PageStore::open(&input).with_context(|| format!("opening {:?}", input))?;
    let model = ApModel::learn(&store);
    let cols = openqbw::schema_for(&store, &model, &table);
    if cols.is_empty() {
        anyhow::bail!(
            "no recovered schema found for table {:?} (the table may be unknown, \
             or no SYSCOLUMN rows were recovered for its SYSTABLE.table_id)",
            table
        );
    }
    println!("table: {}  columns: {}", table, cols.len());
    println!(
        "{:>5}  {:<32}  {:>6}  {:>5}  {:>5}  {:>5}  {:>10}",
        "id", "name", "domain", "width", "scale", "nulls", "object"
    );
    for c in &cols {
        println!(
            "{:>5}  {:<32}  {:>6}  {:>5}  {:>5}  {:>5}  {:>10}",
            c.column_id, c.name, c.domain_id, c.width, c.scale, c.nulls as char, c.object_id
        );
    }
    Ok(())
}

fn run_fkgraph(input: PathBuf, resolved_only: bool) -> Result<()> {
    let store = PageStore::open(&input).with_context(|| format!("opening {:?}", input))?;
    let model = ApModel::learn(&store);
    let edges = openqbw::build_fk_graph(&store, &model);
    let s = openqbw::fk_graph_stats(&edges);
    println!(
        "edges={}  resolved={}  strong(>=900)={}  resolved_rate={:.1}%",
        s.edges,
        s.resolved,
        s.strong,
        if s.edges == 0 {
            0.0
        } else {
            100.0 * s.resolved as f64 / s.edges as f64
        }
    );
    println!(
        "{:<40}  {:>4}  {:<28}  {:<40}  {:>5}",
        "source_table", "col", "source_column", "target_table", "score"
    );
    for e in &edges {
        if resolved_only && e.target_table.is_none() {
            continue;
        }
        let tgt = e.target_table.clone().unwrap_or_else(|| "-".into());
        println!(
            "{:<40}  {:>4}  {:<28}  {:<40}  {:>5}",
            e.source_table, e.source_column_id, e.source_column, tgt, e.score
        );
    }
    Ok(())
}

fn run_indexes(input: PathBuf, fk_only: bool, summary_only: bool) -> Result<()> {
    let store = PageStore::open(&input).with_context(|| format!("opening {:?}", input))?;
    let model = ApModel::learn(&store);
    let entries: Vec<SysIndexEntry> = openqbw::collect_unique_sysindex(&store, &model);
    let tables: Vec<SysTableEntry> = openqbw::collect_unique(&store, &model);
    let position = PageAttribution::build(&store, &model);
    let audit = CrossValidation::run(&entries, &position, &tables);

    let fk_count = entries.iter().filter(|e| e.is_foreign_key()).count();
    println!(
        "sysindex entries: {} (fk: {})  distinct resolved (table_id,catalog_page_candidate) pairs: {}",
        entries.len(),
        fk_count,
        audit.distinct_candidates,
    );
    print_audit_summary(&audit);

    if summary_only {
        return Ok(());
    }

    let mut tables_by_owner: BTreeMap<u64, BTreeSet<(u32, String)>> = BTreeMap::new();
    for t in &tables {
        tables_by_owner
            .entry(t.object_id)
            .or_default()
            .insert((t.table_id, t.name.clone()));
    }
    println!();
    println!(
        "{:>14}  {:>8}  {:>8}  {:<40}  index_name",
        "owner_oid", "tid", "page_candidate", "owner"
    );
    for e in &entries {
        if fk_only && !e.is_foreign_key() {
            continue;
        }
        let (table_id, owner) = match tables_by_owner.get(&e.owner_object_id) {
            Some(candidates) if candidates.len() == 1 => {
                let (table_id, name) = candidates.iter().next().expect("one candidate");
                (table_id.to_string(), name.clone())
            }
            Some(candidates) => (
                "<unresolved>".into(),
                format!("<ambiguous owner: {} table rows>", candidates.len()),
            ),
            None => ("<unresolved>".into(), "<orphan owner object>".into()),
        };
        println!(
            "{:>14}  {:>8}  {:>8}  {:<40}  {}",
            e.owner_object_id, table_id, e.catalog_page_candidate, owner, e.name
        );
    }
    Ok(())
}

fn print_audit_summary(audit: &CrossValidation) {
    println!(
        "cross-validation: agree={} disagree={} missing={} orphan={} ambiguous_owner={}  agreement_rate={:.1}%",
        audit.agree,
        audit.disagree,
        audit.missing,
        audit.orphan_index,
        audit.ambiguous_owner,
        audit.agreement_rate() * 100.0,
    );
    if !audit.disagree_samples.is_empty() {
        println!(
            "  diagnostic candidate comparisons (sysindex_table -> position_table @ page_candidate : index):"
        );
        for (tid, sysn, posn, candidate, idx) in &audit.disagree_samples {
            println!(
                "    tid={:<6} {:<32} -> {:<32} @ page_candidate={:<8} : {}",
                tid, sysn, posn, candidate, idx
            );
        }
    }
}

fn run_validate_attribution(input: PathBuf) -> Result<()> {
    let store = PageStore::open(&input).with_context(|| format!("opening {:?}", input))?;
    let model = ApModel::learn(&store);
    let position = openqbw::PageAttribution::build(&store, &model);
    let schema = openqbw::SchemaAttribution::build(&store, &model);
    println!(
        "tables with width bands: {}  total pages: {}",
        schema.len(),
        store.page_count()
    );
    let pairs = (1..store.page_count())
        .filter_map(|pn| position.attribute(pn).map(|e| (pn, e.name.clone())));
    let stats = schema.validate_corpus(&store, &model, pairs);
    let total = stats.total().max(1);
    println!(
        "{:>10}  {:>10}  {:>10}  {:>10}  {:>10}",
        "pass", "fail", "no_band", "unmeasured", "total"
    );
    println!(
        "{:>10}  {:>10}  {:>10}  {:>10}  {:>10}",
        stats.pass,
        stats.fail,
        stats.no_band,
        stats.unmeasured,
        stats.total()
    );
    println!(
        "pass rate: {:.1}%  fail rate: {:.1}%",
        100.0 * stats.pass as f64 / total as f64,
        100.0 * stats.fail as f64 / total as f64,
    );
    Ok(())
}

fn run_nulls(input: PathBuf) -> Result<()> {
    let store = PageStore::open(&input).with_context(|| format!("opening {:?}", input))?;
    let model = ApModel::learn(&store);
    let buckets = openqbw::nullability_histogram(&store, &model);
    let total: usize = buckets.iter().map(|b| b.count).sum();
    println!(
        "total syscolumn rows: {}  distinct nullability values: {}",
        total,
        buckets.len()
    );
    println!("{:>6}  {:>8}  sample_columns", "nulls", "count");
    for b in &buckets {
        let samples = b.sample_columns.join(", ");
        println!("{:>6}  {:>8}  {}", b.nulls as char, b.count, samples);
    }
    Ok(())
}

fn run_verify(input: PathBuf, output: Option<PathBuf>, strict_attribution: bool) -> Result<()> {
    let out = match output {
        Some(p) => p,
        None => std::env::temp_dir().join(format!("openqbw-verify-{}.sqlite", std::process::id())),
    };
    let stats = run_export(input.clone(), out.clone())?;
    println!();
    println!("=== verification report ===");

    let conn = Connection::open(&out)?;
    println!();
    println!("Per source_table line-item counts:");
    let mut stmt = conn.prepare(
        "SELECT source_table, COUNT(*), COALESCE(SUM(amount_cents), 0)
         FROM transaction_line_items
         GROUP BY source_table
         ORDER BY source_table",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })?;
    for row in rows {
        let (t, n, sum) = row?;
        println!("  {:44}  {:>8}  ${:>15.2}", t, n, sum as f64 / 100.0);
    }

    println!();
    println!("Per type transaction counts:");
    let mut stmt = conn.prepare(
        "SELECT type, COUNT(*), COALESCE(SUM(total_cents), 0)
         FROM transactions
         GROUP BY type
         ORDER BY type",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })?;
    for row in rows {
        let (t, n, sum) = row?;
        println!("  {:44}  {:>8}  ${:>15.2}", t, n, sum as f64 / 100.0);
    }

    println!();
    let parent_count: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT qb_id_parent) FROM transaction_line_items",
        [],
        |r| r.get(0),
    )?;
    let grand_total: i64 = conn.query_row(
        "SELECT COALESCE(SUM(amount_cents), 0) FROM transaction_line_items",
        [],
        |r| r.get(0),
    )?;
    let regression_ok =
        grand_total == PHASE5_INVOICE_TOTAL_CENTS && parent_count == PHASE5_INVOICE_COUNT;
    println!(
        "Phase 5 regression (universal anchor):  parents={}/{}  grand_total=${:.2}/${:.2}  {}",
        parent_count,
        PHASE5_INVOICE_COUNT,
        grand_total as f64 / 100.0,
        PHASE5_INVOICE_TOTAL_CENTS as f64 / 100.0,
        if regression_ok { "PASS" } else { "DIFF" },
    );

    // Per-source-table parent counts (gives a sense of attribution
    // distribution; expect most parents under the dominant lineitem
    // tables on Rock Castle: abmc_invoice_inventory_lineitem,
    // abmc_general_journal_inventory_lineitem, abmc_credit_memo_inventory_lineitem).
    println!();
    println!("Top 10 source_tables by distinct parent QB-IDs:");
    let mut stmt = conn.prepare(
        "SELECT source_table, COUNT(DISTINCT qb_id_parent) as n
         FROM transaction_line_items
         GROUP BY source_table
         ORDER BY n DESC
         LIMIT 10",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
    for row in rows {
        let (t, n) = row?;
        println!("  {:44}  {:>8}", t, n);
    }

    println!();
    println!("Journal sum-to-zero check (Phase 2.2, signed amounts, C.48 Track A):");
    // Same-type 2-line journal pair-balance: the strictest case where the
    // high-bit-of-byte-1 sign hypothesis is unambiguous. Acceptance target:
    // 100% same-type pair-balance.
    let pair_stats: (i64, i64) = conn.query_row(
        "SELECT
           COUNT(*) AS pairs,
           COALESCE(SUM(CASE WHEN signed_sum = 0 THEN 1 ELSE 0 END), 0) AS balanced
         FROM (
           SELECT qb_id_parent,
                  SUM(amount_cents_signed) AS signed_sum,
                  COUNT(*) AS n,
                  COUNT(DISTINCT amount_type) AS types
           FROM transaction_line_items
           WHERE source_table = 'abmc_general_journal_inventory_lineitem'
             AND amount_type IN (1, 2)
             AND amount_cents_signed IS NOT NULL
           GROUP BY qb_id_parent
           HAVING n = 2 AND types = 1
         )",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let (pairs, balanced) = pair_stats;
    if pairs == 0 {
        println!("  no same-type 2-line journal pairs found");
    } else {
        let pct = (balanced as f64) / (pairs as f64) * 100.0;
        let ok = balanced == pairs;
        println!(
            "  same-type 2-line journal pairs: {}/{} balance ({:.1}%) {}",
            balanced,
            pairs,
            pct,
            if ok { "PASS" } else { "DIFF" },
        );
    }

    // Broader (all journals) for visibility - not an acceptance criterion
    // because 0x03 entries are not amount records (see C.48 Track A) and
    // attribution is fuzzy (see C.47).
    let all_stats: (i64, i64) = conn.query_row(
        "SELECT
           COUNT(*) AS p,
           COALESCE(SUM(CASE WHEN signed_sum = 0 THEN 1 ELSE 0 END), 0) AS bal
         FROM (
           SELECT qb_id_parent,
                  COALESCE(SUM(amount_cents_signed), 0) AS signed_sum
           FROM transaction_line_items
           WHERE source_table = 'abmc_general_journal_inventory_lineitem'
           GROUP BY qb_id_parent
         )",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let (allp, allb) = all_stats;
    if allp > 0 {
        println!(
            "  all journal-attributed parents (signed sum incl. type-0x03 nulls): {}/{} ({:.1}%)",
            allb,
            allp,
            (allb as f64) / (allp as f64) * 100.0,
        );
    }
    println!("  note: type-0x03 entries are NOT signed amounts (727 distinct values across");
    println!("        11,754 occurrences in Rock Castle - see NOTES.md C.48 Track A).");

    println!();
    println!("=== SYSINDEX cross-validation (WP-6Z.3) ===");
    {
        let store = PageStore::open(&input).with_context(|| format!("re-opening {:?}", input))?;
        let model = ApModel::learn(&store);
        let entries = openqbw::collect_unique_sysindex(&store, &model);
        let tables: Vec<SysTableEntry> = openqbw::collect_unique(&store, &model);
        let position = PageAttribution::build(&store, &model);
        let audit = CrossValidation::run(&entries, &position, &tables);
        let fk_count = entries.iter().filter(|e| e.is_foreign_key()).count();
        println!(
            "  sysindex entries: {} (fk: {})  distinct (tid,root) pairs: {}",
            entries.len(),
            fk_count,
            audit.distinct_candidates,
        );
        print_audit_summary(&audit);
    }

    if strict_attribution {
        println!();
        println!("=== content-signature attribution (--strict-attribution) ===");
        let store = PageStore::open(&input).with_context(|| format!("re-opening {:?}", input))?;
        let model = ApModel::learn(&store);
        let content = ContentAttribution::build(&store, &model);
        let position = PageAttribution::build(&store, &model);
        println!(
            "  unique signatures: {}  ambiguous: {}  skipped roots: {}",
            content.len(),
            content.ambiguous_count(),
            content.skipped_count(),
        );

        // Collect the distinct E-page numbers that contributed at least
        // one line item, so the comparison runs over the pages we
        // actually attribute in production.
        let mut stmt = conn.prepare(
            "SELECT DISTINCT page_number FROM transaction_line_items ORDER BY page_number",
        )?;
        let pages: Vec<u64> = stmt
            .query_map([], |r| r.get::<_, i64>(0))?
            .filter_map(|r| r.ok())
            .map(|n| n as u64)
            .collect();
        let agree = content.compare(&store, &model, &position, pages.iter().copied());
        let total = agree.total().max(1);
        println!(
            "  pages compared: {}  agree: {} ({:.2}%)  disagree: {}  only_position: {}  only_content: {}  neither: {}",
            agree.total(),
            agree.agree,
            (agree.agree as f64) * 100.0 / (total as f64),
            agree.disagree,
            agree.only_position,
            agree.only_content,
            agree.neither,
        );
    }

    println!();
    println!("Overall: {}", stats.summary());
    Ok(())
}

fn is_system_name(name: &str) -> bool {
    name.starts_with("SYS")
        || name.starts_with("ISYS")
        || name.starts_with("RS_")
        || name.starts_with("dbo")
}

fn create_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE transactions (
            qb_id        TEXT PRIMARY KEY,
            type         TEXT NOT NULL,
            source_table TEXT NOT NULL,
            txn_date_raw INTEGER,
            counter      INTEGER,
            line_count   INTEGER NOT NULL,
            total_cents  INTEGER NOT NULL,
            has_deferred INTEGER NOT NULL,
            source_page  INTEGER
        );

        CREATE TABLE transaction_line_items (
            qb_id_parent        TEXT NOT NULL,
            line_number         INTEGER NOT NULL,
            item_qb_id          TEXT,
            amount_type         INTEGER NOT NULL,
            amount_cents        INTEGER,
            amount_cents_signed INTEGER,
            amount_raw_hex      TEXT NOT NULL,
            txn_date_raw        INTEGER,
            counter             INTEGER,
            source_table        TEXT NOT NULL,
            page_number         INTEGER NOT NULL,
            page_offset         INTEGER NOT NULL,
            PRIMARY KEY (qb_id_parent, line_number, source_table)
        );

        CREATE INDEX idx_lineitems_page   ON transaction_line_items(page_number);
        CREATE INDEX idx_lineitems_source ON transaction_line_items(source_table);
        CREATE INDEX idx_tx_type          ON transactions(type);
        CREATE INDEX idx_tx_source        ON transactions(source_table);
        "#,
    )?;
    Ok(())
}

fn insert_transaction_headers(
    tx: &Transaction<'_>,
    headers: &[TransactionHeader],
) -> Result<HashMap<String, TransactionHeader>> {
    let mut map: HashMap<String, TransactionHeader> = HashMap::new();
    for h in headers {
        map.entry(h.qb_id.clone()).or_insert_with(|| h.clone());
    }
    let mut stmt = tx.prepare(
        "INSERT INTO transactions \
         (qb_id, type, source_table, txn_date_raw, counter, \
          line_count, total_cents, has_deferred, source_page) \
         VALUES (?, ?, ?, ?, ?, 0, 0, 0, ?)",
    )?;
    let mut ordered: Vec<&TransactionHeader> = map.values().collect();
    ordered.sort_by_key(|h| (h.page_number, h.page_offset));
    for h in ordered {
        stmt.execute(params![
            h.qb_id,
            h.txn_type(),
            h.source_table,
            h.txn_date_raw,
            h.counter,
            h.page_number as i64,
        ])?;
    }
    Ok(map)
}

/// Insert synthesized rows for parent QB-IDs that appear in line items
/// but have no matching header record (or update aggregates for those
/// that do). Synthesized rows get `type='unknown'`.
fn insert_synthesized_transactions(
    tx: &Transaction<'_>,
    items: &[LineItem],
    header_map: &HashMap<String, TransactionHeader>,
) -> Result<()> {
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<&LineItem>> = HashMap::new();
    for li in items {
        groups
            .entry(li.invoice_id.clone())
            .or_insert_with(|| {
                order.push(li.invoice_id.clone());
                Vec::new()
            })
            .push(li);
    }

    let mut update_stmt = tx.prepare(
        "UPDATE transactions SET line_count=?, total_cents=?, has_deferred=? WHERE qb_id=?",
    )?;
    let mut insert_stmt = tx.prepare(
        "INSERT INTO transactions \
         (qb_id, type, source_table, txn_date_raw, counter, \
          line_count, total_cents, has_deferred, source_page) \
         VALUES (?, 'unknown', ?, ?, ?, ?, ?, ?, ?)",
    )?;
    for qb_id in order {
        let lines = &groups[&qb_id];
        let total: i64 = lines
            .iter()
            .filter_map(|l| l.amount_cents.map(|c| c as i64))
            .sum();
        let has_deferred = lines.iter().any(|l| l.amount_type == AmountType::Deferred) as i64;
        let line_count = lines.len() as i64;
        if header_map.contains_key(&qb_id) {
            update_stmt.execute(params![line_count, total, has_deferred, qb_id])?;
            continue;
        }
        let date = lines.iter().find_map(|l| l.txn_date_raw);
        let counter = lines.iter().find_map(|l| l.counter);
        let src = lines
            .iter()
            .find_map(|l| l.source_table.clone())
            .unwrap_or_default();
        let page = lines.first().map(|l| l.page_number as i64).unwrap_or(0);
        insert_stmt.execute(params![
            qb_id,
            src,
            date,
            counter,
            line_count,
            total,
            has_deferred,
            page
        ])?;
    }
    Ok(())
}

fn insert_transaction_line_items(tx: &Transaction<'_>, items: &[LineItem]) -> Result<()> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO transaction_line_items \
         (qb_id_parent, line_number, item_qb_id, amount_type, amount_cents, \
          amount_cents_signed, amount_raw_hex, txn_date_raw, counter, source_table, \
          page_number, page_offset) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )?;
    let mut line_no: BTreeMap<(String, String), i64> = BTreeMap::new();
    for li in items {
        let src = li.source_table.clone().unwrap_or_default();
        let key = (li.invoice_id.clone(), src.clone());
        let n = line_no.entry(key).or_insert(0);
        *n += 1;
        let type_byte = amount_type_byte(li.amount_type);
        let hex = li
            .amount_raw
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        stmt.execute(params![
            li.invoice_id,
            *n,
            li.item_qb_id,
            type_byte,
            li.amount_cents,
            li.amount_cents_signed,
            hex,
            li.txn_date_raw,
            li.counter,
            src,
            li.page_number as i64,
            li.page_offset as i64,
        ])?;
    }
    Ok(())
}

fn amount_type_byte(t: AmountType) -> i64 {
    match t {
        AmountType::None => 0,
        AmountType::OneByteOne => 1,
        AmountType::Standard => 2,
        AmountType::Deferred => 3,
        AmountType::Other(b) => b as i64,
    }
}

#[derive(Debug)]
struct ExportStats {
    pages: u64,
    transactions: i64,
    headers: i64,
    line_items: i64,
    grand_total_cents: i64,
}

impl ExportStats {
    fn summary(&self) -> String {
        format!(
            "openqbw: pages={} transactions={} headers={} lineitems={} grand_total=${:.2}",
            self.pages,
            self.transactions,
            self.headers,
            self.line_items,
            self.grand_total_cents as f64 / 100.0,
        )
    }
}

fn collect_export_stats(
    conn: &Connection,
    store: &PageStore,
    items: &[LineItem],
    headers: &[TransactionHeader],
) -> Result<ExportStats> {
    let txns: i64 = conn.query_row("SELECT COUNT(*) FROM transactions", [], |r| r.get(0))?;
    let total: i64 = conn.query_row(
        "SELECT COALESCE(SUM(total_cents), 0) FROM transactions",
        [],
        |r| r.get(0),
    )?;
    Ok(ExportStats {
        pages: store.page_count(),
        transactions: txns,
        headers: headers.len() as i64,
        line_items: items.len() as i64,
        grand_total_cents: total,
    })
}

// =========================================================================
// migrate -- data-liberation export
// =========================================================================

fn run_migrate(input: PathBuf, out: PathBuf, format: MigrateFormat) -> Result<()> {
    match format {
        MigrateFormat::Sqlite => run_export(input, out).map(|s| println!("{}", s.summary())),
        MigrateFormat::Csv => run_migrate_csv(input, out),
        MigrateFormat::Iif => run_migrate_iif(input, out),
    }
}

fn collect_records(
    input: &PathBuf,
) -> Result<(Vec<LineItem>, Vec<TransactionHeader>, PageStore, ApModel)> {
    let store = PageStore::open(input).with_context(|| format!("opening {:?}", input))?;
    let model = ApModel::learn(&store);
    let attribution = PageAttribution::build(&store, &model);
    warn_on_attribution_gap(&attribution);
    let mut items: Vec<LineItem> =
        iter_lineitems_with_attribution(&store, &model, &attribution).collect();
    items.sort_by_key(|li| (li.page_number, li.page_offset));
    let mut headers: Vec<TransactionHeader> =
        iter_transaction_headers(&store, &model, &attribution).collect();
    headers.sort_by_key(|h| (h.page_number, h.page_offset));
    Ok((items, headers, store, model))
}

/// Minimal CSV-field escaper: quote if the field contains comma, quote,
/// CR, or LF, doubling embedded quotes.
fn csv_field(s: &str) -> String {
    if s.bytes().any(|b| matches!(b, b',' | b'"' | b'\n' | b'\r')) {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for ch in s.chars() {
            if ch == '"' {
                out.push('"');
            }
            out.push(ch);
        }
        out.push('"');
        out
    } else {
        s.to_string()
    }
}

fn iso_date_from_unix_days(days: i64) -> String {
    // 1970-01-01 was a Thursday; we want a calendar date. Use chrono-free
    // implementation: 1970-01-01 + days.
    // Simple algorithm via days-from-civil; good for the [1900, 2400] range.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", y, m, d)
}

fn lineitem_date(li: &LineItem) -> String {
    li.txn_date_days_since_unix()
        .map(iso_date_from_unix_days)
        .unwrap_or_default()
}

fn run_migrate_csv(input: PathBuf, out: PathBuf) -> Result<()> {
    std::fs::create_dir_all(&out).with_context(|| format!("creating {:?}", out))?;
    let (items, headers, store, model) = collect_records(&input)?;

    // catalog.csv
    let mut cat = std::fs::File::create(out.join("catalog.csv"))?;
    use std::io::Write;
    writeln!(
        cat,
        "table_id,object_id,name,row_count,table_page_count,ext_page_count,row_length,row_flags"
    )?;
    let mut tables: Vec<SysTableEntry> = openqbw::collect_unique(&store, &model);
    tables.sort_by_key(|e| e.table_id);
    for t in &tables {
        writeln!(
            cat,
            "{},{},{},{},{},{},{},{}",
            t.table_id,
            t.object_id,
            csv_field(&t.name),
            t.row_count,
            t.table_page_count,
            t.ext_page_count,
            t.row_length,
            t.row_flags,
        )?;
    }

    // transactions.csv
    let mut txf = std::fs::File::create(out.join("transactions.csv"))?;
    writeln!(txf, "qb_id,txn_type,source_table,page_number,page_offset")?;
    for h in &headers {
        writeln!(
            txf,
            "{},{},{},{},{}",
            csv_field(&h.qb_id),
            csv_field(h.txn_type()),
            csv_field(&h.source_table),
            h.page_number,
            h.page_offset,
        )?;
    }

    // lineitems.csv
    let mut lif = std::fs::File::create(out.join("lineitems.csv"))?;
    writeln!(
        lif,
        "invoice_id,item_qb_id,amount_cents,amount_signed_cents,amount_decimal,txn_date,source_table,page_number,page_offset"
    )?;
    for li in &items {
        let amt = li.amount_cents.map(|c| c.to_string()).unwrap_or_default();
        let amts = li
            .amount_cents_signed
            .map(|c| c.to_string())
            .unwrap_or_default();
        let dec = li
            .amount_cents
            .map(|c| format!("{:.2}", c as f64 / 100.0))
            .unwrap_or_default();
        writeln!(
            lif,
            "{},{},{},{},{},{},{},{},{}",
            csv_field(&li.invoice_id),
            csv_field(li.item_qb_id.as_deref().unwrap_or("")),
            amt,
            amts,
            dec,
            lineitem_date(li),
            csv_field(li.source_table.as_deref().unwrap_or("")),
            li.page_number,
            li.page_offset,
        )?;
    }

    println!(
        "openqbw migrate csv: out={:?} tables={} transactions={} lineitems={}",
        out,
        tables.len(),
        headers.len(),
        items.len(),
    );
    Ok(())
}

fn run_migrate_iif(input: PathBuf, out: PathBuf) -> Result<()> {
    let (items, headers, _store, _model) = collect_records(&input)?;
    use std::io::Write;
    let mut f = std::fs::File::create(&out).with_context(|| format!("creating {:?}", out))?;

    // IIF requires CRLF line endings for maximum compatibility with the
    // Windows tools that consume it.
    let nl = "\r\n";
    write!(
        f,
        "!TRNS\tTRNSID\tTRNSTYPE\tDATE\tACCNT\tNAME\tAMOUNT\tMEMO{nl}"
    )?;
    write!(
        f,
        "!SPL\tSPLID\tTRNSTYPE\tDATE\tACCNT\tNAME\tAMOUNT\tMEMO{nl}"
    )?;
    write!(f, "!ENDTRNS{nl}")?;

    // Bucket line items by parent invoice id. We emit one TRNS per parent
    // group: in this build most parents are orphans (no matching header)
    // because the WP-6Z work only parses the lineitem and a small slice of
    // header tables. We still emit them as TRNS/SPL pairs so the IIF is
    // useful for liberation. When a matching header exists, we use its
    // txn_type; otherwise we default to GENERAL JOURNAL.
    let mut by_parent: HashMap<&str, Vec<&LineItem>> = HashMap::new();
    for li in &items {
        by_parent
            .entry(li.invoice_id.as_str())
            .or_default()
            .push(li);
    }
    let header_by_id: HashMap<&str, &TransactionHeader> =
        headers.iter().map(|h| (h.qb_id.as_str(), h)).collect();
    let mut parent_ids: Vec<&str> = by_parent.keys().copied().collect();
    parent_ids.sort_unstable();

    let mut trns_id: u64 = 1;
    let mut spl_id: u64 = 1;
    let mut written_txns = 0usize;
    let mut written_lines = 0usize;

    for parent_id in parent_ids {
        let kids = by_parent.get(parent_id).cloned().unwrap_or_default();
        if kids.is_empty() {
            continue;
        }
        let sum_cents: i64 = kids
            .iter()
            .map(|li| li.amount_cents.unwrap_or(0) as i64)
            .sum();
        let date = kids
            .iter()
            .find_map(|li| li.txn_date_days_since_unix())
            .map(iso_date_from_unix_days)
            .unwrap_or_default();
        let ttype = header_by_id
            .get(parent_id)
            .map(|h| h.txn_type().to_uppercase())
            .unwrap_or_else(|| "GENERAL JOURNAL".to_string());
        let amt = sum_cents as f64 / 100.0;
        let memo = format_args!("qb_id={parent_id}").to_string();
        write!(
            f,
            "TRNS\t{trns_id}\t{ttype}\t{date}\tAccounts Receivable\t\t{amt:.2}\t{memo}{nl}"
        )?;
        for li in &kids {
            let amt = -(li.amount_cents.unwrap_or(0) as i64) as f64 / 100.0;
            let date = lineitem_date(li);
            let accnt = li.source_table.as_deref().unwrap_or("");
            let memo = li.item_qb_id.as_deref().unwrap_or("");
            write!(
                f,
                "SPL\t{spl_id}\t{ttype}\t{date}\t{accnt}\t\t{amt:.2}\t{memo}{nl}"
            )?;
            spl_id += 1;
            written_lines += 1;
        }
        write!(f, "ENDTRNS{nl}")?;
        trns_id += 1;
        written_txns += 1;
    }

    println!(
        "openqbw migrate iif: out={:?} transactions={} lineitems={}",
        out, written_txns, written_lines
    );
    Ok(())
}

// =========================================================================
// forensics -- file-level discovery
// =========================================================================

fn run_forensics(input: PathBuf) -> Result<()> {
    let store = PageStore::open(&input).with_context(|| format!("opening {:?}", input))?;
    let model = ApModel::learn(&store);
    let attribution = PageAttribution::build(&store, &model);

    let file_size = std::fs::metadata(&input)
        .map(|m| m.len())
        .unwrap_or_default();
    let page_count = store.page_count();

    println!("=== file ===");
    println!("path        : {:?}", input);
    println!(
        "size        : {} bytes ({:.1} MiB)",
        file_size,
        file_size as f64 / 1024.0 / 1024.0
    );
    println!("pages       : {} (4096 B each)", page_count);
    println!(
        "ap learned  : {} / {} blocks ({:.1}%)",
        model.learned_block_count(),
        page_count.div_ceil(16),
        100.0 * model.learned_block_count() as f64 / page_count.div_ceil(16).max(1) as f64,
    );

    let tables: Vec<SysTableEntry> = openqbw::collect_unique(&store, &model);
    let user_tables: Vec<&SysTableEntry> =
        tables.iter().filter(|t| !is_system_name(&t.name)).collect();
    println!();
    println!("=== catalog ===");
    println!("tables total: {}", tables.len());
    println!("tables user : {}", user_tables.len());

    let items: Vec<LineItem> =
        iter_lineitems_with_attribution(&store, &model, &attribution).collect();
    let headers: Vec<TransactionHeader> =
        iter_transaction_headers(&store, &model, &attribution).collect();

    println!();
    println!("=== business records ===");
    println!("transaction headers : {}", headers.len());
    println!("line items          : {}", items.len());

    // Distinct invoice IDs in line items vs in headers; gaps suggest
    // deleted parents.
    use std::collections::HashSet;
    let header_ids: HashSet<&str> = headers.iter().map(|h| h.qb_id.as_str()).collect();
    let parent_ids: HashSet<&str> = items.iter().map(|li| li.invoice_id.as_str()).collect();
    let orphan_parents = parent_ids.difference(&header_ids).count();
    let childless_headers = header_ids.difference(&parent_ids).count();
    let grand_total_cents: i64 = items
        .iter()
        .map(|li| li.amount_cents.unwrap_or(0) as i64)
        .sum();

    println!("distinct parent invoice ids : {}", parent_ids.len());
    println!("orphan parents (no header)  : {}", orphan_parents);
    println!("childless headers           : {}", childless_headers);
    println!(
        "lineitem grand total        : ${:.2}",
        grand_total_cents as f64 / 100.0
    );

    if orphan_parents > 0 || childless_headers > 0 {
        println!();
        println!(
            "note: a non-zero orphan count is a discovery signal -- the file \n      may contain partially-purged records or a parent table this \n      build does not parse yet."
        );
    }

    Ok(())
}

#[cfg(test)]
mod accounting_routing_tests {
    use super::*;

    #[test]
    fn generic_collector_rejects_a_dedicated_general_journal_policy() {
        let policy = openqbw::enterprise24_r21_partial_table_policy(
            Enterprise24AccountingTable::GeneralJournalLine,
        )
        .expect("General Journal policy is static");
        let scan = openqbw::EnterpriseTableScan {
            target_table_id: Enterprise24AccountingTable::GeneralJournalLine.id(),
            candidate_groups: Vec::new(),
            table_id_conflicts: Vec::new(),
            census: openqbw::EnterpriseTableScanCensus::default(),
        };
        let error = collect_enterprise24_partial_table_rows(
            &scan,
            policy,
            &opensqlany::RowSchema::new(Vec::new()),
            openqbw::Enterprise24TableCoverageExpectation {
                logical_records: 0,
                table_pages: 0,
                external_table_pages: 0,
            },
        )
        .expect_err(
            "dedicated General Journal policy must never be routed through the generic collector",
        );
        assert!(matches!(
            error,
            openqbw::Enterprise24AccountingPipelineError::PolicyRequiresDedicatedCollector {
                table_id: 3078
            }
        ));
    }
}

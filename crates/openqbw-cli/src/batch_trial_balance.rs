//! Parallel, all-or-nothing Trial Balance extraction for private local QBW
//! copies.  This module intentionally has no QuickBooks automation surface:
//! workers only call the same direct, read-only decoder used by
//! `accounting-report`.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use openqbw::{
    AccountId, MaterializedPostingDate, QuickBooksAccrualTrialBalancePolicy, TrialBalance,
    TrialBalanceOptions,
};
use rusqlite::{Connection, MAIN_DB};

use crate::batch_extract::{SnapshotJobOutcome, schedule_snapshot_jobs, snapshot_still_matches};
use crate::report_output::{
    ReportBundle, ReportMetadata, TrialBalancePolicyProvenance, write_sqlite_with_account_catalog,
};
use crate::{create_staged_file, publish_staged_path, remove_staged_path};

/// One manifest row.  Paths are deliberately never written to the output DB
/// or included in diagnostic messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchTrialBalanceInput {
    pub entity_id: String,
    pub qbw_path: PathBuf,
    pub snapshot_id: String,
    pub fiscal_year_start: String,
    pub retained_earnings_account_id: String,
    /// The display label used by the source QuickBooks report.  It is kept in
    /// policy provenance only; accounting always keys the roll-forward by the
    /// stable account identifier above.
    pub retained_earnings_report_name: String,
}

#[derive(Clone, Debug)]
struct CompletedTrialBalance {
    input_index: usize,
    entity_id: String,
    snapshot_id: String,
    metadata: ReportMetadata,
    report: TrialBalance,
    account_catalog: Vec<openqbw::Account>,
}

/// Parse a strict, headered CSV manifest.  The six required columns are
/// deliberately boring and dependency-free so private installations do not
/// need a JSON parser or network-resolved dependency.
pub fn parse_manifest_csv(bytes: &[u8]) -> Result<Vec<BatchTrialBalanceInput>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "manifest is not valid UTF-8".to_owned())?;
    let rows = parse_csv(text)?;
    let Some(header) = rows.first() else {
        return Err("manifest must contain a header and at least one input row".to_owned());
    };
    let expected = [
        "entity_id",
        "qbw_path",
        "snapshot_id",
        "fiscal_year_start",
        "retained_earnings_account_id",
        "retained_earnings_report_name",
    ];
    if header.iter().map(String::as_str).ne(expected) {
        return Err("manifest header must exactly be entity_id,qbw_path,snapshot_id,fiscal_year_start,retained_earnings_account_id,retained_earnings_report_name".to_owned());
    }
    if rows.len() == 1 {
        return Err("manifest must contain at least one input row".to_owned());
    }
    let mut seen_entities = BTreeSet::new();
    let mut inputs = Vec::with_capacity(rows.len() - 1);
    for (offset, row) in rows.iter().enumerate().skip(1) {
        let row_number = offset + 1;
        if row.len() != expected.len() {
            return Err(format!(
                "manifest row {row_number} has the wrong number of columns"
            ));
        }
        if row.iter().any(|value| value.trim().is_empty()) {
            return Err(format!(
                "manifest row {row_number} contains an empty required value"
            ));
        }
        if !seen_entities.insert(row[0].clone()) {
            return Err(format!("manifest row {row_number} repeats an entity_id"));
        }
        // Validate the values that determine accounting semantics before any
        // file is opened.  Do not put caller values in diagnostics.
        MaterializedPostingDate::parse_iso_date(&row[3])
            .map_err(|_| format!("manifest row {row_number} has an invalid fiscal_year_start"))?;
        AccountId::new(row[4].clone()).map_err(|_| {
            format!("manifest row {row_number} has an invalid retained earnings account id")
        })?;
        inputs.push(BatchTrialBalanceInput {
            entity_id: row[0].clone(),
            qbw_path: PathBuf::from(&row[1]),
            snapshot_id: row[2].clone(),
            fiscal_year_start: row[3].clone(),
            retained_earnings_account_id: row[4].clone(),
            retained_earnings_report_name: row[5].clone(),
        });
    }
    Ok(inputs)
}

/// Execute each manifest input independently, then create the requested
/// SQLite file only if every worker successfully produced a validated Trial
/// Balance.  Results are committed in manifest order, not completion order.
pub fn run_batch_trial_balance<F>(
    manifest: Vec<BatchTrialBalanceInput>,
    as_of_iso: &str,
    workers: usize,
    generated_at: &str,
    output: &Path,
    build_ledger: F,
) -> Result<(), String>
where
    F: Fn(Vec<u8>, String) -> anyhow::Result<openqbw::Ledger> + Sync,
{
    if output.exists() {
        return Err("refusing to overwrite existing consolidated output".to_owned());
    }
    if generated_at.trim().is_empty() {
        return Err("generated_at must not be empty".to_owned());
    }
    let as_of = MaterializedPostingDate::parse_iso_date(as_of_iso)
        .map_err(|_| "as_of must be strict ISO YYYY-MM-DD".to_owned())?;
    let as_of_day = as_of.accounting_date();
    for (index, input) in manifest.iter().enumerate() {
        let fiscal_year_start = MaterializedPostingDate::parse_iso_date(&input.fiscal_year_start)
            .map_err(|_| {
            format!(
                "manifest row {} has an invalid fiscal_year_start",
                index + 2
            )
        })?;
        if fiscal_year_start.accounting_date() > as_of_day {
            return Err(format!(
                "manifest row {} has fiscal_year_start after as_of",
                index + 2
            ));
        }
    }
    let paths = manifest.iter().map(|item| item.qbw_path.clone()).collect();
    let scheduled = schedule_snapshot_jobs(paths, workers, |job| {
        let input_index = job.input_index;
        let input = &manifest[input_index];
        // The decoder consumes precisely the bytes that were hashed. This
        // avoids a second path read whose contents could differ from the
        // reported snapshot; `PageStore::from_bytes` takes ownership without
        // making another company-file copy.
        let (_, source_path, snapshot, bytes) = job.into_parts();
        let ledger = match build_ledger(bytes, input.snapshot_id.clone()) {
            Ok(ledger) => ledger,
            Err(_) => return Err(()),
        };
        let account_catalog = ledger.accounts().cloned().collect::<Vec<_>>();
        if !snapshot_still_matches(&source_path, &snapshot) {
            return Err(());
        }
        let fiscal_year_start =
            match MaterializedPostingDate::parse_iso_date(&input.fiscal_year_start) {
                Ok(value) if value.accounting_date() <= as_of_day => value,
                _ => return Err(()),
            };
        let retained_earnings_account_id =
            match AccountId::new(input.retained_earnings_account_id.clone()) {
                Ok(value) => value,
                Err(_) => return Err(()),
            };
        let policy = QuickBooksAccrualTrialBalancePolicy::new(
            fiscal_year_start.accounting_date(),
            retained_earnings_account_id.clone(),
        );
        let report = match ledger.quickbooks_accrual_trial_balance_as_of(
            as_of_day,
            TrialBalanceOptions::default(),
            &policy,
        ) {
            Ok(report) => report,
            Err(_) => return Err(()),
        };
        let metadata = ReportMetadata {
            entity_id: input.entity_id.clone(),
            // A local path is intentionally never persisted. The caller's
            // opaque snapshot label is the source identifier instead.
            source_file: input.snapshot_id.clone(),
            parser_version: env!("CARGO_PKG_VERSION").to_owned(),
            generated_at: generated_at.to_owned(),
            trial_balance_policy: Some(TrialBalancePolicyProvenance {
                source: "explicit".to_owned(),
                fiscal_year_start: fiscal_year_start.to_iso_date(),
                as_of: as_of.to_iso_date(),
                retained_earnings_account_id: retained_earnings_account_id.as_str().to_owned(),
                retained_earnings_report_name: Some(input.retained_earnings_report_name.clone()),
            }),
        };
        if metadata.validate().is_err() {
            return Err(());
        }
        Ok(CompletedTrialBalance {
            input_index,
            entity_id: input.entity_id.clone(),
            snapshot_id: input.snapshot_id.clone(),
            metadata,
            report,
            account_catalog,
        })
    })
    .map_err(|error| format!("batch scheduling failed: {error}"))?;

    let mut completed = Vec::with_capacity(manifest.len());
    for result in scheduled.results {
        match result.outcome {
            SnapshotJobOutcome::Completed(Ok(value)) => completed.push(value),
            // The stable row number is sufficient to correct a private
            // manifest without leaking a local path or business label.
            SnapshotJobOutcome::Completed(Err(())) | SnapshotJobOutcome::InputError { .. } => {
                return Err(format!(
                    "batch extraction failed for manifest row {}",
                    result.input_index + 2
                ));
            }
        }
    }
    completed.sort_by_key(|value| value.input_index);
    write_consolidated_sqlite(output, &completed)
}

fn write_consolidated_sqlite(
    output: &Path,
    completed: &[CompletedTrialBalance],
) -> Result<(), String> {
    // Build only after all readers succeed and keep the final path untouched
    // until the complete database can be published with create-new semantics.
    let (_stage_directory, stage, mut file) = create_staged_file(output)
        .map_err(|_| "creating staged consolidated output failed".to_owned())?;
    let write_result = (|| -> Result<(), String> {
        let mut connection = Connection::open_in_memory()
            .map_err(|_| "opening in-memory consolidated SQLite output failed".to_owned())?;
        for item in completed {
            write_sqlite_with_account_catalog(
                &mut connection,
                &item.metadata,
                ReportBundle {
                    trial_balance: Some(&item.report),
                    general_ledger: None,
                },
                &item.account_catalog,
            )
            .map_err(|_| "writing consolidated SQLite output failed".to_owned())?;
            connection.execute_batch(
                "CREATE TABLE IF NOT EXISTS batch_trial_balance_sources (\
                 entity_id TEXT NOT NULL PRIMARY KEY, snapshot_id TEXT NOT NULL, manifest_index INTEGER NOT NULL\
                 ) STRICT;",
            ).map_err(|_| "writing consolidated SQLite output failed".to_owned())?;
            connection.execute(
                "INSERT INTO batch_trial_balance_sources(entity_id,snapshot_id,manifest_index) VALUES(?1,?2,?3)",
                rusqlite::params![item.entity_id, item.snapshot_id, item.input_index as i64],
            ).map_err(|_| "writing consolidated SQLite output failed".to_owned())?;
        }
        let serialized = connection
            .serialize(MAIN_DB)
            .map_err(|_| "serializing consolidated SQLite output failed".to_owned())?;
        file.write_all(&serialized)
            .map_err(|_| "writing staged consolidated SQLite output failed".to_owned())?;
        file.sync_all()
            .map_err(|_| "syncing staged consolidated SQLite output failed".to_owned())
    })();
    if write_result.is_err() {
        remove_staged_path(&stage, false);
        return write_result;
    }
    publish_staged_path(&stage, output, false, false, None)
        .map_err(|_| "publishing consolidated output failed".to_owned())
}

fn parse_csv(text: &str) -> Result<Vec<Vec<String>>, String> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut after_quote = false;
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if after_quote {
            match character {
                ',' => {
                    row.push(std::mem::take(&mut field));
                    after_quote = false;
                }
                '\n' => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                    after_quote = false;
                }
                '\r' => {
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                    after_quote = false;
                }
                _ => return Err("manifest has characters after a closing quote".to_owned()),
            }
            continue;
        }
        match character {
            '"' if quoted => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                    after_quote = true;
                }
            }
            '"' if field.is_empty() => quoted = true,
            '"' => return Err("manifest has a bare quote in an unquoted field".to_owned()),
            ',' if !quoted => {
                row.push(std::mem::take(&mut field));
            }
            '\n' if !quoted => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            '\r' if !quoted => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            value => field.push(value),
        }
    }
    if quoted {
        return Err("manifest contains an unterminated quoted field".to_owned());
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ledger() -> openqbw::Ledger {
        let retained = openqbw::Account::new(
            AccountId::new("SAMPLE_RE").unwrap(),
            "SAMPLE Retained Earnings",
            openqbw::AccountType::Equity,
            true,
        )
        .unwrap();
        openqbw::Ledger::new([retained], [], openqbw::LedgerCompleteness::Complete).unwrap()
    }

    fn temp(name: &str, extension: &str) -> PathBuf {
        std::env::temp_dir().join(format!("openqbw-{name}-{}.{extension}", std::process::id()))
    }

    fn sample_input(entity: &str, path: PathBuf) -> BatchTrialBalanceInput {
        BatchTrialBalanceInput {
            entity_id: entity.to_owned(),
            qbw_path: path,
            snapshot_id: format!("SAMPLE_SNAPSHOT_{entity}"),
            fiscal_year_start: "2026-01-01".to_owned(),
            retained_earnings_account_id: "SAMPLE_RE".to_owned(),
            retained_earnings_report_name: "SAMPLE Retained Earnings".to_owned(),
        }
    }

    #[test]
    fn manifest_is_strict_and_supports_quoted_paths() {
        let parsed = parse_manifest_csv(b"entity_id,qbw_path,snapshot_id,fiscal_year_start,retained_earnings_account_id,retained_earnings_report_name\nSAMPLE_A,\"C:/private,copy.qbw\",SAMPLE_HASH,2026-01-01,SAMPLE_RE,SAMPLE Retained Earnings\n").unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].qbw_path, PathBuf::from("C:/private,copy.qbw"));
        assert!(parse_manifest_csv(b"entity_id,qbw_path\n").is_err());
    }

    #[test]
    fn malformed_csv_fails_closed() {
        assert!(parse_manifest_csv(b"entity_id,qbw_path,snapshot_id,fiscal_year_start,retained_earnings_account_id,retained_earnings_report_name\nSAMPLE_A,\"unterminated,S,2026-01-01,R,SAMPLE\n").is_err());
        assert!(parse_manifest_csv(b"entity_id,qbw_path,snapshot_id,fiscal_year_start,retained_earnings_account_id,retained_earnings_report_name\nSAMPLE_A,plain\"quote,S,2026-01-01,R,SAMPLE\n").is_err());
        assert!(parse_manifest_csv(b"entity_id,qbw_path,snapshot_id,fiscal_year_start,retained_earnings_account_id,retained_earnings_report_name\nSAMPLE_A,\"quoted\"tail,S,2026-01-01,R,SAMPLE\n").is_err());
    }

    #[test]
    fn existing_output_is_never_opened() {
        let output = temp("batch-existing", "sqlite");
        std::fs::write(&output, b"SAMPLE_EXISTING").unwrap();
        let inputs = vec![BatchTrialBalanceInput {
            entity_id: "SAMPLE_A".into(),
            qbw_path: PathBuf::from("SAMPLE_MISSING.qbw"),
            snapshot_id: "SAMPLE_SNAPSHOT".into(),
            fiscal_year_start: "2026-01-01".into(),
            retained_earnings_account_id: "SAMPLE_RE".into(),
            retained_earnings_report_name: "SAMPLE Retained Earnings".into(),
        }];
        assert!(
            run_batch_trial_balance(
                inputs,
                "2026-01-31",
                1,
                "2026-01-31T00:00:00Z",
                &output,
                |_, _| unreachable!()
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&output).unwrap(), b"SAMPLE_EXISTING");
        std::fs::remove_file(output).unwrap();
    }

    #[test]
    fn parallel_success_commits_manifest_order_and_policy_metadata_to_sqlite() {
        let first = temp("batch-first", "qbw");
        let second = temp("batch-second", "qbw");
        let output = temp("batch-ordered", "sqlite");
        let _ = std::fs::remove_file(&output);
        std::fs::write(&first, b"SAMPLE_FIRST").unwrap();
        std::fs::write(&second, b"SAMPLE_SECOND").unwrap();
        run_batch_trial_balance(
            vec![
                sample_input("SAMPLE_B", second.clone()),
                sample_input("SAMPLE_A", first.clone()),
            ],
            "2026-01-31",
            2,
            "2026-01-31T00:00:00Z",
            &output,
            |_, _| Ok(sample_ledger()),
        )
        .unwrap();
        let connection = Connection::open(&output).unwrap();
        let rows = connection.prepare("SELECT entity_id, manifest_index FROM batch_trial_balance_sources ORDER BY manifest_index")
            .unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))
            .unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(
            rows,
            vec![("SAMPLE_B".to_owned(), 0), ("SAMPLE_A".to_owned(), 1)]
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM trial_balance_policy_metadata",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT source_file FROM report_metadata WHERE entity_id='SAMPLE_B'",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "SAMPLE_SNAPSHOT_SAMPLE_B"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT retained_earnings_report_name FROM trial_balance_policy_metadata WHERE entity_id='SAMPLE_B'",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "SAMPLE Retained Earnings"
        );
        drop(connection);
        std::fs::remove_file(first).unwrap();
        std::fs::remove_file(second).unwrap();
        std::fs::remove_file(output).unwrap();
    }

    #[test]
    fn worker_failure_leaves_no_consolidated_database() {
        let first = temp("batch-good", "qbw");
        let second = temp("batch-fail", "qbw");
        let output = temp("batch-no-partial", "sqlite");
        let _ = std::fs::remove_file(&output);
        std::fs::write(&first, b"SAMPLE_GOOD").unwrap();
        std::fs::write(&second, b"SAMPLE_FAIL").unwrap();
        let inputs = vec![
            sample_input("SAMPLE_A", first.clone()),
            sample_input("SAMPLE_B", second.clone()),
        ];
        let result = run_batch_trial_balance(
            inputs,
            "2026-01-31",
            2,
            "2026-01-31T00:00:00Z",
            &output,
            |bytes, _| {
                if bytes == b"SAMPLE_FAIL" {
                    anyhow::bail!("SAMPLE failure")
                } else {
                    Ok(sample_ledger())
                }
            },
        );
        assert!(result.is_err());
        assert!(!output.exists());
        std::fs::remove_file(first).unwrap();
        std::fs::remove_file(second).unwrap();
    }

    #[test]
    fn sqlite_merge_failure_removes_our_new_output() {
        let output = temp("batch-merge-failure", "sqlite");
        let _ = std::fs::remove_file(&output);
        let policy = QuickBooksAccrualTrialBalancePolicy::new(
            MaterializedPostingDate::parse_iso_date("2026-01-01")
                .unwrap()
                .accounting_date(),
            AccountId::new("SAMPLE_RE").unwrap(),
        );
        let report = sample_ledger()
            .quickbooks_accrual_trial_balance_as_of(
                MaterializedPostingDate::parse_iso_date("2026-01-31")
                    .unwrap()
                    .accounting_date(),
                TrialBalanceOptions::default(),
                &policy,
            )
            .unwrap();
        let malformed = CompletedTrialBalance {
            input_index: 0,
            entity_id: "SAMPLE_A".to_owned(),
            snapshot_id: "SAMPLE_SNAPSHOT".to_owned(),
            metadata: ReportMetadata {
                entity_id: String::new(),
                source_file: "SAMPLE_SNAPSHOT".to_owned(),
                parser_version: "SAMPLE".to_owned(),
                generated_at: "2026-01-31T00:00:00Z".to_owned(),
                trial_balance_policy: None,
            },
            report,
            account_catalog: vec![],
        };
        assert!(write_consolidated_sqlite(&output, &[malformed]).is_err());
        assert!(!output.exists());
    }
}

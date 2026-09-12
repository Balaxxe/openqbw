//! Deterministic encoders for immutable ledger-derived financial statements.

use openqbw::{FinancialStatement, FinancialStatementRow, MaterializedPostingDate};

use super::*;

fn validate_metadata(
    report: &FinancialStatement,
    metadata: &ReportMetadata,
) -> Result<(), ReportOutputError> {
    metadata.validate()?;
    match (report.policy(), metadata.trial_balance_policy.as_ref()) {
        (None, None) => Ok(()),
        (Some(policy), Some(source))
            if policy.retained_earnings_account_id.as_str()
                == source.retained_earnings_account_id
                && MaterializedPostingDate::parse_iso_date(&source.as_of)
                    .ok()
                    .map(|date| date.accounting_date())
                    == Some(report.as_of())
                && MaterializedPostingDate::parse_iso_date(&source.fiscal_year_start)
                    .ok()
                    .map(|date| date.accounting_date())
                    == Some(policy.fiscal_year_start) =>
        {
            Ok(())
        }
        _ => Err(ReportOutputError::InvalidTrialBalancePolicyMetadata),
    }
}

type AccountNames = BTreeMap<String, String>;

fn names(report: &FinancialStatement) -> Result<(AccountNames, AccountNames), ReportOutputError> {
    let full = account_full_names_with_catalog(report.accounts(), [])?;
    let display = account_display_names_with_catalog(report.accounts(), [], &full)?;
    Ok((full, display))
}

fn label<'a>(
    row: &'a FinancialStatementRow,
    metadata: &'a ReportMetadata,
    display: &'a BTreeMap<String, String>,
) -> &'a str {
    if let Some(account) = &row.account {
        if let Some(policy) = &metadata.trial_balance_policy
            && account.id.as_str() == policy.retained_earnings_account_id
            && let Some(name) = &policy.retained_earnings_report_name
        {
            return name;
        }
        return &display[account.id.as_str()];
    }
    &row.label
}

pub(crate) fn statement_csv(
    report: &FinancialStatement,
    metadata: &ReportMetadata,
) -> Result<String, ReportOutputError> {
    validate_metadata(report, metadata)?;
    let (full, display) = names(report)?;
    let mut out = String::from(
        "entity_id,report_type,from_day,as_of_day,row_index,row_kind,row_key,section,label,account_id,account_number,account_name,account_full_name,account_display_name,parent_account_id,account_type,quickbooks_classification,active,activity,amount_cents,amount,net_cents,net,source_file,parser_version,generated_at,tb_policy_source,tb_policy_as_of,tb_policy_fiscal_year_start,tb_policy_retained_earnings_account_id,tb_policy_retained_earnings_report_name\n",
    );
    let from = report.from().map(|value| value.to_string());
    let as_of = report.as_of().to_string();
    let policy = metadata.trial_balance_policy.as_ref();
    for (index, row) in report.rows().iter().enumerate() {
        let account = row.account.as_ref();
        let index = index.to_string();
        let amount = row.amount_minor_units.to_string();
        let decimal = format_cents(row.amount_minor_units);
        let net = row.signed_minor_units.map(|value| value.to_string());
        let net_decimal = row.signed_minor_units.map(format_cents);
        csv_row(
            &mut out,
            &[
                Some(&metadata.entity_id),
                Some(report.kind().as_str()),
                from.as_deref(),
                Some(&as_of),
                Some(&index),
                Some(row.kind),
                Some(&row.key),
                Some(row.section),
                Some(label(row, metadata, &display)),
                account.map(|value| value.id.as_str()),
                account.and_then(|value| value.account_number.as_deref()),
                account.map(|value| value.name.as_str()),
                account.map(|value| full[value.id.as_str()].as_str()),
                account.map(|value| display[value.id.as_str()].as_str()),
                account.and_then(|value| value.parent_account_id.as_ref().map(|id| id.as_str())),
                account.map(|value| account_type_name(&value.account_type)),
                account.and_then(|value| {
                    value
                        .quickbooks_classification
                        .map(openqbw::QuickBooksAccountClassification::source_label)
                }),
                account.and_then(|value| csv_legacy_active(value.activity)),
                account.map(|value| value.activity.as_str()),
                Some(&amount),
                Some(&decimal),
                net.as_deref(),
                net_decimal.as_deref(),
                Some(&metadata.source_file),
                Some(&metadata.parser_version),
                Some(&metadata.generated_at),
                policy.map(|value| value.source.as_str()),
                policy.map(|value| value.as_of.as_str()),
                policy.map(|value| value.fiscal_year_start.as_str()),
                policy.map(|value| value.retained_earnings_account_id.as_str()),
                policy.and_then(|value| value.retained_earnings_report_name.as_deref()),
            ],
        );
    }
    Ok(out)
}

pub(crate) fn statement_json(
    report: &FinancialStatement,
    metadata: &ReportMetadata,
) -> Result<String, ReportOutputError> {
    validate_metadata(report, metadata)?;
    let (full, display) = names(report)?;
    let mut out = String::from("{\"metadata\":");
    out.push_str(&json_metadata(metadata, true));
    json_key_string(&mut out, "report_type", report.kind().as_str());
    json_key_optional_number(&mut out, "from_day", report.from().map(i64::from));
    json_key_number(&mut out, "as_of_day", i128::from(report.as_of()));
    out.push_str(",\"accounts\":[");
    for (index, account) in report.accounts().iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        json_account(&mut out, account, &full, &display)?;
    }
    out.push_str("],\"rows\":[");
    for (index, row) in report.rows().iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        out.push('{');
        json_key_string_no_prefix(&mut out, "row_key", &row.key);
        json_key_number(&mut out, "row_index", index as i128);
        json_key_string(&mut out, "row_kind", row.kind);
        json_key_string(&mut out, "section", row.section);
        json_key_string(&mut out, "label", label(row, metadata, &display));
        json_key_optional_string(
            &mut out,
            "account_id",
            row.account.as_ref().map(|account| account.id.as_str()),
        );
        json_key_number(&mut out, "amount_cents", i128::from(row.amount_minor_units));
        json_key_string(&mut out, "amount", &format_cents(row.amount_minor_units));
        json_key_optional_number(&mut out, "net_cents", row.signed_minor_units);
        json_key_optional_string(
            &mut out,
            "net",
            row.signed_minor_units.map(format_cents).as_deref(),
        );
        out.push('}');
    }
    out.push_str("]}\n");
    Ok(out)
}

pub(crate) fn write_statement_sqlite(
    connection: &mut Connection,
    report: &FinancialStatement,
    metadata: &ReportMetadata,
) -> Result<(), ReportOutputError> {
    validate_metadata(report, metadata)?;
    let (full, display) = names(report)?;
    let transaction = connection.transaction()?;
    create_schema(&transaction)?;
    transaction.execute_batch("CREATE TABLE IF NOT EXISTS financial_statement_metadata (
        entity_id TEXT NOT NULL, report_type TEXT NOT NULL, period_start_day INTEGER NOT NULL, as_of_day INTEGER NOT NULL,
        from_day INTEGER, source_file TEXT NOT NULL, parser_version TEXT NOT NULL, generated_at TEXT NOT NULL,
        fiscal_year_start_day INTEGER, retained_earnings_account_id TEXT, retained_earnings_report_name TEXT, policy_source TEXT,
        PRIMARY KEY(entity_id,report_type,period_start_day,as_of_day)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS financial_statement_rows (
        entity_id TEXT NOT NULL, report_type TEXT NOT NULL, period_start_day INTEGER NOT NULL, as_of_day INTEGER NOT NULL,
        row_index INTEGER NOT NULL, row_key TEXT NOT NULL, row_kind TEXT NOT NULL, section TEXT NOT NULL, label TEXT NOT NULL,
        account_id TEXT, amount_cents INTEGER NOT NULL, net_cents INTEGER,
        PRIMARY KEY(entity_id,report_type,period_start_day,as_of_day,row_key)
    ) STRICT;")?;
    let start = report.from().unwrap_or(report.as_of());
    let key = params![
        metadata.entity_id,
        report.kind().as_str(),
        start,
        report.as_of()
    ];
    transaction.execute("DELETE FROM financial_statement_rows WHERE entity_id=?1 AND report_type=?2 AND period_start_day=?3 AND as_of_day=?4", key)?;
    transaction.execute("DELETE FROM financial_statement_metadata WHERE entity_id=?1 AND report_type=?2 AND period_start_day=?3 AND as_of_day=?4", key)?;
    transaction.execute(
        "INSERT INTO financial_statement_metadata VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![
            metadata.entity_id,
            report.kind().as_str(),
            start,
            report.as_of(),
            report.from(),
            metadata.source_file,
            metadata.parser_version,
            metadata.generated_at,
            report.policy().map(|policy| policy.fiscal_year_start),
            report
                .policy()
                .map(|policy| policy.retained_earnings_account_id.as_str()),
            metadata
                .trial_balance_policy
                .as_ref()
                .and_then(|policy| policy.retained_earnings_report_name.as_deref()),
            metadata
                .trial_balance_policy
                .as_ref()
                .map(|policy| policy.source.as_str()),
        ],
    )?;
    for account in report.accounts() {
        upsert_account(
            &transaction,
            &metadata.entity_id,
            account,
            &full[account.id.as_str()],
            &display[account.id.as_str()],
        )?;
    }
    for (index, row) in report.rows().iter().enumerate() {
        transaction.execute(
            "INSERT INTO financial_statement_rows VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                metadata.entity_id,
                report.kind().as_str(),
                start,
                report.as_of(),
                index as i64,
                row.key,
                row.kind,
                row.section,
                label(row, metadata, &display),
                row.account.as_ref().map(|account| account.id.as_str()),
                row.amount_minor_units,
                row.signed_minor_units,
            ],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openqbw::{
        AccountId, Ledger, LedgerCompleteness, Posting, PostingId, PostingProvenance,
        QuickBooksAccountClassification as Class, QuickBooksAccrualTrialBalancePolicy,
        TransactionId, TrialBalanceOptions,
    };

    fn day(value: &str) -> i32 {
        MaterializedPostingDate::parse_iso_date(value)
            .unwrap()
            .accounting_date()
    }

    fn fixture() -> (Ledger, ReportMetadata) {
        let accounts = [
            ("cash", "Cash", Class::Bank),
            ("income", "Revenue", Class::Income),
            ("child", "SAMPLE, \"Sales\"\nLine", Class::Income),
            ("retained", "Retained Earnings", Class::Equity),
        ]
        .into_iter()
        .map(|(id, name, class)| {
            let row = Account::new(
                AccountId::new(id).unwrap(),
                name,
                class.trial_balance_type(),
                true,
            )
            .unwrap()
            .with_quickbooks_classification(class);
            if id == "child" {
                row.with_hierarchy(None, Some(AccountId::new("income").unwrap()))
                    .unwrap()
            } else {
                row
            }
        })
        .collect::<Vec<_>>();
        let postings = [("cash", 501), ("child", -501)]
            .into_iter()
            .map(|(id, amount)| Posting {
                transaction_id: TransactionId::new("synthetic").unwrap(),
                id: PostingId::new(id).unwrap(),
                account_id: AccountId::new(id).unwrap(),
                date: day("2026-01-01"),
                signed_minor_units: amount,
                current_state: CurrentState::Current,
                provenance: PostingProvenance::new(id, None, None, "synthetic").unwrap(),
                transaction_type: None,
                memo: None,
            });
        let ledger = Ledger::new(accounts, postings, LedgerCompleteness::Complete).unwrap();
        let metadata = ReportMetadata {
            entity_id: "SAMPLE".into(),
            source_file: "synthetic".into(),
            parser_version: "test".into(),
            generated_at: "2026-01-31T00:00:00Z".into(),
            trial_balance_policy: None,
        };
        (ledger, metadata)
    }

    #[test]
    fn all_formats_preserve_cents_row_identity_hierarchy_and_escaping() {
        let (ledger, metadata) = fixture();
        let pnl = ledger
            .profit_and_loss(
                day("2026-01-01"),
                day("2026-01-31"),
                TrialBalanceOptions::default(),
            )
            .unwrap();
        let csv = statement_csv(&pnl, &metadata).unwrap();
        assert!(csv.contains("Revenue:SAMPLE, \"\"Sales\"\"\nLine"));
        let total = csv
            .lines()
            .find(|line| line.contains(",calculated,net_income,"))
            .unwrap()
            .split(',')
            .collect::<Vec<_>>();
        assert_eq!(total.len(), csv.lines().next().unwrap().split(',').count());
        assert_eq!(total[19], "501");
        assert_eq!(total[20], "5.01");
        assert_eq!(total[21], "");
        let json = statement_json(&pnl, &metadata).unwrap();
        let mut connection = Connection::open_in_memory().unwrap();
        let valid: i64 = connection
            .query_row("SELECT json_valid(?1)", [&json], |row| row.get(0))
            .unwrap();
        assert_eq!(valid, 1);
        let json_rows: Vec<(String, i64, Option<i64>)> = connection.prepare("SELECT json_extract(value,'$.row_key'),json_extract(value,'$.amount_cents'),json_extract(value,'$.net_cents') FROM json_each(?1,'$.rows') ORDER BY json_extract(value,'$.row_index')").unwrap().query_map([&json], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap().collect::<Result<_,_>>().unwrap();
        write_statement_sqlite(&mut connection, &pnl, &metadata).unwrap();
        let sql_rows: Vec<(String, i64, Option<i64>)> = connection.prepare("SELECT row_key,amount_cents,net_cents FROM financial_statement_rows ORDER BY row_index").unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap().collect::<Result<_,_>>().unwrap();
        assert_eq!(sql_rows, json_rows);
        assert_eq!(sql_rows[0], ("account:child".into(), 501, Some(-501)));
        let parent: String = connection
            .query_row(
                "SELECT account_full_name FROM accounts WHERE account_id='income'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(parent, "Revenue");
        assert_eq!(json, statement_json(&pnl, &metadata).unwrap());
        assert_eq!(csv, statement_csv(&pnl, &metadata).unwrap());
    }

    #[test]
    fn balance_sheet_policy_must_match_the_report_and_alias_is_presentation_only() {
        let (ledger, mut metadata) = fixture();
        let policy = QuickBooksAccrualTrialBalancePolicy::new(
            day("2026-01-01"),
            AccountId::new("retained").unwrap(),
        );
        let report = ledger
            .balance_sheet_as_of(
                day("2026-01-31"),
                TrialBalanceOptions {
                    include_zero_balance_accounts: true,
                },
                &policy,
            )
            .unwrap();
        assert!(statement_json(&report, &metadata).is_err());
        metadata.trial_balance_policy = Some(TrialBalancePolicyProvenance {
            source: "explicit".into(),
            fiscal_year_start: "2026-01-01".into(),
            as_of: "2026-01-31".into(),
            retained_earnings_account_id: "retained".into(),
            retained_earnings_report_name: Some("SAMPLE Equity Label".into()),
        });
        let mut connection = Connection::open_in_memory().unwrap();
        write_statement_sqlite(&mut connection, &report, &metadata).unwrap();
        let row_label: String = connection
            .query_row(
                "SELECT label FROM financial_statement_rows WHERE row_key='account:retained'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(row_label, "SAMPLE Equity Label");
        let account_name: String = connection
            .query_row(
                "SELECT account_name FROM accounts WHERE account_id='retained'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(account_name, "Retained Earnings");
        let json = statement_json(&report, &metadata).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT json_extract(?1,'$.metadata.trial_balance_policy.fiscal_year_start')",
                    [&json],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "2026-01-01"
        );
        let saved = metadata.trial_balance_policy.clone();
        for field in 0..3 {
            metadata.trial_balance_policy = saved.clone();
            let altered = metadata.trial_balance_policy.as_mut().unwrap();
            match field {
                0 => altered.as_of = "2026-01-30".into(),
                1 => altered.fiscal_year_start = "2025-01-01".into(),
                _ => altered.retained_earnings_account_id = "cash".into(),
            }
            assert!(statement_csv(&report, &metadata).is_err());
            assert!(statement_json(&report, &metadata).is_err());
            assert!(write_statement_sqlite(&mut connection, &report, &metadata).is_err());
        }
    }

    #[test]
    fn sqlite_preserves_distinct_periods_entities_and_rolls_back_failed_replacement() {
        let (ledger, mut metadata) = fixture();
        let first = ledger
            .profit_and_loss(
                day("2026-01-01"),
                day("2026-01-31"),
                TrialBalanceOptions::default(),
            )
            .unwrap();
        let second = ledger
            .profit_and_loss(
                day("2026-01-02"),
                day("2026-01-31"),
                TrialBalanceOptions::default(),
            )
            .unwrap();
        let mut connection = Connection::open_in_memory().unwrap();
        write_statement_sqlite(&mut connection, &first, &metadata).unwrap();
        write_statement_sqlite(&mut connection, &second, &metadata).unwrap();
        write_statement_sqlite(&mut connection, &first, &metadata).unwrap();
        metadata.entity_id = "SAMPLE_B".into();
        write_statement_sqlite(&mut connection, &first, &metadata).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM financial_statement_metadata",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            3
        );
        let before: i64 = connection
            .query_row("SELECT COUNT(*) FROM financial_statement_rows", [], |row| {
                row.get(0)
            })
            .unwrap();
        connection.execute_batch("CREATE TRIGGER reject_statement BEFORE INSERT ON financial_statement_rows BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;").unwrap();
        metadata.source_file = "changed".into();
        assert!(write_statement_sqlite(&mut connection, &first, &metadata).is_err());
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM financial_statement_rows", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            before
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM financial_statement_metadata WHERE source_file='changed'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }
}

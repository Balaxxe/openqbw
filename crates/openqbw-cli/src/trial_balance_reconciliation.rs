//! Parser and exact-cents reconciliation for native QuickBooks Trial Balance
//! CSV exports and normalized `openqbw accounting-report --format csv`
//! output.
//!
//! This module deliberately has no QuickBooks/SDK dependency.  It consumes the
//! CSV export produced by QuickBooks Desktop and is intended as the acceptance
//! oracle for an independently decoded QBW posting stream.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

/// A Trial Balance expressed as signed account balances in cents.
///
/// Positive values are debit balances; negative values are credit balances.
/// Account labels are preserved exactly (other than surrounding whitespace),
/// because reconciliation must be account-for-account rather than fuzzy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrialBalance {
    pub balances_cents: BTreeMap<String, i64>,
    pub total_debits_cents: i64,
    pub total_credits_cents: i64,
}

impl TrialBalance {
    pub fn from_balances<I>(balances: I) -> Result<Self, TrialBalanceError>
    where
        I: IntoIterator<Item = (String, i64)>,
    {
        let mut result = Self {
            balances_cents: BTreeMap::new(),
            total_debits_cents: 0,
            total_credits_cents: 0,
        };
        for (account, balance) in balances {
            let account = account.trim().to_owned();
            if account.is_empty() {
                return Err(TrialBalanceError::EmptyAccountName);
            }
            if result
                .balances_cents
                .insert(account.clone(), balance)
                .is_some()
            {
                return Err(TrialBalanceError::DuplicateAccount(account));
            }
            if balance >= 0 {
                result.total_debits_cents = result
                    .total_debits_cents
                    .checked_add(balance)
                    .ok_or(TrialBalanceError::AmountOverflow)?;
            } else {
                let credit = balance
                    .checked_neg()
                    .ok_or(TrialBalanceError::AmountOverflow)?;
                result.total_credits_cents = result
                    .total_credits_cents
                    .checked_add(credit)
                    .ok_or(TrialBalanceError::AmountOverflow)?;
            }
        }
        Ok(result)
    }

    pub fn is_balanced(&self) -> bool {
        self.total_debits_cents == self.total_credits_cents
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountVariance {
    pub account: String,
    /// `actual - reference`, in cents. Positive means the actual balance is
    /// more debit (or less credit) than the reference balance.
    pub variance_cents: i128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrialBalanceReconciliation {
    pub missing_accounts: Vec<AccountVariance>,
    pub extra_accounts: Vec<AccountVariance>,
    pub mismatched_accounts: Vec<AccountVariance>,
    pub reference_total_debits_cents: i64,
    pub reference_total_credits_cents: i64,
    pub actual_total_debits_cents: i64,
    pub actual_total_credits_cents: i64,
    pub debit_total_variance_cents: i128,
    pub credit_total_variance_cents: i128,
    pub net_total_variance_cents: i128,
    pub max_account_variance_cents: i128,
}

impl TrialBalanceReconciliation {
    pub fn passes(&self) -> bool {
        self.missing_accounts.is_empty()
            && self.extra_accounts.is_empty()
            && self.mismatched_accounts.is_empty()
            && self.reference_total_debits_cents == self.reference_total_credits_cents
            && self.actual_total_debits_cents == self.actual_total_credits_cents
            && self.debit_total_variance_cents == 0
            && self.credit_total_variance_cents == 0
            && self.net_total_variance_cents == 0
            && self.max_account_variance_cents == 0
    }

    /// A stable, machine- and audit-friendly one-line status.  Detailed
    /// account differences remain available in the public vectors above.
    pub fn status_line(&self) -> String {
        if self.passes() {
            "PASS: all accounts and totals reconcile exactly to $0.00".to_owned()
        } else {
            format!(
                "FAIL: missing={} extra={} mismatched={} reference_balanced={} actual_balanced={} debit_variance_cents={} credit_variance_cents={} net_variance_cents={} max_account_variance_cents={}",
                self.missing_accounts.len(),
                self.extra_accounts.len(),
                self.mismatched_accounts.len(),
                self.reference_total_debits_cents == self.reference_total_credits_cents,
                self.actual_total_debits_cents == self.actual_total_credits_cents,
                self.debit_total_variance_cents,
                self.credit_total_variance_cents,
                self.net_total_variance_cents,
                self.max_account_variance_cents,
            )
        }
    }
}

/// Compare two Trial Balances exactly, account by account and cent by cent.
pub fn reconcile_trial_balances(
    reference: &TrialBalance,
    actual: &TrialBalance,
) -> TrialBalanceReconciliation {
    let mut missing_accounts = Vec::new();
    let mut extra_accounts = Vec::new();
    let mut mismatched_accounts = Vec::new();
    let mut max_account_variance_cents = 0_i128;

    for (account, reference_balance) in &reference.balances_cents {
        match actual.balances_cents.get(account) {
            None => {
                let variance = -i128::from(*reference_balance);
                max_account_variance_cents = max_account_variance_cents.max(variance.abs());
                missing_accounts.push(AccountVariance {
                    account: account.clone(),
                    variance_cents: variance,
                });
            }
            Some(actual_balance) if actual_balance != reference_balance => {
                let variance = i128::from(*actual_balance) - i128::from(*reference_balance);
                max_account_variance_cents = max_account_variance_cents.max(variance.abs());
                mismatched_accounts.push(AccountVariance {
                    account: account.clone(),
                    variance_cents: variance,
                });
            }
            Some(_) => {}
        }
    }
    for (account, actual_balance) in &actual.balances_cents {
        if !reference.balances_cents.contains_key(account) {
            let variance = i128::from(*actual_balance);
            max_account_variance_cents = max_account_variance_cents.max(variance.abs());
            extra_accounts.push(AccountVariance {
                account: account.clone(),
                variance_cents: variance,
            });
        }
    }

    TrialBalanceReconciliation {
        missing_accounts,
        extra_accounts,
        mismatched_accounts,
        reference_total_debits_cents: reference.total_debits_cents,
        reference_total_credits_cents: reference.total_credits_cents,
        actual_total_debits_cents: actual.total_debits_cents,
        actual_total_credits_cents: actual.total_credits_cents,
        debit_total_variance_cents: i128::from(actual.total_debits_cents)
            - i128::from(reference.total_debits_cents),
        credit_total_variance_cents: i128::from(actual.total_credits_cents)
            - i128::from(reference.total_credits_cents),
        net_total_variance_cents: (i128::from(actual.total_debits_cents)
            - i128::from(actual.total_credits_cents))
            - (i128::from(reference.total_debits_cents)
                - i128::from(reference.total_credits_cents)),
        max_account_variance_cents,
    }
}

/// Render deterministic, exact-cent account diagnostics for a failed
/// reconciliation.  Callers decide whether to print these because account
/// labels are business data; this library never emits them implicitly.
pub fn reconciliation_diagnostic_lines(
    reference: &TrialBalance,
    actual: &TrialBalance,
    reconciliation: &TrialBalanceReconciliation,
) -> Vec<String> {
    let mut lines = Vec::new();
    for variance in &reconciliation.missing_accounts {
        let expected = reference.balances_cents[variance.account.as_str()];
        lines.push(format!(
            "missing account={:?} reference_cents={} actual_cents=<absent> variance_cents={}",
            variance.account, expected, variance.variance_cents
        ));
    }
    for variance in &reconciliation.extra_accounts {
        let observed = actual.balances_cents[variance.account.as_str()];
        lines.push(format!(
            "extra account={:?} reference_cents=<absent> actual_cents={} variance_cents={}",
            variance.account, observed, variance.variance_cents
        ));
    }
    for variance in &reconciliation.mismatched_accounts {
        let expected = reference.balances_cents[variance.account.as_str()];
        let observed = actual.balances_cents[variance.account.as_str()];
        lines.push(format!(
            "mismatch account={:?} reference_cents={} actual_cents={} variance_cents={}",
            variance.account, expected, observed, variance.variance_cents
        ));
    }
    lines
}

/// Parse either a QuickBooks Desktop Trial Balance CSV export or the
/// normalized CSV emitted by `openqbw accounting-report --report
/// trial-balance --format csv`.
///
/// Native exports have account labels and display-money Debit/Credit columns.
/// Normalized extractor exports have leaf account labels, hierarchy-qualified
/// account labels, immutable account IDs, and integer-cent columns.
/// Reconciliation intentionally joins native Desktop labels to
/// `account_full_name`: native reports do not carry the extractor's internal
/// account ID and leaf account names are not unique. The native account-number
/// presentation wrapper is removed before joining. Older normalized CSVs
/// without that column remain parseable using `account_name`.
/// The normalized parser
/// verifies its debit, credit, and signed-cent fields agree before accepting a
/// row, so a malformed generated report cannot silently reconcile.
pub fn parse_trial_balance_csv(bytes: &[u8]) -> Result<TrialBalance, TrialBalanceError> {
    let text = decode_windows_1252(bytes);
    let rows = parse_csv_records(&text)?;
    if let Some(header) = find_normalized_header(&rows) {
        return parse_normalized_trial_balance_csv_rows(&rows, header);
    }
    parse_quickbooks_trial_balance_csv_rows(&rows)
}

/// Parse a QuickBooks Desktop Trial Balance CSV export.
///
/// The report preamble is tolerated. The first header record containing
/// `Account`, `Debit`, and `Credit` columns establishes the table.  Quoted
/// commas, CRLF line endings, and Windows-1252 text are supported. Amounts
/// are converted directly to cents; floating point is never used.
pub fn parse_quickbooks_trial_balance_csv(bytes: &[u8]) -> Result<TrialBalance, TrialBalanceError> {
    let text = decode_windows_1252(bytes);
    let rows = parse_csv_records(&text)?;
    parse_quickbooks_trial_balance_csv_rows(&rows)
}

fn parse_quickbooks_trial_balance_csv_rows(
    rows: &[Vec<String>],
) -> Result<TrialBalance, TrialBalanceError> {
    let (account_col, debit_col, credit_col, data_start) = find_header(rows)?;
    let mut balances = Vec::new();

    for row in rows.iter().skip(data_start) {
        let account = cell(row, account_col).trim();
        if account.is_empty() || is_total_row(account) {
            continue;
        }
        let debit_cell = cell(row, debit_col).trim();
        let credit_cell = cell(row, credit_col).trim();
        // Preamble/footer rows can appear after the table.  A genuine account
        // row must carry an amount in at least one balance column.
        if debit_cell.is_empty() && credit_cell.is_empty() {
            continue;
        }
        let debit = parse_money_cents(debit_cell)?;
        let credit = parse_money_cents(credit_cell)?;
        let balance = debit
            .checked_sub(credit)
            .ok_or(TrialBalanceError::AmountOverflow)?;
        // SDK summary-report exports can emit an explicit `0.00` row for
        // every chart account, while the normalized Trial Balance defaults to
        // QuickBooks' nonzero presentation. A zero row cannot affect either
        // account variance or totals and must not become a spurious missing
        // account during reconciliation.
        if balance == 0 {
            continue;
        }
        balances.push((canonical_native_account_full_name(account), balance));
    }
    if balances.is_empty() {
        return Err(TrialBalanceError::NoAccountRows);
    }
    TrialBalance::from_balances(balances)
}

#[derive(Debug, Clone, Copy)]
struct NormalizedHeader {
    account_label: usize,
    debit_cents: usize,
    credit_cents: usize,
    net_cents: usize,
    data_start: usize,
}

fn find_normalized_header(rows: &[Vec<String>]) -> Option<NormalizedHeader> {
    rows.iter().enumerate().find_map(|(row_index, row)| {
        let mut account_name = None;
        let mut account_full_name = None;
        let mut account_display_name = None;
        let mut debit_cents = None;
        let mut credit_cents = None;
        let mut net_cents = None;
        for (index, value) in row.iter().enumerate() {
            match value.trim().to_ascii_lowercase().as_str() {
                "account_name" => account_name = Some(index),
                "account_full_name" => account_full_name = Some(index),
                "account_display_name" => account_display_name = Some(index),
                "debit_cents" => debit_cents = Some(index),
                "credit_cents" => credit_cents = Some(index),
                "net_cents" => net_cents = Some(index),
                _ => {}
            }
        }
        Some(NormalizedHeader {
            account_label: account_display_name
                .or(account_full_name)
                .or(account_name)?,
            debit_cents: debit_cents?,
            credit_cents: credit_cents?,
            net_cents: net_cents?,
            data_start: row_index + 1,
        })
    })
}

fn parse_normalized_trial_balance_csv_rows(
    rows: &[Vec<String>],
    header: NormalizedHeader,
) -> Result<TrialBalance, TrialBalanceError> {
    let mut balances = Vec::new();
    for row in rows.iter().skip(header.data_start) {
        let account = cell(row, header.account_label).trim();
        // A normalized report has no permitted footer, but an empty trailing
        // line is harmless. Any nonempty partial row is an error below.
        if account.is_empty()
            && cell(row, header.debit_cents).trim().is_empty()
            && cell(row, header.credit_cents).trim().is_empty()
            && cell(row, header.net_cents).trim().is_empty()
        {
            continue;
        }
        if account.is_empty() {
            return Err(TrialBalanceError::EmptyAccountName);
        }
        let debit = parse_normalized_cents(cell(row, header.debit_cents), "debit_cents", true)?;
        let credit = parse_normalized_cents(cell(row, header.credit_cents), "credit_cents", true)?;
        let net = parse_normalized_cents(cell(row, header.net_cents), "net_cents", false)?
            .ok_or_else(|| TrialBalanceError::MissingNormalizedCents {
                account: account.to_owned(),
                column: "net_cents",
            })?;
        let debit = debit.unwrap_or(0);
        let credit = credit.unwrap_or(0);
        let calculated = debit
            .checked_sub(credit)
            .ok_or(TrialBalanceError::AmountOverflow)?;
        if calculated != net {
            return Err(TrialBalanceError::InconsistentNormalizedRow {
                account: account.to_owned(),
                debit_cents: debit,
                credit_cents: credit,
                net_cents: net,
            });
        }
        balances.push((canonical_native_account_full_name(account), net));
    }
    if balances.is_empty() {
        return Err(TrialBalanceError::NoAccountRows);
    }
    TrialBalance::from_balances(balances)
}

fn parse_normalized_cents(
    value: &str,
    column: &'static str,
    nonnegative: bool,
) -> Result<Option<i64>, TrialBalanceError> {
    let text = value.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let cents = text
        .parse::<i64>()
        .map_err(|_| TrialBalanceError::InvalidNormalizedCents {
            column,
            value: text.to_owned(),
        })?;
    if nonnegative && cents < 0 {
        return Err(TrialBalanceError::InvalidNormalizedCents {
            column,
            value: text.to_owned(),
        });
    }
    Ok(Some(cents))
}

fn cell(row: &[String], index: usize) -> &str {
    row.get(index).map(String::as_str).unwrap_or("")
}

fn is_total_row(account: &str) -> bool {
    let folded = account.trim().to_ascii_lowercase();
    folded == "total" || folded.starts_with("total ") || folded.starts_with("total:")
}

/// Removes only the proven native presentation wrapper
/// `account-number + whitespace + middle-dot + whitespace`. The normalized
/// join key remains the number-free hierarchy-qualified account path.
pub(crate) fn canonical_native_account_full_name(account: &str) -> String {
    let account = account.trim();
    let Some((number, name)) = account.split_once('·') else {
        return account.to_owned();
    };
    if !number.trim().is_empty()
        && number.trim().bytes().all(|byte| byte.is_ascii_digit())
        && number.chars().last().is_some_and(char::is_whitespace)
        && name.chars().next().is_some_and(char::is_whitespace)
    {
        name.trim_start().to_owned()
    } else {
        account.to_owned()
    }
}

fn find_header(rows: &[Vec<String>]) -> Result<(usize, usize, usize, usize), TrialBalanceError> {
    for (row_index, row) in rows.iter().enumerate() {
        let mut account = None;
        let mut debit = None;
        let mut credit = None;
        for (index, value) in row.iter().enumerate() {
            match value.trim().to_ascii_lowercase().as_str() {
                "account" | "account name" => account = Some(index),
                "debit" | "debits" => debit = Some(index),
                "credit" | "credits" => credit = Some(index),
                _ => {}
            }
        }
        if let (Some(account), Some(debit), Some(credit)) = (account, debit, credit) {
            return Ok((account, debit, credit, row_index + 1));
        }
        // Native Desktop Trial Balance exports can leave the account heading
        // blank and emit just `,"Debit","Credit"`.  The first physical
        // column is still the account label in subsequent rows, so accepting
        // this exact shape avoids inventing a report-specific export setting.
        // Do not generalize this to arbitrary missing-header CSV: the account
        // column must be physically present before the Debit column.
        if let (None, Some(debit), Some(credit)) = (account, debit, credit)
            && debit > 0
            && credit > debit
        {
            return Ok((0, debit, credit, row_index + 1));
        }
    }
    Err(TrialBalanceError::MissingRequiredHeader)
}

pub(crate) fn parse_money_cents(value: &str) -> Result<i64, TrialBalanceError> {
    let mut text = value.trim();
    if text.is_empty() || text == "-" {
        return Ok(0);
    }
    let mut negative = false;
    if text.starts_with('(') && text.ends_with(')') {
        negative = true;
        text = &text[1..text.len() - 1];
    }
    if let Some(rest) = text.strip_prefix('-') {
        negative = true;
        text = rest;
    } else if let Some(rest) = text.strip_prefix('+') {
        text = rest;
    }
    let text = text.trim().strip_prefix('$').unwrap_or(text.trim());
    let compact: String = text.chars().filter(|c| *c != ',' && *c != ' ').collect();
    if compact.is_empty() {
        return Err(TrialBalanceError::InvalidAmount(value.to_owned()));
    }
    let (whole, fraction) = match compact.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (compact.as_str(), ""),
    };
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 2
    {
        return Err(TrialBalanceError::InvalidAmount(value.to_owned()));
    }
    let whole: i64 = whole
        .parse()
        .map_err(|_| TrialBalanceError::AmountOverflow)?;
    let fractional = match fraction.len() {
        0 => 0,
        1 => i64::from(fraction.as_bytes()[0] - b'0') * 10,
        2 => {
            i64::from(fraction.as_bytes()[0] - b'0') * 10 + i64::from(fraction.as_bytes()[1] - b'0')
        }
        _ => unreachable!(),
    };
    let cents = whole
        .checked_mul(100)
        .and_then(|n| n.checked_add(fractional))
        .ok_or(TrialBalanceError::AmountOverflow)?;
    Ok(if negative { -cents } else { cents })
}

pub(crate) fn decode_windows_1252(bytes: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_owned();
    }
    bytes
        .iter()
        .map(|&byte| match byte {
            0x80 => '\u{20AC}',
            0x82 => '\u{201A}',
            0x83 => '\u{0192}',
            0x84 => '\u{201E}',
            0x85 => '\u{2026}',
            0x86 => '\u{2020}',
            0x87 => '\u{2021}',
            0x88 => '\u{02C6}',
            0x89 => '\u{2030}',
            0x8A => '\u{0160}',
            0x8B => '\u{2039}',
            0x8C => '\u{0152}',
            0x8E => '\u{017D}',
            0x91 => '\u{2018}',
            0x92 => '\u{2019}',
            0x93 => '\u{201C}',
            0x94 => '\u{201D}',
            0x95 => '\u{2022}',
            0x96 => '\u{2013}',
            0x97 => '\u{2014}',
            0x98 => '\u{02DC}',
            0x99 => '\u{2122}',
            0x9A => '\u{0161}',
            0x9B => '\u{203A}',
            0x9C => '\u{0153}',
            0x9E => '\u{017E}',
            0x9F => '\u{0178}',
            other => char::from_u32(other as u32).unwrap(),
        })
        .collect()
}

pub(crate) fn parse_csv_records(text: &str) -> Result<Vec<Vec<String>>, TrialBalanceError> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if quoted {
            match ch {
                '"' if chars.peek() == Some(&'"') => {
                    field.push('"');
                    chars.next();
                }
                '"' => quoted = false,
                _ => field.push(ch),
            }
            continue;
        }
        match ch {
            '"' if field.is_empty() => quoted = true,
            ',' => {
                row.push(std::mem::take(&mut field));
            }
            '\n' => {
                if field.ends_with('\r') {
                    field.pop();
                }
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            _ => field.push(ch),
        }
    }
    if quoted {
        return Err(TrialBalanceError::UnclosedQuote);
    }
    if !field.is_empty() || !row.is_empty() {
        if field.ends_with('\r') {
            field.pop();
        }
        row.push(field);
        rows.push(row);
    }
    Ok(rows)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrialBalanceError {
    MissingRequiredHeader,
    NoAccountRows,
    EmptyAccountName,
    DuplicateAccount(String),
    InvalidAmount(String),
    InvalidNormalizedCents {
        column: &'static str,
        value: String,
    },
    MissingNormalizedCents {
        account: String,
        column: &'static str,
    },
    InconsistentNormalizedRow {
        account: String,
        debit_cents: i64,
        credit_cents: i64,
        net_cents: i64,
    },
    AmountOverflow,
    UnclosedQuote,
}

impl fmt::Display for TrialBalanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequiredHeader => {
                f.write_str("CSV has no Account/Debit/Credit header row")
            }
            Self::NoAccountRows => f.write_str("CSV contains no Trial Balance account rows"),
            Self::EmptyAccountName => f.write_str("Trial Balance contains an empty account name"),
            Self::DuplicateAccount(account) => {
                write!(f, "Trial Balance contains duplicate account {account:?}")
            }
            Self::InvalidAmount(value) => write!(f, "invalid currency amount {value:?}"),
            Self::InvalidNormalizedCents { column, value } => {
                write!(f, "invalid integer-cent value {value:?} in {column}")
            }
            Self::MissingNormalizedCents { account, column } => {
                write!(
                    f,
                    "normalized Trial Balance account {account:?} is missing {column}"
                )
            }
            Self::InconsistentNormalizedRow {
                account,
                debit_cents,
                credit_cents,
                net_cents,
            } => write!(
                f,
                "normalized Trial Balance account {account:?} has debit_cents={debit_cents}, credit_cents={credit_cents}, but net_cents={net_cents}"
            ),
            Self::AmountOverflow => f.write_str("currency amount exceeds i64 cents"),
            Self::UnclosedQuote => f.write_str("CSV ends inside a quoted field"),
        }
    }
}

impl Error for TrialBalanceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoted_cp1252_crlf_export_and_money_without_floats() {
        let fixture = b"\"Trial Balance\"\r\n\"As of demo date\"\r\n\"Account\",\"Debit\",\"Credit\"\r\n\"Cash, operating\",\"1,234.56\",\"\"\r\n\"Owner\x92s equity\",\"\",\"1,234.56\"\r\n\"TOTAL\",\"1,234.56\",\"1,234.56\"\r\n";
        let parsed = parse_quickbooks_trial_balance_csv(fixture).unwrap();
        assert_eq!(parsed.balances_cents.get("Cash, operating"), Some(&123_456));
        assert_eq!(parsed.balances_cents.get("Owner’s equity"), Some(&-123_456));
        assert!(parsed.is_balanced());
    }

    #[test]
    fn parses_native_desktop_blank_account_header_shape() {
        let fixture = b"\"Aug 26, 26\"\r\n,\"Debit\",\"Credit\"\r\n\"Cash\",\"1.00\",\"\"\r\n\"Equity\",\"\",\"1.00\"\r\n\"TOTAL\",\"1.00\",\"1.00\"\r\n";
        let parsed = parse_quickbooks_trial_balance_csv(fixture).unwrap();
        assert_eq!(parsed.balances_cents.get("Cash"), Some(&100));
        assert_eq!(parsed.balances_cents.get("Equity"), Some(&-100));
        assert!(parsed.is_balanced());
    }

    #[test]
    fn native_explicit_zero_accounts_are_omitted_for_default_presentation() {
        let fixture = b"Account,Debit,Credit\nSAMPLE Zero,0.00,\nSAMPLE Cash,1.00,\nSAMPLE Equity,,1.00\nTOTAL,1.00,1.00\n";
        let parsed = parse_quickbooks_trial_balance_csv(fixture).unwrap();
        assert!(!parsed.balances_cents.contains_key("SAMPLE Zero"));
        assert!(parsed.is_balanced());
    }

    #[test]
    fn native_account_number_presentation_is_removed_for_full_name_join() {
        let fixture = b"Account,Debit,Credit\n1000 \xB7 SAMPLE Parent:SAMPLE Child,1.00,\n2000 \xB7 SAMPLE Equity,,1.00\nTOTAL,1.00,1.00\n";
        let parsed = parse_quickbooks_trial_balance_csv(fixture).unwrap();
        assert_eq!(
            parsed.balances_cents.get("SAMPLE Parent:SAMPLE Child"),
            Some(&100)
        );
        assert_eq!(parsed.balances_cents.get("SAMPLE Equity"), Some(&-100));
    }

    #[test]
    fn normalized_extractor_csv_reconciles_with_native_csv_exactly() {
        let native = b"\"Trial Balance\"\r\n\"Account\",\"Debit\",\"Credit\"\r\n\"Sample cash\",\"12.34\",\"\"\r\n\"Sample equity\",\"\",\"12.34\"\r\n\"TOTAL\",\"12.34\",\"12.34\"\r\n";
        let generated = b"entity_id,as_of_day,account_id,account_number,account_name,parent_account_id,account_type,active,activity,debit_cents,debit,credit_cents,credit,net_cents,net,source_file,parser_version,generated_at,tb_policy_source,tb_policy_as_of,tb_policy_fiscal_year_start,tb_policy_retained_earnings_account_id\nexample,1,stable-cash,,Sample cash,,asset,true,active,1234,12.34,,,1234,12.34,local,test,2026-01-01T00:00:00Z,explicit,2026-01-01,2026-01-01,stable-equity\nexample,1,stable-equity,,Sample equity,,equity,true,active,,,1234,12.34,-1234,-12.34,local,test,2026-01-01T00:00:00Z,explicit,2026-01-01,2026-01-01,stable-equity\n";

        let reference = parse_trial_balance_csv(native).unwrap();
        let actual = parse_trial_balance_csv(generated).unwrap();
        let reconciliation = reconcile_trial_balances(&reference, &actual);
        assert!(reconciliation.passes());
    }

    #[test]
    fn normalized_csv_uses_hierarchy_qualified_name_when_leaf_names_repeat() {
        let native = "Account,Debit,Credit\n1000 · SAMPLE Parent:Retained Earnings,1.25,\n2000 · Retained Earnings,,1.25\nTOTAL,1.25,1.25\n";
        let generated = "account_name,account_full_name,account_display_name,debit_cents,credit_cents,net_cents\nRetained Earnings,SAMPLE Parent:Retained Earnings,1000 · SAMPLE Parent:Retained Earnings,125,,125\nRetained Earnings,Retained Earnings,2000 · Retained Earnings,,125,-125\n";
        let result = reconcile_trial_balances(
            &parse_trial_balance_csv(native.as_bytes()).unwrap(),
            &parse_trial_balance_csv(generated.as_bytes()).unwrap(),
        );
        assert!(result.passes());
    }

    #[test]
    fn report_encoder_output_is_accepted_by_reconciliation_parser() {
        use crate::report_output::{ReportMetadata, trial_balance_csv};
        use openqbw::{
            Account, AccountId, AccountType, TrialBalance as ExtractedTrialBalance, TrialBalanceRow,
        };

        let cash = Account::new(
            AccountId::new("sample-cash-id").unwrap(),
            "Sample cash",
            AccountType::Asset,
            true,
        )
        .unwrap();
        let equity = Account::new(
            AccountId::new("sample-equity-id").unwrap(),
            "Sample equity",
            AccountType::Equity,
            true,
        )
        .unwrap();
        let report = ExtractedTrialBalance {
            as_of: 1,
            rows: vec![
                TrialBalanceRow {
                    account: cash,
                    signed_minor_units: 1234,
                    debit_minor_units: Some(1234),
                    credit_minor_units: None,
                },
                TrialBalanceRow {
                    account: equity,
                    signed_minor_units: -1234,
                    debit_minor_units: None,
                    credit_minor_units: Some(1234),
                },
            ],
        };
        let metadata = ReportMetadata {
            entity_id: "sample-entity".to_owned(),
            source_file: "sample-local-qbw".to_owned(),
            parser_version: "sample-test".to_owned(),
            generated_at: "2026-01-01T00:00:00Z".to_owned(),
            trial_balance_policy: None,
        };
        let generated = trial_balance_csv(&report, &metadata).unwrap();
        let native =
            b"Account,Debit,Credit\nSample cash,12.34,\nSample equity,,12.34\nTOTAL,12.34,12.34\n";
        let result = reconcile_trial_balances(
            &parse_quickbooks_trial_balance_csv(native).unwrap(),
            &parse_trial_balance_csv(generated.as_bytes()).unwrap(),
        );
        assert!(result.passes());
    }

    #[test]
    fn normalized_csv_rejects_inconsistent_display_components() {
        let generated = b"account_name,debit_cents,credit_cents,net_cents\nSample cash,100,,99\n";
        assert_eq!(
            parse_trial_balance_csv(generated),
            Err(TrialBalanceError::InconsistentNormalizedRow {
                account: "Sample cash".to_owned(),
                debit_cents: 100,
                credit_cents: 0,
                net_cents: 99,
            })
        );
    }

    #[test]
    fn reconciliation_identifies_all_difference_classes_and_exact_variance() {
        let reference = TrialBalance::from_balances([
            ("A".to_owned(), 1_000),
            ("B".to_owned(), -1_000),
            ("C".to_owned(), 250),
        ])
        .unwrap();
        let actual = TrialBalance::from_balances([
            ("A".to_owned(), 1_001),
            ("B".to_owned(), -1_000),
            ("D".to_owned(), -250),
        ])
        .unwrap();
        let result = reconcile_trial_balances(&reference, &actual);
        assert!(!result.passes());
        assert_eq!(
            result.missing_accounts,
            vec![AccountVariance {
                account: "C".to_owned(),
                variance_cents: -250
            }]
        );
        assert_eq!(
            result.extra_accounts,
            vec![AccountVariance {
                account: "D".to_owned(),
                variance_cents: -250
            }]
        );
        assert_eq!(
            result.mismatched_accounts,
            vec![AccountVariance {
                account: "A".to_owned(),
                variance_cents: 1
            }]
        );
        assert_eq!(result.max_account_variance_cents, 250);
        assert_eq!(result.debit_total_variance_cents, -249);
        assert_eq!(result.credit_total_variance_cents, 250);
        assert_eq!(
            reconciliation_diagnostic_lines(&reference, &actual, &result),
            vec![
                "missing account=\"C\" reference_cents=250 actual_cents=<absent> variance_cents=-250",
                "extra account=\"D\" reference_cents=<absent> actual_cents=-250 variance_cents=-250",
                "mismatch account=\"A\" reference_cents=1000 actual_cents=1001 variance_cents=1",
            ]
        );
    }

    #[test]
    fn pass_requires_every_account_and_every_total_to_match() {
        let reference = TrialBalance::from_balances([
            ("Demo asset".to_owned(), 999),
            ("Demo equity".to_owned(), -999),
        ])
        .unwrap();
        let actual = reference.clone();
        let result = reconcile_trial_balances(&reference, &actual);
        assert!(result.passes());
        assert_eq!(
            result.status_line(),
            "PASS: all accounts and totals reconcile exactly to $0.00"
        );
    }

    #[test]
    fn identical_but_unbalanced_reports_do_not_pass() {
        let unbalanced = TrialBalance::from_balances([("Demo asset".to_owned(), 999)]).unwrap();
        assert!(!unbalanced.is_balanced());

        let result = reconcile_trial_balances(&unbalanced, &unbalanced);
        assert!(!result.passes());
        assert!(result.status_line().starts_with("FAIL:"));
    }

    #[test]
    fn balance_totals_reject_i64_overflow() {
        assert_eq!(
            TrialBalance::from_balances([("Impossible credit".to_owned(), i64::MIN)]),
            Err(TrialBalanceError::AmountOverflow)
        );
        assert_eq!(
            TrialBalance::from_balances([
                ("First debit".to_owned(), i64::MAX),
                ("Second debit".to_owned(), 1),
            ]),
            Err(TrialBalanceError::AmountOverflow)
        );
    }

    #[test]
    fn rejects_ambiguous_duplicate_account_rows() {
        let fixture = b"Account,Debit,Credit\nDemo,1.00,\nDemo,,1.00\n";
        assert_eq!(
            parse_quickbooks_trial_balance_csv(fixture),
            Err(TrialBalanceError::DuplicateAccount("Demo".to_owned()))
        );
    }
}

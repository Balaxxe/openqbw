//! Exact, line-level reconciliation of a native QuickBooks Desktop General
//! //! Ledger CSV with the normalized direct-QBW ledger.
//!
//! QuickBooks Desktop presents a General Ledger as account sections with
//! running balances.  The balance column is presentation state, not a posting
//! amount, so comparison deliberately uses the debit/credit movement on every
//! dated row.  Account headings and subtotal rows are never counted as
//! postings.

use std::collections::BTreeMap;
use std::fmt;

use openqbw::{
    Account, AccountId, AccountingDate, GeneralLedgerEntry, MaterializedPostingDate,
    QuickBooksAccountClassification,
};

use crate::trial_balance_reconciliation::{
    canonical_native_account_full_name, decode_windows_1252, parse_csv_records, parse_money_cents,
};

/// One native or generated posting represented in the strongest identity the
/// direct reader currently proves in both sources.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GeneralLedgerPostingIdentity {
    /// Calendar day encoded as the normalized accounting-day value.
    pub date: AccountingDate,
    /// Hierarchy-qualified account identity as presented by QuickBooks.
    pub account_full_name: String,
    /// Debit-positive / credit-negative amount in cents.
    pub signed_cents: i64,
}

/// A native QuickBooks Desktop GL row.  `transaction_type` and
/// `transaction_number` are retained for future strict semantic matching, but
/// are not silently included in the identity until the direct table decoders
/// prove corresponding fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeGeneralLedgerPosting {
    pub identity: GeneralLedgerPostingIdentity,
    pub transaction_type: Option<String>,
    pub transaction_number: Option<String>,
}

/// Parsed native report rows, retaining neutral dated presentation rows as an
/// aggregate rather than treating them as accounting postings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedNativeGeneralLedger {
    pub postings: Vec<NativeGeneralLedgerPosting>,
    pub neutral_zero_rows: usize,
}

/// Parsed deterministic CSV emitted by `accounting-report --report
/// general-ledger --format csv`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedGeneralLedger {
    pub postings: Vec<GeneralLedgerPostingIdentity>,
    pub transaction_type_complete: bool,
}

/// Parses the public generated GL serialization before reconciliation.  This
/// prevents the command from comparing a second, private in-memory view of
/// the ledger instead of the rows the extractor actually emits.
pub fn parse_generated_general_ledger_csv(
    bytes: &[u8],
    from: AccountingDate,
    through: AccountingDate,
) -> Result<GeneratedGeneralLedger, GeneralLedgerError> {
    let text = decode_windows_1252(bytes);
    let rows = parse_csv_records(&text).map_err(|_| GeneralLedgerError::InvalidCsv)?;
    let header = find_generated_header(&rows)?;
    let mut postings = Vec::new();
    let mut transaction_type_complete = true;
    for row in rows.iter().skip(header.data_start) {
        let account = cell(row, header.account).trim();
        let posting_day = cell(row, header.posting_day).trim();
        let net_cents = cell(row, header.net_cents).trim();
        if account.is_empty() && posting_day.is_empty() && net_cents.is_empty() {
            continue;
        }
        if account.is_empty() || posting_day.is_empty() || net_cents.is_empty() {
            return Err(GeneralLedgerError::MalformedGeneratedRow);
        }
        // The deterministic report intentionally stores the normalized
        // accounting-day integer, rather than a locale-sensitive display
        // date.  Native Desktop dates are converted into this same domain.
        let date = posting_day
            .parse::<AccountingDate>()
            .map_err(|_| GeneralLedgerError::InvalidDate)?;
        if !(from..=through).contains(&date) {
            return Err(GeneralLedgerError::DateOutsideReportRange);
        }
        let signed_cents = net_cents
            .parse::<i64>()
            .map_err(|_| GeneralLedgerError::InvalidGeneratedCents)?;
        if signed_cents == 0 {
            return Err(GeneralLedgerError::GeneratedZeroMovement);
        }
        if cell(row, header.transaction_type).trim().is_empty() {
            transaction_type_complete = false;
        }
        postings.push(GeneralLedgerPostingIdentity {
            date,
            account_full_name: canonical_native_account_full_name(account),
            signed_cents,
        });
    }
    if postings.is_empty() {
        return Err(GeneralLedgerError::NoPostingRows);
    }
    Ok(GeneratedGeneralLedger {
        postings,
        transaction_type_complete,
    })
}

/// Aggregate-only outcome of a deterministic posting multiset comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneralLedgerReconciliation {
    pub native_postings: usize,
    pub generated_postings: usize,
    pub matching_postings: usize,
    pub missing_postings: usize,
    pub extra_postings: usize,
    /// Aggregate-only overlap after omitting account identity.  This is a
    /// diagnostic counter, never a PASS criterion.
    pub matching_date_amount_postings: usize,
    /// Number of distinct account labels shared after native presentation
    /// canonicalization. Diagnostic only; it is not a reconciliation key.
    pub shared_account_identities: usize,
    pub native_only_account_identities: usize,
    pub generated_only_account_identities: usize,
    /// Semantic columns present in native Desktop GL but not yet established
    /// by the direct QBW posting contract.  A caller can therefore distinguish
    /// a line-level amount/account/date PASS from a future TxnID-grade proof.
    pub unavailable_semantic_fields: Vec<&'static str>,
}

impl GeneralLedgerReconciliation {
    pub fn passes_posting_multiset(&self) -> bool {
        self.missing_postings == 0 && self.extra_postings == 0
    }

    pub fn status_line(&self) -> &'static str {
        if self.passes_posting_multiset() {
            "PASS: native and direct-QBW General Ledger posting multisets reconcile exactly"
        } else {
            "FAIL: native and direct-QBW General Ledger posting multisets differ"
        }
    }
}

/// Parses a native QuickBooks Desktop General Ledger CSV for an explicitly
/// bounded report period.  Two-digit calendar years are resolved only when a
/// unique 1900s/2000s candidate falls within that caller-provided period.
pub fn parse_quickbooks_general_ledger_csv(
    bytes: &[u8],
    from: AccountingDate,
    through: AccountingDate,
) -> Result<ParsedNativeGeneralLedger, GeneralLedgerError> {
    if from > through {
        return Err(GeneralLedgerError::InvalidDateRange);
    }
    let text = decode_windows_1252(bytes);
    let rows = parse_csv_records(&text).map_err(|_| GeneralLedgerError::InvalidCsv)?;
    let header = find_header(&rows)?;
    let mut account = None;
    let mut nearest_numbered_ancestor = None;
    let mut section_has_postings = false;
    let mut postings = Vec::new();
    let mut neutral_zero_rows = 0;

    for row in rows.iter().skip(header.data_start) {
        let account_cell = cell(row, header.account).trim();
        let date_cell = cell(row, header.date).trim();
        if date_cell.is_empty() {
            // An account-section heading can include a running opening or
            // closing balance.  It is intentionally not a posting.
            if is_total_label(account_cell) {
                // Desktop writes a subtotal/total line before the next
                // account heading.  A later non-dated label can therefore
                // begin the next section.
                account = None;
                section_has_postings = false;
            } else if !account_cell.is_empty() && !section_has_postings {
                // Desktop writes hierarchy levels in consecutive account
                // heading rows, for example an account-numbered parent then
                // an unnumbered leaf.  Join only these pre-posting headings;
                // an opening-balance presentation row later in a section
                // cannot replace the account identity.
                let label = canonical_native_account_full_name(account_cell);
                if has_native_account_number_prefix(account_cell) {
                    nearest_numbered_ancestor = Some(label.clone());
                    account = Some(label);
                } else if let Some(ancestor) = &nearest_numbered_ancestor {
                    account = Some(format!("{ancestor}:{label}"));
                } else {
                    account = Some(label);
                }
            }
            continue;
        }
        let account_full_name = account
            .clone()
            .ok_or(GeneralLedgerError::PostingWithoutAccount)?;
        let date = parse_desktop_date(date_cell, from, through)?;
        let debit = parse_money_cents(cell(row, header.debit).trim())
            .map_err(|_| GeneralLedgerError::InvalidMoney)?;
        let credit = parse_money_cents(cell(row, header.credit).trim())
            .map_err(|_| GeneralLedgerError::InvalidMoney)?;
        if debit != 0 && credit != 0 {
            return Err(GeneralLedgerError::BothDebitAndCredit);
        }
        if debit == 0 && credit == 0 {
            // Desktop can include a dated zero-movement presentation or void
            // row. It is neither a debit/credit posting nor evidence that a
            // direct decoder may emit a zero posting, so retain only a count.
            neutral_zero_rows += 1;
            continue;
        }
        let signed_cents = debit
            .checked_sub(credit)
            .ok_or(GeneralLedgerError::AmountOverflow)?;
        postings.push(NativeGeneralLedgerPosting {
            identity: GeneralLedgerPostingIdentity {
                date,
                account_full_name,
                signed_cents,
            },
            transaction_type: nonempty(cell(row, header.transaction_type)),
            transaction_number: nonempty(cell(row, header.transaction_number)),
        });
        section_has_postings = true;
    }
    if postings.is_empty() {
        return Err(GeneralLedgerError::NoPostingRows);
    }
    Ok(ParsedNativeGeneralLedger {
        postings,
        neutral_zero_rows,
    })
}

/// Compares every line movement, retaining multiplicity for duplicate same-day
/// same-account amounts.  This is deliberately not a totals comparison.
pub fn reconcile_general_ledger_postings(
    native: &[NativeGeneralLedgerPosting],
    generated: impl IntoIterator<Item = GeneralLedgerPostingIdentity>,
    direct_has_transaction_type: bool,
    direct_has_transaction_number: bool,
) -> GeneralLedgerReconciliation {
    let generated = generated.into_iter().collect::<Vec<_>>();
    let mut native_counts = multiset(native.iter().map(|row| row.identity.clone()));
    let mut generated_counts = multiset(generated.iter().cloned());
    let native_postings = native.len();
    let generated_postings: usize = generated_counts.values().sum();
    let mut matching_postings = 0;
    for identity in native_counts.keys().cloned().collect::<Vec<_>>() {
        let native_count = native_counts[&identity];
        if let Some(generated_count) = generated_counts.get_mut(&identity) {
            let matched = native_count.min(*generated_count);
            *native_counts.get_mut(&identity).expect("key came from map") -= matched;
            *generated_count -= matched;
            matching_postings += matched;
        }
    }
    let missing_postings = native_counts.values().sum();
    let extra_postings = generated_counts.values().sum();
    let matching_date_amount_postings = projection_overlap(
        native
            .iter()
            .map(|row| (row.identity.date, row.identity.signed_cents)),
        generated.iter().map(|row| (row.date, row.signed_cents)),
    );
    let native_accounts = native
        .iter()
        .map(|row| row.identity.account_full_name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let generated_accounts = generated
        .iter()
        .map(|row| row.account_full_name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let shared_account_identities = native_accounts.intersection(&generated_accounts).count();
    let native_only_account_identities = native_accounts.difference(&generated_accounts).count();
    let generated_only_account_identities = generated_accounts.difference(&native_accounts).count();
    let mut unavailable_semantic_fields = Vec::new();
    if !direct_has_transaction_type && native.iter().any(|row| row.transaction_type.is_some()) {
        unavailable_semantic_fields.push("transaction_type");
    }
    if !direct_has_transaction_number && native.iter().any(|row| row.transaction_number.is_some()) {
        unavailable_semantic_fields.push("transaction_number");
    }
    GeneralLedgerReconciliation {
        native_postings,
        generated_postings,
        matching_postings,
        missing_postings,
        extra_postings,
        matching_date_amount_postings,
        shared_account_identities,
        native_only_account_identities,
        generated_only_account_identities,
        unavailable_semantic_fields,
    }
}

/// Resolves a Desktop account-section presentation against the direct reader's
/// decoded chart identities.  This handles the one report form where an
/// unnumbered root heading follows a numbered hierarchy section: the native
/// presentation alone cannot say whether it inherits that prior ancestor.
///
/// Resolution never uses date, amount, transaction text, or fuzzy matching.
/// A constructed full path wins when it is an exact chart name.  Otherwise its
/// leaf is accepted only when that exact leaf is a unique decoded full name;
/// every other case fails closed.
#[allow(dead_code)] // Kept as the chart-agnostic public resolver for callers.
pub fn resolve_native_account_sections(
    native: &mut [NativeGeneralLedgerPosting],
    decoded_full_names: &std::collections::BTreeSet<String>,
) -> Result<(), GeneralLedgerError> {
    resolve_native_account_sections_with_chart(
        native,
        decoded_full_names,
        &[],
        &BTreeMap::new(),
        &BTreeMap::new(),
        &[],
    )
}

/// Chart-aware variant of [`resolve_native_account_sections`].
///
/// Desktop can emit a bare `Accounts Payable` system grouping even when the
/// decoded chart's current AP account has another user-facing name. That
/// presentation is resolved only from the source-attested QuickBooks
/// classification and only when the *complete* decoded chart contains exactly
/// one current Accounts Payable account. Missing or multiple candidates fail
/// closed; no account-name, amount, or date heuristic is involved.
pub fn resolve_native_account_sections_with_chart(
    native: &mut [NativeGeneralLedgerPosting],
    decoded_full_names: &std::collections::BTreeSet<String>,
    decoded_chart: &[Account],
    full_names_by_account_id: &BTreeMap<String, String>,
    display_names_by_account_id: &BTreeMap<String, String>,
    generated_entries: &[GeneralLedgerEntry],
) -> Result<(), GeneralLedgerError> {
    let mut unresolved_sections = BTreeMap::<String, Vec<usize>>::new();
    for row in native.iter_mut() {
        if decoded_full_names.contains(&row.identity.account_full_name) {
            continue;
        }
        if let Some(account_id) = resolve_native_display_name(
            &row.identity.account_full_name,
            display_names_by_account_id,
        )? {
            let full_name = full_names_by_account_id
                .get(account_id.as_str())
                .ok_or(GeneralLedgerError::UnresolvedNativeAccountSection)?;
            row.identity.account_full_name = full_name.clone();
            continue;
        }
        if let Some(account_id) =
            resolve_native_account_name(&row.identity.account_full_name, decoded_chart)?
        {
            let full_name = full_names_by_account_id
                .get(account_id.as_str())
                .ok_or(GeneralLedgerError::UnresolvedNativeAccountSection)?;
            row.identity.account_full_name = full_name.clone();
            continue;
        }
        let leaf = row
            .identity
            .account_full_name
            .rsplit(':')
            .next()
            .expect("a String always has one split component");
        let mut exact_leaf = decoded_full_names
            .iter()
            .filter(|name| name.as_str() == leaf);
        let Some(resolved) = exact_leaf.next() else {
            // This may be an application-owned AP control section. Its
            // semantic proof is evaluated after all ordinary chart names.
            continue;
        };
        if exact_leaf.next().is_some() {
            // A system control role can share a leaf with user hierarchy
            // labels. Defer to the stricter AP proof below rather than
            // selecting a display-name candidate.
            continue;
        }
        row.identity.account_full_name = resolved.clone();
    }
    // The pass above resolves every normal hierarchy presentation. Build
    // unresolved groups from the original parse state only in a second pass:
    // a group may be an application-owned AP control section rather than a
    // chart display label.
    for (index, row) in native.iter().enumerate() {
        if !decoded_full_names.contains(&row.identity.account_full_name) {
            unresolved_sections
                .entry(row.identity.account_full_name.clone())
                .or_default()
                .push(index);
        }
    }
    for indices in unresolved_sections.into_values() {
        let account_id = resolve_accounts_payable_control_section(
            native,
            &indices,
            decoded_chart,
            generated_entries,
        )?;
        let full_name = full_names_by_account_id
            .get(account_id.as_str())
            .ok_or(GeneralLedgerError::UnresolvedNativeAccountSection)?
            .clone();
        for index in indices {
            native[index].identity.account_full_name = full_name.clone();
        }
    }
    Ok(())
}

/// Resolves an ordinary native presentation against the complete decoded
/// display-name map. This preserves account-number formatting rules without
/// treating a leaf name or arbitrary label as an identity.
fn resolve_native_display_name(
    native_name: &str,
    display_names_by_account_id: &BTreeMap<String, String>,
) -> Result<Option<openqbw::AccountId>, GeneralLedgerError> {
    let native_name = canonical_native_account_full_name(native_name);
    let mut matches = display_names_by_account_id
        .iter()
        .filter(|(_, display_name)| canonical_native_account_full_name(display_name) == native_name)
        .map(|(account_id, _)| AccountId::new(account_id.clone()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GeneralLedgerError::UnresolvedNativeAccountSection)?;
    let Some(account_id) = matches.pop() else {
        return Ok(None);
    };
    if !matches.is_empty() {
        return Err(GeneralLedgerError::AmbiguousNativeAccountSection);
    }
    Ok(Some(account_id))
}

/// Resolves an exact account-name presentation only when the complete decoded
/// chart proves it belongs to one account. This is a normal chart identity
/// join, distinct from the AP control-role resolver below.
fn resolve_native_account_name(
    native_name: &str,
    decoded_chart: &[Account],
) -> Result<Option<AccountId>, GeneralLedgerError> {
    let native_name = canonical_native_account_full_name(native_name);
    let mut matches = exact_account_name_matches(&native_name, decoded_chart);
    if matches.is_empty() {
        // Native Desktop may retain a numbered ancestor heading while showing
        // an unnumbered ordinary account name. The leaf is acceptable only
        // when the complete decoded chart has exactly one identical name.
        let leaf = native_name.rsplit(':').next().unwrap_or(&native_name);
        matches = exact_account_name_matches(leaf, decoded_chart);
    }
    let Some(account_id) = matches.pop() else {
        return Ok(None);
    };
    if !matches.is_empty() {
        return Err(GeneralLedgerError::AmbiguousNativeAccountSection);
    }
    Ok(Some(account_id))
}

fn exact_account_name_matches(native_name: &str, decoded_chart: &[Account]) -> Vec<AccountId> {
    decoded_chart
        .iter()
        .filter(|account| account.name == native_name)
        .map(|account| account.id.clone())
        .collect()
}

/// Proves that one unresolved native account section is QuickBooks' AP
/// control-role presentation without reading its label. The section must be a
/// complete recognized movement multiset containing both Bill and
/// Bill-Pmt-Check and must identify one
/// source-attested AP account among the complete decoded chart. Historical
/// reports intentionally retain inactive Accounts, so activity is never used
/// to discard a candidate here.
fn resolve_accounts_payable_control_section(
    native: &[NativeGeneralLedgerPosting],
    indices: &[usize],
    decoded_chart: &[Account],
    generated_entries: &[GeneralLedgerEntry],
) -> Result<openqbw::AccountId, GeneralLedgerError> {
    let mut native_types = BTreeMap::<String, usize>::new();
    let mut native_movements = BTreeMap::<(AccountingDate, String, i64), usize>::new();
    for &index in indices {
        let row = &native[index];
        let Some(transaction_type) =
            normalize_ap_control_transaction_type(row.transaction_type.as_deref())
        else {
            emit_private_control_role_diagnostic(native, indices, decoded_chart, generated_entries);
            return Err(GeneralLedgerError::UnresolvedNativeAccountSection);
        };
        *native_types.entry(transaction_type.clone()).or_default() += 1;
        *native_movements
            .entry((
                row.identity.date,
                transaction_type,
                row.identity.signed_cents,
            ))
            .or_default() += 1;
    }
    if !native_types.contains_key("bill") || !native_types.contains_key("bill-pmt-check") {
        emit_private_control_role_diagnostic(native, indices, decoded_chart, generated_entries);
        return Err(GeneralLedgerError::UnresolvedNativeAccountSection);
    }

    let matching_account_ids = decoded_chart
        .iter()
        .filter(|account| {
            account.quickbooks_classification
                == Some(QuickBooksAccountClassification::AccountsPayable)
        })
        .filter(|account| {
            generated_ap_control_multiset(generated_entries, account.id.as_str())
                .is_some_and(|movements| movements == native_movements)
        })
        .map(|account| account.id.clone())
        .collect::<Vec<_>>();
    let [candidate] = matching_account_ids.as_slice() else {
        if matching_account_ids.is_empty() {
            emit_private_control_role_diagnostic(native, indices, decoded_chart, generated_entries);
            return Err(GeneralLedgerError::NoAccountsPayableControlMatch);
        }
        return Err(GeneralLedgerError::AmbiguousNativeAccountSection);
    };
    Ok(candidate.clone())
}

/// Emits only aggregate decoder facts for local diagnosis when explicitly
/// requested. It never includes an account name, identifier, memo, source
/// path, or amount. This is intentionally opt-in so ordinary CLI failures
/// remain concise.
fn emit_private_control_role_diagnostic(
    native: &[NativeGeneralLedgerPosting],
    indices: &[usize],
    decoded_chart: &[Account],
    generated_entries: &[GeneralLedgerEntry],
) {
    if std::env::var_os("OPENQBW_PRIVATE_CONTROL_ROLE_DIAGNOSTICS").is_none() {
        return;
    }
    let native_movements = generic_native_control_multiset(native, indices);
    let type_buckets = native_movements.iter().fold(
        BTreeMap::<String, usize>::new(),
        |mut buckets, ((_, kind, _), count)| {
            *buckets.entry(kind.clone()).or_default() += count;
            buckets
        },
    );
    let matching_roles = decoded_chart
        .iter()
        .filter(|account| {
            generic_generated_control_multiset(generated_entries, account.id.as_str())
                == native_movements
        })
        .map(|account| {
            format!(
                "{}:{}",
                account_type_name(&account.account_type),
                account
                    .quickbooks_classification
                    .map(QuickBooksAccountClassification::source_label)
                    .unwrap_or("none")
            )
        })
        .collect::<Vec<_>>();
    eprintln!(
        "private-control-role-diagnostic native_rows={} native_types={} exact_generated_role_matches={}",
        indices.len(),
        type_buckets
            .into_iter()
            .map(|(kind, count)| format!("{kind}:{count}"))
            .collect::<Vec<_>>()
            .join("|"),
        if matching_roles.is_empty() {
            "none".to_owned()
        } else {
            matching_roles.join("|")
        },
    );
}

fn generic_native_control_multiset(
    native: &[NativeGeneralLedgerPosting],
    indices: &[usize],
) -> BTreeMap<(AccountingDate, String, i64), usize> {
    let mut movements = BTreeMap::new();
    for &index in indices {
        let row = &native[index];
        *movements
            .entry((
                row.identity.date,
                generic_transaction_type(row.transaction_type.as_deref()),
                row.identity.signed_cents,
            ))
            .or_default() += 1;
    }
    movements
}

fn generic_generated_control_multiset(
    entries: &[GeneralLedgerEntry],
    account_id: &str,
) -> BTreeMap<(AccountingDate, String, i64), usize> {
    let mut movements = BTreeMap::new();
    for entry in entries
        .iter()
        .filter(|entry| entry.account.id.as_str() == account_id)
    {
        *movements
            .entry((
                entry.posting.date,
                generic_transaction_type(entry.posting.transaction_type.as_deref()),
                entry.posting.signed_minor_units,
            ))
            .or_default() += 1;
    }
    movements
}

fn generic_transaction_type(value: Option<&str>) -> String {
    value
        .unwrap_or("<missing>")
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn account_type_name(account_type: &openqbw::AccountType) -> &'static str {
    match account_type {
        openqbw::AccountType::Asset => "asset",
        openqbw::AccountType::Liability => "liability",
        openqbw::AccountType::Equity => "equity",
        openqbw::AccountType::Income => "income",
        openqbw::AccountType::Expense => "expense",
        openqbw::AccountType::CostOfGoodsSold => "cogs",
        openqbw::AccountType::Other(_) => "other",
    }
}

fn generated_ap_control_multiset(
    entries: &[GeneralLedgerEntry],
    account_id: &str,
) -> Option<BTreeMap<(AccountingDate, String, i64), usize>> {
    let mut movements = BTreeMap::new();
    for entry in entries
        .iter()
        .filter(|entry| entry.account.id.as_str() == account_id)
    {
        let transaction_type =
            normalize_ap_control_transaction_type(entry.posting.transaction_type.as_deref())?;
        *movements
            .entry((
                entry.posting.date,
                transaction_type,
                entry.posting.signed_minor_units,
            ))
            .or_default() += 1;
    }
    Some(movements)
}

fn normalize_ap_control_transaction_type(value: Option<&str>) -> Option<String> {
    // Production rows use the stable native-style labels emitted by the
    // Enterprise posting adapters (`Bill` and `Bill Pmt-Check`).  The two
    // table-ID forms are accepted solely to reconcile CSVs made by older
    // extractor builds during migration; new output must never emit them.
    let compact = value?
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    match compact.as_str() {
        "bill" | "enterprise24table3042" => Some("bill".to_owned()),
        "billpmtcheck" | "billpaymentcheck" | "enterprise24table3039" => {
            Some("bill-pmt-check".to_owned())
        }
        "credit" | "vendorcredit" | "enterprise24table3042vendorcredit" => {
            Some("credit".to_owned())
        }
        "generaljournal" | "enterprise24table3078" => Some("general-journal".to_owned()),
        "check" | "enterprise24table3047" => Some("check".to_owned()),
        "deposit" | "enterprise24table3069" => Some("deposit".to_owned()),
        _ => None,
    }
}

fn projection_overlap<K: Ord>(
    left: impl IntoIterator<Item = K>,
    right: impl IntoIterator<Item = K>,
) -> usize {
    let mut left_counts = BTreeMap::<K, usize>::new();
    let mut right_counts = BTreeMap::<K, usize>::new();
    for value in left {
        *left_counts.entry(value).or_default() += 1;
    }
    for value in right {
        *right_counts.entry(value).or_default() += 1;
    }
    left_counts
        .into_iter()
        .map(|(key, left)| left.min(right_counts.get(&key).copied().unwrap_or(0)))
        .sum()
}

fn multiset(
    values: impl IntoIterator<Item = GeneralLedgerPostingIdentity>,
) -> BTreeMap<GeneralLedgerPostingIdentity, usize> {
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(value).or_default() += 1;
    }
    counts
}

#[derive(Clone, Copy)]
struct Header {
    account: usize,
    transaction_type: usize,
    date: usize,
    transaction_number: usize,
    debit: usize,
    credit: usize,
    data_start: usize,
}

#[derive(Clone, Copy)]
struct GeneratedHeader {
    posting_day: usize,
    account: usize,
    net_cents: usize,
    transaction_type: usize,
    data_start: usize,
}

fn find_generated_header(rows: &[Vec<String>]) -> Result<GeneratedHeader, GeneralLedgerError> {
    for (index, row) in rows.iter().enumerate() {
        let mut posting_day = None;
        let mut account_full_name = None;
        let mut account_display_name = None;
        let mut account_name = None;
        let mut net_cents = None;
        let mut transaction_type = None;
        for (column, value) in row.iter().enumerate() {
            match value.trim().to_ascii_lowercase().as_str() {
                "posting_day" => posting_day = Some(column),
                "account_full_name" => account_full_name = Some(column),
                "account_display_name" => account_display_name = Some(column),
                "account_name" => account_name = Some(column),
                "net_cents" => net_cents = Some(column),
                "transaction_type" => transaction_type = Some(column),
                _ => {}
            }
        }
        if let (Some(posting_day), Some(account), Some(net_cents), Some(transaction_type)) = (
            posting_day,
            account_display_name.or(account_full_name).or(account_name),
            net_cents,
            transaction_type,
        ) {
            return Ok(GeneratedHeader {
                posting_day,
                account,
                net_cents,
                transaction_type,
                data_start: index + 1,
            });
        }
    }
    Err(GeneralLedgerError::MissingGeneratedHeader)
}

fn find_header(rows: &[Vec<String>]) -> Result<Header, GeneralLedgerError> {
    for (index, row) in rows.iter().enumerate() {
        let mut account = None;
        let mut transaction_type = None;
        let mut date = None;
        let mut transaction_number = None;
        let mut debit = None;
        let mut credit = None;
        for (column, value) in row.iter().enumerate() {
            match value.trim().to_ascii_lowercase().as_str() {
                "account" | "account name" => account = Some(column),
                "type" | "transaction type" => transaction_type = Some(column),
                "date" => date = Some(column),
                "num" | "number" | "transaction number" => transaction_number = Some(column),
                "debit" | "debits" => debit = Some(column),
                "credit" | "credits" => credit = Some(column),
                _ => {}
            }
        }
        // Desktop's GL report deliberately has a blank first heading over its
        // account-section column.  The fixed physical first column is enough;
        // do not accept arbitrary header gaps.
        if account.is_none()
            && transaction_type.is_some()
            && date.is_some()
            && debit.is_some()
            && credit.is_some()
        {
            account = Some(0);
        }
        if let (
            Some(account),
            Some(transaction_type),
            Some(date),
            Some(transaction_number),
            Some(debit),
            Some(credit),
        ) = (
            account,
            transaction_type,
            date,
            transaction_number,
            debit,
            credit,
        ) {
            return Ok(Header {
                account,
                transaction_type,
                date,
                transaction_number,
                debit,
                credit,
                data_start: index + 1,
            });
        }
    }
    Err(GeneralLedgerError::MissingRequiredHeader)
}

fn parse_desktop_date(
    value: &str,
    from: AccountingDate,
    through: AccountingDate,
) -> Result<AccountingDate, GeneralLedgerError> {
    let components: Vec<_> = value.trim().split('/').collect();
    if components.len() != 3 {
        return Err(GeneralLedgerError::InvalidDate);
    }
    let month = components[0]
        .parse::<u8>()
        .map_err(|_| GeneralLedgerError::InvalidDate)?;
    let day = components[1]
        .parse::<u8>()
        .map_err(|_| GeneralLedgerError::InvalidDate)?;
    let supplied_year = components[2]
        .parse::<i32>()
        .map_err(|_| GeneralLedgerError::InvalidDate)?;
    let years: Vec<i32> = if components[2].len() == 2 {
        [1900 + supplied_year, 2000 + supplied_year]
            .into_iter()
            .collect()
    } else if components[2].len() == 4 {
        vec![supplied_year]
    } else {
        return Err(GeneralLedgerError::InvalidDate);
    };
    let mut candidates = Vec::new();
    for year in years {
        let candidate = MaterializedPostingDate::from_ymd(year, month, day)
            .map_err(|_| GeneralLedgerError::InvalidDate)?
            .accounting_date();
        if (from..=through).contains(&candidate) {
            candidates.push(candidate);
        }
    }
    match candidates.as_slice() {
        [date] => Ok(*date),
        [] => Err(GeneralLedgerError::DateOutsideReportRange),
        _ => Err(GeneralLedgerError::AmbiguousTwoDigitYear),
    }
}

fn cell(row: &[String], index: usize) -> &str {
    row.get(index).map(String::as_str).unwrap_or("")
}
fn nonempty(value: &str) -> Option<String> {
    (!value.trim().is_empty()).then(|| value.trim().to_owned())
}
fn is_total_label(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("total")
        || value.trim().to_ascii_lowercase().starts_with("total ")
}

fn has_native_account_number_prefix(value: &str) -> bool {
    let Some((number, name)) = value.trim().split_once('·') else {
        return false;
    };
    !number.trim().is_empty()
        && number.trim().bytes().all(|byte| byte.is_ascii_digit())
        && number.chars().last().is_some_and(char::is_whitespace)
        && name.chars().next().is_some_and(char::is_whitespace)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeneralLedgerError {
    InvalidCsv,
    MissingRequiredHeader,
    InvalidDateRange,
    InvalidDate,
    AmbiguousTwoDigitYear,
    DateOutsideReportRange,
    PostingWithoutAccount,
    BothDebitAndCredit,
    InvalidMoney,
    AmountOverflow,
    NoPostingRows,
    MissingGeneratedHeader,
    MalformedGeneratedRow,
    InvalidGeneratedCents,
    GeneratedZeroMovement,
    UnresolvedNativeAccountSection,
    AmbiguousNativeAccountSection,
    NoAccountsPayableControlMatch,
}

impl fmt::Display for GeneralLedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidCsv => "native General Ledger CSV is malformed",
            Self::MissingRequiredHeader => "native General Ledger CSV has no required account/type/date/num/debit/credit header",
            Self::InvalidDateRange => "General Ledger report start must not be after its end",
            Self::InvalidDate => "native General Ledger contains an invalid calendar date",
            Self::AmbiguousTwoDigitYear => "native General Ledger two-digit year is ambiguous for the requested report range",
            Self::DateOutsideReportRange => "native General Ledger contains a date outside the requested report range",
            Self::PostingWithoutAccount => "native General Ledger posting has no preceding account section",
            Self::BothDebitAndCredit => "native General Ledger row has both debit and credit amounts",
            Self::InvalidMoney => "native General Ledger contains an invalid monetary value",
            Self::AmountOverflow => "native General Ledger amount exceeds supported cents range",
            Self::NoPostingRows => "native General Ledger contains no posting rows",
            Self::MissingGeneratedHeader => "generated General Ledger CSV has no required normalized header",
            Self::MalformedGeneratedRow => "generated General Ledger has a partial posting row",
            Self::InvalidGeneratedCents => "generated General Ledger has an invalid net_cents value",
            Self::GeneratedZeroMovement => "generated General Ledger contains a zero-value posting",
            Self::UnresolvedNativeAccountSection => "native General Ledger account section has no exact decoded chart identity",
            Self::AmbiguousNativeAccountSection => "native General Ledger account section maps to more than one decoded chart identity",
            Self::NoAccountsPayableControlMatch => "native Bill/Bill-Pmt-Check control section does not map to exactly one source-classified Accounts Payable account",
        })
    }
}
impl std::error::Error for GeneralLedgerError {}

#[cfg(test)]
mod tests {
    use super::*;
    use openqbw::{
        AccountActivity, AccountId, AccountType, CurrentState, DebitCredit, DebitCreditAmount,
        Posting, PostingId, PostingProvenance, TransactionId,
    };
    use std::collections::BTreeSet;

    fn date(value: &str) -> AccountingDate {
        MaterializedPostingDate::parse_iso_date(value)
            .unwrap()
            .accounting_date()
    }

    #[test]
    fn parses_cp1252_quoted_account_sections_and_ignores_running_balances() {
        let csv = b",Type,Date,Num,Name,Memo,Split,Debit,Credit,Balance\r\nSAMPLE Cash,,,,,,,,100.00\r\n,,8/1/26,100,SAMPLE,V\x92s,SAMPLE Split,25.00,,125.00\r\nSAMPLE Equity,,,,,,,,(100.00)\r\n,Journal,8/1/26,,SAMPLE,,, ,25.00,(125.00)\r\n";
        let rows = parse_quickbooks_general_ledger_csv(csv, date("2026-08-01"), date("2026-08-31"))
            .unwrap();
        assert_eq!(rows.postings.len(), 2);
        assert_eq!(rows.neutral_zero_rows, 0);
        assert_eq!(rows.postings[0].identity.account_full_name, "SAMPLE Cash");
        assert_eq!(rows.postings[0].identity.signed_cents, 2500);
        assert_eq!(rows.postings[1].identity.signed_cents, -2500);
    }

    #[test]
    fn reconciliation_is_a_multiplicity_preserving_posting_comparison() {
        let identity = GeneralLedgerPostingIdentity {
            date: date("2026-08-01"),
            account_full_name: "SAMPLE Cash".into(),
            signed_cents: 100,
        };
        let native = vec![
            NativeGeneralLedgerPosting {
                identity: identity.clone(),
                transaction_type: Some("Check".into()),
                transaction_number: Some("SAMPLE-1".into()),
            },
            NativeGeneralLedgerPosting {
                identity: identity.clone(),
                transaction_type: Some("Check".into()),
                transaction_number: Some("SAMPLE-2".into()),
            },
        ];
        let result = reconcile_general_ledger_postings(&native, [identity], false, false);
        assert!(!result.passes_posting_multiset());
        assert_eq!(result.matching_postings, 1);
        assert_eq!(result.missing_postings, 1);
        assert_eq!(
            result.unavailable_semantic_fields,
            ["transaction_type", "transaction_number"]
        );
    }

    #[test]
    fn refuses_a_dated_row_before_an_account_heading() {
        let csv = b",Type,Date,Num,Name,Memo,Split,Debit,Credit,Balance\n,Check,8/1/26,SAMPLE,,,,1.00,,1.00\n";
        assert_eq!(
            parse_quickbooks_general_ledger_csv(csv, date("2026-08-01"), date("2026-08-31")),
            Err(GeneralLedgerError::PostingWithoutAccount)
        );
    }

    #[test]
    fn dated_zero_movement_is_counted_as_neutral_not_a_posting() {
        let csv = b",Type,Date,Num,Name,Memo,Split,Debit,Credit,Balance\nSAMPLE Cash,,,,,,,,\n,Check,8/1/26,SAMPLE,,,,0.00,0.00,0.00\n,Check,8/2/26,SAMPLE,,,,1.00,,1.00\n";
        let parsed =
            parse_quickbooks_general_ledger_csv(csv, date("2026-08-01"), date("2026-08-31"))
                .unwrap();
        assert_eq!(parsed.neutral_zero_rows, 1);
        assert_eq!(parsed.postings.len(), 1);
    }

    #[test]
    fn accounts_payable_control_section_requires_one_current_source_classified_account() {
        let mut native = vec![
            NativeGeneralLedgerPosting {
                identity: GeneralLedgerPostingIdentity {
                    date: date("2026-08-01"),
                    account_full_name: "SAMPLE System Control".into(),
                    signed_cents: -100,
                },
                transaction_type: Some("Bill".into()),
                transaction_number: None,
            },
            NativeGeneralLedgerPosting {
                identity: GeneralLedgerPostingIdentity {
                    date: date("2026-08-02"),
                    account_full_name: "SAMPLE System Control".into(),
                    signed_cents: 100,
                },
                transaction_type: Some("Bill Pmt-Check".into()),
                transaction_number: None,
            },
        ];
        let account = Account::new(
            AccountId::new("SAMPLE-AP").unwrap(),
            "SAMPLE Payables".to_owned(),
            AccountType::Liability,
            true,
        )
        .unwrap()
        .with_quickbooks_classification(QuickBooksAccountClassification::AccountsPayable);
        let names = BTreeMap::from([("SAMPLE-AP".to_owned(), "SAMPLE Payables".to_owned())]);
        let generated = [
            generated_entry(&account, "Bill", date("2026-08-01"), -100, "1"),
            generated_entry(&account, "Bill Pmt-Check", date("2026-08-02"), 100, "2"),
        ];
        resolve_native_account_sections_with_chart(
            &mut native,
            &BTreeSet::from(["SAMPLE Payables".to_owned()]),
            std::slice::from_ref(&account),
            &names,
            &BTreeMap::new(),
            &generated,
        )
        .unwrap();
        assert_eq!(native[0].identity.account_full_name, "SAMPLE Payables");

        let mut no_candidate = native.clone();
        for row in &mut no_candidate {
            row.identity.account_full_name = "SAMPLE System Control".into();
        }
        assert_eq!(
            resolve_native_account_sections_with_chart(
                &mut no_candidate,
                &BTreeSet::from(["SAMPLE Payables".to_owned()]),
                &[],
                &names,
                &BTreeMap::new(),
                &generated,
            ),
            Err(GeneralLedgerError::NoAccountsPayableControlMatch)
        );
        let mut unresolved = native.clone();
        for row in &mut unresolved {
            row.identity.account_full_name = "SAMPLE System Control".into();
        }
        let account_two = Account::new(
            AccountId::new("SAMPLE-AP-TWO").unwrap(),
            "SAMPLE Other Payables".to_owned(),
            AccountType::Liability,
            true,
        )
        .unwrap()
        .with_quickbooks_classification(QuickBooksAccountClassification::AccountsPayable);
        let mut ambiguous_generated = generated.to_vec();
        ambiguous_generated.extend([
            generated_entry(&account_two, "Bill", date("2026-08-01"), -100, "3"),
            generated_entry(&account_two, "Bill Pmt-Check", date("2026-08-02"), 100, "4"),
        ]);
        assert_eq!(
            resolve_native_account_sections_with_chart(
                &mut unresolved,
                &BTreeSet::from(["SAMPLE Payables".to_owned()]),
                &[account.clone(), account_two],
                &names,
                &BTreeMap::new(),
                &ambiguous_generated,
            ),
            Err(GeneralLedgerError::AmbiguousNativeAccountSection)
        );
        let mut mixed_type = native.clone();
        for row in &mut mixed_type {
            row.identity.account_full_name = "SAMPLE System Control".into();
        }
        mixed_type[1].transaction_type = Some("Check".into());
        assert_eq!(
            resolve_native_account_sections_with_chart(
                &mut mixed_type,
                &BTreeSet::from(["SAMPLE Payables".to_owned()]),
                std::slice::from_ref(&account),
                &names,
                &BTreeMap::new(),
                &generated,
            ),
            Err(GeneralLedgerError::UnresolvedNativeAccountSection)
        );

        let mut inactive = native;
        for row in &mut inactive {
            row.identity.account_full_name = "SAMPLE System Control".into();
        }
        let inactive_account = account.with_activity(AccountActivity::Inactive);
        resolve_native_account_sections_with_chart(
            &mut inactive,
            &BTreeSet::from(["SAMPLE Payables".to_owned()]),
            &[inactive_account],
            &names,
            &BTreeMap::new(),
            &generated,
        )
        .unwrap();
    }

    #[test]
    fn normalizes_native_labels_and_only_migrates_legacy_table_labels() {
        assert_eq!(
            normalize_ap_control_transaction_type(Some("Bill Pmt-Check")),
            Some("bill-pmt-check".to_owned())
        );
        assert_eq!(
            normalize_ap_control_transaction_type(Some("Bill")),
            Some("bill".to_owned())
        );
        assert_eq!(
            normalize_ap_control_transaction_type(Some("enterprise24-table-3039")),
            Some("bill-pmt-check".to_owned())
        );
        assert_eq!(
            normalize_ap_control_transaction_type(Some("Vendor Credit")),
            Some("credit".to_owned())
        );
        assert_eq!(
            normalize_ap_control_transaction_type(Some("General Journal")),
            Some("general-journal".to_owned())
        );
        assert_eq!(
            normalize_ap_control_transaction_type(Some("Check")),
            Some("check".to_owned())
        );
    }

    #[test]
    fn inherited_native_ancestor_can_use_only_a_unique_decoded_leaf_name() {
        let account = Account::new(
            AccountId::new("SAMPLE-LEAF").unwrap(),
            "SAMPLE Leaf".to_owned(),
            AccountType::Asset,
            true,
        )
        .unwrap();
        assert_eq!(
            resolve_native_account_name(
                "SAMPLE Ancestor:SAMPLE Leaf",
                std::slice::from_ref(&account),
            ),
            Ok(Some(account.id.clone()))
        );
        let duplicate = Account::new(
            AccountId::new("SAMPLE-LEAF-TWO").unwrap(),
            "SAMPLE Leaf".to_owned(),
            AccountType::Asset,
            true,
        )
        .unwrap();
        assert_eq!(
            resolve_native_account_name("SAMPLE Ancestor:SAMPLE Leaf", &[account, duplicate]),
            Err(GeneralLedgerError::AmbiguousNativeAccountSection)
        );
    }

    fn generated_entry(
        account: &Account,
        transaction_type: &str,
        date: AccountingDate,
        signed_cents: i64,
        suffix: &str,
    ) -> GeneralLedgerEntry {
        let side = if signed_cents < 0 {
            DebitCredit::Credit
        } else {
            DebitCredit::Debit
        };
        GeneralLedgerEntry {
            account: account.clone(),
            posting: Posting::new(
                TransactionId::new(format!("SAMPLE-TXN-{suffix}")).unwrap(),
                PostingId::new(format!("SAMPLE-POST-{suffix}")).unwrap(),
                account.id.clone(),
                date,
                DebitCreditAmount::new(side, signed_cents.checked_abs().unwrap()).unwrap(),
                CurrentState::Current,
                PostingProvenance::new(format!("SAMPLE-{suffix}"), None, None, "sample").unwrap(),
                Some(transaction_type.to_owned()),
                None,
            ),
        }
    }
}

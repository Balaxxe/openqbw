//! Local-only normalization of controlled SDK-oracle artifacts.
//!
//! This module is a research bridge, not a production decoder. It verifies
//! the manifest's read-only attestation, digests, response status, and record
//! counts before writing two intentionally ignored TSV fixtures. It never
//! writes or prints QBXML itself, and its public summary contains no business
//! fields or company path.

use std::error::Error;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::sdk_oracle_manifest::{OracleManifestError, parse_sdk_oracle_manifest, sha256_hex};

const ACCOUNTS_TSV: &str = "accounts.sdk-oracle.tsv";
const JOURNAL_TSV: &str = "journal.sdk-oracle.tsv";

/// Non-sensitive result of local SDK fixture normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdkOracleNormalizationSummary {
    /// Account rows written to the private local TSV.
    pub account_rows: u64,
    /// Journal-entry rows validated from the private QBXML artifact.
    pub journal_entry_rows: u64,
    /// Journal-line rows written to the private local TSV.
    pub journal_line_rows: u64,
    /// Journal lines in the source response, including non-posting lines.
    pub journal_source_line_rows: u64,
    /// Basename of the local account output; never a company path.
    pub accounts_output_name: &'static str,
    /// Basename of the local journal output; never a company path.
    pub journal_output_name: &'static str,
}

/// Validate and normalize local SDK oracle files into local-only TSV fixtures.
///
/// The output directory must be outside source control in normal use. The
/// repository ignores these exact names as a defense-in-depth safeguard. This
/// function refuses to overwrite an existing fixture.
pub fn normalize_sdk_oracle(
    manifest_bytes: &[u8],
    accounts_xml: &[u8],
    journal_xml: &[u8],
    output_dir: &Path,
) -> Result<SdkOracleNormalizationSummary, OracleNormalizationError> {
    let manifest = parse_sdk_oracle_manifest(manifest_bytes)?;
    if sha256_hex(accounts_xml) != manifest.accounts_sha256
        || sha256_hex(journal_xml) != manifest.journal_sha256
    {
        return Err(OracleNormalizationError::DigestMismatch);
    }
    if !successful_response(accounts_xml, b"AccountQueryRs")
        || !successful_response(journal_xml, b"JournalEntryQueryRs")
    {
        return Err(OracleNormalizationError::UnsuccessfulResponse);
    }

    let accounts = parse_accounts(accounts_xml)
        .map_err(|_| OracleNormalizationError::InvalidAccountsArtifact)?;
    let (journal_entries, journal_source_lines, journal_lines) =
        parse_journal(journal_xml).map_err(|_| OracleNormalizationError::InvalidJournalArtifact)?;
    if accounts.len() as u64 != manifest.account_count
        || journal_entries as u64 != manifest.journal_entry_count
        || journal_source_lines as u64 != manifest.journal_line_count
    {
        return Err(OracleNormalizationError::CountMismatch);
    }

    let account_path = output_dir.join(ACCOUNTS_TSV);
    let journal_path = output_dir.join(JOURNAL_TSV);
    if account_path.exists() || journal_path.exists() {
        return Err(OracleNormalizationError::OutputExists);
    }
    fs::create_dir_all(output_dir).map_err(|_| OracleNormalizationError::OutputIo)?;
    write_new(&account_path, &accounts_tsv(&accounts))?;
    if let Err(error) = write_new(&journal_path, &journal_tsv(&journal_lines)) {
        // The pair is one fixture snapshot.  Do not strand a valid-looking
        // account-only fixture if the second, independently required output
        // cannot be created.  `create_new` above ensures this can only remove
        // the file created during this call, never a caller's prior fixture.
        let _ = fs::remove_file(&account_path);
        let _ = fs::remove_file(&journal_path);
        return Err(error);
    }

    Ok(SdkOracleNormalizationSummary {
        account_rows: accounts.len() as u64,
        journal_entry_rows: journal_entries as u64,
        journal_line_rows: journal_lines.len() as u64,
        journal_source_line_rows: journal_source_lines as u64,
        accounts_output_name: ACCOUNTS_TSV,
        journal_output_name: JOURNAL_TSV,
    })
}

fn write_new(path: &Path, content: &str) -> Result<(), OracleNormalizationError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| OracleNormalizationError::OutputIo)?;
    file.write_all(content.as_bytes())
        .map_err(|_| OracleNormalizationError::OutputIo)
}

#[derive(Clone)]
struct AccountRow {
    list_id: String,
    name: String,
    full_name: String,
    account_type: String,
    parent_list_id: String,
    is_active: String,
}

#[derive(Clone)]
struct JournalLine {
    txn_id: String,
    line_id: String,
    txn_date: String,
    account_list_id: String,
    amount: String,
}

fn parse_accounts(xml: &[u8]) -> Result<Vec<AccountRow>, OracleNormalizationError> {
    let mut output = Vec::new();
    for scope in scopes(xml, b"AccountRet") {
        let list_id = required_id(scope, b"ListID")?;
        let name = required_scalar(scope, b"Name")?;
        let full_name = required_scalar(scope, b"FullName")?;
        let account_type = required_scalar(scope, b"AccountType")?;
        let parent_list_id = scopes(scope, b"ParentRef")
            .first()
            .map(|parent| required_id(parent, b"ListID"))
            .transpose()?
            .unwrap_or_default();
        let is_active = optional_scalar(scope, b"IsActive").unwrap_or_else(|| "true".to_owned());
        if !matches!(is_active.as_str(), "true" | "false") {
            return Err(OracleNormalizationError::InvalidArtifact);
        }
        output.push(AccountRow {
            list_id,
            name,
            full_name,
            account_type,
            parent_list_id,
            is_active,
        });
    }
    if output.is_empty() {
        return Err(OracleNormalizationError::InvalidArtifact);
    }
    Ok(output)
}

fn parse_journal(xml: &[u8]) -> Result<(usize, usize, Vec<JournalLine>), OracleNormalizationError> {
    let entries: Vec<_> = scopes(xml, b"JournalEntryRet")
        .into_iter()
        .chain(scopes(xml, b"GeneralJournalEntryRet"))
        .collect();
    if entries.is_empty() {
        return Err(OracleNormalizationError::InvalidArtifact);
    }
    let mut output = Vec::new();
    let mut source_line_count = 0usize;
    for entry in &entries {
        let txn_id = required_id(entry, b"TxnID")?;
        let txn_date = required_date(entry, b"TxnDate")?;
        for line in scopes(entry, b"JournalDebitLine")
            .into_iter()
            .chain(scopes(entry, b"JournalCreditLine"))
            .chain(scopes(entry, b"GeneralJournalLineRet"))
        {
            source_line_count += 1;
            let line_id = required_id(line, b"TxnLineID")?;
            let account_list_id = scopes(line, b"AccountRef")
                .first()
                .map(|account| required_id(account, b"ListID"))
                .transpose()?;
            let amount = optional_amount(line, b"Amount")?;
            // Keep source count separately. Lines without both an account and
            // an amount cannot be GL postings and would make the existing GJ
            // probe reject the whole fixture; they remain accounted for in
            // `journal_source_line_rows` rather than being silently lost.
            if let (Some(account_list_id), Some(amount)) = (account_list_id, amount) {
                output.push(JournalLine {
                    txn_id: txn_id.clone(),
                    line_id,
                    txn_date: txn_date.clone(),
                    account_list_id,
                    amount,
                });
            }
        }
    }
    if source_line_count == 0 || output.is_empty() {
        return Err(OracleNormalizationError::InvalidArtifact);
    }
    Ok((entries.len(), source_line_count, output))
}

fn accounts_tsv(rows: &[AccountRow]) -> String {
    let mut output =
        String::from("account_list_id\tname\tfull_name\taccount_type\tparent_list_id\tis_active\n");
    for row in rows {
        output.push_str(&row.list_id);
        output.push('\t');
        output.push_str(&row.name);
        output.push('\t');
        output.push_str(&row.full_name);
        output.push('\t');
        output.push_str(&row.account_type);
        output.push('\t');
        output.push_str(&row.parent_list_id);
        output.push('\t');
        output.push_str(&row.is_active);
        output.push('\n');
    }
    output
}

fn journal_tsv(rows: &[JournalLine]) -> String {
    let mut output = String::from("txn_id\ttxn_line_id\ttxn_date\taccount_list_id\tamount\n");
    for row in rows {
        output.push_str(&row.txn_id);
        output.push('\t');
        output.push_str(&row.line_id);
        output.push('\t');
        output.push_str(&row.txn_date);
        output.push('\t');
        output.push_str(&row.account_list_id);
        output.push('\t');
        output.push_str(&row.amount);
        output.push('\n');
    }
    output
}

fn successful_response(xml: &[u8], response: &[u8]) -> bool {
    let mut open = Vec::with_capacity(response.len() + 1);
    open.push(b'<');
    open.extend_from_slice(response);
    let Some(start) = xml.windows(open.len()).position(|window| window == open) else {
        return false;
    };
    let Some(end_offset) = xml[start..].iter().position(|byte| *byte == b'>') else {
        return false;
    };
    let tag = &xml[start..start + end_offset + 1];
    tag.windows(b"statusCode=\"0\"".len())
        .any(|window| window == b"statusCode=\"0\"")
}

fn required_id(scope: &[u8], tag: &[u8]) -> Result<String, OracleNormalizationError> {
    let value = required_scalar(scope, tag)?;
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(OracleNormalizationError::InvalidArtifact);
    }
    Ok(value)
}

fn required_date(scope: &[u8], tag: &[u8]) -> Result<String, OracleNormalizationError> {
    let value = required_scalar(scope, tag)?;
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .filter(|(index, _)| !matches!(index, 4 | 7))
            .all(|(_, byte)| byte.is_ascii_digit())
    {
        return Err(OracleNormalizationError::InvalidArtifact);
    }
    Ok(value)
}

fn optional_amount(scope: &[u8], tag: &[u8]) -> Result<Option<String>, OracleNormalizationError> {
    let Some(value) = optional_scalar(scope, tag) else {
        return Ok(None);
    };
    let digits = value.strip_prefix('-').unwrap_or(&value);
    let (whole, fractional) = digits.split_once('.').unwrap_or((digits, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
        || fractional.len() > 5
    {
        return Err(OracleNormalizationError::InvalidArtifact);
    }
    Ok(Some(value))
}

fn required_scalar(scope: &[u8], tag: &[u8]) -> Result<String, OracleNormalizationError> {
    optional_scalar(scope, tag).ok_or(OracleNormalizationError::InvalidArtifact)
}

fn optional_scalar(scope: &[u8], tag: &[u8]) -> Option<String> {
    let value = tag_value(scope, tag)?;
    if value.contains(['\t', '\r', '\n']) {
        return None;
    }
    Some(value)
}

fn tag_value(scope: &[u8], tag: &[u8]) -> Option<String> {
    let mut open = Vec::with_capacity(tag.len() + 2);
    open.push(b'<');
    open.extend_from_slice(tag);
    open.push(b'>');
    let mut close = Vec::with_capacity(tag.len() + 3);
    close.extend_from_slice(b"</");
    close.extend_from_slice(tag);
    close.push(b'>');
    let start = scope
        .windows(open.len())
        .position(|window| window == open)?
        + open.len();
    let end = scope[start..]
        .windows(close.len())
        .position(|window| window == close)?
        + start;
    xml_unescape(&scope[start..end])
}

fn scopes<'a>(xml: &'a [u8], tag: &[u8]) -> Vec<&'a [u8]> {
    let mut open = Vec::with_capacity(tag.len() + 2);
    open.push(b'<');
    open.extend_from_slice(tag);
    open.push(b'>');
    let mut close = Vec::with_capacity(tag.len() + 3);
    close.extend_from_slice(b"</");
    close.extend_from_slice(tag);
    close.push(b'>');
    let mut result = Vec::new();
    let mut at = 0;
    while let Some(relative) = xml[at..]
        .windows(open.len())
        .position(|window| window == open)
    {
        let body_start = at + relative + open.len();
        let Some(end_relative) = xml[body_start..]
            .windows(close.len())
            .position(|window| window == close)
        else {
            return Vec::new();
        };
        let body_end = body_start + end_relative;
        result.push(&xml[body_start..body_end]);
        at = body_end + close.len();
    }
    result
}

fn xml_unescape(input: &[u8]) -> Option<String> {
    let mut output = Vec::with_capacity(input.len());
    let mut at = 0;
    while at < input.len() {
        let remaining = &input[at..];
        if remaining.starts_with(b"&amp;") {
            output.push(b'&');
            at += 5;
        } else if remaining.starts_with(b"&lt;") {
            output.push(b'<');
            at += 4;
        } else if remaining.starts_with(b"&gt;") {
            output.push(b'>');
            at += 4;
        } else if remaining.starts_with(b"&quot;") {
            output.push(b'\"');
            at += 6;
        } else if remaining.starts_with(b"&apos;") {
            output.push(b'\'');
            at += 6;
        } else if input[at] == b'&' {
            return None;
        } else {
            output.push(input[at]);
            at += 1;
        }
    }
    String::from_utf8(output).ok()
}

/// Errors deliberately omit all artifact values and paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleNormalizationError {
    /// The privacy-safe manifest was invalid.
    Manifest(OracleManifestError),
    /// An artifact's actual digest differed from its manifest digest.
    DigestMismatch,
    /// One or more SDK response status attributes were not successful.
    UnsuccessfulResponse,
    /// Parsed record counts differed from the manifest.
    CountMismatch,
    /// XML did not match the narrow accepted QBXML shape.
    InvalidArtifact,
    /// Account XML did not match the narrow accepted QBXML shape.
    InvalidAccountsArtifact,
    /// Journal XML did not match the narrow accepted QBXML shape.
    InvalidJournalArtifact,
    /// A local output already exists; it is never overwritten.
    OutputExists,
    /// A local output path could not be created or written.
    OutputIo,
}

impl From<OracleManifestError> for OracleNormalizationError {
    fn from(value: OracleManifestError) -> Self {
        Self::Manifest(value)
    }
}

impl fmt::Display for OracleNormalizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(error) => write!(f, "SDK oracle manifest error: {error}"),
            Self::DigestMismatch => {
                f.write_str("SDK oracle artifact digest does not match manifest")
            }
            Self::UnsuccessfulResponse => {
                f.write_str("SDK oracle response status is not successful")
            }
            Self::CountMismatch => f.write_str("SDK oracle record count does not match manifest"),
            Self::InvalidArtifact => f.write_str("SDK oracle artifact has an unsupported shape"),
            Self::InvalidAccountsArtifact => {
                f.write_str("SDK oracle account artifact has an unsupported shape")
            }
            Self::InvalidJournalArtifact => {
                f.write_str("SDK oracle journal artifact has an unsupported shape")
            }
            Self::OutputExists => f.write_str("SDK oracle local output already exists"),
            Self::OutputIo => f.write_str("SDK oracle local output could not be written"),
        }
    }
}

impl Error for OracleNormalizationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk_oracle_manifest::sha256_hex;

    fn manifest(
        accounts: &[u8],
        journal: &[u8],
        accounts_count: usize,
        entries: usize,
        lines: usize,
    ) -> Vec<u8> {
        format!(
            r#"{{"company_file":"C:\\masked\\fixture.qbw","read_only":true,"qbxml_version":"16.0","account_count":{accounts_count},"journal_entry_count":{entries},"journal_line_count":{lines},"accounts_sha256":"{}","journal_sha256":"{}"}}"#,
            sha256_hex(accounts),
            sha256_hex(journal),
        )
        .into_bytes()
    }

    const ACCOUNTS: &[u8] = br#"<AccountQueryRs statusCode="0"><AccountRet><ListID>ACCOUNT012345678</ListID><Name>Demo</Name><FullName>Demo</FullName><AccountType>Bank</AccountType><IsActive>true</IsActive></AccountRet></AccountQueryRs>"#;
    const JOURNAL: &[u8] = br#"<JournalEntryQueryRs statusCode="0"><JournalEntryRet><TxnID>ABCDEF0123456789</TxnID><TxnDate>2026-08-26</TxnDate><JournalDebitLine><TxnLineID>LINEID0123456789</TxnLineID><AccountRef><ListID>ACCOUNT012345678</ListID></AccountRef><Amount>12.34001</Amount></JournalDebitLine></JournalEntryRet></JournalEntryQueryRs>"#;

    #[test]
    fn parses_synthetic_artifacts_without_printing_values() {
        let accounts = parse_accounts(ACCOUNTS).unwrap();
        let (entries, source_lines, journal) = parse_journal(JOURNAL).unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(entries, 1);
        assert_eq!(source_lines, 1);
        assert_eq!(journal.len(), 1);
        assert_eq!(
            journal_tsv(&journal).lines().next(),
            Some("txn_id\ttxn_line_id\ttxn_date\taccount_list_id\tamount")
        );
    }

    #[test]
    fn rejects_digest_count_and_status_mismatches() {
        let valid = manifest(ACCOUNTS, JOURNAL, 1, 1, 1);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp = std::env::temp_dir().join(format!("openqbw-sdk-normalize-{nonce}"));
        let result = normalize_sdk_oracle(&valid, ACCOUNTS, JOURNAL, &temp).unwrap();
        assert_eq!(result.journal_line_rows, 1);
        assert_eq!(result.journal_source_line_rows, 1);

        assert_eq!(
            normalize_sdk_oracle(&valid, b"different", JOURNAL, &temp),
            Err(OracleNormalizationError::DigestMismatch)
        );
        let wrong_count = manifest(ACCOUNTS, JOURNAL, 2, 1, 1);
        assert_eq!(
            normalize_sdk_oracle(&wrong_count, ACCOUNTS, JOURNAL, &temp),
            Err(OracleNormalizationError::CountMismatch)
        );
        let bad_status = String::from_utf8(JOURNAL.to_vec())
            .unwrap()
            .replace("statusCode=\"0\"", "statusCode=\"1\"")
            .into_bytes();
        let bad_manifest = manifest(ACCOUNTS, &bad_status, 1, 1, 1);
        assert_eq!(
            normalize_sdk_oracle(&bad_manifest, ACCOUNTS, &bad_status, &temp),
            Err(OracleNormalizationError::UnsuccessfulResponse)
        );
    }

    #[test]
    fn preexisting_journal_path_does_not_create_an_account_output() {
        let valid = manifest(ACCOUNTS, JOURNAL, 1, 1, 1);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp = std::env::temp_dir().join(format!("openqbw-sdk-cleanup-{nonce}"));
        std::fs::create_dir_all(&temp).unwrap();
        // A directory at the journal path is an existing output and must stop
        // the paired fixture before the account file is created.
        std::fs::create_dir(temp.join(JOURNAL_TSV)).unwrap();

        assert_eq!(
            normalize_sdk_oracle(&valid, ACCOUNTS, JOURNAL, &temp),
            Err(OracleNormalizationError::OutputExists)
        );
        assert!(!temp.join(ACCOUNTS_TSV).exists());
        let _ = std::fs::remove_dir(temp.join(JOURNAL_TSV));
        let _ = std::fs::remove_dir(temp);
    }
}

//! Aggregate-only identifier representation probe for a controlled posting delta.
//!
//! This research helper extracts the one transaction identifier and its line
//! identifiers from a *locally supplied synthetic QBXML oracle*, then searches
//! only the net changed pages for mechanically derived representations.  It
//! never serializes identifiers, source paths, page numbers, offsets, bytes,
//! or surrounding company content.  A hit is representation evidence only;
//! it is not a decoder, row boundary, or field-identity claim.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;

use openqbw::{deobfuscate_with_bv, recover_bv_any};
use opensqlany::{ApModel, PageStore};

use crate::batch_extract::StreamingSha256;
use crate::snapshot_compare::{PAGE_SIZE, parse_control_noise_manifest};

const MAX_IDENTIFIER_BYTES: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct SearchEvidence {
    pub candidate_page_count: u64,
    pub marker_colocated_page_count: u64,
    pub representation_hit_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentifierCategoryEvidence {
    /// This is a fixed schema label (`transaction` or `line`), never an ID.
    pub category: &'static str,
    pub identifier_count: u64,
    pub generated_representation_count: u64,
    pub raw: SearchEvidence,
    pub recover_bv_any_candidate: SearchEvidence,
    pub ap_model_candidate: SearchEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SentinelIdentifierProbe {
    pub page_count: u64,
    pub raw_changed_page_count: u64,
    pub control_noise_subtracted_page_count: u64,
    pub remaining_changed_page_count: u64,
    pub marker_count: u64,
    pub transaction: IdentifierCategoryEvidence,
    pub lines: IdentifierCategoryEvidence,
}

/// Extract and probe the single controlled JournalEntry whose `RefNumber`
/// exactly matches `document_number`.  The supplied marker literals must be
/// non-empty ASCII synthetic markers and are used only for page co-location.
pub fn probe_sentinel_identifiers(
    before_path: &Path,
    after_path: &Path,
    control_noise_manifest: &Path,
    journal_oracle: &Path,
    document_number: &str,
    markers: &[String],
) -> Result<SentinelIdentifierProbe, String> {
    if !document_number.is_ascii() || document_number.is_empty() {
        return Err("document number must be non-empty ASCII".to_owned());
    }
    let marker_bytes = validate_markers(markers)?;
    let (transaction_id, line_ids) = extract_journal_ids(
        &fs::read_to_string(journal_oracle).map_err(io)?,
        document_number,
    )?;
    let transaction_forms = representations(&transaction_id)?;
    let line_forms = line_ids
        .iter()
        .map(|id| representations(id))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let before_len = regular_file_len(before_path)?;
    if before_len != regular_file_len(after_path)? || !before_len.is_multiple_of(PAGE_SIZE as u64) {
        return Err("snapshots must have equal 4096-byte aligned lengths".to_owned());
    }
    let mut control = parse_control_noise_manifest(&fs::read(control_noise_manifest).map_err(io)?)?;
    let after_store = PageStore::open(after_path)
        .map_err(|_| "could not open after snapshot as page store".to_owned())?;
    let ap_model = ApModel::learn(&after_store);
    let mut before_reader =
        BufReader::with_capacity(PAGE_SIZE * 16, File::open(before_path).map_err(io)?);
    let mut after_reader =
        BufReader::with_capacity(PAGE_SIZE * 16, File::open(after_path).map_err(io)?);
    let mut before = [0u8; PAGE_SIZE];
    let mut after = [0u8; PAGE_SIZE];
    let mut raw_changed = 0;
    let mut subtracted = 0;
    let mut remaining = 0;
    let mut transaction = category("transaction", 1, transaction_forms.len());
    let mut lines = category("line", line_ids.len(), line_forms.len());
    for pn in 0..before_len / PAGE_SIZE as u64 {
        before_reader.read_exact(&mut before).map_err(io)?;
        after_reader.read_exact(&mut after).map_err(io)?;
        if before == after {
            continue;
        }
        raw_changed += 1;
        let transition = (sha(&before), sha(&after));
        if let Some(count) = control.get_mut(&transition)
            && *count != 0
        {
            *count -= 1;
            subtracted += 1;
            continue;
        }
        remaining += 1;
        inspect(
            &after,
            &marker_bytes,
            &transaction_forms,
            &mut transaction.raw,
        );
        inspect(&after, &marker_bytes, &line_forms, &mut lines.raw);
        if let Some(bv) = recover_bv_any(pn, &after) {
            let candidate = deobfuscate_with_bv(&after, pn, bv);
            inspect(
                &candidate,
                &marker_bytes,
                &transaction_forms,
                &mut transaction.recover_bv_any_candidate,
            );
            inspect(
                &candidate,
                &marker_bytes,
                &line_forms,
                &mut lines.recover_bv_any_candidate,
            );
        }
        let candidate = ap_model.deobfuscate_with_store(&after, pn, &after_store);
        inspect(
            &candidate,
            &marker_bytes,
            &transaction_forms,
            &mut transaction.ap_model_candidate,
        );
        inspect(
            &candidate,
            &marker_bytes,
            &line_forms,
            &mut lines.ap_model_candidate,
        );
    }
    ensure_eof(&mut before_reader)?;
    ensure_eof(&mut after_reader)?;
    if regular_file_len(before_path)? != before_len || regular_file_len(after_path)? != before_len {
        return Err("snapshot changed during read".to_owned());
    }
    Ok(SentinelIdentifierProbe {
        page_count: before_len / PAGE_SIZE as u64,
        raw_changed_page_count: raw_changed,
        control_noise_subtracted_page_count: subtracted,
        remaining_changed_page_count: remaining,
        marker_count: markers.len() as u64,
        transaction,
        lines,
    })
}

fn category(category: &'static str, ids: usize, forms: usize) -> IdentifierCategoryEvidence {
    IdentifierCategoryEvidence {
        category,
        identifier_count: ids as u64,
        generated_representation_count: forms as u64,
        raw: SearchEvidence::default(),
        recover_bv_any_candidate: SearchEvidence::default(),
        ap_model_candidate: SearchEvidence::default(),
    }
}

fn inspect(page: &[u8], markers: &[Vec<u8>], forms: &[Vec<u8>], evidence: &mut SearchEvidence) {
    let hits = forms
        .iter()
        .map(|form| count_nonoverlapping(page, form) as u64)
        .sum::<u64>();
    if hits == 0 {
        return;
    }
    evidence.candidate_page_count += 1;
    evidence.representation_hit_count += hits;
    if markers
        .iter()
        .any(|marker| count_nonoverlapping(page, marker) != 0)
    {
        evidence.marker_colocated_page_count += 1;
    }
}

fn count_nonoverlapping(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut at = 0;
    while at + needle.len() <= haystack.len() {
        let Some(relative) = haystack[at..]
            .windows(needle.len())
            .position(|window| window == needle)
        else {
            break;
        };
        count += 1;
        at += relative + needle.len();
    }
    count
}

fn extract_journal_ids(xml: &str, document_number: &str) -> Result<(String, Vec<String>), String> {
    let records = elements(xml, "JournalEntryRet");
    let mut matching = records
        .into_iter()
        .filter(|record| values(record, "RefNumber").contains(&document_number));
    let record = matching.next().ok_or_else(|| {
        "synthetic journal entry was not present exactly once in oracle".to_owned()
    })?;
    if matching.next().is_some() {
        return Err("synthetic journal entry was not present exactly once in oracle".to_owned());
    }
    let mut transaction_ids = values(record, "TxnID");
    let transaction_id = transaction_ids.pop().ok_or_else(|| {
        "journal oracle did not contain exactly one transaction identifier".to_owned()
    })?;
    if !transaction_ids.is_empty() {
        return Err("journal oracle did not contain exactly one transaction identifier".to_owned());
    }
    // QuickBooks can include a metadata-only JournalDebitLine with a line ID
    // but no AccountRef/Amount/Memo.  The controlled JE has four populated
    // posting lines; keep this filter structural and do not inspect values.
    let line_ids = ["JournalDebitLine", "JournalCreditLine"]
        .into_iter()
        .flat_map(|tag| elements(record, tag))
        .filter(|line| line.contains("<AccountRef>"))
        .flat_map(|line| values(line, "TxnLineID"))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if line_ids.len() != 4 || line_ids.iter().any(|id| id.is_empty()) {
        return Err(
            "journal oracle did not contain exactly four populated line identifiers".to_owned(),
        );
    }
    Ok((transaction_id.to_owned(), line_ids))
}

fn elements<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut result = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(&close) else { break };
        result.push(&after[..end]);
        rest = &after[end + close.len()..];
    }
    result
}
fn values<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    elements(xml, tag)
}

fn validate_markers(markers: &[String]) -> Result<Vec<Vec<u8>>, String> {
    if markers.is_empty() {
        return Err("at least one synthetic marker is required".to_owned());
    }
    let mut unique = BTreeMap::new();
    for marker in markers {
        if marker.is_empty() || !marker.is_ascii() || unique.insert(marker, ()).is_some() {
            return Err("markers must be distinct non-empty ASCII values".to_owned());
        }
    }
    Ok(markers
        .iter()
        .map(|marker| marker.as_bytes().to_vec())
        .collect())
}

/// Derived representations are deliberately mechanical and bounded: literal,
/// punctuation-stripped literal, UTF-16LE, raw decoded hex bytes, GUID field
/// reordered bytes, and big/little-endian 4/8-byte windows.  These forms are
/// only hypotheses, including after candidate AP transforms.
fn representations(identifier: &str) -> Result<Vec<Vec<u8>>, String> {
    if identifier.is_empty() || !identifier.is_ascii() || identifier.len() > MAX_IDENTIFIER_BYTES {
        return Err("oracle identifier was not bounded non-empty ASCII".to_owned());
    }
    let mut forms = BTreeMap::<Vec<u8>, ()>::new();
    forms.insert(identifier.as_bytes().to_vec(), ());
    let stripped = identifier
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .collect::<Vec<_>>();
    if !stripped.is_empty() {
        forms.insert(stripped.clone(), ());
    }
    let mut utf16 = Vec::with_capacity(identifier.len() * 2);
    for byte in identifier.bytes() {
        utf16.extend([byte, 0]);
    }
    forms.insert(utf16, ());
    if stripped.len() >= 2 && stripped.len() % 2 == 0 && stripped.iter().all(u8::is_ascii_hexdigit)
    {
        let binary = (0..stripped.len())
            .step_by(2)
            .map(|i| hex(stripped[i]) * 16 + hex(stripped[i + 1]))
            .collect::<Vec<_>>();
        forms.insert(binary.clone(), ());
        if binary.len() == 16 {
            let mut guid = binary.clone();
            guid[0..4].reverse();
            guid[4..6].reverse();
            guid[6..8].reverse();
            forms.insert(guid, ());
        }
        for width in [4usize, 8] {
            for chunk in binary.windows(width) {
                forms.insert(chunk.to_vec(), ());
                let mut reversed = chunk.to_vec();
                reversed.reverse();
                forms.insert(reversed, ());
            }
        }
    }
    Ok(forms.into_keys().collect())
}
fn hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}
fn regular_file_len(path: &Path) -> Result<u64, String> {
    let meta = fs::metadata(path).map_err(io)?;
    if !meta.is_file() {
        return Err("input is not a regular file".to_owned());
    }
    Ok(meta.len())
}
fn ensure_eof(reader: &mut impl Read) -> Result<(), String> {
    let mut byte = [0];
    if reader.read(&mut byte).map_err(io)? == 0 {
        Ok(())
    } else {
        Err("snapshot changed during read".to_owned())
    }
}
fn io(error: std::io::Error) -> String {
    error.kind().to_string()
}
fn sha(bytes: &[u8]) -> String {
    let mut hasher = StreamingSha256::new();
    hasher.update(bytes);
    hasher.finish_hex()
}

pub fn to_json(probe: &SentinelIdentifierProbe) -> String {
    fn evidence(out: &mut String, value: &SearchEvidence) {
        let _ = write!(
            out,
            "{{\"candidate_page_count\":{},\"marker_colocated_page_count\":{},\"representation_hit_count\":{}}}",
            value.candidate_page_count,
            value.marker_colocated_page_count,
            value.representation_hit_count
        );
    }
    fn category(out: &mut String, value: &IdentifierCategoryEvidence) {
        let _ = write!(
            out,
            "{{\"category\":\"{}\",\"identifier_count\":{},\"generated_representation_count\":{},\"raw_storage\":",
            value.category, value.identifier_count, value.generated_representation_count
        );
        evidence(out, &value.raw);
        out.push_str(",\"recover_bv_any\":");
        evidence(out, &value.recover_bv_any_candidate);
        out.push_str(",\"ap_model\":");
        evidence(out, &value.ap_model_candidate);
        out.push('}');
    }
    let mut out = String::from(
        "{\"schema_version\":\"openqbw.sentinel-identifier-probe.v1\",\"classification\":\"aggregate_representation_evidence_not_identifier_or_posting_decoder\"",
    );
    let _ = write!(
        out,
        ",\"page_size\":{},\"page_count\":{},\"raw_changed_page_count\":{},\"control_noise_subtraction\":{{\"applied\":true,\"subtracted_changed_page_count\":{},\"remaining_changed_page_count\":{}}},\"marker_count\":{}",
        PAGE_SIZE,
        probe.page_count,
        probe.raw_changed_page_count,
        probe.control_noise_subtracted_page_count,
        probe.remaining_changed_page_count,
        probe.marker_count
    );
    out.push_str(",\"representations_attempted\":[\"literal\",\"stripped\",\"utf16le\",\"hex_binary\",\"guid_binary\",\"numeric_endian_windows\",\"recover_bv_any_candidate\",\"ap_model_candidate\"],\"categories\":[");
    category(&mut out, &probe.transaction);
    out.push(',');
    category(&mut out, &probe.lines);
    out.push_str("]}");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extracts_one_txnid_and_four_line_ids_without_retaining_output_values() {
        let xml = "<JournalEntryRet><TxnID>00112233445566778899AABBCCDDEEFF</TxnID><RefNumber>SAMPLE_JE_001</RefNumber><JournalDebitLine><TxnLineID>metadata</TxnLineID></JournalDebitLine><JournalDebitLine><AccountRef></AccountRef><TxnLineID>a1</TxnLineID></JournalDebitLine><JournalDebitLine><AccountRef></AccountRef><TxnLineID>a2</TxnLineID></JournalDebitLine><JournalCreditLine><AccountRef></AccountRef><TxnLineID>a3</TxnLineID></JournalCreditLine><JournalCreditLine><AccountRef></AccountRef><TxnLineID>a4</TxnLineID></JournalCreditLine></JournalEntryRet>";
        let (transaction, lines) = extract_journal_ids(xml, "SAMPLE_JE_001").unwrap();
        assert_eq!(transaction.len(), 32);
        assert_eq!(lines.len(), 4);
        let json = to_json(&SentinelIdentifierProbe {
            page_count: 1,
            raw_changed_page_count: 1,
            control_noise_subtracted_page_count: 0,
            remaining_changed_page_count: 1,
            marker_count: 4,
            transaction: category(
                "transaction",
                1,
                representations(&transaction).unwrap().len(),
            ),
            lines: category("line", lines.len(), 4),
        });
        assert!(!json.contains(&transaction));
        assert!(!json.contains(&lines[0]));
        assert!(!json.contains("offset"));
    }
    #[test]
    fn derived_forms_include_binary_guid_and_numeric_hypotheses() {
        let forms = representations("00112233445566778899AABBCCDDEEFF").unwrap();
        assert!(forms.iter().any(|v| v.len() == 16));
        assert!(forms.iter().any(|v| v.len() == 8));
        assert!(forms.iter().any(|v| v.len() == 64));
    }
}

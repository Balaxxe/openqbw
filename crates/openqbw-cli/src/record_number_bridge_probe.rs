//! Controlled-delta probe for the numeric record-number component of QBXML IDs.
//!
//! This accepts only the narrow synthetic JE/account oracle shape used by the
//! Delta Lab and emits aggregate assertions and hit counts. IDs, raw values,
//! bytes, paths, page locations, and offsets are never emitted.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;

use openqbw::{deobfuscate_with_bv, recover_bv_any};
use opensqlany::{ApModel, Page, PageStore, SlottedPage};

use crate::batch_extract::StreamingSha256;
use crate::snapshot_compare::{PAGE_SIZE, parse_control_noise_manifest};

// This is a private controlled fixture locator. It is never serialized.
const JE_ENVELOPE_PAGE: u64 = 2457;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct NumericSearchEvidence {
    pub page_count: u64,
    pub hit_count: u64,
    pub envelope_range_count: u64,
    pub envelope_hit_count: u64,
    pub static_header_position_hit_count: u64,
    pub static_header_range_hit_count: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NumericGroupEvidence {
    pub role: &'static str,
    pub value_count: u64,
    pub unique_value_count: u64,
    pub generated_representation_count: u64,
    pub raw: NumericSearchEvidence,
    pub recover_bv_any_candidate: NumericSearchEvidence,
    pub ap_model_candidate: NumericSearchEvidence,
    forms: Vec<Form>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordNumberBridgeProbe {
    pub page_count: u64,
    pub raw_changed_page_count: u64,
    pub control_noise_subtracted_page_count: u64,
    pub remaining_changed_page_count: u64,
    pub oracle_assertions: OracleAssertions,
    pub master: NumericGroupEvidence,
    pub target: NumericGroupEvidence,
    pub account: NumericGroupEvidence,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleAssertions {
    pub journal_id_shape_valid: bool,
    pub account_id_shape_valid: bool,
    pub line_count_is_four: bool,
    pub target_components_sequential_from_master_plus_two: bool,
    pub target_second_components_equal: bool,
    pub account_components_unique: bool,
    pub account_components_sequential: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Form {
    label: &'static str,
    bytes: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub fn probe_record_number_bridge(
    before: &Path,
    after: &Path,
    control_noise_manifest: &Path,
    journal_oracle: &Path,
    account_oracle: &Path,
    document_number: &str,
    account_marker: &str,
    markers: &[String],
) -> Result<RecordNumberBridgeProbe, String> {
    let marker_bytes = markers
        .iter()
        .map(|v| {
            if v.is_empty() || !v.is_ascii() {
                Err("markers must be non-empty ASCII".to_owned())
            } else {
                Ok(v.as_bytes().to_vec())
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    if marker_bytes.is_empty() || !document_number.is_ascii() || !account_marker.is_ascii() {
        return Err("synthetic selector is invalid".to_owned());
    }
    let (master, targets, journal_assertions) = parse_journal(
        &fs::read_to_string(journal_oracle).map_err(io)?,
        document_number,
    )?;
    let (accounts, account_assertions) = parse_accounts(
        &fs::read_to_string(account_oracle).map_err(io)?,
        account_marker,
    )?;
    let assertions = OracleAssertions {
        journal_id_shape_valid: journal_assertions.0,
        account_id_shape_valid: account_assertions.0,
        line_count_is_four: targets.len() == 4,
        target_components_sequential_from_master_plus_two: targets
            .iter()
            .enumerate()
            .all(|(i, v)| *v == master + i as u32 + 2),
        target_second_components_equal: journal_assertions.1,
        account_components_unique: accounts.iter().collect::<BTreeSet<_>>().len() == accounts.len(),
        account_components_sequential: accounts.windows(2).all(|pair| pair[1] == pair[0] + 1),
    };
    if !(assertions.journal_id_shape_valid
        && assertions.account_id_shape_valid
        && assertions.line_count_is_four
        && assertions.target_components_sequential_from_master_plus_two
        && assertions.target_second_components_equal
        && assertions.account_components_unique
        && assertions.account_components_sequential)
    {
        return Err("controlled oracle record-number invariants did not hold".to_owned());
    }
    let groups = [
        ("master", vec![master]),
        ("target", targets),
        ("account", accounts),
    ];
    let before_len = file_len(before)?;
    if before_len != file_len(after)? || !before_len.is_multiple_of(PAGE_SIZE as u64) {
        return Err("snapshots must have equal 4096-byte aligned lengths".to_owned());
    }
    let mut control = parse_control_noise_manifest(&fs::read(control_noise_manifest).map_err(io)?)?;
    let after_store = PageStore::open(after)
        .map_err(|_| "could not open after snapshot as page store".to_owned())?;
    let model = ApModel::learn(&after_store);
    let mut results = groups
        .into_iter()
        .map(|(role, values)| group(role, values))
        .collect::<Vec<_>>();
    let mut left = BufReader::with_capacity(PAGE_SIZE * 16, File::open(before).map_err(io)?);
    let mut right = BufReader::with_capacity(PAGE_SIZE * 16, File::open(after).map_err(io)?);
    let mut before_page = [0u8; PAGE_SIZE];
    let mut after_page = [0u8; PAGE_SIZE];
    let mut changed = 0;
    let mut subtracted = 0;
    let mut remaining = 0;
    for pn in 0..before_len / PAGE_SIZE as u64 {
        left.read_exact(&mut before_page).map_err(io)?;
        right.read_exact(&mut after_page).map_err(io)?;
        if before_page == after_page {
            continue;
        }
        changed += 1;
        let key = (sha(&before_page), sha(&after_page));
        if let Some(count) = control.get_mut(&key)
            && *count != 0
        {
            *count -= 1;
            subtracted += 1;
            continue;
        }
        remaining += 1;
        inspect_all(
            &after_page,
            &marker_bytes,
            (pn == JE_ENVELOPE_PAGE).then_some(after_page.as_slice()),
            &mut results,
            Transform::Raw,
        );
        let recovered =
            recover_bv_any(pn, &after_page).map(|bv| deobfuscate_with_bv(&after_page, pn, bv));
        if let Some(candidate) = recovered.as_deref() {
            inspect_all(
                candidate,
                &marker_bytes,
                (pn == JE_ENVELOPE_PAGE).then_some(candidate),
                &mut results,
                Transform::Bv,
            );
        }
        let ap = model.deobfuscate_with_store(&after_page, pn, &after_store);
        inspect_all(
            &ap,
            &marker_bytes,
            (pn == JE_ENVELOPE_PAGE).then_some(ap.as_slice()),
            &mut results,
            Transform::Ap,
        );
    }
    ensure_eof(&mut left)?;
    ensure_eof(&mut right)?;
    if file_len(before)? != before_len || file_len(after)? != before_len {
        return Err("snapshot changed during read".to_owned());
    }
    Ok(RecordNumberBridgeProbe {
        page_count: before_len / PAGE_SIZE as u64,
        raw_changed_page_count: changed,
        control_noise_subtracted_page_count: subtracted,
        remaining_changed_page_count: remaining,
        oracle_assertions: assertions,
        master: results.remove(0),
        target: results.remove(0),
        account: results.remove(0),
    })
}

#[derive(Clone, Copy)]
enum Transform {
    Raw,
    Bv,
    Ap,
}
fn inspect_all(
    page: &[u8],
    markers: &[Vec<u8>],
    envelope_page: Option<&[u8]>,
    groups: &mut [NumericGroupEvidence],
    transform: Transform,
) {
    for group in groups {
        let forms = group.forms.clone();
        let evidence = match transform {
            Transform::Raw => &mut group.raw,
            Transform::Bv => &mut group.recover_bv_any_candidate,
            Transform::Ap => &mut group.ap_model_candidate,
        };
        inspect_group(page, markers, &forms, evidence);
        if let Some(candidate) = envelope_page {
            inspect_envelopes(group.role, candidate, markers, &forms, evidence);
        }
    }
}
fn inspect_group(
    page: &[u8],
    markers: &[Vec<u8>],
    forms: &[Form],
    evidence: &mut NumericSearchEvidence,
) {
    let hits = forms
        .iter()
        .map(|f| count(page, &f.bytes) as u64)
        .sum::<u64>();
    if hits != 0 {
        evidence.page_count += 1;
        evidence.hit_count += hits;
    }
    let _ = markers;
}
fn inspect_envelopes(
    role: &str,
    page: &[u8],
    markers: &[Vec<u8>],
    forms: &[Form],
    evidence: &mut NumericSearchEvidence,
) {
    let slotted = SlottedPage::parse(Page::from_bytes(0, page));
    for (_, row) in slotted.row_bytes() {
        if !markers.iter().any(|m| count(row, m) != 0) {
            continue;
        }
        evidence.envelope_range_count += 1;
        evidence.envelope_hit_count += forms
            .iter()
            .map(|f| count(row, &f.bytes) as u64)
            .sum::<u64>();
        evidence.static_header_position_hit_count += header_hits(role, row, forms) as u64;
        evidence.static_header_range_hit_count += header_range_hits(role, row, forms) as u64;
    }
}
fn header_hits(role: &str, row: &[u8], forms: &[Form]) -> usize {
    match role {
        "master" if row.len() >= 14 => forms
            .iter()
            .filter(|form| matches!(form.label, "u32le" | "u32be") && row[10..14] == form.bytes)
            .count(),
        "target" if row.len() >= 10 => forms
            .iter()
            .filter(|form| {
                matches!(form.label, "u32le" | "u32be")
                    && (row[2..6] == form.bytes || row[6..10] == form.bytes)
            })
            .count(),
        "account" if row.len() >= 22 => forms
            .iter()
            .filter(|form| {
                matches!(form.label, "u16le" | "u32_low16le") && row[20..22] == form.bytes
            })
            .count(),
        _ => 0,
    }
}
fn header_range_hits(role: &str, row: &[u8], forms: &[Form]) -> usize {
    fn hits(row: &[u8], range: std::ops::Range<usize>, forms: &[Form]) -> usize {
        forms
            .iter()
            .filter(|form| {
                form.bytes.len() <= range.len() && count(&row[range.clone()], &form.bytes) != 0
            })
            .count()
    }
    match role {
        "master" if row.len() >= 14 => hits(row, 10..14, forms),
        "target" if row.len() >= 10 => hits(row, 2..6, forms) + hits(row, 6..10, forms),
        "account" if row.len() >= 22 => hits(row, 20..22, forms),
        _ => 0,
    }
}
fn group(role: &'static str, values: Vec<u32>) -> NumericGroupEvidence {
    let unique = values.iter().collect::<BTreeSet<_>>().len();
    let forms = forms(&values);
    NumericGroupEvidence {
        role,
        value_count: values.len() as u64,
        unique_value_count: unique as u64,
        generated_representation_count: forms.len() as u64,
        raw: Default::default(),
        recover_bv_any_candidate: Default::default(),
        ap_model_candidate: Default::default(),
        forms,
    }
}

type JournalComponents = (u32, Vec<u32>, (bool, bool));
fn parse_journal(xml: &str, document: &str) -> Result<JournalComponents, String> {
    let records = elements(xml, "JournalEntryRet");
    let mut matches = records
        .into_iter()
        .filter(|record| values(record, "RefNumber").contains(&document));
    let record = matches.next().ok_or_else(|| {
        "synthetic journal entry was not present exactly once in oracle".to_owned()
    })?;
    if matches.next().is_some() {
        return Err("synthetic journal entry was not present exactly once in oracle".to_owned());
    }
    let master_id = values(record, "TxnID")
        .first()
        .copied()
        .ok_or_else(|| "journal transaction ID missing".to_owned())?;
    let (master, second) = parse_id(master_id, 5)?;
    let lines = ["JournalDebitLine", "JournalCreditLine"]
        .into_iter()
        .flat_map(|tag| elements(record, tag))
        .filter(|line| line.contains("<AccountRef>"))
        .flat_map(|line| values(line, "TxnLineID"))
        .map(|id| parse_id(id, 5))
        .collect::<Result<Vec<_>, _>>()?;
    let seconds_equal = lines.iter().all(|(_, component)| *component == second);
    Ok((
        master,
        lines.into_iter().map(|(value, _)| value).collect(),
        (true, seconds_equal),
    ))
}
fn parse_accounts(xml: &str, marker: &str) -> Result<(Vec<u32>, (bool,)), String> {
    let accounts = elements(xml, "AccountRet")
        .into_iter()
        .filter(|record| record.contains(marker))
        .map(|record| {
            values(record, "ListID")
                .first()
                .copied()
                .ok_or_else(|| "synthetic account lacks list ID".to_owned())
                .and_then(|id| parse_id(id, 8).map(|(value, _)| value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if accounts.len() != 5 {
        return Err("synthetic account oracle did not select exactly five accounts".to_owned());
    }
    Ok((accounts, (true,)))
}
fn parse_id(value: &str, hex_width: usize) -> Result<(u32, &str), String> {
    let (first, second) = value
        .split_once('-')
        .ok_or_else(|| "oracle identifier does not use two components".to_owned())?;
    if first.len() != hex_width
        || second.len() != 10
        || !first.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !second.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("oracle identifier does not have approved component shape".to_owned());
    }
    Ok((
        u32::from_str_radix(first, 16)
            .map_err(|_| "invalid first identifier component".to_owned())?,
        second,
    ))
}
fn elements<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(&close) else { break };
        out.push(&after[..end]);
        rest = &after[end + close.len()..];
    }
    out
}
fn values<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    elements(xml, tag)
}
fn forms(values: &[u32]) -> Vec<Form> {
    let mut out = BTreeMap::new();
    for &value in values {
        // A ListID's high component can exceed u16. The low 16 bits are a
        // separate, explicitly named controlled hypothesis; do not silently
        // truncate it into the generic u16 representation.
        let low16 = (value & 0xffff) as u16;
        out.insert(("u32_low16le", low16.to_le_bytes().to_vec()), ());
        out.insert(("u32_low16be", low16.to_be_bytes().to_vec()), ());
        if let Ok(value16) = u16::try_from(value) {
            out.insert(("u16le", value16.to_le_bytes().to_vec()), ());
            out.insert(("u16be", value16.to_be_bytes().to_vec()), ());
        }
        let b = value.to_be_bytes();
        out.insert(("u24le", vec![b[3], b[2], b[1]]), ());
        out.insert(("u24be", b[1..].to_vec()), ());
        out.insert(("u32le", value.to_le_bytes().to_vec()), ());
        out.insert(("u32be", value.to_be_bytes().to_vec()), ());
        out.insert(("leb128", leb128(value)), ());
        out.insert(("be_base128", be_base128(value)), ());
    }
    out.into_keys()
        .map(|(label, bytes)| Form { label, bytes })
        .collect()
}
fn leb128(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return out;
        }
    }
}
fn be_base128(value: u32) -> Vec<u8> {
    let mut stack = vec![(value & 0x7f) as u8];
    let mut value = value >> 7;
    while value != 0 {
        stack.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }
    stack.reverse();
    stack
}
fn count(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut at = 0;
    let mut count = 0;
    while at + needle.len() <= haystack.len() {
        let Some(found) = haystack[at..]
            .windows(needle.len())
            .position(|part| part == needle)
        else {
            break;
        };
        count += 1;
        at += found + needle.len();
    }
    count
}
fn file_len(path: &Path) -> Result<u64, String> {
    let metadata = fs::metadata(path).map_err(io)?;
    if !metadata.is_file() {
        return Err("input is not a regular file".to_owned());
    }
    Ok(metadata.len())
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

pub fn to_json(probe: &RecordNumberBridgeProbe) -> String {
    fn e(out: &mut String, value: &NumericSearchEvidence) {
        let _ = write!(
            out,
            "{{\"candidate_page_count\":{},\"representation_hit_count\":{},\"sentinel_envelope_range_count\":{},\"sentinel_envelope_hit_count\":{},\"static_header_position_hit_count\":{},\"static_header_range_hit_count\":{}}}",
            value.page_count,
            value.hit_count,
            value.envelope_range_count,
            value.envelope_hit_count,
            value.static_header_position_hit_count,
            value.static_header_range_hit_count
        );
    }
    fn group(out: &mut String, value: &NumericGroupEvidence) {
        let _ = write!(
            out,
            "{{\"role\":\"{}\",\"value_count\":{},\"unique_value_count\":{},\"generated_representation_count\":{},\"raw_storage\":",
            value.role,
            value.value_count,
            value.unique_value_count,
            value.generated_representation_count
        );
        e(out, &value.raw);
        out.push_str(",\"recover_bv_any\":");
        e(out, &value.recover_bv_any_candidate);
        out.push_str(",\"ap_model\":");
        e(out, &value.ap_model_candidate);
        out.push('}');
    }
    let a = &probe.oracle_assertions;
    let mut out = String::from(
        "{\"schema_version\":\"openqbw.record-number-bridge-probe.v1\",\"classification\":\"aggregate_numeric_representation_evidence_not_a_record_or_posting_decoder\"",
    );
    let _ = write!(
        out,
        ",\"page_size\":{},\"page_count\":{},\"raw_changed_page_count\":{},\"control_noise_subtraction\":{{\"applied\":true,\"subtracted_changed_page_count\":{},\"remaining_changed_page_count\":{}}},\"representations_attempted\":[\"u16le\",\"u16be\",\"u24le\",\"u24be\",\"u32le\",\"u32be\",\"u32_low16le\",\"u32_low16be\",\"leb128\",\"be_base128\"],\"oracle_assertions\":{{\"journal_id_shape_valid\":{},\"account_id_shape_valid\":{},\"line_count_is_four\":{},\"target_components_sequential_from_master_plus_two\":{},\"target_second_components_equal\":{},\"account_components_unique\":{},\"account_components_sequential\":{}}},\"groups\":[",
        PAGE_SIZE,
        probe.page_count,
        probe.raw_changed_page_count,
        probe.control_noise_subtracted_page_count,
        probe.remaining_changed_page_count,
        a.journal_id_shape_valid,
        a.account_id_shape_valid,
        a.line_count_is_four,
        a.target_components_sequential_from_master_plus_two,
        a.target_second_components_equal,
        a.account_components_unique,
        a.account_components_sequential
    );
    group(&mut out, &probe.master);
    out.push(',');
    group(&mut out, &probe.target);
    out.push(',');
    group(&mut out, &probe.account);
    out.push_str("]}");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_only_first_components_and_excludes_metadata_line() {
        let journal = "<JournalEntryRet><TxnID>10000-0000000000</TxnID><RefNumber>SAMPLE_JE_001</RefNumber><JournalDebitLine><TxnLineID>fffff-0000000000</TxnLineID></JournalDebitLine><JournalDebitLine><AccountRef></AccountRef><TxnLineID>10002-0000000000</TxnLineID></JournalDebitLine><JournalDebitLine><AccountRef></AccountRef><TxnLineID>10003-0000000000</TxnLineID></JournalDebitLine><JournalCreditLine><AccountRef></AccountRef><TxnLineID>10004-0000000000</TxnLineID></JournalCreditLine><JournalCreditLine><AccountRef></AccountRef><TxnLineID>10005-0000000000</TxnLineID></JournalCreditLine></JournalEntryRet>";
        let (master, lines, (_, suffixes_equal)) = parse_journal(journal, "SAMPLE_JE_001").unwrap();
        assert_eq!(lines.len(), 4);
        assert!(suffixes_equal);
        assert!(
            lines
                .iter()
                .enumerate()
                .all(|(index, value)| *value == master + index as u32 + 2)
        );
        let accounts = "<AccountRet><ListID>10000000-0000000000</ListID>SAMPLE_MARKER</AccountRet><AccountRet><ListID>10000001-0000000000</ListID>SAMPLE_MARKER</AccountRet><AccountRet><ListID>10000002-0000000000</ListID>SAMPLE_MARKER</AccountRet><AccountRet><ListID>10000003-0000000000</ListID>SAMPLE_MARKER</AccountRet><AccountRet><ListID>10000004-0000000000</ListID>SAMPLE_MARKER</AccountRet>";
        let (values, _) = parse_accounts(accounts, "SAMPLE_MARKER").unwrap();
        assert!(values.windows(2).all(|pair| pair[1] == pair[0] + 1));
    }
    #[test]
    fn numeric_forms_cover_widths_and_varints_without_values_in_json() {
        let fs = forms(&[0x12345]);
        assert!(fs.iter().any(|form| form.label == "u24le"));
        assert!(fs.iter().any(|form| form.label == "leb128"));
        let high = forms(&[0x1234_5678]);
        assert!(
            high.iter()
                .any(|form| form.label == "u32_low16le" && form.bytes == [0x78, 0x56])
        );
        assert!(
            high.iter()
                .any(|form| form.label == "u32_low16be" && form.bytes == [0x56, 0x78])
        );
        let probe = RecordNumberBridgeProbe {
            page_count: 1,
            raw_changed_page_count: 1,
            control_noise_subtracted_page_count: 0,
            remaining_changed_page_count: 1,
            oracle_assertions: OracleAssertions {
                journal_id_shape_valid: true,
                account_id_shape_valid: true,
                line_count_is_four: true,
                target_components_sequential_from_master_plus_two: true,
                target_second_components_equal: true,
                account_components_unique: true,
                account_components_sequential: true,
            },
            master: group("master", vec![0x12345]),
            target: group("target", vec![0x12347]),
            account: group("account", vec![0x12345678]),
        };
        let json = to_json(&probe);
        assert!(!json.contains("12345"));
        assert!(!json.contains("offset"));
    }
}

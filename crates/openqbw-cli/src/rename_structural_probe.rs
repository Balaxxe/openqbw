//! Aggregate-only pairing probe for a controlled account rename.
//!
//! This is deliberately narrower than a decoder.  It accepts only the old and
//! new synthetic names plus synthetic values asserted to be stable, subtracts
//! the exact no-edit transition multiset, and reports counts only.  It never
//! exposes a page number, byte offset, record bytes, or a general search hit.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;

use openqbw::{PageScanOutcome, deobfuscate_with_bv, recover_bv_any, scan_decoded_page};
use opensqlany::Page;

use crate::batch_extract::StreamingSha256;
use crate::snapshot_compare::{PAGE_SIZE, parse_control_noise_manifest};

#[cfg(test)]
const PAGE_TYPE_OFFSET: usize = 0xff2;

/// Counts for one representation.  An exact normalized pair means that a
/// bounded contiguous candidate containing all supplied synthetic values was
/// byte-identical after replacing the supplied old/new name with one opaque
/// token.  It is a certified *byte invariant*, not a certified account row.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct RepresentationEvidence {
    pub inspected_net_changed_pages: u64,
    pub qualified_before_pages: u64,
    pub qualified_after_pages: u64,
    pub exact_normalized_page_pairs: u64,
    pub exact_normalized_window_pairs: u64,
    /// Both sides additionally occupied a valid physical slotted-page
    /// fragment.  This certifies only the physical bound, never table/field
    /// identity or plaintext correctness.
    pub slotted_fragment_pairs: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenameStructuralProbe {
    pub page_count: u64,
    pub raw_changed_page_count: u64,
    pub control_noise_subtracted_page_count: u64,
    pub remaining_changed_page_count: u64,
    pub old_name: String,
    pub new_name: String,
    pub stable_literals: Vec<String>,
    /// Direct stored-byte evidence.  The exact normalized counts are
    /// certified as byte comparisons only.
    pub raw: RepresentationEvidence,
    /// `recover_bv_any` was available for both sides of a page.  All of this
    /// section is heuristic candidate evidence; it is never plaintext or
    /// record certified.
    pub recover_bv_any_candidate: RepresentationEvidence,
    pub recover_bv_any_both_sides_page_count: u64,
}

pub fn probe_account_rename_structure(
    before_path: &Path,
    after_path: &Path,
    control_noise_manifest: &Path,
    old_name: &str,
    new_name: &str,
    stable_literals: &[String],
) -> Result<RenameStructuralProbe, String> {
    let old = validate_one(old_name, "old name")?;
    let new = validate_one(new_name, "new name")?;
    if old == new {
        return Err("old and new name must differ".to_owned());
    }
    let stable = validate_stable(stable_literals, &old, &new)?;
    let before_len = file_len(before_path)?;
    if before_len != file_len(after_path)? || !before_len.is_multiple_of(PAGE_SIZE as u64) {
        return Err("snapshots must have equal 4096-byte aligned lengths".to_owned());
    }
    let mut control = parse_control_noise_manifest(&fs::read(control_noise_manifest).map_err(io)?)?;
    let mut before_reader =
        BufReader::with_capacity(PAGE_SIZE * 16, File::open(before_path).map_err(io)?);
    let mut after_reader =
        BufReader::with_capacity(PAGE_SIZE * 16, File::open(after_path).map_err(io)?);
    let mut before = [0u8; PAGE_SIZE];
    let mut after = [0u8; PAGE_SIZE];
    let mut raw_changed = 0;
    let mut subtracted = 0;
    let mut remaining = 0;
    let mut raw = RepresentationEvidence::default();
    let mut recovered = RepresentationEvidence::default();
    let mut recovered_both = 0;
    for page_number in 0..before_len / PAGE_SIZE as u64 {
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
        inspect_pair(&before, &after, &old, &new, &stable, &mut raw);
        let (Some(before_bv), Some(after_bv)) = (
            recover_bv_any(page_number, &before),
            recover_bv_any(page_number, &after),
        ) else {
            continue;
        };
        recovered_both += 1;
        let before_plain = deobfuscate_with_bv(&before, page_number, before_bv);
        let after_plain = deobfuscate_with_bv(&after, page_number, after_bv);
        inspect_pair(
            &before_plain,
            &after_plain,
            &old,
            &new,
            &stable,
            &mut recovered,
        );
    }
    ensure_eof(&mut before_reader)?;
    ensure_eof(&mut after_reader)?;
    if file_len(before_path)? != before_len || file_len(after_path)? != before_len {
        return Err("snapshot changed during read".to_owned());
    }
    Ok(RenameStructuralProbe {
        page_count: before_len / PAGE_SIZE as u64,
        raw_changed_page_count: raw_changed,
        control_noise_subtracted_page_count: subtracted,
        remaining_changed_page_count: remaining,
        old_name: old,
        new_name: new,
        stable_literals: stable,
        raw,
        recover_bv_any_candidate: recovered,
        recover_bv_any_both_sides_page_count: recovered_both,
    })
}

fn inspect_pair(
    before: &[u8],
    after: &[u8],
    old: &str,
    new: &str,
    stable: &[String],
    out: &mut RepresentationEvidence,
) {
    out.inspected_net_changed_pages += 1;
    let before_windows = candidate_windows(before, old.as_bytes(), stable);
    let after_windows = candidate_windows(after, new.as_bytes(), stable);
    if !before_windows.is_empty() {
        out.qualified_before_pages += 1;
    }
    if !after_windows.is_empty() {
        out.qualified_after_pages += 1;
    }
    if normalize(before, old.as_bytes()) == normalize(after, new.as_bytes())
        && !before_windows.is_empty()
        && !after_windows.is_empty()
    {
        out.exact_normalized_page_pairs += 1;
    }
    let mut exact = false;
    for left in &before_windows {
        for right in &after_windows {
            if normalize(&before[left.clone()], old.as_bytes())
                == normalize(&after[right.clone()], new.as_bytes())
            {
                exact = true;
            }
        }
    }
    if exact {
        out.exact_normalized_window_pairs += 1;
    }
    if exact && slotted_match(before, after, old, new, stable) {
        out.slotted_fragment_pairs += 1;
    }
}

fn candidate_windows(bytes: &[u8], name: &[u8], stable: &[String]) -> Vec<std::ops::Range<usize>> {
    let mut groups: Vec<Vec<usize>> = vec![find_all(bytes, name)];
    groups.extend(stable.iter().map(|value| find_all(bytes, value.as_bytes())));
    if groups.iter().any(Vec::is_empty) {
        return Vec::new();
    }
    // At most 64 combinations. This prevents a malformed input from turning a
    // narrow controlled-delta tool into an expensive corpus scanner.
    let mut spans = BTreeSet::new();
    fn walk(
        groups: &[Vec<usize>],
        lengths: &[usize],
        index: usize,
        lo: usize,
        hi: usize,
        out: &mut BTreeSet<(usize, usize)>,
    ) {
        if index == groups.len() {
            out.insert((lo, hi));
            return;
        }
        for &offset in groups[index].iter().take(64) {
            let start = if index == 0 { offset } else { lo.min(offset) };
            let end = if index == 0 {
                offset + lengths[index]
            } else {
                hi.max(offset + lengths[index])
            };
            walk(groups, lengths, index + 1, start, end, out);
            if out.len() >= 64 {
                return;
            }
        }
    }
    let lengths = std::iter::once(name.len())
        .chain(stable.iter().map(String::len))
        .collect::<Vec<_>>();
    walk(&groups, &lengths, 0, 0, 0, &mut spans);
    spans.into_iter().map(|(start, end)| start..end).collect()
}

fn slotted_match(before: &[u8], after: &[u8], old: &str, new: &str, stable: &[String]) -> bool {
    let PageScanOutcome::Rows(left) = scan_decoded_page(Page::from_bytes(0, before)) else {
        return false;
    };
    let PageScanOutcome::Rows(right) = scan_decoded_page(Page::from_bytes(0, after)) else {
        return false;
    };
    left.iter().any(|a| fragment_has(&a.bytes, old, stable))
        && right.iter().any(|b| fragment_has(&b.bytes, new, stable))
        && left.iter().any(|a| {
            right.iter().any(|b| {
                fragment_has(&a.bytes, old, stable)
                    && fragment_has(&b.bytes, new, stable)
                    && normalize(&a.bytes, old.as_bytes()) == normalize(&b.bytes, new.as_bytes())
            })
        })
}

fn fragment_has(bytes: &[u8], name: &str, stable: &[String]) -> bool {
    !find_all(bytes, name.as_bytes()).is_empty()
        && stable
            .iter()
            .all(|v| !find_all(bytes, v.as_bytes()).is_empty())
}

fn normalize(bytes: &[u8], name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at..].starts_with(name) {
            out.extend_from_slice(b"\x00RENAME\x00");
            at += name.len();
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    out
}

fn find_all(bytes: &[u8], needle: &[u8]) -> Vec<usize> {
    bytes
        .windows(needle.len())
        .enumerate()
        .filter_map(|(i, value)| (value == needle).then_some(i))
        .take(64)
        .collect()
}

fn validate_one(value: &str, label: &str) -> Result<String, String> {
    if value.is_empty() || !value.is_ascii() {
        return Err(format!("{label} must be non-empty ASCII"));
    }
    Ok(value.to_owned())
}
fn validate_stable(values: &[String], old: &str, new: &str) -> Result<Vec<String>, String> {
    if values.is_empty() {
        return Err("at least one stable synthetic literal is required".to_owned());
    }
    let mut set = BTreeSet::new();
    for value in values {
        if value.is_empty()
            || !value.is_ascii()
            || value == old
            || value == new
            || !set.insert(value.clone())
        {
            return Err(
                "stable literals must be distinct non-empty ASCII values different from names"
                    .to_owned(),
            );
        }
    }
    Ok(set.into_iter().collect())
}
fn file_len(path: &Path) -> Result<u64, String> {
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

pub fn to_json(probe: &RenameStructuralProbe) -> String {
    fn evidence(out: &mut String, value: &RepresentationEvidence) {
        let _ = write!(
            out,
            "{{\"inspected_net_changed_pages\":{},\"qualified_before_pages\":{},\"qualified_after_pages\":{},\"exact_normalized_page_pairs\":{},\"exact_normalized_window_pairs\":{},\"slotted_fragment_pairs\":{}}}",
            value.inspected_net_changed_pages,
            value.qualified_before_pages,
            value.qualified_after_pages,
            value.exact_normalized_page_pairs,
            value.exact_normalized_window_pairs,
            value.slotted_fragment_pairs
        );
    }
    let mut out = String::from("{\"schema_version\":\"openqbw.rename-structural-probe.v1\"");
    let _ = write!(
        out,
        ",\"page_size\":{},\"page_count\":{},\"raw_changed_page_count\":{},\"control_noise_subtraction\":{{\"applied\":true,\"subtracted_changed_page_count\":{},\"remaining_changed_page_count\":{}}}",
        PAGE_SIZE,
        probe.page_count,
        probe.raw_changed_page_count,
        probe.control_noise_subtracted_page_count,
        probe.remaining_changed_page_count
    );
    let _ = write!(
        out,
        ",\"synthetic_markers\":{{\"old_name\":{:?},\"new_name\":{:?},\"stable_literals\":{:?}}}",
        probe.old_name, probe.new_name, probe.stable_literals
    );
    out.push_str(",\"raw_storage\":{\"classification\":\"certified_byte_invariant_not_account_decoder\",\"evidence\":");
    evidence(&mut out, &probe.raw);
    out.push('}');
    let _ = write!(
        out,
        ",\"recover_bv_any\":{{\"classification\":\"heuristic_candidate_only_not_plaintext_or_record_certified\",\"both_sides_page_count\":{},\"evidence\":",
        probe.recover_bv_any_both_sides_page_count
    );
    evidence(&mut out, &probe.recover_bv_any_candidate);
    out.push_str("}}");
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_rename_is_bounded_and_does_not_claim_a_record() {
        let mut before = [0u8; PAGE_SIZE];
        let mut after = [0u8; PAGE_SIZE];
        before[PAGE_TYPE_OFFSET] = b'E';
        after[PAGE_TYPE_OFFSET] = b'E';
        let left = b"SAMPLE_ACCOUNT_002|SAMPLE_ASSET_OLD|SAMPLE_ASSET_MARKER";
        let right = b"SAMPLE_ACCOUNT_002|SAMPLE_ASSET_NEW|SAMPLE_ASSET_MARKER";
        before[80..80 + left.len()].copy_from_slice(left);
        after[80..80 + right.len()].copy_from_slice(right);
        let mut evidence = RepresentationEvidence::default();
        inspect_pair(
            &before,
            &after,
            "SAMPLE_ASSET_OLD",
            "SAMPLE_ASSET_NEW",
            &["SAMPLE_ACCOUNT_002".into(), "SAMPLE_ASSET_MARKER".into()],
            &mut evidence,
        );
        assert_eq!(evidence.exact_normalized_window_pairs, 1);
        assert_eq!(evidence.exact_normalized_page_pairs, 1);
        assert_eq!(evidence.slotted_fragment_pairs, 0);
    }
    #[test]
    fn a_non_name_difference_rejects_exact_pairing() {
        let mut before = [0u8; PAGE_SIZE];
        let mut after = [0u8; PAGE_SIZE];
        before[PAGE_TYPE_OFFSET] = b'E';
        after[PAGE_TYPE_OFFSET] = b'E';
        let left = b"SAMPLE_ACCOUNT_002|SAMPLE_ASSET_OLD|SAMPLE_ASSET_MARKER";
        let right = b"SAMPLE_ACCOUNT_002|SAMPLE_ASSET_NEW|SAMPLE_MARKER-changed";
        before[80..80 + left.len()].copy_from_slice(left);
        after[80..80 + right.len()].copy_from_slice(right);
        let mut evidence = RepresentationEvidence::default();
        inspect_pair(
            &before,
            &after,
            "SAMPLE_ASSET_OLD",
            "SAMPLE_ASSET_NEW",
            &["SAMPLE_ACCOUNT_002".into(), "SAMPLE_ASSET_MARKER".into()],
            &mut evidence,
        );
        assert_eq!(evidence.exact_normalized_window_pairs, 0);
    }
}

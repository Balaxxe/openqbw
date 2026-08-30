//! Sentinel-only evidence collection for controlled transaction deltas.
//!
//! This is deliberately a wrapper around the account-delta byte scanner, not
//! a transaction decoder.  A caller assigns stable *synthetic* roles to the
//! supplied markers (for example `line-memo-1=SAMPLE_JE_001_LINE_001`).  Keeping
//! roles separate from literals makes a stage result useful for research while
//! ensuring this command cannot discover arbitrary company text.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;

use crate::account_delta_probe::{
    AccountDeltaProbe, ApAwareAccountDeltaProbe, PAGE_TYPE_OFFSET, decode_ap_page,
    probe_synthetic_delta_ap_aware_with_literal_collision_policy,
    probe_synthetic_delta_with_literal_collision_policy,
};
use crate::batch_extract::StreamingSha256;
use crate::snapshot_compare::{PAGE_SIZE, parse_control_noise_manifest};
use opensqlany::{ApModel, PageStore};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostingMarker {
    pub role: String,
    pub literal: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostingMarkerEvidence {
    pub role: String,
    pub literal: String,
    pub before_occurrences: u64,
    pub after_occurrences: u64,
    pub candidate_page_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostingDeltaProbe {
    pub probe: AccountDeltaProbe,
    pub marker_evidence: Vec<PostingMarkerEvidence>,
}

/// Aggregate-only AP-aware evidence for a controlled posting delta.
///
/// The AP transform is a candidate generator, never a posting decoder.  A
/// result therefore deliberately distinguishes heuristic and model-selected
/// candidate pages and always renders `plaintext_certified=false`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApAwarePostingDeltaProbe {
    pub raw: PostingDeltaProbe,
    pub heuristic_candidate_page_count: u64,
    pub model_candidate_page_count: u64,
    pub candidate_page_count: u64,
    pub marker_evidence: Vec<PostingMarkerEvidence>,
    pub candidate_clusters: Vec<crate::account_delta_probe::CandidateCluster>,
}

/// Aggregate-only evidence for a controlled transaction deletion.  Unlike an
/// insertion probe this explicitly keeps chronological input order: `before`
/// contains the controlled transaction and `after` is the later image from
/// which it was removed.  It is not implemented by swapping a creation probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostingRemovalProbe {
    pub page_count: u64,
    pub raw_changed_page_count: u64,
    pub control_noise_subtracted_page_count: u64,
    pub remaining_changed_page_count: u64,
    pub candidate_page_count: u64,
    pub marker_evidence: Vec<PostingMarkerEvidence>,
    pub candidate_clusters: Vec<RemovalCandidateCluster>,
    pub control_noise_manifest_sha256: String,
}

/// The marker list is deliberately limited to explicit caller-supplied
/// sentinels.  No location, row, surrounding content, or non-sentinel value
/// is retained.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RemovalCandidateCluster {
    pub before_page_type_raw: u8,
    pub after_page_type_raw: u8,
    pub marker_literals: Vec<String>,
    pub page_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApAwarePostingRemovalProbe {
    pub raw: PostingRemovalProbe,
    pub heuristic_candidate_page_count: u64,
    pub model_candidate_page_count: u64,
    pub candidate_page_count: u64,
    pub marker_evidence: Vec<PostingMarkerEvidence>,
    pub candidate_clusters: Vec<RemovalCandidateCluster>,
}

/// Parse one `role=synthetic-ascii-marker` argument.  Roles are identifiers,
/// not free text, so output schemas stay stable and cannot accidentally carry
/// a label copied from a company file.
pub fn parse_marker_argument(argument: &str) -> Result<PostingMarker, String> {
    let (role, literal) = argument
        .split_once('=')
        .ok_or_else(|| "marker must use role=synthetic-ascii-marker".to_owned())?;
    if role.is_empty()
        || !role
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(
            "marker role must be non-empty lowercase ASCII letters, digits, or hyphens".to_owned(),
        );
    }
    if literal.is_empty() || !literal.is_ascii() {
        return Err("marker literal must be non-empty ASCII".to_owned());
    }
    Ok(PostingMarker {
        role: role.to_owned(),
        literal: literal.to_owned(),
    })
}

pub fn probe_posting_delta(
    before_path: &Path,
    after_path: &Path,
    control_noise_manifest: &Path,
    markers: &[PostingMarker],
) -> Result<PostingDeltaProbe, String> {
    validate_markers(markers)?;
    let literal_list: Vec<String> = markers
        .iter()
        .map(|marker| marker.literal.clone())
        .collect();
    let collision_policy = collision_policy(markers);
    let probe = probe_synthetic_delta_with_literal_collision_policy(
        before_path,
        after_path,
        control_noise_manifest,
        &literal_list,
        &collision_policy,
    )?;
    Ok(posting_probe_from_account_probe(probe, markers))
}

/// Run the posting probe after candidate AP recovery.  Only explicit
/// `account` / `account-*` roles may have a preexisting before-image value;
/// document/reference and line-memo markers remain full-before collision
/// checked in both stored and candidate-transformed images.
pub fn probe_posting_delta_ap_aware(
    before_path: &Path,
    after_path: &Path,
    control_noise_manifest: &Path,
    markers: &[PostingMarker],
) -> Result<ApAwarePostingDeltaProbe, String> {
    validate_markers(markers)?;
    let literal_list: Vec<String> = markers
        .iter()
        .map(|marker| marker.literal.clone())
        .collect();
    let collision_policy = collision_policy(markers);
    let probe = probe_synthetic_delta_ap_aware_with_literal_collision_policy(
        before_path,
        after_path,
        control_noise_manifest,
        &literal_list,
        &collision_policy,
    )?;
    Ok(ap_aware_posting_probe_from_account_probe(probe, markers))
}

/// Probe a deletion in chronological order.  Non-account markers must occur
/// in the complete before image and be absent from the complete after image;
/// `account` and `account-*` controls may preexist in both images.  Markers
/// are then counted only on net changed pages after exact control subtraction.
pub fn probe_posting_removal(
    before_path: &Path,
    after_path: &Path,
    control_noise_manifest: &Path,
    markers: &[PostingMarker],
) -> Result<PostingRemovalProbe, String> {
    validate_markers(markers)?;
    probe_posting_removal_raw(
        before_path,
        after_path,
        control_noise_manifest,
        markers,
        true,
    )
}

/// Candidate-only AP counterpart to [`probe_posting_removal`].  The removal
/// contract is checked on complete candidate-decoded images, rather than
/// reversing chronology or interpreting an AP result as plaintext.
pub fn probe_posting_removal_ap_aware(
    before_path: &Path,
    after_path: &Path,
    control_noise_manifest: &Path,
    markers: &[PostingMarker],
) -> Result<ApAwarePostingRemovalProbe, String> {
    // Retain raw structural evidence without requiring stored-byte visibility:
    // this opt-in pass also supports markers visible only after candidate AP
    // recovery, which are checked strictly below on complete images.
    let raw = probe_posting_removal_raw(
        before_path,
        after_path,
        control_noise_manifest,
        markers,
        false,
    )?;
    let literal_bytes = marker_bytes(markers)?;
    let before_store = PageStore::open(before_path)
        .map_err(|_| "could not open before snapshot as page store".to_owned())?;
    let after_store = PageStore::open(after_path)
        .map_err(|_| "could not open after snapshot as page store".to_owned())?;
    if before_store.page_count() != after_store.page_count() {
        return Err("snapshots must have equal byte lengths".to_owned());
    }
    let before_model = ApModel::learn(&before_store);
    let after_model = ApModel::learn(&after_store);
    let mut complete_before = vec![0u64; markers.len()];
    let mut complete_after = vec![0u64; markers.len()];
    for pn in 0..before_store.page_count() {
        let before = before_store
            .page(pn)
            .map_err(|_| "could not read before snapshot page".to_owned())?;
        let after = after_store
            .page(pn)
            .map_err(|_| "could not read after snapshot page".to_owned())?;
        let (before_plain, _) = decode_ap_page(before.bytes(), pn, &before_model, &before_store);
        let (after_plain, _) = decode_ap_page(after.bytes(), pn, &after_model, &after_store);
        for (index, (_, literal)) in literal_bytes.iter().enumerate() {
            complete_before[index] += count_nonoverlapping(&before_plain, literal) as u64;
            complete_after[index] += count_nonoverlapping(&after_plain, literal) as u64;
        }
    }
    assert_removal_presence(
        markers,
        &complete_before,
        &complete_after,
        " after candidate AP decode",
    )?;

    let manifest_bytes = fs::read(control_noise_manifest).map_err(io_error)?;
    let mut control = parse_control_noise_manifest(&manifest_bytes)?;
    let mut remaining_before = vec![0u64; markers.len()];
    let mut candidate_pages = vec![0u64; markers.len()];
    let mut candidate_page_count = 0u64;
    let mut heuristic_candidate_page_count = 0u64;
    let mut model_candidate_page_count = 0u64;
    let mut clusters = BTreeMap::new();
    for pn in 0..before_store.page_count() {
        let before = before_store
            .page(pn)
            .map_err(|_| "could not read before snapshot page".to_owned())?;
        let after = after_store
            .page(pn)
            .map_err(|_| "could not read after snapshot page".to_owned())?;
        if before.bytes() == after.bytes() {
            continue;
        }
        let pair = (sha256_hex(before.bytes()), sha256_hex(after.bytes()));
        if let Some(count) = control.get_mut(&pair)
            && *count != 0
        {
            *count -= 1;
            continue;
        }
        let (plain, heuristic) = decode_ap_page(before.bytes(), pn, &before_model, &before_store);
        if heuristic {
            heuristic_candidate_page_count += 1;
        } else {
            model_candidate_page_count += 1;
        }
        let mut literals = Vec::new();
        for (index, (literal, bytes)) in literal_bytes.iter().enumerate() {
            let count = count_nonoverlapping(&plain, bytes) as u64;
            remaining_before[index] += count;
            if count != 0 {
                candidate_pages[index] += 1;
                literals.push(literal.clone());
            }
        }
        if !literals.is_empty() {
            candidate_page_count += 1;
            *clusters
                .entry((
                    before.bytes()[PAGE_TYPE_OFFSET],
                    after.bytes()[PAGE_TYPE_OFFSET],
                    literals,
                ))
                .or_insert(0) += 1;
        }
    }
    Ok(ApAwarePostingRemovalProbe {
        raw,
        heuristic_candidate_page_count,
        model_candidate_page_count,
        candidate_page_count,
        marker_evidence: markers
            .iter()
            .enumerate()
            .map(|(i, marker)| PostingMarkerEvidence {
                role: marker.role.clone(),
                literal: marker.literal.clone(),
                before_occurrences: complete_before[i],
                after_occurrences: complete_after[i],
                candidate_page_count: candidate_pages[i],
            })
            .collect(),
        candidate_clusters: removal_clusters(clusters),
    })
}

fn probe_posting_removal_raw(
    before_path: &Path,
    after_path: &Path,
    control_noise_manifest: &Path,
    markers: &[PostingMarker],
    enforce_presence: bool,
) -> Result<PostingRemovalProbe, String> {
    let literal_bytes = marker_bytes(markers)?;
    let before_len = regular_file_len(before_path)?;
    if before_len != regular_file_len(after_path)? {
        return Err("snapshots must have equal byte lengths".to_owned());
    }
    if !before_len.is_multiple_of(PAGE_SIZE as u64) {
        return Err("snapshots must be aligned to 4096-byte pages".to_owned());
    }
    let manifest_bytes = fs::read(control_noise_manifest).map_err(io_error)?;
    let mut control = parse_control_noise_manifest(&manifest_bytes)?;
    let manifest_sha = sha256_hex(&manifest_bytes);
    let mut before_reader =
        BufReader::with_capacity(PAGE_SIZE * 16, File::open(before_path).map_err(io_error)?);
    let mut after_reader =
        BufReader::with_capacity(PAGE_SIZE * 16, File::open(after_path).map_err(io_error)?);
    let mut before_page = [0u8; PAGE_SIZE];
    let mut after_page = [0u8; PAGE_SIZE];
    let mut complete_before = vec![0u64; markers.len()];
    let mut complete_after = vec![0u64; markers.len()];
    let mut remaining_before = vec![0u64; markers.len()];
    let mut candidate_pages = vec![0u64; markers.len()];
    let mut raw_changed = 0;
    let mut subtracted = 0;
    let mut remaining = 0;
    let mut clusters = BTreeMap::new();
    for _ in 0..before_len / PAGE_SIZE as u64 {
        before_reader
            .read_exact(&mut before_page)
            .map_err(io_error)?;
        after_reader.read_exact(&mut after_page).map_err(io_error)?;
        for (i, (_, bytes)) in literal_bytes.iter().enumerate() {
            complete_before[i] += count_nonoverlapping(&before_page, bytes) as u64;
            complete_after[i] += count_nonoverlapping(&after_page, bytes) as u64;
        }
        if before_page == after_page {
            continue;
        }
        raw_changed += 1;
        let pair = (sha256_hex(&before_page), sha256_hex(&after_page));
        if let Some(count) = control.get_mut(&pair)
            && *count != 0
        {
            *count -= 1;
            subtracted += 1;
            continue;
        }
        remaining += 1;
        let mut literals = Vec::new();
        for (i, (literal, bytes)) in literal_bytes.iter().enumerate() {
            let count = count_nonoverlapping(&before_page, bytes) as u64;
            remaining_before[i] += count;
            if count != 0 {
                candidate_pages[i] += 1;
                literals.push(literal.clone());
            }
        }
        if !literals.is_empty() {
            *clusters
                .entry((
                    before_page[PAGE_TYPE_OFFSET],
                    after_page[PAGE_TYPE_OFFSET],
                    literals,
                ))
                .or_insert(0) += 1;
        }
    }
    assert_eof(&mut before_reader)?;
    assert_eof(&mut after_reader)?;
    if regular_file_len(before_path)? != before_len || regular_file_len(after_path)? != before_len {
        return Err("snapshot changed during read".to_owned());
    }
    if enforce_presence {
        assert_removal_presence(markers, &complete_before, &complete_after, "")?;
    }
    let candidate_page_count = clusters.values().sum();
    Ok(PostingRemovalProbe {
        page_count: before_len / PAGE_SIZE as u64,
        raw_changed_page_count: raw_changed,
        control_noise_subtracted_page_count: subtracted,
        remaining_changed_page_count: remaining,
        candidate_page_count,
        marker_evidence: markers
            .iter()
            .enumerate()
            .map(|(i, marker)| PostingMarkerEvidence {
                role: marker.role.clone(),
                literal: marker.literal.clone(),
                before_occurrences: complete_before[i],
                after_occurrences: complete_after[i],
                candidate_page_count: candidate_pages[i],
            })
            .collect(),
        candidate_clusters: removal_clusters(clusters),
        control_noise_manifest_sha256: manifest_sha,
    })
}

fn marker_bytes(markers: &[PostingMarker]) -> Result<Vec<(String, Vec<u8>)>, String> {
    validate_markers(markers)?;
    Ok(markers
        .iter()
        .map(|m| (m.literal.clone(), m.literal.as_bytes().to_vec()))
        .collect())
}
fn assert_removal_presence(
    markers: &[PostingMarker],
    before: &[u64],
    after: &[u64],
    suffix: &str,
) -> Result<(), String> {
    for ((marker, before), after) in markers.iter().zip(before).zip(after) {
        if !is_preexisting_account_role(&marker.role) && (*before == 0 || *after != 0) {
            return Err(format!(
                "non-account transaction markers must be present in complete before snapshot and absent from complete after snapshot{suffix}"
            ));
        }
    }
    Ok(())
}
fn removal_clusters(
    clusters: BTreeMap<(u8, u8, Vec<String>), u64>,
) -> Vec<RemovalCandidateCluster> {
    clusters
        .into_iter()
        .map(
            |((before_page_type_raw, after_page_type_raw, marker_literals), page_count)| {
                RemovalCandidateCluster {
                    before_page_type_raw,
                    after_page_type_raw,
                    marker_literals,
                    page_count,
                }
            },
        )
        .collect()
}
fn count_nonoverlapping(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut at = 0;
    while let Some(found) = haystack[at..]
        .windows(needle.len())
        .position(|w| w == needle)
    {
        count += 1;
        at += found + needle.len();
    }
    count
}

#[cfg(test)]
mod nonoverlap_tests {
    use super::count_nonoverlapping;

    #[test]
    fn counts_only_disjoint_matches() {
        assert_eq!(count_nonoverlapping(b"aaaaa", b"aa"), 2);
        assert_eq!(count_nonoverlapping(b"aaaa", b"aa"), 2);
        assert_eq!(count_nonoverlapping(b"abc", b""), 0);
    }
}
fn regular_file_len(path: &Path) -> Result<u64, String> {
    let metadata = fs::metadata(path).map_err(io_error)?;
    if !metadata.is_file() {
        return Err("input is not a regular file".to_owned());
    }
    Ok(metadata.len())
}
fn assert_eof(reader: &mut impl Read) -> Result<(), String> {
    let mut byte = [0u8; 1];
    match reader.read(&mut byte).map_err(io_error)? {
        0 => Ok(()),
        _ => Err("snapshot changed during read".to_owned()),
    }
}
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = StreamingSha256::new();
    hasher.update(bytes);
    hasher.finish_hex()
}
fn io_error(error: std::io::Error) -> String {
    error.kind().to_string()
}

/// Render aggregate-only deletion evidence. `direction` is explicit so this
/// output cannot be mistaken for an insertion probe run with swapped inputs.
pub fn removal_to_json(result: &PostingRemovalProbe) -> String {
    let mut out = String::from(
        "{\"schema_version\":\"openqbw.posting-removal-probe.v1\",\"direction\":\"chronological_removal\"",
    );
    let _ = write!(
        out,
        ",\"page_size\":4096,\"page_count\":{},\"raw_changed_page_count\":{},\"control_noise_subtraction\":{{\"applied\":true,\"manifest_sha256\":\"{}\",\"subtracted_changed_page_count\":{},\"remaining_changed_page_count\":{}}},\"candidate_page_count\":{}",
        result.page_count,
        result.raw_changed_page_count,
        result.control_noise_manifest_sha256,
        result.control_noise_subtracted_page_count,
        result.remaining_changed_page_count,
        result.candidate_page_count
    );
    write_removal_markers(&mut out, &result.marker_evidence);
    write_removal_clusters(&mut out, &result.candidate_clusters);
    out.push('}');
    out
}

pub fn removal_ap_aware_to_json(result: &ApAwarePostingRemovalProbe) -> String {
    let mut out = String::from(
        "{\"schema_version\":\"openqbw.posting-removal-ap-aware-probe.v1\",\"direction\":\"chronological_removal\"",
    );
    let _ = write!(
        out,
        ",\"page_size\":4096,\"raw\":{}",
        removal_to_json(&result.raw)
    );
    let _ = write!(
        out,
        ",\"ap_recovery\":{{\"plaintext_certified\":false,\"result_scope\":\"candidate_only\",\"heuristic_candidate_page_count\":{},\"model_candidate_page_count\":{}}},\"candidate_page_count\":{}",
        result.heuristic_candidate_page_count,
        result.model_candidate_page_count,
        result.candidate_page_count
    );
    write_removal_markers(&mut out, &result.marker_evidence);
    write_removal_clusters(&mut out, &result.candidate_clusters);
    out.push('}');
    out
}

fn write_removal_markers(out: &mut String, evidence: &[PostingMarkerEvidence]) {
    out.push_str(",\"marker_evidence\":[");
    for (i, e) in evidence.iter().enumerate() {
        if i != 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"role\":{},\"literal\":{},\"before_occurrences\":{},\"after_occurrences\":{},\"candidate_page_count\":{}}}",
            json_string(&e.role),
            json_string(&e.literal),
            e.before_occurrences,
            e.after_occurrences,
            e.candidate_page_count
        );
    }
    out.push(']');
}
fn write_removal_clusters(out: &mut String, clusters: &[RemovalCandidateCluster]) {
    out.push_str(",\"candidate_clusters\":[");
    for (i, cluster) in clusters.iter().enumerate() {
        if i != 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"before_page_type_raw\":{},\"after_page_type_raw\":{},\"marker_literals\":[",
            cluster.before_page_type_raw, cluster.after_page_type_raw
        );
        for (j, literal) in cluster.marker_literals.iter().enumerate() {
            if j != 0 {
                out.push(',');
            }
            out.push_str(&json_string(literal));
        }
        let _ = write!(out, "],\"page_count\":{}}}", cluster.page_count);
    }
    out.push(']');
}

fn validate_markers(markers: &[PostingMarker]) -> Result<(), String> {
    if markers.is_empty() {
        return Err("at least one synthetic posting marker is required".to_owned());
    }
    let mut roles = BTreeSet::new();
    let mut literals = BTreeSet::new();
    for marker in markers {
        // Re-parse to keep programmatic callers under the same contract.
        let parsed = parse_marker_argument(&format!("{}={}", marker.role, marker.literal))?;
        if !roles.insert(parsed.role) || !literals.insert(parsed.literal) {
            return Err("posting marker roles and literals must each be distinct".to_owned());
        }
    }
    Ok(())
}

fn collision_policy(markers: &[PostingMarker]) -> Vec<bool> {
    markers
        .iter()
        .map(|marker| !is_preexisting_account_role(&marker.role))
        .collect()
}

fn is_preexisting_account_role(role: &str) -> bool {
    role == "account" || role.starts_with("account-")
}

fn posting_probe_from_account_probe(
    probe: AccountDeltaProbe,
    markers: &[PostingMarker],
) -> PostingDeltaProbe {
    let evidence_by_literal: BTreeMap<_, _> = probe
        .literals
        .iter()
        .map(|evidence| (evidence.literal.as_str(), evidence))
        .collect();
    let marker_evidence = markers
        .iter()
        .map(|marker| {
            let evidence = evidence_by_literal[marker.literal.as_str()];
            PostingMarkerEvidence {
                role: marker.role.clone(),
                literal: marker.literal.clone(),
                before_occurrences: evidence.before_occurrences,
                after_occurrences: evidence.after_occurrences,
                candidate_page_count: evidence.candidate_page_count,
            }
        })
        .collect();
    PostingDeltaProbe {
        probe,
        marker_evidence,
    }
}

fn ap_aware_posting_probe_from_account_probe(
    probe: ApAwareAccountDeltaProbe,
    markers: &[PostingMarker],
) -> ApAwarePostingDeltaProbe {
    let raw = posting_probe_from_account_probe(probe.raw, markers);
    let evidence_by_literal: BTreeMap<_, _> = probe
        .literals
        .iter()
        .map(|evidence| (evidence.literal.as_str(), evidence))
        .collect();
    let marker_evidence = markers
        .iter()
        .map(|marker| {
            let evidence = evidence_by_literal[marker.literal.as_str()];
            PostingMarkerEvidence {
                role: marker.role.clone(),
                literal: marker.literal.clone(),
                before_occurrences: evidence.before_occurrences,
                after_occurrences: evidence.after_occurrences,
                candidate_page_count: evidence.candidate_page_count,
            }
        })
        .collect();
    ApAwarePostingDeltaProbe {
        raw,
        heuristic_candidate_page_count: probe.heuristic_candidate_page_count,
        model_candidate_page_count: probe.model_candidate_page_count,
        candidate_page_count: probe.candidate_page_count,
        marker_evidence,
        candidate_clusters: probe.candidate_clusters,
    }
}

/// JSON intentionally contains only caller-supplied synthetic markers and
/// aggregate structural evidence.  It contains no QBW path, page location,
/// page hash, surrounding byte, decoded value, or inferred transaction field.
pub fn to_json(result: &PostingDeltaProbe) -> String {
    let probe = &result.probe;
    let mut out = String::from("{\"schema_version\":\"openqbw.posting-delta-probe.v1\"");
    let _ = write!(
        out,
        ",\"page_size\":4096,\"page_count\":{},\"raw_changed_page_count\":{},\"control_noise_subtraction\":{{\"applied\":true,\"manifest_sha256\":\"{}\",\"subtracted_changed_page_count\":{},\"remaining_changed_page_count\":{}}},\"candidate_page_count\":{}",
        probe.page_count,
        probe.raw_changed_page_count,
        probe.control_noise_manifest_sha256,
        probe.control_noise_subtracted_page_count,
        probe.remaining_changed_page_count,
        probe.candidate_page_count,
    );
    out.push_str(",\"marker_evidence\":[");
    for (index, evidence) in result.marker_evidence.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"role\":{},\"literal\":{},\"before_occurrences\":{},\"after_occurrences\":{},\"candidate_page_count\":{}}}",
            json_string(&evidence.role),
            json_string(&evidence.literal),
            evidence.before_occurrences,
            evidence.after_occurrences,
            evidence.candidate_page_count
        );
    }
    out.push_str("],\"candidate_clusters\":[");
    for (index, cluster) in probe.candidate_clusters.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"before_page_type_raw\":{},\"after_page_type_raw\":{},\"after_literals\":[",
            cluster.before_page_type_raw, cluster.after_page_type_raw
        );
        for (literal_index, literal) in cluster.after_literals.iter().enumerate() {
            if literal_index != 0 {
                out.push(',');
            }
            out.push_str(&json_string(literal));
        }
        let _ = write!(out, "],\"page_count\":{}}}", cluster.page_count);
    }
    out.push_str("]}");
    out
}

/// Render AP-aware posting evidence without paths, page positions, raw bytes,
/// decoded non-sentinel content, IDs, dates, or amounts.  This is explicitly
/// candidate-only evidence rather than a plaintext or posting certificate.
pub fn ap_aware_to_json(result: &ApAwarePostingDeltaProbe) -> String {
    let mut out = String::from("{\"schema_version\":\"openqbw.posting-delta-ap-aware-probe.v1\"");
    let _ = write!(out, ",\"page_size\":4096,\"raw\":{}", to_json(&result.raw));
    let _ = write!(
        out,
        ",\"ap_recovery\":{{\"plaintext_certified\":false,\"result_scope\":\"candidate_only\",\"heuristic_candidate_page_count\":{},\"model_candidate_page_count\":{}}},\"candidate_page_count\":{}",
        result.heuristic_candidate_page_count,
        result.model_candidate_page_count,
        result.candidate_page_count,
    );
    out.push_str(",\"marker_evidence\":[");
    for (index, evidence) in result.marker_evidence.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"role\":{},\"literal\":{},\"before_occurrences\":{},\"after_occurrences\":{},\"candidate_page_count\":{}}}",
            json_string(&evidence.role),
            json_string(&evidence.literal),
            evidence.before_occurrences,
            evidence.after_occurrences,
            evidence.candidate_page_count
        );
    }
    out.push_str("],\"candidate_clusters\":[");
    for (index, cluster) in result.candidate_clusters.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"before_page_type_raw\":{},\"after_page_type_raw\":{},\"after_literals\":[",
            cluster.before_page_type_raw, cluster.after_page_type_raw
        );
        for (literal_index, literal) in cluster.after_literals.iter().enumerate() {
            if literal_index != 0 {
                out.push(',');
            }
            out.push_str(&json_string(literal));
        }
        let _ = write!(out, "],\"page_count\":{}}}", cluster.page_count);
    }
    out.push_str("]}");
    out
}

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for character in value.chars() {
        match character {
            '\"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if character < ' ' => {
                let _ = write!(out, "\\u{:04x}", character as u32);
            }
            character => out.push(character),
        }
    }
    out.push('\"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use crate::snapshot_compare::{PAGE_SIZE, compare_snapshots, to_json as comparison_json};

    fn ap_page(pn: u64, bv: u8, page_type: u8, literals: &[&[u8]]) -> [u8; PAGE_SIZE] {
        let mut plain = [0u8; PAGE_SIZE];
        let mut cursor = 64;
        for literal in literals {
            plain[cursor..cursor + literal.len()].copy_from_slice(literal);
            cursor += literal.len() + 8;
        }
        let mut raw = [0u8; PAGE_SIZE];
        let bias = (pn % 16) as u8 / 2 * 4;
        for sector in 0..8usize {
            let start = sector * 512;
            let end = if sector == 7 { 0xff0 } else { start + 512 };
            let base = bv
                .wrapping_add(pn as u8)
                .wrapping_add(sector as u8)
                .wrapping_sub(bias);
            for offset in start..end {
                raw[offset] = plain[offset].wrapping_add(base);
            }
        }
        raw[0xff2] = page_type;
        raw
    }

    #[test]
    fn marker_contract_accepts_all_four_je_line_memos_and_rejects_invalid_shapes() {
        for line in 1..=4 {
            let argument = format!("line-memo-{line}=SAMPLE_MARKER-JE1-L{line}");
            assert_eq!(
                parse_marker_argument(&argument).unwrap().role,
                format!("line-memo-{line}")
            );
        }
        assert!(parse_marker_argument("Header=SAMPLE_MARKER").is_err());
        assert!(parse_marker_argument("header=é").is_err());
        assert!(parse_marker_argument("no-separator").is_err());
    }

    #[test]
    fn output_has_no_decoder_claim_or_location() {
        let result = PostingDeltaProbe {
            probe: AccountDeltaProbe {
                page_count: 3,
                raw_changed_page_count: 2,
                control_noise_subtracted_page_count: 1,
                remaining_changed_page_count: 1,
                candidate_page_count: 1,
                literals: vec![],
                candidate_clusters: vec![],
                control_noise_manifest_sha256: "a".repeat(64),
            },
            marker_evidence: vec![PostingMarkerEvidence {
                role: "line-memo-1".into(),
                literal: "SAMPLE_JE_001_LINE_001".into(),
                before_occurrences: 0,
                after_occurrences: 1,
                candidate_page_count: 1,
            }],
        };
        let json = to_json(&result);
        assert!(json.contains("line-memo-1"));
        assert!(!json.contains("page_number"));
        assert!(!json.contains("offset"));
        assert!(!json.contains("decoded"));
    }

    #[test]
    fn permits_preexisting_synthetic_account_marker_but_reports_its_before_count() {
        let stem =
            std::env::temp_dir().join(format!("openqbw-posting-delta-{}", std::process::id()));
        let before = stem.with_extension("before.qbw");
        let after = stem.with_extension("after.qbw");
        let control_before = stem.with_extension("control-before.qbw");
        let control_after = stem.with_extension("control-after.qbw");
        let manifest = stem.with_extension("control.json");
        let mut old = [0u8; PAGE_SIZE];
        let account = b"SAMPLE_EXPENSE_ACCOUNT";
        old[16..16 + account.len()].copy_from_slice(account);
        let mut new = old;
        let line_memo = b"SAMPLE_JE_001_LINE_001";
        new[64..64 + line_memo.len()].copy_from_slice(line_memo);
        fs::write(&before, old).unwrap();
        fs::write(&after, new).unwrap();
        fs::write(&control_before, old).unwrap();
        fs::write(&control_after, old).unwrap();
        let control = compare_snapshots(&control_before, &control_after, None).unwrap();
        fs::write(&manifest, comparison_json(&control, None, None)).unwrap();
        let result = probe_posting_delta(
            &before,
            &after,
            &manifest,
            &[
                parse_marker_argument("account=SAMPLE_EXPENSE_ACCOUNT").unwrap(),
                parse_marker_argument("line-memo-1=SAMPLE_JE_001_LINE_001").unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(result.marker_evidence[0].before_occurrences, 1);
        assert_eq!(result.marker_evidence[0].after_occurrences, 1);
        assert_eq!(result.marker_evidence[1].after_occurrences, 1);
        for path in [&before, &after, &control_before, &control_after, &manifest] {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn rejects_preexisting_transaction_marker_while_allowing_account_marker() {
        let stem =
            std::env::temp_dir().join(format!("openqbw-posting-collision-{}", std::process::id()));
        let before = stem.with_extension("before.qbw");
        let after = stem.with_extension("after.qbw");
        let manifest = stem.with_extension("control.json");
        let mut old = [0u8; PAGE_SIZE];
        let account = b"SAMPLE_BANK_ACCOUNT";
        let line_memo = b"SAMPLE_JE_001_LINE_001";
        old[16..16 + account.len()].copy_from_slice(account);
        old[64..64 + line_memo.len()].copy_from_slice(line_memo);
        let mut new = old;
        new[128] = 1;
        fs::write(&before, old).unwrap();
        fs::write(&after, new).unwrap();
        fs::write(&manifest, br#"{"raw_page_hash_transitions":[]}"#).unwrap();
        let result = probe_posting_delta(
            &before,
            &after,
            &manifest,
            &[
                parse_marker_argument("account-bank=SAMPLE_BANK_ACCOUNT").unwrap(),
                parse_marker_argument("line-memo-1=SAMPLE_JE_001_LINE_001").unwrap(),
            ],
        );
        assert_eq!(
            result,
            Err("synthetic literals must be absent from the complete before snapshot".into())
        );
        for path in [&before, &after, &manifest] {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn removal_mode_keeps_chronology_and_requires_transaction_absence_after() {
        let stem =
            std::env::temp_dir().join(format!("openqbw-posting-removal-{}", std::process::id()));
        let before = stem.with_extension("before.qbw");
        let after = stem.with_extension("after.qbw");
        let manifest = stem.with_extension("control.json");
        let mut old = [0u8; PAGE_SIZE];
        let account = b"SAMPLE_BANK_ACCOUNT";
        let line_memo = b"SAMPLE_JE_001_LINE_001";
        old[16..16 + account.len()].copy_from_slice(account);
        old[64..64 + line_memo.len()].copy_from_slice(line_memo);
        let mut new = old;
        new[64..64 + line_memo.len()].fill(0);
        fs::write(&before, old).unwrap();
        fs::write(&after, new).unwrap();
        fs::write(&manifest, br#"{"raw_page_hash_transitions":[]}"#).unwrap();
        let markers = [
            parse_marker_argument("account-bank=SAMPLE_BANK_ACCOUNT").unwrap(),
            parse_marker_argument("line-memo-1=SAMPLE_JE_001_LINE_001").unwrap(),
        ];
        let result = probe_posting_removal(&before, &after, &manifest, &markers).unwrap();
        assert_eq!(result.marker_evidence[0].before_occurrences, 1);
        assert_eq!(result.marker_evidence[0].after_occurrences, 1);
        assert_eq!(result.marker_evidence[1].before_occurrences, 1);
        assert_eq!(result.marker_evidence[1].after_occurrences, 0);
        assert_eq!(result.candidate_page_count, 1);
        let json = removal_to_json(&result);
        assert!(json.contains("chronological_removal"));
        assert!(!json.contains("page_number"));
        assert!(!json.contains("offset"));
        assert!(!json.contains(before.to_string_lossy().as_ref()));
        fs::write(&after, old).unwrap();
        assert!(probe_posting_removal(&before, &after, &manifest, &markers).is_err());
        for path in [&before, &after, &manifest] {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn ap_removal_accepts_candidate_only_before_marker_but_not_after_marker() {
        let stem =
            std::env::temp_dir().join(format!("openqbw-posting-removal-ap-{}", std::process::id()));
        let before = stem.with_extension("before.qbw");
        let after = stem.with_extension("after.qbw");
        let manifest = stem.with_extension("control.json");
        let pure = ap_page(0, 41, b'@', &[]);
        let old = ap_page(
            1,
            41,
            b'E',
            &[b"SAMPLE_BANK_ACCOUNT", b"SAMPLE_JE_001_LINE_001"],
        );
        let new = ap_page(1, 41, b'E', &[b"SAMPLE_BANK_ACCOUNT"]);
        fs::write(&before, [pure, old].concat()).unwrap();
        fs::write(&after, [pure, new].concat()).unwrap();
        fs::write(&manifest, br#"{"raw_page_hash_transitions":[]}"#).unwrap();
        let markers = [
            parse_marker_argument("account-bank=SAMPLE_BANK_ACCOUNT").unwrap(),
            parse_marker_argument("line-memo-1=SAMPLE_JE_001_LINE_001").unwrap(),
        ];
        let result = probe_posting_removal_ap_aware(&before, &after, &manifest, &markers).unwrap();
        assert_eq!(result.marker_evidence[1].before_occurrences, 1);
        assert_eq!(result.marker_evidence[1].after_occurrences, 0);
        let json = removal_ap_aware_to_json(&result);
        assert!(json.contains("candidate_only"));
        assert!(!json.contains("page_number"));
        fs::write(&after, [pure, old].concat()).unwrap();
        assert!(probe_posting_removal_ap_aware(&before, &after, &manifest, &markers).is_err());
        for path in [&before, &after, &manifest] {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn ap_aware_mode_preserves_per_marker_collision_policy_and_labels_candidates() {
        let stem = std::env::temp_dir().join(format!("openqbw-posting-ap-{}", std::process::id()));
        let before = stem.with_extension("before.qbw");
        let after = stem.with_extension("after.qbw");
        let manifest = stem.with_extension("control.json");
        let pure = ap_page(0, 41, b'@', &[]);
        let old = ap_page(1, 41, b'E', &[b"SAMPLE_BANK_ACCOUNT"]);
        let new = ap_page(
            1,
            41,
            b'E',
            &[b"SAMPLE_BANK_ACCOUNT", b"SAMPLE_JE_001_LINE_001"],
        );
        fs::write(&before, [pure, old].concat()).unwrap();
        fs::write(&after, [pure, new].concat()).unwrap();
        fs::write(&manifest, br#"{"raw_page_hash_transitions":[]}"#).unwrap();
        let probe = probe_posting_delta_ap_aware(
            &before,
            &after,
            &manifest,
            &[
                parse_marker_argument("account-bank=SAMPLE_BANK_ACCOUNT").unwrap(),
                parse_marker_argument("line-memo-1=SAMPLE_JE_001_LINE_001").unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(probe.marker_evidence[0].before_occurrences, 1);
        assert_eq!(probe.marker_evidence[1].before_occurrences, 0);
        assert_eq!(probe.marker_evidence[1].after_occurrences, 1);
        let json = ap_aware_to_json(&probe);
        assert!(json.contains("\"plaintext_certified\":false"));
        assert!(json.contains("\"result_scope\":\"candidate_only\""));
        assert!(json.contains("\"heuristic_candidate_page_count\":"));
        assert!(json.contains("\"model_candidate_page_count\":"));
        assert!(!json.contains("page_number"));
        assert!(!json.contains("offset"));
        assert!(!json.contains(before.to_string_lossy().as_ref()));
        for path in [&before, &after, &manifest] {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn ap_aware_mode_rejects_a_preexisting_transaction_marker_after_transform() {
        let stem = std::env::temp_dir().join(format!(
            "openqbw-posting-ap-collision-{}",
            std::process::id()
        ));
        let before = stem.with_extension("before.qbw");
        let after = stem.with_extension("after.qbw");
        let manifest = stem.with_extension("control.json");
        let pure = ap_page(0, 41, b'@', &[]);
        let signal = ap_page(
            1,
            41,
            b'E',
            &[b"SAMPLE_BANK_ACCOUNT", b"SAMPLE_JE_001_LINE_001"],
        );
        fs::write(&before, [pure, signal].concat()).unwrap();
        fs::write(&after, [pure, signal].concat()).unwrap();
        fs::write(&manifest, br#"{"raw_page_hash_transitions":[]}"#).unwrap();
        let result = probe_posting_delta_ap_aware(
            &before,
            &after,
            &manifest,
            &[
                parse_marker_argument("account-bank=SAMPLE_BANK_ACCOUNT").unwrap(),
                parse_marker_argument("line-memo-1=SAMPLE_JE_001_LINE_001").unwrap(),
            ],
        );
        assert_eq!(
            result,
            Err(
                "synthetic literals must be absent from complete before snapshot after candidate AP decode"
                    .into()
            )
        );
        for path in [&before, &after, &manifest] {
            let _ = fs::remove_file(path);
        }
    }
}

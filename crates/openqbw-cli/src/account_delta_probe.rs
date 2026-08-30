//! Aggregate, sentinel-only probe for account-creation controlled deltas.
//!
//! This intentionally is not a row decoder.  It streams two page-aligned
//! copies, first proves every caller-supplied sentinel is absent from the
//! complete before snapshot, subtracts the no-edit control by *exact*
//! before/after page-hash pair, and scans only caller-supplied synthetic
//! literals on the remaining pages.  It never emits page numbers, offsets, paths, page contents, or
//! contextual bytes.  The output therefore establishes a bounded candidate
//! set for subsequent decoder research without becoming a data-exfiltration
//! utility for ordinary company files.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;

use crate::batch_extract::StreamingSha256;
use crate::snapshot_compare::{PAGE_SIZE, parse_control_noise_manifest};
use openqbw::{deobfuscate_with_bv, recover_bv_any};
use opensqlany::{ApModel, PageStore};

pub(crate) const PAGE_TYPE_OFFSET: usize = 0xff2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiteralEvidence {
    pub literal: String,
    pub before_occurrences: u64,
    pub after_occurrences: u64,
    pub candidate_page_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CandidateCluster {
    pub before_page_type_raw: u8,
    pub after_page_type_raw: u8,
    /// Sorted caller-supplied literals that occur in the after page.  No
    /// non-sentinel bytes are surfaced.
    pub after_literals: Vec<String>,
    pub page_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountDeltaProbe {
    pub page_count: u64,
    pub raw_changed_page_count: u64,
    pub control_noise_subtracted_page_count: u64,
    pub remaining_changed_page_count: u64,
    pub candidate_page_count: u64,
    pub literals: Vec<LiteralEvidence>,
    pub candidate_clusters: Vec<CandidateCluster>,
    pub control_noise_manifest_sha256: String,
}

/// Aggregate-only evidence from the opt-in AP-aware pass.
///
/// This is not an account decoder and is deliberately **not** a plaintext
/// certificate.  Both AP paths select candidate keystream parameters from
/// page-local structural/statistical signals.  A later sentinel hit makes a
/// changed page worth further controlled-delta investigation, but does not
/// prove that the selected parameters, every decoded byte, or any accounting
/// field is correct.  In particular, the supplied literal is never used to
/// choose an AP candidate, so a hit is not literal-crib-tuned; nevertheless,
/// it remains a candidate rather than a certified plaintext result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApAwareAccountDeltaProbe {
    pub raw: AccountDeltaProbe,
    /// Pages decoded using `recover_bv_any`.  This name intentionally avoids
    /// calling the result "exact": its C.36, zero-density, and brute-force
    /// branches are recovery heuristics, not a record-level authentication.
    pub heuristic_candidate_page_count: u64,
    /// Pages decoded by the `ApModel` statistical fallback.  This is likewise
    /// candidate-only and is kept separate for aggregate research diagnostics.
    pub model_candidate_page_count: u64,
    pub candidate_page_count: u64,
    pub literals: Vec<LiteralEvidence>,
    /// Aggregate co-occurrence on AP-decoded net changed pages. This proves
    /// only candidate locality, never record boundaries or field identity.
    pub candidate_clusters: Vec<CandidateCluster>,
}

/// Stream a controlled delta.  `literals` must be a non-empty collection of
/// distinct non-empty ASCII synthetic markers, and each must be absent from
/// the entire before snapshot. Rejecting arbitrary Unicode avoids ambiguous
/// byte encodings and makes the test reproducible. The latter condition is a
/// hard precondition: otherwise a hit can be an existing company value rather
/// than evidence produced by this one controlled edit.
pub fn probe_account_delta(
    before_path: &Path,
    after_path: &Path,
    control_noise_manifest: &Path,
    literals: &[String],
) -> Result<AccountDeltaProbe, String> {
    probe_account_delta_with_collision_policy(
        before_path,
        after_path,
        control_noise_manifest,
        literals,
        true,
    )
}

/// Version of [`probe_account_delta`] for a controlled mutation of an already
/// existing synthetic account, such as a rename.  This is intentionally
/// opt-in: ordinary creation probes must keep the stricter absence guard.
/// The caller is still responsible for supplying only approved synthetic
/// markers; this function remains aggregate-only and is not a general text
/// search facility.
pub fn probe_account_delta_allow_existing(
    before_path: &Path,
    after_path: &Path,
    control_noise_manifest: &Path,
    literals: &[String],
) -> Result<AccountDeltaProbe, String> {
    probe_account_delta_with_collision_policy(
        before_path,
        after_path,
        control_noise_manifest,
        literals,
        false,
    )
}

fn probe_account_delta_with_collision_policy(
    before_path: &Path,
    after_path: &Path,
    control_noise_manifest: &Path,
    literals: &[String],
    require_absent_before: bool,
) -> Result<AccountDeltaProbe, String> {
    probe_synthetic_delta(
        before_path,
        after_path,
        control_noise_manifest,
        literals,
        require_absent_before,
    )
}

/// Perform the raw probe and an explicitly requested AP-aware confirmation.
///
/// The default CLI path deliberately does not invoke this function. Each
/// snapshot gets its own learned [`ApModel`].  `recover_bv_any` is tried
/// first, followed by the model fallback. Neither is a plaintext
/// certification, and all output remains aggregate-only candidate evidence.
pub fn probe_account_delta_ap_aware(
    before_path: &Path,
    after_path: &Path,
    control_noise_manifest: &Path,
    literals: &[String],
) -> Result<ApAwareAccountDeltaProbe, String> {
    probe_account_delta_ap_aware_with_collision_policy(
        before_path,
        after_path,
        control_noise_manifest,
        literals,
        true,
    )
}

/// AP-aware counterpart to [`probe_account_delta_allow_existing`].  A model
/// fallback is useful candidate evidence only; callers must not treat it as a
/// decoder or record-identity proof.
pub fn probe_account_delta_ap_aware_allow_existing(
    before_path: &Path,
    after_path: &Path,
    control_noise_manifest: &Path,
    literals: &[String],
) -> Result<ApAwareAccountDeltaProbe, String> {
    probe_account_delta_ap_aware_with_collision_policy(
        before_path,
        after_path,
        control_noise_manifest,
        literals,
        false,
    )
}

fn probe_account_delta_ap_aware_with_collision_policy(
    before_path: &Path,
    after_path: &Path,
    control_noise_manifest: &Path,
    literals: &[String],
    require_absent_before: bool,
) -> Result<ApAwareAccountDeltaProbe, String> {
    let collision_policy = vec![require_absent_before; literals.len()];
    probe_synthetic_delta_ap_aware_with_literal_collision_policy(
        before_path,
        after_path,
        control_noise_manifest,
        literals,
        &collision_policy,
    )
}

/// AP-aware controlled-delta implementation with a per-literal collision
/// policy.  This supports a posting-stage probe which must allow references
/// to already-created synthetic accounts while still rejecting pre-existing
/// transaction markers.  It is crate-private to keep the public account
/// probe contract simple.
pub(crate) fn probe_synthetic_delta_ap_aware_with_literal_collision_policy(
    before_path: &Path,
    after_path: &Path,
    control_noise_manifest: &Path,
    literals: &[String],
    require_absent_before: &[bool],
) -> Result<ApAwareAccountDeltaProbe, String> {
    if literals.len() != require_absent_before.len() {
        return Err("literal collision policy must match literal count".to_owned());
    }
    let raw = probe_synthetic_delta_with_literal_collision_policy(
        before_path,
        after_path,
        control_noise_manifest,
        literals,
        require_absent_before,
    )?;
    let literal_bytes = validate_literals(literals)?;
    let before_store = PageStore::open(before_path)
        .map_err(|_| "could not open before snapshot as page store".to_owned())?;
    let after_store = PageStore::open(after_path)
        .map_err(|_| "could not open after snapshot as page store".to_owned())?;
    if before_store.page_count() != after_store.page_count() {
        return Err("snapshots must have equal byte lengths".to_owned());
    }
    let after_model = ApModel::learn(&after_store);
    // The raw probe proves that no literal occurs untransformed in the full
    // before snapshot. That is insufficient for the AP mode: an existing
    // plaintext marker may be obfuscated in the stored bytes. Scan the full
    // before image using the *same candidate transform* and fail closed on a
    // hit. This is intentionally more work than the raw probe, but AP-aware
    // mode is opt-in controlled-delta research and must not represent an
    // already-present encrypted sentinel as a new candidate.
    let before_model = ApModel::learn(&before_store);
    let mut before_candidate_occurrences = vec![0u64; literals.len()];
    for pn in 0..before_store.page_count() {
        let before = before_store
            .page(pn)
            .map_err(|_| "could not read before snapshot page".to_owned())?;
        let (plain, _) = decode_ap_page(before.bytes(), pn, &before_model, &before_store);
        for (index, (_, literal)) in literal_bytes.iter().enumerate() {
            before_candidate_occurrences[index] += count_nonoverlapping(&plain, literal) as u64;
        }
    }
    // A rename intentionally contains old synthetic markers in its before
    // image. Preserve the stronger AP collision guard for account creation,
    // while the explicit allow-existing mode reports its bounded evidence
    // without misclassifying that known precondition as an error.
    if before_candidate_occurrences
        .iter()
        .zip(require_absent_before)
        .any(|(count, required)| *required && *count != 0)
    {
        return Err(
            "synthetic literals must be absent from complete before snapshot after candidate AP decode"
                .to_owned(),
        );
    }

    let manifest_bytes = fs::read(control_noise_manifest).map_err(io_error)?;
    let mut control = parse_control_noise_manifest(&manifest_bytes)?;
    let mut after_occurrences = vec![0u64; literals.len()];
    let mut candidate_page_counts = vec![0u64; literals.len()];
    let mut candidate_page_count = 0u64;
    let mut heuristic_candidate_page_count = 0u64;
    let mut model_candidate_page_count = 0u64;
    let mut clusters: BTreeMap<(u8, u8, Vec<String>), u64> = BTreeMap::new();
    for pn in 0..after_store.page_count() {
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
        let (plain, used_heuristic_candidate) =
            decode_ap_page(after.bytes(), pn, &after_model, &after_store);
        if used_heuristic_candidate {
            heuristic_candidate_page_count += 1;
        } else {
            model_candidate_page_count += 1;
        }
        let mut page_has_literal = false;
        let mut after_literals = Vec::new();
        for (index, (_, literal)) in literal_bytes.iter().enumerate() {
            let count = count_nonoverlapping(&plain, literal) as u64;
            after_occurrences[index] += count;
            if count != 0 {
                candidate_page_counts[index] += 1;
                page_has_literal = true;
                after_literals.push(literals[index].clone());
            }
        }
        if page_has_literal {
            candidate_page_count += 1;
            *clusters
                .entry((
                    before.bytes()[PAGE_TYPE_OFFSET],
                    after.bytes()[PAGE_TYPE_OFFSET],
                    after_literals,
                ))
                .or_insert(0) += 1;
        }
    }
    Ok(ApAwareAccountDeltaProbe {
        raw,
        heuristic_candidate_page_count,
        model_candidate_page_count,
        candidate_page_count,
        literals: literals
            .iter()
            .enumerate()
            .map(|(index, literal)| LiteralEvidence {
                literal: literal.clone(),
                before_occurrences: before_candidate_occurrences[index],
                after_occurrences: after_occurrences[index],
                candidate_page_count: candidate_page_counts[index],
            })
            .collect(),
        candidate_clusters: clusters
            .into_iter()
            .map(
                |((before_page_type_raw, after_page_type_raw, after_literals), page_count)| {
                    CandidateCluster {
                        before_page_type_raw,
                        after_page_type_raw,
                        after_literals,
                        page_count,
                    }
                },
            )
            .collect(),
    })
}

/// Produce a candidate AP decode.  The boolean reports that the
/// `recover_bv_any` heuristic supplied the candidate; it does not mean the
/// result is exact or plaintext-certified.
pub(crate) fn decode_ap_page(
    raw: &[u8],
    pn: u64,
    model: &ApModel,
    store: &PageStore,
) -> (Vec<u8>, bool) {
    if let Some(bv) = recover_bv_any(pn, raw) {
        (deobfuscate_with_bv(raw, pn, bv), true)
    } else {
        (model.deobfuscate_with_store(raw, pn, store), false)
    }
}

/// Shared streaming implementation for controlled synthetic deltas.  Account
/// creation requires every marker to be new; posting stages may additionally
/// cite a previously created synthetic account marker so the caller can study
/// whether it co-occurs with a new transaction marker.  The latter mode is
/// evidence-only and must never be used to claim the existing marker itself
/// was written by the current edit.
pub(crate) fn probe_synthetic_delta(
    before_path: &Path,
    after_path: &Path,
    control_noise_manifest: &Path,
    literals: &[String],
    require_absent_before: bool,
) -> Result<AccountDeltaProbe, String> {
    let collision_policy = vec![require_absent_before; literals.len()];
    probe_synthetic_delta_with_literal_collision_policy(
        before_path,
        after_path,
        control_noise_manifest,
        literals,
        &collision_policy,
    )
}

/// Shared streaming implementation with a per-literal before-snapshot
/// collision policy.  `true` means the synthetic marker must be completely
/// absent before the controlled edit; `false` is reserved for a stable,
/// already-created synthetic reference (such as an account name mentioned by
/// a new transaction).  It never relaxes checks for the other markers.
pub(crate) fn probe_synthetic_delta_with_literal_collision_policy(
    before_path: &Path,
    after_path: &Path,
    control_noise_manifest: &Path,
    literals: &[String],
    require_absent_before: &[bool],
) -> Result<AccountDeltaProbe, String> {
    if literals.len() != require_absent_before.len() {
        return Err("literal collision policy must match literal count".to_owned());
    }
    let literal_bytes = validate_literals(literals)?;
    let before_start = regular_file_len(before_path)?;
    let after_start = regular_file_len(after_path)?;
    if before_start != after_start {
        return Err("snapshots must have equal byte lengths".to_owned());
    }
    if !before_start.is_multiple_of(PAGE_SIZE as u64) {
        return Err("snapshots must be aligned to 4096-byte pages".to_owned());
    }
    let manifest_bytes = fs::read(control_noise_manifest).map_err(io_error)?;
    let mut control = parse_control_noise_manifest(&manifest_bytes)?;
    let control_noise_manifest_sha256 = sha256_hex(&manifest_bytes);

    let before_file = File::open(before_path).map_err(io_error)?;
    let after_file = File::open(after_path).map_err(io_error)?;
    let mut before_reader = BufReader::with_capacity(PAGE_SIZE * 16, before_file);
    let mut after_reader = BufReader::with_capacity(PAGE_SIZE * 16, after_file);
    let mut before_page = [0u8; PAGE_SIZE];
    let mut after_page = [0u8; PAGE_SIZE];
    let mut raw_changed_page_count = 0u64;
    let mut control_noise_subtracted_page_count = 0u64;
    let mut remaining_changed_page_count = 0u64;
    let mut before_occurrences = vec![0u64; literals.len()];
    let mut after_occurrences = vec![0u64; literals.len()];
    let mut candidate_page_counts = vec![0u64; literals.len()];
    let mut clusters: BTreeMap<(u8, u8, Vec<String>), u64> = BTreeMap::new();

    for _ in 0..(before_start / PAGE_SIZE as u64) {
        before_reader
            .read_exact(&mut before_page)
            .map_err(io_error)?;
        after_reader.read_exact(&mut after_page).map_err(io_error)?;
        // Count the before image before the equality/control tests.  An
        // unchanged occurrence is still a fatal collision with the claimed
        // synthetic sentinel, and therefore must not be hidden by the fast
        // path below.
        for (index, (_, needle)) in literal_bytes.iter().enumerate() {
            before_occurrences[index] += count_nonoverlapping(&before_page, needle) as u64;
        }
        if before_page == after_page {
            continue;
        }
        raw_changed_page_count += 1;
        let pair = (sha256_hex(&before_page), sha256_hex(&after_page));
        if let Some(count) = control.get_mut(&pair)
            && *count != 0
        {
            *count -= 1;
            control_noise_subtracted_page_count += 1;
            continue;
        }
        remaining_changed_page_count += 1;
        let mut after_literals = Vec::new();
        for (index, (literal, needle)) in literal_bytes.iter().enumerate() {
            let after_count = count_nonoverlapping(&after_page, needle) as u64;
            after_occurrences[index] += after_count;
            if after_count != 0 {
                candidate_page_counts[index] += 1;
                after_literals.push(literal.clone());
            }
        }
        if !after_literals.is_empty() {
            *clusters
                .entry((
                    before_page[PAGE_TYPE_OFFSET],
                    after_page[PAGE_TYPE_OFFSET],
                    after_literals,
                ))
                .or_insert(0) += 1;
        }
    }
    assert_eof(&mut before_reader)?;
    assert_eof(&mut after_reader)?;
    if regular_file_len(before_path)? != before_start
        || regular_file_len(after_path)? != after_start
    {
        return Err("snapshot changed during read".to_owned());
    }
    if before_occurrences
        .iter()
        .zip(require_absent_before)
        .any(|(count, required)| *required && *count != 0)
    {
        return Err(
            "synthetic literals must be absent from the complete before snapshot".to_owned(),
        );
    }

    let literals = literals
        .iter()
        .enumerate()
        .map(|(index, literal)| LiteralEvidence {
            literal: literal.clone(),
            before_occurrences: before_occurrences[index],
            after_occurrences: after_occurrences[index],
            candidate_page_count: candidate_page_counts[index],
        })
        .collect();
    let candidate_page_count = clusters.values().sum();
    let candidate_clusters = clusters
        .into_iter()
        .map(
            |((before_page_type_raw, after_page_type_raw, after_literals), page_count)| {
                CandidateCluster {
                    before_page_type_raw,
                    after_page_type_raw,
                    after_literals,
                    page_count,
                }
            },
        )
        .collect();
    Ok(AccountDeltaProbe {
        page_count: before_start / PAGE_SIZE as u64,
        raw_changed_page_count,
        control_noise_subtracted_page_count,
        remaining_changed_page_count,
        candidate_page_count,
        literals,
        candidate_clusters,
        control_noise_manifest_sha256,
    })
}

pub fn to_json(probe: &AccountDeltaProbe) -> String {
    let mut out = String::from("{\"schema_version\":\"openqbw.account-delta-probe.v1\"");
    let _ = write!(
        out,
        ",\"page_size\":{},\"page_count\":{},\"raw_changed_page_count\":{},\"control_noise_subtraction\":{{\"applied\":true,\"manifest_sha256\":\"{}\",\"subtracted_changed_page_count\":{},\"remaining_changed_page_count\":{}}},\"candidate_page_count\":{}",
        PAGE_SIZE,
        probe.page_count,
        probe.raw_changed_page_count,
        probe.control_noise_manifest_sha256,
        probe.control_noise_subtracted_page_count,
        probe.remaining_changed_page_count,
        probe.candidate_page_count,
    );
    out.push_str(",\"literal_evidence\":[");
    for (index, evidence) in probe.literals.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"literal\":{},\"before_occurrences\":{},\"after_occurrences\":{},\"candidate_page_count\":{}}}",
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

/// Render an AP-aware probe without paths, page positions, raw bytes, or
/// decoded non-sentinel content.  The result explicitly fails closed as
/// candidate evidence: it cannot certify plaintext, account rows, or fields.
pub fn ap_aware_to_json(probe: &ApAwareAccountDeltaProbe) -> String {
    let mut out = String::from("{\"schema_version\":\"openqbw.account-delta-ap-aware-probe.v2\"");
    let _ = write!(
        out,
        ",\"page_size\":{},\"raw\":{}",
        PAGE_SIZE,
        to_json(&probe.raw)
    );
    let _ = write!(
        out,
        ",\"ap_recovery\":{{\"plaintext_certified\":false,\"result_scope\":\"candidate_only\",\"heuristic_candidate_page_count\":{},\"model_candidate_page_count\":{}}},\"candidate_page_count\":{}",
        probe.heuristic_candidate_page_count,
        probe.model_candidate_page_count,
        probe.candidate_page_count
    );
    out.push_str(",\"literal_evidence\":[");
    for (index, evidence) in probe.literals.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"literal\":{},\"before_occurrences\":{},\"after_occurrences\":{},\"candidate_page_count\":{}}}",
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

fn validate_literals(literals: &[String]) -> Result<Vec<(String, Vec<u8>)>, String> {
    if literals.is_empty() {
        return Err("at least one synthetic literal is required".to_owned());
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(literals.len());
    for literal in literals {
        if literal.is_empty() || !literal.is_ascii() || !seen.insert(literal) {
            return Err("literals must be distinct, non-empty ASCII strings".to_owned());
        }
        out.push((literal.clone(), literal.as_bytes().to_vec()));
    }
    Ok(out)
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

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "openqbw-account-probe-{}-{name}",
            std::process::id()
        ))
    }
    fn page(fill: u8, page_type: u8, literal: &[u8]) -> [u8; PAGE_SIZE] {
        let mut page = [fill; PAGE_SIZE];
        page[PAGE_TYPE_OFFSET] = page_type;
        page[16..16 + literal.len()].copy_from_slice(literal);
        page
    }
    fn write_pages(path: &Path, pages: &[[u8; PAGE_SIZE]]) {
        fs::write(
            path,
            pages
                .iter()
                .flat_map(|page| page.iter().copied())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    }

    fn ap_page(pn: u64, bv: u8, page_type: u8, literal: &[u8]) -> [u8; PAGE_SIZE] {
        let mut plain = [0u8; PAGE_SIZE];
        plain[64..64 + literal.len()].copy_from_slice(literal);
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
        raw[PAGE_TYPE_OFFSET] = page_type;
        raw
    }

    #[test]
    fn subtracts_exact_control_and_emits_only_sentinel_evidence() {
        let before = path("before.qbw");
        let after = path("after.qbw");
        let control_before = path("control-before.qbw");
        let control_after = path("control-after.qbw");
        let manifest = path("control.json");
        let unchanged = page(1, b'A', b"");
        let noise_before = page(2, b'N', b"");
        let noise_after = page(3, b'N', b"");
        let signal_before = page(4, b'R', b"");
        let mut signal_after = page(5, b'S', b"SAMPLE_ACCOUNT_001");
        signal_after[64..64 + b"SAMPLE_BANK_ACCOUNT".len()].copy_from_slice(b"SAMPLE_BANK_ACCOUNT");
        write_pages(&before, &[unchanged, noise_before, signal_before]);
        write_pages(&after, &[unchanged, noise_after, signal_after]);
        write_pages(&control_before, &[unchanged, noise_before, unchanged]);
        write_pages(&control_after, &[unchanged, noise_after, unchanged]);
        let control =
            crate::snapshot_compare::compare_snapshots(&control_before, &control_after, None)
                .unwrap();
        fs::write(
            &manifest,
            crate::snapshot_compare::to_json(&control, None, None),
        )
        .unwrap();
        let literals = vec![
            "SAMPLE_ACCOUNT_001".to_owned(),
            "SAMPLE_BANK_ACCOUNT".to_owned(),
        ];
        let probe = probe_account_delta(&before, &after, &manifest, &literals).unwrap();
        assert_eq!(probe.raw_changed_page_count, 2);
        assert_eq!(probe.control_noise_subtracted_page_count, 1);
        assert_eq!(probe.remaining_changed_page_count, 1);
        assert_eq!(probe.candidate_page_count, 1);
        assert_eq!(probe.literals[0].after_occurrences, 1);
        assert_eq!(probe.literals[1].after_occurrences, 1);
        let json = to_json(&probe);
        assert!(!json.contains(before.to_string_lossy().as_ref()));
        assert!(!json.contains("page_number"));
        assert!(!json.contains("offset"));
        for path in [&before, &after, &control_before, &control_after, &manifest] {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn rejects_unsafe_literal_sets() {
        let empty = Vec::new();
        assert!(validate_literals(&empty).is_err());
        assert!(validate_literals(&["duplicate".into(), "duplicate".into()]).is_err());
        assert!(validate_literals(&["é".into()]).is_err());
    }

    #[test]
    fn rejects_a_sentinel_that_already_exists_on_an_unchanged_before_page() {
        let before = path("collision-before.qbw");
        let after = path("collision-after.qbw");
        let control_before = path("collision-control-before.qbw");
        let control_after = path("collision-control-after.qbw");
        let manifest = path("collision-control.json");
        let unchanged_with_collision = page(1, b'A', b"SAMPLE_ACCOUNT_001");
        let changed_before = page(2, b'B', b"");
        let changed_after = page(3, b'C', b"SAMPLE_BANK_ACCOUNT");
        write_pages(&before, &[unchanged_with_collision, changed_before]);
        write_pages(&after, &[unchanged_with_collision, changed_after]);
        write_pages(&control_before, &[unchanged_with_collision]);
        write_pages(&control_after, &[unchanged_with_collision]);
        let control =
            crate::snapshot_compare::compare_snapshots(&control_before, &control_after, None)
                .unwrap();
        fs::write(
            &manifest,
            crate::snapshot_compare::to_json(&control, None, None),
        )
        .unwrap();
        let result = probe_account_delta(
            &before,
            &after,
            &manifest,
            &[
                "SAMPLE_ACCOUNT_001".to_owned(),
                "SAMPLE_BANK_ACCOUNT".to_owned(),
            ],
        );
        assert_eq!(
            result,
            Err("synthetic literals must be absent from the complete before snapshot".to_owned())
        );
        for path in [&before, &after, &control_before, &control_after, &manifest] {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn rename_mode_retains_existing_marker_counts_but_not_locations() {
        let before = path("rename-before.qbw");
        let after = path("rename-after.qbw");
        let manifest = path("rename-control.json");
        let old = b"SAMPLE_ASSET_OLD";
        let new = b"SAMPLE_ASSET_NEW";
        let signal_before = page(9, b'R', old);
        let mut signal_after = page(10, b'R', new);
        signal_after[64..64 + b"SAMPLE_ACCOUNT_002".len()].copy_from_slice(b"SAMPLE_ACCOUNT_002");
        write_pages(&before, &[signal_before]);
        write_pages(&after, &[signal_after]);
        fs::write(&manifest, br#"{"raw_page_hash_transitions":[]}"#).unwrap();
        let probe = probe_account_delta_allow_existing(
            &before,
            &after,
            &manifest,
            &[
                "SAMPLE_ASSET_OLD".into(),
                "SAMPLE_ASSET_NEW".into(),
                "SAMPLE_ACCOUNT_002".into(),
            ],
        )
        .unwrap();
        assert_eq!(probe.literals[0].before_occurrences, 1);
        assert_eq!(probe.literals[0].after_occurrences, 0);
        assert_eq!(probe.literals[1].before_occurrences, 0);
        assert_eq!(probe.literals[1].after_occurrences, 1);
        assert_eq!(probe.literals[2].after_occurrences, 1);
        let json = to_json(&probe);
        assert!(!json.contains(before.to_string_lossy().as_ref()));
        assert!(!json.contains("page_number"));
        assert!(!json.contains("offset"));
        for path in [&before, &after, &manifest] {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn ap_aware_mode_proves_only_synthetic_literals_without_leaking_locations() {
        let before = path("ap-before.qbw");
        let after = path("ap-after.qbw");
        let manifest = path("ap-control.json");
        // Page zero is a pure AP page so each snapshot learns a model from
        // its own data. Page one is a changed data page carrying only the
        // caller-supplied sentinel after AP recovery.
        let pure = ap_page(0, 41, b'@', b"");
        let signal_before = ap_page(1, 41, b'E', b"");
        let signal_after = ap_page(1, 41, b'E', b"SAMPLE_BANK_ACCOUNT");
        write_pages(&before, &[pure, signal_before]);
        write_pages(&after, &[pure, signal_after]);
        fs::write(&manifest, br#"{"raw_page_hash_transitions":[]}"#).unwrap();
        let result = probe_account_delta_ap_aware(
            &before,
            &after,
            &manifest,
            &["SAMPLE_BANK_ACCOUNT".to_owned()],
        )
        .unwrap();
        assert_eq!(result.raw.candidate_page_count, 0);
        assert_eq!(result.candidate_page_count, 1);
        assert_eq!(result.literals[0].before_occurrences, 0);
        assert_eq!(result.literals[0].after_occurrences, 1);
        let json = ap_aware_to_json(&result);
        assert!(json.contains("\"plaintext_certified\":false"));
        assert!(json.contains("\"result_scope\":\"candidate_only\""));
        assert!(json.contains("\"heuristic_candidate_page_count\":"));
        assert!(json.contains("\"model_candidate_page_count\":"));
        assert!(!json.contains("exact_page_count"));
        assert!(!json.contains("model_fallback_page_count"));
        assert!(!json.contains(before.to_string_lossy().as_ref()));
        assert!(!json.contains(after.to_string_lossy().as_ref()));
        assert!(!json.contains("page_number"));
        assert!(!json.contains("offset"));
        assert!(!json.contains("raw_bytes"));
        for path in [&before, &after, &manifest] {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn ap_aware_mode_rejects_a_marker_present_only_after_candidate_transform() {
        let before = path("ap-collision-before.qbw");
        let after = path("ap-collision-after.qbw");
        let manifest = path("ap-collision-control.json");
        // The stored bytes deliberately do not contain the literal.  The
        // ordinary raw collision guard therefore passes, while the AP-aware
        // guard must reject the marker after applying its candidate transform.
        let pure = ap_page(0, 41, b'@', b"");
        let already_present = ap_page(1, 41, b'E', b"SAMPLE_BANK_ACCOUNT");
        write_pages(&before, &[pure, already_present]);
        write_pages(&after, &[pure, already_present]);
        fs::write(&manifest, br#"{"raw_page_hash_transitions":[]}"#).unwrap();

        let result = probe_account_delta_ap_aware(
            &before,
            &after,
            &manifest,
            &["SAMPLE_BANK_ACCOUNT".to_owned()],
        );
        assert_eq!(
            result,
            Err(
                "synthetic literals must be absent from complete before snapshot after candidate AP decode"
                    .to_owned()
            )
        );
        for path in [&before, &after, &manifest] {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn ap_aware_rename_mode_permits_only_the_explicit_existing_marker() {
        let before = path("ap-rename-before.qbw");
        let after = path("ap-rename-after.qbw");
        let manifest = path("ap-rename-control.json");
        let pure = ap_page(0, 41, b'@', b"");
        let signal_before = ap_page(1, 41, b'E', b"SAMPLE_ASSET_OLD");
        let signal_after = ap_page(1, 41, b'E', b"SAMPLE_ASSET_NEW");
        write_pages(&before, &[pure, signal_before]);
        write_pages(&after, &[pure, signal_after]);
        fs::write(&manifest, br#"{"raw_page_hash_transitions":[]}"#).unwrap();
        let probe = probe_account_delta_ap_aware_allow_existing(
            &before,
            &after,
            &manifest,
            &["SAMPLE_ASSET_OLD".into(), "SAMPLE_ASSET_NEW".into()],
        )
        .unwrap();
        assert_eq!(probe.literals[0].before_occurrences, 1);
        assert_eq!(probe.literals[1].before_occurrences, 0);
        assert_eq!(probe.literals[1].after_occurrences, 1);
        assert_eq!(probe.candidate_clusters.len(), 1);
        assert_eq!(
            probe.candidate_clusters[0].after_literals,
            vec!["SAMPLE_ASSET_NEW"]
        );
        let json = ap_aware_to_json(&probe);
        assert!(json.contains("candidate_only"));
        assert!(json.contains("candidate_clusters"));
        assert!(!json.contains(before.to_string_lossy().as_ref()));
        assert!(!json.contains("page_number"));
        for path in [&before, &after, &manifest] {
            let _ = fs::remove_file(path);
        }
    }
}

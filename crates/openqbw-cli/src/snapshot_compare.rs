//! Privacy-safe, streaming comparison of two immutable page-aligned snapshots.
//!
//! This module intentionally never retains more than two 4 KiB pages.  Its
//! JSON contains snapshot hashes and aggregate *multisets* of opaque page-hash
//! transitions, but never page offsets, page numbers, file paths, or contents.
//! The latter multiset is necessary for safe control-noise subtraction: a
//! control change can be removed only when its complete before/after page hash
//! pair is identical, never merely because a page type happens to match.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;

use crate::batch_extract::StreamingSha256;

pub const PAGE_SIZE: usize = 4096;
const PAGE_TYPE_OFFSET: usize = 0xff2;
const CRC_OFFSET: usize = 0xffc;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotIdentity {
    pub byte_length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotComparison {
    pub before: SnapshotIdentity,
    pub after: SnapshotIdentity,
    pub page_count: u64,
    pub changed_page_count: u64,
    pub crc_change_count: u64,
    pub raw_page_type_transitions: BTreeMap<(u8, u8), u64>,
    /// Aggregate only: keys deliberately contain no page number or offset.
    pub raw_page_hash_transitions: BTreeMap<(String, String), u64>,
    pub remaining_changed_page_count: u64,
    pub remaining_page_type_transitions: BTreeMap<(u8, u8), u64>,
    pub remaining_page_hash_transitions: BTreeMap<(String, String), u64>,
    pub control_noise_manifest_sha256: Option<String>,
    pub control_noise_subtracted_page_count: u64,
}

/// Compare two same-size, 4096-byte aligned snapshots. Both inputs are
/// checked before and after the stream to reject a snapshot that changes while
/// it is being read.
pub fn compare_snapshots(
    before_path: &Path,
    after_path: &Path,
    control_noise_manifest: Option<&Path>,
) -> Result<SnapshotComparison, String> {
    let before_start = regular_file_metadata(before_path)?;
    let after_start = regular_file_metadata(after_path)?;
    validate_geometry(before_start.len(), after_start.len())?;

    let before_file = File::open(before_path).map_err(io_error)?;
    let after_file = File::open(after_path).map_err(io_error)?;
    let mut before_reader = BufReader::with_capacity(PAGE_SIZE * 16, before_file);
    let mut after_reader = BufReader::with_capacity(PAGE_SIZE * 16, after_file);
    let mut before_page = [0u8; PAGE_SIZE];
    let mut after_page = [0u8; PAGE_SIZE];
    let mut before_hasher = StreamingSha256::new();
    let mut after_hasher = StreamingSha256::new();
    let mut changed_page_count = 0u64;
    let mut crc_change_count = 0u64;
    let mut raw_page_type_transitions = BTreeMap::new();
    let mut raw_page_hash_transitions = BTreeMap::new();
    let mut hash_pair_types = BTreeMap::new();

    for _ in 0..(before_start.len() / PAGE_SIZE as u64) {
        before_reader
            .read_exact(&mut before_page)
            .map_err(io_error)?;
        after_reader.read_exact(&mut after_page).map_err(io_error)?;
        before_hasher.update(&before_page);
        after_hasher.update(&after_page);
        if before_page == after_page {
            continue;
        }
        changed_page_count += 1;
        if before_page[CRC_OFFSET..] != after_page[CRC_OFFSET..] {
            crc_change_count += 1;
        }
        *raw_page_type_transitions
            .entry((before_page[PAGE_TYPE_OFFSET], after_page[PAGE_TYPE_OFFSET]))
            .or_insert(0) += 1;
        let transition = (sha256_hex(&before_page), sha256_hex(&after_page));
        hash_pair_types.insert(
            transition.clone(),
            (before_page[PAGE_TYPE_OFFSET], after_page[PAGE_TYPE_OFFSET]),
        );
        *raw_page_hash_transitions.entry(transition).or_insert(0) += 1;
    }
    assert_eof(&mut before_reader)?;
    assert_eof(&mut after_reader)?;

    let before_end = regular_file_metadata(before_path)?;
    let after_end = regular_file_metadata(after_path)?;
    if before_start.len() != before_end.len()
        || before_start.modified().ok() != before_end.modified().ok()
        || after_start.len() != after_end.len()
        || after_start.modified().ok() != after_end.modified().ok()
    {
        return Err("snapshot changed during read".to_owned());
    }

    let mut remaining_page_hash_transitions = raw_page_hash_transitions.clone();
    let mut control_noise_manifest_sha256 = None;
    let mut control_noise_subtracted_page_count = 0u64;
    if let Some(manifest_path) = control_noise_manifest {
        let bytes = fs::read(manifest_path).map_err(io_error)?;
        let control = parse_control_noise_manifest(&bytes)?;
        control_noise_manifest_sha256 = Some(sha256_hex(&bytes));
        for (pair, control_count) in control {
            let Some(observed) = remaining_page_hash_transitions.get_mut(&pair) else {
                continue;
            };
            let removed = (*observed).min(control_count);
            *observed -= removed;
            control_noise_subtracted_page_count += removed;
        }
        remaining_page_hash_transitions.retain(|_, count| *count != 0);
    }
    let remaining_changed_page_count = remaining_page_hash_transitions.values().sum();
    let mut remaining_page_type_transitions = BTreeMap::new();
    // A hash transition maps to exactly one raw type transition in this run.
    // Do not use a control manifest's type summary, which could over-subtract.
    for (pair, remaining_count) in &remaining_page_hash_transitions {
        let (before_type, after_type) = hash_pair_types
            .get(pair)
            .copied()
            .ok_or_else(|| "internal error: hash transition lost its page type".to_owned())?;
        *remaining_page_type_transitions
            .entry((before_type, after_type))
            .or_insert(0) += remaining_count;
    }

    Ok(SnapshotComparison {
        before: SnapshotIdentity {
            byte_length: before_start.len(),
            sha256: before_hasher.finish_hex(),
        },
        after: SnapshotIdentity {
            byte_length: after_start.len(),
            sha256: after_hasher.finish_hex(),
        },
        page_count: before_start.len() / PAGE_SIZE as u64,
        changed_page_count,
        crc_change_count,
        raw_page_type_transitions,
        raw_page_hash_transitions,
        remaining_changed_page_count,
        remaining_page_type_transitions,
        remaining_page_hash_transitions,
        control_noise_manifest_sha256,
        control_noise_subtracted_page_count,
    })
}

fn regular_file_metadata(path: &Path) -> Result<fs::Metadata, String> {
    let metadata = fs::metadata(path).map_err(io_error)?;
    if !metadata.is_file() {
        return Err("input is not a regular file".to_owned());
    }
    Ok(metadata)
}

fn validate_geometry(before_len: u64, after_len: u64) -> Result<(), String> {
    if before_len != after_len {
        return Err("snapshots must have equal byte lengths".to_owned());
    }
    if !before_len.is_multiple_of(PAGE_SIZE as u64) {
        return Err("snapshots must be aligned to 4096-byte pages".to_owned());
    }
    Ok(())
}

fn assert_eof(reader: &mut impl Read) -> Result<(), String> {
    let mut byte = [0u8; 1];
    match reader.read(&mut byte).map_err(io_error)? {
        0 => Ok(()),
        _ => Err("snapshot changed during read".to_owned()),
    }
}

fn io_error(error: std::io::Error) -> String {
    error.kind().to_string()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = StreamingSha256::new();
    hasher.update(bytes);
    hasher.finish_hex()
}

/// Render deterministic JSON. Paths and page positions are intentionally not
/// part of this format. Optional identifiers are caller-provided labels, not
/// derived paths.
pub fn to_json(
    comparison: &SnapshotComparison,
    before_source_identifier: Option<&str>,
    after_source_identifier: Option<&str>,
) -> String {
    let mut out =
        String::from("{\"schema_version\":\"openqbw.compare-snapshots.v1\",\"page_size\":4096,");
    write_snapshot(&mut out, "before", &comparison.before);
    out.push(',');
    write_snapshot(&mut out, "after", &comparison.after);
    let _ = write!(
        out,
        ",\"page_count\":{},\"changed_page_count\":{},\"crc_change_count\":{}",
        comparison.page_count, comparison.changed_page_count, comparison.crc_change_count
    );
    write_type_histogram(
        &mut out,
        "raw_page_type_transitions",
        &comparison.raw_page_type_transitions,
    );
    write_hash_histogram(
        &mut out,
        "raw_page_hash_transitions",
        &comparison.raw_page_hash_transitions,
    );
    let _ = write!(
        out,
        ",\"control_noise_subtraction\":{{\"applied\":{},\"manifest_sha256\":{},\"subtracted_changed_page_count\":{},\"remaining_changed_page_count\":{} }}",
        comparison.control_noise_manifest_sha256.is_some(),
        comparison
            .control_noise_manifest_sha256
            .as_deref()
            .map(json_string)
            .unwrap_or_else(|| "null".to_owned()),
        comparison.control_noise_subtracted_page_count,
        comparison.remaining_changed_page_count,
    );
    write_type_histogram(
        &mut out,
        "remaining_page_type_transitions",
        &comparison.remaining_page_type_transitions,
    );
    write_hash_histogram(
        &mut out,
        "remaining_page_hash_transitions",
        &comparison.remaining_page_hash_transitions,
    );
    if let (Some(before), Some(after)) = (before_source_identifier, after_source_identifier) {
        let _ = write!(
            out,
            ",\"source_identifiers\":{{\"before\":{},\"after\":{}}}",
            json_string(before),
            json_string(after)
        );
    }
    out.push('}');
    out
}

fn write_snapshot(out: &mut String, key: &str, snapshot: &SnapshotIdentity) {
    let _ = write!(
        out,
        "\"{}\":{{\"byte_length\":{},\"sha256\":\"{}\"}}",
        key, snapshot.byte_length, snapshot.sha256
    );
}

fn write_type_histogram(out: &mut String, key: &str, histogram: &BTreeMap<(u8, u8), u64>) {
    let _ = write!(out, ",\"{}\":[", key);
    for (index, ((before, after), count)) in histogram.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"before_page_type_raw\":{},\"after_page_type_raw\":{},\"count\":{}}}",
            before, after, count
        );
    }
    out.push(']');
}

fn write_hash_histogram(out: &mut String, key: &str, histogram: &BTreeMap<(String, String), u64>) {
    let _ = write!(out, ",\"{}\":[", key);
    for (index, ((before, after), count)) in histogram.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"before_sha256\":\"{}\",\"after_sha256\":\"{}\",\"count\":{}}}",
            before, after, count
        );
    }
    out.push(']');
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

/// Parse only the opaque hash transition multiset emitted by `to_json`.
/// No paths, offsets, or payloads are accepted. A malformed control manifest
/// is a hard error rather than a reason to apply a broader heuristic.
pub(crate) fn parse_control_noise_manifest(
    bytes: &[u8],
) -> Result<BTreeMap<(String, String), u64>, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| "control manifest is not UTF-8 JSON".to_owned())?;
    let needle = "\"raw_page_hash_transitions\":";
    let start = text
        .find(needle)
        .ok_or_else(|| "control manifest lacks raw_page_hash_transitions".to_owned())?
        + needle.len();
    let rest = text[start..].trim_start();
    let body = rest
        .strip_prefix('[')
        .ok_or_else(|| "control manifest has invalid transition array".to_owned())?;
    let end = body
        .find(']')
        .ok_or_else(|| "control manifest has unterminated transition array".to_owned())?;
    let content = &body[..end];
    if content.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut result = BTreeMap::new();
    for object in content.split("},{") {
        let object = object.trim_matches(|c| c == '{' || c == '}');
        let before = object_string(object, "before_sha256")?;
        let after = object_string(object, "after_sha256")?;
        let count = object_u64(object, "count")?;
        if !is_sha256_hex(&before) || !is_sha256_hex(&after) || count == 0 {
            return Err("control manifest has invalid opaque hash transition".to_owned());
        }
        let entry = result.entry((before, after)).or_insert(0u64);
        *entry = entry
            .checked_add(count)
            .ok_or_else(|| "control manifest count overflow".to_owned())?;
    }
    Ok(result)
}

fn object_string(object: &str, key: &str) -> Result<String, String> {
    let prefix = format!("\"{key}\":\"");
    let start = object
        .find(&prefix)
        .ok_or_else(|| "control manifest transition lacks hash".to_owned())?
        + prefix.len();
    let rest = &object[start..];
    let end = rest
        .find('"')
        .ok_or_else(|| "control manifest transition has invalid hash".to_owned())?;
    Ok(rest[..end].to_owned())
}

fn object_u64(object: &str, key: &str) -> Result<u64, String> {
    let prefix = format!("\"{key}\":");
    let start = object
        .find(&prefix)
        .ok_or_else(|| "control manifest transition lacks count".to_owned())?
        + prefix.len();
    let digits: String = object[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits
        .parse()
        .map_err(|_| "control manifest transition has invalid count".to_owned())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("openqbw-snapshot-{}-{}", std::process::id(), name))
    }
    fn page(fill: u8, page_type: u8, crc: u32) -> [u8; PAGE_SIZE] {
        let mut page = [fill; PAGE_SIZE];
        page[PAGE_TYPE_OFFSET] = page_type;
        page[CRC_OFFSET..].copy_from_slice(&crc.to_le_bytes());
        page
    }
    fn write_pages(path: &Path, pages: &[[u8; PAGE_SIZE]]) {
        let bytes: Vec<u8> = pages.iter().flat_map(|page| page.iter().copied()).collect();
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn streams_aggregate_only_and_subtracts_exact_hash_pairs() {
        let before = path("before.qbw");
        let after = path("after.qbw");
        let control_before = path("control-before.qbw");
        let control_after = path("control-after.qbw");
        let manifest = path("control.json");
        let unchanged = page(1, b'E', 1);
        let noise_before = page(2, b'A', 2);
        let noise_after = page(3, b'B', 3);
        let signal_before = page(4, b'E', 4);
        let signal_after = page(5, b'G', 5);
        write_pages(&before, &[unchanged, noise_before, signal_before]);
        write_pages(&after, &[unchanged, noise_after, signal_after]);
        write_pages(&control_before, &[unchanged, noise_before, unchanged]);
        write_pages(&control_after, &[unchanged, noise_after, unchanged]);
        let control = compare_snapshots(&control_before, &control_after, None).unwrap();
        fs::write(&manifest, to_json(&control, None, None)).unwrap();
        let actual = compare_snapshots(&before, &after, Some(&manifest)).unwrap();
        assert_eq!(actual.changed_page_count, 2);
        assert_eq!(actual.crc_change_count, 2);
        assert_eq!(actual.control_noise_subtracted_page_count, 1);
        assert_eq!(actual.remaining_changed_page_count, 1);
        assert_eq!(
            actual.remaining_page_type_transitions.get(&(b'E', b'G')),
            Some(&1)
        );
        let json = to_json(&actual, None, None);
        assert!(!json.contains(before.to_string_lossy().as_ref()));
        assert!(!json.contains("page_number"));
        for p in [&before, &after, &control_before, &control_after, &manifest] {
            let _ = fs::remove_file(p);
        }
    }

    #[test]
    fn rejects_nonmatching_or_unaligned_inputs() {
        let before = path("unaligned-before.qbw");
        let after = path("unaligned-after.qbw");
        fs::write(&before, [0u8; 1]).unwrap();
        fs::write(&after, [0u8; 1]).unwrap();
        assert_eq!(
            compare_snapshots(&before, &after, None).unwrap_err(),
            "snapshots must be aligned to 4096-byte pages"
        );
        fs::write(&after, [0u8; 2]).unwrap();
        assert_eq!(
            compare_snapshots(&before, &after, None).unwrap_err(),
            "snapshots must have equal byte lengths"
        );
        let _ = fs::remove_file(before);
        let _ = fs::remove_file(after);
    }

    #[test]
    fn control_manifest_is_strict_about_exact_hash_transitions() {
        let bytes = br#"{\"raw_page_hash_transitions\":[{\"before_sha256\":\"not-a-hash\",\"after_sha256\":\"not-a-hash\",\"count\":1}]}"#;
        assert!(parse_control_noise_manifest(bytes).is_err());
    }
}

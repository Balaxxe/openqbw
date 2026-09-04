//! Bounded, deterministic multi-file extraction scaffolding.
//!
//! This module deliberately does **not** invoke an accounting decoder. Until
//! account/posting coverage is attested, every readable QBW is reported as
//! unsupported rather than producing partial accounting output. The worker
//! pool exists so a future complete decoder can be attached without changing
//! ordering, provenance, or error-isolation semantics.

use std::fmt::Write as _;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

/// Hard ceiling for concurrently opened company files.
pub const MAX_WORKERS: usize = 8;
const HASH_BUFFER_BYTES: usize = 1024 * 1024;
/// Largest input that the in-memory SQL Anywhere decoder can safely accept.
///
/// `PageStore` owns its complete input, so a decoder cannot be made streaming
/// without changing that library's representation.  This explicit ceiling
/// makes batch memory bounded at `MAX_WORKERS * MAX_SNAPSHOT_FILE_BYTES` and
/// rejects oversize input before allocating it.
pub const MAX_SNAPSHOT_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Immutable identity of the exact bytes inspected by one worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotMetadata {
    pub byte_length: u64,
    pub sha256: String,
}

/// A byte-identified local input made available to a future decoder.
///
/// The scheduler verifies that the file was stable while deriving
/// [`SnapshotMetadata`]. A decoder attached here must treat the metadata as
/// provenance for the exact bytes it reads and stage any externally visible
/// artifacts until its own input-consistency checks have succeeded.
pub struct SnapshotJob {
    pub input_index: usize,
    pub source_path: PathBuf,
    pub snapshot: SnapshotMetadata,
    bytes: Vec<u8>,
}

impl SnapshotJob {
    /// Consume the job into its identity, provenance, and exact source bytes.
    /// A decoder must use the returned bytes rather than reopening the path.
    pub fn into_parts(self) -> (usize, PathBuf, SnapshotMetadata, Vec<u8>) {
        (
            self.input_index,
            self.source_path,
            self.snapshot,
            self.bytes,
        )
    }
}

impl std::fmt::Debug for SnapshotJob {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SnapshotJob")
            .field("input_index", &self.input_index)
            .field("source_path", &self.source_path)
            .field("snapshot", &self.snapshot)
            .field("bytes", &format_args!("<{} bytes>", self.bytes.len()))
            .finish()
    }
}

/// Terminal outcome for one scheduled snapshot job.
///
/// Input failures are captured before a processor is called; processor output
/// is otherwise opaque so the scheduler can support a future strict decoder
/// without inventing partial-accounting success states.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotJobOutcome<T> {
    Completed(T),
    InputError { reason: String },
}

/// One deterministically placed result from [`schedule_snapshot_jobs`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotJobResult<T> {
    pub input_index: usize,
    pub source_path: PathBuf,
    pub snapshot: Option<SnapshotMetadata>,
    pub outcome: SnapshotJobOutcome<T>,
}

/// Ordered, failure-isolated generic snapshot schedule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotJobRun<T> {
    pub worker_limit: usize,
    pub results: Vec<SnapshotJobResult<T>>,
}

/// A per-input terminal status. No status represents a successful extraction
/// until a complete accounting decoder is wired in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchStatus {
    Unsupported { reason: &'static str },
    InputError { reason: String },
}

/// Isolated result for one caller-supplied input, ordered by `input_index`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchFileResult {
    pub input_index: usize,
    pub source_path: PathBuf,
    pub snapshot: Option<SnapshotMetadata>,
    pub status: BatchStatus,
}

/// Deterministic batch response suitable for JSON emission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchRun {
    pub worker_limit: usize,
    pub results: Vec<BatchFileResult>,
}

/// Validate and normalize the requested worker bound.
pub fn worker_limit(requested: usize, input_count: usize) -> Result<usize, String> {
    if input_count == 0 {
        return Err("at least one input is required".to_owned());
    }
    if requested == 0 {
        return Err("workers must be at least 1".to_owned());
    }
    if requested > MAX_WORKERS {
        return Err(format!("workers must not exceed {MAX_WORKERS}"));
    }
    Ok(requested.min(input_count))
}

/// Inspect all inputs with a bounded worker pool and stable input ordering.
///
/// Each worker reads only its assigned file. A read/hash failure is captured
/// as that file's result and never aborts sibling files. A readable `.qbw`
/// remains deliberately `Unsupported`: outputting a partial Trial Balance or
/// GL before decoder coverage is complete would be unsafe.
pub fn inspect_files(inputs: Vec<PathBuf>, requested_workers: usize) -> Result<BatchRun, String> {
    let input_count = inputs.len();
    let bound = worker_limit(requested_workers, input_count)?;
    let tasks = Arc::new(Mutex::new(inputs.into_iter().enumerate()));
    let (sender, receiver) = mpsc::channel();
    let run = thread::scope(|scope| {
        for _ in 0..bound {
            let tasks = Arc::clone(&tasks);
            let sender = sender.clone();
            scope.spawn(move || {
                loop {
                    let Some((input_index, source_path)) =
                        tasks.lock().expect("batch task lock poisoned").next()
                    else {
                        break;
                    };
                    let result = match attest_file(&source_path) {
                        Ok(snapshot) => BatchFileResult {
                            input_index,
                            status: unsupported_status(&source_path),
                            source_path,
                            snapshot: Some(snapshot),
                        },
                        Err(reason) => BatchFileResult {
                            input_index,
                            source_path,
                            snapshot: None,
                            status: BatchStatus::InputError { reason },
                        },
                    };
                    sender.send(result).expect("batch result receiver dropped");
                }
            });
        }
        drop(sender);
        let mut ordered: Vec<Option<BatchFileResult>> = (0..input_count).map(|_| None).collect();
        for result in receiver {
            let index = result.input_index;
            ordered[index] = Some(result);
        }
        BatchRun {
            worker_limit: bound,
            results: ordered
                .into_iter()
                .map(|result| result.expect("one result per batch input"))
                .collect(),
        }
    });
    Ok(run)
}

/// Run one pure, caller-supplied processor for each stable local snapshot.
///
/// Results are returned in caller input order, rather than completion order.
/// A failed open/hash is isolated to its input and the processor is not
/// invoked for that input. The opaque completed value provides a narrow seam
/// for a future complete decoder to attach its own strict result type while
/// preserving the batch scheduler's deterministic ordering and isolation.
pub fn schedule_snapshot_jobs<T, F>(
    inputs: Vec<PathBuf>,
    requested_workers: usize,
    processor: F,
) -> Result<SnapshotJobRun<T>, String>
where
    T: Send,
    F: Fn(SnapshotJob) -> T + Sync,
{
    let input_count = inputs.len();
    let bound = worker_limit(requested_workers, input_count)?;
    let tasks = Arc::new(Mutex::new(
        inputs
            .into_iter()
            .enumerate()
            .collect::<Vec<_>>()
            .into_iter(),
    ));
    let (sender, receiver) = mpsc::channel();
    let run = thread::scope(|scope| {
        for _ in 0..bound {
            let tasks = Arc::clone(&tasks);
            let sender = sender.clone();
            let processor = &processor;
            scope.spawn(move || {
                loop {
                    let next = tasks.lock().expect("batch task lock poisoned").next();
                    let Some((input_index, source_path)) = next else {
                        break;
                    };
                    let result = run_one(input_index, source_path, processor);
                    // The receiver stays alive until all scoped workers join.
                    sender.send(result).expect("batch result receiver dropped");
                }
            });
        }
        drop(sender);
        let mut ordered: Vec<Option<SnapshotJobResult<T>>> =
            (0..input_count).map(|_| None).collect();
        let mut returned = Vec::new();
        for result in receiver {
            returned.push(result);
        }
        for result in returned {
            let index = result.input_index;
            ordered[index] = Some(result);
        }
        SnapshotJobRun {
            worker_limit: bound,
            results: ordered
                .into_iter()
                .map(|r| r.expect("one result per batch input"))
                .collect(),
        }
    });
    Ok(run)
}

fn run_one<T, F>(input_index: usize, source_path: PathBuf, processor: &F) -> SnapshotJobResult<T>
where
    F: Fn(SnapshotJob) -> T,
{
    let (snapshot, bytes) = match snapshot_file(&source_path) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return SnapshotJobResult {
                input_index,
                source_path,
                snapshot: None,
                outcome: SnapshotJobOutcome::InputError { reason: error },
            };
        }
    };
    let job = SnapshotJob {
        input_index,
        source_path: source_path.clone(),
        snapshot: snapshot.clone(),
        bytes,
    };
    SnapshotJobResult {
        input_index,
        source_path,
        snapshot: Some(snapshot),
        outcome: SnapshotJobOutcome::Completed(processor(job)),
    }
}

fn unsupported_status(source_path: &Path) -> BatchStatus {
    if is_qbw_path(source_path) {
        BatchStatus::Unsupported {
            reason: "normalized accounting decoder is not yet complete",
        }
    } else {
        BatchStatus::Unsupported {
            reason: "input does not have a .qbw extension",
        }
    }
}

/// Read and hash one immutable file. Both pre- and post-read metadata must
/// agree with the exact byte count read; the returned bytes are the same bytes
/// supplied to a decoder, so no later path reopen can race the attestation.
fn snapshot_file(path: &Path) -> Result<(SnapshotMetadata, Vec<u8>), String> {
    let before = std::fs::metadata(path).map_err(|error| error.kind().to_string())?;
    if !before.is_file() {
        return Err("input is not a regular file".to_owned());
    }
    let expected_len = before.len();
    if expected_len > MAX_SNAPSHOT_FILE_BYTES {
        return Err(format!(
            "input exceeds the {}-byte batch snapshot limit",
            MAX_SNAPSHOT_FILE_BYTES
        ));
    }
    let before_modified = before.modified().ok();
    let mut file = File::open(path).map_err(|error| error.kind().to_string())?;
    let capacity = usize::try_from(expected_len).map_err(|_| "input is too large".to_owned())?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| "unable to reserve bounded batch snapshot buffer".to_owned())?;
    let snapshot = read_and_hash_snapshot(&mut file, expected_len, &mut bytes)?;
    let after = std::fs::metadata(path).map_err(|error| error.kind().to_string())?;
    if after.len() != expected_len
        || snapshot.byte_length != expected_len
        || after.modified().ok() != before_modified
    {
        return Err("snapshot changed during read".to_owned());
    }
    Ok((snapshot, bytes))
}

/// Re-attest a local path against a previously scheduled snapshot without
/// exposing the path or bytes to callers.  Batch accounting uses this after a
/// direct page-store decode, so a source mutation between scheduler read and
/// decoder read fails closed rather than being reported under stale provenance.
pub fn snapshot_still_matches(path: &Path, expected: &SnapshotMetadata) -> bool {
    attest_file(path)
        .map(|actual| actual == *expected)
        .unwrap_or(false)
}

/// Hash a file without retaining its bytes. Used by inspection and
/// post-decode re-attestation, where keeping a second company-file copy would
/// only inflate peak memory.
fn attest_file(path: &Path) -> Result<SnapshotMetadata, String> {
    let before = std::fs::metadata(path).map_err(|error| error.kind().to_string())?;
    if !before.is_file() {
        return Err("input is not a regular file".to_owned());
    }
    let expected_len = before.len();
    if expected_len > MAX_SNAPSHOT_FILE_BYTES {
        return Err(format!(
            "input exceeds the {}-byte batch snapshot limit",
            MAX_SNAPSHOT_FILE_BYTES
        ));
    }
    let before_modified = before.modified().ok();
    let mut file = File::open(path).map_err(|error| error.kind().to_string())?;
    let snapshot = hash_reader(&mut file, expected_len)?;
    let after = std::fs::metadata(path).map_err(|error| error.kind().to_string())?;
    if after.len() != expected_len
        || snapshot.byte_length != expected_len
        || after.modified().ok() != before_modified
    {
        return Err("snapshot changed during read".to_owned());
    }
    Ok(snapshot)
}

fn read_and_hash_snapshot(
    reader: &mut impl Read,
    expected_len: u64,
    bytes: &mut Vec<u8>,
) -> Result<SnapshotMetadata, String> {
    let mut hasher = StreamingSha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; HASH_BUFFER_BYTES];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| error.kind().to_string())?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| "input size overflow".to_owned())?;
        if total > expected_len {
            return Err("snapshot changed during read".to_owned());
        }
        bytes.extend_from_slice(&buffer[..count]);
        hasher.update(&buffer[..count]);
    }
    if total != expected_len {
        return Err("snapshot changed during read".to_owned());
    }
    Ok(SnapshotMetadata {
        byte_length: total,
        sha256: hasher.finish_hex(),
    })
}

fn hash_reader(mut reader: impl Read, expected_len: u64) -> Result<SnapshotMetadata, String> {
    let mut hasher = StreamingSha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; HASH_BUFFER_BYTES];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| error.kind().to_string())?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| "input size overflow".to_owned())?;
        if total > expected_len {
            return Err("snapshot changed during read".to_owned());
        }
        hasher.update(&buffer[..count]);
    }
    if total != expected_len {
        return Err("snapshot changed during read".to_owned());
    }
    Ok(SnapshotMetadata {
        byte_length: total,
        sha256: hasher.finish_hex(),
    })
}

fn is_qbw_path(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("qbw"))
}

/// Render a single deterministic, dependency-free JSON document.
pub fn to_json(run: &BatchRun) -> String {
    let mut out = format!(
        "{{\"schema_version\":\"openqbw.batch.v1\",\"worker_limit\":{},\"results\":[",
        run.worker_limit
    );
    for (position, result) in run.results.iter().enumerate() {
        if position != 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"input_index\":{},\"source_path\":\"{}\",",
            result.input_index,
            json_escape(&result.source_path.to_string_lossy())
        );
        match &result.snapshot {
            Some(snapshot) => {
                let _ = write!(
                    out,
                    "\"snapshot\":{{\"byte_length\":{},\"sha256\":\"{}\"}},",
                    snapshot.byte_length, snapshot.sha256
                );
            }
            None => out.push_str("\"snapshot\":null,"),
        }
        match &result.status {
            BatchStatus::Unsupported { reason } => {
                let _ = write!(
                    out,
                    "\"status\":\"unsupported\",\"reason\":\"{}\"}}",
                    json_escape(reason)
                );
            }
            BatchStatus::InputError { reason } => {
                let _ = write!(
                    out,
                    "\"status\":\"input_error\",\"reason\":\"{}\"}}",
                    json_escape(reason)
                );
            }
        }
    }
    out.push_str("]}");
    out
}

fn json_escape(value: &str) -> String {
    let mut out = String::new();
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
    out
}

/// Incremental SHA-256 used solely for local immutable-snapshot provenance.
/// It keeps at most one 64-byte block plus the fixed I/O buffer in memory.
pub(crate) struct StreamingSha256 {
    state: [u32; 8],
    block: [u8; 64],
    block_len: usize,
    total_len: u64,
}

impl StreamingSha256 {
    pub(crate) fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            block: [0; 64],
            block_len: 0,
            total_len: 0,
        }
    }

    pub(crate) fn update(&mut self, mut input: &[u8]) {
        self.total_len = self.total_len.wrapping_add(input.len() as u64);
        if self.block_len != 0 {
            let take = (64 - self.block_len).min(input.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&input[..take]);
            self.block_len += take;
            input = &input[take..];
            if self.block_len == 64 {
                compress(&mut self.state, &self.block);
                self.block_len = 0;
            }
        }
        while input.len() >= 64 {
            let block: &[u8; 64] = input[..64].try_into().expect("block width");
            compress(&mut self.state, block);
            input = &input[64..];
        }
        if !input.is_empty() {
            self.block[..input.len()].copy_from_slice(input);
            self.block_len = input.len();
        }
    }

    pub(crate) fn finish_hex(mut self) -> String {
        let bit_len = self.total_len.wrapping_mul(8);
        self.block[self.block_len] = 0x80;
        self.block_len += 1;
        if self.block_len > 56 {
            self.block[self.block_len..].fill(0);
            compress(&mut self.state, &self.block);
            self.block_len = 0;
        }
        self.block[self.block_len..56].fill(0);
        self.block[56..].copy_from_slice(&bit_len.to_be_bytes());
        compress(&mut self.state, &self.block);
        self.state
            .iter()
            .map(|word| format!("{word:08x}"))
            .collect()
    }
}

const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut words = [0u32; 64];
    for (index, word) in words[..16].iter_mut().enumerate() {
        *word = u32::from_be_bytes(
            block[index * 4..index * 4 + 4]
                .try_into()
                .expect("word width"),
        );
    }
    for index in 16..64 {
        let s0 = words[index - 15].rotate_right(7)
            ^ words[index - 15].rotate_right(18)
            ^ (words[index - 15] >> 3);
        let s1 = words[index - 2].rotate_right(17)
            ^ words[index - 2].rotate_right(19)
            ^ (words[index - 2] >> 10);
        words[index] = words[index - 16]
            .wrapping_add(s0)
            .wrapping_add(words[index - 7])
            .wrapping_add(s1);
    }
    let mut work = *state;
    for (index, constant) in SHA256_K.iter().enumerate() {
        let s1 = work[4].rotate_right(6) ^ work[4].rotate_right(11) ^ work[4].rotate_right(25);
        let choice = (work[4] & work[5]) ^ ((!work[4]) & work[6]);
        let first = work[7]
            .wrapping_add(s1)
            .wrapping_add(choice)
            .wrapping_add(*constant)
            .wrapping_add(words[index]);
        let s0 = work[0].rotate_right(2) ^ work[0].rotate_right(13) ^ work[0].rotate_right(22);
        let majority = (work[0] & work[1]) ^ (work[0] & work[2]) ^ (work[1] & work[2]);
        work = [
            first.wrapping_add(s0.wrapping_add(majority)),
            work[0],
            work[1],
            work[2],
            work[3].wrapping_add(first),
            work[4],
            work[5],
            work[6],
        ];
    }
    for (digest, value) in state.iter_mut().zip(work) {
        *digest = digest.wrapping_add(value);
    }
}

// Independent test-only SHA-256 vector implementation. Production hashing is
// shared with the manifest parser so both provenance paths use one routine.
#[cfg(test)]
fn sha256_hex(bytes: &[u8]) -> String {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    let mut padded = bytes.to_vec();
    padded.push(0x80);
    while !(padded.len() + 8).is_multiple_of(64) {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in w[..16].iter_mut().enumerate() {
            *word = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().expect("chunk word"));
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        );
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
    state.iter().map(|word| format!("{word:08x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "openqbw-{name}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    #[test]
    fn sha256_matches_standard_empty_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn streaming_hash_matches_one_shot_across_large_buffer_boundaries() {
        let bytes = (0..(HASH_BUFFER_BYTES * 3 + 97))
            .map(|index| (index.wrapping_mul(17) as u8).wrapping_add(3))
            .collect::<Vec<_>>();
        let streamed = hash_reader(Cursor::new(&bytes), bytes.len() as u64).expect("streamed");
        assert_eq!(streamed.byte_length, bytes.len() as u64);
        assert_eq!(streamed.sha256, sha256_hex(&bytes));
    }

    #[test]
    fn truncated_stream_is_rejected_as_changed_snapshot() {
        let error = hash_reader(Cursor::new(b"short"), 6).expect_err("must reject truncation");
        assert_eq!(error, "snapshot changed during read");
    }

    #[test]
    fn batch_is_ordered_and_isolates_missing_input() {
        let first = temp_path("first.qbw");
        let second = temp_path("second.txt");
        let missing = temp_path("missing.qbw");
        std::fs::write(&first, b"first").expect("first");
        std::fs::write(&second, b"second").expect("second");
        let run = inspect_files(vec![first.clone(), missing, second.clone()], 3).expect("batch");
        assert_eq!(run.worker_limit, 3);
        assert_eq!(
            run.results
                .iter()
                .map(|r| r.input_index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert!(matches!(
            run.results[0].status,
            BatchStatus::Unsupported { .. }
        ));
        assert!(matches!(
            run.results[1].status,
            BatchStatus::InputError { .. }
        ));
        assert!(matches!(
            run.results[2].status,
            BatchStatus::Unsupported {
                reason: "input does not have a .qbw extension"
            }
        ));
        assert_eq!(
            run.results[0].snapshot.as_ref().expect("snapshot").sha256,
            sha256_hex(b"first")
        );
        let _ = std::fs::remove_file(first);
        let _ = std::fs::remove_file(second);
    }

    #[test]
    fn generic_snapshot_schedule_preserves_order_and_skips_bad_inputs() {
        let first = temp_path("schedule-first.qbw");
        let second = temp_path("schedule-second.qbw");
        let missing = temp_path("schedule-missing.qbw");
        std::fs::write(&first, b"first").expect("first");
        std::fs::write(&second, b"second").expect("second");
        let calls = AtomicUsize::new(0);
        let run = schedule_snapshot_jobs(vec![first.clone(), missing, second.clone()], 3, |job| {
            calls.fetch_add(1, Ordering::Relaxed);
            if job.input_index == 0 {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            (job.input_index, job.snapshot.sha256)
        })
        .expect("schedule");
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(
            run.results
                .iter()
                .map(|result| result.input_index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert!(matches!(
            run.results[1].outcome,
            SnapshotJobOutcome::InputError { .. }
        ));
        assert!(matches!(
            run.results[0].outcome,
            SnapshotJobOutcome::Completed((0, _))
        ));
        assert!(matches!(
            run.results[2].outcome,
            SnapshotJobOutcome::Completed((2, _))
        ));
        let _ = std::fs::remove_file(first);
        let _ = std::fs::remove_file(second);
    }

    #[test]
    fn processor_receives_the_exact_hashed_bytes_even_if_the_path_changes() {
        let file = temp_path("stable-job.qbw");
        let original = b"original-snapshot";
        std::fs::write(&file, original).expect("original");
        let run = schedule_snapshot_jobs(vec![file.clone()], 1, |job| {
            let sha256 = job.snapshot.sha256.clone();
            let debug = format!("{job:?}");
            assert!(!debug.contains("original-snapshot"));
            std::fs::write(&job.source_path, b"replacement").expect("replace path");
            let (_, _, _, bytes) = job.into_parts();
            (sha256, bytes)
        })
        .expect("schedule");
        match &run.results[0].outcome {
            SnapshotJobOutcome::Completed((sha256, bytes)) => {
                assert_eq!(sha256, &sha256_hex(original));
                assert_eq!(bytes, original);
            }
            SnapshotJobOutcome::InputError { reason } => {
                panic!("unexpected input error: {reason}")
            }
        }
        assert_eq!(std::fs::read(&file).expect("replacement"), b"replacement");
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn json_is_deterministic_and_fail_closed() {
        let file = temp_path("one.qbw");
        std::fs::write(&file, b"x").expect("file");
        let first = to_json(&inspect_files(vec![file.clone()], 1).expect("first"));
        let second = to_json(&inspect_files(vec![file.clone()], 1).expect("second"));
        assert_eq!(first, second);
        assert!(first.contains("\"status\":\"unsupported\""));
        assert!(!first.contains("success"));
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn worker_bound_is_enforced() {
        assert!(worker_limit(0, 1).is_err());
        assert!(worker_limit(MAX_WORKERS + 1, 1).is_err());
        assert_eq!(worker_limit(MAX_WORKERS, 2), Ok(2));
    }

    #[test]
    fn oversized_snapshot_is_rejected_before_buffering() {
        let file = temp_path("oversized.qbw");
        let handle = std::fs::File::create(&file).expect("file");
        handle
            .set_len(MAX_SNAPSHOT_FILE_BYTES + 1)
            .expect("sparse length");
        drop(handle);
        let error = snapshot_file(&file).expect_err("must reject oversized snapshot");
        assert!(error.contains("batch snapshot limit"));
        let _ = std::fs::remove_file(file);
    }
}

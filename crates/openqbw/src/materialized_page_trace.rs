//! Provenance-safe correlation of immutable QBW pages with external runtime traces.
//!
//! This module deliberately does not acquire a runtime trace, decode a row, or
//! interpret a runtime page directory.  A separately authorised research tool
//! may capture a bounded materialized-page observation and its mapping to a
//! raw QBW page.  This type checks that mapping against an immutable raw-page
//! witness without retaining company payload bytes.

use std::collections::{BTreeMap, BTreeSet};

use opensqlany::{
    ContinuationTarget, MaterializedPageError, MaterializedTablePage, Page, RowSegmentError,
};

use crate::SourceSnapshotId;

/// The fixed physical size of one SQL Anywhere page.
pub const RAW_PAGE_BYTES: usize = 4096;

/// A validated lowercase hexadecimal SHA-256 digest.
///
/// Digest production intentionally remains outside this crate: callers can
/// use the same approved hashing process for a raw-page inventory and a
/// bounded runtime trace without linking against a runtime database service.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Validates a lowercase 64-character hexadecimal SHA-256 digest.
    pub fn new(value: impl Into<String>) -> Result<Self, MaterializedPageTraceError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(MaterializedPageTraceError::InvalidSha256);
        }
        Ok(Self(value))
    }

    /// Returns the validated digest text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Non-payload identity and trailer facts for one immutable raw QBW page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawPageWitness {
    /// Identity of the exact immutable source snapshot.
    pub snapshot: SourceSnapshotId,
    /// Zero-based physical page number within that snapshot.
    pub page_number: u64,
    /// SHA-256 of exactly the raw 4096-byte physical page.
    pub raw_sha256: Sha256Digest,
    /// Raw page type byte at trailer offset `0xff2`.
    pub page_type_raw: u8,
    /// CRC stored at raw-page offset `0xffc`.
    pub stored_crc32: u32,
}

impl RawPageWitness {
    /// Creates a no-payload witness from an immutable raw page and externally
    /// supplied digest of that page's exact bytes.
    pub fn from_raw_page(
        snapshot: SourceSnapshotId,
        page: Page<'_>,
        raw_sha256: Sha256Digest,
    ) -> Result<Self, MaterializedPageTraceError> {
        if page.bytes().len() != RAW_PAGE_BYTES {
            return Err(MaterializedPageTraceError::UnexpectedRawPageLength {
                actual: page.bytes().len(),
            });
        }
        Ok(Self {
            snapshot,
            page_number: page.index(),
            raw_sha256,
            page_type_raw: page.trailer().page_type_raw,
            stored_crc32: page.stored_crc(),
        })
    }
}

/// A bounded, payload-free observation emitted by an external runtime tracer.
///
/// `raw_sha256` must be calculated over the raw page that the tracer asserts
/// it materialized, not over a decoded or runtime-owned buffer.  The remaining
/// fields are opaque trace labels and counts; this crate does not infer their
/// storage semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedPageTrace {
    /// Stable identifier assigned by the tracing run.
    pub trace_id: String,
    /// Identity of the immutable snapshot the tracer opened.
    pub snapshot: SourceSnapshotId,
    /// Physical raw page asserted to underlie the materialized page.
    pub page_number: u64,
    /// SHA-256 of the asserted raw 4096-byte page.
    pub raw_sha256: Sha256Digest,
    /// Number of bounded segments reported by the runtime observation.
    pub observed_segment_count: u32,
}

/// Caller-supplied coordinate of one record in a runtime materialized page.
///
/// The owner context and record ID use the runtime trace's own coordinate
/// system.  Neither value is a raw page number, raw byte offset, table ID, or
/// QuickBooks object identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaterializedRecordCoordinate {
    /// Opaque owner context emitted by the runtime observation.
    pub owner_context: u16,
    /// Opaque record identifier within that owner context.
    pub record_id: u16,
    /// Byte offset in the externally supplied materialized-page byte slice.
    pub byte_offset: usize,
}

impl MaterializedRecordCoordinate {
    /// Creates a caller-supplied materialized record coordinate.
    pub const fn new(owner_context: u16, record_id: u16, byte_offset: usize) -> Self {
        Self {
            owner_context,
            record_id,
            byte_offset,
        }
    }
}

/// Payload-free observation of one bounded materialized physical row record.
///
/// The bytes after its leading length are deliberately not assigned a
/// row-segment meaning. Materialized application rows use them as a null map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedRowRecordObservation {
    /// Trace that supplied the raw-page coordinate and materialized bytes.
    pub trace_id: String,
    /// Caller-supplied runtime coordinate of this record.
    pub coordinate: MaterializedRecordCoordinate,
    /// Row length validated against the supplied materialized-page bytes.
    pub declared_len: usize,
}

/// Caller assertion that a particular materialized record is known, from
/// independent evidence, to use the SA17 row-segment carrier dialect.
///
/// This opt-in marker prevents normal application rows from being silently
/// interpreted as row segments merely because their null-map byte resembles a
/// segment flag byte.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RowSegmentCarrierEvidence;

/// Payload-free observation of an explicitly attested row-segment carrier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedRowSegmentObservation {
    /// Record facts validated before carrier interpretation.
    pub record: MaterializedRowRecordObservation,
    /// Uninterpreted row-segment header flags.
    pub flags: u8,
    /// Header length selected solely by the proven continuation bit.
    pub header_len: usize,
    /// Length of the checked payload after the selected header.
    pub payload_len: usize,
    /// Unresolved continuation target, when the continuation bit is set.
    pub continuation_target: Option<ContinuationTarget>,
}

/// Validates and observes one externally located materialized row record
/// without retaining its payload.
///
/// The caller owns both `coordinate` and the materialized page bytes. This
/// function resolves `record_id` through the checked type-4 page directory
/// and rejects a disagreement with `byte_offset`. It does not derive either
/// coordinate from raw QBW bytes and does not assert that the supplied
/// materialized page was produced from `trace`; use
/// [`correlate_materialized_page_traces`] to check the external raw-page
/// mapping separately.
pub fn observe_materialized_row_record(
    trace: &MaterializedPageTrace,
    coordinate: MaterializedRecordCoordinate,
    materialized_page_bytes: &[u8],
) -> Result<MaterializedRowRecordObservation, MaterializedPageTraceError> {
    if materialized_page_bytes.len() != RAW_PAGE_BYTES {
        return Err(
            MaterializedPageTraceError::UnexpectedMaterializedPageLength {
                actual: materialized_page_bytes.len(),
            },
        );
    }
    let page = MaterializedTablePage::parse(materialized_page_bytes)
        .map_err(MaterializedPageTraceError::InvalidMaterializedTablePage)?;
    let record = page
        .record(coordinate.record_id)
        .map_err(MaterializedPageTraceError::InvalidMaterializedTablePage)?;
    if record.byte_offset() != coordinate.byte_offset {
        return Err(
            MaterializedPageTraceError::MaterializedRecordByteOffsetMismatch {
                record_id: coordinate.record_id,
                observed_offset: coordinate.byte_offset,
                resolved_offset: record.byte_offset(),
            },
        );
    }
    Ok(MaterializedRowRecordObservation {
        trace_id: trace.trace_id.clone(),
        coordinate,
        declared_len: record.declared_len(),
    })
}

/// Observe a materialized record as an SA17 row segment only after an explicit
/// caller-owned carrier attestation.
pub fn observe_materialized_row_segment(
    trace: &MaterializedPageTrace,
    coordinate: MaterializedRecordCoordinate,
    materialized_page_bytes: &[u8],
    _carrier: RowSegmentCarrierEvidence,
) -> Result<MaterializedRowSegmentObservation, MaterializedPageTraceError> {
    let record = observe_materialized_row_record(trace, coordinate, materialized_page_bytes)?;
    let page = MaterializedTablePage::parse(materialized_page_bytes)
        .map_err(MaterializedPageTraceError::InvalidMaterializedTablePage)?;
    let physical = page
        .record(coordinate.record_id)
        .map_err(MaterializedPageTraceError::InvalidMaterializedTablePage)?;
    let segment = physical.as_row_segment().map_err(|source| {
        MaterializedPageTraceError::InvalidMaterializedRowSegment {
            record_id: coordinate.record_id,
            source,
        }
    })?;
    Ok(MaterializedRowSegmentObservation {
        record,
        flags: segment.flags(),
        header_len: segment.header_len(),
        payload_len: segment.payload().len(),
        continuation_target: segment.next_target(),
    })
}

impl MaterializedPageTrace {
    /// Creates a trace observation, rejecting an empty trace identifier.
    pub fn new(
        trace_id: impl Into<String>,
        snapshot: SourceSnapshotId,
        page_number: u64,
        raw_sha256: Sha256Digest,
        observed_segment_count: u32,
    ) -> Result<Self, MaterializedPageTraceError> {
        let trace_id = trace_id.into();
        if trace_id.trim().is_empty() {
            return Err(MaterializedPageTraceError::EmptyTraceId);
        }
        Ok(Self {
            trace_id,
            snapshot,
            page_number,
            raw_sha256,
            observed_segment_count,
        })
    }
}

/// Outcome for one external runtime trace observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PageTraceCorrelation {
    /// Snapshot, page number, and raw digest all matched one raw witness.
    Matched {
        /// Caller-assigned external trace identifier.
        trace_id: String,
        /// Number of opaque runtime segments the tracer observed.
        observed_segment_count: u32,
        /// Raw trailer type, copied only after an exact match.
        page_type_raw: u8,
        /// Stored raw-page CRC, copied only after an exact match.
        stored_crc32: u32,
    },
    /// No raw witness was supplied for the trace's snapshot/page coordinate.
    MissingRawWitness {
        /// Caller-assigned external trace identifier.
        trace_id: String,
    },
    /// A witness existed at the coordinate, but its raw bytes did not match.
    RawDigestMismatch {
        /// Caller-assigned external trace identifier.
        trace_id: String,
    },
}

/// Deterministic correlation result, in supplied trace order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageTraceCorrelationReport {
    /// One result per supplied trace, preserving trace order.
    pub outcomes: Vec<PageTraceCorrelation>,
}

/// Correlates payload-free runtime trace observations with raw-page witnesses.
///
/// This confirms only an externally asserted raw-page mapping.  A `Matched`
/// result does not prove table ownership, row boundaries, continuation links,
/// field locations, or any accounting interpretation.
pub fn correlate_materialized_page_traces(
    raw_witnesses: impl IntoIterator<Item = RawPageWitness>,
    traces: impl IntoIterator<Item = MaterializedPageTrace>,
) -> Result<PageTraceCorrelationReport, MaterializedPageTraceError> {
    let mut by_coordinate = BTreeMap::new();
    for witness in raw_witnesses {
        let key = (witness.snapshot.clone(), witness.page_number);
        if by_coordinate.insert(key.clone(), witness).is_some() {
            return Err(MaterializedPageTraceError::DuplicateRawWitness {
                snapshot: key.0.as_str().to_owned(),
                page_number: key.1,
            });
        }
    }

    let mut trace_ids = BTreeSet::new();
    let mut outcomes = Vec::new();
    for trace in traces {
        if !trace_ids.insert(trace.trace_id.clone()) {
            return Err(MaterializedPageTraceError::DuplicateTraceId(trace.trace_id));
        }
        let key = (trace.snapshot.clone(), trace.page_number);
        let outcome = match by_coordinate.get(&key) {
            None => PageTraceCorrelation::MissingRawWitness {
                trace_id: trace.trace_id,
            },
            Some(witness) if witness.raw_sha256 != trace.raw_sha256 => {
                PageTraceCorrelation::RawDigestMismatch {
                    trace_id: trace.trace_id,
                }
            }
            Some(witness) => PageTraceCorrelation::Matched {
                trace_id: trace.trace_id,
                observed_segment_count: trace.observed_segment_count,
                page_type_raw: witness.page_type_raw,
                stored_crc32: witness.stored_crc32,
            },
        };
        outcomes.push(outcome);
    }
    Ok(PageTraceCorrelationReport { outcomes })
}

/// Validation failures in the raw-page/runtime-trace correlation boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaterializedPageTraceError {
    /// The caller supplied an invalid SHA-256 digest.
    InvalidSha256,
    /// A raw-page source did not provide the fixed 4096-byte page size.
    UnexpectedRawPageLength {
        /// Actual byte length reported by the source page view.
        actual: usize,
    },
    /// A caller-supplied materialized page did not have the fixed page size.
    UnexpectedMaterializedPageLength {
        /// Actual byte length supplied by the external trace.
        actual: usize,
    },
    /// The supplied materialized page was not a fully-valid type-4 page, or
    /// its requested page-local record was unavailable.
    InvalidMaterializedTablePage(MaterializedPageError),
    /// An explicitly attested row-segment carrier did not satisfy the bounded
    /// SA17 row-segment grammar.
    InvalidMaterializedRowSegment {
        /// Requested page-local record identifier.
        record_id: u16,
        /// Fail-closed row-segment boundary error.
        source: RowSegmentError,
    },
    /// The externally reported byte offset disagreed with the checked page
    /// directory resolution for the supplied record ID.
    MaterializedRecordByteOffsetMismatch {
        /// Requested page-local record identifier.
        record_id: u16,
        /// Externally observed byte offset.
        observed_offset: usize,
        /// Offset resolved from the checked page directory.
        resolved_offset: usize,
    },
    /// A runtime trace lacked a caller-assigned identifier.
    EmptyTraceId,
    /// More than one raw witness claimed the same snapshot/page coordinate.
    DuplicateRawWitness {
        /// Duplicate snapshot identity.
        snapshot: String,
        /// Duplicate physical page number within that snapshot.
        page_number: u64,
    },
    /// More than one runtime observation used the same trace ID.
    DuplicateTraceId(String),
}

impl std::fmt::Display for MaterializedPageTraceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSha256 => {
                f.write_str("SHA-256 digest must be 64 lowercase hexadecimal characters")
            }
            Self::UnexpectedRawPageLength { actual } => {
                write!(f, "raw page had {actual} bytes, expected {RAW_PAGE_BYTES}")
            }
            Self::UnexpectedMaterializedPageLength { actual } => write!(
                f,
                "materialized page had {actual} bytes, expected {RAW_PAGE_BYTES}"
            ),
            Self::InvalidMaterializedTablePage(source) => {
                write!(f, "materialized table page was invalid: {source}")
            }
            Self::InvalidMaterializedRowSegment { record_id, source } => write!(
                f,
                "materialized record id {record_id} was not a valid attested row segment: {source}"
            ),
            Self::MaterializedRecordByteOffsetMismatch {
                record_id,
                observed_offset,
                resolved_offset,
            } => write!(
                f,
                "materialized record id {record_id} resolved to offset {resolved_offset}, not observed offset {observed_offset}"
            ),
            Self::EmptyTraceId => f.write_str("runtime trace identifier was empty"),
            Self::DuplicateRawWitness {
                snapshot,
                page_number,
            } => {
                write!(
                    f,
                    "duplicate raw witness for snapshot {snapshot}, page {page_number}"
                )
            }
            Self::DuplicateTraceId(trace_id) => {
                write!(f, "duplicate runtime trace identifier {trace_id}")
            }
        }
    }
}

impl std::error::Error for MaterializedPageTraceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidMaterializedTablePage(source) => Some(source),
            Self::InvalidMaterializedRowSegment { source, .. } => Some(source),
            Self::InvalidSha256
            | Self::UnexpectedRawPageLength { .. }
            | Self::UnexpectedMaterializedPageLength { .. }
            | Self::MaterializedRecordByteOffsetMismatch { .. }
            | Self::EmptyTraceId
            | Self::DuplicateRawWitness { .. }
            | Self::DuplicateTraceId(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use opensqlany::{MaterializedPageError, Page};

    use super::*;

    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn snapshot() -> SourceSnapshotId {
        SourceSnapshotId::new("sha256:file-a").unwrap()
    }

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::new(value).unwrap()
    }

    fn witness() -> RawPageWitness {
        let mut bytes = [0_u8; RAW_PAGE_BYTES];
        bytes[0xff2] = b'E';
        bytes[0xffc..].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        RawPageWitness::from_raw_page(snapshot(), Page::from_bytes(42, &bytes), digest(DIGEST_A))
            .unwrap()
    }

    #[test]
    fn exact_coordinate_and_digest_match_retains_only_safe_facts() {
        let trace =
            MaterializedPageTrace::new("trace-1", snapshot(), 42, digest(DIGEST_A), 3).unwrap();
        let report = correlate_materialized_page_traces([witness()], [trace]).unwrap();
        assert_eq!(
            report.outcomes,
            vec![PageTraceCorrelation::Matched {
                trace_id: "trace-1".into(),
                observed_segment_count: 3,
                page_type_raw: b'E',
                stored_crc32: 0x1234_5678,
            }]
        );
    }

    #[test]
    fn same_coordinate_with_a_different_digest_does_not_match() {
        let trace =
            MaterializedPageTrace::new("trace-1", snapshot(), 42, digest(DIGEST_B), 0).unwrap();
        let report = correlate_materialized_page_traces([witness()], [trace]).unwrap();
        assert_eq!(
            report.outcomes,
            vec![PageTraceCorrelation::RawDigestMismatch {
                trace_id: "trace-1".into(),
            }]
        );
    }

    #[test]
    fn absent_coordinate_is_reported_without_guessing_another_page() {
        let trace =
            MaterializedPageTrace::new("trace-1", snapshot(), 43, digest(DIGEST_A), 1).unwrap();
        let report = correlate_materialized_page_traces([witness()], [trace]).unwrap();
        assert_eq!(
            report.outcomes,
            vec![PageTraceCorrelation::MissingRawWitness {
                trace_id: "trace-1".into(),
            }]
        );
    }

    #[test]
    fn duplicate_trace_ids_are_rejected() {
        let first =
            MaterializedPageTrace::new("same", snapshot(), 42, digest(DIGEST_A), 0).unwrap();
        let second =
            MaterializedPageTrace::new("same", snapshot(), 43, digest(DIGEST_A), 0).unwrap();
        assert_eq!(
            correlate_materialized_page_traces([witness()], [first, second]),
            Err(MaterializedPageTraceError::DuplicateTraceId("same".into()))
        );
    }

    fn trace() -> MaterializedPageTrace {
        MaterializedPageTrace::new("trace-1", snapshot(), 42, digest(DIGEST_A), 0).unwrap()
    }

    fn materialized_page(record_count: u16) -> [u8; RAW_PAGE_BYTES] {
        let mut page = [0_u8; RAW_PAGE_BYTES];
        page[0x10] = 4;
        page[0x16..0x18].copy_from_slice(&record_count.to_le_bytes());
        page
    }

    fn set_record(page: &mut [u8], record_id: u16, byte_offset: usize, segment: &[u8]) {
        assert!(byte_offset >= 0x1c);
        let directory_entry = 0x1c + usize::from(record_id) * 2;
        page[directory_entry..directory_entry + 2]
            .copy_from_slice(&u16::try_from(byte_offset - 0x1c).unwrap().to_le_bytes());
        page[byte_offset..byte_offset + segment.len()].copy_from_slice(segment);
    }

    #[test]
    fn explicitly_attested_segment_observation_keeps_only_segment_header_facts() {
        let mut page = materialized_page(10);
        // len=11, continued flag, resolver key=0x44332211, record=0x6655,
        // then two payload bytes. The final two bytes are deliberately ignored.
        set_record(
            &mut page,
            9,
            100,
            &[
                11, 0, 0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xAA, 0xBB, 0xCC, 0xDD,
            ],
        );
        let observation = observe_materialized_row_segment(
            &trace(),
            MaterializedRecordCoordinate::new(7, 9, 100),
            &page,
            RowSegmentCarrierEvidence,
        )
        .unwrap();
        assert_eq!(observation.record.trace_id, "trace-1");
        assert_eq!(
            observation.record.coordinate,
            MaterializedRecordCoordinate::new(7, 9, 100)
        );
        assert_eq!(observation.record.declared_len, 11);
        assert_eq!(observation.flags, 0x04);
        assert_eq!(observation.header_len, 9);
        assert_eq!(observation.payload_len, 2);
        assert_eq!(
            observation.continuation_target,
            Some(ContinuationTarget::new(0x4433_2211, 0x6655))
        );
    }

    #[test]
    fn materialized_record_observation_rejects_a_page_with_an_invalid_directory_record() {
        let mut page = materialized_page(1);
        set_record(&mut page, 0, 4094, &[5, 0]);
        assert_eq!(
            observe_materialized_row_record(
                &trace(),
                MaterializedRecordCoordinate::new(0, 0, 4094),
                &page,
            ),
            Err(MaterializedPageTraceError::InvalidMaterializedTablePage(
                MaterializedPageError::InvalidRecordLength {
                    record_id: 0,
                    directory_offset: 4094 - 0x1c,
                    declared: 5,
                    available: 2,
                }
            ))
        );
    }

    #[test]
    fn materialized_observation_rejects_mismatched_directory_offset() {
        let mut page = materialized_page(1);
        set_record(&mut page, 0, 100, &[3, 0, 0]);

        assert_eq!(
            observe_materialized_row_record(
                &trace(),
                MaterializedRecordCoordinate::new(0, 0, 101),
                &page,
            ),
            Err(
                MaterializedPageTraceError::MaterializedRecordByteOffsetMismatch {
                    record_id: 0,
                    observed_offset: 101,
                    resolved_offset: 100,
                }
            )
        );
    }
}

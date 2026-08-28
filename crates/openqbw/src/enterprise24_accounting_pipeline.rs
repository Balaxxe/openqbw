//! Evidence-bound Enterprise 24 accounting extraction orchestration.
//!
//! This module is deliberately a *pipeline*, rather than another row parser.
//! It connects the one-pass page inventory, versioned partial-prefix policies,
//! candidate consensus, Account identity resolution, and the normalized ledger
//! hand-off contract.  A successful partial decode is not a claim that the
//! complete physical row is understood.  Consequently, a missing family,
//! unresolved page candidate, or an explicitly unsupported family prevents
//! construction of [`crate::DecodedAccounts`], [`crate::DecodedPostings`], and
//! [`crate::Ledger`].

use std::collections::BTreeMap;

use opensqlany::{
    BooleanTailLayout, EnumLayout, NullBitmapCoverage, NullBitmapLayout, NumericLayout,
    PartialDecodedRow, RowPrefixLayout, RowSchema, VariableLengthLayout, VariableOverflowLayout,
    decode_row_prefix_and_boolean_tail,
};
use thiserror::Error;

use crate::{
    AccountId, AccountRowStateEvidence, CheckVoidCompanionMasterEvidence, CompleteCoverage,
    CurrentState, DebitCredit, DebitCreditAmount, DecodedAccounts, DecodedPostings,
    DecoderIdentity, Enterprise24AccountingTable, EnterprisePostingAdaptation,
    EnterprisePostingExclusion, EnterpriseTableScan, Ledger, LedgerAdapter, MaterializedAccountRow,
    MaterializedBillPostingRow, MaterializedCheckPostingRow, MaterializedCheckVoidCompanionCarrier,
    MaterializedGeneralJournalDisposition, Posting, PostingDisposition, PostingExclusion,
    PostingExclusionReason, PostingId, PostingProvenance, RowStorageAttestation, SourceSnapshotId,
    SysColumn, SysTableEntry, TransactionId, adapt_enterprise_posting_row_partial,
    adapt_materialized_bill_posting_row, adapt_materialized_check_posting_row,
    adapt_materialized_general_journal_posting_row, classify_materialized_check_void_companion,
    classify_materialized_general_journal_rows, decode_schema_account_row_partial,
    resolve_enterprise24_account_type18, validate_enterprise24_r21_schema_manifest,
};

/// Compatibility state of a table-bound partial decoder policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Enterprise24PartialPolicyStatus {
    /// The named prefix and Boolean sidecar may be decoded, but all later
    /// non-Boolean bytes remain opaque.
    Partial,
    /// The prefix boundary is known, but the exact storage layout is pending.
    LayoutPending,
    /// No production partial layout is available for this table.
    Unsupported,
}

/// One versioned, table-bound prefix policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Enterprise24PartialTablePolicy {
    /// Physical Enterprise table.
    pub table: Enterprise24AccountingTable,
    /// Stable policy/version label used in diagnostics and provenance.
    pub version: &'static str,
    /// Highest one-based catalog ordinal decoded by this policy.
    ///
    /// It is a prefix boundary, not a complete-row assertion.
    pub through_ordinal: Option<u32>,
    /// Whether this policy has a decoder at all.
    pub status: Enterprise24PartialPolicyStatus,
    /// Sole accepted row-storage layout when all of its parameters are proven.
    pub storage: Option<RowStorageAttestation>,
}

const PREFIX_TWO_DECLARED_4096_POINTER_16: RowStorageAttestation = RowStorageAttestation {
    uncompressed: true,
    boolean_tail: BooleanTailLayout::InlineBytes,
    numeric_layout: NumericLayout::EnterpriseMaterializedRaw,
    enum_layout: EnumLayout::Unsupported,
    variable_overflow_layout: VariableOverflowLayout::Pointer { width: 16 },
    variable_length_layout: VariableLengthLayout::DeclaredWidth {
        wide_at_or_above: 4096,
    },
    null_bitmap_layout: NullBitmapLayout::MsbPresent,
    null_bitmap_coverage: NullBitmapCoverage::NullableColumns,
    row_prefix_layout: RowPrefixLayout::TwoByteCarrier,
};

const PREFIX_TWO_U8: RowStorageAttestation = RowStorageAttestation {
    uncompressed: true,
    boolean_tail: BooleanTailLayout::InlineBytes,
    numeric_layout: NumericLayout::EnterpriseMaterializedRaw,
    enum_layout: EnumLayout::Unsupported,
    variable_overflow_layout: VariableOverflowLayout::Unsupported,
    variable_length_layout: VariableLengthLayout::U8,
    null_bitmap_layout: NullBitmapLayout::MsbPresent,
    null_bitmap_coverage: NullBitmapCoverage::NullableColumns,
    row_prefix_layout: RowPrefixLayout::TwoByteCarrier,
};

const PREFIX_ONE_U8: RowStorageAttestation = RowStorageAttestation {
    uncompressed: true,
    boolean_tail: BooleanTailLayout::InlineBytes,
    numeric_layout: NumericLayout::EnterpriseMaterializedRaw,
    enum_layout: EnumLayout::Unsupported,
    variable_overflow_layout: VariableOverflowLayout::Unsupported,
    variable_length_layout: VariableLengthLayout::U8,
    null_bitmap_layout: NullBitmapLayout::MsbPresent,
    null_bitmap_coverage: NullBitmapCoverage::NullableColumns,
    row_prefix_layout: RowPrefixLayout::OneByteCarrier,
};

/// Table-3047 e4 Check rows: bounded through `amount_amt` (ordinal 33),
/// with schema-derived variable-field framing and an inline Boolean sidecar.
const CHECK_PREFIX_ONE_DECLARED_4096_POINTER_16: RowStorageAttestation = RowStorageAttestation {
    uncompressed: true,
    boolean_tail: BooleanTailLayout::InlineBytes,
    numeric_layout: NumericLayout::EnterpriseMaterializedRaw,
    enum_layout: EnumLayout::Unsupported,
    variable_overflow_layout: VariableOverflowLayout::Pointer { width: 16 },
    variable_length_layout: VariableLengthLayout::DeclaredWidth {
        wide_at_or_above: 4096,
    },
    null_bitmap_layout: NullBitmapLayout::MsbPresent,
    null_bitmap_coverage: NullBitmapCoverage::NullableColumns,
    row_prefix_layout: RowPrefixLayout::OneByteCarrier,
};

/// Current R21 partial-prefix policies.
///
/// The boundaries are the evidence-backed probe boundaries. Dedicated physical
/// grammars are collected separately from schema-prefix layouts.
pub const ENTERPRISE24_R21_PARTIAL_TABLE_POLICIES: [Enterprise24PartialTablePolicy; 6] = [
    Enterprise24PartialTablePolicy {
        table: Enterprise24AccountingTable::AccountUser,
        version: "enterprise24-r21-account-prefix-v1",
        through_ordinal: Some(24),
        status: Enterprise24PartialPolicyStatus::Partial,
        storage: Some(PREFIX_TWO_DECLARED_4096_POINTER_16),
    },
    Enterprise24PartialTablePolicy {
        table: Enterprise24AccountingTable::BillPaymentCheckLine,
        version: "enterprise24-r21-bill-payment-check-prefix-v1",
        through_ordinal: Some(33),
        status: Enterprise24PartialPolicyStatus::Partial,
        storage: Some(PREFIX_TWO_DECLARED_4096_POINTER_16),
    },
    Enterprise24PartialTablePolicy {
        table: Enterprise24AccountingTable::BillLine,
        version: "enterprise24-r21-bill-prefix-v1",
        through_ordinal: Some(34),
        status: Enterprise24PartialPolicyStatus::Partial,
        storage: Some(PREFIX_TWO_U8),
    },
    Enterprise24PartialTablePolicy {
        table: Enterprise24AccountingTable::CheckLine,
        // E4 accounting rows are schema-decoded only through amount ordinal
        // 33. The fixed kind-64 void companions remain carrier-only rows.
        version: "enterprise24-r21-check-e4-prefix-v2",
        through_ordinal: Some(33),
        status: Enterprise24PartialPolicyStatus::Partial,
        storage: Some(CHECK_PREFIX_ONE_DECLARED_4096_POINTER_16),
    },
    Enterprise24PartialTablePolicy {
        table: Enterprise24AccountingTable::DepositLine,
        version: "enterprise24-r21-deposit-prefix-v1",
        through_ordinal: Some(28),
        status: Enterprise24PartialPolicyStatus::Partial,
        storage: Some(PREFIX_ONE_U8),
    },
    Enterprise24PartialTablePolicy {
        table: Enterprise24AccountingTable::GeneralJournalLine,
        version: "enterprise24-r21-general-journal-materialized-v1",
        through_ordinal: None,
        status: Enterprise24PartialPolicyStatus::Partial,
        storage: None,
    },
];

/// Looks up the policy for an accounting line or Account table.
#[must_use]
pub fn enterprise24_r21_partial_table_policy(
    table: Enterprise24AccountingTable,
) -> Option<Enterprise24PartialTablePolicy> {
    ENTERPRISE24_R21_PARTIAL_TABLE_POLICIES
        .iter()
        .copied()
        .find(|policy| policy.table == table)
}

fn policy_schema_matches(policy: Enterprise24PartialTablePolicy, schema: &RowSchema) -> bool {
    let Some(storage) = policy.storage else {
        return false;
    };
    storage.uncompressed
        && schema.boolean_tail == storage.boolean_tail
        && schema.numeric_layout == storage.numeric_layout
        && schema.enum_layout == storage.enum_layout
        && schema.variable_overflow_layout == storage.variable_overflow_layout
        && schema.variable_length_layout == storage.variable_length_layout
        && schema.null_bitmap_layout == storage.null_bitmap_layout
        && schema.null_bitmap_coverage == storage.null_bitmap_coverage
        && schema.row_prefix_layout == storage.row_prefix_layout
}

/// One candidate record after a versioned partial decode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Enterprise24PartialRecordCandidate {
    /// Exact materialized record bytes retained only while local extraction runs.
    pub bytes: Vec<u8>,
    /// Prefix and Boolean-tail values established by the table policy.
    pub partial: PartialDecodedRow,
}

/// One consensus-resolved logical physical row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Enterprise24PartialRecord {
    /// Raw QBW page number.
    pub raw_page_number: u64,
    /// Materialized page directory record identifier.
    pub record_id: u16,
    /// One candidate's raw row bytes. Equal prefix semantics, not equal opaque
    /// bytes, is the candidate-resolution condition.
    pub bytes: Vec<u8>,
    /// Consensus prefix/Boolean-tail values.
    pub partial: PartialDecodedRow,
}

/// Resolves a row's materialization candidates only when their decoded prefix
/// semantics agree exactly.
///
/// Opaque bytes may differ because this pipeline deliberately does not claim
/// to decode later columns. The returned candidate is therefore only a carrier
/// for the first bounded byte sequence and the consensus partial value; it is
/// never a justification for choosing one opaque-tail interpretation.
#[must_use]
pub fn resolve_enterprise24_partial_record_candidates(
    candidates: &[Enterprise24PartialRecordCandidate],
) -> Option<Enterprise24PartialRecordCandidate> {
    let first = candidates.first()?;
    candidates
        .iter()
        .skip(1)
        .all(|candidate| candidate.partial == first.partial)
        .then(|| first.clone())
}

/// Complete candidate-resolution accounting for one partial table scan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Enterprise24PartialTableCoverage {
    /// Physical table being covered.
    pub table_id: u32,
    /// Candidate page groups considered.
    pub candidate_page_groups: u64,
    /// Independent persisted SYSTABLE logical row count.
    pub expected_logical_records: Option<u64>,
    /// Independent persisted SYSTABLE table page count.
    pub expected_table_pages: Option<u32>,
    /// Independently persisted count of external table pages.  Enterprise
    /// table-page groups cover both the primary and external page lists.
    pub expected_external_table_pages: Option<u32>,
    /// Resolved physical logical rows.
    pub resolved_records: u64,
    /// Candidate groups/records that could not produce one consensus result.
    pub unresolved_records: u64,
    /// Missing materialized directory entries observed in any candidate.
    pub missing_records: u64,
    /// Directory record identifiers whose availability differed between
    /// materialization candidates. This includes record IDs outside one
    /// candidate's declared directory domain. Such a page has no consensus
    /// carrier for those IDs and cannot yield complete extraction coverage.
    pub candidate_directory_disagreements: u64,
    /// Rows rejected by the partial decoder.
    pub decode_failures: u64,
    /// Bounded directory carriers proven not to be rows in this table's
    /// logical row domain. They remain counted rather than being discarded.
    pub non_row_artifacts: u64,
    /// Explicitly unsupported policy, if applicable.
    pub unsupported: bool,
    /// The prefix is known but storage facts required for decoding are absent.
    pub layout_pending: bool,
}

impl Enterprise24PartialTableCoverage {
    fn complete(&self) -> bool {
        !self.unsupported
            && !self.layout_pending
            && self.unresolved_records == 0
            && self.decode_failures == 0
            && self.candidate_directory_disagreements == 0
            && self.expected_logical_records == Some(self.resolved_records)
            && self.expected_table_pages.is_none_or(|primary| {
                primary
                    .checked_add(self.expected_external_table_pages.unwrap_or(0))
                    .is_some_and(|expected| expected == self.candidate_page_groups as u32)
            })
    }
}

/// Independent logical table coverage read from SYSTABLE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Enterprise24TableCoverageExpectation {
    /// Persisted logical application row count.
    pub logical_records: u64,
    /// Persisted count of table pages.
    pub table_pages: u32,
    /// Persisted external-table page count.
    pub external_table_pages: u32,
}

impl From<&SysTableEntry> for Enterprise24TableCoverageExpectation {
    fn from(table: &SysTableEntry) -> Self {
        Self {
            logical_records: table.row_count,
            table_pages: table.table_page_count,
            external_table_pages: table.ext_page_count,
        }
    }
}

/// A partial table collection with no implicit candidate selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Enterprise24PartialTableRows {
    /// Table policy used to decode rows.
    pub policy: Enterprise24PartialTablePolicy,
    /// Consensus-resolved rows.
    pub records: Vec<Enterprise24PartialRecord>,
    /// Coverage and unresolved-candidate diagnostics.
    pub coverage: Enterprise24PartialTableCoverage,
}

/// Candidate-directory consensus for one materialized page group.
///
/// The common record IDs are the intersection of every candidate directory's
/// in-range, present entries. Empty slots agreed by every candidate are
/// preserved separately, while any non-uniform availability or record-count
/// domain is retained as a fail-closed disagreement. In particular, callers
/// must never iterate the maximum candidate record count and treat its tail
/// as source rows.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct CandidateDirectoryConsensus {
    common_record_ids: Vec<u16>,
    agreed_empty_record_ids: Vec<u16>,
    disagreement_record_count: u64,
}

fn candidate_directory_consensus<F>(
    record_counts: &[u16],
    mut present: F,
) -> CandidateDirectoryConsensus
where
    F: FnMut(usize, u16) -> bool,
{
    let Some(&minimum_count) = record_counts.iter().min() else {
        return CandidateDirectoryConsensus::default();
    };
    let maximum_count = record_counts.iter().copied().max().unwrap_or(minimum_count);
    let mut result = CandidateDirectoryConsensus {
        disagreement_record_count: u64::from(maximum_count - minimum_count),
        ..CandidateDirectoryConsensus::default()
    };
    for record_id in 0..minimum_count {
        let present_count = record_counts
            .iter()
            .enumerate()
            .filter(|(candidate_index, _)| present(*candidate_index, record_id))
            .count();
        if present_count == record_counts.len() {
            result.common_record_ids.push(record_id);
        } else if present_count == 0 {
            result.agreed_empty_record_ids.push(record_id);
        } else {
            result.disagreement_record_count += 1;
        }
    }
    result
}

/// Extracts partial rows from an already one-pass-scanned table.
///
/// Every materialization candidate for a `(page, record_id)` must decode to
/// identical partial semantics. Candidate byte differences in the opaque tail
/// do not select a winner. Missing slots and decoding failures are retained in
/// coverage. Empty directory slots are expected non-records; the independent
/// SYSTABLE logical-record and table-page expectations determine completeness.
pub fn collect_enterprise24_partial_table_rows(
    scan: &EnterpriseTableScan,
    policy: Enterprise24PartialTablePolicy,
    schema: &RowSchema,
    expectation: Enterprise24TableCoverageExpectation,
) -> Result<Enterprise24PartialTableRows, Enterprise24AccountingPipelineError> {
    // Bill's complete bounded carrier grammar is stricter than its current
    // prefix policy.  Route it before inspecting a generic schema so a
    // non-row directory artifact cannot be misreported as a schema failure.
    if policy.table == Enterprise24AccountingTable::BillLine {
        return collect_enterprise24_bill_table_rows(scan, expectation);
    }
    if scan.target_table_id != policy.table.id() {
        return Err(Enterprise24AccountingPipelineError::ScanTableMismatch {
            scan_table_id: scan.target_table_id,
            policy_table_id: policy.table.id(),
        });
    }
    let mut coverage = Enterprise24PartialTableCoverage {
        table_id: policy.table.id(),
        candidate_page_groups: scan.candidate_groups.len() as u64,
        expected_logical_records: Some(expectation.logical_records),
        expected_table_pages: Some(expectation.table_pages),
        expected_external_table_pages: Some(expectation.external_table_pages),
        unsupported: policy.status == Enterprise24PartialPolicyStatus::Unsupported,
        layout_pending: policy.status == Enterprise24PartialPolicyStatus::LayoutPending,
        ..Enterprise24PartialTableCoverage::default()
    };
    if policy.status != Enterprise24PartialPolicyStatus::Partial {
        return Ok(Enterprise24PartialTableRows {
            policy,
            records: Vec::new(),
            coverage,
        });
    }
    let Some(through) = policy.through_ordinal else {
        return Err(
            Enterprise24AccountingPipelineError::PolicyRequiresDedicatedCollector {
                table_id: policy.table.id(),
            },
        );
    };
    if !policy_schema_matches(policy, schema) {
        return Err(Enterprise24AccountingPipelineError::PolicyStorageMismatch {
            table_id: policy.table.id(),
        });
    }
    let mut records = Vec::new();
    for group in &scan.candidate_groups {
        let record_counts: Vec<_> = group
            .candidates
            .iter()
            .map(|candidate| candidate.table_page().record_count())
            .collect();
        let directory =
            candidate_directory_consensus(&record_counts, |candidate_index, record_id| {
                group.candidates[candidate_index]
                    .table_page()
                    .record(record_id)
                    .is_ok()
            });
        coverage.missing_records += directory.agreed_empty_record_ids.len() as u64;
        coverage.candidate_directory_disagreements += directory.disagreement_record_count;
        for record_id in directory.common_record_ids {
            let mut decoded = Vec::new();
            let mut any_failure = false;
            for page in &group.candidates {
                let record = page
                    .table_page()
                    .record(record_id)
                    .expect("candidate-directory consensus established presence");
                let bytes = record.bytes().to_vec();
                match decode_row_prefix_and_boolean_tail(&bytes, schema, through) {
                    Ok(partial) => {
                        decoded.push(Enterprise24PartialRecordCandidate { bytes, partial })
                    }
                    Err(_) => any_failure = true,
                }
            }
            if any_failure {
                coverage.decode_failures += 1;
            }
            if any_failure || decoded.len() != group.candidates.len() {
                coverage.unresolved_records += 1;
                continue;
            }
            let Some(first) = resolve_enterprise24_partial_record_candidates(&decoded) else {
                coverage.unresolved_records += 1;
                continue;
            };
            coverage.resolved_records += 1;
            records.push(Enterprise24PartialRecord {
                raw_page_number: group.raw_page_number,
                record_id,
                bytes: first.bytes,
                partial: first.partial,
            });
        }
    }
    Ok(Enterprise24PartialTableRows {
        policy,
        records,
        coverage,
    })
}

/// Collects table-3042 Bill carriers with the complete bounded Bill grammar.
///
/// SYSTABLE's logical row count for this family counts the 2,349 semantic
/// Bill lines, rather than every nonzero physical directory slot.  The R21
/// corpus also contains one bounded, nine-byte non-row carrier.  It is kept
/// in `non_row_artifacts` and is accepted only after the strict Bill rows
/// independently meet the persisted logical-row count.  This collector never
/// chooses a materialization candidate: candidates must parse to equal Bill
/// semantics, or agree on the exact bounded non-row artifact shape.
pub fn collect_enterprise24_bill_table_rows(
    scan: &EnterpriseTableScan,
    expectation: Enterprise24TableCoverageExpectation,
) -> Result<Enterprise24PartialTableRows, Enterprise24AccountingPipelineError> {
    let policy = enterprise24_r21_partial_table_policy(Enterprise24AccountingTable::BillLine)
        .expect("Bill policy is static");
    if scan.target_table_id != policy.table.id() {
        return Err(Enterprise24AccountingPipelineError::ScanTableMismatch {
            scan_table_id: scan.target_table_id,
            policy_table_id: policy.table.id(),
        });
    }
    let mut coverage = Enterprise24PartialTableCoverage {
        table_id: policy.table.id(),
        candidate_page_groups: scan.candidate_groups.len() as u64,
        expected_logical_records: Some(expectation.logical_records),
        expected_table_pages: Some(expectation.table_pages),
        expected_external_table_pages: Some(expectation.external_table_pages),
        ..Enterprise24PartialTableCoverage::default()
    };
    let mut records = Vec::new();
    for group in &scan.candidate_groups {
        let counts = group
            .candidates
            .iter()
            .map(|page| page.table_page().record_count())
            .collect::<Vec<_>>();
        let directory = candidate_directory_consensus(&counts, |candidate, record| {
            group.candidates[candidate]
                .table_page()
                .record(record)
                .is_ok()
        });
        coverage.missing_records += directory.agreed_empty_record_ids.len() as u64;
        coverage.candidate_directory_disagreements += directory.disagreement_record_count;
        for record_id in directory.common_record_ids {
            let candidates = group
                .candidates
                .iter()
                .map(|page| {
                    page.table_page()
                        .record(record_id)
                        .expect("candidate-directory consensus established presence")
                        .bytes()
                        .to_vec()
                })
                .collect::<Vec<_>>();
            let parsed = candidates
                .iter()
                .map(|bytes| MaterializedBillPostingRow::parse(bytes))
                .collect::<Vec<_>>();
            if parsed.iter().all(Result::is_ok) {
                let first = parsed[0].as_ref().expect("all candidates parsed");
                if !parsed
                    .iter()
                    .skip(1)
                    .all(|candidate| candidate.as_ref() == Ok(first))
                {
                    coverage.unresolved_records += 1;
                    continue;
                }
                let bytes = candidates[0].clone();
                coverage.resolved_records += 1;
                records.push(Enterprise24PartialRecord {
                    raw_page_number: group.raw_page_number,
                    record_id,
                    partial: empty_physical_partial(&bytes),
                    bytes,
                });
            } else if parsed.iter().all(Result::is_err)
                && candidates
                    .iter()
                    .all(|bytes| is_r21_bill_non_row_artifact(bytes))
            {
                // This remains a counted physical carrier. Its exclusion is
                // validated by the independent semantic-row count in
                // `Enterprise24PartialTableCoverage::complete`.
                coverage.non_row_artifacts += 1;
            } else {
                coverage.decode_failures += 1;
                coverage.unresolved_records += 1;
            }
        }
    }
    Ok(Enterprise24PartialTableRows {
        policy,
        records,
        coverage,
    })
}

fn empty_physical_partial(bytes: &[u8]) -> PartialDecodedRow {
    PartialDecodedRow {
        declared_size: bytes.len(),
        flags: u16::from(bytes.get(2).copied().unwrap_or_default()),
        through_ordinal: 0,
        prefix_values: Vec::new(),
        boolean_values: Vec::new(),
        opaque_middle_len: bytes.len(),
    }
}

/// The sole R21 table-3042 directory artifact observed outside SYSTABLE's
/// logical row domain.  It is deliberately narrow: a future compact Bill row
/// does not become an artifact merely because the full Bill parser rejects it.
fn is_r21_bill_non_row_artifact(bytes: &[u8]) -> bool {
    bytes.len() == 9
        && bytes
            .get(..2)
            .is_some_and(|length| u16::from_le_bytes([length[0], length[1]]) == 9)
        && bytes.get(2).copied() == Some(0x44)
        && bytes.get(3).copied() == Some(0x08)
        && bytes.get(4).copied() == Some(0x4a)
}

/// Collects table-3047 using semantic prefix consensus for e4 accounting rows
/// while retaining kind-64 void companions as exact bounded carriers.
///
/// The caller supplies the policy-attested full catalog schema. E4 rows are
/// decoded only through ordinal 33; later non-Boolean bytes remain opaque.
/// A kind-64 row is accepted only through the independent fixed carrier
/// parser, so it cannot be mistaken for a schema posting row.
pub fn collect_enterprise24_check_prefix_table_rows(
    scan: &EnterpriseTableScan,
    schema: &RowSchema,
    expectation: Enterprise24TableCoverageExpectation,
) -> Result<Enterprise24PartialTableRows, Enterprise24AccountingPipelineError> {
    let policy = enterprise24_r21_partial_table_policy(Enterprise24AccountingTable::CheckLine)
        .expect("Check policy is static");
    if scan.target_table_id != policy.table.id() {
        return Err(Enterprise24AccountingPipelineError::ScanTableMismatch {
            scan_table_id: scan.target_table_id,
            policy_table_id: policy.table.id(),
        });
    }
    if !policy_schema_matches(policy, schema) {
        return Err(Enterprise24AccountingPipelineError::PolicyStorageMismatch {
            table_id: policy.table.id(),
        });
    }
    let through = policy
        .through_ordinal
        .expect("Check prefix policy has a bounded amount ordinal");
    let mut coverage = Enterprise24PartialTableCoverage {
        table_id: policy.table.id(),
        candidate_page_groups: scan.candidate_groups.len() as u64,
        expected_logical_records: Some(expectation.logical_records),
        expected_table_pages: Some(expectation.table_pages),
        expected_external_table_pages: Some(expectation.external_table_pages),
        ..Enterprise24PartialTableCoverage::default()
    };
    let mut records = Vec::new();
    for group in &scan.candidate_groups {
        let record_counts: Vec<_> = group
            .candidates
            .iter()
            .map(|candidate| candidate.table_page().record_count())
            .collect();
        let directory =
            candidate_directory_consensus(&record_counts, |candidate_index, record_id| {
                group.candidates[candidate_index]
                    .table_page()
                    .record(record_id)
                    .is_ok()
            });
        coverage.missing_records += directory.agreed_empty_record_ids.len() as u64;
        coverage.candidate_directory_disagreements += directory.disagreement_record_count;
        for record_id in directory.common_record_ids {
            let mut prefix_candidates = Vec::new();
            let mut companion_candidates = Vec::new();
            let mut failure = false;
            for page in &group.candidates {
                let record = page
                    .table_page()
                    .record(record_id)
                    .expect("candidate-directory consensus established presence");
                let bytes = record.bytes().to_vec();
                if let Ok(companion) = MaterializedCheckVoidCompanionCarrier::parse(&bytes) {
                    companion_candidates.push((bytes, companion));
                } else if let Ok(partial) =
                    decode_row_prefix_and_boolean_tail(&bytes, schema, through)
                {
                    prefix_candidates.push(Enterprise24PartialRecordCandidate { bytes, partial });
                } else {
                    failure = true;
                }
            }
            if failure
                || (!prefix_candidates.is_empty() && !companion_candidates.is_empty())
                || (prefix_candidates.len() + companion_candidates.len() != group.candidates.len())
            {
                coverage.decode_failures += 1;
                coverage.unresolved_records += 1;
                continue;
            }
            if let Some((bytes, first)) = companion_candidates.first() {
                if !companion_candidates
                    .iter()
                    .skip(1)
                    .all(|(_, candidate)| candidate == first)
                {
                    coverage.unresolved_records += 1;
                    continue;
                }
                coverage.resolved_records += 1;
                coverage.non_row_artifacts += 1;
                records.push(Enterprise24PartialRecord {
                    raw_page_number: group.raw_page_number,
                    record_id,
                    bytes: bytes.clone(),
                    partial: PartialDecodedRow {
                        declared_size: bytes.len(),
                        flags: u16::from(bytes[2]),
                        through_ordinal: 0,
                        prefix_values: Vec::new(),
                        boolean_values: Vec::new(),
                        opaque_middle_len: bytes.len(),
                    },
                });
                continue;
            }
            let Some(first) = resolve_enterprise24_partial_record_candidates(&prefix_candidates)
            else {
                coverage.unresolved_records += 1;
                continue;
            };
            coverage.resolved_records += 1;
            records.push(Enterprise24PartialRecord {
                raw_page_number: group.raw_page_number,
                record_id,
                bytes: first.bytes,
                partial: first.partial,
            });
        }
    }
    Ok(Enterprise24PartialTableRows {
        policy,
        records,
        coverage,
    })
}

/// Collects table-3078 carriers using exact candidate-byte consensus.
///
/// General Journal source and auxiliary classifications depend on relations
/// between rows, so semantic parsing occurs only after the complete logical
/// collection is available to the pipeline.  Unlike a schema-prefix path,
/// opaque candidate tails cannot choose a winner: every candidate carrier
/// must be byte-identical.
pub fn collect_enterprise24_general_journal_table_rows(
    scan: &EnterpriseTableScan,
    expectation: Enterprise24TableCoverageExpectation,
) -> Result<Enterprise24PartialTableRows, Enterprise24AccountingPipelineError> {
    let policy =
        enterprise24_r21_partial_table_policy(Enterprise24AccountingTable::GeneralJournalLine)
            .expect("General Journal policy is static");
    if scan.target_table_id != policy.table.id() {
        return Err(Enterprise24AccountingPipelineError::ScanTableMismatch {
            scan_table_id: scan.target_table_id,
            policy_table_id: policy.table.id(),
        });
    }
    let mut coverage = Enterprise24PartialTableCoverage {
        table_id: policy.table.id(),
        candidate_page_groups: scan.candidate_groups.len() as u64,
        expected_logical_records: Some(expectation.logical_records),
        expected_table_pages: Some(expectation.table_pages),
        expected_external_table_pages: Some(expectation.external_table_pages),
        ..Enterprise24PartialTableCoverage::default()
    };
    let mut records = Vec::new();
    for group in &scan.candidate_groups {
        let counts = group
            .candidates
            .iter()
            .map(|page| page.table_page().record_count())
            .collect::<Vec<_>>();
        let directory = candidate_directory_consensus(&counts, |candidate, record| {
            group.candidates[candidate]
                .table_page()
                .record(record)
                .is_ok()
        });
        coverage.missing_records += directory.agreed_empty_record_ids.len() as u64;
        coverage.candidate_directory_disagreements += directory.disagreement_record_count;
        for record_id in directory.common_record_ids {
            let bytes = group
                .candidates
                .iter()
                .map(|page| {
                    page.table_page()
                        .record(record_id)
                        .expect("candidate-directory consensus established presence")
                        .bytes()
                        .to_vec()
                })
                .collect::<Vec<_>>();
            let Some(first) = bytes.first() else {
                coverage.unresolved_records += 1;
                continue;
            };
            if !bytes.iter().skip(1).all(|candidate| candidate == first) {
                coverage.unresolved_records += 1;
                continue;
            }
            coverage.resolved_records += 1;
            records.push(Enterprise24PartialRecord {
                raw_page_number: group.raw_page_number,
                record_id,
                bytes: first.clone(),
                partial: PartialDecodedRow {
                    declared_size: first.len(),
                    flags: u16::from(first.get(2).copied().unwrap_or_default()),
                    through_ordinal: 0,
                    prefix_values: Vec::new(),
                    boolean_values: Vec::new(),
                    opaque_middle_len: first.len(),
                },
            });
        }
    }
    Ok(Enterprise24PartialTableRows {
        policy,
        records,
        coverage,
    })
}

/// Structured evidence returned by the production scaffold.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Enterprise24AccountingCoverageDiagnostics {
    /// Coverage for every required Account/posting table policy.
    pub tables: BTreeMap<u32, Enterprise24PartialTableCoverage>,
    /// Number of account candidates presented to the Account adapter.
    pub account_candidates: u64,
    /// Number of selected normalized Account rows.
    pub normalized_accounts: u64,
    /// Lifecycle-excluded physical Account rows retained in coverage evidence.
    pub excluded_accounts: u64,
    /// Number of recognized posting candidates presented to the posting adapter.
    pub posting_candidates: u64,
    /// Number of normalized nonzero postings.
    pub normalized_postings: u64,
    /// Number of closed non-posting dispositions.
    pub excluded_postings: u64,
    /// Fail-closed reasons, deliberately free of application-row contents.
    pub blockers: Vec<Enterprise24AccountingPipelineBlocker>,
}

/// A concise, machine-actionable reason final construction is unavailable.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[allow(missing_docs)] // Fields repeat the documented blocker payload.
pub enum Enterprise24AccountingPipelineBlocker {
    /// A required table has no current production row-layout policy.
    UnsupportedTable { table_id: u32 },
    /// The supplied recovered catalog did not match the Enterprise 24 R21 manifest.
    SchemaManifestValidationFailed,
    /// The supplied row schema differs from the sole table policy storage layout.
    SchemaStorageMismatch { table_id: u32 },
    /// Candidate consensus or partial decode coverage was incomplete.
    IncompleteTableCoverage { table_id: u32 },
    /// An Account row could not be normalized from its bounded evidence.
    AccountAdaptationFailed { page: u64, record: u16 },
    /// A posting row could not be normalized from its bounded evidence.
    PostingAdaptationFailed {
        table_id: u32,
        page: u64,
        record: u16,
    },
    /// A normalized posting referenced no resolved Account identity.
    PostingAccountIdentityUnavailable {
        table_id: u32,
        page: u64,
        record: u16,
    },
    /// A complete physical posting-family census did not balance by master.
    UnbalancedPostingMasters { table_id: u32 },
    /// The final normalized ledger rejected a structural invariant.
    LedgerContractRejected,
}

/// Full scaffold result. The reportable ledger is present only after every
/// required family completed and the contract boundaries accepted it.
#[derive(Debug)]
pub struct Enterprise24AccountingPipelineResult {
    /// Sanitized table and normalization coverage.
    pub diagnostics: Enterprise24AccountingCoverageDiagnostics,
    /// A complete normalized ledger, never a partial accounting result.
    pub ledger: Option<Ledger>,
}

/// Normalize consensus-resolved partial tables into a ledger when and only
/// when every required family passes its evidence gates.
pub fn build_enterprise24_accounting_pipeline(
    snapshot: SourceSnapshotId,
    catalog_columns: &[SysColumn],
    account_rows: &Enterprise24PartialTableRows,
    posting_rows: &[Enterprise24PartialTableRows],
    schemas: &BTreeMap<u32, RowSchema>,
) -> Enterprise24AccountingPipelineResult {
    let mut diagnostics = Enterprise24AccountingCoverageDiagnostics::default();
    if validate_enterprise24_r21_schema_manifest(catalog_columns).is_err() {
        diagnostics
            .blockers
            .push(Enterprise24AccountingPipelineBlocker::SchemaManifestValidationFailed);
    }
    add_table_coverage(&mut diagnostics, &account_rows.coverage);
    for rows in posting_rows {
        add_table_coverage(&mut diagnostics, &rows.coverage);
    }
    for policy in ENTERPRISE24_R21_PARTIAL_TABLE_POLICIES {
        let Some(coverage) = diagnostics.tables.get(&policy.table.id()) else {
            diagnostics
                .blockers
                .push(Enterprise24AccountingPipelineBlocker::UnsupportedTable {
                    table_id: policy.table.id(),
                });
            continue;
        };
        if policy.status != Enterprise24PartialPolicyStatus::Partial {
            diagnostics
                .blockers
                .push(Enterprise24AccountingPipelineBlocker::UnsupportedTable {
                    table_id: policy.table.id(),
                });
        } else if !coverage.complete() {
            diagnostics.blockers.push(
                Enterprise24AccountingPipelineBlocker::IncompleteTableCoverage {
                    table_id: policy.table.id(),
                },
            );
        }
        if let (Some(_storage), Some(schema)) = (policy.storage, schemas.get(&policy.table.id()))
            && !policy_schema_matches(policy, schema)
        {
            diagnostics.blockers.push(
                Enterprise24AccountingPipelineBlocker::SchemaStorageMismatch {
                    table_id: policy.table.id(),
                },
            );
        }
    }

    let Some(account_schema) = schemas.get(&Enterprise24AccountingTable::AccountUser.id()) else {
        diagnostics.blockers.push(
            Enterprise24AccountingPipelineBlocker::IncompleteTableCoverage {
                table_id: Enterprise24AccountingTable::AccountUser.id(),
            },
        );
        return Enterprise24AccountingPipelineResult {
            diagnostics,
            ledger: None,
        };
    };
    diagnostics.account_candidates = account_rows.records.len() as u64;
    // Pass one establishes the physical-record-number -> ordinary ListID map.
    let identity_map: BTreeMap<u32, AccountId> = account_rows
        .records
        .iter()
        .filter_map(|record| {
            let identity = MaterializedAccountRow::parse(&record.bytes).ok()?;
            let id = AccountId::new(identity.ordinary_list_id()).ok()?;
            Some((identity.record_number(), id))
        })
        .collect();
    if identity_map.len() != account_rows.records.len() {
        for record in &account_rows.records {
            if MaterializedAccountRow::parse(&record.bytes).is_err() {
                diagnostics.blockers.push(
                    Enterprise24AccountingPipelineBlocker::AccountAdaptationFailed {
                        page: record.raw_page_number,
                        record: record.record_id,
                    },
                );
            }
        }
    }

    // Pass two resolves parent references only after every identity is known.
    let mut accounts = Vec::new();
    for record in &account_rows.records {
        let identity = match MaterializedAccountRow::parse(&record.bytes) {
            Ok(identity) => identity,
            Err(_) => continue,
        };
        match decode_schema_account_row_partial(
            &record.partial,
            account_schema,
            identity,
            AccountRowStateEvidence { internal: false },
            |record_number| identity_map.get(&record_number).cloned(),
            resolve_enterprise24_account_type18,
        ) {
            Ok(Some(row)) => accounts.push(row.account),
            Ok(None) => diagnostics.excluded_accounts += 1,
            Err(_) => diagnostics.blockers.push(
                Enterprise24AccountingPipelineBlocker::AccountAdaptationFailed {
                    page: record.raw_page_number,
                    record: record.record_id,
                },
            ),
        }
    }
    diagnostics.normalized_accounts = accounts.len() as u64;

    let mut dispositions = Vec::new();
    for rows in posting_rows {
        let table = rows.policy.table;
        if !table.is_posting_table()
            || rows.policy.status == Enterprise24PartialPolicyStatus::Unsupported
        {
            continue;
        }
        if table == Enterprise24AccountingTable::GeneralJournalLine {
            let carriers = match classify_materialized_general_journal_rows(
                &rows
                    .records
                    .iter()
                    .map(|record| record.bytes.clone())
                    .collect::<Vec<_>>(),
            ) {
                Ok(carriers) if carriers.len() == rows.records.len() => carriers,
                Err(_) => {
                    diagnostics.blockers.push(
                        Enterprise24AccountingPipelineBlocker::PostingAdaptationFailed {
                            table_id: table.id(),
                            page: 0,
                            record: 0,
                        },
                    );
                    continue;
                }
                Ok(_) => {
                    diagnostics.blockers.push(
                        Enterprise24AccountingPipelineBlocker::PostingAdaptationFailed {
                            table_id: table.id(),
                            page: 0,
                            record: 0,
                        },
                    );
                    continue;
                }
            };
            let mut balances = BTreeMap::<u64, i128>::new();
            for carrier in &carriers {
                if let MaterializedGeneralJournalDisposition::Posting(row) = carrier {
                    *balances
                        .entry(u64::from(row.master_record_number()))
                        .or_default() += i128::from(row.signed_cents());
                }
            }
            if balances.values().any(|balance| *balance != 0) {
                diagnostics.blockers.push(
                    Enterprise24AccountingPipelineBlocker::UnbalancedPostingMasters {
                        table_id: table.id(),
                    },
                );
            }
            for (record, carrier) in rows.records.iter().zip(carriers) {
                diagnostics.posting_candidates += 1;
                let adaptation = match carrier {
                    MaterializedGeneralJournalDisposition::Posting(row) => {
                        adapt_materialized_general_journal_posting_row(&row)
                    }
                    MaterializedGeneralJournalDisposition::SourceOrLink(_)
                    | MaterializedGeneralJournalDisposition::AuxiliaryLinkChain { .. }
                    | MaterializedGeneralJournalDisposition::TerminalMetadataCarrier { .. }
                    | MaterializedGeneralJournalDisposition::CanonicalZeroAmount(_) => {
                        let provenance = match PostingProvenance::new(
                            format!(
                                "enterprise24:{}:{}:{}",
                                table.id(),
                                record.raw_page_number,
                                record.record_id
                            ),
                            u32::try_from(record.raw_page_number).ok(),
                            Some(record.record_id),
                            rows.policy.version,
                        ) {
                            Ok(value) => value,
                            Err(_) => {
                                diagnostics.blockers.push(Enterprise24AccountingPipelineBlocker::PostingAdaptationFailed { table_id: table.id(), page: record.raw_page_number, record: record.record_id });
                                continue;
                            }
                        };
                        diagnostics.excluded_postings += 1;
                        let reason = match carrier {
                            MaterializedGeneralJournalDisposition::CanonicalZeroAmount(_) => {
                                PostingExclusionReason::CanonicalZeroAmount
                            }
                            _ => PostingExclusionReason::SourceOrLinkRow,
                        };
                        dispositions.push(PostingExclusion::new(provenance, reason).into());
                        continue;
                    }
                };
                match adaptation.and_then(|adaptation| {
                    normalized_disposition(
                        table,
                        record,
                        adaptation,
                        &identity_map,
                        rows.policy.version,
                    )
                    .map_err(|_| {
                        crate::EnterprisePostingAdapterError::InvalidPostingAmount {
                            name: "normalization".to_owned(),
                        }
                    })
                }) {
                    Ok(PostingDisposition::Posting(posting)) => {
                        diagnostics.normalized_postings += 1;
                        dispositions.push(PostingDisposition::Posting(posting));
                    }
                    Ok(PostingDisposition::Excluded(exclusion)) => {
                        diagnostics.excluded_postings += 1;
                        dispositions.push(PostingDisposition::Excluded(exclusion));
                    }
                    Err(_) => diagnostics.blockers.push(
                        Enterprise24AccountingPipelineBlocker::PostingAdaptationFailed {
                            table_id: table.id(),
                            page: record.raw_page_number,
                            record: record.record_id,
                        },
                    ),
                }
            }
            continue;
        }
        if table == Enterprise24AccountingTable::CheckLine {
            let selected = try_materialized_check_dispositions(rows, &identity_map).or_else(|_| {
                schemas
                    .get(&table.id())
                    .ok_or(())
                    .and_then(|schema| try_partial_check_dispositions(rows, schema, &identity_map))
            });
            diagnostics.posting_candidates += rows.records.len() as u64;
            match selected {
                Ok(selected) => {
                    for disposition in selected {
                        match &disposition {
                            PostingDisposition::Posting(_) => diagnostics.normalized_postings += 1,
                            PostingDisposition::Excluded(_) => diagnostics.excluded_postings += 1,
                        }
                        dispositions.push(disposition);
                    }
                }
                Err(()) => {
                    diagnostics.blockers.push(
                        Enterprise24AccountingPipelineBlocker::UnbalancedPostingMasters {
                            table_id: table.id(),
                        },
                    );
                    for record in &rows.records {
                        diagnostics.blockers.push(
                            Enterprise24AccountingPipelineBlocker::PostingAdaptationFailed {
                                table_id: table.id(),
                                page: record.raw_page_number,
                                record: record.record_id,
                            },
                        );
                    }
                }
            }
            continue;
        }
        if table == Enterprise24AccountingTable::BillLine {
            let mut balances = BTreeMap::<u64, i128>::new();
            for record in &rows.records {
                match MaterializedBillPostingRow::parse(&record.bytes) {
                    Ok(row) if !row.has_canonical_zero_amount() => {
                        *balances
                            .entry(u64::from(row.master_record_number()))
                            .or_default() += i128::from(row.signed_cents());
                    }
                    Ok(_) => {}
                    Err(_) => diagnostics.blockers.push(
                        Enterprise24AccountingPipelineBlocker::PostingAdaptationFailed {
                            table_id: table.id(),
                            page: record.raw_page_number,
                            record: record.record_id,
                        },
                    ),
                }
            }
            if balances.values().any(|balance| *balance != 0) {
                diagnostics.blockers.push(
                    Enterprise24AccountingPipelineBlocker::UnbalancedPostingMasters {
                        table_id: table.id(),
                    },
                );
            }
            for record in &rows.records {
                diagnostics.posting_candidates += 1;
                let adaptation = MaterializedBillPostingRow::parse(&record.bytes)
                    .map_err(|_| ())
                    .and_then(|row| adapt_materialized_bill_posting_row(&row).map_err(|_| ()));
                match adaptation {
                    Ok(adaptation) => match normalized_disposition(
                        table,
                        record,
                        adaptation,
                        &identity_map,
                        rows.policy.version,
                    ) {
                        Ok(PostingDisposition::Posting(posting)) => {
                            diagnostics.normalized_postings += 1;
                            dispositions.push(PostingDisposition::Posting(posting));
                        }
                        Ok(PostingDisposition::Excluded(exclusion)) => {
                            diagnostics.excluded_postings += 1;
                            dispositions.push(PostingDisposition::Excluded(exclusion));
                        }
                        Err(NormalizationFailure::MissingAccountIdentity) => diagnostics
                            .blockers
                            .push(
                                Enterprise24AccountingPipelineBlocker::PostingAccountIdentityUnavailable {
                                    table_id: table.id(),
                                    page: record.raw_page_number,
                                    record: record.record_id,
                                },
                            ),
                        Err(NormalizationFailure::Other) => diagnostics.blockers.push(
                            Enterprise24AccountingPipelineBlocker::PostingAdaptationFailed {
                                table_id: table.id(),
                                page: record.raw_page_number,
                                record: record.record_id,
                            },
                        ),
                    },
                    Err(()) => diagnostics.blockers.push(
                        Enterprise24AccountingPipelineBlocker::PostingAdaptationFailed {
                            table_id: table.id(),
                            page: record.raw_page_number,
                            record: record.record_id,
                        },
                    ),
                }
            }
            continue;
        }
        let Some(schema) = schemas.get(&table.id()) else {
            diagnostics.blockers.push(
                Enterprise24AccountingPipelineBlocker::IncompleteTableCoverage {
                    table_id: table.id(),
                },
            );
            continue;
        };
        for record in &rows.records {
            diagnostics.posting_candidates += 1;
            match adapt_enterprise_posting_row_partial(table, schema, &record.partial) {
                Ok(adaptation) => match normalized_disposition(
                    table,
                    record,
                    adaptation,
                    &identity_map,
                    rows.policy.version,
                ) {
                    Ok(PostingDisposition::Posting(posting)) => {
                        diagnostics.normalized_postings += 1;
                        dispositions.push(PostingDisposition::Posting(posting));
                    }
                    Ok(PostingDisposition::Excluded(exclusion)) => {
                        diagnostics.excluded_postings += 1;
                        dispositions.push(PostingDisposition::Excluded(exclusion));
                    }
                    Err(NormalizationFailure::MissingAccountIdentity) => diagnostics.blockers.push(
                        Enterprise24AccountingPipelineBlocker::PostingAccountIdentityUnavailable {
                            table_id: table.id(),
                            page: record.raw_page_number,
                            record: record.record_id,
                        },
                    ),
                    Err(NormalizationFailure::Other) => diagnostics.blockers.push(
                        Enterprise24AccountingPipelineBlocker::PostingAdaptationFailed {
                            table_id: table.id(),
                            page: record.raw_page_number,
                            record: record.record_id,
                        },
                    ),
                },
                Err(_) => diagnostics.blockers.push(
                    Enterprise24AccountingPipelineBlocker::PostingAdaptationFailed {
                        table_id: table.id(),
                        page: record.raw_page_number,
                        record: record.record_id,
                    },
                ),
            }
        }
    }
    diagnostics.blockers.sort();
    diagnostics.blockers.dedup();
    if !diagnostics.blockers.is_empty() {
        return Enterprise24AccountingPipelineResult {
            diagnostics,
            ledger: None,
        };
    }

    let account_coverage = CompleteCoverage::new(
        diagnostics.normalized_accounts,
        diagnostics.normalized_accounts,
    )
    .expect("identical counts");
    let posting_coverage = CompleteCoverage::new(
        diagnostics.posting_candidates,
        diagnostics.posting_candidates,
    )
    .expect("identical counts");
    let accounts = match DecodedAccounts::new(
        snapshot.clone(),
        DecoderIdentity::new("enterprise24-r21-account-pipeline-v1").expect("literal"),
        accounts,
        account_coverage,
    ) {
        Ok(value) => value,
        Err(_) => return rejected_result(diagnostics),
    };
    let postings = match DecodedPostings::new(
        snapshot,
        DecoderIdentity::new("enterprise24-r21-posting-pipeline-v1").expect("literal"),
        dispositions,
        posting_coverage,
    ) {
        Ok(value) => value,
        Err(_) => return rejected_result(diagnostics),
    };
    match LedgerAdapter::build(accounts, postings) {
        Ok(ledger) => Enterprise24AccountingPipelineResult {
            diagnostics,
            ledger: Some(ledger),
        },
        Err(_) => rejected_result(diagnostics),
    }
}

fn check_companion_disposition(
    record: &Enterprise24PartialRecord,
    carrier: MaterializedCheckVoidCompanionCarrier,
    evidence: &BTreeMap<u64, CheckVoidCompanionMasterEvidence>,
    decoder: &str,
) -> Result<PostingDisposition, ()> {
    let master_evidence = evidence
        .get(&u64::from(carrier.master_record_number()))
        .copied()
        .unwrap_or(CheckVoidCompanionMasterEvidence {
            canonical_zero_e4_row_count: 0,
            nonzero_posting_row_count: 0,
        });
    classify_materialized_check_void_companion(carrier, master_evidence).map_err(|_| ())?;
    let provenance = PostingProvenance::new(
        format!(
            "enterprise24:{}:{}:{}",
            Enterprise24AccountingTable::CheckLine.id(),
            record.raw_page_number,
            record.record_id
        ),
        u32::try_from(record.raw_page_number).ok(),
        Some(record.record_id),
        decoder,
    )
    .map_err(|_| ())?;
    Ok(PostingExclusion::new(provenance, PostingExclusionReason::SourceOrLinkRow).into())
}

fn try_materialized_check_dispositions(
    rows: &Enterprise24PartialTableRows,
    identity_map: &BTreeMap<u32, AccountId>,
) -> Result<Vec<PostingDisposition>, ()> {
    validate_check_master_balances(&rows.records)?;
    let evidence = check_void_evidence_for_rows(&rows.records)?;
    let carriers = rows
        .records
        .iter()
        .filter_map(|record| MaterializedCheckVoidCompanionCarrier::parse(&record.bytes).ok())
        .collect::<Vec<_>>();
    let mut carrier_counts = BTreeMap::<u32, usize>::new();
    let mut carrier_targets = std::collections::BTreeSet::new();
    for carrier in &carriers {
        *carrier_counts
            .entry(carrier.master_record_number())
            .or_default() += 1;
        if carrier.target_record_number() == carrier.master_record_number()
            || !carrier_targets.insert(carrier.target_record_number())
        {
            return Err(());
        }
    }
    if carrier_counts.values().any(|count| *count != 1) {
        return Err(());
    }
    let posting_targets = rows
        .records
        .iter()
        .filter(|record| MaterializedCheckVoidCompanionCarrier::parse(&record.bytes).is_err())
        .map(|record| MaterializedCheckPostingRow::parse(&record.bytes).map_err(|_| ()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|row| row.target_record_number())
        .collect::<std::collections::BTreeSet<_>>();
    if !carrier_targets.is_disjoint(&posting_targets) {
        return Err(());
    }
    let mut selected = Vec::with_capacity(rows.records.len());
    for record in &rows.records {
        if let Ok(carrier) = MaterializedCheckVoidCompanionCarrier::parse(&record.bytes) {
            selected.push(check_companion_disposition(
                record,
                carrier,
                &evidence,
                rows.policy.version,
            )?);
            continue;
        }
        let row = MaterializedCheckPostingRow::parse(&record.bytes).map_err(|_| ())?;
        let adaptation = adapt_materialized_check_posting_row(&row).map_err(|_| ())?;
        selected.push(
            normalized_disposition(
                Enterprise24AccountingTable::CheckLine,
                record,
                adaptation,
                identity_map,
                rows.policy.version,
            )
            .map_err(|_| ())?,
        );
    }
    Ok(selected)
}

fn try_partial_check_dispositions(
    rows: &Enterprise24PartialTableRows,
    schema: &RowSchema,
    identity_map: &BTreeMap<u32, AccountId>,
) -> Result<Vec<PostingDisposition>, ()> {
    if rows.records.iter().any(|record| {
        MaterializedCheckVoidCompanionCarrier::parse(&record.bytes)
            .is_ok_and(MaterializedCheckVoidCompanionCarrier::is_long_envelope)
    }) {
        return Err(());
    }
    validate_check_master_balances_partial(&rows.records, schema)?;
    let evidence = check_void_evidence_for_partial_rows(&rows.records, schema)?;
    let mut selected = Vec::with_capacity(rows.records.len());
    for record in &rows.records {
        if let Ok(carrier) = MaterializedCheckVoidCompanionCarrier::parse(&record.bytes) {
            selected.push(check_companion_disposition(
                record,
                carrier,
                &evidence,
                rows.policy.version,
            )?);
            continue;
        }
        match adapt_enterprise_posting_row_partial(
            Enterprise24AccountingTable::CheckLine,
            schema,
            &record.partial,
        ) {
            Ok(adaptation) => selected.push(
                normalized_disposition(
                    Enterprise24AccountingTable::CheckLine,
                    record,
                    adaptation,
                    identity_map,
                    rows.policy.version,
                )
                .map_err(|_| ())?,
            ),
            Err(_) => return Err(()),
        }
    }
    Ok(selected)
}

fn check_void_evidence_for_rows(
    rows: &[Enterprise24PartialRecord],
) -> Result<BTreeMap<u64, CheckVoidCompanionMasterEvidence>, ()> {
    let mut counts = BTreeMap::<u64, (u8, u32)>::new();
    for record in rows {
        if MaterializedCheckVoidCompanionCarrier::parse(&record.bytes).is_ok() {
            continue;
        }
        let row = MaterializedCheckPostingRow::parse(&record.bytes).map_err(|_| ())?;
        let adaptation = adapt_materialized_check_posting_row(&row).map_err(|_| ())?;
        let (transaction_id, canonical_zero, nonzero) = match adaptation {
            EnterprisePostingAdaptation::Posting(row) => (row.transaction_id, false, true),
            EnterprisePostingAdaptation::Excluded(
                EnterprisePostingExclusion::CanonicalZeroVoided { transaction_id, .. },
            ) => (transaction_id, true, false),
            EnterprisePostingAdaptation::Excluded(_) => continue,
        };
        let entry = counts.entry(transaction_id).or_default();
        if canonical_zero {
            entry.0 = entry.0.saturating_add(1);
        }
        if nonzero {
            entry.1 = entry.1.saturating_add(1);
        }
    }
    Ok(counts
        .into_iter()
        .map(
            |(master, (canonical_zero_e4_row_count, nonzero_posting_row_count))| {
                (
                    master,
                    CheckVoidCompanionMasterEvidence {
                        canonical_zero_e4_row_count,
                        nonzero_posting_row_count,
                    },
                )
            },
        )
        .collect())
}

fn check_void_evidence_for_partial_rows(
    rows: &[Enterprise24PartialRecord],
    schema: &RowSchema,
) -> Result<BTreeMap<u64, CheckVoidCompanionMasterEvidence>, ()> {
    let mut counts = BTreeMap::<u64, (u8, u32)>::new();
    for record in rows {
        if MaterializedCheckVoidCompanionCarrier::parse(&record.bytes).is_ok() {
            continue;
        }
        let adaptation = match adapt_enterprise_posting_row_partial(
            Enterprise24AccountingTable::CheckLine,
            schema,
            &record.partial,
        ) {
            Ok(adaptation) => adaptation,
            Err(_) => return Err(()),
        };
        let (transaction_id, canonical_zero, nonzero) = match adaptation {
            EnterprisePostingAdaptation::Posting(row) => (row.transaction_id, false, true),
            EnterprisePostingAdaptation::Excluded(
                EnterprisePostingExclusion::CanonicalZeroVoided { transaction_id, .. },
            ) => (transaction_id, true, false),
            EnterprisePostingAdaptation::Excluded(_) => continue,
        };
        let entry = counts.entry(transaction_id).or_default();
        if canonical_zero {
            entry.0 = entry.0.saturating_add(1);
        }
        if nonzero {
            entry.1 = entry.1.saturating_add(1);
        }
    }
    Ok(counts
        .into_iter()
        .map(
            |(master, (canonical_zero_e4_row_count, nonzero_posting_row_count))| {
                (
                    master,
                    CheckVoidCompanionMasterEvidence {
                        canonical_zero_e4_row_count,
                        nonzero_posting_row_count,
                    },
                )
            },
        )
        .collect())
}

fn validate_check_master_balances_partial(
    rows: &[Enterprise24PartialRecord],
    schema: &RowSchema,
) -> Result<(), ()> {
    let mut balances = BTreeMap::<u64, i128>::new();
    for record in rows {
        if MaterializedCheckVoidCompanionCarrier::parse(&record.bytes).is_ok() {
            continue;
        }
        let adaptation = match adapt_enterprise_posting_row_partial(
            Enterprise24AccountingTable::CheckLine,
            schema,
            &record.partial,
        ) {
            Ok(adaptation) => adaptation,
            Err(_) => return Err(()),
        };
        if let EnterprisePostingAdaptation::Posting(row) = adaptation {
            *balances.entry(row.transaction_id).or_default() += i128::from(row.amount_cents);
        }
    }
    balances
        .into_values()
        .all(|balance| balance == 0)
        .then_some(())
        .ok_or(())
}

/// Requires every non-void Check master in the complete table-3047 census to
/// net to zero.  The companion carrier is explicitly non-posting, while a
/// canonical-zero Check row is a lifecycle tombstone rather than a monetary
/// line.  This is a table-family invariant in addition to the final ledger's
/// cross-family balance contract.
fn validate_check_master_balances(rows: &[Enterprise24PartialRecord]) -> Result<(), ()> {
    let mut balances = BTreeMap::<u64, i128>::new();
    for record in rows {
        if MaterializedCheckVoidCompanionCarrier::parse(&record.bytes).is_ok() {
            continue;
        }
        let row = MaterializedCheckPostingRow::parse(&record.bytes).map_err(|_| ())?;
        if !row.has_canonical_zero_amount() {
            *balances
                .entry(u64::from(row.master_record_number()))
                .or_default() += i128::from(row.signed_cents());
        }
    }
    balances
        .into_values()
        .all(|balance| balance == 0)
        .then_some(())
        .ok_or(())
}

fn add_table_coverage(
    diagnostics: &mut Enterprise24AccountingCoverageDiagnostics,
    coverage: &Enterprise24PartialTableCoverage,
) {
    diagnostics
        .tables
        .insert(coverage.table_id, coverage.clone());
}

fn rejected_result(
    mut diagnostics: Enterprise24AccountingCoverageDiagnostics,
) -> Enterprise24AccountingPipelineResult {
    diagnostics
        .blockers
        .push(Enterprise24AccountingPipelineBlocker::LedgerContractRejected);
    diagnostics.blockers.sort();
    diagnostics.blockers.dedup();
    Enterprise24AccountingPipelineResult {
        diagnostics,
        ledger: None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NormalizationFailure {
    MissingAccountIdentity,
    Other,
}

fn normalized_disposition(
    table: Enterprise24AccountingTable,
    record: &Enterprise24PartialRecord,
    adaptation: EnterprisePostingAdaptation,
    identity_map: &BTreeMap<u32, AccountId>,
    decoder: &str,
) -> Result<PostingDisposition, NormalizationFailure> {
    let provenance = PostingProvenance::new(
        format!(
            "enterprise24:{}:{}:{}",
            table.id(),
            record.raw_page_number,
            record.record_id
        ),
        u32::try_from(record.raw_page_number).ok(),
        Some(record.record_id),
        decoder,
    )
    .map_err(|_| NormalizationFailure::Other)?;
    match adaptation {
        EnterprisePostingAdaptation::Posting(row) => {
            let account_id = identity_map
                .get(&(row.account_id as u32))
                .cloned()
                .ok_or(NormalizationFailure::MissingAccountIdentity)?;
            let (side, minor_units) = if row.amount_cents > 0 {
                (DebitCredit::Debit, row.amount_cents)
            } else {
                (
                    DebitCredit::Credit,
                    row.amount_cents
                        .checked_abs()
                        .ok_or(NormalizationFailure::Other)?,
                )
            };
            let amount = DebitCreditAmount::new(side, minor_units)
                .map_err(|_| NormalizationFailure::Other)?;
            Ok(Posting::new(
                TransactionId::new(format!("enterprise24-txn-{}", row.transaction_id))
                    .map_err(|_| NormalizationFailure::Other)?,
                PostingId::new(format!(
                    "enterprise24-line-{}-{}",
                    table.id(),
                    row.target_id
                ))
                .map_err(|_| NormalizationFailure::Other)?,
                account_id,
                row.transaction_date,
                amount,
                CurrentState::Current,
                provenance,
                Some(row.transaction_type.source_label().to_owned()),
                None,
            )
            .into())
        }
        EnterprisePostingAdaptation::Excluded(exclusion) => {
            let reason = match exclusion {
                EnterprisePostingExclusion::NoPost { .. }
                | EnterprisePostingExclusion::MemorizedTransaction { .. }
                | EnterprisePostingExclusion::SourceOrLink { .. } => {
                    PostingExclusionReason::SourceOrLinkRow
                }
                EnterprisePostingExclusion::CanonicalZeroVoided { .. } => {
                    PostingExclusionReason::CanonicalZeroVoidedRow
                }
            };
            Ok(PostingExclusion::new(provenance, reason).into())
        }
    }
}

/// Pipeline construction failures that are invalid at the API boundary.
#[derive(Debug, Error, Eq, PartialEq)]
#[allow(missing_docs)] // Fields repeat the documented error payload.
pub enum Enterprise24AccountingPipelineError {
    /// A table scan was paired with a policy for another table.
    #[error("partial policy table {policy_table_id} does not match scan table {scan_table_id}")]
    ScanTableMismatch {
        scan_table_id: u32,
        policy_table_id: u32,
    },
    /// The supplied schema did not equal the table's sole attested storage layout.
    #[error("schema storage layout does not match Enterprise 24 policy for table {table_id}")]
    PolicyStorageMismatch { table_id: u32 },
    /// The table has a bounded physical grammar and must not be sent through
    /// the generic schema-prefix collector.
    #[error("Enterprise 24 table {table_id} requires its dedicated collector")]
    PolicyRequiresDedicatedCollector { table_id: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Account, AccountType};
    use opensqlany::{PartialRowValue, Value};

    fn partial(integer: i64) -> PartialDecodedRow {
        PartialDecodedRow {
            declared_size: 4,
            flags: 0,
            through_ordinal: 1,
            prefix_values: vec![PartialRowValue {
                column_index: 0,
                column_id: 1,
                value: Value::Integer(integer),
            }],
            boolean_values: Vec::new(),
            opaque_middle_len: 0,
        }
    }

    fn check_record(
        target: u32,
        master: u32,
        account: u32,
        amount: [u8; 4],
    ) -> Enterprise24PartialRecord {
        // Exact bounded terminal Check grammar: the source account is at
        // +0x1e and the monetary token begins at +0x53.
        let mut bytes = vec![0_u8; 0x53 + amount.len()];
        let declared_len = bytes.len() as u16;
        bytes[..2].copy_from_slice(&declared_len.to_le_bytes());
        bytes[3] = crate::MATERIALIZED_CHECK_POSTING_KIND;
        bytes[0x0c..0x10].copy_from_slice(&target.to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&master.to_le_bytes());
        bytes[0x14..0x18].copy_from_slice(&account.to_le_bytes());
        bytes[0x1e..0x22].copy_from_slice(&account.to_le_bytes());
        bytes[0x53..].copy_from_slice(&amount);
        Enterprise24PartialRecord {
            raw_page_number: 1,
            record_id: target as u16,
            partial: PartialDecodedRow {
                declared_size: bytes.len(),
                flags: 0,
                through_ordinal: 0,
                prefix_values: Vec::new(),
                boolean_values: Vec::new(),
                opaque_middle_len: bytes.len(),
            },
            bytes,
        }
    }

    fn check_companion_record(
        target: u32,
        master: u32,
        length: usize,
    ) -> Enterprise24PartialRecord {
        let mut bytes = vec![0_u8; length];
        bytes[..2].copy_from_slice(&(length as u16).to_le_bytes());
        bytes[3] = crate::MATERIALIZED_CHECK_VOID_COMPANION_KIND;
        bytes[0x0c..0x10].copy_from_slice(&target.to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&master.to_le_bytes());
        Enterprise24PartialRecord {
            raw_page_number: 1,
            record_id: target as u16,
            partial: PartialDecodedRow {
                declared_size: bytes.len(),
                flags: 0,
                through_ordinal: 0,
                prefix_values: Vec::new(),
                boolean_values: Vec::new(),
                opaque_middle_len: bytes.len(),
            },
            bytes,
        }
    }

    #[test]
    fn policies_are_versioned_and_mark_general_journal_as_dedicated() {
        let check =
            enterprise24_r21_partial_table_policy(Enterprise24AccountingTable::CheckLine).unwrap();
        assert_eq!(check.through_ordinal, Some(33));
        assert_eq!(check.status, Enterprise24PartialPolicyStatus::Partial);
        assert_eq!(
            check.storage,
            Some(CHECK_PREFIX_ONE_DECLARED_4096_POINTER_16)
        );
        let general_journal =
            enterprise24_r21_partial_table_policy(Enterprise24AccountingTable::GeneralJournalLine)
                .unwrap();
        assert_eq!(
            general_journal.status,
            Enterprise24PartialPolicyStatus::Partial
        );
        assert_eq!(general_journal.through_ordinal, None);
        assert_eq!(general_journal.storage, None);
    }

    #[test]
    fn missing_required_general_journal_policy_blocks_a_ledger_without_fabricating_success() {
        let account_policy =
            enterprise24_r21_partial_table_policy(Enterprise24AccountingTable::AccountUser)
                .unwrap();
        let account_rows = Enterprise24PartialTableRows {
            policy: account_policy,
            records: Vec::new(),
            coverage: Enterprise24PartialTableCoverage {
                table_id: account_policy.table.id(),
                ..Enterprise24PartialTableCoverage::default()
            },
        };
        let result = build_enterprise24_accounting_pipeline(
            SourceSnapshotId::new("synthetic-mini-store").unwrap(),
            &[],
            &account_rows,
            &[],
            &BTreeMap::new(),
        );
        assert!(result.ledger.is_none());
        assert!(
            result.diagnostics.blockers.contains(
                &Enterprise24AccountingPipelineBlocker::UnsupportedTable { table_id: 3078 }
            )
        );
    }

    #[test]
    fn unresolved_coverage_is_a_distinct_final_blocker() {
        let coverage = Enterprise24PartialTableCoverage {
            table_id: 3047,
            unresolved_records: 1,
            ..Enterprise24PartialTableCoverage::default()
        };
        assert!(!coverage.complete());
    }

    #[test]
    fn direct_check_master_balance_gate_requires_each_master_to_net_zero() {
        // Same base-100 magnitude, opposite calibrated sign markers.
        let debit = check_record(10, 100, 7, [2, 0xbf, 1, 23]);
        let credit = check_record(11, 100, 8, [2, 0x3f, 1, 23]);
        assert!(validate_check_master_balances(&[debit.clone(), credit]).is_ok());

        let unbalanced_credit = check_record(11, 100, 8, [2, 0x3f, 1, 24]);
        assert!(validate_check_master_balances(&[debit, unbalanced_credit]).is_err());
    }

    #[test]
    fn materialized_check_strategy_requires_one_noncolliding_companion_per_master() {
        let master = 100;
        let records = vec![
            check_companion_record(
                103,
                master,
                crate::MATERIALIZED_CHECK_VOID_COMPANION_LONG_LEN,
            ),
            check_record(101, master, 7, [0, 0x81, 0, 0]),
            check_record(102, master, 8, [0, 0x81, 0, 0]),
        ];
        let rows = Enterprise24PartialTableRows {
            policy: enterprise24_r21_partial_table_policy(Enterprise24AccountingTable::CheckLine)
                .unwrap(),
            records: records.clone(),
            coverage: Enterprise24PartialTableCoverage::default(),
        };
        let selected = try_materialized_check_dispositions(&rows, &BTreeMap::new()).unwrap();
        assert_eq!(selected.len(), 3);
        assert!(
            selected
                .iter()
                .all(|row| matches!(row, PostingDisposition::Excluded(_)))
        );

        let mut duplicate = records.clone();
        duplicate.push(check_companion_record(
            104,
            master,
            crate::MATERIALIZED_CHECK_VOID_COMPANION_LONG_LEN,
        ));
        let duplicate_rows = Enterprise24PartialTableRows {
            policy: rows.policy,
            records: duplicate,
            coverage: Enterprise24PartialTableCoverage::default(),
        };
        assert!(try_materialized_check_dispositions(&duplicate_rows, &BTreeMap::new()).is_err());

        let collision_rows = Enterprise24PartialTableRows {
            policy: rows.policy,
            records: vec![
                check_companion_record(
                    101,
                    master,
                    crate::MATERIALIZED_CHECK_VOID_COMPANION_LONG_LEN,
                ),
                check_record(101, master, 7, [0, 0x81, 0, 0]),
                check_record(102, master, 8, [0, 0x81, 0, 0]),
            ],
            coverage: Enterprise24PartialTableCoverage::default(),
        };
        assert!(try_materialized_check_dispositions(&collision_rows, &BTreeMap::new()).is_err());
    }

    #[test]
    fn expected_empty_directory_slots_do_not_break_logical_table_coverage() {
        let coverage = Enterprise24PartialTableCoverage {
            table_id: 3039,
            candidate_page_groups: 2,
            expected_table_pages: Some(2),
            expected_logical_records: Some(5),
            resolved_records: 5,
            // The six empty slots are physical directory facts, not rows.
            missing_records: 6,
            ..Enterprise24PartialTableCoverage::default()
        };
        assert!(coverage.complete());
    }

    #[test]
    fn logical_coverage_includes_catalogued_external_table_pages() {
        let coverage = Enterprise24PartialTableCoverage {
            table_id: 3042,
            candidate_page_groups: 3,
            expected_table_pages: Some(2),
            expected_external_table_pages: Some(1),
            expected_logical_records: Some(7),
            resolved_records: 7,
            non_row_artifacts: 1,
            ..Enterprise24PartialTableCoverage::default()
        };
        assert!(coverage.complete());
    }

    #[test]
    fn bill_artifact_classifier_is_exact_and_bounded() {
        let artifact = [9, 0, 0x44, 0x08, 0x4a, 0, 0, 0, 0];
        assert!(is_r21_bill_non_row_artifact(&artifact));
        let mut altered = artifact;
        altered[4] = 0;
        assert!(!is_r21_bill_non_row_artifact(&altered));
        assert!(!is_r21_bill_non_row_artifact(&artifact[..8]));
    }

    #[test]
    fn lifecycle_excluded_accounts_do_not_inflate_decoded_account_coverage() {
        let selected = Account::new(
            AccountId::new("synthetic-account").unwrap(),
            "Synthetic Account",
            AccountType::Asset,
            true,
        )
        .unwrap();
        let physical_candidates = 2_u64;
        let excluded_accounts = 1_u64;
        let selected_accounts = physical_candidates - excluded_accounts;
        let handoff = DecodedAccounts::new(
            SourceSnapshotId::new("synthetic-mini-store").unwrap(),
            DecoderIdentity::new("synthetic-account-pipeline").unwrap(),
            [selected],
            CompleteCoverage::new(selected_accounts, selected_accounts).unwrap(),
        );
        assert!(handoff.is_ok());
    }

    #[test]
    fn synthetic_mini_store_candidate_consensus_never_selects_divergent_prefixes() {
        let left = Enterprise24PartialRecordCandidate {
            bytes: vec![4, 0, 0, 1],
            partial: partial(7),
        };
        let same_prefix_other_opaque_tail = Enterprise24PartialRecordCandidate {
            bytes: vec![4, 0, 0, 9],
            partial: partial(7),
        };
        let divergent = Enterprise24PartialRecordCandidate {
            bytes: vec![4, 0, 0, 2],
            partial: partial(8),
        };
        assert!(
            resolve_enterprise24_partial_record_candidates(&[
                left.clone(),
                same_prefix_other_opaque_tail,
            ])
            .is_some()
        );
        assert!(resolve_enterprise24_partial_record_candidates(&[left, divergent]).is_none());
    }

    #[test]
    fn directory_consensus_uses_only_common_present_slots_and_flags_divergence() {
        // Candidate zero declares four slots; candidate one declares five.
        // Slot one is present in only one candidate, slots two and three are
        // agreed empty, and the extra fifth slot is outside candidate zero's
        // directory domain. Only slot zero may enter a consensus decoder.
        let present = [
            [true, true, false, false, false],
            [true, false, false, false, true],
        ];
        let consensus = candidate_directory_consensus(&[4, 5], |candidate, record| {
            present[candidate][usize::from(record)]
        });
        assert_eq!(consensus.common_record_ids, vec![0]);
        assert_eq!(consensus.agreed_empty_record_ids, vec![2, 3]);
        assert_eq!(consensus.disagreement_record_count, 2);
    }

    #[test]
    fn directory_consensus_accepts_agreed_empty_slots_without_source_rows() {
        let present = [[true, false, true], [true, false, true]];
        let consensus = candidate_directory_consensus(&[3, 3], |candidate, record| {
            present[candidate][usize::from(record)]
        });
        assert_eq!(consensus.common_record_ids, vec![0, 2]);
        assert_eq!(consensus.agreed_empty_record_ids, vec![1]);
        assert_eq!(consensus.disagreement_record_count, 0);
    }
}

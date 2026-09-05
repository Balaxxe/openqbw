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

use std::collections::{BTreeMap, BTreeSet};

use opensqlany::{
    BooleanTailLayout, ColumnType, EnumLayout, NullBitmapCoverage, NullBitmapLayout, NumericLayout,
    PartialDecodedRow, RowPrefixLayout, RowSchema, Value, VariableLengthLayout,
    VariableOverflowLayout, decode_row_prefix_and_boolean_tail,
};
use thiserror::Error;

use crate::{
    AccountId, AccountRowStateEvidence, CheckVoidCompanionMasterEvidence, CompleteCoverage,
    CurrentState, DebitCredit, DebitCreditAmount, DecodedAccounts, DecodedPostings,
    DecoderIdentity, Enterprise24AccountingTable, EnterprisePostingAdaptation,
    EnterprisePostingExclusion, EnterpriseTableScan, GeneralJournalHeaderMetadataWitness, Ledger,
    LedgerAdapter, MaterializedAccountRow, MaterializedBillHeaderRow, MaterializedBillPostingRow,
    MaterializedCheckPostingRow, MaterializedCheckVoidCompanionCarrier,
    MaterializedGeneralJournalDisposition, Posting, PostingDisposition, PostingExclusion,
    PostingExclusionReason, PostingId, PostingProvenance, RowStorageAttestation, SourceSnapshotId,
    SysColumn, SysTableEntry, TransactionId, adapt_enterprise_posting_row_partial,
    adapt_materialized_bill_posting_row, adapt_materialized_check_posting_row,
    adapt_materialized_general_journal_posting_row, boolean_value_by_column_name,
    classify_materialized_check_void_companion,
    classify_materialized_general_journal_rows_with_header_witnesses,
    decode_schema_account_row_partial, prefix_value_by_column_name,
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
    /// Schema-decoded kind-64 Bill carriers proven to be non-posting logical
    /// rows by the table-3040 header witness and a complete retained family.
    pub logical_non_row_carriers: u64,
    /// Empty continuation segments whose same-table destination is retained.
    pub forwarding_alias_records: u64,
    /// Isolated text-payload pages corroborated by external-page coverage.
    pub external_text_payload_pages: u64,
    /// A bounded surplus of candidate pages with no declared directory rows.
    /// Observed and catalogued page counts remain separately available.
    pub certified_empty_surplus_page_groups: u64,
    /// Explicitly unsupported policy, if applicable.
    pub unsupported: bool,
    /// The prefix is known but storage facts required for decoding are absent.
    pub layout_pending: bool,
}

impl Enterprise24PartialTableCoverage {
    /// Whether this table's physical and logical coverage attestation is
    /// complete for its policy.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.complete()
    }

    fn complete(&self) -> bool {
        !self.unsupported
            && !self.layout_pending
            && self.unresolved_records == 0
            && self.decode_failures == 0
            && self.candidate_directory_disagreements == 0
            && self.expected_logical_records.is_some_and(|expected| {
                self.resolved_records
                    .checked_add(self.logical_non_row_carriers)
                    == Some(expected)
            })
            && (self.logical_non_row_carriers == 0
                || self.table_id == Enterprise24AccountingTable::BillLine.id())
            && (self.certified_empty_surplus_page_groups == 0
                || (self.table_id == Enterprise24AccountingTable::GeneralJournalLine.id()
                    && self.certified_empty_surplus_page_groups == 1
                    && self.resolved_records > 0))
            && self.expected_table_pages.is_none_or(|primary| {
                u64::from(primary)
                    .checked_add(u64::from(self.expected_external_table_pages.unwrap_or(0)))
                    .and_then(|expected| {
                        expected.checked_add(self.certified_empty_surplus_page_groups)
                    })
                    .is_some_and(|expected| expected == self.candidate_page_groups)
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
/// Forwarding aliases are resolved against retained same-table rows. An
/// isolated external text segment requires a complete catalogued page and
/// logical-row partition. Candidates must agree on Bill semantics or the
/// exact continuation locator; no unknown record is dropped to fit a count.
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
    let mut aliases = Vec::new();
    let mut external_text_candidates = 0_u64;
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
        let isolated_single_record_group =
            group.candidates.len() == 1 && counts == [1] && directory.common_record_ids.len() == 1;
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
            } else if let Some(destination) = consensus_forwarding_locator(&candidates) {
                aliases.push(((group.raw_page_number, record_id), destination));
            } else if isolated_single_record_group
                && is_r21_bill_external_text_payload(&candidates[0])
            {
                external_text_candidates += 1;
            } else {
                coverage.decode_failures += 1;
                coverage.unresolved_records += 1;
            }
        }
    }
    if validate_forwarding_aliases(&records, &aliases, |bytes| {
        MaterializedBillPostingRow::parse(bytes).is_ok()
    }) {
        coverage.forwarding_alias_records = aliases.len() as u64;
        coverage.non_row_artifacts += aliases.len() as u64;
    } else {
        coverage.decode_failures += aliases.len() as u64;
        coverage.unresolved_records += aliases.len() as u64;
    }
    if external_text_candidates != 0 {
        let expected_pages =
            u64::from(expectation.table_pages) + u64::from(expectation.external_table_pages);
        if external_text_candidates == 1
            && expectation.external_table_pages == 1
            && coverage.candidate_page_groups == expected_pages
            && coverage.resolved_records == expectation.logical_records
            && coverage.unresolved_records == 0
            && coverage.decode_failures == 0
            && coverage.candidate_directory_disagreements == 0
        {
            coverage.external_text_payload_pages = 1;
        } else {
            coverage.decode_failures += external_text_candidates;
            coverage.unresolved_records += external_text_candidates;
        }
    }
    Ok(Enterprise24PartialTableRows {
        policy,
        records,
        coverage,
    })
}

/// Collects Bill lines with the complete Bill schema and consensus-resolved
/// table-3040 master witnesses. This additionally recognizes the narrow
/// non-posting kind-64 split/link carrier; it never adapts that carrier into a
/// posting or monetary amount.
pub fn collect_enterprise24_bill_table_rows_with_context(
    scan: &EnterpriseTableScan,
    schema: &RowSchema,
    bill_header_masters: &BTreeSet<u32>,
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
    if !policy_schema_matches(policy, schema) {
        return Err(Enterprise24AccountingPipelineError::PolicyStorageMismatch {
            table_id: policy.table.id(),
        });
    }
    let through = policy
        .through_ordinal
        .expect("Bill policy has a bounded prefix");
    let mut coverage = Enterprise24PartialTableCoverage {
        table_id: policy.table.id(),
        candidate_page_groups: scan.candidate_groups.len() as u64,
        expected_logical_records: Some(expectation.logical_records),
        expected_table_pages: Some(expectation.table_pages),
        expected_external_table_pages: Some(expectation.external_table_pages),
        ..Enterprise24PartialTableCoverage::default()
    };
    let mut records = Vec::new();
    let mut pending_carriers = Vec::new();
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
            let decoded = group
                .candidates
                .iter()
                .map(|page| {
                    let bytes = page
                        .table_page()
                        .record(record_id)
                        .expect("consensus presence")
                        .bytes()
                        .to_vec();
                    decode_row_prefix_and_boolean_tail(&bytes, schema, through)
                        .map(|partial| Enterprise24PartialRecordCandidate { bytes, partial })
                })
                .collect::<Vec<_>>();
            if decoded.iter().any(Result::is_err) {
                coverage.decode_failures += 1;
                coverage.unresolved_records += 1;
                continue;
            }
            let decoded = decoded.into_iter().map(Result::unwrap).collect::<Vec<_>>();
            let Some(first) = resolve_enterprise24_partial_record_candidates(&decoded) else {
                coverage.unresolved_records += 1;
                continue;
            };
            let parsed = decoded
                .iter()
                .map(|candidate| MaterializedBillPostingRow::parse(&candidate.bytes))
                .collect::<Vec<_>>();
            if parsed.iter().all(Result::is_ok) {
                let first_posting = parsed[0].as_ref().expect("all postings parsed");
                if !parsed
                    .iter()
                    .skip(1)
                    .all(|posting| posting.as_ref() == Ok(first_posting))
                {
                    coverage.unresolved_records += 1;
                    continue;
                }
                coverage.resolved_records += 1;
                records.push(Enterprise24PartialRecord {
                    raw_page_number: group.raw_page_number,
                    record_id,
                    bytes: first.bytes,
                    partial: first.partial,
                });
            } else if is_bill_kind64_framing(&first.bytes) {
                pending_carriers.push(first);
            } else {
                coverage.decode_failures += 1;
                coverage.unresolved_records += 1;
            }
        }
    }
    let mut pending_targets = BTreeSet::new();
    for carrier in pending_carriers {
        let unique_target = named_u32(schema, &carrier.partial, "target_id")
            .is_some_and(|target| pending_targets.insert(target));
        if unique_target
            && is_attested_bill_nonposting_carrier(&carrier, &records, schema, bill_header_masters)
        {
            coverage.non_row_artifacts += 1;
            coverage.logical_non_row_carriers += 1;
        } else {
            coverage.decode_failures += 1;
            coverage.unresolved_records += 1;
        }
    }
    Ok(Enterprise24PartialTableRows {
        policy,
        records,
        coverage,
    })
}

/// Resolves distinct table-3040 Bill-header master witnesses only when every
/// materialization candidate for the same physical slot agrees.
pub fn collect_enterprise24_bill_header_master_witnesses(
    scan: &EnterpriseTableScan,
) -> Result<BTreeSet<u32>, Enterprise24AccountingPipelineError> {
    if scan.target_table_id != Enterprise24AccountingTable::BillHeader.id() {
        return Err(Enterprise24AccountingPipelineError::ScanTableMismatch {
            scan_table_id: scan.target_table_id,
            policy_table_id: Enterprise24AccountingTable::BillHeader.id(),
        });
    }
    let mut witnesses = BTreeSet::new();
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
        if directory.disagreement_record_count != 0 {
            return Err(Enterprise24AccountingPipelineError::BillHeaderWitnessResolutionFailed);
        }
        for record_id in directory.common_record_ids {
            let headers = group
                .candidates
                .iter()
                .map(|page| {
                    MaterializedBillHeaderRow::parse(
                        page.table_page()
                            .record(record_id)
                            .expect("consensus presence")
                            .bytes(),
                    )
                })
                .collect::<Vec<_>>();
            if !headers.iter().all(Result::is_ok) {
                return Err(Enterprise24AccountingPipelineError::BillHeaderWitnessResolutionFailed);
            }
            let first = headers[0].as_ref().expect("all headers parsed");
            if !headers
                .iter()
                .skip(1)
                .all(|header| header.as_ref() == Ok(first))
                || !witnesses.insert(first.bill_master_record_number())
            {
                return Err(Enterprise24AccountingPipelineError::BillHeaderWitnessResolutionFailed);
            }
        }
    }
    Ok(witnesses)
}

fn is_bill_kind64_framing(bytes: &[u8]) -> bool {
    bytes.len() >= 5
        && usize::from(u16::from_le_bytes([bytes[0], bytes[1]])) == bytes.len()
        && bytes[2] == 0x40
        && bytes[3] == 0x02
        && bytes[4] == 0x64
}

fn named_u32(schema: &RowSchema, partial: &PartialDecodedRow, name: &str) -> Option<u32> {
    match prefix_value_by_column_name(schema, partial, name).ok()?? {
        Value::Integer(value) => u32::try_from(*value).ok().filter(|value| *value != 0),
        _ => None,
    }
}

fn named_null(schema: &RowSchema, partial: &PartialDecodedRow, name: &str) -> bool {
    matches!(
        prefix_value_by_column_name(schema, partial, name),
        Ok(Some(Value::Null))
    )
}

fn named_bool(schema: &RowSchema, partial: &PartialDecodedRow, name: &str) -> Option<bool> {
    match boolean_value_by_column_name(schema, partial, name).ok()?? {
        Value::Boolean(value) => Some(*value),
        _ => None,
    }
}

fn is_attested_bill_nonposting_carrier(
    carrier: &Enterprise24PartialRecordCandidate,
    records: &[Enterprise24PartialRecord],
    schema: &RowSchema,
    headers: &BTreeSet<u32>,
) -> bool {
    if !is_bill_kind64_framing(&carrier.bytes)
        || !named_null(schema, &carrier.partial, "account_id")
        || !named_null(schema, &carrier.partial, "amount_amt")
        || named_bool(schema, &carrier.partial, "is_source_bool") != Some(false)
        || named_bool(schema, &carrier.partial, "is_no_post_bool") != Some(false)
        || named_bool(schema, &carrier.partial, "is_memorized_transaction_bool") != Some(false)
        || named_bool(schema, &carrier.partial, "is_split_bool") != Some(true)
        || named_bool(schema, &carrier.partial, "is_arap_bool") != Some(true)
    {
        return false;
    }
    let (Some(target), Some(master), Some(next), Some(sibling)) = (
        named_u32(schema, &carrier.partial, "target_id"),
        named_u32(schema, &carrier.partial, "transaction_id"),
        named_u32(schema, &carrier.partial, "next_target_id"),
        named_u32(schema, &carrier.partial, "sibling_account_id"),
    ) else {
        return false;
    };
    let (Ok(Some(date)), Ok(Some(view))) = (
        prefix_value_by_column_name(schema, &carrier.partial, "transaction_date"),
        prefix_value_by_column_name(schema, &carrier.partial, "transaction_view_type"),
    ) else {
        return false;
    };
    if !headers.contains(&master)
        || records
            .iter()
            .any(|record| named_u32(schema, &record.partial, "target_id") == Some(target))
    {
        return false;
    }
    let family = records
        .iter()
        .filter(|record| named_u32(schema, &record.partial, "transaction_id") == Some(master))
        .collect::<Vec<_>>();
    if family.len() != 5
        || family.iter().any(|record| {
            prefix_value_by_column_name(schema, &record.partial, "transaction_date")
                .ok()
                .flatten()
                != Some(date)
                || prefix_value_by_column_name(schema, &record.partial, "transaction_view_type")
                    .ok()
                    .flatten()
                    != Some(view)
        })
        || family
            .iter()
            .filter(|record| named_u32(schema, &record.partial, "target_id") == Some(next))
            .count()
            != 1
    {
        return false;
    }
    let mut accounts = BTreeSet::new();
    let mut targets = BTreeSet::new();
    let mut balance = 0_i128;
    for record in family {
        let Ok(posting) = MaterializedBillPostingRow::parse(&record.bytes) else {
            return false;
        };
        if posting.has_canonical_zero_amount() || !targets.insert(posting.target_record_number()) {
            return false;
        }
        accounts.insert(posting.account_record_number());
        balance += i128::from(posting.signed_cents());
    }
    accounts.len() == 2 && accounts.contains(&sibling) && balance == 0
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

type RecordLocation = (u64, u16);

/// A payload-free continuation. Its resolver key becomes a page reference
/// only after the table-local destination is independently retained below.
fn forwarding_locator(bytes: &[u8]) -> Option<RecordLocation> {
    let segment = opensqlany::parse_row_segment(bytes).ok()?;
    if bytes.len() != 9 || segment.declared_len() != bytes.len() || segment.flags() != 0x44 {
        return None;
    }
    let target = segment.next_target()?;
    (target.resolver_key() != 0).then_some((u64::from(target.resolver_key()), target.record_id()))
}

fn consensus_forwarding_locator(candidates: &[Vec<u8>]) -> Option<RecordLocation> {
    let first = forwarding_locator(candidates.first()?)?;
    candidates
        .iter()
        .all(|bytes| forwarding_locator(bytes) == Some(first))
        .then_some(first)
}

fn validate_forwarding_aliases(
    records: &[Enterprise24PartialRecord],
    aliases: &[(RecordLocation, RecordLocation)],
    is_posting: impl Fn(&[u8]) -> bool,
) -> bool {
    if aliases.is_empty() {
        return true;
    }
    let mut retained = BTreeMap::new();
    for record in records {
        if retained
            .insert((record.raw_page_number, record.record_id), &record.bytes)
            .is_some()
        {
            return false;
        }
    }
    let mut sources = BTreeSet::new();
    let mut destinations = BTreeSet::new();
    aliases.iter().all(|(source, destination)| {
        source != destination
            && !retained.contains_key(source)
            && sources.insert(*source)
            && destinations.insert(*destination)
            && retained
                .get(destination)
                .is_some_and(|bytes| forwarding_locator(bytes).is_none() && is_posting(bytes))
    })
}

fn is_r21_bill_external_text_payload(bytes: &[u8]) -> bool {
    let Ok(segment) = opensqlany::parse_row_segment(bytes) else {
        return false;
    };
    let payload = segment.payload();
    segment.declared_len() == bytes.len()
        && segment.flags() == 0
        && payload.iter().any(u8::is_ascii_graphic)
        && payload
            .iter()
            .all(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
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
    let mut aliases = Vec::new();
    let mut zero_slot_groups = 0_u64;
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
        if !counts.is_empty() && counts.iter().all(|&count| count == 0) {
            zero_slot_groups += 1;
        }
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
            if let Some(destination) = forwarding_locator(first) {
                aliases.push(((group.raw_page_number, record_id), destination));
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
    if validate_forwarding_aliases(&records, &aliases, |bytes| {
        crate::MaterializedGeneralJournalPostingRow::parse(bytes).is_ok()
    }) {
        coverage.forwarding_alias_records = aliases.len() as u64;
        coverage.non_row_artifacts += aliases.len() as u64;
    } else {
        coverage.decode_failures += aliases.len() as u64;
        coverage.unresolved_records += aliases.len() as u64;
    }
    let expected_pages =
        u64::from(expectation.table_pages) + u64::from(expectation.external_table_pages);
    if coverage.candidate_page_groups == expected_pages + 1
        && zero_slot_groups > 0
        && coverage.resolved_records > 0
        && coverage.resolved_records == expectation.logical_records
        && coverage.unresolved_records == 0
        && coverage.decode_failures == 0
        && coverage.candidate_directory_disagreements == 0
    {
        coverage.certified_empty_surplus_page_groups = 1;
    }
    Ok(Enterprise24PartialTableRows {
        policy,
        records,
        coverage,
    })
}

/// Collects exact General Journal header witnesses from byte-identical candidates.
///
/// The headers are used only to corroborate the separate family-64 metadata
/// grammar; they are not decoded into ledger postings.
pub fn collect_enterprise24_general_journal_header_metadata_witnesses(
    scan: &EnterpriseTableScan,
) -> Result<Vec<GeneralJournalHeaderMetadataWitness>, Enterprise24AccountingPipelineError> {
    let table_id = Enterprise24AccountingTable::GeneralJournalHeader.id();
    if scan.target_table_id != table_id {
        return Err(Enterprise24AccountingPipelineError::ScanTableMismatch {
            scan_table_id: scan.target_table_id,
            policy_table_id: table_id,
        });
    }
    let mut witnesses = Vec::new();
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
        if directory.disagreement_record_count != 0 {
            return Err(Enterprise24AccountingPipelineError::HeaderWitnessConsensusFailed);
        }
        for record_id in directory.common_record_ids {
            let candidates = group
                .candidates
                .iter()
                .map(|page| {
                    page.table_page()
                        .record(record_id)
                        .expect("candidate-directory consensus established presence")
                        .bytes()
                })
                .collect::<Vec<_>>();
            let Some(first) = candidates.first() else {
                return Err(Enterprise24AccountingPipelineError::HeaderWitnessConsensusFailed);
            };
            if !candidates
                .iter()
                .skip(1)
                .all(|candidate| *candidate == *first)
            {
                return Err(Enterprise24AccountingPipelineError::HeaderWitnessConsensusFailed);
            }
            let has_header_framing = first.len() >= 23
                && first.get(0..2).is_some_and(|declared| {
                    u16::from_le_bytes([declared[0], declared[1]]) as usize == first.len()
                })
                && first.get(2) == Some(&crate::MATERIALIZED_GENERAL_JOURNAL_FLAGS)
                && first.get(3) == Some(&crate::MATERIALIZED_GENERAL_JOURNAL_ROW_KIND)
                && first.get(4..7) == Some(&[0xa7, 0xfe, 0][..]);
            if !has_header_framing {
                continue;
            }
            let witness = GeneralJournalHeaderMetadataWitness::parse(first)
                .map_err(|_| Enterprise24AccountingPipelineError::HeaderWitnessParseFailed)?;
            witnesses.push(witness);
        }
    }
    Ok(witnesses)
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
    /// More than one supplied table census claimed the same table identity.
    DuplicateTableCoverage { table_id: u32 },
    /// A row collection's decoder policy did not attest the same table as its coverage.
    TablePolicyCoverageMismatch {
        policy_table_id: u32,
        coverage_table_id: u32,
    },
    /// More than one physical Account row claimed the same record number.
    DuplicateAccountRecordNumber { record_number: u32 },
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
    /// Every attested strategy for a posting family rejected its complete
    /// evidence; this is not itself a claim that its monetary masters failed.
    PostingStrategyRejected { table_id: u32 },
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
    build_enterprise24_accounting_pipeline_with_general_journal_header_witnesses(
        snapshot,
        catalog_columns,
        account_rows,
        posting_rows,
        schemas,
        &[],
    )
}

/// Builds the accounting pipeline with consensus table-3076 header context.
pub fn build_enterprise24_accounting_pipeline_with_general_journal_header_witnesses(
    snapshot: SourceSnapshotId,
    catalog_columns: &[SysColumn],
    account_rows: &Enterprise24PartialTableRows,
    posting_rows: &[Enterprise24PartialTableRows],
    schemas: &BTreeMap<u32, RowSchema>,
    general_journal_header_witnesses: &[GeneralJournalHeaderMetadataWitness],
) -> Enterprise24AccountingPipelineResult {
    let mut diagnostics = Enterprise24AccountingCoverageDiagnostics::default();
    if validate_enterprise24_r21_schema_manifest(catalog_columns).is_err() {
        diagnostics
            .blockers
            .push(Enterprise24AccountingPipelineBlocker::SchemaManifestValidationFailed);
    }
    add_table_coverage(
        &mut diagnostics,
        account_rows.policy.table.id(),
        &account_rows.coverage,
    );
    for rows in posting_rows {
        add_table_coverage(&mut diagnostics, rows.policy.table.id(), &rows.coverage);
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
    let mut identity_map = BTreeMap::new();
    for record in &account_rows.records {
        let identity = match MaterializedAccountRow::parse(&record.bytes) {
            Ok(identity) => identity,
            Err(_) => {
                diagnostics.blockers.push(
                    Enterprise24AccountingPipelineBlocker::AccountAdaptationFailed {
                        page: record.raw_page_number,
                        record: record.record_id,
                    },
                );
                continue;
            }
        };
        let id = match AccountId::new(identity.ordinary_list_id()) {
            Ok(id) => id,
            Err(_) => {
                diagnostics.blockers.push(
                    Enterprise24AccountingPipelineBlocker::AccountAdaptationFailed {
                        page: record.raw_page_number,
                        record: record.record_id,
                    },
                );
                continue;
            }
        };
        let record_number = identity.record_number();
        if identity_map.contains_key(&record_number) {
            diagnostics.blockers.push(
                Enterprise24AccountingPipelineBlocker::DuplicateAccountRecordNumber {
                    record_number,
                },
            );
            continue;
        }
        identity_map.insert(record_number, id);
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
            let carriers = match classify_materialized_general_journal_rows_with_header_witnesses(
                &rows
                    .records
                    .iter()
                    .map(|record| record.bytes.clone())
                    .collect::<Vec<_>>(),
                general_journal_header_witnesses,
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
                    | MaterializedGeneralJournalDisposition::HeaderMetadataCarrier { .. }
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
            let selected = schemas.get(&table.id()).ok_or(()).and_then(|schema| {
                try_materialized_check_dispositions(rows, schema, &identity_map)
                    .or_else(|_| try_partial_check_dispositions(rows, schema, &identity_map))
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
                        Enterprise24AccountingPipelineBlocker::PostingStrategyRejected {
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
            if validate_materialized_bill_zero_families(&rows.records).is_err() {
                diagnostics.blockers.push(
                    Enterprise24AccountingPipelineBlocker::PostingStrategyRejected {
                        table_id: table.id(),
                    },
                );
                continue;
            }
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
        if table == Enterprise24AccountingTable::BillPaymentCheckLine
            && validate_partial_zero_families(table, &rows.records, schema, &BTreeSet::new())
                .is_err()
        {
            diagnostics.blockers.push(
                Enterprise24AccountingPipelineBlocker::PostingStrategyRejected {
                    table_id: table.id(),
                },
            );
            continue;
        }
        if table == Enterprise24AccountingTable::DepositLine {
            let headers = match deposit_nonposting_header_record_ids(&rows.records, schema) {
                Ok(headers) => headers,
                Err(()) => {
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
            // Only the independently proven header topologies may skip
            // monetary-row validation; unknown carriers remain failures.
            if validate_partial_zero_families(table, &rows.records, schema, &headers).is_err() {
                diagnostics.blockers.push(
                    Enterprise24AccountingPipelineBlocker::PostingStrategyRejected {
                        table_id: table.id(),
                    },
                );
                continue;
            }
            match validate_deposit_master_balances(&rows.records, schema, &headers) {
                Ok(()) => {}
                Err(DepositTableValidationError::Adaptation) => {
                    diagnostics.blockers.push(
                        Enterprise24AccountingPipelineBlocker::PostingAdaptationFailed {
                            table_id: table.id(),
                            page: 0,
                            record: 0,
                        },
                    );
                    continue;
                }
                Err(DepositTableValidationError::Unbalanced) => {
                    diagnostics.blockers.push(
                        Enterprise24AccountingPipelineBlocker::UnbalancedPostingMasters {
                            table_id: table.id(),
                        },
                    );
                    continue;
                }
            }
            for record in &rows.records {
                diagnostics.posting_candidates += 1;
                if headers.contains(&(record.raw_page_number, record.record_id)) {
                    match deposit_nonposting_header_disposition(record, rows.policy.version) {
                        Ok(disposition) => {
                            diagnostics.excluded_postings += 1;
                            dispositions.push(disposition);
                        }
                        Err(()) => diagnostics.blockers.push(
                            Enterprise24AccountingPipelineBlocker::PostingAdaptationFailed {
                                table_id: table.id(),
                                page: record.raw_page_number,
                                record: record.record_id,
                            },
                        ),
                    }
                    continue;
                }
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
            continue;
        }
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

/// Identifies the two exact non-posting Deposit headers found by the complete
/// table census.  A matching byte envelope alone is never enough: each header
/// must occur once in its complete same-transaction topology, and every
/// economic sibling must be independently adaptable and balanced.
fn deposit_nonposting_header_record_ids(
    rows: &[Enterprise24PartialRecord],
    schema: &RowSchema,
) -> Result<BTreeSet<(u64, u16)>, ()> {
    const HEADER_70_LEN: usize = 108;
    const HEADER_71_LEN: usize = 112;
    const HEADER_70_KIND: u8 = 0x70;
    const HEADER_71_KIND: u8 = 0x71;
    const LINKED_KIND: u8 = 0xe1;
    const COUNTERPART_F1_KIND: u8 = 0xf1;

    let mut by_transaction = BTreeMap::<u64, Vec<&Enterprise24PartialRecord>>::new();
    let mut all_targets = BTreeSet::new();
    for record in rows {
        if !all_targets.insert(deposit_partial_id(record, schema, "target_id")?) {
            return Err(());
        }
        by_transaction
            .entry(deposit_partial_id(record, schema, "transaction_id")?)
            .or_default()
            .push(record);
    }
    let mut headers = BTreeSet::new();
    for group in by_transaction.values() {
        let header_candidates = group
            .iter()
            .copied()
            .filter(|record| deposit_header_envelope(&record.bytes).is_some())
            .collect::<Vec<_>>();
        if header_candidates.is_empty() {
            continue;
        }
        if header_candidates.len() != 1 {
            return Err(());
        }
        let header = header_candidates[0];
        let Some(kind) = deposit_header_envelope(&header.bytes) else {
            return Err(());
        };
        let expected_split = match kind {
            HEADER_70_KIND => true,
            HEADER_71_KIND => false,
            _ => return Err(()),
        };
        if !deposit_header_fields_match(header, schema, expected_split)? {
            return Err(());
        }
        match kind {
            HEADER_70_KIND if header.bytes.len() == HEADER_70_LEN => {
                if group.len() != 4 {
                    return Err(());
                }
                let siblings = group
                    .iter()
                    .copied()
                    .filter(|record| !std::ptr::eq(*record, header))
                    .collect::<Vec<_>>();
                let mut adapted = Vec::new();
                for sibling in siblings {
                    let EnterprisePostingAdaptation::Posting(posting) =
                        adapt_enterprise_posting_row_partial(
                            Enterprise24AccountingTable::DepositLine,
                            schema,
                            &sibling.partial,
                        )
                        .map_err(|_| ())?
                    else {
                        return Err(());
                    };
                    adapted.push((sibling, posting));
                }
                let linked_sources = adapted
                    .iter()
                    .filter(|(record, posting)| {
                        record.bytes.get(3) == Some(&LINKED_KIND)
                            && posting.is_source == Some(true)
                            && posting.is_split == Some(true)
                    })
                    .count();
                let counterparts = adapted
                    .iter()
                    .filter(|(record, posting)| {
                        record.bytes.get(3) == Some(&COUNTERPART_F1_KIND)
                            && posting.is_source == Some(false)
                            && posting.is_split == Some(true)
                    })
                    .count();
                if linked_sources != 1
                    || counterparts != 2
                    || adapted
                        .iter()
                        .map(|(_, posting)| i128::from(posting.amount_cents))
                        .sum::<i128>()
                        != 0
                {
                    return Err(());
                }
            }
            HEADER_71_KIND if header.bytes.len() == HEADER_71_LEN => {
                if group.len() != 2 {
                    return Err(());
                }
                let sibling = group
                    .iter()
                    .copied()
                    .find(|record| !std::ptr::eq(*record, header))
                    .ok_or(())?;
                if sibling.bytes.get(3) != Some(&LINKED_KIND)
                    || !deposit_partial_bool(sibling, schema, "is_source_bool")?
                    || deposit_partial_bool(sibling, schema, "is_split_bool")?
                    || !deposit_partial_is_null(sibling, schema, "amount_amt")?
                    || deposit_partial_is_null(sibling, schema, "account_id")?
                    || !matches!(
                        adapt_enterprise_posting_row_partial(
                            Enterprise24AccountingTable::DepositLine,
                            schema,
                            &sibling.partial,
                        ),
                        Ok(EnterprisePostingAdaptation::Excluded(
                            EnterprisePostingExclusion::SourceOrLink { .. }
                        ))
                    )
                {
                    return Err(());
                }
            }
            _ => return Err(()),
        }
        headers.insert((header.raw_page_number, header.record_id));
    }
    Ok(headers)
}

fn deposit_header_envelope(bytes: &[u8]) -> Option<u8> {
    let [first, second, flags, kind, ..] = bytes else {
        return None;
    };
    let declared = usize::from(u16::from_le_bytes([*first, *second]));
    (declared == bytes.len() && *flags == 0 && matches!(*kind, 0x70 | 0x71)).then_some(*kind)
}

fn deposit_header_fields_match(
    record: &Enterprise24PartialRecord,
    schema: &RowSchema,
    expected_split: bool,
) -> Result<bool, ()> {
    Ok(deposit_partial_is_null(record, schema, "account_id")?
        && deposit_partial_is_null(record, schema, "amount_amt")?
        && !deposit_partial_bool(record, schema, "is_source_bool")?
        && !deposit_partial_bool(record, schema, "is_no_post_bool")?
        && !deposit_partial_bool(record, schema, "is_memorized_transaction_bool")?
        && deposit_partial_bool(record, schema, "is_split_bool")? == expected_split)
}

fn deposit_partial_value<'a>(
    record: &'a Enterprise24PartialRecord,
    schema: &'a RowSchema,
    name: &str,
) -> Result<&'a Value, ()> {
    prefix_value_by_column_name(schema, &record.partial, name)
        .map_err(|_| ())?
        .ok_or(())
}

fn deposit_partial_id(
    record: &Enterprise24PartialRecord,
    schema: &RowSchema,
    name: &str,
) -> Result<u64, ()> {
    let column = schema
        .columns
        .iter()
        .find(|column| column.name == name)
        .ok_or(())?;
    if !matches!(
        column.column_type,
        ColumnType::Integer
            | ColumnType::Integer2
            | ColumnType::UInt32
            | ColumnType::UInt64
            | ColumnType::Int64
    ) {
        return Err(());
    }
    match deposit_partial_value(record, schema, name)? {
        Value::Unsigned(value) if *value != 0 => Ok(*value),
        Value::Integer(value) if *value > 0 => u64::try_from(*value).map_err(|_| ()),
        _ => Err(()),
    }
}

fn deposit_partial_bool(
    record: &Enterprise24PartialRecord,
    schema: &RowSchema,
    name: &str,
) -> Result<bool, ()> {
    match boolean_value_by_column_name(schema, &record.partial, name)
        .map_err(|_| ())?
        .ok_or(())?
    {
        Value::Boolean(value) => Ok(*value),
        _ => Err(()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DepositTableValidationError {
    Adaptation,
    Unbalanced,
}

fn validate_deposit_master_balances(
    rows: &[Enterprise24PartialRecord],
    schema: &RowSchema,
    headers: &BTreeSet<(u64, u16)>,
) -> Result<(), DepositTableValidationError> {
    let mut balances = BTreeMap::<u64, i128>::new();
    for record in rows {
        if headers.contains(&(record.raw_page_number, record.record_id)) {
            continue;
        }
        let adaptation = adapt_enterprise_posting_row_partial(
            Enterprise24AccountingTable::DepositLine,
            schema,
            &record.partial,
        )
        .map_err(|_| DepositTableValidationError::Adaptation)?;
        if let EnterprisePostingAdaptation::Posting(posting) = adaptation {
            *balances.entry(posting.transaction_id).or_default() +=
                i128::from(posting.amount_cents);
        }
    }
    balances
        .into_values()
        .all(|balance| balance == 0)
        .then_some(())
        .ok_or(DepositTableValidationError::Unbalanced)
}

fn deposit_partial_is_null(
    record: &Enterprise24PartialRecord,
    schema: &RowSchema,
    name: &str,
) -> Result<bool, ()> {
    Ok(matches!(
        deposit_partial_value(record, schema, name)?,
        Value::Null
    ))
}

fn deposit_nonposting_header_disposition(
    record: &Enterprise24PartialRecord,
    decoder: &str,
) -> Result<PostingDisposition, ()> {
    let provenance = PostingProvenance::new(
        format!(
            "enterprise24:{}:{}:{}",
            Enterprise24AccountingTable::DepositLine.id(),
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
    schema: &RowSchema,
    identity_map: &BTreeMap<u32, AccountId>,
) -> Result<Vec<PostingDisposition>, ()> {
    prepare_check_dispositions(rows, schema, identity_map, |record| {
        adapt_check_observation(record, schema)
    })
}

/// Every nonzero amount remains on the strict physical path. A direct
/// canonical zero with an opaque suffix may instead be a neutral observation
/// only when the attested named prefix and the fixed physical header agree.
/// This does not attest the suffix or permit a schema-derived nonzero amount.
fn adapt_check_observation(
    record: &Enterprise24PartialRecord,
    schema: &RowSchema,
) -> Result<EnterprisePostingAdaptation, ()> {
    match MaterializedCheckPostingRow::parse(&record.bytes) {
        Ok(row) => adapt_materialized_check_posting_row(&row).map_err(|_| ()),
        Err(crate::MaterializedCheckPostingRowError::UnattestedAmountEnvelope { .. }) => {
            let adaptation = adapt_enterprise_posting_row_partial(
                Enterprise24AccountingTable::CheckLine,
                schema,
                &record.partial,
            )
            .map_err(|_| ())?;
            let EnterprisePostingAdaptation::Excluded(
                EnterprisePostingExclusion::CanonicalZeroAmount {
                    target_id,
                    transaction_id,
                    account_id,
                    transaction_date,
                    transaction_type,
                },
            ) = adaptation
            else {
                return Err(());
            };
            let bytes = &record.bytes;
            if bytes.len() < 0x55
                || usize::from(u16::from_le_bytes([bytes[0], bytes[1]])) != bytes.len()
                || bytes[2] != 0
                || bytes[3] != crate::MATERIALIZED_CHECK_POSTING_KIND
                || bytes.get(0x53..0x55) != Some(&[0, 0x81])
            {
                return Err(());
            }
            let read = |offset: usize| {
                bytes
                    .get(offset..offset + 4)
                    .and_then(|value| value.try_into().ok())
                    .map(u32::from_le_bytes)
            };
            if read(0x0c) != u32::try_from(target_id).ok()
                || read(0x10) != u32::try_from(transaction_id).ok()
                || read(0x14) != u32::try_from(account_id).ok()
                || crate::MaterializedPostingDate::from_raw_bits(read(0x18).ok_or(())?)
                    .map_err(|_| ())?
                    .accounting_date()
                    != transaction_date
                || transaction_type != crate::EnterprisePostingTransactionType::Check
                || (read(0x22).ok_or(())? == 0 && read(0x1e).ok_or(())? == 0)
            {
                return Err(());
            }
            Ok(EnterprisePostingAdaptation::Excluded(
                EnterprisePostingExclusion::CanonicalZeroAmount {
                    target_id,
                    transaction_id,
                    account_id,
                    transaction_date,
                    transaction_type,
                },
            ))
        }
        Err(_) => Err(()),
    }
}

fn try_partial_check_dispositions(
    rows: &Enterprise24PartialTableRows,
    schema: &RowSchema,
    identity_map: &BTreeMap<u32, AccountId>,
) -> Result<Vec<PostingDisposition>, ()> {
    prepare_check_dispositions(rows, schema, identity_map, |record| {
        adapt_enterprise_posting_row_partial(
            Enterprise24AccountingTable::CheckLine,
            schema,
            &record.partial,
        )
        .map_err(|_| ())
    })
}

#[derive(Clone, Copy)]
struct CompactCheckSourceLink {
    target_id: u64,
    transaction_id: u64,
    transaction_date: crate::AccountingDate,
    next_target_id: u64,
    sibling_account_id: u64,
}

/// The compact kind-64 source row is an observed, schema-bound link carrier.
/// Its nullable principal fields cannot be interpreted as a posting.  Admission
/// is deliberately deferred until its named next target is retained in the
/// same balanced Check family.
fn compact_check_source_link(
    record: &Enterprise24PartialRecord,
    schema: &RowSchema,
) -> Result<Option<CompactCheckSourceLink>, ()> {
    let bytes = &record.bytes;
    if bytes.len() != 151
        || usize::from(u16::from_le_bytes([bytes[0], bytes[1]])) != bytes.len()
        || bytes[2] != 0
        || bytes[3] != crate::MATERIALIZED_CHECK_VOID_COMPANION_KIND
    {
        return Ok(None);
    }
    let target_id = check_partial_id(record, schema, "target_id")?;
    let transaction_id = check_partial_id(record, schema, "transaction_id")?;
    let next_target_id = check_partial_id(record, schema, "next_target_id")?;
    let sibling_account_id = check_partial_id(record, schema, "sibling_account_id")?;
    let transaction_date = check_partial_date(record, schema, "transaction_date")?;
    if bytes
        .get(0x0c..0x10)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        != u32::try_from(target_id).ok()
        || bytes
            .get(0x10..0x14)
            .and_then(|value| value.try_into().ok())
            .map(u32::from_le_bytes)
            != u32::try_from(transaction_id).ok()
        || !check_partial_is_null(record, schema, "account_id")?
        || !check_partial_is_null(record, schema, "amount_amt")?
        || check_partial_small_int(record, schema, "transaction_view_type")? != 3
        || check_partial_bool(record, schema, "is_source_bool")?
        || check_partial_bool(record, schema, "is_no_post_bool")?
        || check_partial_bool(record, schema, "is_memorized_transaction_bool")?
        || !check_partial_bool(record, schema, "is_split_bool")?
        || target_id == transaction_id
        || target_id == next_target_id
    {
        return Err(());
    }
    Ok(Some(CompactCheckSourceLink {
        target_id,
        transaction_id,
        transaction_date,
        next_target_id,
        sibling_account_id,
    }))
}

fn check_partial_value<'a>(
    record: &'a Enterprise24PartialRecord,
    schema: &'a RowSchema,
    name: &str,
) -> Result<(&'a opensqlany::ColumnDef, &'a Value), ()> {
    let columns = schema
        .columns
        .iter()
        .filter(|column| column.name == name)
        .collect::<Vec<_>>();
    let [column] = columns.as_slice() else {
        return Err(());
    };
    let value = if column.column_type == ColumnType::Boolean {
        boolean_value_by_column_name(schema, &record.partial, name).map_err(|_| ())?
    } else {
        prefix_value_by_column_name(schema, &record.partial, name).map_err(|_| ())?
    }
    .ok_or(())?;
    Ok((column, value))
}

fn check_partial_id(
    record: &Enterprise24PartialRecord,
    schema: &RowSchema,
    name: &str,
) -> Result<u64, ()> {
    let (column, value) = check_partial_value(record, schema, name)?;
    if !matches!(
        column.column_type,
        ColumnType::Integer
            | ColumnType::Integer2
            | ColumnType::UInt32
            | ColumnType::UInt64
            | ColumnType::Int64
    ) {
        return Err(());
    }
    match value {
        Value::Integer(value) if *value > 0 => u64::try_from(*value).map_err(|_| ()),
        Value::Unsigned(value) if *value != 0 => Ok(*value),
        _ => Err(()),
    }
}

fn check_partial_date(
    record: &Enterprise24PartialRecord,
    schema: &RowSchema,
    name: &str,
) -> Result<crate::AccountingDate, ()> {
    let (column, value) = check_partial_value(record, schema, name)?;
    let Value::Date(value) = value else {
        return Err(());
    };
    (column.column_type == ColumnType::Date)
        .then(|| crate::MaterializedPostingDate::from_raw_minutes(value.raw_minutes))
        .ok_or(())?
        .map_err(|_| ())
        .map(|value| value.accounting_date())
}

fn check_partial_small_int(
    record: &Enterprise24PartialRecord,
    schema: &RowSchema,
    name: &str,
) -> Result<i64, ()> {
    let (column, value) = check_partial_value(record, schema, name)?;
    if column.column_type != ColumnType::SmallInt {
        return Err(());
    }
    match value {
        Value::Integer(value) => Ok(*value),
        Value::Unsigned(value) => i64::try_from(*value).map_err(|_| ()),
        _ => Err(()),
    }
}

fn check_partial_bool(
    record: &Enterprise24PartialRecord,
    schema: &RowSchema,
    name: &str,
) -> Result<bool, ()> {
    let (column, value) = check_partial_value(record, schema, name)?;
    matches!(column.column_type, ColumnType::Boolean)
        .then_some(())
        .ok_or(())?;
    match value {
        Value::Boolean(value) => Ok(*value),
        _ => Err(()),
    }
}

fn check_partial_is_null(
    record: &Enterprise24PartialRecord,
    schema: &RowSchema,
    name: &str,
) -> Result<bool, ()> {
    Ok(matches!(
        check_partial_value(record, schema, name)?.1,
        Value::Null
    ))
}

fn check_adaptation_target(adaptation: &EnterprisePostingAdaptation) -> Result<u64, ()> {
    match adaptation {
        EnterprisePostingAdaptation::Posting(row) => Ok(row.target_id),
        EnterprisePostingAdaptation::Excluded(
            EnterprisePostingExclusion::CanonicalZeroAmount { target_id, .. }
            | EnterprisePostingExclusion::NoPost { target_id, .. }
            | EnterprisePostingExclusion::MemorizedTransaction { target_id, .. }
            | EnterprisePostingExclusion::SourceOrLink { target_id, .. },
        ) => Ok(*target_id),
        EnterprisePostingAdaptation::Excluded(
            EnterprisePostingExclusion::CanonicalZeroVoided { .. },
        ) => Err(()),
    }
}

#[derive(Default)]
struct CheckMasterObservation {
    zero_targets: BTreeSet<u64>,
    nonzero_count: u64,
    nonzero_net: i128,
}

/// Both strategies use the same complete-family validation. Observations are
/// collected once, so balance, companion proof, and normalization cannot
/// accidentally use different decoders or skip a zero-only observation.
fn prepare_check_dispositions(
    rows: &Enterprise24PartialTableRows,
    schema: &RowSchema,
    identity_map: &BTreeMap<u32, AccountId>,
    adapt: impl Fn(&Enterprise24PartialRecord) -> Result<EnterprisePostingAdaptation, ()>,
) -> Result<Vec<PostingDisposition>, ()> {
    let mut observations = Vec::with_capacity(rows.records.len());
    let mut compact_sources = BTreeMap::new();
    let mut carriers = BTreeMap::<usize, MaterializedCheckVoidCompanionCarrier>::new();
    let mut carrier_counts = BTreeMap::<u64, usize>::new();
    let mut carrier_targets = BTreeSet::new();
    let mut all_targets = BTreeSet::new();
    let mut masters = BTreeMap::<u64, CheckMasterObservation>::new();
    for (index, record) in rows.records.iter().enumerate() {
        if let Ok(carrier) = MaterializedCheckVoidCompanionCarrier::parse(&record.bytes) {
            let master = u64::from(carrier.master_record_number());
            let target = u64::from(carrier.target_record_number());
            if target == master || !carrier_targets.insert(target) || !all_targets.insert(target) {
                return Err(());
            }
            *carrier_counts.entry(master).or_default() += 1;
            carriers.insert(index, carrier);
            observations.push(None);
            continue;
        }
        if record.bytes.len() == 151
            && record.bytes.get(3) == Some(&crate::MATERIALIZED_CHECK_VOID_COMPANION_KIND)
        {
            let source = compact_check_source_link(record, schema)?.ok_or(())?;
            if !all_targets.insert(source.target_id) {
                return Err(());
            }
            compact_sources.insert(index, source);
            observations.push(None);
            continue;
        }
        let adaptation = adapt(record)?;
        let target = check_adaptation_target(&adaptation)?;
        if !all_targets.insert(target) {
            return Err(());
        }
        observations.push(Some(adaptation));
    }

    let retained = observations
        .iter()
        .flatten()
        .filter_map(|adaptation| match adaptation {
            EnterprisePostingAdaptation::Posting(row) => Some((
                row.target_id,
                (row.transaction_id, row.transaction_date, row.account_id),
            )),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let mut compact_next_targets = BTreeSet::new();
    for (index, source) in compact_sources {
        let next = retained.get(&source.next_target_id).ok_or(())?;
        if next.0 != source.transaction_id
            || next.1 != source.transaction_date
            || next.2 == source.sibling_account_id
            || !identity_map.contains_key(&u32::try_from(next.2).map_err(|_| ())?)
            || !identity_map
                .contains_key(&u32::try_from(source.sibling_account_id).map_err(|_| ())?)
            || !compact_next_targets.insert(source.next_target_id)
        {
            return Err(());
        }
        let mut sibling_present = false;
        for adaptation in observations.iter().flatten() {
            let (master, date, account) = match adaptation {
                EnterprisePostingAdaptation::Posting(row) => (
                    row.transaction_id,
                    row.transaction_date,
                    Some(row.account_id),
                ),
                EnterprisePostingAdaptation::Excluded(
                    EnterprisePostingExclusion::CanonicalZeroAmount {
                        transaction_id,
                        transaction_date,
                        account_id,
                        ..
                    },
                ) => (*transaction_id, *transaction_date, Some(*account_id)),
                _ => continue,
            };
            if master == source.transaction_id {
                if date != source.transaction_date {
                    return Err(());
                }
                sibling_present |= account == Some(source.sibling_account_id);
            }
        }
        if !sibling_present {
            return Err(());
        }
        observations[index] = Some(EnterprisePostingAdaptation::Excluded(
            EnterprisePostingExclusion::SourceOrLink {
                target_id: source.target_id,
                transaction_id: source.transaction_id,
            },
        ));
    }

    let mut targets = BTreeSet::new();
    for adaptation in observations.iter().flatten() {
        let monetary = match &adaptation {
            EnterprisePostingAdaptation::Posting(row) => {
                let master = masters.entry(row.transaction_id).or_default();
                master.nonzero_count += 1;
                master.nonzero_net += i128::from(row.amount_cents);
                Some(row.target_id)
            }
            EnterprisePostingAdaptation::Excluded(
                EnterprisePostingExclusion::CanonicalZeroAmount {
                    target_id,
                    transaction_id,
                    ..
                },
            ) => {
                masters
                    .entry(*transaction_id)
                    .or_default()
                    .zero_targets
                    .insert(*target_id);
                Some(*target_id)
            }
            EnterprisePostingAdaptation::Excluded(
                EnterprisePostingExclusion::NoPost { .. }
                | EnterprisePostingExclusion::MemorizedTransaction { .. }
                | EnterprisePostingExclusion::SourceOrLink { .. },
            ) => None,
            // No current adapter produces this legacy lifecycle assertion.
            // It cannot substitute for the complete companion proof below.
            EnterprisePostingAdaptation::Excluded(
                EnterprisePostingExclusion::CanonicalZeroVoided { .. },
            ) => return Err(()),
        };
        if monetary.is_some_and(|target| !targets.insert(target)) {
            return Err(());
        }
    }
    let target_collision = !targets.is_disjoint(&carrier_targets);
    let carrier_count_invalid = carrier_counts.values().any(|count| *count != 1);
    let master_invalid = masters.values().any(|master| master.nonzero_net != 0);
    if target_collision || carrier_count_invalid || master_invalid {
        return Err(());
    }
    let mut evidence = BTreeMap::new();
    for master in carrier_counts.keys() {
        let observation = masters.get(master).ok_or(())?;
        if observation.zero_targets.len() != 2 || observation.nonzero_count != 0 {
            return Err(());
        }
        evidence.insert(
            *master,
            CheckVoidCompanionMasterEvidence {
                canonical_zero_e4_row_count: 2,
                nonzero_posting_row_count: 0,
            },
        );
    }
    rows.records
        .iter()
        .zip(observations)
        .enumerate()
        .map(|(index, (record, adaptation))| {
            if let Some(carrier) = carriers.get(&index) {
                check_companion_disposition(record, *carrier, &evidence, rows.policy.version)
            } else {
                normalized_disposition(
                    Enterprise24AccountingTable::CheckLine,
                    record,
                    adaptation.ok_or(())?,
                    identity_map,
                    rows.policy.version,
                )
                .map_err(|_| ())
            }
        })
        .collect()
}

#[cfg(test)]
fn validate_check_master_balances(rows: &[Enterprise24PartialRecord]) -> Result<(), ()> {
    let accounts = BTreeMap::from([
        (7, AccountId::new("sample-account-a").unwrap()),
        (8, AccountId::new("sample-account-b").unwrap()),
    ]);
    let table = Enterprise24PartialTableRows {
        policy: enterprise24_r21_partial_table_policy(Enterprise24AccountingTable::CheckLine)
            .ok_or(())?,
        records: rows.to_vec(),
        coverage: Enterprise24PartialTableCoverage::default(),
    };
    prepare_check_dispositions(&table, &RowSchema::new(Vec::new()), &accounts, |record| {
        let row = MaterializedCheckPostingRow::parse(&record.bytes).map_err(|_| ())?;
        adapt_materialized_check_posting_row(&row).map_err(|_| ())
    })
    .map(|_| ())
}

fn validate_materialized_bill_zero_families(rows: &[Enterprise24PartialRecord]) -> Result<(), ()> {
    let mut families = BTreeMap::<u32, Vec<MaterializedBillPostingRow>>::new();
    let mut targets = BTreeSet::new();
    for record in rows {
        let row = MaterializedBillPostingRow::parse(&record.bytes).map_err(|_| ())?;
        if !targets.insert(row.target_record_number()) {
            return Err(());
        }
        families
            .entry(row.master_record_number())
            .or_default()
            .push(row);
    }
    for family in families.values() {
        let zeros = family
            .iter()
            .filter(|row| row.has_canonical_zero_amount())
            .collect::<Vec<_>>();
        if zeros.is_empty() {
            continue;
        }
        // Canonical-zero splits can coexist with balanced monetary siblings.
        // Logical targets identify distinct lines, even when accounts repeat.
        // A uniform date and known view preserve the attested Bill family;
        // zero does not select a current version or establish a void.
        let zero = zeros[0];
        let date = zero.posting_date().map_err(|_| ())?;
        let kind = zero.transaction_kind().ok_or(())?;
        let mut net = 0_i128;
        for row in family {
            if row.posting_date().map_err(|_| ())? != date || row.transaction_kind() != Some(kind) {
                return Err(());
            }
            if !row.has_canonical_zero_amount() {
                net += i128::from(row.signed_cents());
            }
        }
        if net != 0 {
            return Err(());
        }
    }
    Ok(())
}

/// Generic families that now expose an attested canonical-zero adaptation use
/// the same no-mixed-siblings rule as Check. This includes Deposit so the new
/// adapter branch cannot silently widen that family.
fn validate_partial_zero_families(
    table: Enterprise24AccountingTable,
    rows: &[Enterprise24PartialRecord],
    schema: &RowSchema,
    proven_headers: &BTreeSet<(u64, u16)>,
) -> Result<(), ()> {
    let mut families = BTreeMap::<u64, (u32, u32)>::new();
    let mut targets = BTreeSet::new();
    for record in rows {
        if proven_headers.contains(&(record.raw_page_number, record.record_id)) {
            continue;
        }
        let adaptation =
            adapt_enterprise_posting_row_partial(table, schema, &record.partial).map_err(|_| ())?;
        let (target_id, transaction_id, zero) = match adaptation {
            EnterprisePostingAdaptation::Posting(row) => (row.target_id, row.transaction_id, false),
            EnterprisePostingAdaptation::Excluded(
                EnterprisePostingExclusion::CanonicalZeroAmount {
                    target_id,
                    transaction_id,
                    ..
                },
            )
            | EnterprisePostingAdaptation::Excluded(
                EnterprisePostingExclusion::CanonicalZeroVoided {
                    target_id,
                    transaction_id,
                    ..
                },
            ) => (target_id, transaction_id, true),
            EnterprisePostingAdaptation::Excluded(_) => continue,
        };
        if !targets.insert(target_id) {
            return Err(());
        }
        let entry = families.entry(transaction_id).or_default();
        if zero {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
    }
    families
        .into_values()
        .all(|(zeros, nonzeros)| zeros == 0 || nonzeros == 0)
        .then_some(())
        .ok_or(())
}

fn add_table_coverage(
    diagnostics: &mut Enterprise24AccountingCoverageDiagnostics,
    policy_table_id: u32,
    coverage: &Enterprise24PartialTableCoverage,
) {
    if policy_table_id != coverage.table_id {
        diagnostics.blockers.push(
            Enterprise24AccountingPipelineBlocker::TablePolicyCoverageMismatch {
                policy_table_id,
                coverage_table_id: coverage.table_id,
            },
        );
        return;
    }
    if diagnostics.tables.contains_key(&coverage.table_id) {
        diagnostics.blockers.push(
            Enterprise24AccountingPipelineBlocker::DuplicateTableCoverage {
                table_id: coverage.table_id,
            },
        );
        return;
    }
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
                .get(
                    &u32::try_from(row.account_id)
                        .map_err(|_| NormalizationFailure::MissingAccountIdentity)?,
                )
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
                EnterprisePostingExclusion::CanonicalZeroAmount { account_id, .. } => {
                    // The adapter established all required monetary fields before
                    // this branch. Resolve the account here as well, so a zero
                    // row cannot bypass the same account-identity contract.
                    identity_map
                        .get(
                            &u32::try_from(account_id)
                                .map_err(|_| NormalizationFailure::MissingAccountIdentity)?,
                        )
                        .ok_or(NormalizationFailure::MissingAccountIdentity)?;
                    PostingExclusionReason::CanonicalZeroAmount
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
    /// General Journal header candidates did not agree on one physical row.
    #[error("General Journal header candidates did not reach byte consensus")]
    HeaderWitnessConsensusFailed,
    /// A consensus General Journal header did not satisfy its fixed framing.
    #[error("General Journal header witness did not satisfy its fixed framing")]
    HeaderWitnessParseFailed,
    /// Table-3040 header candidates did not yield one unique Bill master
    /// witness per physical header carrier.
    #[error("Bill header witnesses could not be resolved by candidate consensus")]
    BillHeaderWitnessResolutionFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Account, AccountType};
    use opensqlany::{ColumnDef, EnterpriseNumericToken, PartialRowValue, SaDate, Value};

    #[test]
    fn logical_carrier_coverage_requires_an_explicit_nonoverflowing_count() {
        let coverage = Enterprise24PartialTableCoverage {
            table_id: Enterprise24AccountingTable::BillLine.id(),
            resolved_records: u64::MAX,
            logical_non_row_carriers: 1,
            ..Enterprise24PartialTableCoverage::default()
        };
        assert!(!coverage.is_complete());
        assert!(
            !Enterprise24PartialTableCoverage {
                expected_logical_records: Some(0),
                ..coverage
            }
            .is_complete()
        );
        assert!(
            !Enterprise24PartialTableCoverage {
                table_id: Enterprise24AccountingTable::CheckLine.id(),
                resolved_records: 2,
                logical_non_row_carriers: 1,
                expected_logical_records: Some(3),
                ..Enterprise24PartialTableCoverage::default()
            }
            .is_complete()
        );
    }

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

    fn check_record<const N: usize>(
        target: u32,
        master: u32,
        account: u32,
        amount: [u8; N],
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

    fn deposit_schema() -> RowSchema {
        let mut schema = RowSchema::new(vec![
            ColumnDef::new(1, "target_id", ColumnType::Integer, 4, false),
            ColumnDef::new(2, "transaction_id", ColumnType::Integer, 4, false),
            ColumnDef::new(3, "account_id", ColumnType::Integer, 4, true),
            ColumnDef::new(4, "transaction_date", ColumnType::Date, 4, true),
            ColumnDef::new(5, "amount_amt", ColumnType::Numeric, 20, true),
            ColumnDef::new(6, "is_no_post_bool", ColumnType::Boolean, 1, false),
            ColumnDef::new(
                7,
                "is_memorized_transaction_bool",
                ColumnType::Boolean,
                1,
                false,
            ),
            ColumnDef::new(8, "is_source_bool", ColumnType::Boolean, 1, false),
            ColumnDef::new(9, "is_split_bool", ColumnType::Boolean, 1, false),
        ]);
        schema.numeric_layout = NumericLayout::EnterpriseMaterializedRaw;
        schema
    }

    #[allow(clippy::too_many_arguments)]
    fn deposit_record(
        record_id: u16,
        target: i64,
        transaction: i64,
        kind: u8,
        len: usize,
        account: Option<i64>,
        amount: Option<(u8, u8)>,
        source: bool,
        split: bool,
    ) -> Enterprise24PartialRecord {
        let mut bytes = vec![0_u8; len];
        bytes[..2].copy_from_slice(&(len as u16).to_le_bytes());
        bytes[3] = kind;
        bytes[8..12].copy_from_slice(&(target as u32).to_le_bytes());
        bytes[12..16].copy_from_slice(&(transaction as u32).to_le_bytes());
        let values = vec![
            Value::Integer(target),
            Value::Integer(transaction),
            account.map_or(Value::Null, Value::Integer),
            Value::Date(SaDate {
                raw_minutes: 194_516_640,
            }),
            amount.map_or(Value::Null, |(marker, digit)| {
                Value::EnterpriseNumeric(EnterpriseNumericToken {
                    marker,
                    digits: vec![digit],
                })
            }),
            Value::Boolean(false),
            Value::Boolean(false),
            Value::Boolean(source),
            Value::Boolean(split),
        ];
        Enterprise24PartialRecord {
            raw_page_number: 1,
            record_id,
            partial: PartialDecodedRow {
                declared_size: len,
                flags: 0,
                through_ordinal: 5,
                prefix_values: values
                    .iter()
                    .take(5)
                    .cloned()
                    .enumerate()
                    .map(|(column_index, value)| PartialRowValue {
                        column_index,
                        column_id: (column_index + 1) as u32,
                        value,
                    })
                    .collect(),
                boolean_values: values
                    .iter()
                    .skip(5)
                    .cloned()
                    .enumerate()
                    .map(|(offset, value)| PartialRowValue {
                        column_index: offset + 5,
                        column_id: (offset + 6) as u32,
                        value,
                    })
                    .collect(),
                opaque_middle_len: 0,
            },
            bytes,
        }
    }

    fn deposit_header_70(
        record_id: u16,
        target: i64,
        transaction: i64,
    ) -> Enterprise24PartialRecord {
        deposit_record(
            record_id,
            target,
            transaction,
            0x70,
            108,
            None,
            None,
            false,
            true,
        )
    }

    fn deposit_header_71(
        record_id: u16,
        target: i64,
        transaction: i64,
    ) -> Enterprise24PartialRecord {
        deposit_record(
            record_id,
            target,
            transaction,
            0x71,
            112,
            None,
            None,
            false,
            false,
        )
    }

    fn valid_70_group(transaction: i64) -> Vec<Enterprise24PartialRecord> {
        vec![
            deposit_header_70(1, 101, transaction),
            deposit_record(
                2,
                102,
                transaction,
                0xe1,
                80,
                Some(10),
                Some((0xbf, 10)),
                true,
                true,
            ),
            deposit_record(
                3,
                103,
                transaction,
                0xf1,
                80,
                Some(11),
                Some((0x3f, 5)),
                false,
                true,
            ),
            deposit_record(
                4,
                104,
                transaction,
                0xf1,
                80,
                Some(12),
                Some((0x3f, 5)),
                false,
                true,
            ),
        ]
    }

    fn valid_71_group(transaction: i64) -> Vec<Enterprise24PartialRecord> {
        vec![
            deposit_header_71(5, 201, transaction),
            deposit_record(6, 202, transaction, 0xe1, 80, Some(13), None, true, false),
        ]
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
    fn deposit_nonposting_headers_require_the_two_complete_proven_topologies() {
        let schema = deposit_schema();
        let mut records = valid_70_group(1000);
        records.extend(valid_71_group(2000));
        let headers = deposit_nonposting_header_record_ids(&records, &schema).unwrap();
        assert_eq!(headers, BTreeSet::from([(1, 1), (1, 5)]));
        assert_eq!(
            validate_deposit_master_balances(&records, &schema, &headers),
            Ok(())
        );
        assert!(
            validate_partial_zero_families(
                Enterprise24AccountingTable::DepositLine,
                &records,
                &schema,
                &headers,
            )
            .is_ok()
        );
        assert!(
            validate_partial_zero_families(
                Enterprise24AccountingTable::DepositLine,
                &records,
                &schema,
                &BTreeSet::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn deposit_nonposting_header_classifier_rejects_every_missing_or_changed_evidence_gate() {
        let schema = deposit_schema();

        let mut missing_counterpart = valid_70_group(1000);
        missing_counterpart.pop();
        assert!(deposit_nonposting_header_record_ids(&missing_counterpart, &schema).is_err());

        let mut unbalanced = valid_70_group(1000);
        unbalanced[3] = deposit_record(
            4,
            104,
            1000,
            0xf1,
            80,
            Some(12),
            Some((0x3f, 4)),
            false,
            true,
        );
        assert!(deposit_nonposting_header_record_ids(&unbalanced, &schema).is_err());

        let mut wrong_split = valid_70_group(1000);
        wrong_split[0] = deposit_record(1, 101, 1000, 0x70, 108, None, None, false, false);
        assert!(deposit_nonposting_header_record_ids(&wrong_split, &schema).is_err());

        let mut duplicate_target = valid_70_group(1000);
        duplicate_target[1] = deposit_record(
            2,
            101,
            1000,
            0xe1,
            80,
            Some(10),
            Some((0xbf, 10)),
            true,
            true,
        );
        assert!(deposit_nonposting_header_record_ids(&duplicate_target, &schema).is_err());

        let mut cross_transaction_duplicate = valid_70_group(1000);
        cross_transaction_duplicate.extend(valid_71_group(2000));
        cross_transaction_duplicate[4] = deposit_header_71(5, 101, 2000);
        assert!(
            deposit_nonposting_header_record_ids(&cross_transaction_duplicate, &schema).is_err()
        );

        let mut nonnull_header_account = valid_71_group(2000);
        nonnull_header_account[0] =
            deposit_record(5, 201, 2000, 0x71, 112, Some(13), None, false, false);
        assert!(deposit_nonposting_header_record_ids(&nonnull_header_account, &schema).is_err());

        let mut header_71_with_posting = valid_71_group(2000);
        header_71_with_posting[1] = deposit_record(
            6,
            202,
            2000,
            0xe1,
            80,
            Some(13),
            Some((0xbf, 1)),
            true,
            false,
        );
        assert!(deposit_nonposting_header_record_ids(&header_71_with_posting, &schema).is_err());

        let mut wrong_envelope = valid_70_group(1000);
        wrong_envelope[0].bytes[0] = 0;
        assert!(
            deposit_nonposting_header_record_ids(&wrong_envelope, &schema)
                .unwrap()
                .is_empty()
        );

        let mut bad_provenance = valid_70_group(1000);
        bad_provenance[0].partial.prefix_values[0].column_id = 999;
        assert!(deposit_nonposting_header_record_ids(&bad_provenance, &schema).is_err());
    }

    #[test]
    fn deposit_master_balance_gate_rejects_cross_master_cancellation() {
        let schema = deposit_schema();
        let records = vec![
            deposit_record(
                10,
                301,
                3000,
                0xe1,
                80,
                Some(10),
                Some((0xbf, 1)),
                true,
                true,
            ),
            deposit_record(
                11,
                401,
                4000,
                0xe1,
                80,
                Some(11),
                Some((0x3f, 1)),
                true,
                true,
            ),
        ];
        assert_eq!(
            validate_deposit_master_balances(&records, &schema, &BTreeSet::new()),
            Err(DepositTableValidationError::Unbalanced)
        );
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
    fn coverage_rejects_duplicate_and_policy_mismatched_table_claims() {
        let mut diagnostics = Enterprise24AccountingCoverageDiagnostics::default();
        let coverage = Enterprise24PartialTableCoverage {
            table_id: Enterprise24AccountingTable::CheckLine.id(),
            ..Enterprise24PartialTableCoverage::default()
        };
        add_table_coverage(
            &mut diagnostics,
            Enterprise24AccountingTable::CheckLine.id(),
            &coverage,
        );
        add_table_coverage(
            &mut diagnostics,
            Enterprise24AccountingTable::CheckLine.id(),
            &coverage,
        );
        add_table_coverage(
            &mut diagnostics,
            Enterprise24AccountingTable::BillLine.id(),
            &coverage,
        );
        assert!(diagnostics.blockers.contains(
            &Enterprise24AccountingPipelineBlocker::DuplicateTableCoverage {
                table_id: Enterprise24AccountingTable::CheckLine.id(),
            }
        ));
        assert!(diagnostics.blockers.contains(
            &Enterprise24AccountingPipelineBlocker::TablePolicyCoverageMismatch {
                policy_table_id: Enterprise24AccountingTable::BillLine.id(),
                coverage_table_id: Enterprise24AccountingTable::CheckLine.id(),
            }
        ));
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
    fn materialized_check_companion_requires_exact_family_and_resolved_accounts() {
        let master = 100;
        let records = vec![
            check_companion_record(
                103,
                master,
                crate::MATERIALIZED_CHECK_VOID_COMPANION_LONG_LEN,
            ),
            check_record(101, master, 7, [0, 0x81]),
            check_record(102, master, 8, [0, 0x81]),
        ];
        let rows = Enterprise24PartialTableRows {
            policy: enterprise24_r21_partial_table_policy(Enterprise24AccountingTable::CheckLine)
                .unwrap(),
            records: records.clone(),
            coverage: Enterprise24PartialTableCoverage::default(),
        };
        let accounts = BTreeMap::from([
            (7, AccountId::new("companion-zero-account-7").unwrap()),
            (8, AccountId::new("companion-zero-account-8").unwrap()),
        ]);
        let selected =
            try_materialized_check_dispositions(&rows, &deposit_schema(), &accounts).unwrap();
        assert_eq!(selected.len(), 3);
        assert!(
            selected
                .iter()
                .all(|item| matches!(item, PostingDisposition::Excluded(_)))
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
        assert!(
            try_materialized_check_dispositions(&duplicate_rows, &deposit_schema(), &accounts)
                .is_err()
        );

        let collision_rows = Enterprise24PartialTableRows {
            policy: rows.policy,
            records: vec![
                check_companion_record(
                    101,
                    master,
                    crate::MATERIALIZED_CHECK_VOID_COMPANION_LONG_LEN,
                ),
                check_record(101, master, 7, [0, 0x81]),
                check_record(102, master, 8, [0, 0x81]),
            ],
            coverage: Enterprise24PartialTableCoverage::default(),
        };
        assert!(
            try_materialized_check_dispositions(&collision_rows, &deposit_schema(), &accounts)
                .is_err()
        );
    }

    #[test]
    fn materialized_neutral_zero_only_check_family_is_not_a_void_claim() {
        let rows = Enterprise24PartialTableRows {
            policy: enterprise24_r21_partial_table_policy(Enterprise24AccountingTable::CheckLine)
                .unwrap(),
            records: vec![
                check_record(101, 100, 7, [0, 0x81]),
                check_record(102, 101, 8, [0, 0x81]),
            ],
            coverage: Enterprise24PartialTableCoverage::default(),
        };
        let accounts = BTreeMap::from([
            (7, AccountId::new("neutral-zero-account-7").unwrap()),
            (8, AccountId::new("neutral-zero-account-8").unwrap()),
        ]);
        let dispositions =
            try_materialized_check_dispositions(&rows, &deposit_schema(), &accounts).unwrap();
        assert_eq!(dispositions.len(), 2);
        assert!(
            dispositions
                .iter()
                .all(|item| matches!(item, PostingDisposition::Excluded(_)))
        );
    }

    #[test]
    fn materialized_unbalanced_check_master_with_zero_row_stays_blocked() {
        let rows = Enterprise24PartialTableRows {
            policy: enterprise24_r21_partial_table_policy(Enterprise24AccountingTable::CheckLine)
                .unwrap(),
            records: vec![
                check_record(101, 100, 7, [0, 0x81]),
                check_record(102, 100, 8, [2, 0xbf, 1, 23]),
            ],
            coverage: Enterprise24PartialTableCoverage::default(),
        };
        assert!(
            try_materialized_check_dispositions(&rows, &deposit_schema(), &BTreeMap::new())
                .is_err()
        );
    }

    #[test]
    fn ordinary_balanced_check_master_can_include_a_neutral_zero_row() {
        let mut rows = Enterprise24PartialTableRows {
            policy: enterprise24_r21_partial_table_policy(Enterprise24AccountingTable::CheckLine)
                .unwrap(),
            records: vec![
                check_record(101, 100, 7, [0, 0x81]),
                check_record(102, 100, 7, [2, 0xbf, 1, 23]),
                check_record(103, 100, 8, [2, 0x3f, 1, 23]),
            ],
            coverage: Enterprise24PartialTableCoverage::default(),
        };
        let accounts = BTreeMap::from([
            (7, AccountId::new("mixed-check-account-7").unwrap()),
            (8, AccountId::new("mixed-check-account-8").unwrap()),
        ]);
        let dispositions =
            try_materialized_check_dispositions(&rows, &deposit_schema(), &accounts).unwrap();
        assert_eq!(dispositions.len(), 3);
        assert_eq!(
            dispositions
                .iter()
                .filter(|row| matches!(row, PostingDisposition::Excluded(_)))
                .count(),
            1
        );
        // The same balanced monetary legs cannot validate a void companion.
        rows.records.push(check_companion_record(
            104,
            100,
            crate::MATERIALIZED_CHECK_VOID_COMPANION_LONG_LEN,
        ));
        assert!(try_materialized_check_dispositions(&rows, &deposit_schema(), &accounts).is_err());
    }

    fn schema_check_record(
        target: u32,
        master: u32,
        account: i64,
        zero: bool,
    ) -> Enterprise24PartialRecord {
        // The shared synthetic schema contains the named monetary prefix and
        // Boolean sidecar consumed by the Check adapter. Raw carrier parsing
        // is tested separately; these fixtures exercise the validated prefix.
        let mut record = deposit_record(
            target as u16,
            i64::from(target),
            i64::from(master),
            crate::MATERIALIZED_CHECK_POSTING_KIND,
            85,
            Some(account),
            Some((0xbf, 1)),
            false,
            false,
        );
        if zero {
            record.partial.prefix_values[4].value =
                Value::EnterpriseNumeric(EnterpriseNumericToken {
                    marker: 0x81,
                    digits: Vec::new(),
                });
        }
        record
    }

    fn compact_check_schema() -> RowSchema {
        let mut schema = RowSchema::new(vec![
            ColumnDef::new(1, "target_id", ColumnType::Integer, 4, false),
            ColumnDef::new(2, "transaction_id", ColumnType::Integer, 4, false),
            ColumnDef::new(3, "account_id", ColumnType::Integer, 4, true),
            ColumnDef::new(4, "transaction_date", ColumnType::Date, 4, true),
            ColumnDef::new(5, "transaction_view_type", ColumnType::SmallInt, 2, true),
            ColumnDef::new(11, "next_target_id", ColumnType::Integer, 4, true),
            ColumnDef::new(14, "sibling_account_id", ColumnType::Integer, 4, true),
            ColumnDef::new(25, "amount_amt", ColumnType::Numeric, 20, true),
            ColumnDef::new(26, "is_source_bool", ColumnType::Boolean, 1, false),
            ColumnDef::new(27, "is_no_post_bool", ColumnType::Boolean, 1, false),
            ColumnDef::new(
                28,
                "is_memorized_transaction_bool",
                ColumnType::Boolean,
                1,
                false,
            ),
            ColumnDef::new(33, "is_split_bool", ColumnType::Boolean, 1, false),
        ]);
        schema.numeric_layout = NumericLayout::EnterpriseMaterializedRaw;
        schema
    }

    fn compact_check_record(
        target: u32,
        master: u32,
        next: u32,
        sibling: u32,
    ) -> Enterprise24PartialRecord {
        let mut bytes = vec![0_u8; 151];
        bytes[..2].copy_from_slice(&151_u16.to_le_bytes());
        bytes[3] = crate::MATERIALIZED_CHECK_VOID_COMPANION_KIND;
        bytes[0x0c..0x10].copy_from_slice(&target.to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&master.to_le_bytes());
        let prefix = vec![
            (1, Value::Integer(i64::from(target))),
            (2, Value::Integer(i64::from(master))),
            (3, Value::Null),
            (
                4,
                Value::Date(SaDate {
                    raw_minutes: 194_516_640,
                }),
            ),
            (5, Value::Integer(3)),
            (11, Value::Integer(i64::from(next))),
            (14, Value::Integer(i64::from(sibling))),
            (25, Value::Null),
        ]
        .into_iter()
        .enumerate()
        .map(|(column_index, (column_id, value))| PartialRowValue {
            column_index,
            column_id,
            value,
        })
        .collect();
        let boolean_values = [(26, false), (27, false), (28, false), (33, true)]
            .into_iter()
            .enumerate()
            .map(|(offset, (column_id, value))| PartialRowValue {
                column_index: offset + 8,
                column_id,
                value: Value::Boolean(value),
            })
            .collect();
        Enterprise24PartialRecord {
            raw_page_number: 1,
            record_id: target as u16,
            bytes,
            partial: PartialDecodedRow {
                declared_size: 151,
                flags: 0,
                through_ordinal: 33,
                prefix_values: prefix,
                boolean_values,
                opaque_middle_len: 0,
            },
        }
    }

    fn compact_schema_posting(
        target: u32,
        master: u32,
        account: u32,
        marker: u8,
    ) -> Enterprise24PartialRecord {
        let mut record = compact_check_record(target, master, target + 100, account);
        record.bytes.resize(85, 0);
        record.bytes[..2].copy_from_slice(&85_u16.to_le_bytes());
        record.bytes[3] = crate::MATERIALIZED_CHECK_POSTING_KIND;
        record.partial.prefix_values = vec![
            (1, Value::Integer(i64::from(target))),
            (2, Value::Integer(i64::from(master))),
            (3, Value::Integer(i64::from(account))),
            (
                4,
                Value::Date(SaDate {
                    raw_minutes: 194_516_640,
                }),
            ),
            (5, Value::Integer(3)),
            (11, Value::Null),
            (14, Value::Null),
            (
                25,
                Value::EnterpriseNumeric(EnterpriseNumericToken {
                    marker,
                    digits: vec![1],
                }),
            ),
        ]
        .into_iter()
        .enumerate()
        .map(|(column_index, (column_id, value))| PartialRowValue {
            column_index,
            column_id,
            value,
        })
        .collect();
        record.partial.boolean_values = [(26, false), (27, false), (28, false), (33, true)]
            .into_iter()
            .enumerate()
            .map(|(offset, (column_id, value))| PartialRowValue {
                column_index: offset + 8,
                column_id,
                value: Value::Boolean(value),
            })
            .collect();
        record
    }

    #[test]
    fn compact_check_source_link_requires_exact_schema_and_retained_balanced_target() {
        let schema = compact_check_schema();
        let accounts = BTreeMap::from([
            (7, AccountId::new("compact-source-account").unwrap()),
            (8, AccountId::new("compact-next-account").unwrap()),
            (9, AccountId::new("compact-unrelated-account").unwrap()),
        ]);
        let rows = |records| Enterprise24PartialTableRows {
            policy: enterprise24_r21_partial_table_policy(Enterprise24AccountingTable::CheckLine)
                .unwrap(),
            records,
            coverage: Enterprise24PartialTableCoverage::default(),
        };
        let source = compact_check_record(1, 10, 2, 7);
        let valid = rows(vec![
            source.clone(),
            compact_schema_posting(2, 10, 8, 0xbf),
            compact_schema_posting(3, 10, 7, 0x3f),
        ]);
        assert!(try_partial_check_dispositions(&valid, &schema, &accounts).is_ok());

        let mut wrong_kind = source.clone();
        wrong_kind.bytes[3] = 0x63;
        let mut missing_next = source.clone();
        missing_next.partial.prefix_values[5].value = Value::Null;
        let mut source_flag = source;
        source_flag.partial.boolean_values[0].value = Value::Boolean(true);
        for invalid in [wrong_kind, missing_next, source_flag] {
            assert!(
                try_partial_check_dispositions(
                    &rows(vec![
                        invalid,
                        compact_schema_posting(2, 10, 8, 0xbf),
                        compact_schema_posting(3, 10, 7, 0x3f)
                    ]),
                    &schema,
                    &accounts
                )
                .is_err()
            );
        }
        let mut nonnull_account = compact_check_record(1, 10, 2, 7);
        nonnull_account.partial.prefix_values[2].value = Value::Integer(7);
        let mut nonnull_amount = compact_check_record(1, 10, 2, 7);
        nonnull_amount.partial.prefix_values[7].value =
            Value::EnterpriseNumeric(EnterpriseNumericToken {
                marker: 0xbf,
                digits: vec![1],
            });
        for invalid in [nonnull_account, nonnull_amount] {
            assert!(
                try_partial_check_dispositions(
                    &rows(vec![
                        invalid,
                        compact_schema_posting(2, 10, 8, 0xbf),
                        compact_schema_posting(3, 10, 7, 0x3f),
                    ]),
                    &schema,
                    &accounts
                )
                .is_err()
            );
        }
        assert!(
            try_partial_check_dispositions(
                &rows(vec![
                    compact_check_record(1, 10, 2, 99),
                    compact_schema_posting(2, 10, 8, 0xbf),
                    compact_schema_posting(3, 10, 7, 0x3f)
                ]),
                &schema,
                &accounts
            )
            .is_err()
        );
        // The counterpart cannot be the retained next row's account.
        assert!(
            try_partial_check_dispositions(
                &rows(vec![
                    compact_check_record(1, 10, 2, 8),
                    compact_schema_posting(2, 10, 8, 0xbf),
                    compact_schema_posting(3, 10, 7, 0x3f),
                ]),
                &schema,
                &accounts
            )
            .is_err()
        );
        // Distinct compact sources cannot share a retained next target.
        assert!(
            try_partial_check_dispositions(
                &rows(vec![
                    compact_check_record(1, 10, 2, 7),
                    compact_check_record(4, 10, 2, 7),
                    compact_schema_posting(2, 10, 8, 0xbf),
                    compact_schema_posting(3, 10, 7, 0x3f),
                ]),
                &schema,
                &accounts
            )
            .is_err()
        );
        assert!(
            try_partial_check_dispositions(
                &rows(vec![
                    compact_check_record(1, 10, 2, 7),
                    compact_schema_posting(2, 10, 8, 0xbf),
                    compact_schema_posting(2, 10, 7, 0x3f),
                ]),
                &schema,
                &accounts
            )
            .is_err()
        );
        // A chart-resolved sibling still needs a retained row in this exact
        // master/date family.
        assert!(
            try_partial_check_dispositions(
                &rows(vec![
                    compact_check_record(1, 10, 2, 9),
                    compact_schema_posting(2, 10, 8, 0xbf),
                    compact_schema_posting(3, 10, 7, 0x3f)
                ]),
                &schema,
                &accounts
            )
            .is_err()
        );
        let mut wrong_date = compact_check_record(1, 10, 2, 7);
        wrong_date.partial.prefix_values[3].value = Value::Date(SaDate {
            raw_minutes: 194_518_080,
        });
        assert!(
            try_partial_check_dispositions(
                &rows(vec![
                    wrong_date,
                    compact_schema_posting(2, 10, 8, 0xbf),
                    compact_schema_posting(3, 10, 7, 0x3f)
                ]),
                &schema,
                &accounts
            )
            .is_err()
        );
        assert!(
            try_partial_check_dispositions(
                &rows(vec![
                    compact_check_record(1, 10, 2, 7),
                    compact_schema_posting(2, 10, 8, 0xbf),
                    compact_schema_posting(3, 11, 7, 0x3f)
                ]),
                &schema,
                &accounts
            )
            .is_err()
        );
    }

    #[test]
    fn schema_check_companion_requires_distinct_complete_zero_family() {
        let schema = deposit_schema();
        let accounts = BTreeMap::from([
            (7, AccountId::new("sample-equity").unwrap()),
            (8, AccountId::new("sample-cash").unwrap()),
        ]);
        let companion =
            check_companion_record(103, 100, crate::MATERIALIZED_CHECK_VOID_COMPANION_LEN);
        let first = schema_check_record(101, 100, 7, true);
        let second = schema_check_record(102, 100, 8, true);
        let rows = |records| Enterprise24PartialTableRows {
            policy: enterprise24_r21_partial_table_policy(Enterprise24AccountingTable::CheckLine)
                .unwrap(),
            records,
            coverage: Enterprise24PartialTableCoverage::default(),
        };
        let valid = rows(vec![companion.clone(), first.clone(), second.clone()]);
        let result = try_partial_check_dispositions(&valid, &schema, &accounts).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(
            result
                .iter()
                .filter(|item| matches!(item,
                    PostingDisposition::Excluded(excluded)
                        if excluded.reason() == PostingExclusionReason::CanonicalZeroAmount
                ))
                .count(),
            2
        );

        let mut duplicate_target = first.clone();
        duplicate_target.record_id = 104;
        let invalid_families = [
            vec![companion.clone(), first.clone()],
            vec![
                companion.clone(),
                first.clone(),
                second.clone(),
                schema_check_record(104, 100, 7, true),
            ],
            vec![companion.clone(), first.clone(), duplicate_target],
            vec![
                companion.clone(),
                first.clone(),
                second.clone(),
                check_companion_record(104, 100, crate::MATERIALIZED_CHECK_VOID_COMPANION_LEN),
            ],
            vec![
                companion.clone(),
                first.clone(),
                schema_check_record(103, 100, 8, true),
            ],
            vec![
                companion.clone(),
                first.clone(),
                schema_check_record(102, 100, 8, false),
            ],
            vec![companion, first, schema_check_record(102, 100, 99, true)],
        ];
        for records in invalid_families {
            assert!(try_partial_check_dispositions(&rows(records), &schema, &accounts).is_err());
        }
    }

    fn bridged_check_zero(target: u32, master: u32, account: u32) -> Enterprise24PartialRecord {
        let mut record = check_record(target, master, account, [0, 0x81]);
        record.bytes.resize(188, 0);
        record.bytes[..2].copy_from_slice(&188_u16.to_le_bytes());
        record.bytes[24..28].copy_from_slice(&194_516_640_u32.to_le_bytes());
        record.partial = schema_check_record(target, master, i64::from(account), true).partial;
        record.partial.declared_size = record.bytes.len();
        record
    }

    #[test]
    fn check_zero_prefix_bridge_reaches_all_family_and_normalization_gates() {
        let schema = deposit_schema();
        let accounts = BTreeMap::from([
            (7, AccountId::new("sample-account-a").unwrap()),
            (8, AccountId::new("sample-account-b").unwrap()),
        ]);
        let first = bridged_check_zero(101, 100, 7);
        assert!(matches!(
            MaterializedCheckPostingRow::parse(&first.bytes),
            Err(crate::MaterializedCheckPostingRowError::UnattestedAmountEnvelope { .. })
        ));
        let rows = Enterprise24PartialTableRows {
            policy: enterprise24_r21_partial_table_policy(Enterprise24AccountingTable::CheckLine)
                .unwrap(),
            records: vec![
                check_companion_record(103, 100, crate::MATERIALIZED_CHECK_VOID_COMPANION_LONG_LEN),
                first.clone(),
                bridged_check_zero(102, 100, 8),
            ],
            coverage: Enterprise24PartialTableCoverage::default(),
        };
        let selected = try_materialized_check_dispositions(&rows, &schema, &accounts).unwrap();
        assert_eq!(selected.len(), 3);
        assert_eq!(
            selected
                .iter()
                .filter(|item| matches!(item,
                    PostingDisposition::Excluded(excluded)
                        if excluded.reason() == PostingExclusionReason::CanonicalZeroAmount
                ))
                .count(),
            2
        );

        let mut unknown_account = rows.clone();
        unknown_account.records[1] = bridged_check_zero(101, 100, 99);
        assert!(try_materialized_check_dispositions(&unknown_account, &schema, &accounts).is_err());

        let mut mismatched_target = first.clone();
        mismatched_target.bytes[12..16].copy_from_slice(&199_u32.to_le_bytes());
        let mut mismatched_date = first.clone();
        mismatched_date.bytes[24..28].copy_from_slice(&194_518_080_u32.to_le_bytes());
        let mut invalid_flags = first.clone();
        invalid_flags.bytes[2] = 0x40;
        let mut invalid_source = first.clone();
        invalid_source.bytes[30..38].fill(0);
        let mut malformed_length = first.clone();
        malformed_length.bytes[..2].copy_from_slice(&189_u16.to_le_bytes());
        let mut schema_nonzero = first.clone();
        schema_nonzero.partial.prefix_values[4].value =
            Value::EnterpriseNumeric(EnterpriseNumericToken {
                marker: 0xbf,
                digits: vec![1],
            });
        let mut schema_missing_account = first.clone();
        schema_missing_account.partial.prefix_values[2].value = Value::Null;
        let mut schema_bad_date = first;
        schema_bad_date.partial.prefix_values[3].value = Value::Date(SaDate { raw_minutes: 1 });
        for invalid in [
            mismatched_target,
            mismatched_date,
            invalid_flags,
            invalid_source,
            malformed_length,
            schema_nonzero,
            schema_missing_account,
            schema_bad_date,
        ] {
            assert!(adapt_check_observation(&invalid, &schema).is_err());
        }
    }

    #[test]
    fn neutral_bill_payment_rows_keep_logical_identity_and_mixed_master_guards() {
        let schema = deposit_schema();
        let first = schema_check_record(101, 100, 7, true);
        let second = schema_check_record(102, 100, 8, true);
        let table = Enterprise24AccountingTable::BillPaymentCheckLine;
        assert!(
            validate_partial_zero_families(
                table,
                &[first.clone(), second],
                &schema,
                &BTreeSet::new()
            )
            .is_ok()
        );
        let mut duplicate_target = first.clone();
        duplicate_target.record_id = 104;
        assert!(
            validate_partial_zero_families(
                table,
                &[first.clone(), duplicate_target],
                &schema,
                &BTreeSet::new()
            )
            .is_err()
        );
        assert!(
            validate_partial_zero_families(
                table,
                &[first, schema_check_record(102, 100, 8, false)],
                &schema,
                &BTreeSet::new()
            )
            .is_err()
        );
    }

    #[test]
    fn neutral_zero_account_join_rejects_missing_and_truncated_aliases() {
        let accounts = BTreeMap::from([(7, AccountId::new("sample-account").unwrap())]);
        let record = schema_check_record(101, 100, 7, true);
        for account_id in [99_u64, u64::from(u32::MAX) + 8] {
            let adaptation = EnterprisePostingAdaptation::Excluded(
                EnterprisePostingExclusion::CanonicalZeroAmount {
                    target_id: 101,
                    transaction_id: 100,
                    account_id,
                    transaction_date: 1,
                    transaction_type: crate::EnterprisePostingTransactionType::Check,
                },
            );
            assert!(matches!(
                normalized_disposition(
                    Enterprise24AccountingTable::CheckLine,
                    &record,
                    adaptation,
                    &accounts,
                    "sample-decoder"
                ),
                Err(NormalizationFailure::MissingAccountIdentity)
            ));
        }
    }

    fn bill_family_record(target: u32, account: u32, amount: &[u8]) -> Enterprise24PartialRecord {
        let mut bytes = vec![0_u8; 64];
        bytes[..2].copy_from_slice(&64_u16.to_le_bytes());
        bytes[2] = 0x40;
        bytes[3] = 0x02;
        bytes[4] = 0xe4;
        bytes[12..16].copy_from_slice(&target.to_le_bytes());
        bytes[16..20].copy_from_slice(&100_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&account.to_le_bytes());
        bytes[24..28].copy_from_slice(&194_516_640_u32.to_le_bytes());
        bytes[28..30].copy_from_slice(&9_u16.to_le_bytes());
        bytes[56 - amount.len()..56].copy_from_slice(amount);
        bytes[59..].copy_from_slice(&[0, 0, 0, 0, 0x81]);
        Enterprise24PartialRecord {
            raw_page_number: 1,
            record_id: target as u16,
            bytes,
            partial: partial(1),
        }
    }

    #[test]
    fn bill_neutral_split_requires_complete_distinct_balanced_family() {
        let zero = bill_family_record(101, 7, &[0, 0x81]);
        let debit = bill_family_record(102, 8, &[1, 0xbf, 1]);
        let credit = bill_family_record(103, 9, &[1, 0x3f, 1]);
        assert!(
            validate_materialized_bill_zero_families(&[
                zero.clone(),
                debit.clone(),
                credit.clone()
            ])
            .is_ok()
        );
        assert!(
            validate_materialized_bill_zero_families(&[
                zero.clone(),
                bill_family_record(104, 8, &[0, 0x81]),
                bill_family_record(105, 8, &[0, 0x81]),
                debit.clone(),
                credit.clone(),
            ])
            .is_ok()
        );
        assert!(
            validate_materialized_bill_zero_families(&[
                zero.clone(),
                bill_family_record(102, 7, &[1, 0xbf, 1]),
                credit.clone(),
            ])
            .is_ok()
        );

        let mut different_date = credit.clone();
        different_date.bytes[24..28].copy_from_slice(&194_518_080_u32.to_le_bytes());
        let mut different_view = credit.clone();
        different_view.bytes[28..30].copy_from_slice(&12_u16.to_le_bytes());
        let mut malformed_date = zero.clone();
        malformed_date.bytes[24..28].copy_from_slice(&1_u32.to_le_bytes());
        for records in [
            vec![zero.clone(), debit.clone()],
            vec![zero.clone(), debit.clone(), different_date],
            vec![zero.clone(), debit.clone(), different_view],
            vec![malformed_date, debit.clone(), credit.clone()],
            vec![zero.clone(), zero.clone(), debit.clone(), credit.clone()],
            vec![zero, debit, bill_family_record(102, 9, &[1, 0x3f, 1])],
        ] {
            assert!(validate_materialized_bill_zero_families(&records).is_err());
        }
    }

    fn bill_carrier_schema() -> RowSchema {
        let names = [
            "target_id",
            "transaction_id",
            "account_id",
            "transaction_date",
            "transaction_view_type",
            "next_target_id",
            "sibling_account_id",
            "amount_amt",
            "is_source_bool",
            "is_no_post_bool",
            "is_memorized_transaction_bool",
            "is_split_bool",
            "is_arap_bool",
        ];
        RowSchema::new(
            names
                .into_iter()
                .enumerate()
                .map(|(index, name)| {
                    ColumnDef::new((index + 1) as u32, name, ColumnType::Integer, 4, true)
                })
                .collect(),
        )
    }

    fn bill_carrier_partial(
        target: u32,
        master: u32,
        account: Option<u32>,
        next: Option<u32>,
        sibling: Option<u32>,
        amount: Value,
    ) -> PartialDecodedRow {
        let values = [
            Value::Integer(i64::from(target)),
            Value::Integer(i64::from(master)),
            account.map_or(Value::Null, |value| Value::Integer(i64::from(value))),
            Value::Integer(77),
            Value::Integer(9),
            next.map_or(Value::Null, |value| Value::Integer(i64::from(value))),
            sibling.map_or(Value::Null, |value| Value::Integer(i64::from(value))),
            amount,
        ];
        PartialDecodedRow {
            declared_size: 1,
            flags: 0,
            through_ordinal: 13,
            prefix_values: values
                .into_iter()
                .enumerate()
                .map(|(index, value)| PartialRowValue {
                    column_index: index,
                    column_id: (index + 1) as u32,
                    value,
                })
                .collect(),
            boolean_values: [false, false, false, true, true]
                .into_iter()
                .enumerate()
                .map(|(offset, value)| PartialRowValue {
                    column_index: offset + 8,
                    column_id: (offset + 9) as u32,
                    value: Value::Boolean(value),
                })
                .collect(),
            opaque_middle_len: 0,
        }
    }

    #[test]
    fn bill_kind64_carrier_requires_full_schema_and_complete_nonposting_relation() {
        let schema = bill_carrier_schema();
        let amounts: [&[u8]; 5] = [
            &[1, 0xbf, 1],
            &[1, 0xbf, 1],
            &[1, 0xbf, 1],
            &[1, 0x3f, 1],
            &[1, 0x3f, 2],
        ];
        let accounts = [7, 8, 7, 8, 7];
        let records = amounts
            .into_iter()
            .zip(accounts)
            .enumerate()
            .map(|(index, (amount, account))| {
                let target = 101 + index as u32;
                let mut record = bill_family_record(target, account, amount);
                record.partial =
                    bill_carrier_partial(target, 100, Some(account), None, None, Value::Integer(1));
                record
            })
            .collect::<Vec<_>>();
        let carrier = Enterprise24PartialRecordCandidate {
            bytes: vec![0; 16],
            partial: bill_carrier_partial(200, 100, None, Some(101), Some(8), Value::Null),
        };
        let mut carrier = carrier;
        carrier.bytes[..2].copy_from_slice(&16_u16.to_le_bytes());
        carrier.bytes[2..5].copy_from_slice(&[0x40, 0x02, 0x64]);
        let headers = BTreeSet::from([100]);
        assert!(is_attested_bill_nonposting_carrier(
            &carrier, &records, &schema, &headers
        ));
        let mut present_amount = carrier.clone();
        present_amount.partial.prefix_values[7].value = Value::Integer(1);
        assert!(!is_attested_bill_nonposting_carrier(
            &present_amount,
            &records,
            &schema,
            &headers
        ));
        let mut wrong_sibling = carrier.clone();
        wrong_sibling.partial.prefix_values[6].value = Value::Integer(99);
        assert!(!is_attested_bill_nonposting_carrier(
            &wrong_sibling,
            &records,
            &schema,
            &headers
        ));
        let mut incomplete = records.clone();
        incomplete.pop();
        assert!(!is_attested_bill_nonposting_carrier(
            &carrier,
            &incomplete,
            &schema,
            &headers
        ));
        let mut wrong_view = records.clone();
        wrong_view[4].partial.prefix_values[4].value = Value::Integer(12);
        assert!(!is_attested_bill_nonposting_carrier(
            &carrier,
            &wrong_view,
            &schema,
            &headers
        ));
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
    fn forwarding_locators_decode_references_instead_of_matching_pointer_bytes() {
        let mut locator = vec![9, 0, 0x44, 17, 0, 0, 0, 2, 0];
        assert_eq!(forwarding_locator(&locator), Some((17, 2)));
        locator[3..7].copy_from_slice(&401_u32.to_le_bytes());
        locator[7..9].copy_from_slice(&12_u16.to_le_bytes());
        assert_eq!(forwarding_locator(&locator), Some((401, 12)));
        assert_eq!(
            consensus_forwarding_locator(&[locator.clone(), locator.clone()]),
            Some((401, 12))
        );
        let mut divergent = locator.clone();
        divergent[7] += 1;
        assert_eq!(
            consensus_forwarding_locator(&[locator.clone(), divergent]),
            None
        );
        for (offset, value) in [(0, 8), (1, 1), (2, 0x40)] {
            let mut altered = locator.clone();
            altered[offset] = value;
            assert_eq!(forwarding_locator(&altered), None);
        }
        assert_eq!(forwarding_locator(&locator[..8]), None);
        locator.push(0);
        assert_eq!(forwarding_locator(&locator), None);
    }

    #[test]
    fn forwarding_aliases_require_unique_retained_monetary_destinations() {
        let mut debit = bill_family_record(101, 7, &[1, 0xbf, 1]);
        debit.raw_page_number = 17;
        debit.record_id = 2;
        let mut credit = bill_family_record(102, 8, &[1, 0x3f, 1]);
        credit.raw_page_number = 17;
        credit.record_id = 3;
        let rows = vec![debit, credit];
        let is_bill = |bytes: &[u8]| MaterializedBillPostingRow::parse(bytes).is_ok();
        assert!(validate_forwarding_aliases(
            &rows,
            &[((6, 0), (17, 2)), ((6, 1), (17, 3))],
            is_bill
        ));
        for aliases in [
            vec![((17, 2), (17, 2))],
            vec![((6, 0), (99, 2))],
            vec![((6, 0), (17, 8))],
            vec![((6, 0), (17, 2)), ((6, 1), (17, 2))],
            vec![((6, 0), (17, 2)), ((6, 0), (17, 3))],
            vec![((6, 0), (6, 1)), ((6, 1), (6, 0))],
        ] {
            assert!(!validate_forwarding_aliases(&rows, &aliases, is_bill));
        }
        let mut invalid_destination = rows.clone();
        invalid_destination[0].bytes = vec![9, 0, 0x44, 17, 0, 0, 0, 3, 0];
        assert!(!validate_forwarding_aliases(
            &invalid_destination,
            &[((6, 0), (17, 2))],
            is_bill
        ));
        let mut duplicate_location = rows;
        duplicate_location[1].record_id = 2;
        assert!(!validate_forwarding_aliases(
            &duplicate_location,
            &[((6, 0), (17, 2))],
            is_bill
        ));
    }

    #[test]
    fn certified_empty_page_drift_cannot_cover_missing_rows_or_other_tables() {
        let coverage = Enterprise24PartialTableCoverage {
            table_id: 3078,
            candidate_page_groups: 4,
            expected_table_pages: Some(3),
            expected_external_table_pages: Some(0),
            expected_logical_records: Some(11),
            resolved_records: 11,
            certified_empty_surplus_page_groups: 1,
            ..Enterprise24PartialTableCoverage::default()
        };
        assert!(coverage.complete());
        for altered in [
            Enterprise24PartialTableCoverage {
                resolved_records: 10,
                ..coverage.clone()
            },
            Enterprise24PartialTableCoverage {
                candidate_directory_disagreements: 1,
                ..coverage.clone()
            },
            Enterprise24PartialTableCoverage {
                unresolved_records: 1,
                ..coverage.clone()
            },
            Enterprise24PartialTableCoverage {
                decode_failures: 1,
                ..coverage.clone()
            },
            Enterprise24PartialTableCoverage {
                candidate_page_groups: 2,
                ..coverage.clone()
            },
            Enterprise24PartialTableCoverage {
                candidate_page_groups: 5,
                certified_empty_surplus_page_groups: 2,
                ..coverage.clone()
            },
            Enterprise24PartialTableCoverage {
                table_id: 3042,
                ..coverage
            },
        ] {
            assert!(!altered.complete());
        }
    }

    #[test]
    fn external_text_payload_must_fill_one_exact_uncontinued_segment() {
        let mut segment = vec![7, 0, 0];
        segment.extend_from_slice(b"memo");
        assert!(is_r21_bill_external_text_payload(&segment));
        let mut extra = segment.clone();
        extra.push(b'x');
        assert!(!is_r21_bill_external_text_payload(&extra));
        for (offset, value) in [(0, 6), (1, 1), (2, 1), (3, 0)] {
            let mut altered = segment.clone();
            altered[offset] = value;
            assert!(!is_r21_bill_external_text_payload(&altered));
        }
        assert!(!is_r21_bill_external_text_payload(&segment[..6]));
        assert!(!is_r21_bill_external_text_payload(&[3, 0, 0]));
        assert!(!is_r21_bill_external_text_payload(&[4, 0, 0, b' ']));
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

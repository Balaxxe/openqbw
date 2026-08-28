//! QuickBooks `.qbw` file parser.
//!
//! Provides QuickBooks-specific catalog, provenance, legacy transaction,
//! normalized-accounting, and report-validation primitives over the
//! [`opensqlany`] SA17 page-store layer.
//!
//! # Status
//!
//! Prototype quality. Enterprise 24 SYSTAB and SYSCOLUMN catalog rows are
//! recovered with exact known-plaintext AP witnesses and physical row bounds.
//! Complete Enterprise 24 account/posting extraction is still unfinished, so
//! the normalized Trial Balance APIs must only be used with a decoder that has
//! satisfied their explicit completeness contracts. See `RESEARCH.md` for the
//! evidence ledger and remaining gaps.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod accounting;
mod attribution_content;
mod attribution_schema;
mod bv_recovery;
mod cindex_drec;
mod date;
mod decoder_contract;
mod enterprise24_accounting_pipeline;
mod enterprise24_accounting_table;
mod enterprise24_schema_manifest;
mod enterprise24_transform_key;
mod enterprise_page_materializer;
mod enterprise_table_scan;
mod fkgraph;
mod index_root_map;
mod lineitem;
mod long_value_ref;
mod materialized_account;
mod materialized_account_type_mapping;
mod materialized_bill_header;
mod materialized_bill_payment_check_posting;
mod materialized_bill_posting;
mod materialized_check_posting;
mod materialized_check_void_companion;
mod materialized_deposit_posting;
mod materialized_general_journal_posting;
mod materialized_numeric;
mod materialized_page_trace;
mod materialized_posting_date;
mod materialized_row_schema_attestation;
mod materialized_table_id;
mod materialized_transaction_master;
mod nullability;
mod opaque;
mod opaque_page_tuples;
mod page_attribution;
mod partial_row;
mod physical_carrier_census;
mod quickbooks_balance;
mod quickbooks_date;
mod row_scan;
mod schema_account_adapter;
mod schema_adapter;
mod schema_posting_adapter;
mod syscolumn;
mod sysindex;
mod sysobject;
mod systable;
mod tagged_field;
mod transaction_header;

pub use accounting::{
    Account, AccountActivity, AccountId, AccountType, AccountingDate, AccountingError,
    CurrentState, DebitCredit, DebitCreditAmount, GeneralLedger, GeneralLedgerEntry, Ledger,
    LedgerCompleteness, NormalBalance, Posting, PostingId, PostingProvenance,
    QuickBooksAccrualTrialBalancePolicy, TransactionId, TrialBalance, TrialBalanceOptions,
    TrialBalanceRow,
};
pub use attribution_content::{AttributionAgreement, ContentAttribution, RowSignature, SIG_LEN};
pub use attribution_schema::{
    MIN_ROW_BODY_BYTES, SchemaAttribution, VARIABLE_COLUMN_UPPER_ALLOWANCE, ValidationStats,
    WidthBand,
};
pub use bv_recovery::{
    APAGE_MAGIC, AffineKnownPlaintextWitness, affine_known_plaintext_witnesses,
    deobfuscate_with_bv, oracle_bv_e_page, recover_bv_any, recover_bv_apage, recover_bv_brute,
    recover_bv_qb_data,
};
pub use cindex_drec::{
    DREC_MAX_LEN, DrecByteOrder, DrecClass, DrecDescriptor, DrecError, DrecField, DrecRecord,
    DrecSchema, DrecValue, encode_drec, parse_drec,
};
pub use date::{
    SA_DAY_MAX_PLAUSIBLE, SA_DAY_MIN_PLAUSIBLE, sa_day_to_unix_day, sa_day_to_unix_seconds,
    unix_day_to_sa_day,
};
pub use decoder_contract::{
    CompleteCoverage, DecodedAccounts, DecodedPostings, DecoderContractError, DecoderIdentity,
    LedgerAdapter, PostingDisposition, PostingExclusion, PostingExclusionReason, SourceSnapshotId,
};
pub use enterprise_page_materializer::{
    EnterpriseCandidateResolutionError, EnterpriseMaterializedTablePage,
    EnterprisePageMaterializationError, EnterprisePageTransformKey,
    discover_enterprise_page_transform_key, discover_enterprise_page_transform_key_candidates,
    discover_enterprise_page_transform_key_candidates_in_store,
    discover_enterprise_page_transform_key_in_store, materialize_enterprise_table_page,
    materialize_enterprise_table_page_candidates_with_key,
    materialize_enterprise_table_page_with_key, resolve_enterprise_table_page_candidates,
};
pub use enterprise_table_scan::{
    EnterpriseTableDirectoryCounts, EnterpriseTableIdConflict, EnterpriseTablePageCandidateGroup,
    EnterpriseTableScan, EnterpriseTableScanCensus, EnterpriseTableScanError,
    EnterpriseTableScanSkipReason, EnterpriseTableStoreScan, EnterpriseTableStoreScanCensus,
    resolve_enterprise_table_candidate_group, scan_enterprise_table_pages,
    scan_enterprise_table_store,
};
pub use enterprise24_accounting_pipeline::{
    ENTERPRISE24_R21_PARTIAL_TABLE_POLICIES, Enterprise24AccountingCoverageDiagnostics,
    Enterprise24AccountingPipelineBlocker, Enterprise24AccountingPipelineError,
    Enterprise24AccountingPipelineResult, Enterprise24PartialPolicyStatus,
    Enterprise24PartialRecord, Enterprise24PartialRecordCandidate,
    Enterprise24PartialTableCoverage, Enterprise24PartialTablePolicy, Enterprise24PartialTableRows,
    Enterprise24TableCoverageExpectation, build_enterprise24_accounting_pipeline,
    collect_enterprise24_bill_table_rows, collect_enterprise24_check_prefix_table_rows,
    collect_enterprise24_general_journal_table_rows, collect_enterprise24_partial_table_rows,
    enterprise24_r21_partial_table_policy, resolve_enterprise24_partial_record_candidates,
};
pub use enterprise24_accounting_table::{
    Enterprise24AccountingTable, UnsupportedEnterprise24AccountingTable,
};
pub use enterprise24_schema_manifest::{
    ENTERPRISE24_R21_SCHEMA_MANIFEST, Enterprise24R21SchemaManifestError,
    Enterprise24R21SchemaTableManifest, Enterprise24R21ValidatedCatalog,
    attest_enterprise24_r21_catalog, enterprise24_r21_schema_fingerprint,
    validate_enterprise24_r21_schema_manifest,
};
pub use enterprise24_transform_key::{
    Enterprise24R21TransformKeyAttestation, Enterprise24R21TransformKeyResolutionError,
    discover_enterprise24_r21_transform_key_in_store,
};
pub use fkgraph::{FkEdge, FkGraphStats, build as build_fk_graph, stats as fk_graph_stats};
pub use index_root_map::{
    AmbiguousOwnerObjectId, IndexRoot, IndexRootMap, InvalidIndexRoot, OrphanIndexRoot,
    TableIndexRoots,
};
pub use lineitem::{
    AmountType, DATE_EPOCH_DAYS_BEFORE_UNIX, LineItem, LineItemError, iter_lineitems,
    iter_lineitems_with_attribution,
};
pub use long_value_ref::{
    LONG_VALUE_REF_LEN, LONG_VALUE_REF_MARKER, LongValueRef, LongValueRefError,
    parse_long_value_ref,
};
pub use materialized_account::{
    MATERIALIZED_ACCOUNT_ROW_KIND, MaterializedAccountRow, MaterializedAccountRowError,
    MaterializedAccountSuffixState, MaterializedAccountType, format_ordinary_account_list_id,
};
pub use materialized_account_type_mapping::{
    MaterializedAccountTypeMappingError, QuickBooksAccountClassification,
    map_materialized_account_type_code,
};
pub use materialized_bill_header::{
    MATERIALIZED_BILL_HEADER_TABLE_ID, MaterializedBillHeaderKind, MaterializedBillHeaderRow,
    MaterializedBillHeaderRowError,
};
pub use materialized_bill_payment_check_posting::{
    MATERIALIZED_BILL_PAYMENT_CHECK_TABLE_ID, MaterializedBillPaymentCheckPostingRow,
    MaterializedBillPaymentCheckPostingRowError, MaterializedBillPaymentCheckPostingShape,
};
pub use materialized_bill_posting::{
    MATERIALIZED_BILL_POSTING_TABLE_ID, MaterializedBillPostingRow,
    MaterializedBillPostingRowError, MaterializedBillTransactionKind,
};
pub use materialized_check_posting::{
    MATERIALIZED_CHECK_POSTING_KIND, MaterializedCheckPostingRow, MaterializedCheckPostingRowError,
    MaterializedCheckPostingShape,
};
pub use materialized_check_void_companion::{
    CheckVoidCompanionClassification, CheckVoidCompanionMasterEvidence,
    MATERIALIZED_CHECK_VOID_COMPANION_EXTENDED_LEN, MATERIALIZED_CHECK_VOID_COMPANION_FLAGS,
    MATERIALIZED_CHECK_VOID_COMPANION_KIND, MATERIALIZED_CHECK_VOID_COMPANION_LEN,
    MATERIALIZED_CHECK_VOID_COMPANION_LONG_LEN, MATERIALIZED_CHECK_VOID_COMPANION_TABLE_ID,
    MATERIALIZED_CHECK_VOID_COMPANION_VARIABLE_219_LEN,
    MATERIALIZED_CHECK_VOID_COMPANION_VARIABLE_222_LEN,
    MATERIALIZED_CHECK_VOID_COMPANION_VARIABLE_223_LEN, MaterializedCheckVoidCompanionCarrier,
    MaterializedCheckVoidCompanionError, classify_materialized_check_void_companion,
};
pub use materialized_deposit_posting::{
    MATERIALIZED_DEPOSIT_COUNTERPART_F0_KIND, MATERIALIZED_DEPOSIT_COUNTERPART_F1_KIND,
    MATERIALIZED_DEPOSIT_POSTING_KIND, MATERIALIZED_DEPOSIT_TERMINAL_POSTING_KIND,
    MaterializedDepositCounterpartPostingRow, MaterializedDepositPostingRow,
    MaterializedDepositPostingRowError,
};
pub use materialized_general_journal_posting::{
    MATERIALIZED_GENERAL_JOURNAL_FLAGS, MATERIALIZED_GENERAL_JOURNAL_POSTING_TABLE_ID,
    MATERIALIZED_GENERAL_JOURNAL_ROW_KIND, MaterializedGeneralJournalAmountPosition,
    MaterializedGeneralJournalCanonicalZeroAmount, MaterializedGeneralJournalDisposition,
    MaterializedGeneralJournalPostingRow, MaterializedGeneralJournalPostingRowError,
    MaterializedGeneralJournalPostingTargetRow, MaterializedGeneralJournalPostingTargetShape,
    MaterializedGeneralJournalProductionRowError, MaterializedGeneralJournalSourceLink,
    MaterializedGeneralJournalSourceLinkRow, classify_materialized_general_journal_rows,
    validate_materialized_general_journal_master_balances,
};
pub use materialized_page_trace::{
    MaterializedPageTrace, MaterializedPageTraceError, MaterializedRecordCoordinate,
    MaterializedRowRecordObservation, MaterializedRowSegmentObservation, PageTraceCorrelation,
    PageTraceCorrelationReport, RAW_PAGE_BYTES, RawPageWitness, RowSegmentCarrierEvidence,
    Sha256Digest, correlate_materialized_page_traces, observe_materialized_row_record,
    observe_materialized_row_segment,
};
pub use materialized_posting_date::{
    MATERIALIZED_POSTING_MINUTES_PER_DAY, MaterializedPostingDate, MaterializedPostingDateError,
};
pub use materialized_row_schema_attestation::{
    AttestedAndResolvedMaterializedTableSchema, AttestedMaterializedRowSchema,
    MaterializedRowCoverageAttestation, MaterializedRowSchemaAttestationError,
    MaterializedTableCoverageAttestation, RejectedRowStorageLayout, RejectedTableRowStorageLayout,
    ResolvedMaterializedTablePage, ResolvedMaterializedTableRow,
    attest_and_resolve_materialized_table_schema, attest_materialized_row_schema,
};
pub use materialized_table_id::{
    MaterializedTableId, MaterializedTableIdError, materialized_table_id,
};
pub use materialized_transaction_master::{
    MATERIALIZED_MASTER_FLAGS, MATERIALIZED_MASTER_KIND, MaterializedTransactionMasterRow,
    MaterializedTransactionMasterRowError, parse_materialized_transaction_master_row,
};
pub use nullability::{NullabilityBucket, histogram as nullability_histogram};
#[allow(deprecated)]
pub use nullability::{NullsFlagBucket, nulls_flag_histogram};
pub use opaque::{OPAQUE_ENTROPY_THRESHOLD, is_opaque_high_entropy};
pub use opaque_page_tuples::{OpaquePageTuple, scan_opaque_page_tuples};
pub use page_attribution::{AttributionGap, PageAttribution};
pub use partial_row::{
    PartialRowLookupError, boolean_value_by_column_id, boolean_value_by_column_name,
    prefix_value_by_column_id, prefix_value_by_column_name,
};
pub use physical_carrier_census::{
    AdjacentPageStructuralSummary, ContinuationPrefixProvenance, MAX_CONTINUATION_PREFIX_LEN,
    PhysicalCarrierCensus, PhysicalCarrierPage, PhysicalCarrierPageStatus, SlotDirectoryCensus,
    census_decoded_physical_carrier_page, census_physical_carriers,
};
pub use quickbooks_balance::{
    QuickBooksLegacyBalance, QuickBooksLegacyBalanceError, QuickBooksLegacyBalanceFlags,
    QuickBooksLegacyBalanceKind,
};
pub use quickbooks_date::{QuickBooksDate, QuickBooksDateError};
pub use row_scan::{
    PageScanOutcome, PageSkipReason, RowFragment, RowProvenance, RowScanError, RowScanEvent,
    RowScanIter, SkippedPage, SlotEndian, iter_row_fragments, scan_decoded_page,
};
pub use schema_account_adapter::{
    AccountLifecycle, AccountRowDisposition, AccountRowStateEvidence, AccountSelectionAudit,
    ENTERPRISE24_ACCOUNT_COLUMN_COUNT, ENTERPRISE24_ACCOUNT_TABLE_ID, SchemaAccountAdapterError,
    SchemaAccountRow, adapt_complete_account_schema, audit_account_selection,
    decode_schema_account_row_exact, decode_schema_account_row_partial,
    resolve_enterprise24_account_type18, validate_account_row_schema,
};
pub use schema_adapter::{
    CatalogCoverageAttestation, CatalogDefaultAttestation, CatalogDefaultEnvelope,
    RowStorageAttestation, SchemaAdapterError, adapt_complete_schema,
};
pub use schema_posting_adapter::{
    EnterprisePostingAdaptation, EnterprisePostingAdapterError, EnterprisePostingExclusion,
    EnterprisePostingRow, EnterprisePostingTransactionType, adapt_enterprise_posting_row,
    adapt_enterprise_posting_row_partial, adapt_materialized_bill_posting_row,
    adapt_materialized_check_posting_row, adapt_materialized_general_journal_posting_row,
};
pub use syscolumn::{
    MATERIALIZED_SYSCOLUMN_TABLE_ID, MaterializedSysColumnCollection,
    MaterializedSysColumnCollectionError, MaterializedSysColumnCompletenessAttestation,
    MaterializedSysColumnSkippedPages, SYSCOLUMN_TAG, SysColumn, SysColumnTagBvRecovery,
    collect_materialized_syscolumns, collect_unique as collect_unique_syscolumns, iter_syscolumns,
    parse_materialized_syscolumn_record, recover_bv_from_syscolumn_tag,
    scan_materialized_syscolumn_records, scan_page as scan_syscolumn_page,
    scan_page_from_syscolumn_tag, schema_for,
};
pub use sysindex::{
    AuditOutcome, CrossValidation, DISAGREE_SAMPLE_LIMIT, SYSINDEX_CREATOR, SysIndexEntry,
    collect_unique as collect_unique_sysindex, iter_sysindex, scan_page as scan_sysindex_page,
};
pub use sysobject::{SYSOBJECT_NAME_OFFSET, bridge_owners_to_tables};
pub use systable::{
    MATERIALIZED_SYSTABLE_TABLE_ID, MaterializedSysTableCollection,
    MaterializedSysTableCollectionError, MaterializedSysTableSkippedPages,
    MaterializedTableLogicalExpectation, SysTableEntry, SysTablePostNameDiagnostics,
    aggregate_post_name_diagnostics, collect_materialized_systables, collect_unique,
    iter_systable_entries, parse_materialized_systable_record, scan_materialized_systable_records,
    scan_page as scan_systable_page, scan_raw_page_with_affine_witness,
};
pub use tagged_field::{
    PLAUSIBLE_SA_DATE_MAX_EXCLUSIVE, PLAUSIBLE_SA_DATE_MIN, PrintableStringAnchor, QB_ID_LEN,
    QbIdAnchor, RowAnchors, SaDateAnchor, SignedAmountAnchor, discover_row_anchors,
    discover_row_anchors_in_date_range,
};
pub use transaction_header::{TransactionHeader, iter_transaction_headers};

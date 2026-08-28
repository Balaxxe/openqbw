//! Fail-closed hand-off contracts between physical QBW decoders and accounting.
//!
//! This module contains no page, row, or QuickBooks layout knowledge.  A
//! decoder must turn its findings into normalized [`Account`] and [`Posting`]
//! values, explicitly attest that it did not silently omit any recognized row,
//! and identify the exact immutable source snapshot.  Only then can the two
//! streams be joined into a [`Ledger`].
//!
//! The boundary is intentionally small: it is suitable for independent account
//! and posting decoders and does not imply use of QuickBooks, its SDK, COM,
//! ODBC, or any live database service.

use crate::{Account, AccountingError, Ledger, LedgerCompleteness, Posting};

/// An opaque identity for the precise QBW snapshot an extraction read.
///
/// Callers commonly use a content hash plus size, but the contract does not
/// prescribe a hashing implementation.  It must change whenever the source
/// bytes being decoded change.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourceSnapshotId(String);

impl SourceSnapshotId {
    /// Creates a non-empty, opaque snapshot identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, DecoderContractError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(DecoderContractError::EmptySourceSnapshotId);
        }
        Ok(Self(value))
    }

    /// Returns the caller-supplied opaque identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A named, versioned decoder identity used for an extraction hand-off.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DecoderIdentity(String);

impl DecoderIdentity {
    /// Creates a non-empty decoder identity such as `account-v1`.
    pub fn new(value: impl Into<String>) -> Result<Self, DecoderContractError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(DecoderContractError::EmptyDecoderIdentity);
        }
        Ok(Self(value))
    }

    /// Returns the caller-supplied decoder identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Evidence that a decoder handled every recognized source candidate.
///
/// Counts refer to logical source candidates, not bytes or page slots.  A
/// handled posting candidate is either a non-zero normalized [`Posting`] or a
/// deliberate [`PostingExclusion`].  This distinction matters for physical
/// source/link rows, deletion tombstones, and proven canonical-zero void rows:
/// they are accounting-relevant evidence, but are not valid ledger postings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteCoverage {
    /// Number of recognized logical source candidates.
    pub recognized_candidates: u64,
    /// Number of candidates explicitly handed to the contract.
    pub handled_candidates: u64,
}

impl CompleteCoverage {
    /// Creates coverage only when every recognized candidate was normalized.
    pub fn new(
        recognized_candidates: u64,
        handled_candidates: u64,
    ) -> Result<Self, DecoderContractError> {
        if recognized_candidates != handled_candidates {
            return Err(DecoderContractError::CoverageMismatch {
                recognized_candidates,
                handled_candidates,
            });
        }
        Ok(Self {
            recognized_candidates,
            handled_candidates,
        })
    }
}

/// A proven reason why one recognized physical candidate is not a posting.
///
/// This enum is deliberately closed.  A decoder cannot turn an unrecognized
/// or merely inconvenient row into an exclusion by attaching free-form text.
/// Non-zero superseded candidates remain [`Posting`] values with
/// [`crate::CurrentState::Superseded`] so that the ledger can audit them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostingExclusionReason {
    /// The row is a source/header/link carrier and does not itself post.
    SourceOrLinkRow,
    /// The row is a deletion tombstone rather than a posting candidate.
    DeletionTombstone,
    /// The row is a voided posting carrier with the decoder's proven,
    /// canonical zero amount representation.
    CanonicalZeroVoidedRow,
    /// The row has a decoder-proven canonical zero amount, but its lifecycle
    /// meaning has not been established as a void or deletion.
    CanonicalZeroAmount,
}

/// Auditable disposition of a recognized physical posting candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostingExclusion {
    provenance: crate::PostingProvenance,
    reason: PostingExclusionReason,
}

impl PostingExclusion {
    /// Records a proven non-posting disposition for a recognized row.
    pub fn new(provenance: crate::PostingProvenance, reason: PostingExclusionReason) -> Self {
        Self { provenance, reason }
    }

    /// Returns the physical/source evidence for the handled row.
    pub fn provenance(&self) -> &crate::PostingProvenance {
        &self.provenance
    }

    /// Returns the closed, decoder-proven exclusion reason.
    pub const fn reason(&self) -> PostingExclusionReason {
        self.reason
    }
}

/// One explicitly handled posting candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PostingDisposition {
    /// A non-zero row supplied to the normalized ledger.
    Posting(Posting),
    /// A recognized row intentionally retained outside the ledger.
    Excluded(PostingExclusion),
}

impl PostingDisposition {
    /// Returns the provenance of the physical source candidate.
    pub fn provenance(&self) -> &crate::PostingProvenance {
        match self {
            Self::Posting(posting) => &posting.provenance,
            Self::Excluded(exclusion) => exclusion.provenance(),
        }
    }
}

impl From<Posting> for PostingDisposition {
    fn from(posting: Posting) -> Self {
        Self::Posting(posting)
    }
}

impl From<PostingExclusion> for PostingDisposition {
    fn from(exclusion: PostingExclusion) -> Self {
        Self::Excluded(exclusion)
    }
}

/// Complete, source-bound normalized account rows produced by an account decoder.
#[derive(Clone, Debug)]
pub struct DecodedAccounts {
    snapshot: SourceSnapshotId,
    decoder: DecoderIdentity,
    accounts: Vec<Account>,
}

impl DecodedAccounts {
    /// Accepts account rows only if their complete-coverage attestation agrees
    /// exactly with the supplied collection.
    pub fn new(
        snapshot: SourceSnapshotId,
        decoder: DecoderIdentity,
        accounts: impl IntoIterator<Item = Account>,
        coverage: CompleteCoverage,
    ) -> Result<Self, DecoderContractError> {
        let accounts: Vec<_> = accounts.into_iter().collect();
        validate_materialized_count(coverage, accounts.len())?;
        Ok(Self {
            snapshot,
            decoder,
            accounts,
        })
    }

    /// Returns the snapshot identity that this decoder read.
    pub fn snapshot(&self) -> &SourceSnapshotId {
        &self.snapshot
    }

    /// Returns the decoder identity that produced these rows.
    pub fn decoder(&self) -> &DecoderIdentity {
        &self.decoder
    }
}

/// Complete, source-bound normalized posting candidates produced by a decoder.
#[derive(Clone, Debug)]
pub struct DecodedPostings {
    snapshot: SourceSnapshotId,
    decoder: DecoderIdentity,
    dispositions: Vec<PostingDisposition>,
}

impl DecodedPostings {
    /// Accepts explicitly handled posting candidates only if the decoder
    /// attests that none of its recognized candidates were silently dropped.
    ///
    /// Existing callers that only have non-zero [`Posting`] values can pass
    /// them directly.  Decoders must use [`PostingExclusion`] for a proven
    /// non-posting row; zero `Posting` values remain rejected by [`Ledger`].
    pub fn new<I, T>(
        snapshot: SourceSnapshotId,
        decoder: DecoderIdentity,
        dispositions: I,
        coverage: CompleteCoverage,
    ) -> Result<Self, DecoderContractError>
    where
        I: IntoIterator<Item = T>,
        T: Into<PostingDisposition>,
    {
        let dispositions: Vec<_> = dispositions.into_iter().map(Into::into).collect();
        validate_materialized_count(coverage, dispositions.len())?;
        validate_unique_candidate_provenance(&dispositions)?;
        Ok(Self {
            snapshot,
            decoder,
            dispositions,
        })
    }

    /// Returns the snapshot identity that this decoder read.
    pub fn snapshot(&self) -> &SourceSnapshotId {
        &self.snapshot
    }

    /// Returns the decoder identity that produced these rows.
    pub fn decoder(&self) -> &DecoderIdentity {
        &self.decoder
    }

    /// Returns every handled source candidate, including explicit exclusions.
    pub fn dispositions(&self) -> impl Iterator<Item = &PostingDisposition> {
        self.dispositions.iter()
    }

    /// Returns only the non-zero normalized posting candidates.
    pub fn postings(&self) -> impl Iterator<Item = &Posting> {
        self.dispositions
            .iter()
            .filter_map(|disposition| match disposition {
                PostingDisposition::Posting(posting) => Some(posting),
                PostingDisposition::Excluded(_) => None,
            })
    }

    /// Consumes this hand-off and returns the normalized candidates that may
    /// enter a ledger. Explicit exclusions remain inspectable through
    /// [`Self::dispositions`] until this conversion is requested.
    fn into_postings(self) -> impl Iterator<Item = Posting> {
        self.dispositions
            .into_iter()
            .filter_map(|disposition| match disposition {
                PostingDisposition::Posting(posting) => Some(posting),
                PostingDisposition::Excluded(_) => None,
            })
    }
}

fn validate_materialized_count(
    coverage: CompleteCoverage,
    actual_rows: usize,
) -> Result<(), DecoderContractError> {
    let actual_rows =
        u64::try_from(actual_rows).map_err(|_| DecoderContractError::MaterializedCountOverflow)?;
    if coverage.handled_candidates != actual_rows {
        return Err(DecoderContractError::MaterializedCountMismatch {
            attested_rows: coverage.handled_candidates,
            actual_rows,
        });
    }
    Ok(())
}

fn validate_unique_candidate_provenance(
    dispositions: &[PostingDisposition],
) -> Result<(), DecoderContractError> {
    let mut source_rows = std::collections::BTreeSet::new();
    for disposition in dispositions {
        let source_row = disposition.provenance().source_row.clone();
        if !source_rows.insert(source_row.clone()) {
            return Err(DecoderContractError::DuplicateCandidateProvenance { source_row });
        }
    }
    Ok(())
}

/// Builds a reportable ledger only from two complete, matching snapshot streams.
pub struct LedgerAdapter;

impl LedgerAdapter {
    /// Joins independently decoded account and posting streams.
    ///
    /// This is the only conversion provided by the contract.  It always passes
    /// [`LedgerCompleteness::Complete`] because incomplete/unsupported decoders
    /// cannot construct either input wrapper; such decoders must return their
    /// own failure instead of emitting a potentially partial financial report.
    pub fn build(
        accounts: DecodedAccounts,
        postings: DecodedPostings,
    ) -> Result<Ledger, DecoderContractError> {
        if accounts.snapshot != postings.snapshot {
            return Err(DecoderContractError::SnapshotMismatch {
                accounts_snapshot: accounts.snapshot.0,
                postings_snapshot: postings.snapshot.0,
            });
        }
        Ledger::new(
            accounts.accounts,
            postings.into_postings(),
            LedgerCompleteness::Complete,
        )
        .map_err(DecoderContractError::InvalidNormalizedLedger)
    }
}

/// Failure at the decoder-to-ledger boundary.
#[derive(Debug)]
pub enum DecoderContractError {
    /// A source snapshot identifier was empty.
    EmptySourceSnapshotId,
    /// A decoder identity was empty.
    EmptyDecoderIdentity,
    /// A decoder asserted complete coverage while dropping candidates.
    CoverageMismatch {
        /// Number of candidates recognized by the decoder.
        recognized_candidates: u64,
        /// Number of candidates explicitly handled by the decoder.
        handled_candidates: u64,
    },
    /// The supplied Rust collection did not match the decoder's attestation.
    MaterializedCountMismatch {
        /// Number of candidates explicitly handled by the decoder.
        attested_rows: u64,
        /// Actual supplied collection length.
        actual_rows: u64,
    },
    /// A platform could not represent a collection length as the contract's u64 count.
    MaterializedCountOverflow,
    /// Two handled candidates named the same file-local source row.
    DuplicateCandidateProvenance {
        /// Duplicate source row locator.
        source_row: String,
    },
    /// Account and posting decoders did not read the same immutable QBW snapshot.
    SnapshotMismatch {
        /// Account decoder input identity.
        accounts_snapshot: String,
        /// Posting decoder input identity.
        postings_snapshot: String,
    },
    /// Normalized rows violated a ledger invariant.
    InvalidNormalizedLedger(AccountingError),
}

impl std::fmt::Display for DecoderContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySourceSnapshotId => write!(f, "source snapshot identifier was empty"),
            Self::EmptyDecoderIdentity => write!(f, "decoder identity was empty"),
            Self::CoverageMismatch {
                recognized_candidates,
                handled_candidates,
            } => write!(
                f,
                "decoder recognized {recognized_candidates} candidates but handled {handled_candidates}"
            ),
            Self::MaterializedCountMismatch {
                attested_rows,
                actual_rows,
            } => write!(
                f,
                "decoder attested {attested_rows} rows but supplied {actual_rows}"
            ),
            Self::MaterializedCountOverflow => write!(f, "materialized row count exceeded u64"),
            Self::DuplicateCandidateProvenance { source_row } => write!(
                f,
                "decoder supplied more than one disposition for source row {source_row}"
            ),
            Self::SnapshotMismatch {
                accounts_snapshot,
                postings_snapshot,
            } => write!(
                f,
                "accounts came from snapshot {accounts_snapshot}, postings from {postings_snapshot}"
            ),
            Self::InvalidNormalizedLedger(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DecoderContractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidNormalizedLedger(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccountId, AccountType, CurrentState, DebitCredit, DebitCreditAmount, PostingId,
        PostingProvenance, TransactionId,
    };

    fn snapshot(value: &str) -> SourceSnapshotId {
        SourceSnapshotId::new(value).unwrap()
    }

    fn decoder(value: &str) -> DecoderIdentity {
        DecoderIdentity::new(value).unwrap()
    }

    fn account(id: &str) -> Account {
        Account::new(AccountId::new(id).unwrap(), id, AccountType::Asset, true).unwrap()
    }

    fn posting(id: &str, account_id: &str, side: DebitCredit) -> Posting {
        Posting::new(
            TransactionId::new("transaction").unwrap(),
            PostingId::new(id).unwrap(),
            AccountId::new(account_id).unwrap(),
            5,
            DebitCreditAmount::new(side, 100).unwrap(),
            CurrentState::Current,
            PostingProvenance::new(format!("source-{id}"), Some(9), Some(1), "test").unwrap(),
            None,
            None,
        )
    }

    #[test]
    fn complete_matching_streams_build_a_reportable_ledger() {
        let accounts = DecodedAccounts::new(
            snapshot("sha256:a"),
            decoder("accounts-v1"),
            [account("asset"), account("equity")],
            CompleteCoverage::new(2, 2).unwrap(),
        )
        .unwrap();
        let postings = DecodedPostings::new(
            snapshot("sha256:a"),
            decoder("postings-v1"),
            [
                posting("debit", "asset", DebitCredit::Debit),
                posting("credit", "equity", DebitCredit::Credit),
            ],
            CompleteCoverage::new(2, 2).unwrap(),
        )
        .unwrap();
        let ledger = LedgerAdapter::build(accounts, postings).unwrap();
        assert_eq!(ledger.general_ledger_as_of(5).unwrap().entries.len(), 2);
    }

    #[test]
    fn coverage_attestation_cannot_silently_drop_or_add_rows() {
        assert!(matches!(
            CompleteCoverage::new(3, 2),
            Err(DecoderContractError::CoverageMismatch { .. })
        ));
        let result = DecodedAccounts::new(
            snapshot("s"),
            decoder("d"),
            [account("asset")],
            CompleteCoverage::new(2, 2).unwrap(),
        );
        assert!(matches!(
            result,
            Err(DecoderContractError::MaterializedCountMismatch {
                attested_rows: 2,
                actual_rows: 1
            })
        ));
    }

    #[test]
    fn streams_from_different_file_snapshots_cannot_be_combined() {
        let accounts = DecodedAccounts::new(
            snapshot("before"),
            decoder("a"),
            [account("asset")],
            CompleteCoverage::new(1, 1).unwrap(),
        )
        .unwrap();
        let postings = DecodedPostings::new(
            snapshot("after"),
            decoder("p"),
            Vec::<Posting>::new(),
            CompleteCoverage::new(0, 0).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            LedgerAdapter::build(accounts, postings),
            Err(DecoderContractError::SnapshotMismatch { .. })
        ));
    }

    #[test]
    fn normalized_ledger_invariants_remain_a_required_final_gate() {
        let accounts = DecodedAccounts::new(
            snapshot("s"),
            decoder("a"),
            [account("asset")],
            CompleteCoverage::new(1, 1).unwrap(),
        )
        .unwrap();
        let postings = DecodedPostings::new(
            snapshot("s"),
            decoder("p"),
            [posting("bad", "missing", DebitCredit::Debit)],
            CompleteCoverage::new(1, 1).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            LedgerAdapter::build(accounts, postings),
            Err(DecoderContractError::InvalidNormalizedLedger(
                AccountingError::UnknownAccount { .. }
            ))
        ));
    }

    #[test]
    fn proven_non_posting_rows_count_for_coverage_without_entering_ledger() {
        let accounts = DecodedAccounts::new(
            snapshot("s"),
            decoder("a"),
            [account("asset"), account("equity")],
            CompleteCoverage::new(2, 2).unwrap(),
        )
        .unwrap();
        let source_link = PostingExclusion::new(
            PostingProvenance::new("source-link", Some(2), Some(1), "test").unwrap(),
            PostingExclusionReason::SourceOrLinkRow,
        );
        let voided = PostingExclusion::new(
            PostingProvenance::new("voided-zero", Some(2), Some(2), "test").unwrap(),
            PostingExclusionReason::CanonicalZeroVoidedRow,
        );
        let tombstone = PostingExclusion::new(
            PostingProvenance::new("tombstone", Some(2), Some(3), "test").unwrap(),
            PostingExclusionReason::DeletionTombstone,
        );
        let postings = DecodedPostings::new(
            snapshot("s"),
            decoder("p"),
            [
                PostingDisposition::from(posting("debit", "asset", DebitCredit::Debit)),
                PostingDisposition::from(posting("credit", "equity", DebitCredit::Credit)),
                PostingDisposition::from(source_link),
                PostingDisposition::from(voided),
                PostingDisposition::from(tombstone),
            ],
            CompleteCoverage::new(5, 5).unwrap(),
        )
        .unwrap();
        assert_eq!(postings.dispositions().count(), 5);
        assert_eq!(postings.postings().count(), 2);

        let ledger = LedgerAdapter::build(accounts, postings).unwrap();
        assert_eq!(ledger.general_ledger_as_of(5).unwrap().entries.len(), 2);
    }

    #[test]
    fn zero_posting_cannot_be_used_as_an_exclusion_shortcut() {
        let accounts = DecodedAccounts::new(
            snapshot("s"),
            decoder("a"),
            [account("asset")],
            CompleteCoverage::new(1, 1).unwrap(),
        )
        .unwrap();
        let mut zero = posting("zero", "asset", DebitCredit::Debit);
        zero.signed_minor_units = 0;
        let postings = DecodedPostings::new(
            snapshot("s"),
            decoder("p"),
            [zero],
            CompleteCoverage::new(1, 1).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            LedgerAdapter::build(accounts, postings),
            Err(DecoderContractError::InvalidNormalizedLedger(
                AccountingError::ZeroPosting { .. }
            ))
        ));
    }

    #[test]
    fn one_source_row_cannot_receive_two_dispositions() {
        let first = posting("first", "asset", DebitCredit::Debit);
        let duplicate = PostingExclusion::new(
            first.provenance.clone(),
            PostingExclusionReason::DeletionTombstone,
        );
        assert!(matches!(
            DecodedPostings::new(
                snapshot("s"),
                decoder("p"),
                [
                    PostingDisposition::from(first),
                    PostingDisposition::from(duplicate)
                ],
                CompleteCoverage::new(2, 2).unwrap(),
            ),
            Err(DecoderContractError::DuplicateCandidateProvenance { .. })
        ));
    }
}

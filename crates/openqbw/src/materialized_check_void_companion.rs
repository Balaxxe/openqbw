//! Closed classifier for the proven table-3047 Check void-companion carrier.
//!
//! This narrow helper is intentionally not a generic "unknown Check row"
//! exclusion.  It accepts only the bounded, fixed-shape companion carrier and
//! only after the caller independently supplies the complete per-master
//! lifecycle evidence recovered from the Check target rows.

use thiserror::Error;

/// Physical Enterprise table containing the bounded Check companion carrier.
pub const MATERIALIZED_CHECK_VOID_COMPANION_TABLE_ID: u32 = 3047;
/// Exact observed table-3047 companion-row flags byte.
pub const MATERIALIZED_CHECK_VOID_COMPANION_FLAGS: u8 = 0;
/// Exact observed table-3047 companion-row kind byte.
pub const MATERIALIZED_CHECK_VOID_COMPANION_KIND: u8 = 0x64;
/// Exact bounded byte length of the observed companion carrier.
pub const MATERIALIZED_CHECK_VOID_COMPANION_LEN: usize = 185;

const TARGET_OFFSET: usize = 0x0c;
const MASTER_OFFSET: usize = 0x10;

/// A bounded Check void-companion carrier before its lifecycle proof is applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaterializedCheckVoidCompanionCarrier {
    target_record_number: u32,
    master_record_number: u32,
}

impl MaterializedCheckVoidCompanionCarrier {
    /// Parse only the exact fixed-shape table-3047 companion carrier.
    pub fn parse(input: &[u8]) -> Result<Self, MaterializedCheckVoidCompanionError> {
        if input.len() != MATERIALIZED_CHECK_VOID_COMPANION_LEN {
            return Err(MaterializedCheckVoidCompanionError::LengthMismatch {
                actual: input.len(),
            });
        }
        let declared_len = usize::from(u16::from_le_bytes([input[0], input[1]]));
        if declared_len != input.len() {
            return Err(
                MaterializedCheckVoidCompanionError::DeclaredLengthMismatch {
                    declared: declared_len,
                },
            );
        }
        if input[2] != MATERIALIZED_CHECK_VOID_COMPANION_FLAGS {
            return Err(MaterializedCheckVoidCompanionError::UnexpectedFlags { actual: input[2] });
        }
        if input[3] != MATERIALIZED_CHECK_VOID_COMPANION_KIND {
            return Err(MaterializedCheckVoidCompanionError::UnexpectedKind { actual: input[3] });
        }
        let target_record_number = u32::from_le_bytes(
            input[TARGET_OFFSET..TARGET_OFFSET + 4]
                .try_into()
                .expect("fixed exact length"),
        );
        let master_record_number = u32::from_le_bytes(
            input[MASTER_OFFSET..MASTER_OFFSET + 4]
                .try_into()
                .expect("fixed exact length"),
        );
        if target_record_number == 0 || master_record_number == 0 {
            return Err(MaterializedCheckVoidCompanionError::ZeroRequiredRecordId);
        }
        Ok(Self {
            target_record_number,
            master_record_number,
        })
    }

    /// Returns the bounded companion target identity.
    #[must_use]
    pub const fn target_record_number(self) -> u32 {
        self.target_record_number
    }

    /// Returns the bounded transaction-master identity used for the lifecycle join.
    #[must_use]
    pub const fn master_record_number(self) -> u32 {
        self.master_record_number
    }
}

/// Complete, caller-provided evidence for one Check master.
///
/// The caller must derive these counts from a complete table-3047 census, not
/// from rows that happened to decode. This helper never scans QBW pages or
/// guesses the current state itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckVoidCompanionMasterEvidence {
    /// Count of the same-master `kind=0xe4` target rows carrying the exact
    /// canonical-zero amount token.
    pub canonical_zero_e4_row_count: u8,
    /// Count of same-master nonzero posting target rows in the current carrier
    /// census. Any nonzero value prevents exclusion.
    pub nonzero_posting_row_count: u32,
}

/// Closed result of applying the independent lifecycle evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckVoidCompanionClassification {
    /// The carrier is a proven void companion, not a posting line.
    VoidCompanionCarrier,
}

/// Classify a parsed carrier only when its master's lifecycle evidence is exact.
pub fn classify_materialized_check_void_companion(
    _carrier: MaterializedCheckVoidCompanionCarrier,
    evidence: CheckVoidCompanionMasterEvidence,
) -> Result<CheckVoidCompanionClassification, MaterializedCheckVoidCompanionError> {
    if evidence.canonical_zero_e4_row_count != 2 {
        return Err(
            MaterializedCheckVoidCompanionError::CanonicalZeroRowCountMismatch {
                actual: evidence.canonical_zero_e4_row_count,
            },
        );
    }
    if evidence.nonzero_posting_row_count != 0 {
        return Err(
            MaterializedCheckVoidCompanionError::NonzeroPostingsPresent {
                actual: evidence.nonzero_posting_row_count,
            },
        );
    }
    Ok(CheckVoidCompanionClassification::VoidCompanionCarrier)
}

/// Reasons a candidate cannot become the closed void-companion exclusion.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MaterializedCheckVoidCompanionError {
    /// The bounded carrier did not have the sole calibrated length.
    #[error(
        "Check void companion length was {actual}, expected {MATERIALIZED_CHECK_VOID_COMPANION_LEN}"
    )]
    LengthMismatch {
        /// Actual bounded byte length.
        actual: usize,
    },
    /// Its on-row declared length disagreed with its bounded length.
    #[error("Check void companion declared length {declared} disagrees with exact bounded length")]
    DeclaredLengthMismatch {
        /// u16 length declared in the candidate row.
        declared: usize,
    },
    /// The carrier flags differed from the calibrated fixed value.
    #[error("Check void companion flags {actual:#04x} are unsupported")]
    UnexpectedFlags {
        /// Actual flags byte.
        actual: u8,
    },
    /// The carrier kind differed from the calibrated fixed value.
    #[error("Check void companion kind {actual:#04x} is unsupported")]
    UnexpectedKind {
        /// Actual row-kind byte.
        actual: u8,
    },
    /// A required target or master record reference was zero.
    #[error("Check void companion has a zero target or master record reference")]
    ZeroRequiredRecordId,
    /// The caller's complete master census did not establish two zero e4 rows.
    #[error("Check void companion master has {actual} canonical-zero e4 rows, expected 2")]
    CanonicalZeroRowCountMismatch {
        /// Actual canonical-zero e4 line count in caller evidence.
        actual: u8,
    },
    /// The master still has a nonzero posting and cannot be excluded.
    #[error("Check void companion master has {actual} nonzero posting rows")]
    NonzeroPostingsPresent {
        /// Actual nonzero posting count in caller evidence.
        actual: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TARGET: u32 = 0x0012_3456;
    const SAMPLE_MASTER: u32 = 0x0012_3457;

    fn sample() -> Vec<u8> {
        let mut row = vec![0_u8; MATERIALIZED_CHECK_VOID_COMPANION_LEN];
        let length = row.len() as u16;
        row[..2].copy_from_slice(&length.to_le_bytes());
        row[3] = MATERIALIZED_CHECK_VOID_COMPANION_KIND;
        row[TARGET_OFFSET..TARGET_OFFSET + 4].copy_from_slice(&SAMPLE_TARGET.to_le_bytes());
        row[MASTER_OFFSET..MASTER_OFFSET + 4].copy_from_slice(&SAMPLE_MASTER.to_le_bytes());
        row
    }

    #[test]
    fn classifies_only_exact_carrier_with_complete_void_evidence() {
        let carrier = MaterializedCheckVoidCompanionCarrier::parse(&sample()).unwrap();
        assert_eq!(carrier.target_record_number(), SAMPLE_TARGET);
        assert_eq!(carrier.master_record_number(), SAMPLE_MASTER);
        assert_eq!(
            classify_materialized_check_void_companion(
                carrier,
                CheckVoidCompanionMasterEvidence {
                    canonical_zero_e4_row_count: 2,
                    nonzero_posting_row_count: 0,
                },
            ),
            Ok(CheckVoidCompanionClassification::VoidCompanionCarrier)
        );
    }

    #[test]
    fn rejects_false_positive_shape_and_incomplete_lifecycle_evidence() {
        let mut wrong_length = sample();
        wrong_length.pop();
        assert!(matches!(
            MaterializedCheckVoidCompanionCarrier::parse(&wrong_length),
            Err(MaterializedCheckVoidCompanionError::LengthMismatch { .. })
        ));
        let mut zero_master = sample();
        zero_master[MASTER_OFFSET..MASTER_OFFSET + 4].fill(0);
        assert!(matches!(
            MaterializedCheckVoidCompanionCarrier::parse(&zero_master),
            Err(MaterializedCheckVoidCompanionError::ZeroRequiredRecordId)
        ));
        let carrier = MaterializedCheckVoidCompanionCarrier::parse(&sample()).unwrap();
        assert!(matches!(
            classify_materialized_check_void_companion(
                carrier,
                CheckVoidCompanionMasterEvidence {
                    canonical_zero_e4_row_count: 1,
                    nonzero_posting_row_count: 0,
                },
            ),
            Err(MaterializedCheckVoidCompanionError::CanonicalZeroRowCountMismatch { actual: 1 })
        ));
        assert!(matches!(
            classify_materialized_check_void_companion(
                carrier,
                CheckVoidCompanionMasterEvidence {
                    canonical_zero_e4_row_count: 2,
                    nonzero_posting_row_count: 1,
                },
            ),
            Err(MaterializedCheckVoidCompanionError::NonzeroPostingsPresent { actual: 1 })
        ));
    }
}

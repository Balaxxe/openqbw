//! Bounded cents codec for controlled materialized QuickBooks posting rows.
//!
//! This is intentionally **not** the generic SQL Anywhere `NUMERIC` grammar.
//! Controlled materialized Check and Journal witnesses use a count-prefixed,
//! little-endian base-100 cents token with a small, observed sign/scale marker
//! set.  Callers must already have an exactly bounded posting-row field.

use thiserror::Error;

use opensqlany::EnterpriseNumericToken;

const CENTS_EXPONENT_MARKER: u8 = 0x3f;
const MAX_OBSERVED_EXPONENT_MARKER: u8 = 0x45;
const CANONICAL_ZERO_MARKER: u8 = 0x81;

/// A bounded, controlled-materialized posting amount in cents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MaterializedPostingCents {
    signed_cents: i64,
    canonical_zero: bool,
}

impl MaterializedPostingCents {
    /// Parses one count-prefixed controlled posting amount token.
    ///
    /// The established nonzero form stores a signed base-100 exponent in the
    /// marker: its low seven bits run from `0x3f` (cents) through `0x45`, and its
    /// high bit is the sign (`set` for positive). The established zero form is
    /// exactly `[0, 0x81]`. Any other marker, scale, or digit order is rejected.
    pub(crate) fn parse(input: &[u8]) -> Result<Self, MaterializedPostingCentsError> {
        if input.len() < 2 {
            return Err(MaterializedPostingCentsError::TokenTooShort {
                actual: input.len(),
            });
        }
        let digits = usize::from(input[0]);
        let marker = input[1];
        if digits == 0 {
            return if marker == CANONICAL_ZERO_MARKER {
                Ok(Self::canonical_zero())
            } else {
                Err(MaterializedPostingCentsError::UnsupportedZeroMarker { marker })
            };
        }

        let end = 2usize.checked_add(digits).ok_or(
            MaterializedPostingCentsError::DigitsOutsideToken {
                digits,
                token_len: input.len(),
            },
        )?;
        let values =
            input
                .get(2..end)
                .ok_or(MaterializedPostingCentsError::DigitsOutsideToken {
                    digits,
                    token_len: input.len(),
                })?;
        Self::from_parts(marker, values)
    }

    /// Converts a schema-decoded raw Enterprise numeric token after the
    /// table-specific caller has established that the column is a monetary
    /// amount denominated in cents.
    pub(crate) fn from_enterprise_token(
        token: &EnterpriseNumericToken,
    ) -> Result<Self, MaterializedPostingCentsError> {
        if token.digits.is_empty() {
            return if token.marker == CANONICAL_ZERO_MARKER {
                Ok(Self::canonical_zero())
            } else {
                Err(MaterializedPostingCentsError::UnsupportedZeroMarker {
                    marker: token.marker,
                })
            };
        }
        Self::from_parts(token.marker, &token.digits)
    }

    fn from_parts(marker: u8, values: &[u8]) -> Result<Self, MaterializedPostingCentsError> {
        let exponent_marker = marker & 0x7f;
        if !(CENTS_EXPONENT_MARKER..=MAX_OBSERVED_EXPONENT_MARKER).contains(&exponent_marker) {
            return Err(MaterializedPostingCentsError::UnsupportedMarker { marker });
        }
        let negative = marker & 0x80 == 0;

        let mut magnitude = 0_i64;
        for &digit in values.iter().rev() {
            if digit > 99 {
                return Err(MaterializedPostingCentsError::InvalidBase100Digit { digit });
            }
            magnitude = magnitude
                .checked_mul(100)
                .and_then(|value| value.checked_add(i64::from(digit)))
                .ok_or(MaterializedPostingCentsError::CentsOverflow)?;
        }
        for _ in CENTS_EXPONENT_MARKER..exponent_marker {
            magnitude = magnitude
                .checked_mul(100)
                .ok_or(MaterializedPostingCentsError::CentsOverflow)?;
        }
        Ok(Self {
            signed_cents: if negative { -magnitude } else { magnitude },
            canonical_zero: false,
        })
    }

    const fn canonical_zero() -> Self {
        Self {
            signed_cents: 0,
            canonical_zero: true,
        }
    }

    /// Returns the exact controlled signed cents value.
    pub(crate) const fn signed_cents(self) -> i64 {
        self.signed_cents
    }

    /// Returns whether this was the observed canonical zero token.
    pub(crate) const fn is_canonical_zero(self) -> bool {
        self.canonical_zero
    }
}

/// Rejection reasons for [`MaterializedPostingCents::parse`].
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub(crate) enum MaterializedPostingCentsError {
    /// The token did not contain its count and marker bytes.
    #[error("materialized posting amount is too short: {actual} bytes")]
    TokenTooShort {
        /// Actual supplied byte count.
        actual: usize,
    },
    /// The count-prefixed digits were not completely bounded by the token.
    #[error(
        "materialized posting amount declares {digits} base-100 digits beyond a {token_len}-byte token"
    )]
    DigitsOutsideToken {
        /// Declared number of base-100 digits.
        digits: usize,
        /// Actual token byte length.
        token_len: usize,
    },
    /// The zero-length token did not use the controlled canonical marker.
    #[error("unsupported materialized posting zero marker {marker:#04x}")]
    UnsupportedZeroMarker {
        /// Observed marker.
        marker: u8,
    },
    /// The nonzero token did not use a controlled sign/scale marker.
    #[error("unsupported materialized posting sign/scale marker {marker:#04x}")]
    UnsupportedMarker {
        /// Observed marker.
        marker: u8,
    },
    /// A base-100 digit was outside its valid range.
    #[error("invalid materialized posting base-100 digit {digit}")]
    InvalidBase100Digit {
        /// Observed digit.
        digit: u8,
    },
    /// The decoded cents magnitude cannot fit an `i64`.
    #[error("materialized posting amount exceeded signed cents")]
    CentsOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_controlled_little_endian_base_100_cents() {
        assert_eq!(
            MaterializedPostingCents::parse(&[2, 0xbf, 41, 37])
                .unwrap()
                .signed_cents(),
            3_741
        );
        assert_eq!(
            MaterializedPostingCents::parse(&[3, 0x3f, 46, 37, 10])
                .unwrap()
                .signed_cents(),
            -103_746
        );
    }

    #[test]
    fn decodes_controlled_whole_and_higher_base_100_exponents() {
        assert_eq!(
            MaterializedPostingCents::parse(&[1, 0xc0, 2])
                .unwrap()
                .signed_cents(),
            200
        );
        assert_eq!(
            MaterializedPostingCents::parse(&[1, 0x41, 4])
                .unwrap()
                .signed_cents(),
            -40_000
        );
    }

    #[test]
    fn decodes_only_the_controlled_zero_marker() {
        let zero = MaterializedPostingCents::parse(&[0, 0x81]).unwrap();
        assert_eq!(zero.signed_cents(), 0);
        assert!(zero.is_canonical_zero());
        assert!(matches!(
            MaterializedPostingCents::parse(&[0, 0x80]),
            Err(MaterializedPostingCentsError::UnsupportedZeroMarker { marker: 0x80 })
        ));
    }

    #[test]
    fn converts_only_explicitly_selected_enterprise_numeric_tokens() {
        let token = EnterpriseNumericToken {
            marker: 0xbf,
            digits: vec![41, 37],
        };
        assert_eq!(
            MaterializedPostingCents::from_enterprise_token(&token)
                .unwrap()
                .signed_cents(),
            3_741
        );
        assert!(matches!(
            MaterializedPostingCents::from_enterprise_token(&EnterpriseNumericToken {
                marker: 0x80,
                digits: Vec::new(),
            }),
            Err(MaterializedPostingCentsError::UnsupportedZeroMarker { marker: 0x80 })
        ));
    }

    #[test]
    fn rejects_unproven_markers_and_incomplete_tokens() {
        assert!(matches!(
            MaterializedPostingCents::parse(&[1, 0x99, 1]),
            Err(MaterializedPostingCentsError::UnsupportedMarker { marker: 0x99 })
        ));
        assert!(matches!(
            MaterializedPostingCents::parse(&[3, 0xbf, 1]),
            Err(MaterializedPostingCentsError::DigitsOutsideToken { digits: 3, .. })
        ));
    }
}

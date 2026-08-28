//! Fixed-width legacy `BalTypeLegacy_6Bytes` values used by QuickBooks dictionaries.
//!
//! This module decodes only the proven six-byte value envelope. It does not
//! locate a balance inside a QBW record, assign a record field tag, or make a
//! posting eligible for accounting output. Those record-placement requirements
//! remain unresolved and are enforced by higher-level decoder contracts.
//!
//! The exact disk order is `[cents, flags, dollars_be_u32]`. A dollar value
//! with no error, percent, or empty flag can be converted losslessly to signed
//! cents. Quantity and status-bearing values remain representable but are not
//! silently treated as money.

use core::fmt;

const KNOWN_FLAG_BITS: u8 = 0x1f;
const KIND_QUANTITY: u8 = 0x01;
const NEGATIVE: u8 = 0x02;
const ERROR: u8 = 0x04;
const PERCENT: u8 = 0x08;
const EMPTY: u8 = 0x10;

/// The proven kind bit in a legacy QuickBooks balance value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QuickBooksLegacyBalanceKind {
    /// A monetary dollar-and-cents value.
    Dollar,
    /// A quantity value whose fractional-byte semantics are not a monetary unit.
    Quantity,
}

/// The recognized flag bits of a legacy six-byte QuickBooks balance.
///
/// Constructing this type rejects all unknown flag bits. The raw recognized
/// byte remains available through [`Self::raw`] for provenance preservation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct QuickBooksLegacyBalanceFlags {
    raw: u8,
}

impl QuickBooksLegacyBalanceFlags {
    /// Validates a raw legacy balance flag byte.
    pub fn from_raw(raw: u8) -> Result<Self, QuickBooksLegacyBalanceError> {
        let unknown_bits = raw & !KNOWN_FLAG_BITS;
        if unknown_bits != 0 {
            return Err(QuickBooksLegacyBalanceError::UnknownFlagBits {
                flags: raw,
                unknown_bits,
            });
        }
        Ok(Self { raw })
    }

    /// Returns the exact validated raw flag byte.
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.raw
    }

    /// Returns whether the balance is a dollar or quantity value.
    #[must_use]
    pub const fn kind(self) -> QuickBooksLegacyBalanceKind {
        if self.raw & KIND_QUANTITY == 0 {
            QuickBooksLegacyBalanceKind::Dollar
        } else {
            QuickBooksLegacyBalanceKind::Quantity
        }
    }

    /// Returns whether the value carries the legacy negative flag.
    #[must_use]
    pub const fn is_negative(self) -> bool {
        self.raw & NEGATIVE != 0
    }

    /// Returns whether the value carries the legacy error flag.
    #[must_use]
    pub const fn is_error(self) -> bool {
        self.raw & ERROR != 0
    }

    /// Returns whether the value carries the legacy percent flag.
    #[must_use]
    pub const fn is_percent(self) -> bool {
        self.raw & PERCENT != 0
    }

    /// Returns whether the value carries the legacy empty flag.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.raw & EMPTY != 0
    }
}

/// A decoded legacy six-byte QuickBooks balance envelope.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct QuickBooksLegacyBalance {
    fraction: u8,
    flags: QuickBooksLegacyBalanceFlags,
    dollars: u32,
}

impl QuickBooksLegacyBalance {
    /// Decodes one `BalTypeLegacy_6Bytes` disk value.
    ///
    /// The disk form is exactly `[cents, flags, dollars_be_u32]`. Dollar
    /// values require `cents <= 99`; quantity values preserve the byte as a
    /// non-monetary fraction because its quantity semantics are not used here.
    pub fn from_disk_bytes(bytes: [u8; 6]) -> Result<Self, QuickBooksLegacyBalanceError> {
        let fraction = bytes[0];
        let flags = QuickBooksLegacyBalanceFlags::from_raw(bytes[1])?;
        if flags.kind() == QuickBooksLegacyBalanceKind::Dollar && fraction > 99 {
            return Err(QuickBooksLegacyBalanceError::InvalidDollarCents { cents: fraction });
        }
        Ok(Self {
            fraction,
            flags,
            dollars: u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
        })
    }

    /// Encodes this balance to the exact six-byte QuickBooks disk form.
    #[must_use]
    pub fn to_disk_bytes(self) -> [u8; 6] {
        let [dollar_3, dollar_2, dollar_1, dollar_0] = self.dollars.to_be_bytes();
        [
            self.fraction,
            self.flags.raw(),
            dollar_3,
            dollar_2,
            dollar_1,
            dollar_0,
        ]
    }

    /// Returns the validated legacy flag representation.
    #[must_use]
    pub const fn flags(self) -> QuickBooksLegacyBalanceFlags {
        self.flags
    }

    /// Returns the whole-dollar component.
    ///
    /// This is a monetary dollar component only when [`Self::kind`] is
    /// [`QuickBooksLegacyBalanceKind::Dollar`].
    #[must_use]
    pub const fn dollars(self) -> u32 {
        self.dollars
    }

    /// Returns the raw second byte component.
    ///
    /// It is cents only for dollar kind. For quantity kind it is preserved
    /// without assigning a monetary interpretation.
    #[must_use]
    pub const fn fraction(self) -> u8 {
        self.fraction
    }

    /// Returns the legacy kind.
    #[must_use]
    pub const fn kind(self) -> QuickBooksLegacyBalanceKind {
        self.flags.kind()
    }

    /// Returns exact signed cents for an eligible monetary dollar value.
    ///
    /// Quantity, error, percent, and empty values are rejected instead of
    /// being coerced to money. A negative-flagged zero is returned as zero;
    /// the original sign flag remains available through [`Self::flags`].
    pub fn signed_cents(self) -> Result<i64, QuickBooksLegacyBalanceError> {
        if self.kind() != QuickBooksLegacyBalanceKind::Dollar {
            return Err(QuickBooksLegacyBalanceError::NotMonetary {
                kind: self.kind(),
                flags: self.flags,
            });
        }
        if self.flags.is_error() || self.flags.is_percent() || self.flags.is_empty() {
            return Err(QuickBooksLegacyBalanceError::NotMonetary {
                kind: self.kind(),
                flags: self.flags,
            });
        }

        let magnitude = i64::from(self.dollars) * 100 + i64::from(self.fraction);
        Ok(if self.flags.is_negative() {
            -magnitude
        } else {
            magnitude
        })
    }
}

/// An invalid or non-monetary legacy QuickBooks balance value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuickBooksLegacyBalanceError {
    /// The flag byte contains bits outside the proven legacy flag mask.
    UnknownFlagBits {
        /// The untrusted raw flag byte.
        flags: u8,
        /// The subset of [`Self::UnknownFlagBits::flags`] not in the known mask.
        unknown_bits: u8,
    },
    /// A dollar-kind value carries a fraction outside `0..=99` cents.
    InvalidDollarCents {
        /// The invalid disk fraction byte.
        cents: u8,
    },
    /// The value is known but cannot safely be represented as money.
    NotMonetary {
        /// The value's validated legacy kind.
        kind: QuickBooksLegacyBalanceKind,
        /// The recognized status flags that prevented monetary interpretation.
        flags: QuickBooksLegacyBalanceFlags,
    },
}

impl fmt::Display for QuickBooksLegacyBalanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFlagBits {
                flags,
                unknown_bits,
            } => write!(
                formatter,
                "QuickBooks legacy balance flags {flags:#04x} contain unknown bits {unknown_bits:#04x}"
            ),
            Self::InvalidDollarCents { cents } => {
                write!(
                    formatter,
                    "QuickBooks legacy dollar cents {cents} exceed 99"
                )
            }
            Self::NotMonetary { kind, flags } => write!(
                formatter,
                "QuickBooks legacy balance is not an eligible monetary dollar value (kind={kind:?}, flags={:#04x})",
                flags.raw()
            ),
        }
    }
}

impl std::error::Error for QuickBooksLegacyBalanceError {}

#[cfg(test)]
mod tests {
    use super::{
        QuickBooksLegacyBalance, QuickBooksLegacyBalanceError, QuickBooksLegacyBalanceKind,
    };

    #[test]
    fn exact_positive_1234_57_disk_vector_round_trips() {
        let balance =
            QuickBooksLegacyBalance::from_disk_bytes([0x39, 0, 0, 0, 0x04, 0xd2]).unwrap();

        assert_eq!(balance.kind(), QuickBooksLegacyBalanceKind::Dollar);
        assert_eq!(balance.dollars(), 1234);
        assert_eq!(balance.fraction(), 57);
        assert_eq!(balance.signed_cents(), Ok(123_457));
        assert_eq!(balance.to_disk_bytes(), [0x39, 0, 0, 0, 0x04, 0xd2]);
    }

    #[test]
    fn exact_negative_1234_57_disk_vector_round_trips() {
        let balance =
            QuickBooksLegacyBalance::from_disk_bytes([0x39, 0x02, 0, 0, 0x04, 0xd2]).unwrap();

        assert!(balance.flags().is_negative());
        assert_eq!(balance.signed_cents(), Ok(-123_457));
        assert_eq!(balance.to_disk_bytes(), [0x39, 0x02, 0, 0, 0x04, 0xd2]);
    }

    #[test]
    fn all_zero_bytes_are_positive_dollar_zero() {
        let zero = QuickBooksLegacyBalance::from_disk_bytes([0; 6]).unwrap();

        assert_eq!(zero.kind(), QuickBooksLegacyBalanceKind::Dollar);
        assert_eq!(zero.signed_cents(), Ok(0));
        assert_eq!(zero.to_disk_bytes(), [0; 6]);
    }

    #[test]
    fn quantity_is_preserved_but_not_interpreted_as_money() {
        let quantity = QuickBooksLegacyBalance::from_disk_bytes([255, 0x01, 0, 0, 0, 5]).unwrap();

        assert_eq!(quantity.kind(), QuickBooksLegacyBalanceKind::Quantity);
        assert_eq!(quantity.fraction(), 255);
        assert!(matches!(
            quantity.signed_cents(),
            Err(QuickBooksLegacyBalanceError::NotMonetary { .. })
        ));
    }

    #[test]
    fn status_bearing_dollars_are_preserved_but_not_money() {
        for flags in [0x04, 0x08, 0x10] {
            let value = QuickBooksLegacyBalance::from_disk_bytes([1, flags, 0, 0, 0, 1]).unwrap();
            assert!(matches!(
                value.signed_cents(),
                Err(QuickBooksLegacyBalanceError::NotMonetary { .. })
            ));
            assert_eq!(value.to_disk_bytes(), [1, flags, 0, 0, 0, 1]);
        }
    }

    #[test]
    fn unknown_bits_and_invalid_dollar_cents_fail_closed() {
        assert_eq!(
            QuickBooksLegacyBalance::from_disk_bytes([0, 0x80, 0, 0, 0, 0]),
            Err(QuickBooksLegacyBalanceError::UnknownFlagBits {
                flags: 0x80,
                unknown_bits: 0x80,
            })
        );
        assert_eq!(
            QuickBooksLegacyBalance::from_disk_bytes([100, 0, 0, 0, 0, 1]),
            Err(QuickBooksLegacyBalanceError::InvalidDollarCents { cents: 100 })
        );
    }
}

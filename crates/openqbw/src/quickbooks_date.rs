//! Fixed-width `DateType32` values used by QuickBooks record dictionaries.
//!
//! This codec is deliberately separate from [`crate::date`], which models SQL
//! Anywhere's day-counter values.  A QuickBooks `DateType32` is a four-byte
//! calendar-date value on disk in this exact order:
//!
//! ```text
//! [year high byte, year low byte, month, day]
//! ```
//!
//! The all-zero byte sequence is the QuickBooks null/default date.  All other
//! values are validated as Gregorian calendar dates; malformed values are
//! rejected rather than normalized or guessed.

use core::fmt;

/// A validated, timezone-free Gregorian date from a QuickBooks `DateType32`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QuickBooksDate {
    year: u16,
    month: u8,
    day: u8,
}

impl QuickBooksDate {
    /// Creates a validated Gregorian calendar date.
    ///
    /// Year zero is rejected because it is reserved for the all-zero
    /// `DateType32` null/default encoding.
    pub fn new(year: u16, month: u8, day: u8) -> Result<Self, QuickBooksDateError> {
        validate_components(year, month, day)?;
        Ok(Self { year, month, day })
    }

    /// Decodes one fixed-width QuickBooks `DateType32` disk value.
    ///
    /// Returns `Ok(None)` only for the all-zero null/default representation.
    /// Every other malformed byte sequence returns an error.
    pub fn from_disk_bytes(bytes: [u8; 4]) -> Result<Option<Self>, QuickBooksDateError> {
        if bytes == [0; 4] {
            return Ok(None);
        }

        let year = u16::from_be_bytes([bytes[0], bytes[1]]);
        Self::new(year, bytes[2], bytes[3]).map(Some)
    }

    /// Encodes this date to the exact four-byte QuickBooks `DateType32` disk form.
    #[must_use]
    pub fn to_disk_bytes(self) -> [u8; 4] {
        let [year_hi, year_lo] = self.year.to_be_bytes();
        [year_hi, year_lo, self.month, self.day]
    }

    /// Returns the Gregorian year.
    #[must_use]
    pub const fn year(self) -> u16 {
        self.year
    }

    /// Returns the Gregorian month in `1..=12`.
    #[must_use]
    pub const fn month(self) -> u8 {
        self.month
    }

    /// Returns the Gregorian day for this year and month.
    #[must_use]
    pub const fn day(self) -> u8 {
        self.day
    }
}

impl fmt::Display for QuickBooksDate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:04}-{:02}-{:02}",
            self.year, self.month, self.day
        )
    }
}

/// An invalid non-null QuickBooks `DateType32` calendar value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuickBooksDateError {
    /// The date has a zero year outside the all-zero null/default encoding.
    ZeroYear,
    /// The month is outside the Gregorian range `1..=12`.
    InvalidMonth {
        /// The invalid value supplied for the month component.
        month: u8,
    },
    /// The day is invalid for the supplied Gregorian year and month.
    InvalidDay {
        /// The validated nonzero year supplied for the date.
        year: u16,
        /// The validated month supplied for the date.
        month: u8,
        /// The invalid day supplied for the date.
        day: u8,
    },
}

impl fmt::Display for QuickBooksDateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroYear => formatter.write_str("QuickBooks DateType32 year must be nonzero"),
            Self::InvalidMonth { month } => {
                write!(
                    formatter,
                    "QuickBooks DateType32 month {month} is outside 1..=12"
                )
            }
            Self::InvalidDay { year, month, day } => write!(
                formatter,
                "QuickBooks DateType32 day {day} is invalid for {year:04}-{month:02}"
            ),
        }
    }
}

impl std::error::Error for QuickBooksDateError {}

fn validate_components(year: u16, month: u8, day: u8) -> Result<(), QuickBooksDateError> {
    if year == 0 {
        return Err(QuickBooksDateError::ZeroYear);
    }
    if !(1..=12).contains(&month) {
        return Err(QuickBooksDateError::InvalidMonth { month });
    }
    if day == 0 || day > days_in_month(year, month) {
        return Err(QuickBooksDateError::InvalidDay { year, month, day });
    }
    Ok(())
}

const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn is_leap_year(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use super::{QuickBooksDate, QuickBooksDateError};

    #[test]
    fn exact_2026_08_19_disk_vector_round_trips() {
        let date = QuickBooksDate::from_disk_bytes([0x07, 0xea, 0x08, 0x13])
            .unwrap()
            .unwrap();

        assert_eq!(date.year(), 2026);
        assert_eq!(date.month(), 8);
        assert_eq!(date.day(), 19);
        assert_eq!(date.to_string(), "2026-08-19");
        assert_eq!(date.to_disk_bytes(), [0x07, 0xea, 0x08, 0x13]);
    }

    #[test]
    fn leap_day_is_accepted_only_in_leap_years() {
        let leap_day = QuickBooksDate::new(2024, 2, 29).unwrap();
        assert_eq!(leap_day.to_disk_bytes(), [0x07, 0xe8, 0x02, 0x1d]);

        assert_eq!(
            QuickBooksDate::from_disk_bytes([0x07, 0xe9, 0x02, 0x1d]),
            Err(QuickBooksDateError::InvalidDay {
                year: 2025,
                month: 2,
                day: 29,
            })
        );
    }

    #[test]
    fn all_zero_bytes_are_the_only_null_default_date() {
        assert_eq!(QuickBooksDate::from_disk_bytes([0; 4]), Ok(None));
        assert_eq!(
            QuickBooksDate::new(0, 1, 1),
            Err(QuickBooksDateError::ZeroYear)
        );
        assert_eq!(
            QuickBooksDate::from_disk_bytes([0, 0, 1, 1]),
            Err(QuickBooksDateError::ZeroYear)
        );
    }

    #[test]
    fn invalid_calendar_components_fail_closed() {
        assert_eq!(
            QuickBooksDate::from_disk_bytes([0x07, 0xea, 13, 1]),
            Err(QuickBooksDateError::InvalidMonth { month: 13 })
        );
        assert_eq!(
            QuickBooksDate::from_disk_bytes([0x07, 0xea, 4, 31]),
            Err(QuickBooksDateError::InvalidDay {
                year: 2026,
                month: 4,
                day: 31,
            })
        );
    }
}

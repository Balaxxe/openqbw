//! Strict calendar-date codec for materialized SQL Anywhere posting rows.
//!
//! This is intentionally distinct from both [`crate::date`] (the legacy
//! SA-day counter) and [`crate::QuickBooksDate`] (QuickBooks `DateType32`).
//! The controlled materialized posting rows carry a little-endian signed
//! 32-bit count of minutes from SQL Anywhere's 1600-02-29 epoch.  QuickBooks
//! posting dates observed in those rows are midnight values, so this codec
//! rejects a non-midnight value rather than silently discarding its time part.

use std::fmt;

use opensqlany::SaDate;
use thiserror::Error;

use crate::AccountingDate;

/// Minutes in one calendar day.
pub const MATERIALIZED_POSTING_MINUTES_PER_DAY: i32 = 1_440;

/// A validated, timezone-free calendar date from a materialized posting row.
///
/// The raw representation is a signed SQL Anywhere minute count.  Its
/// [`AccountingDate`] is the whole-day count from the same epoch and can be
/// compared directly with other values of this type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct MaterializedPostingDate {
    raw_minutes: i32,
    accounting_date: AccountingDate,
    year: i32,
    month: u8,
    day: u8,
}

impl MaterializedPostingDate {
    /// Decodes the exact little-endian signed four-byte on-disk value.
    pub fn from_disk_bytes(bytes: [u8; 4]) -> Result<Self, MaterializedPostingDateError> {
        Self::from_raw_minutes(i32::from_le_bytes(bytes))
    }

    /// Decodes an API value that preserves the four on-disk date bytes as
    /// unsigned bits.
    ///
    /// Physical row parsers often retain fixed-width fields as `u32` so they
    /// can expose the exact bytes without assigning semantics. This method
    /// performs the required two's-complement reinterpretation explicitly;
    /// callers must not numerically cast the value to `i32`.
    pub fn from_raw_bits(raw_bits: u32) -> Result<Self, MaterializedPostingDateError> {
        Self::from_disk_bytes(raw_bits.to_le_bytes())
    }

    /// Creates a date from the signed SQL Anywhere minute count.
    ///
    /// Non-midnight values are rejected.  Materialized posting fields are
    /// business-date fields, and accepting a remainder would silently change
    /// an as-of result when a future format uses a true timestamp instead.
    pub fn from_raw_minutes(raw_minutes: i32) -> Result<Self, MaterializedPostingDateError> {
        let remainder = raw_minutes.rem_euclid(MATERIALIZED_POSTING_MINUTES_PER_DAY);
        if remainder != 0 {
            return Err(MaterializedPostingDateError::NonMidnightMinuteCount {
                raw_minutes,
                remainder_minutes: remainder,
            });
        }

        let sa_date = SaDate { raw_minutes };
        let (year, month, day) = sa_date.ymd();
        validate_ymd(year, month, day)?;
        let accounting_date = sa_date.days_since_sa_epoch();
        if days_since_sa_epoch(year, month, day)? != i64::from(accounting_date) {
            return Err(MaterializedPostingDateError::CalendarRoundTripMismatch { raw_minutes });
        }

        Ok(Self {
            raw_minutes,
            accounting_date,
            year,
            month,
            day,
        })
    }

    /// Creates a date from validated Gregorian components at midnight.
    pub fn from_ymd(year: i32, month: u8, day: u8) -> Result<Self, MaterializedPostingDateError> {
        let days = days_since_sa_epoch(year, month, day)?;
        let raw_minutes = days
            .checked_mul(i64::from(MATERIALIZED_POSTING_MINUTES_PER_DAY))
            .ok_or(MaterializedPostingDateError::MinuteCountOutOfRange { year, month, day })?;
        let raw_minutes = i32::try_from(raw_minutes).map_err(|_| {
            MaterializedPostingDateError::MinuteCountOutOfRange { year, month, day }
        })?;
        Self::from_raw_minutes(raw_minutes)
    }

    /// Parses a strict `YYYY-MM-DD` ISO calendar date for an as-of boundary.
    ///
    /// The interface intentionally accepts only years `0001` through `9999`:
    /// that is the unambiguous ISO shape suitable for a user-facing CLI.
    pub fn parse_iso_date(value: &str) -> Result<Self, MaterializedPostingDateError> {
        let bytes = value.as_bytes();
        if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
            return Err(MaterializedPostingDateError::InvalidIsoDateFormat);
        }
        let year = parse_ascii_digits(&bytes[0..4])
            .ok_or(MaterializedPostingDateError::InvalidIsoDateFormat)?;
        let month = parse_ascii_digits(&bytes[5..7])
            .ok_or(MaterializedPostingDateError::InvalidIsoDateFormat)?;
        let day = parse_ascii_digits(&bytes[8..10])
            .ok_or(MaterializedPostingDateError::InvalidIsoDateFormat)?;
        if year == 0 {
            return Err(MaterializedPostingDateError::InvalidIsoDateFormat);
        }
        Self::from_ymd(
            i32::try_from(year).expect("four ASCII digits fit i32"),
            u8::try_from(month).expect("two ASCII digits fit u8"),
            u8::try_from(day).expect("two ASCII digits fit u8"),
        )
    }

    /// Returns the exact signed minute count from the materialized row.
    #[must_use]
    pub const fn raw_minutes(self) -> i32 {
        self.raw_minutes
    }

    /// Returns the exact four source bytes represented as a little-endian
    /// unsigned bit pattern.
    #[must_use]
    pub const fn raw_bits(self) -> u32 {
        u32::from_le_bytes(self.raw_minutes.to_le_bytes())
    }

    /// Returns the monotonic day count for normalized accounting reports.
    #[must_use]
    pub const fn accounting_date(self) -> AccountingDate {
        self.accounting_date
    }

    /// Returns the validated proleptic-Gregorian `(year, month, day)` tuple.
    #[must_use]
    pub const fn ymd(self) -> (i32, u8, u8) {
        (self.year, self.month, self.day)
    }

    /// Renders the calendar date as `YYYY-MM-DD`.
    #[must_use]
    pub fn to_iso_date(self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

impl fmt::Display for MaterializedPostingDate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_iso_date())
    }
}

/// A malformed or unsupported materialized posting date.
#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum MaterializedPostingDateError {
    /// The minute count encodes a time of day rather than a business date.
    #[error(
        "materialized posting minute count {raw_minutes} has non-midnight remainder {remainder_minutes}"
    )]
    NonMidnightMinuteCount {
        /// Original signed minute count.
        raw_minutes: i32,
        /// Positive Euclidean remainder in minutes after midnight.
        remainder_minutes: i32,
    },
    /// The Gregorian components are not a valid calendar date.
    #[error("invalid Gregorian date {year:04}-{month:02}-{day:02}")]
    InvalidCalendarDate {
        /// Gregorian year.
        year: i32,
        /// Gregorian month.
        month: u8,
        /// Gregorian day.
        day: u8,
    },
    /// A valid date cannot be represented by the signed 32-bit minute field.
    #[error(
        "Gregorian date {year:04}-{month:02}-{day:02} is outside the signed SQL Anywhere minute range"
    )]
    MinuteCountOutOfRange {
        /// Gregorian year.
        year: i32,
        /// Gregorian month.
        month: u8,
        /// Gregorian day.
        day: u8,
    },
    /// The source and calendar conversion did not round trip exactly.
    #[error(
        "materialized posting minute count {raw_minutes} did not round trip through its calendar date"
    )]
    CalendarRoundTripMismatch {
        /// Original signed minute count.
        raw_minutes: i32,
    },
    /// The supplied as-of date is not in strict `YYYY-MM-DD` form.
    #[error("ISO date must use strict YYYY-MM-DD form with a year in 0001..=9999")]
    InvalidIsoDateFormat,
}

fn parse_ascii_digits(input: &[u8]) -> Option<u32> {
    input.iter().try_fold(0_u32, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + u32::from(*byte - b'0'))
    })
}

fn validate_ymd(year: i32, month: u8, day: u8) -> Result<(), MaterializedPostingDateError> {
    let valid = (1..=12).contains(&month) && day >= 1 && day <= days_in_month(year, month);
    valid
        .then_some(())
        .ok_or(MaterializedPostingDateError::InvalidCalendarDate { year, month, day })
}

fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

/// Inverse of `SaDate::ymd`, returning whole days from 1600-02-29.
fn days_since_sa_epoch(year: i32, month: u8, day: u8) -> Result<i64, MaterializedPostingDateError> {
    validate_ymd(year, month, day)?;
    let year = i64::from(year) - if month <= 2 { 1 } else { 0 };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    // `days_from_civil` gives days since 1970-01-01.  SA minute day zero,
    // 1600-02-29, is 135_081 days before that Unix epoch.
    Ok(era * 146_097 + day_of_era - 719_468 + 135_081)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_leap_day_round_trip() {
        let epoch = MaterializedPostingDate::from_raw_minutes(0).unwrap();
        assert_eq!(epoch.ymd(), (1600, 2, 29));
        assert_eq!(epoch.accounting_date(), 0);
        assert_eq!(epoch.to_iso_date(), "1600-02-29");

        let leap = MaterializedPostingDate::from_ymd(2000, 2, 29).unwrap();
        assert_eq!(
            MaterializedPostingDate::from_raw_minutes(leap.raw_minutes()).unwrap(),
            leap
        );
    }

    #[test]
    fn disk_encoding_and_iso_as_of_round_trip() {
        let date = MaterializedPostingDate::parse_iso_date("2024-03-01").unwrap();
        assert_eq!(date.ymd(), (2024, 3, 1));
        assert_eq!(
            MaterializedPostingDate::from_disk_bytes(date.raw_minutes().to_le_bytes()).unwrap(),
            date
        );
        assert_eq!(
            MaterializedPostingDate::from_raw_bits(date.raw_bits()).unwrap(),
            date
        );
    }

    #[test]
    fn unix_epoch_is_a_generic_calendar_vector() {
        let date = MaterializedPostingDate::from_ymd(1970, 1, 1).unwrap();
        assert_eq!(date.accounting_date(), 135_081);
        assert_eq!(date.raw_minutes(), 194_516_640);
        assert_eq!(date.ymd(), (1970, 1, 1));
    }

    #[test]
    fn leap_and_invalid_calendar_dates_are_checked() {
        assert!(MaterializedPostingDate::from_ymd(2024, 2, 29).is_ok());
        assert!(matches!(
            MaterializedPostingDate::from_ymd(2023, 2, 29),
            Err(MaterializedPostingDateError::InvalidCalendarDate { .. })
        ));
        assert!(MaterializedPostingDate::parse_iso_date("2023-02-29").is_err());
        assert!(MaterializedPostingDate::parse_iso_date("2024-2-29").is_err());
        assert!(MaterializedPostingDate::parse_iso_date("0000-01-01").is_err());
    }

    #[test]
    fn non_midnight_and_negative_non_midnight_are_rejected() {
        assert!(matches!(
            MaterializedPostingDate::from_raw_minutes(1),
            Err(MaterializedPostingDateError::NonMidnightMinuteCount {
                remainder_minutes: 1,
                ..
            })
        ));
        assert!(matches!(
            MaterializedPostingDate::from_raw_minutes(-1),
            Err(MaterializedPostingDateError::NonMidnightMinuteCount {
                remainder_minutes: 1439,
                ..
            })
        ));
    }

    #[test]
    fn unrepresentable_cli_date_is_rejected() {
        assert!(matches!(
            MaterializedPostingDate::from_ymd(9999, 12, 31),
            Err(MaterializedPostingDateError::MinuteCountOutOfRange { .. })
        ));
    }
}

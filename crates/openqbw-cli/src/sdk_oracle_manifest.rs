//! Privacy-preserving parser for the disposable SDK-oracle manifest.
//!
//! This module exists only to record reproducibility evidence from the
//! controlled, read-only research harness. It is not part of the production
//! QBW decoder and does not parse QBXML account or journal content. In
//! particular, the manifest's company path is required for shape validation
//! but is deliberately discarded and is never exposed in this API or errors.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

/// Non-sensitive reproducibility facts retained from a read-only SDK oracle.
///
/// The original company path and all QBXML payload contents are intentionally
/// excluded. The SHA-256 digests identify the artifacts without embedding
/// their business content in logs or downstream data structures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdkOracleManifest {
    /// QBXML protocol version reported by the controlled harness.
    pub qbxml_version: String,
    /// Count of account records in the opaque account artifact.
    pub account_count: u64,
    /// Count of journal-entry records in the opaque journal artifact.
    pub journal_entry_count: u64,
    /// Count of journal-line records in the opaque journal artifact.
    pub journal_line_count: u64,
    /// Lowercase SHA-256 digest of the account artifact.
    pub accounts_sha256: String,
    /// Lowercase SHA-256 digest of the journal artifact.
    pub journal_sha256: String,
}

/// Parse the JSON manifest emitted by the controlled read-only SDK harness.
///
/// The parser accepts only the current flat scalar schema. It requires a
/// `company_file` string and `read_only: true` as provenance assertions, then
/// discards the path immediately. Unknown, duplicate, missing, and nested
/// fields are rejected so a future harness format cannot silently change the
/// meaning of the retained counts or digests.
pub fn parse_sdk_oracle_manifest(input: &[u8]) -> Result<SdkOracleManifest, OracleManifestError> {
    let fields = parse_flat_object(input)?;
    const EXPECTED: [&str; 8] = [
        "company_file",
        "read_only",
        "qbxml_version",
        "account_count",
        "journal_entry_count",
        "journal_line_count",
        "accounts_sha256",
        "journal_sha256",
    ];
    if fields.len() != EXPECTED.len() || fields.keys().any(|key| !EXPECTED.contains(&key.as_str()))
    {
        return Err(OracleManifestError::UnexpectedSchema);
    }

    let company_file = string_field(&fields, "company_file")?;
    if company_file.is_empty() {
        return Err(OracleManifestError::InvalidField("company_file"));
    }
    // Do not retain this potentially sensitive value.
    drop(company_file);

    match fields.get("read_only") {
        Some(Scalar::Bool(true)) => {}
        _ => return Err(OracleManifestError::ReadOnlyRequired),
    }

    let qbxml_version = string_field(&fields, "qbxml_version")?;
    if qbxml_version.is_empty() {
        return Err(OracleManifestError::InvalidField("qbxml_version"));
    }
    let accounts_sha256 = sha256_field(&fields, "accounts_sha256")?;
    let journal_sha256 = sha256_field(&fields, "journal_sha256")?;

    Ok(SdkOracleManifest {
        qbxml_version,
        account_count: unsigned_field(&fields, "account_count")?,
        journal_entry_count: unsigned_field(&fields, "journal_entry_count")?,
        journal_line_count: unsigned_field(&fields, "journal_line_count")?,
        accounts_sha256,
        journal_sha256,
    })
}

/// Return the lowercase SHA-256 digest of bytes held by the local harness.
///
/// This small implementation avoids adding a network-fetched dependency to
/// the research CLI. It is used only to compare local artifacts to the
/// manifest; neither input bytes nor digest preimages are logged.
pub fn sha256_hex(input: &[u8]) -> String {
    const INITIAL: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while !(padded.len() + 8).is_multiple_of(64) {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut h = INITIAL;
    for block in padded.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, word) in words[..16].iter_mut().enumerate() {
            *word = u32::from_be_bytes(block[index * 4..index * 4 + 4].try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let mut state = h;
        for (index, constant) in K.iter().enumerate() {
            let s1 =
                state[4].rotate_right(6) ^ state[4].rotate_right(11) ^ state[4].rotate_right(25);
            let choice = (state[4] & state[5]) ^ ((!state[4]) & state[6]);
            let temp1 = state[7]
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(*constant)
                .wrapping_add(words[index]);
            let s0 =
                state[0].rotate_right(2) ^ state[0].rotate_right(13) ^ state[0].rotate_right(22);
            let majority = (state[0] & state[1]) ^ (state[0] & state[2]) ^ (state[1] & state[2]);
            let temp2 = s0.wrapping_add(majority);
            state = [
                temp1.wrapping_add(temp2),
                state[0],
                state[1],
                state[2],
                state[3].wrapping_add(temp1),
                state[4],
                state[5],
                state[6],
            ];
        }
        for (digest_word, state_word) in h.iter_mut().zip(state) {
            *digest_word = digest_word.wrapping_add(state_word);
        }
    }
    let mut output = String::with_capacity(64);
    for word in h {
        use std::fmt::Write;
        write!(output, "{word:08x}").expect("writing to a String cannot fail");
    }
    output
}

fn string_field(
    fields: &BTreeMap<String, Scalar>,
    name: &'static str,
) -> Result<String, OracleManifestError> {
    match fields.get(name) {
        Some(Scalar::String(value)) => Ok(value.clone()),
        Some(_) => Err(OracleManifestError::InvalidField(name)),
        None => Err(OracleManifestError::MissingField(name)),
    }
}

fn unsigned_field(
    fields: &BTreeMap<String, Scalar>,
    name: &'static str,
) -> Result<u64, OracleManifestError> {
    match fields.get(name) {
        Some(Scalar::Unsigned(value)) => Ok(*value),
        Some(_) => Err(OracleManifestError::InvalidField(name)),
        None => Err(OracleManifestError::MissingField(name)),
    }
}

fn sha256_field(
    fields: &BTreeMap<String, Scalar>,
    name: &'static str,
) -> Result<String, OracleManifestError> {
    let value = string_field(fields, name)?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(OracleManifestError::InvalidField(name));
    }
    Ok(value.to_ascii_lowercase())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Scalar {
    String(String),
    Bool(bool),
    Unsigned(u64),
}

fn parse_flat_object(input: &[u8]) -> Result<BTreeMap<String, Scalar>, OracleManifestError> {
    let mut parser = JsonParser { input, cursor: 0 };
    parser.skip_whitespace();
    parser.expect(b'{')?;
    parser.skip_whitespace();
    let mut fields = BTreeMap::new();
    if parser.consume(b'}') {
        parser.ensure_end()?;
        return Ok(fields);
    }

    loop {
        parser.skip_whitespace();
        let key = parser.string()?;
        parser.skip_whitespace();
        parser.expect(b':')?;
        parser.skip_whitespace();
        let value = parser.scalar()?;
        if fields.insert(key.clone(), value).is_some() {
            return Err(OracleManifestError::DuplicateField);
        }
        parser.skip_whitespace();
        if parser.consume(b'}') {
            parser.ensure_end()?;
            return Ok(fields);
        }
        parser.expect(b',')?;
    }
}

struct JsonParser<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl JsonParser<'_> {
    fn skip_whitespace(&mut self) {
        while self
            .input
            .get(self.cursor)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            self.cursor += 1;
        }
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.input.get(self.cursor) == Some(&byte) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), OracleManifestError> {
        if self.consume(byte) {
            Ok(())
        } else {
            Err(OracleManifestError::InvalidJson)
        }
    }

    fn string(&mut self) -> Result<String, OracleManifestError> {
        self.expect(b'"')?;
        let mut result = String::new();
        loop {
            let byte = *self
                .input
                .get(self.cursor)
                .ok_or(OracleManifestError::InvalidJson)?;
            self.cursor += 1;
            match byte {
                b'"' => return Ok(result),
                b'\\' => result.push(self.escape()?),
                0..=0x1f => return Err(OracleManifestError::InvalidJson),
                0x20..=0x7f => result.push(byte as char),
                _ => {
                    let start = self.cursor - 1;
                    let width = utf8_width(byte).ok_or(OracleManifestError::InvalidJson)?;
                    let end = start
                        .checked_add(width)
                        .ok_or(OracleManifestError::InvalidJson)?;
                    let text = std::str::from_utf8(
                        self.input
                            .get(start..end)
                            .ok_or(OracleManifestError::InvalidJson)?,
                    )
                    .map_err(|_| OracleManifestError::InvalidJson)?;
                    result.push_str(text);
                    self.cursor = end;
                }
            }
        }
    }

    fn escape(&mut self) -> Result<char, OracleManifestError> {
        let byte = *self
            .input
            .get(self.cursor)
            .ok_or(OracleManifestError::InvalidJson)?;
        self.cursor += 1;
        match byte {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'/' => Ok('/'),
            b'b' => Ok('\u{0008}'),
            b'f' => Ok('\u{000c}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => self.unicode_escape(),
            _ => Err(OracleManifestError::InvalidJson),
        }
    }

    fn unicode_escape(&mut self) -> Result<char, OracleManifestError> {
        let hex = self
            .input
            .get(self.cursor..self.cursor + 4)
            .ok_or(OracleManifestError::InvalidJson)?;
        self.cursor += 4;
        let text = std::str::from_utf8(hex).map_err(|_| OracleManifestError::InvalidJson)?;
        let code = u16::from_str_radix(text, 16).map_err(|_| OracleManifestError::InvalidJson)?;
        // The harness emits paths/counts/hashes only; rejecting surrogate
        // pairs keeps this deliberately narrow parser unambiguous.
        char::from_u32(u32::from(code)).ok_or(OracleManifestError::InvalidJson)
    }

    fn scalar(&mut self) -> Result<Scalar, OracleManifestError> {
        match self.input.get(self.cursor) {
            Some(b'"') => self.string().map(Scalar::String),
            Some(b't') if self.take_literal(b"true") => Ok(Scalar::Bool(true)),
            Some(b'f') if self.take_literal(b"false") => Ok(Scalar::Bool(false)),
            Some(b'0'..=b'9') => self.unsigned().map(Scalar::Unsigned),
            _ => Err(OracleManifestError::InvalidJson),
        }
    }

    fn take_literal(&mut self, literal: &[u8]) -> bool {
        if self.input.get(self.cursor..self.cursor + literal.len()) == Some(literal) {
            self.cursor += literal.len();
            true
        } else {
            false
        }
    }

    fn unsigned(&mut self) -> Result<u64, OracleManifestError> {
        let start = self.cursor;
        while self
            .input
            .get(self.cursor)
            .is_some_and(|byte| byte.is_ascii_digit())
        {
            self.cursor += 1;
        }
        if self.cursor - start > 1 && self.input[start] == b'0' {
            return Err(OracleManifestError::InvalidJson);
        }
        std::str::from_utf8(&self.input[start..self.cursor])
            .map_err(|_| OracleManifestError::InvalidJson)?
            .parse()
            .map_err(|_| OracleManifestError::InvalidJson)
    }

    fn ensure_end(&mut self) -> Result<(), OracleManifestError> {
        self.skip_whitespace();
        if self.cursor == self.input.len() {
            Ok(())
        } else {
            Err(OracleManifestError::InvalidJson)
        }
    }
}

fn utf8_width(first: u8) -> Option<usize> {
    match first {
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

/// Errors are intentionally value-free: callers can log them without leaking
/// a company path, account data, or XML content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleManifestError {
    /// The input was not the small JSON shape emitted by the harness.
    InvalidJson,
    /// The current manifest shape changed or contains unknown fields.
    UnexpectedSchema,
    /// A required field was absent.
    MissingField(&'static str),
    /// A field occurred more than once.
    DuplicateField,
    /// A recognized field had the wrong type or invalid metadata form.
    InvalidField(&'static str),
    /// The harness did not attest to read-only mode.
    ReadOnlyRequired,
}

impl fmt::Display for OracleManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson => f.write_str("invalid SDK oracle manifest JSON"),
            Self::UnexpectedSchema => f.write_str("unexpected SDK oracle manifest schema"),
            Self::MissingField(name) => write!(f, "SDK oracle manifest missing {name}"),
            Self::DuplicateField => f.write_str("SDK oracle manifest contains a duplicate field"),
            Self::InvalidField(name) => write!(f, "SDK oracle manifest has invalid {name}"),
            Self::ReadOnlyRequired => {
                f.write_str("SDK oracle manifest does not attest read-only mode")
            }
        }
    }
}

impl Error for OracleManifestError {}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    fn manifest(extra: &str) -> String {
        format!(
            r#"{{"company_file":"C:\\masked\\fixture.qbw","read_only":true,"qbxml_version":"16.0","account_count":3,"journal_entry_count":2,"journal_line_count":4,"accounts_sha256":"{DIGEST_A}","journal_sha256":"{DIGEST_B}"{extra}}}"#
        )
    }

    #[test]
    fn parses_manifest_and_drops_company_path() {
        let input = manifest("");
        let parsed = parse_sdk_oracle_manifest(input.as_bytes()).unwrap();
        assert_eq!(parsed.qbxml_version, "16.0");
        assert_eq!(parsed.account_count, 3);
        assert_eq!(parsed.journal_entry_count, 2);
        assert_eq!(parsed.journal_line_count, 4);
        assert_eq!(parsed.accounts_sha256, DIGEST_A);
        assert_eq!(parsed.journal_sha256, DIGEST_B.to_ascii_lowercase());
        assert!(!format!("{parsed:?}").contains("fixture.qbw"));
    }

    #[test]
    fn rejects_non_read_only_manifest_without_echoing_path() {
        let input = manifest("").replace("\"read_only\":true", "\"read_only\":false");
        let error = parse_sdk_oracle_manifest(input.as_bytes()).unwrap_err();
        assert_eq!(error, OracleManifestError::ReadOnlyRequired);
        assert!(!error.to_string().contains("fixture.qbw"));
    }

    #[test]
    fn rejects_unknown_duplicate_and_bad_digest_fields() {
        let unknown = manifest(",\"future_field\":1");
        assert_eq!(
            parse_sdk_oracle_manifest(unknown.as_bytes()),
            Err(OracleManifestError::UnexpectedSchema)
        );
        let duplicate = manifest("").replace(
            "\"journal_sha256\"",
            "\"account_count\":1,\"journal_sha256\"",
        );
        assert_eq!(
            parse_sdk_oracle_manifest(duplicate.as_bytes()),
            Err(OracleManifestError::DuplicateField)
        );
        let bad_digest = manifest("").replace(DIGEST_A, "not-a-digest");
        assert_eq!(
            parse_sdk_oracle_manifest(bad_digest.as_bytes()),
            Err(OracleManifestError::InvalidField("accounts_sha256"))
        );
    }

    #[test]
    fn sha256_matches_standard_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

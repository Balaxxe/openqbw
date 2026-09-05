//! Raw QuickBooks Enterprise 24 page-to-type-4 materialization.
//!
//! The file reader supplies one immutable 4096-byte physical page. This
//! module recovers the page-local permutation key from the known physical page
//! number, applies the bounded SQL Anywhere sector primitive, performs the
//! observed header/trailer relocation, and accepts the result only when one
//! distinct candidate satisfies the complete materialized type-4 contract.
//!
//! The key direction and magnitude's high word are learned from independent
//! type-4 pages. Callers reuse that context for sparse pages. A broader context
//! can retain two adjacent high words only as candidates; the accounting
//! layer must independently attest its catalog, coverage, and unique ledger.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

use opensqlany::{
    MATERIALIZED_TABLE_PAGE_LEN, MaterializedTablePage, PagePermutationError, PageStore,
    permute_sector_in_place,
};
use thiserror::Error;

const SECTOR_LEN: usize = 512;
const SECTOR_COUNT: usize = MATERIALIZED_TABLE_PAGE_LEN / SECTOR_LEN;
const FINAL_SECTOR_TAIL: usize = 16;
const MIN_DECISIVE_KEY_WITNESSES: usize = 3;

/// A file-wide Enterprise sector-transform key context.
///
/// The low two bytes vary by physical page and are recovered from its known
/// page key. Direction and high-word candidates come from table-page witnesses;
/// structural discovery alone is not sufficient to select an accounting key.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EnterprisePageTransformKey {
    high_word: u16,
    negative: bool,
    adjacent_high_word: bool,
    decisive_witness_count: usize,
}

impl EnterprisePageTransformKey {
    /// Construct a context already established by a trusted discovery pass.
    pub const fn from_high_word(high_word: u16) -> Self {
        Self {
            high_word,
            negative: false,
            adjacent_high_word: false,
            decisive_witness_count: 0,
        }
    }

    /// Construct an independently established negative-key context.
    /// The high word belongs to the key magnitude, not its two's complement.
    pub const fn from_negative_high_word(high_word: u16) -> Self {
        Self {
            high_word,
            negative: true,
            adjacent_high_word: false,
            decisive_witness_count: 0,
        }
    }

    /// Whether the recovered sector transformation uses a negative key.
    pub const fn is_negative(self) -> bool {
        self.negative
    }

    /// Retain both parity variants of this high word as candidates only.
    /// Callers must independently attest the catalog and complete accounting
    /// coverage before using this broader context to produce any output.
    pub const fn with_adjacent_high_word(self) -> Self {
        Self {
            high_word: self.high_word & !1,
            adjacent_high_word: true,
            ..self
        }
    }

    /// The stable high word of the sector-transform key magnitude.
    pub const fn high_word(self) -> u16 {
        self.high_word
    }

    /// Number of decisive physical-page witnesses used to discover this key.
    ///
    /// A manually constructed context has zero witnesses because its evidence
    /// lives outside this value.
    pub const fn decisive_witness_count(self) -> usize {
        self.decisive_witness_count
    }
}

/// One owned, completely validated materialized type-4 page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterpriseMaterializedTablePage {
    bytes: [u8; MATERIALIZED_TABLE_PAGE_LEN],
}

impl EnterpriseMaterializedTablePage {
    /// Exact 4096-byte materialized representation.
    pub const fn bytes(&self) -> &[u8; MATERIALIZED_TABLE_PAGE_LEN] {
        &self.bytes
    }

    /// Parse the already-validated materialized table-page view.
    pub fn table_page(&self) -> MaterializedTablePage<'_> {
        MaterializedTablePage::parse(&self.bytes)
            .expect("EnterpriseMaterializedTablePage is validated at construction")
    }
}

/// Materialize one raw Enterprise 24 physical page as a checked type-4 page.
///
/// Recovery is deliberately fail-closed. A raw page is accepted only when its
/// known page number yields exactly one sector-0 key candidate and exactly one
/// distinct full-page candidate passes the materialized directory/segment
/// parser with the same key at offset zero.
pub fn materialize_enterprise_table_page(
    raw_page: &[u8],
    page_number: u64,
) -> Result<EnterpriseMaterializedTablePage, EnterprisePageMaterializationError> {
    let page_key = checked_page_key(raw_page, page_number)?;
    let header = exactly_one_header_transform(raw_page, page_key)?;
    materialize_with_signed_keys(raw_page, page_key, signed_key_candidates(header))
}

/// Materialize one raw Enterprise 24 page using a file-wide key context.
///
/// Unlike [`materialize_enterprise_table_page`], this does not have to infer a
/// high word from the page itself.  It still requires exactly one distinct
/// fully-valid type-4 representation, so an incorrect or mismatched context
/// cannot silently produce a page.
pub fn materialize_enterprise_table_page_with_key(
    raw_page: &[u8],
    page_number: u64,
    transform_key: EnterprisePageTransformKey,
) -> Result<EnterpriseMaterializedTablePage, EnterprisePageMaterializationError> {
    let page_key = checked_page_key(raw_page, page_number)?;
    let header = exactly_one_header_transform(raw_page, page_key)?;
    materialize_with_signed_keys(
        raw_page,
        page_key,
        signed_key_candidates_for_context(header, transform_key),
    )
}

/// Materialize every distinct, fully validated type-4 candidate for a keyed page.
///
/// This function never selects between candidates. It is intended for a
/// table-specific decoder that has independent, complete evidence to reject
/// all but one candidate (for example, an exact row grammar and balancing
/// invariant). A matching table ID alone is not sufficient evidence.
///
/// Unlike the singular materializer, this candidate-preserving form retains
/// every bounded page that survives *all* header transforms compatible with
/// the physical page key under the supplied file-wide context. A header may
/// be ambiguous, so callers must not assume a fixed maximum candidate count.
pub fn materialize_enterprise_table_page_candidates_with_key(
    raw_page: &[u8],
    page_number: u64,
    transform_key: EnterprisePageTransformKey,
) -> Result<Vec<EnterpriseMaterializedTablePage>, EnterprisePageMaterializationError> {
    let page_key = checked_page_key(raw_page, page_number)?;
    let headers = recover_header_candidates(&raw_page[..SECTOR_LEN], page_key);
    if headers.is_empty() {
        return Err(EnterprisePageMaterializationError::NoHeaderCandidate);
    }
    materialized_pages_with_signed_keys(
        raw_page,
        page_key,
        headers
            .into_iter()
            .flat_map(|header| signed_key_candidates_for_context(header, transform_key)),
    )
}

/// Resolve bounded page candidates using an independently evidenced decoder.
///
/// A decoder is run for every candidate. Resolution succeeds when exactly one
/// candidate decodes, or when every successful decode produces an equal typed
/// value. If no candidate decodes or successful decodes disagree, no choice is
/// made. Callers must not use a table ID alone as their decoder predicate.
pub fn resolve_enterprise_table_page_candidates<T, E, F>(
    candidates: &[EnterpriseMaterializedTablePage],
    mut decode: F,
) -> Result<T, EnterpriseCandidateResolutionError>
where
    T: Eq,
    F: FnMut(&EnterpriseMaterializedTablePage) -> Result<T, E>,
{
    let mut selected = None;
    let mut decoded_count = 0_usize;
    for candidate in candidates {
        let Ok(value) = decode(candidate) else {
            continue;
        };
        decoded_count += 1;
        if let Some(existing) = &selected {
            if existing != &value {
                return Err(
                    EnterpriseCandidateResolutionError::DivergentDecodedCandidates {
                        decoded_count,
                    },
                );
            }
        } else {
            selected = Some(value);
        }
    }
    selected.ok_or(EnterpriseCandidateResolutionError::NoCandidateDecoded {
        candidate_count: candidates.len(),
    })
}

/// Failure to resolve structurally valid materialized-page candidates.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EnterpriseCandidateResolutionError {
    /// The supplied family decoder rejected every candidate.
    #[error("the family decoder rejected all {candidate_count} materialized-page candidates")]
    NoCandidateDecoded {
        /// Number of candidates presented to the decoder.
        candidate_count: usize,
    },
    /// More than one candidate decoded, but their typed results disagreed.
    #[error("{decoded_count} materialized-page candidates decoded to distinct values")]
    DivergentDecodedCandidates {
        /// Number of successful decodes observed before disagreement.
        decoded_count: usize,
    },
}

/// Learn a file-wide transform-key context from raw physical pages.
///
/// The input may include every kind of page in a QBW file: non-type-4 pages
/// and non-decisive table pages are ignored.  At least three distinct physical
/// type-4 witnesses must each identify one and the same high word.  Conflicting
/// witnesses and an insufficient sample fail closed.
pub fn discover_enterprise_page_transform_key<'a, I>(
    raw_pages: I,
) -> Result<EnterprisePageTransformKey, EnterprisePageMaterializationError>
where
    I: IntoIterator<Item = (u64, &'a [u8])>,
{
    let mut witnesses = BTreeSet::new();
    let mut high_words = BTreeSet::new();

    for (page_number, raw_page) in raw_pages {
        let page_key = checked_page_key(raw_page, page_number)?;
        let header_candidates = recover_header_candidates(&raw_page[..SECTOR_LEN], page_key);
        if header_candidates.len() != 1 {
            continue;
        }
        let header = header_candidates[0];
        let candidate_high_words = valid_key_contexts(raw_page, page_key, header)?;
        if candidate_high_words.len() != 1 {
            continue;
        }
        witnesses.insert(page_key);
        high_words.extend(candidate_high_words);
    }

    if high_words.len() > 1 {
        return Err(
            EnterprisePageMaterializationError::ConflictingTransformKeyWitnesses {
                count: high_words.len(),
            },
        );
    }
    if witnesses.len() < MIN_DECISIVE_KEY_WITNESSES {
        return Err(
            EnterprisePageMaterializationError::InsufficientTransformKeyWitnesses {
                actual: witnesses.len(),
                minimum: MIN_DECISIVE_KEY_WITNESSES,
            },
        );
    }
    let (high_word, negative) = *high_words
        .first()
        .expect("enough decisive witnesses imply one key context");
    Ok(EnterprisePageTransformKey {
        high_word,
        negative,
        adjacent_high_word: false,
        decisive_witness_count: witnesses.len(),
    })
}

/// Learn a transform-key context directly from an already-open zero-copy page store.
///
/// This is the production convenience form: it borrows each physical page from
/// `store` and never reopens or copies the QBW snapshot.
pub fn discover_enterprise_page_transform_key_in_store(
    store: &PageStore,
) -> Result<EnterprisePageTransformKey, EnterprisePageMaterializationError> {
    discover_enterprise_page_transform_key(store.pages().map(|page| (page.index(), page.bytes())))
}

/// Enumerate every independently witnessed file-wide transform-key candidate.
///
/// Each returned high word has at least one structurally decisive physical
/// type-4 page witness. This function preserves weak and conflicting
/// candidates for a higher-level semantic catalog attestor; it never chooses
/// by plurality. The strict legacy discovery API still requires three
/// agreeing witnesses before returning a key directly.
pub fn discover_enterprise_page_transform_key_candidates<'a, I>(
    raw_pages: I,
) -> Result<Vec<EnterprisePageTransformKey>, EnterprisePageMaterializationError>
where
    I: IntoIterator<Item = (u64, &'a [u8])>,
{
    let mut witnesses = BTreeMap::<(u16, bool), BTreeSet<u32>>::new();
    for (page_number, raw_page) in raw_pages {
        let page_key = checked_page_key(raw_page, page_number)?;
        let header_candidates = recover_header_candidates(&raw_page[..SECTOR_LEN], page_key);
        if header_candidates.len() != 1 {
            continue;
        }
        let candidate_high_words = valid_key_contexts(raw_page, page_key, header_candidates[0])?;
        if candidate_high_words.len() != 1 {
            continue;
        }
        let high_word = *candidate_high_words
            .first()
            .expect("one checked high-word candidate");
        witnesses.entry(high_word).or_default().insert(page_key);
    }

    let candidates = witnesses
        .into_iter()
        .map(
            |((high_word, negative), page_keys)| EnterprisePageTransformKey {
                high_word,
                negative,
                adjacent_high_word: false,
                decisive_witness_count: page_keys.len(),
            },
        )
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Err(
            EnterprisePageMaterializationError::InsufficientTransformKeyWitnesses {
                actual: 0,
                minimum: 1,
            },
        );
    }
    Ok(candidates)
}

/// Enumerate witnessed transform-key candidates from an immutable page store.
pub fn discover_enterprise_page_transform_key_candidates_in_store(
    store: &PageStore,
) -> Result<Vec<EnterprisePageTransformKey>, EnterprisePageMaterializationError> {
    discover_enterprise_page_transform_key_candidates(
        store.pages().map(|page| (page.index(), page.bytes())),
    )
}

fn checked_page_key(
    raw_page: &[u8],
    page_number: u64,
) -> Result<u32, EnterprisePageMaterializationError> {
    if raw_page.len() != MATERIALIZED_TABLE_PAGE_LEN {
        return Err(EnterprisePageMaterializationError::InvalidRawPageLength {
            actual: raw_page.len(),
        });
    }
    u32::try_from(page_number)
        .map_err(|_| EnterprisePageMaterializationError::PageNumberOutOfRange { page_number })
}

fn exactly_one_header_transform(
    raw_page: &[u8],
    page_key: u32,
) -> Result<HeaderTransform, EnterprisePageMaterializationError> {
    let header_candidates = recover_header_candidates(&raw_page[..SECTOR_LEN], page_key);
    match header_candidates.len() {
        0 => Err(EnterprisePageMaterializationError::NoHeaderCandidate),
        1 => Ok(header_candidates[0]),
        count => Err(EnterprisePageMaterializationError::AmbiguousHeaderCandidates { count }),
    }
}

fn materialize_with_signed_keys(
    raw_page: &[u8],
    page_key: u32,
    signed_keys: impl IntoIterator<Item = u32>,
) -> Result<EnterpriseMaterializedTablePage, EnterprisePageMaterializationError> {
    let distinct_pages = materialized_pages_with_signed_keys(raw_page, page_key, signed_keys)?;
    match distinct_pages.len() {
        1 => Ok(distinct_pages
            .into_iter()
            .next()
            .expect("one checked candidate")),
        count => Err(EnterprisePageMaterializationError::AmbiguousMaterializedPages { count }),
    }
}

fn materialized_pages_with_signed_keys(
    raw_page: &[u8],
    page_key: u32,
    signed_keys: impl IntoIterator<Item = u32>,
) -> Result<Vec<EnterpriseMaterializedTablePage>, EnterprisePageMaterializationError> {
    let mut distinct_pages = BTreeSet::new();
    for signed_key in signed_keys {
        let mut candidate: [u8; MATERIALIZED_TABLE_PAGE_LEN] =
            raw_page.try_into().expect("raw length checked by caller");
        transform_page(&mut candidate, signed_key)?;
        relocate_header_trailer(&mut candidate);
        let Ok(page) = MaterializedTablePage::parse(&candidate) else {
            continue;
        };
        if page.key() == page_key {
            distinct_pages.insert(candidate);
        }
    }
    if distinct_pages.is_empty() {
        return Err(EnterprisePageMaterializationError::NotMaterializedTablePage);
    }
    Ok(distinct_pages
        .into_iter()
        .map(|bytes| EnterpriseMaterializedTablePage { bytes })
        .collect())
}

fn valid_key_contexts(
    raw_page: &[u8],
    page_key: u32,
    header: HeaderTransform,
) -> Result<BTreeSet<(u16, bool)>, EnterprisePageMaterializationError> {
    let mut contexts = BTreeSet::new();
    for signed_key in signed_key_candidates(header) {
        if materialize_with_signed_keys(raw_page, page_key, [signed_key]).is_ok() {
            let key = signed_key as i32;
            contexts.insert(((key.unsigned_abs() >> 16) as u16, key < 0));
        }
    }
    Ok(contexts)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct HeaderTransform {
    step_mod_512: u16,
    increment: u8,
    initial_seed: u8,
}

#[derive(Clone, Copy)]
struct HeaderCycleProbe {
    step_mod_512: u16,
    source: [u16; 4],
    rank: [u16; 4],
}

fn header_cycle_probes() -> &'static [HeaderCycleProbe] {
    static PROBES: OnceLock<Vec<HeaderCycleProbe>> = OnceLock::new();
    PROBES.get_or_init(|| {
        (1..SECTOR_LEN)
            .step_by(2)
            .map(|step| {
                let mut source = [0_u16; 4];
                let mut rank = [0_u16; 4];
                let mut seen = [false; 4];
                let mut current = 0_usize;
                let mut ordinal = 0_u16;
                loop {
                    let next = current.wrapping_add(step) & (SECTOR_LEN - 1);
                    if current < 4 {
                        source[current] = next as u16;
                        rank[current] = ordinal;
                        seen[current] = true;
                    }
                    if next == 0 {
                        break;
                    }
                    current = next;
                    ordinal = ordinal.wrapping_add(1);
                }
                debug_assert!(seen.into_iter().all(|value| value));
                HeaderCycleProbe {
                    step_mod_512: step as u16,
                    source,
                    rank,
                }
            })
            .collect()
    })
}

fn recover_header_candidates(raw_sector: &[u8], page_key: u32) -> Vec<HeaderTransform> {
    debug_assert_eq!(raw_sector.len(), SECTOR_LEN);
    let expected = page_key.to_le_bytes();
    let mut candidates = Vec::new();
    for probe in header_cycle_probes() {
        let source_zero = usize::from(probe.source[0]);
        let seed = expected[0].wrapping_sub(raw_sector[source_zero]);
        for increment in constrained_odd_increments(probe, raw_sector, expected, seed) {
            let matches = (0..4).all(|index| {
                let source = usize::from(probe.source[index]);
                raw_sector[source]
                    .wrapping_add(seed)
                    .wrapping_add((probe.rank[index] as u8).wrapping_mul(increment))
                    == expected[index]
            });
            if matches {
                candidates.push(HeaderTransform {
                    step_mod_512: probe.step_mod_512,
                    increment,
                    initial_seed: seed,
                });
            }
        }
    }
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

/// Return the odd increment values compatible with the most selective one of
/// the three nonzero header-byte equations.  Solving that congruence first
/// avoids testing all 128 odd values for every physical page.
fn constrained_odd_increments(
    probe: &HeaderCycleProbe,
    raw_sector: &[u8],
    expected: [u8; 4],
    seed: u8,
) -> Vec<u8> {
    let Some(index) = (1..4)
        .filter(|index| (probe.rank[*index] as u8) != 0)
        .min_by_key(|index| (probe.rank[*index] as u8).trailing_zeros())
    else {
        return (1..=u8::MAX).step_by(2).collect();
    };
    let multiplier = probe.rank[index] as u8;
    let divisor = 1_u16 << multiplier.trailing_zeros();
    let target = expected[index]
        .wrapping_sub(raw_sector[usize::from(probe.source[index])])
        .wrapping_sub(seed);
    if u16::from(target) % divisor != 0 {
        return Vec::new();
    }
    let modulus = 256_u16 / divisor;
    let reduced_multiplier = multiplier / divisor as u8;
    let reduced_target = u16::from(target) / divisor;
    let inverse = inverse_odd_mod_256(reduced_multiplier) as u16;
    let base = (reduced_target * inverse) & (modulus - 1);
    (0..divisor)
        .map(|ordinal| (base + ordinal * modulus) as u8)
        .filter(|increment| increment % 2 == 1)
        .collect()
}

/// Multiplicative inverse of an odd byte modulo 256.
fn inverse_odd_mod_256(value: u8) -> u8 {
    debug_assert_eq!(value % 2, 1);
    let mut inverse = 1_u8;
    for _ in 0..3 {
        inverse = inverse.wrapping_mul(2_u8.wrapping_sub(value.wrapping_mul(inverse)));
    }
    debug_assert_eq!(value.wrapping_mul(inverse), 1);
    inverse
}

fn positive_signed_key_candidates(header: HeaderTransform) -> Vec<u32> {
    let positive_stride = usize::from(header.step_mod_512);
    let low = header.initial_seed;
    let mut candidates = Vec::with_capacity(4);
    for byte_one in [header.increment & !1, header.increment] {
        for before_or in [positive_stride, positive_stride.wrapping_sub(1) & 511] {
            let high_word = before_or.wrapping_sub(usize::from(low)) & 511;
            let candidate =
                ((high_word as u32) << 16) | (u32::from(byte_one) << 8) | u32::from(low);
            if !candidates.contains(&candidate) {
                candidates.push(candidate);
            }
        }
    }
    candidates
}

/// Recover both signs from the observed cycle equations. For a negative
/// key the first full-sector seed is increment minus magnitude's low byte,
/// and the cycle stride is the negation of the magnitude-derived stride.
fn signed_key_candidates(header: HeaderTransform) -> Vec<u32> {
    let mut candidates = positive_signed_key_candidates(header);
    let low = header.increment.wrapping_sub(header.initial_seed);
    let stride = SECTOR_LEN.wrapping_sub(usize::from(header.step_mod_512)) & 511;
    for byte_one in [header.increment & !1, header.increment] {
        for before_or in [stride, stride.wrapping_sub(1) & 511] {
            let high_word = before_or.wrapping_sub(usize::from(low)) & 511;
            let magnitude =
                ((high_word as u32) << 16) | (u32::from(byte_one) << 8) | u32::from(low);
            if magnitude != 0 {
                candidates.push(magnitude.wrapping_neg());
            }
        }
    }
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

fn signed_key_candidates_for_context(
    header: HeaderTransform,
    transform_key: EnterprisePageTransformKey,
) -> Vec<u32> {
    // Preserve both byte-one candidates. A context includes direction so
    // opposite transformations are never merged merely by high word.
    signed_key_candidates(header)
        .into_iter()
        .filter(|candidate| {
            let key = *candidate as i32;
            let high_word = (key.unsigned_abs() >> 16) as u16;
            (key < 0) == transform_key.negative
                && (high_word == transform_key.high_word
                    || (transform_key.adjacent_high_word
                        && high_word == (transform_key.high_word ^ 1)))
        })
        .collect()
}

fn transform_page(
    page: &mut [u8; MATERIALIZED_TABLE_PAGE_LEN],
    signed_key_start: u32,
) -> Result<(), PagePermutationError> {
    for sector_index in 0..SECTOR_COUNT {
        let start = sector_index * SECTOR_LEN;
        let tail = if sector_index + 1 == SECTOR_COUNT {
            FINAL_SECTOR_TAIL
        } else {
            0
        };
        let signed_key = signed_key_start.wrapping_sub(sector_index as u32) as i32;
        permute_sector_in_place(&mut page[start..start + SECTOR_LEN], 0, tail, signed_key)?;
    }
    Ok(())
}

fn relocate_header_trailer(page: &mut [u8; MATERIALIZED_TABLE_PAGE_LEN]) {
    let trailer: [u8; 12] = page[0xff0..0xffc].try_into().expect("fixed trailer range");
    let header_06: [u8; 6] = page[0x06..0x0c].try_into().expect("fixed header range");
    let header_0c: [u8; 4] = page[0x0c..0x10].try_into().expect("fixed header range");
    let header_12: [u8; 2] = page[0x12..0x14].try_into().expect("fixed header range");
    page[0x06..0x0c].copy_from_slice(&trailer[2..8]);
    page[0x0c..0x10].copy_from_slice(&trailer[8..12]);
    page[0x12..0x14].copy_from_slice(&trailer[0..2]);
    page[0xff0..0xff2].copy_from_slice(&header_12);
    page[0xff2..0xff8].copy_from_slice(&header_06);
    page[0xff8..0xffc].copy_from_slice(&header_0c);
}

/// Failure while reconstructing a raw Enterprise page.
#[derive(Debug, Error)]
pub enum EnterprisePageMaterializationError {
    /// Input was not one complete physical page.
    #[error("raw page had {actual} bytes, expected {MATERIALIZED_TABLE_PAGE_LEN}")]
    InvalidRawPageLength {
        /// Supplied byte count.
        actual: usize,
    },
    /// The physical page number does not fit the observed 32-bit page key.
    #[error("page number {page_number} does not fit the Enterprise page key")]
    PageNumberOutOfRange {
        /// Caller-supplied physical page number.
        page_number: u64,
    },
    /// No sector transform reproduced the known four-byte page key.
    #[error("no sector transform reproduced the physical page key")]
    NoHeaderCandidate,
    /// More than one sector transform reproduced the known page key.
    #[error("{count} sector transforms reproduced the physical page key")]
    AmbiguousHeaderCandidates {
        /// Number of distinct candidate parameter sets.
        count: usize,
    },
    /// A lower-level bounded sector permutation failed.
    #[error("page sector transform failed: {0}")]
    SectorTransform(#[from] PagePermutationError),
    /// No full-page candidate satisfied the type-4 directory and row bounds.
    #[error("raw page did not materialize as a validated type-4 table page")]
    NotMaterializedTablePage,
    /// Multiple distinct full pages passed all type-4 structural checks.
    #[error("{count} distinct materialized type-4 pages passed validation")]
    AmbiguousMaterializedPages {
        /// Number of distinct accepted page representations.
        count: usize,
    },
    /// Fewer than three distinct table pages identified a file-wide key.
    #[error("only {actual} decisive type-4 page witnesses found; at least {minimum} are required")]
    InsufficientTransformKeyWitnesses {
        /// Number of distinct physical page witnesses.
        actual: usize,
        /// Minimum number of independent witnesses required.
        minimum: usize,
    },
    /// Decisive type-4 pages identified different file-wide high words.
    #[error("{count} conflicting file-wide transform-key high words were witnessed")]
    ConflictingTransformKeyWitnesses {
        /// Number of distinct witnessed high words.
        count: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE_KEY: u32 = 3_980;
    const SIGNED_KEY: u32 = 0x019f_5a5f;

    fn synthetic_materialized_page() -> [u8; MATERIALIZED_TABLE_PAGE_LEN] {
        let mut page = [0_u8; MATERIALIZED_TABLE_PAGE_LEN];
        page[..4].copy_from_slice(&PAGE_KEY.to_le_bytes());
        page[0x06] = b'E';
        page[0x08..0x0c].copy_from_slice(&[0xD6, 0xA6, 0xAA, 0]);
        page[0x10] = 4;
        let starts = [
            0x0f20, 0x0d20, 0x0b20, 0x0920, 0x0720, 0x0520, 0x0320, 0x0120,
        ];
        page[0x16..0x18].copy_from_slice(&(starts.len() as u16).to_le_bytes());
        for (record_id, start) in starts.into_iter().enumerate() {
            let relative = u16::try_from(start - 0x1c).expect("bounded start");
            let entry = 0x1c + record_id * 2;
            page[entry..entry + 2].copy_from_slice(&relative.to_le_bytes());
            let length = 0x80_usize;
            page[start..start + 2].copy_from_slice(&(length as u16).to_le_bytes());
            page[start + 2] = if record_id % 2 == 0 { 0x40 } else { 0 };
            for (offset, byte) in page[start + 3..start + length].iter_mut().enumerate() {
                *byte = (record_id as u8)
                    .wrapping_mul(29)
                    .wrapping_add((offset as u8).wrapping_mul(37))
                    .wrapping_add(11);
            }
        }
        page
    }

    fn encode_raw(
        materialized: [u8; MATERIALIZED_TABLE_PAGE_LEN],
    ) -> [u8; MATERIALIZED_TABLE_PAGE_LEN] {
        encode_raw_with_key(materialized, SIGNED_KEY)
    }

    fn encode_raw_with_key(
        mut materialized: [u8; MATERIALIZED_TABLE_PAGE_LEN],
        signed_key: u32,
    ) -> [u8; MATERIALIZED_TABLE_PAGE_LEN] {
        relocate_header_trailer(&mut materialized);
        for sector_index in 0..SECTOR_COUNT {
            let start = sector_index * SECTOR_LEN;
            let tail = if sector_index + 1 == SECTOR_COUNT {
                FINAL_SECTOR_TAIL
            } else {
                0
            };
            let key = signed_key.wrapping_sub(sector_index as u32) as i32;
            permute_sector_in_place(&mut materialized[start..start + SECTOR_LEN], 0, tail, -key)
                .expect("inverse sector transform");
        }
        materialized
    }

    fn synthetic_page_for_key(page_key: u32) -> [u8; MATERIALIZED_TABLE_PAGE_LEN] {
        let mut page = synthetic_materialized_page();
        page[..4].copy_from_slice(&page_key.to_le_bytes());
        page
    }

    #[test]
    fn reconstructs_a_synthetic_type4_page_without_payload_oracle() {
        let materialized = synthetic_materialized_page();
        let raw = encode_raw(materialized);
        let recovered = materialize_enterprise_table_page(&raw, u64::from(PAGE_KEY))
            .expect("materialized page");
        assert_eq!(recovered.bytes(), &materialized);
        assert_eq!(recovered.table_page().record_count(), 8);
    }

    #[test]
    fn negative_transform_recovers_full_pages_across_sector_key_carries() {
        for magnitude in [0x013f_7bfe_u32, 0x0034_7b01, 0x012c_25ff] {
            let context =
                EnterprisePageTransformKey::from_negative_high_word((magnitude >> 16) as u16);
            for page_key in [13, 271, 4099] {
                let expected = synthetic_page_for_key(page_key);
                let raw = encode_raw_with_key(expected, magnitude.wrapping_neg());
                let recovered = materialize_enterprise_table_page_candidates_with_key(
                    &raw,
                    u64::from(page_key),
                    context,
                )
                .unwrap();
                assert_eq!(recovered.len(), 1);
                assert_eq!(recovered[0].bytes(), &expected);
                assert!(
                    materialize_enterprise_table_page_candidates_with_key(
                        &raw,
                        u64::from(page_key),
                        EnterprisePageTransformKey::from_high_word(context.high_word()),
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn discovery_keeps_opposite_directions_distinct_at_the_same_high_word() {
        let mut raws = Vec::new();
        for (negative, start) in [(false, PAGE_KEY), (true, PAGE_KEY + 3)] {
            let key = if negative {
                SIGNED_KEY.wrapping_neg()
            } else {
                SIGNED_KEY
            };
            for page_key in start..start + 3 {
                raws.push((
                    page_key,
                    encode_raw_with_key(synthetic_page_for_key(page_key), key),
                ));
            }
        }
        let candidates = discover_enterprise_page_transform_key_candidates(
            raws.iter()
                .map(|(key, raw)| (u64::from(*key), raw.as_slice())),
        )
        .unwrap();
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates
                .iter()
                .map(|key| key.is_negative())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([false, true])
        );
        assert!(
            candidates
                .iter()
                .all(|key| key.decisive_witness_count() == 3)
        );
        assert!(
            discover_enterprise_page_transform_key(
                raws.iter()
                    .map(|(key, raw)| (u64::from(*key), raw.as_slice())),
            )
            .is_err()
        );
    }

    #[test]
    fn adjacent_context_retains_both_witnessed_page_grammars_without_guessing() {
        let pair = EnterprisePageTransformKey::from_high_word(101).with_adjacent_high_word();
        assert_eq!(pair.high_word(), 100);
        for (index, key) in [0x0064_2537_u32, 0x0065_259f].into_iter().enumerate() {
            let page_key = 800 + index as u32;
            let expected = synthetic_page_for_key(page_key);
            let raw = encode_raw_with_key(expected, key);
            let candidates = materialize_enterprise_table_page_candidates_with_key(
                &raw,
                u64::from(page_key),
                pair,
            )
            .unwrap();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].bytes(), &expected);
        }
        let unrelated = encode_raw_with_key(synthetic_page_for_key(805), 0x0068_2537);
        assert!(
            materialize_enterprise_table_page_candidates_with_key(&unrelated, 805, pair).is_err()
        );
    }

    #[test]
    fn discovers_a_context_from_three_independent_pages_and_reuses_it() {
        let page_keys = [PAGE_KEY, PAGE_KEY + 1, PAGE_KEY + 2];
        let raws: Vec<_> = page_keys
            .into_iter()
            .map(|page_key| (page_key, encode_raw(synthetic_page_for_key(page_key))))
            .collect();
        let context = discover_enterprise_page_transform_key(
            raws.iter()
                .map(|(page_key, raw)| (u64::from(*page_key), raw.as_slice())),
        )
        .expect("three agreeing witnesses");
        assert_eq!(context.high_word(), (SIGNED_KEY >> 16) as u16);
        assert_eq!(context.decisive_witness_count(), 3);

        let candidates = materialize_enterprise_table_page_candidates_with_key(
            &raws[2].1,
            u64::from(raws[2].0),
            context,
        )
        .expect("bounded candidates");
        assert_eq!(candidates.len(), 1);

        let recovered =
            materialize_enterprise_table_page_with_key(&raws[2].1, u64::from(raws[2].0), context)
                .expect("context materializes a page without page-local high-word selection");
        assert_eq!(recovered.bytes(), &synthetic_page_for_key(raws[2].0));
    }

    #[test]
    fn candidate_discovery_preserves_every_structurally_witnessed_high_word() {
        let other_signed_key = SIGNED_KEY ^ 0x0001_0000;
        let singleton_signed_key = SIGNED_KEY ^ 0x0002_0000;
        let mut raws = Vec::new();
        for page_key in PAGE_KEY..PAGE_KEY + 3 {
            raws.push((
                page_key,
                encode_raw_with_key(synthetic_page_for_key(page_key), SIGNED_KEY),
            ));
        }
        for page_key in PAGE_KEY + 3..PAGE_KEY + 6 {
            raws.push((
                page_key,
                encode_raw_with_key(synthetic_page_for_key(page_key), other_signed_key),
            ));
        }
        raws.push((
            PAGE_KEY + 6,
            encode_raw_with_key(synthetic_page_for_key(PAGE_KEY + 6), singleton_signed_key),
        ));

        let candidates = discover_enterprise_page_transform_key_candidates(
            raws.iter()
                .map(|(page_key, raw)| (u64::from(*page_key), raw.as_slice())),
        )
        .unwrap();
        assert_eq!(candidates.len(), 3);
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.high_word())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                (SIGNED_KEY >> 16) as u16,
                (other_signed_key >> 16) as u16,
                (singleton_signed_key >> 16) as u16,
            ])
        );
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.decisive_witness_count())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([1, 3])
        );
        assert!(matches!(
            discover_enterprise_page_transform_key(
                raws.iter()
                    .map(|(page_key, raw)| (u64::from(*page_key), raw.as_slice()))
            ),
            Err(EnterprisePageMaterializationError::ConflictingTransformKeyWitnesses { .. })
        ));
    }

    #[test]
    fn discovery_requires_three_distinct_decisive_witnesses() {
        let raw = encode_raw(synthetic_materialized_page());
        assert!(matches!(
            discover_enterprise_page_transform_key([
                (u64::from(PAGE_KEY), raw.as_slice()),
                (u64::from(PAGE_KEY), raw.as_slice()),
            ]),
            Err(
                EnterprisePageMaterializationError::InsufficientTransformKeyWitnesses {
                    actual: 1,
                    minimum: MIN_DECISIVE_KEY_WITNESSES,
                }
            )
        ));
    }

    #[test]
    fn candidate_resolver_requires_a_decoded_consensus() {
        let raw = encode_raw(synthetic_materialized_page());
        let context = EnterprisePageTransformKey::from_high_word((SIGNED_KEY >> 16) as u16);
        let candidates = materialize_enterprise_table_page_candidates_with_key(
            &raw,
            u64::from(PAGE_KEY),
            context,
        )
        .unwrap();
        assert_eq!(
            resolve_enterprise_table_page_candidates(&candidates, |page| {
                Ok::<_, ()>(page.table_page().record_count())
            }),
            Ok(8)
        );
        assert!(matches!(
            resolve_enterprise_table_page_candidates(&candidates, |_| Err::<usize, _>(())),
            Err(EnterpriseCandidateResolutionError::NoCandidateDecoded { candidate_count: 1 })
        ));

        let duplicate_candidates = vec![candidates[0].clone(), candidates[0].clone()];
        let mut next = 0_u8;
        assert!(matches!(
            resolve_enterprise_table_page_candidates(&duplicate_candidates, |_| {
                next += 1;
                Ok::<_, ()>(next)
            }),
            Err(
                EnterpriseCandidateResolutionError::DivergentDecodedCandidates { decoded_count: 2 }
            )
        ));
    }

    #[test]
    fn keyed_materialization_rejects_a_context_with_the_other_header_high_word() {
        let materialized = synthetic_materialized_page();
        let raw = encode_raw(materialized);
        let header = exactly_one_header_transform(&raw, PAGE_KEY).expect("header transform");
        let high_words: BTreeSet<_> = positive_signed_key_candidates(header)
            .into_iter()
            .map(|candidate| (candidate >> 16) as u16)
            .collect();
        assert_eq!(
            high_words.len(),
            2,
            "page-local header leaves two high words"
        );
        let wrong_high_word = high_words
            .into_iter()
            .find(|high_word| *high_word != (SIGNED_KEY >> 16) as u16)
            .expect("alternate high word");
        assert!(matches!(
            materialize_enterprise_table_page_with_key(
                &raw,
                u64::from(PAGE_KEY),
                EnterprisePageTransformKey::from_high_word(wrong_high_word),
            ),
            Err(EnterprisePageMaterializationError::NotMaterializedTablePage)
        ));
    }

    #[test]
    fn rejects_bad_length_page_number_and_non_table_payload() {
        assert!(matches!(
            materialize_enterprise_table_page(&[0; 10], 1),
            Err(EnterprisePageMaterializationError::InvalidRawPageLength { actual: 10 })
        ));
        assert!(matches!(
            materialize_enterprise_table_page(
                &[0; MATERIALIZED_TABLE_PAGE_LEN],
                u64::from(u32::MAX) + 1
            ),
            Err(EnterprisePageMaterializationError::PageNumberOutOfRange { .. })
        ));
        assert!(matches!(
            materialize_enterprise_table_page(&[0; MATERIALIZED_TABLE_PAGE_LEN], 1),
            Err(EnterprisePageMaterializationError::NoHeaderCandidate)
        ));
    }

    #[test]
    fn header_trailer_relocation_is_an_involution() {
        let mut page: [u8; MATERIALIZED_TABLE_PAGE_LEN] =
            core::array::from_fn(|index| index.wrapping_mul(37) as u8);
        let original = page;
        relocate_header_trailer(&mut page);
        relocate_header_trailer(&mut page);
        assert_eq!(page, original);
    }
}

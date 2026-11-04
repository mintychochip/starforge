//! JSONL segmentation with zstd compression and BLAKE3 hashing.
//!
//! [`split_jsonl`] greedily packs JSONL text into compressed segments of at
//! most `cap` bytes (unless a single line alone exceeds the cap) and
//! [`assemble`] reverses the process. [`compress`] and [`decompress`] are the
//! underlying zstd level-3 primitives; [`blake3_hex`] fingerprints bytes.

use crate::FormatError;

/// Default maximum compressed segment size (16 MiB).
pub const DEFAULT_SEGMENT_CAP: usize = 16 * 1024 * 1024;

/// Uncompressed growth between compression measurements (performance
/// cadence only; the `cap` invariant is enforced at every emission).
const MEASURE_TRIGGER: usize = 256 * 1024;

/// zstd compression level for every segment; fixed so output is deterministic.
const ZSTD_LEVEL: i32 = 3;

/// Lowercase BLAKE3 hex digest of `bytes`.
pub fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Compress `bytes` with zstd at level 3.
///
/// Deterministic: the same input always yields the same output bytes.
pub fn compress(bytes: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(bytes, ZSTD_LEVEL).expect("zstd in-memory compression never fails")
}

/// Decompress one zstd frame; corrupt input yields [`FormatError::Decompress`].
pub fn decompress(bytes: &[u8]) -> Result<Vec<u8>, FormatError> {
    zstd::stream::decode_all(bytes).map_err(|_| FormatError::Decompress)
}

/// Decompress one zstd frame with an output cap: at most `limit + 1` bytes
/// are ever read from the decoder, so a decompression bomb cannot force the
/// caller to materialize the full expansion. Output longer than `limit`
/// yields [`FormatError::TooLarge`]; corrupt input yields
/// [`FormatError::Decompress`] like [`decompress`].
pub fn decompress_bounded(bytes: &[u8], limit: usize) -> Result<Vec<u8>, FormatError> {
    use std::io::Read;

    let decoder = zstd::stream::read::Decoder::new(bytes).map_err(|_| FormatError::Decompress)?;
    let mut out = Vec::new();
    decoder
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| FormatError::Decompress)?;
    if out.len() > limit {
        return Err(FormatError::TooLarge { limit });
    }
    Ok(out)
}

/// Greedily pack JSONL text into compressed segments of at most `cap` bytes.
///
/// Every emitted segment compresses to at most `cap` bytes, unless it is a
/// single line that alone exceeds the cap (emitted as its own oversized
/// segment; a line cannot be split). Lines accumulate in an uncompressed
/// buffer that is compressed and measured each time it has grown by at least
/// `MEASURE_TRIGGER.min(cap)` bytes since the last check, plus at the final
/// flush. Lazy checking costs only packing efficiency, never the invariant:
/// emission always takes the largest line-boundary prefix that fits.
/// Empty input yields no segments. A final unterminated line is terminated first.
pub fn split_jsonl(jsonl: &str, cap: usize) -> Vec<Vec<u8>> {
    split_jsonl_with_trigger(jsonl, cap, MEASURE_TRIGGER.min(cap))
}

/// [`split_jsonl`] with an explicit measurement cadence.
///
/// Tests pass a small `trigger` to exercise multi-segment logic
/// deterministically; production use goes through [`split_jsonl`].
pub(crate) fn split_jsonl_with_trigger(jsonl: &str, cap: usize, trigger: usize) -> Vec<Vec<u8>> {
    if jsonl.is_empty() {
        return Vec::new();
    }
    let mut text = jsonl.to_string();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    let mut segments = Vec::new();
    let mut buf = String::new();
    // Cumulative byte length of each buffered line: `buf[..ends[k]]` is `k + 1` lines.
    let mut ends: Vec<usize> = Vec::new();
    let mut next_check = trigger;
    for line in text.split_inclusive('\n') {
        buf.push_str(line);
        ends.push(buf.len());
        if buf.len() >= next_check {
            next_check = buf.len().saturating_add(trigger);
            emit_one_if_over(&mut buf, &mut ends, &mut segments, cap);
        }
    }
    // Final flush under the same enforcement: the remainder may exceed `cap`.
    while !buf.is_empty() {
        if compress(buf.as_bytes()).len() <= cap {
            segments.push(compress(buf.as_bytes()));
            break;
        }
        emit_one(&mut buf, &mut ends, &mut segments, cap);
    }
    segments
}

/// Emit one segment from the front of `buf` if it is over `cap`.
fn emit_one_if_over(
    buf: &mut String,
    ends: &mut Vec<usize>,
    segments: &mut Vec<Vec<u8>>,
    cap: usize,
) {
    if compress(buf.as_bytes()).len() > cap {
        emit_one(buf, ends, segments, cap);
    }
}

/// Emit one segment: the largest line-boundary prefix of `buf` compressing
/// to at most `cap` bytes, or the first line alone if it already exceeds
/// `cap`. Requires non-empty `buf`; always drains at least one line.
fn emit_one(buf: &mut String, ends: &mut Vec<usize>, segments: &mut Vec<Vec<u8>>, cap: usize) {
    debug_assert!(!buf.is_empty());
    let bytes = buf.as_bytes();
    // Binary search for the largest line count whose prefix was measured to
    // fit. Compressed size is assumed near-monotonic in prefix length, but
    // safety does not depend on it: only a measured prefix is ever emitted.
    let mut lo = 0;
    let mut hi = ends.len();
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if compress(&bytes[..ends[mid - 1]]).len() <= cap {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    let taken_lines = if lo == 0 { 1 } else { lo };
    let take = ends[taken_lines - 1];
    segments.push(compress(&bytes[..take]));
    buf.drain(..take);
    ends.drain(..taken_lines);
    for end in ends.iter_mut() {
        *end -= take;
    }
}

/// Decompress `segments` and concatenate them.
///
/// Corrupt input yields [`FormatError::Decompress`]; valid frames that are
/// not UTF-8 yield [`FormatError::BadUtf8`].
pub fn assemble(segments: &[&[u8]]) -> Result<String, FormatError> {
    let mut out = Vec::new();
    for segment in segments {
        out.extend_from_slice(&decompress(segment)?);
    }
    String::from_utf8(out).map_err(|_| FormatError::BadUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FormatError;
    use proptest::prelude::*;

    fn as_refs(segments: &[Vec<u8>]) -> Vec<&[u8]> {
        segments.iter().map(Vec::as_slice).collect()
    }

    /// `split_jsonl` normalizes by terminating a final unterminated line.
    fn normalized(input: &str) -> String {
        if input.is_empty() {
            String::new()
        } else if input.ends_with('\n') {
            input.to_owned()
        } else {
            let mut owned = input.to_owned();
            owned.push('\n');
            owned
        }
    }

    /// Deterministic pseudo-random ASCII (LCG over alphanumerics).
    /// Incompressible enough to force segment splits in tests.
    fn pseudo_random_ascii(len: usize, seed: u64) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut state = seed;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.push(ALPHABET[(state >> 33) as usize % ALPHABET.len()]);
        }
        String::from_utf8(out).expect("alphabet is ASCII")
    }

    #[test]
    fn empty_input_yields_no_segments() {
        assert!(split_jsonl("", 1024).is_empty());
        assert_eq!(assemble(&[]).unwrap(), "");
    }

    #[test]
    fn unterminated_final_line_is_terminated() {
        let segments = split_jsonl("{\"a\":1}\n{\"b\":2}", 1024);
        assert_eq!(
            assemble(&as_refs(&segments)).unwrap(),
            "{\"a\":1}\n{\"b\":2}\n"
        );
    }

    #[test]
    fn blake3_hex_known_answer() {
        assert_eq!(
            blake3_hex(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        let digest = blake3_hex(b"starforge");
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    #[test]
    fn compress_roundtrip_and_determinism() {
        let input = "{\"seq\":42,\"kind\":\"system\"}\n".repeat(100);
        assert_eq!(
            decompress(&compress(input.as_bytes())).unwrap(),
            input.as_bytes()
        );
        assert_eq!(compress(input.as_bytes()), compress(input.as_bytes()));
    }

    #[test]
    fn decompress_rejects_corrupt_input() {
        assert!(matches!(
            decompress(b"this is not zstd"),
            Err(FormatError::Decompress)
        ));
        assert!(matches!(decompress(&[]), Err(FormatError::Decompress)));
        let mut truncated = compress(b"{\"seq\":1}\n");
        truncated.truncate(truncated.len() / 2);
        assert!(matches!(
            decompress(&truncated),
            Err(FormatError::Decompress)
        ));
    }
    #[test]
    fn bounded_decompress_roundtrips_small_bodies() {
        let input = "{\"seq\":42,\"kind\":\"system\"}\n".repeat(100);
        let compressed = compress(input.as_bytes());
        assert_eq!(
            decompress_bounded(&compressed, input.len()).unwrap(),
            input.as_bytes()
        );
        assert_eq!(
            decompress_bounded(&compressed, input.len() * 2).unwrap(),
            input.as_bytes()
        );
    }

    #[test]
    fn bounded_decompress_rejects_bombs_without_full_expansion() {
        // 8 MiB of zeros compresses to kilobytes; the cap trips after
        // reading limit + 1 bytes, never materializing the full body.
        let bomb = compress(&vec![b'0'; 8 * 1024 * 1024]);
        assert!(bomb.len() < 1024, "bomb must stay small on the wire");
        assert!(matches!(
            decompress_bounded(&bomb, 1024),
            Err(FormatError::TooLarge { limit: 1024 })
        ));
    }

    #[test]
    fn bounded_decompress_rejects_corrupt_input() {
        assert!(matches!(
            decompress_bounded(b"this is not zstd", 1024),
            Err(FormatError::Decompress)
        ));
        assert!(matches!(
            decompress_bounded(&[], 1024),
            Err(FormatError::Decompress)
        ));
        let mut truncated = compress(b"{\"seq\":1}\n");
        truncated.truncate(truncated.len() / 2);
        assert!(matches!(
            decompress_bounded(&truncated, 1024),
            Err(FormatError::Decompress)
        ));
    }

    #[test]
    fn assemble_rejects_bad_segments() {
        let garbage = b"not a zstd frame".to_vec();
        assert!(matches!(
            assemble(&[garbage.as_slice()]),
            Err(FormatError::Decompress)
        ));
        let bad_utf8 = compress(&[0xff, 0xfe, 0xfd]);
        assert!(matches!(
            assemble(&[bad_utf8.as_slice()]),
            Err(FormatError::BadUtf8)
        ));
    }

    /// Every segment is within `cap`, unless it is a single line that alone exceeds it.
    fn assert_cap_invariant(segments: &[Vec<u8>], cap: usize) {
        for seg in segments {
            if seg.len() <= cap {
                continue;
            }
            let raw = decompress(seg).expect("segment decompresses");
            let text = String::from_utf8(raw).expect("test data is UTF-8");
            assert!(
                text.ends_with('\n') && !text[..text.len() - 1].contains('\n'),
                "over-cap segment holds several lines"
            );
            assert!(
                compress(text.as_bytes()).len() > cap,
                "over-cap segment's line fits in cap"
            );
        }
    }

    #[test]
    fn oversized_single_line_is_its_own_segment() {
        let line = pseudo_random_ascii(300 * 1024, 7) + "\n";
        let cap = 1024;
        assert!(compress(line.as_bytes()).len() > cap);
        let segments = split_jsonl(&line, cap);
        assert_eq!(segments.len(), 1);
        assert!(segments[0].len() > cap);
        assert_eq!(assemble(&as_refs(&segments)).unwrap(), line);
    }

    #[test]
    fn oversized_line_followed_by_more_lines() {
        let big = pseudo_random_ascii(3000, 11) + "\n";
        let mut input = big.clone();
        for i in 0..50 {
            input.push_str(&pseudo_random_ascii(120, 2000 + i));
            input.push('\n');
        }
        let cap = 1024;
        assert!(compress(big.as_bytes()).len() > cap);
        // Small trigger exercises the check path; the oversized line is
        // emitted alone mid-stream and the following lines keep packing.
        let segments = split_jsonl_with_trigger(&input, cap, 64);
        assert!(segments.len() >= 2);
        assert_eq!(decompress(&segments[0]).unwrap(), big.as_bytes());
        assert_cap_invariant(&segments, cap);
        assert_eq!(assemble(&as_refs(&segments)).unwrap(), input);
    }

    #[test]
    fn boundary_single_segment_exactly_at_cap() {
        let input = "{\"seq\":1,\"kind\":\"system\"}\n{\"seq\":2,\"kind\":\"system\"}\n";
        let cap = compress(input.as_bytes()).len();
        let segments = split_jsonl(input, cap);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].len(), cap);
        assert_eq!(assemble(&as_refs(&segments)).unwrap(), input);
    }

    #[test]
    fn boundary_measure_trigger_256kib() {
        const TRIGGER: usize = 256 * 1024;
        let cap = 1024;
        let line1 = pseudo_random_ascii(200 * 1024 - 1, 1) + "\n";
        let line2 = pseudo_random_ascii(56 * 1024 - 1, 2) + "\n";
        assert_eq!(line1.len() + line2.len(), TRIGGER);
        // Both lines alone exceed the cap, so each becomes its own oversized
        // segment; the check path (over the trigger) and the flush-only path
        // (exactly at the trigger) must agree byte for byte.
        let input = format!("{line1}{line2}");
        let checked = split_jsonl_with_trigger(&format!("{input}x"), cap, TRIGGER);
        let flushed = split_jsonl_with_trigger(&input, cap, TRIGGER + 1);
        assert_eq!(checked.len(), 3);
        assert_eq!(decompress(&checked[0]).unwrap(), line1.as_bytes());
        assert_eq!(decompress(&checked[1]).unwrap(), line2.as_bytes());
        assert_eq!(assemble(&as_refs(&checked)).unwrap(), format!("{input}x\n"));
        assert_eq!(flushed.len(), 2);
        assert_eq!(checked[..2], flushed);
        assert_eq!(assemble(&as_refs(&flushed)).unwrap(), input);
    }

    #[test]
    fn segments_stay_within_cap() {
        let mut input = String::new();
        for i in 0..4096 {
            input.push_str(&pseudo_random_ascii(120, 1000 + i));
            input.push('\n');
        }
        for cap in [1024, 4096, 65_536] {
            let segments = split_jsonl(&input, cap);
            assert!(
                segments.len() >= 2,
                "expected splits, got {}",
                segments.len()
            );
            assert_cap_invariant(&segments, cap);
            for seg in &segments {
                assert!(seg.len() <= cap, "segment {} over cap {}", seg.len(), cap);
            }
            assert_eq!(assemble(&as_refs(&segments)).unwrap(), input);
        }
    }

    #[test]
    fn default_trigger_multi_segment() {
        let mut input = String::new();
        for i in 0..16_528 {
            input.push_str(&pseudo_random_ascii(120, 3000 + i));
            input.push('\n');
        }
        let cap = 300_000;
        let segments = split_jsonl(&input, cap);
        assert!(
            segments.len() >= 2,
            "expected splits, got {}",
            segments.len()
        );
        assert_cap_invariant(&segments, cap);
        assert_eq!(assemble(&as_refs(&segments)).unwrap(), input);
    }

    #[test]
    fn lazy_checks_cost_only_packing() {
        // Same input+cap with near-instant checks and (almost) no checks:
        // identical reassembled output, invariant holds on both paths.
        let mut input = String::new();
        for i in 0..200 {
            input.push_str(&pseudo_random_ascii(120, 4000 + i));
            input.push('\n');
        }
        let cap = 1024;
        let eager = split_jsonl_with_trigger(&input, cap, 64);
        let lazy = split_jsonl_with_trigger(&input, cap, 1 << 40);
        assert!(eager.len() >= 2);
        assert!(lazy.len() >= 2);
        assert_cap_invariant(&eager, cap);
        assert_cap_invariant(&lazy, cap);
        assert_eq!(assemble(&as_refs(&eager)).unwrap(), input);
        assert_eq!(assemble(&as_refs(&lazy)).unwrap(), input);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn roundtrip_arbitrary(chars in prop::collection::vec(any::<char>(), 0..300)) {
            let input: String = chars.into_iter().collect();
            let segments = split_jsonl(&input, 1024);
            for seg in &segments {
                prop_assert!(decompress(seg).is_ok());
            }
            prop_assert_eq!(assemble(&as_refs(&segments)).unwrap(), normalized(&input));
        }

        #[test]
        fn determinism_arbitrary(chars in prop::collection::vec(any::<char>(), 0..300)) {
            let input: String = chars.into_iter().collect();
            prop_assert_eq!(split_jsonl(&input, 1024), split_jsonl(&input, 1024));
        }

        #[test]
        fn multisegment_small_trigger(
            lines in prop::collection::vec("[a-zA-Z0-9 ]{1,60}", 1..80),
            cap in 64usize..2048,
        ) {
            let input = lines.join("\n") + "\n";
            let segments = split_jsonl_with_trigger(&input, cap, 64);
            prop_assert!(!segments.is_empty());
            for seg in &segments {
                let raw = decompress(seg).map_err(|_| TestCaseError::fail("segment must decompress"))?;
                if seg.len() > cap {
                    let text = String::from_utf8(raw).map_err(|_| TestCaseError::fail("test data is UTF-8"))?;
                    prop_assert!(text.ends_with('\n') && !text[..text.len() - 1].contains('\n'));
                    prop_assert!(compress(text.as_bytes()).len() > cap);
                }
            }
            prop_assert_eq!(assemble(&as_refs(&segments)).unwrap(), input.clone());
            prop_assert_eq!(segments, split_jsonl_with_trigger(&input, cap, 64));
        }
    }
}

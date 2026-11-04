//! JSONL segmentation with zstd compression and BLAKE3 hashing.
//!
//! [`split_jsonl`] greedily packs JSONL text into compressed segments of at
//! most `cap` bytes (unless a single line alone exceeds the cap) and
//! [`assemble`] reverses the process. [`compress`] and [`decompress`] are the
//! underlying zstd level-3 primitives; [`blake3_hex`] fingerprints bytes.

use crate::FormatError;

/// Default maximum compressed segment size (16 MiB).
pub const DEFAULT_SEGMENT_CAP: usize = 16 * 1024 * 1024;

/// Uncompressed buffer size past which the accumulator is compressed and measured.
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

/// Greedily pack JSONL text into compressed segments of at most `cap` bytes.
///
/// Lines accumulate in an uncompressed buffer; whenever the buffer exceeds
/// 256 KiB it is compressed and measured, and if it is over `cap` everything
/// before the current line is emitted as a segment. A single line that alone
/// exceeds the cap is emitted as its own oversized segment. Empty input
/// yields no segments. A final unterminated line is terminated first.
pub fn split_jsonl(jsonl: &str, cap: usize) -> Vec<Vec<u8>> {
    if jsonl.is_empty() {
        return Vec::new();
    }
    let mut text = jsonl.to_string();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    let mut segments = Vec::new();
    let mut buf = String::new();
    for line in text.split_inclusive('\n') {
        buf.push_str(line);
        if buf.len() > MEASURE_TRIGGER && compress(buf.as_bytes()).len() > cap {
            let prefix_len = buf.len() - line.len();
            if prefix_len == 0 {
                segments.push(compress(buf.as_bytes()));
                buf.clear();
            } else {
                segments.push(compress(&buf.as_bytes()[..prefix_len]));
                buf.drain(..prefix_len);
            }
        }
    }
    if !buf.is_empty() {
        segments.push(compress(buf.as_bytes()));
    }
    segments
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
        let cap = 1024;
        let line1 = pseudo_random_ascii(200 * 1024 - 1, 1) + "\n";
        let line2 = pseudo_random_ascii(56 * 1024 - 1, 2) + "\n";
        assert_eq!(line1.len() + line2.len(), 256 * 1024);
        // Exactly at the trigger: no measurement, single segment.
        let input = format!("{line1}{line2}");
        let segments = split_jsonl(&input, cap);
        assert_eq!(segments.len(), 1);
        assert_eq!(assemble(&as_refs(&segments)).unwrap(), input);
        // One byte over the trigger: measurement fires, prefix emitted.
        let line2_long = pseudo_random_ascii(56 * 1024, 2) + "\n";
        let input = format!("{line1}{line2_long}");
        let segments = split_jsonl(&input, cap);
        assert_eq!(segments.len(), 2);
        assert_eq!(decompress(&segments[0]).unwrap(), line1.as_bytes());
        assert_eq!(assemble(&as_refs(&segments)).unwrap(), input);
    }

    #[test]
    fn segments_stay_near_cap() {
        let mut input = String::new();
        for i in 0..4096 {
            input.push_str(&pseudo_random_ascii(120, 1000 + i));
            input.push('\n');
        }
        let cap = 300_000;
        let segments = split_jsonl(&input, cap);
        assert!(
            segments.len() >= 2,
            "expected splits, got {}",
            segments.len()
        );
        for seg in &segments {
            assert!(
                seg.len() <= cap + 64 * 1024,
                "segment {} over cap {}",
                seg.len(),
                cap
            );
            decompress(seg).unwrap();
        }
        assert_eq!(assemble(&as_refs(&segments)).unwrap(), input);
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
    }
}

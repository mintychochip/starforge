//! Randomness and hashing for secrets (spec §6.1: tokens and cookies are stored as SHA-256).

use sha2::{Digest, Sha256};

/// `bytes` bytes from the OS random number generator, hex-encoded.
pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0_u8; bytes];
    getrandom::fill(&mut buf).expect("the OS random number generator is available");
    hex::encode(buf)
}

pub fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_hex_is_fresh_and_sized() {
        let a = random_hex(32);
        assert_eq!(a.len(), 64);
        assert_ne!(a, random_hex(32));
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

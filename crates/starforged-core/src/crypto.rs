//! Randomness and hashing for secrets (spec §6.1: tokens and cookies are stored as SHA-256),
//! plus the sealed-credentials box for git remote credentials (M4b D1).

use base64::Engine as _;
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
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

/// Sealed-credentials box (M4b D1): XChaCha20-Poly1305 under a key derived
/// with HKDF-SHA256 from the server `secret_key` bytes (salt `"starforge"`,
/// info `"mirror-credentials-v1"`), so mirror credentials are unreadable
/// without the secret key and independent of the webhook key.
///
/// Sealed format: `x1:` + base64(24-byte random nonce ‖ ciphertext‖tag).
/// The derived key never renders in `Debug`.
#[derive(Clone)]
pub struct CredentialBox {
    key: [u8; 32],
}

impl CredentialBox {
    /// Derives the sealing key from `secret_key` bytes (the raw 32 bytes
    /// decoded from `security.secret_key`, the same bytes the webhook key
    /// is built from).
    pub fn new(secret_key: &[u8]) -> Self {
        let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"starforge");
        let prk = salt.extract(secret_key);
        let mut okm = [0_u8; 32];
        prk.expand(
            &[b"mirror-credentials-v1".as_slice()],
            ring::hkdf::HKDF_SHA256,
        )
        .expect("hkdf expand to 32 bytes")
        .fill(&mut okm)
        .expect("hkdf fill of a 32-byte buffer");
        CredentialBox { key: okm }
    }

    /// Directly wraps an already-derived key (tests).
    pub fn from_key(key: [u8; 32]) -> Self {
        CredentialBox { key }
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        let key = Key::try_from(&self.key[..]).expect("32-byte XChaCha key");
        XChaCha20Poly1305::new(&key)
    }

    /// Seals `plain` with a fresh random nonce. Panics only if the OS
    /// random number generator is unavailable, matching [`random_hex`].
    pub fn seal(&self, plain: &[u8]) -> String {
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).expect("the OS random number generator is available");
        let ciphertext = self
            .cipher()
            .encrypt(
                &XNonce::try_from(&nonce[..]).expect("24-byte XChaCha nonce"),
                Payload {
                    msg: plain,
                    aad: b"",
                },
            )
            .expect("XChaCha20-Poly1305 encryption does not fail");
        let mut packed = nonce.to_vec();
        packed.extend_from_slice(&ciphertext);
        format!(
            "x1:{}",
            base64::engine::general_purpose::STANDARD.encode(&packed)
        )
    }

    /// Opens a value produced by [`CredentialBox::seal`]. Tampered,
    /// truncated, malformed, or wrong-key input is an error, never a plain
    /// fallback.
    pub fn open(&self, sealed: &str) -> Result<Vec<u8>> {
        let b64 = sealed
            .strip_prefix("x1:")
            .ok_or_else(|| crate::CoreError::Invalid("unknown credential format".into()))?;
        let packed = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| crate::CoreError::Invalid("corrupt sealed credential".into()))?;
        if packed.len() < 24 + 16 {
            return Err(crate::CoreError::Invalid(
                "corrupt sealed credential".into(),
            ));
        }
        let (nonce, ciphertext) = packed.split_at(24);
        self.cipher()
            .decrypt(
                &XNonce::try_from(nonce)
                    .map_err(|_| crate::CoreError::Invalid("corrupt sealed credential".into()))?,
                Payload {
                    msg: ciphertext,
                    aad: b"",
                },
            )
            .map_err(|_| crate::CoreError::Invalid("cannot decrypt the sealed credential".into()))
    }
}

/// Alias so callers can write `Result<Vec<u8>>` for [`CredentialBox::open`].
pub type Result<T, E = crate::CoreError> = std::result::Result<T, E>;

impl std::fmt::Debug for CredentialBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialBox(<redacted>)")
    }
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

    #[test]
    fn credential_box_round_trip() {
        let bx = CredentialBox::new(&[7_u8; 32]);
        let sealed = bx.seal(b"git-user:token-value");
        assert!(sealed.starts_with("x1:"), "{sealed}");
        assert!(!sealed.contains("token-value"));
        assert_eq!(bx.open(&sealed).unwrap(), b"git-user:token-value");
        // A fresh nonce per seal: same plaintext seals differently.
        assert_ne!(sealed, bx.seal(b"git-user:token-value"));
    }

    #[test]
    fn credential_box_detects_tamper() {
        let bx = CredentialBox::new(&[7_u8; 32]);
        let sealed = bx.seal(b"secret");
        // Flip a byte in the decoded payload and re-encode.
        let b64 = sealed.strip_prefix("x1:").unwrap();
        let mut packed = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        let last = packed.len() - 1;
        packed[last] ^= 0xff;
        let tampered = format!(
            "x1:{}",
            base64::engine::general_purpose::STANDARD.encode(&packed)
        );
        assert!(bx.open(&tampered).is_err());
        assert!(bx.open("x1:not-base64!!!").is_err());
        assert!(bx.open("v1:whatever").is_err());
        assert!(bx.open("x1:").is_err());
    }

    #[test]
    fn credential_box_wrong_key_cannot_open() {
        let bx = CredentialBox::new(&[7_u8; 32]);
        let other = CredentialBox::new(&[9_u8; 32]);
        let sealed = bx.seal(b"secret");
        assert!(other.open(&sealed).is_err());
    }

    #[test]
    fn credential_box_debug_redacts_key() {
        let bx = CredentialBox::new(&[7_u8; 32]);
        let rendered = format!("{bx:?}");
        assert_eq!(rendered, "CredentialBox(<redacted>)");
    }
}

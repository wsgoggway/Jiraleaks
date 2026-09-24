use sha2::{Digest, Sha256};

/// Compute a SHA-256 hash of a secret value, prefixed with "sha256:".
/// Used for deduplication and allowlist-by-hash.
pub fn secret_hash(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    format!("sha256:{}", hex::encode(result))
}

/// SHA-256 digest of arbitrary bytes as 64 lowercase, zero-padded hex digits
/// (no `sha256:` prefix).
///
/// Unlike [`secret_hash`] this hashes an arbitrary byte string rather than a
/// secret value; it exists so identity strings derived from structured input
/// (see [`crate::finding::FindingKey::fingerprint`]) reuse the same hex encoder
/// instead of growing a second one. Byte-for-byte identical to
/// `format!("{:x}", Sha256::digest(bytes))`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Minimal hex encoding without external crate.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_hash_deterministic() {
        let h1 = secret_hash("test-secret");
        let h2 = secret_hash("test-secret");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_secret_hash_different() {
        let h1 = secret_hash("secret-a");
        let h2 = secret_hash("secret-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_format() {
        let h = secret_hash("test");
        assert!(h.starts_with("sha256:"));
        assert_eq!(h.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn sha256_hex_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_hex_is_zero_padded_byte_wise() {
        // Digest starts with the byte 0x0b: a byte-wise zero-padded encoder
        // keeps the leading "0b", a whole-number encoder would drop it and be
        // 63 characters long. Fingerprint strings persisted as primary keys
        // depend on this padding.
        let digest = sha256_hex(b"pad-probe-2");
        assert_eq!(
            digest,
            "0babf6ba665a2c29816f2a6dec34308b630f8c8de7a1d972a4849d82a33900e7"
        );
        assert_eq!(digest.len(), 64);
        assert_eq!(sha256_hex(b"sha256:x").len(), 64);
    }
}

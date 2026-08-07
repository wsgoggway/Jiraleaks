use sha2::{Digest, Sha256};

/// Compute a SHA-256 hash of a secret value, prefixed with "sha256:".
/// Used for deduplication and allowlist-by-hash.
pub fn secret_hash(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    format!("sha256:{}", hex::encode(result))
}

/// Minimal hex encoding without external crate.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
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
}

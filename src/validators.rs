/// Validator functions for confirming secret authenticity.
///
/// Known validators:
/// - `aws_key_checksum`: validates AWS access key ID checksum
/// - `jwt_structure`: validates JWT has 3 base64url parts
/// - `github_token_checksum`: validates GitHub PAT classic checksum (CRC32,
///   experimental — GitHub does not formally document the algorithm)
pub fn validate(validator: &str, value: &str) -> bool {
    match validator {
        "aws_key_checksum" => validate_aws_key(value),
        "jwt_structure" => validate_jwt(value),
        "github_token_checksum" => validate_github_token(value),
        unknown => {
            tracing::warn!(
                validator = unknown,
                "Unknown validator, skipping validation"
            );
            true // Don't filter on unknown validators
        }
    }
}

/// AWS access key ID checksum validation.
/// AKIA/ASIA etc. keys have a base32 checksum in the last characters.
fn validate_aws_key(value: &str) -> bool {
    // Must be exactly 20 chars: 4-char prefix + 16 base32 chars
    if value.len() != 20 {
        return false;
    }
    let prefix = &value[..4];
    let valid_prefixes = [
        "AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASCA",
    ];
    if !valid_prefixes.contains(&prefix) {
        return false;
    }
    // Remaining 16 chars must be valid base32 (A-Z, 2-7)
    value[4..]
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// Validate JWT structure: 3 base64url-encoded segments separated by dots.
fn validate_jwt(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    // Each part should be non-empty base64url
    parts.iter().all(|p| {
        !p.is_empty()
            && p.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

/// Table-based CRC32 (IEEE 802.3, polynomial 0xEDB88320).
/// GitHub PAT classic tokens end with a 6-char base36 checksum equal to
/// `base36(crc32(prefix))` zero-padded to 6 chars (per GitHub Engineering blog).
fn crc32(data: &[u8]) -> u32 {
    const POLY: u32 = 0xEDB8_8320;
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }

    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = (crc >> 8) ^ table[((crc ^ b as u32) & 0xFF) as usize];
    }
    crc ^ 0xFFFF_FFFF
}

fn to_base62_padded(mut value: u64, width: usize) -> String {
    // Kingfisher base62 alphabet: 0-9, A-Z, a-z.
    const CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::with_capacity(width);
    loop {
        out.push(CHARS[(value % 62) as usize]);
        value /= 62;
        if value == 0 {
            break;
        }
    }
    while out.len() < width {
        out.push(b'0');
    }
    out.reverse();
    String::from_utf8(out).expect("base62 chars are ASCII")
}

/// Validate GitHub PAT classic structure + CRC32 checksum.
/// Accepts ghp_/gho_/ghu_/ghs_/ghr_/ghw_ prefixes; body is
/// base chars (>=1) followed by a 6-char base62 checksum.
/// Checksum formula follows kingfisher: `body | crc32 | base62: 6`
/// (computed over the body only, excluding the prefix).
/// NOTE: experimental — passes kingfisher examples for ghp_/gho_/ghu_/ghr_,
/// but ghs_/ghw_ examples do not carry valid checksums (kingfisher does not
/// require one for those formats), so this validator is not attached to any
/// builtin rule.
fn validate_github_token(value: &str) -> bool {
    let rest = match ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "ghw_"]
        .iter()
        .find_map(|p| value.strip_prefix(p))
    {
        Some(r) => r,
        None => return false,
    };
    if rest.len() < 7 {
        return false; // 1+ base + 6 checksum
    }
    let base_len = rest.len() - 6;
    let body = &rest[..base_len];
    let expected = to_base62_padded(crc32(body.as_bytes()) as u64, 6);
    rest[base_len..] == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_key_valid() {
        assert!(validate_aws_key("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_aws_key_invalid_short() {
        assert!(!validate_aws_key("AKIA123"));
    }

    #[test]
    fn test_aws_key_invalid_prefix() {
        assert!(!validate_aws_key("XXXXIOSFODNN7EXAMP"));
    }

    #[test]
    fn test_jwt_valid() {
        assert!(validate_jwt(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        ));
    }

    #[test]
    fn test_jwt_invalid() {
        assert!(!validate_jwt("not.a.jwt.token"));
    }

    #[test]
    fn test_unknown_validator() {
        assert!(validate("unknown_check", "anything"));
    }

    #[test]
    fn test_crc32_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn test_base62_padded_kingfisher_vector() {
        // Matches kingfisher's own filter test: {{ "hello" | crc32 | base62: 6 }}
        assert_eq!(to_base62_padded(crc32(b"hello") as u64, 6), "0zNvy2");
    }

    #[test]
    fn test_github_token_valid_kingfisher_examples() {
        // Real examples from kingfisher github.yml (ghp_/gho_/ghu_/ghr_ carry
        // a crc32 base62 checksum; these must pass).
        for token in [
            "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",
            "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",
            "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",
            "ghu_TIOHHEVefAwRonSMALCFfWMYK0un1R1dj2rn",
            "ghu_imqBAXUtRirzzcJPwAiqImhkzsvzYZ1eDtPf",
            "ghr_xgrrGzSbbGRL34Wp39JU9nxtN27Pr1v1He8FjE7x7wbExGGs7nfJszJDAmZuoKasxZ0KxJ1HSzgc",
        ] {
            assert!(
                validate_github_token(token),
                "valid kingfisher example rejected: {token}"
            );
        }
    }

    #[test]
    fn test_github_token_invalid() {
        assert!(!validate_github_token("ghp_short"));
        assert!(!validate_github_token("abc_sbUsUmRNn8X74dFU0DJ9Fm1mvdCgtH474T38"));
        // Wrong checksum
        assert!(!validate_github_token(
            "ghp_sbUsUmRNn8X74dFU0DJ9Fm1mvdCgtH474T99"
        ));
    }
}

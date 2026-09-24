/// Validator functions for confirming secret authenticity.
///
/// Known validators:
/// - `aws_key_checksum`: validates the AWS access key ID prefix and alphabet
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

/// AWS access key ID validation: the four-character prefix names the credential
/// type, and the sixteen characters after it are the AWS alphabet.
///
/// That alphabet is base32 — `A`–`Z` and `2`–`7`, uppercase only. The digits
/// `0`, `1`, `8` and `9` are not in it, and AWS does not issue an access key id
/// that contains them, so `ASIA0000000000000000` is a near miss and not a
/// credential. The rule's regex (`[0-9A-Z]{16}`) is deliberately wider than the
/// alphabet, because the validator is the layer that knows this — which is why
/// the check has to be real here and not another uppercase-or-digit test.
fn validate_aws_key(value: &str) -> bool {
    // The prefixes AWS issues for access key ids, as the rule's regex lists them.
    // A prefix in this list but not in the regex is a dead branch, and one in the
    // regex but not here means every hit of that prefix is rejected — the test
    // below keeps the two lists equal.
    const VALID_PREFIXES: [&str; 9] = [
        "AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASCA",
    ];

    // Must be exactly 20 chars: 4-char prefix + 16 base32 chars. The ASCII check
    // guards the byte split below: without it a multi-byte character straddling
    // the fourth byte would panic `split_at` instead of rejecting the value.
    if value.len() != 20 || !value.is_ascii() {
        return false;
    }
    let (prefix, body) = value.split_at(4);
    if !VALID_PREFIXES.contains(&prefix) {
        return false;
    }
    body.bytes()
        .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
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
        for value in [
            // The sample AWS documents.
            "AKIAIOSFODNN7EXAMPLE",
            // A real-shaped `ASIA` key id; `7` is the only digit, and it is in the
            // alphabet.
            "ASIAOZW6VBVAZFJHJLQA",
            // Digits of the alphabet, and nothing else.
            "ASIA2345672345672345",
        ] {
            assert!(validate_aws_key(value), "{value} must be accepted");
        }
    }

    /// `0`, `1`, `8` and `9` are outside the AWS base32 alphabet, so a key id
    /// containing one is not a key id. The regex accepts it, the validator is what
    /// rejects it.
    #[test]
    fn test_aws_key_non_base32_digits_are_rejected() {
        for digit in ["0", "1", "8", "9"] {
            let value = format!("ASIA{}", digit.repeat(16));
            assert!(!validate_aws_key(&value), "{value} must be rejected");
        }
    }

    #[test]
    fn test_aws_key_lowercase_body_is_rejected() {
        assert!(!validate_aws_key("AKIAiosfodnn7example"));
    }

    /// A multi-byte character straddling the fourth byte must reject the value
    /// rather than panic the slice that splits the prefix off.
    #[test]
    fn test_aws_key_multibyte_prefix_boundary_is_rejected() {
        let value = format!("AKI\u{e4}{}", "A".repeat(15));
        assert_eq!(value.len(), 20, "the value must pass the length check");
        assert!(!validate_aws_key(&value));
    }

    /// The prefix list and the rule's regex must agree: every prefix the
    /// validator accepts has to be one the builtin rule matches, and every value
    /// built from it has to survive the rule's whole filter chain.
    #[test]
    fn test_aws_key_prefixes_match_the_builtin_rule() {
        let engine = crate::rules::RulesEngine::new(None).expect("builtin rules load");
        for prefix in [
            "AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASCA",
        ] {
            let value = format!("{prefix}2345672345672345");
            assert!(
                validate_aws_key(&value),
                "the validator rejects its own prefix {prefix}"
            );
            assert!(
                engine
                    .scan(&value, "test_field")
                    .iter()
                    .any(|hit| hit.rule_id == "aws_access_key_id"),
                "the builtin rule does not accept the prefix {prefix}: the validator is \
                 stricter than the regex, so every hit of that prefix is rejected"
            );
        }
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
        assert!(!validate_github_token(
            "abc_sbUsUmRNn8X74dFU0DJ9Fm1mvdCgtH474T38"
        ));
        // Wrong checksum
        assert!(!validate_github_token(
            "ghp_sbUsUmRNn8X74dFU0DJ9Fm1mvdCgtH474T99"
        ));
    }
}

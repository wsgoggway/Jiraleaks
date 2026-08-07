use std::collections::HashMap;

/// Compute Shannon entropy of a string in bits per character.
///
/// Higher entropy indicates more randomness — useful for
/// distinguishing real secrets from placeholders.
pub fn shannon(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<char, usize> = HashMap::new();
    let len = s.chars().count();

    for ch in s.chars() {
        *freq.entry(ch).or_insert(0) += 1;
    }

    let mut entropy = 0.0_f64;
    for count in freq.values() {
        let p = *count as f64 / len as f64;
        entropy -= p * p.log2();
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_string() {
        assert_eq!(shannon(""), 0.0);
    }

    #[test]
    fn test_single_char() {
        assert_eq!(shannon("aaaa"), 0.0);
    }

    #[test]
    fn test_random_looking() {
        let e = shannon("kX7mP2qR9sT4vW1y");
        assert!(e > 3.0, "Expected entropy > 3.0, got {e}");
    }

    #[test]
    fn test_low_entropy() {
        let e = shannon("password123");
        assert!(e < 3.5);
    }
}

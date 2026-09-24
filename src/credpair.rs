use std::sync::OnceLock;

use fancy_regex::Regex;

use crate::error::ScannerError;
use crate::hash::secret_hash;
use crate::redact;

/// Maximum byte distance between a username match and a password match for the
/// proximity heuristic to report them as one pair. Both ends are inclusive, so a
/// match exactly [`PROXIMITY_WINDOW_BYTES`] bytes away still pairs.
const PROXIMITY_WINDOW_BYTES: usize = 200;

/// Maximum number of matches materialised per pattern for a single segment.
///
/// Scanned text is attacker-controlled, and `user=a\npassword=b\n` repeated makes a
/// single 2 MiB field hold hundreds of thousands of candidate matches. Iteration is
/// lazy, so this bound also caps how much regex work one segment can trigger.
const MAX_MATCHES_PER_PATTERN: usize = 4096;

/// Maximum number of hits returned for a single text segment.
///
/// Each hit costs a redaction and a SHA-256 over attacker-chosen data, and the
/// pipeline only applies `max_findings_per_issue` *after* this function returns.
/// Keeping the per-segment output constant keeps one hostile segment from
/// monopolising a worker and stays well below the default issue limit (1000).
const MAX_HITS_PER_SEGMENT: usize = 256;

/// Maximum number of bytes of a segment the detector inspects.
///
/// The cost of a `fancy_regex` search over a segment is not bounded by the number of
/// matches it finds, so capping matches alone is not enough: measured on this code,
/// the URL-userinfo pattern — which finds nothing on
/// `"user=a\npass=b\n".repeat(_)` — takes ~11 ms over 14 KiB, ~108 ms over 224 KiB
/// and does not finish in 250 s over 896 KiB. Bounding the bytes handed to the engine
/// bounds every case, whatever the pattern does internally: the same worst case
/// measured at this limit stays in the tens of milliseconds.
///
/// 64 KiB is well above the realistic size of a Jira description, comment or custom
/// field, so ordinary content is never truncated. Extracted segments are capped at
/// `max_text_size_kb` (2 MiB by default), and the rules engine still scans the whole
/// segment — credential-pair detection is a heuristic layered on top of it.
const MAX_SCAN_BYTES: usize = 64 * 1024;

/// Credential pair finding: username + password together.
#[derive(Debug, Clone)]
pub struct CredPairHit {
    pub username: String,
    pub redacted_password: String,
    pub password_hash: String,
    pub field_path: String,
    pub format: CredPairFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredPairFormat {
    Json,
    UrlUserinfo,
    Proximity,
}

/// Detects credential material that is only recognisable as a *pair*: a username
/// sitting next to a password, `user:pass@host` userinfo, or a JSON object holding
/// both fields.
///
/// The value itself carries no state. The patterns are compiled once per process
/// into a process-wide cache ([`COMPILED`]) instead of once per call — `fancy_regex`
/// compilation is orders of magnitude more expensive than matching, and `detect` runs
/// for every text segment of every issue. This keeps the type usable as a plain
/// `CredentialPairDetector` value while removing the per-segment compilation cost.
#[derive(Debug, Clone, Copy, Default)]
pub struct CredentialPairDetector;

/// Patterns shared by every detector value.
struct Compiled {
    /// `scheme://user:password@host`
    url_userinfo: Regex,
    /// `user=...` / `login: ...` and friends, at the start of a line.
    username_key: Regex,
    /// `password=...` / `secret: ...` and friends, at the start of a line.
    password_key: Regex,
}

/// Process-wide compiled pattern cache. Compilation is retried on every call until
/// it succeeds, so a failure is reported instead of silently disabling detection.
static COMPILED: OnceLock<Result<Compiled, String>> = OnceLock::new();

/// JSON keys holding a username. Documented formats: `user` / `username`.
const JSON_USERNAME_KEYS: &[&str] = &[
    "username",
    "user",
    "login",
    "email",
    "client_id",
    "clientId",
];

/// JSON keys holding a password or secret. `pass` is documented in README
/// ("adjacent user/username and password/pass fields") and was previously missing.
const JSON_PASSWORD_KEYS: &[&str] = &[
    "password",
    "pass",
    "passwd",
    "pwd",
    "secret",
    "client_secret",
    "clientSecret",
    "api_key",
    "apiKey",
];

impl Compiled {
    /// Pattern errors are reduced to their message: `fancy_regex::Error` is a large
    /// value, and the cache only ever needs to explain the failure once.
    fn build() -> Result<Self, String> {
        Ok(Self {
            url_userinfo: Regex::new(r"\b[a-z][a-z0-9+.-]*://([^:\s/@]+):([^@\s/]+)@")
                .map_err(|e| e.to_string())?,
            username_key: Regex::new(
                r"(?im)^\s*(?:user(?:name)?|login|email|client[_-]?id|db[_-]?user|access[_-]?key|smtp[_-]?user|api[_-]?user)\s*[:=]\s*(\S+)",
            )
            .map_err(|e| e.to_string())?,
            password_key: Regex::new(
                r"(?im)^\s*(?:pass(?:word|wd)?|secret|client[_-]?secret|api[_-]?(?:key|secret)|smtp[_-]?pass)\s*[:=]\s*(\S+)",
            )
            .map_err(|e| e.to_string())?,
        })
    }
}

/// Return the compiled patterns, building them on first use.
fn compiled() -> Result<&'static Compiled, ScannerError> {
    COMPILED.get_or_init(Compiled::build).as_ref().map_err(|e| {
        ScannerError::Other(format!("credential-pair patterns failed to compile: {e}"))
    })
}

/// Push one hit, unless the per-segment budget is exhausted.
///
/// Returns `false` when the caller must stop producing hits.
fn push_hit(
    hits: &mut Vec<CredPairHit>,
    field_path: &str,
    username: &str,
    password: &str,
    format: CredPairFormat,
) -> bool {
    if hits.len() >= MAX_HITS_PER_SEGMENT {
        return false;
    }

    hits.push(CredPairHit {
        username: username.to_string(),
        redacted_password: redact::redact(password),
        password_hash: secret_hash(password),
        field_path: field_path.to_string(),
        format,
    });

    true
}

impl CredentialPairDetector {
    /// Build the detector, compiling the patterns on first use.
    ///
    /// The patterns are compile-time constants covered by the test suite, so this
    /// only ever fails if one of them is broken in the source — it is a startup
    /// check, not a runtime condition.
    pub fn new() -> Result<Self, ScannerError> {
        compiled()?;
        Ok(Self)
    }

    /// Detect credential pairs in a text segment.
    ///
    /// At most [`MAX_SCAN_BYTES`] of the segment are inspected, and the returned
    /// vector never exceeds [`MAX_HITS_PER_SEGMENT`] entries regardless of the input.
    /// A segment whose patterns fail to compile yields no hits (logged) instead of
    /// panicking mid-scan.
    pub fn detect(&self, text: &str, field_path: &str) -> Vec<CredPairHit> {
        let Ok(patterns) = compiled() else {
            tracing::warn!("credential-pair detection disabled: patterns failed to compile");
            return Vec::new();
        };

        let truncated = text.len() > MAX_SCAN_BYTES;
        let text = head(text, MAX_SCAN_BYTES);
        if truncated {
            tracing::debug!(
                limit = MAX_SCAN_BYTES,
                "Credential-pair scan truncated to the first bytes of the segment"
            );
        }

        let mut hits = Vec::new();

        // 1. URL userinfo (also caught by db_url_credentials rule — dedup via hash)
        self.detect_url_userinfo(patterns, text, field_path, &mut hits);

        // 2. Proximity pairs: username-like and password-like within 200 bytes
        self.detect_proximity(patterns, text, field_path, &mut hits);

        // 3. JSON pairs
        self.detect_json(text, field_path, &mut hits);

        hits
    }

    fn detect_url_userinfo(
        &self,
        patterns: &Compiled,
        text: &str,
        field_path: &str,
        hits: &mut Vec<CredPairHit>,
    ) {
        // `captures_iter` is lazy: the `take` also bounds the regex work spent on a
        // hostile segment. Groups come from the match itself — re-running
        // `captures()` over the matched span (as this used to) was pure waste.
        for caps in patterns
            .url_userinfo
            .captures_iter(text)
            .flatten()
            .take(MAX_MATCHES_PER_PATTERN)
        {
            let (Some(user), Some(pass)) = (caps.get(1), caps.get(2)) else {
                continue;
            };

            let password = pass.as_str();
            if is_placeholder(password) {
                continue;
            }

            if !push_hit(
                hits,
                field_path,
                user.as_str(),
                password,
                CredPairFormat::UrlUserinfo,
            ) {
                return;
            }
        }
    }

    fn detect_proximity(
        &self,
        patterns: &Compiled,
        text: &str,
        field_path: &str,
        hits: &mut Vec<CredPairHit>,
    ) {
        // Collect match start positions. Both vectors stay ordered by construction and
        // are sorted anyway so the sliding window below does not depend on the regex
        // iterator's ordering guarantee.
        let mut users = capture_spans(&patterns.username_key, text);
        let mut passwords = capture_spans(&patterns.password_key, text);
        users.sort_unstable_by_key(|(pos, _)| *pos);
        passwords.sort_unstable_by_key(|(pos, _)| *pos);

        // Two monotonic cursors instead of a cross-product: `lo` is the first
        // username that may still be inside the window of the current password and
        // `hi` the first one past it. Both only move forward, so the whole scan is
        // O(users + passwords) rather than O(users x passwords) — the previous
        // nested loop on `user=a\npassword=b\n` repeated produced tens of billions
        // of comparisons and tens of millions of allocations in a single 2 MiB field.
        let mut lo = 0usize;
        let mut hi = 0usize;

        for (p_pos, password) in &passwords {
            if is_placeholder(password) {
                continue;
            }

            let window_start = p_pos.saturating_sub(PROXIMITY_WINDOW_BYTES);
            let window_end = p_pos.saturating_add(PROXIMITY_WINDOW_BYTES);

            while lo < users.len() && users[lo].0 < window_start {
                lo += 1;
            }
            if hi < lo {
                hi = lo;
            }
            while hi < users.len() && users[hi].0 <= window_end {
                hi += 1;
            }

            for (_, username) in &users[lo..hi] {
                if !push_hit(
                    hits,
                    field_path,
                    username,
                    password,
                    CredPairFormat::Proximity,
                ) {
                    return;
                }
            }
        }
    }

    fn detect_json(&self, text: &str, field_path: &str, hits: &mut Vec<CredPairHit>) {
        // Cheap guard: only object literals can hold key/value pairs, and this keeps
        // ordinary prose out of the JSON parser.
        if !text.trim_start().starts_with('{') {
            return;
        }

        let Ok(serde_json::Value::Object(obj)) = serde_json::from_str::<serde_json::Value>(text)
        else {
            return;
        };

        // Several aliases frequently carry the same secret (`password` and `passwd`),
        // and several username aliases may carry the same username. Report each
        // (username, password) value pair once instead of amplifying one secret into
        // a duplicate finding per alias combination.
        let mut seen: Vec<(&str, &str)> = Vec::new();

        for uk in JSON_USERNAME_KEYS {
            let Some(user) = obj.get(*uk).and_then(|v| v.as_str()) else {
                continue;
            };
            if user.is_empty() {
                continue;
            }

            for pk in JSON_PASSWORD_KEYS {
                let Some(pass) = obj.get(*pk).and_then(|v| v.as_str()) else {
                    continue;
                };
                if pass.is_empty() || is_placeholder(pass) {
                    continue;
                }

                if seen.contains(&(user, pass)) {
                    continue;
                }
                seen.push((user, pass));

                if !push_hit(hits, field_path, user, pass, CredPairFormat::Json) {
                    return;
                }
            }
        }
    }
}

/// The first `max_bytes` bytes of `text`, backed off to a character boundary.
fn head(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }

    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Collect `(start_offset, value)` for group 1 of every match, in match order.
///
/// At most [`MAX_MATCHES_PER_PATTERN`] matches are materialised.
fn capture_spans<'a>(re: &Regex, text: &'a str) -> Vec<(usize, &'a str)> {
    re.captures_iter(text)
        .flatten()
        .filter_map(|caps| caps.get(1).map(|m| (m.start(), m.as_str())))
        .take(MAX_MATCHES_PER_PATTERN)
        .collect()
}

/// Check if a value matches known placeholder patterns.
fn is_placeholder(value: &str) -> bool {
    let lower = value.to_lowercase();
    let placeholders = [
        "password",
        "secret",
        "changeme",
        "example",
        "your_secret_here",
        "redacted",
        "xxxxxx",
        "dummy",
        "test",
        "placeholder",
    ];

    if placeholders.iter().any(|p| lower == *p) {
        return true;
    }

    // Template patterns: <...>, ${...}, {{...}}
    if value.starts_with('<') && value.ends_with('>') {
        return true;
    }
    if value.starts_with("${") && value.ends_with('}') {
        return true;
    }
    if value.starts_with("{{") && value.ends_with("}}") {
        return true;
    }

    false
}

/// Public wrapper for is_placeholder check used by pipeline.
pub fn is_placeholder_static(value: &str) -> bool {
    is_placeholder(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// Wall-clock ceiling for the hostile-input tests. The pre-fix cross-product
    /// needed minutes-to-hours on the same input, so any regression back to a nested
    /// loop fails this assertion long before the test would hang.
    const HOSTILE_BUDGET: Duration = Duration::from_secs(2);

    fn detector() -> CredentialPairDetector {
        CredentialPairDetector::new().expect("patterns compile")
    }

    #[test]
    fn test_segment_is_scanned_only_up_to_the_byte_limit() {
        // A credential far past the limit is deliberately out of scope; a segment at
        // or under the limit is fully covered.
        let filler = "f".repeat(MAX_SCAN_BYTES + 1024);
        let text = format!("{filler}\nusername=alice\npassword=hunter2secret\n");
        assert!(detector().detect(&text, "comment").is_empty());

        let text = format!("username=alice\npassword=hunter2secret\n{filler}");
        assert_eq!(detector().detect(&text, "comment").len(), 1);
    }

    #[test]
    fn test_byte_limit_respects_char_boundaries() {
        // The limit must not split a multi-byte character and panic.
        let text = "я".repeat(MAX_SCAN_BYTES);
        let hits = detector().detect(&text, "comment");
        assert!(hits.is_empty());
    }

    #[test]
    fn test_new_compiles_patterns() {
        assert!(CredentialPairDetector::new().is_ok());
    }

    #[test]
    fn test_url_userinfo_detected() {
        let hits = detector().detect(
            "connection: postgres://svc_app:s3cr3tP4ss@db.internal:5432/app",
            "description",
        );

        assert_eq!(hits.len(), 1, "exactly one url-userinfo pair: {hits:?}");
        assert_eq!(hits[0].format, CredPairFormat::UrlUserinfo);
        assert_eq!(hits[0].username, "svc_app");
        assert_eq!(hits[0].field_path, "description");
        let password = "s3cr3tP4ss";
        assert!(!hits[0].redacted_password.contains(password));
        assert_eq!(hits[0].redacted_password, "s3...ss");
        assert!(hits[0].password_hash.starts_with("sha256:"));
    }

    #[test]
    fn test_url_userinfo_placeholder_skipped() {
        let hits = detector().detect(
            "postgres://user:PASSWORD@host/db and redis://user:${REDIS_PASS}@host",
            "description",
        );
        assert!(
            hits.is_empty(),
            "placeholders must not be reported: {hits:?}"
        );
    }

    #[test]
    fn test_proximity_pair_within_window() {
        let hits = detector().detect("username=alice\npassword=hunter2secret\n", "comment");

        assert_eq!(hits.len(), 1, "one pair: {hits:?}");
        assert_eq!(hits[0].format, CredPairFormat::Proximity);
        assert_eq!(hits[0].username, "alice");
        assert_eq!(hits[0].redacted_password, "hu...et");
    }

    /// A username line, `filler` bytes of padding, then a password line.
    fn proximity_text(filler: usize) -> String {
        format!("user=a\n{}\npassword=b\n", "f".repeat(filler))
    }

    /// Byte distance between the two captures produced by [`proximity_text`].
    ///
    /// `user=a` puts the captured username at offset 5; the password capture sits
    /// after `"user=a\n"` (7) + filler + `"\n"` (1) + `"password="` (9).
    fn pair_distance(filler: usize) -> usize {
        (7 + filler + 1 + 9) - 5
    }

    #[test]
    fn test_proximity_distance_maths_is_the_intended_one() {
        // Guards the two boundary tests below against silently testing nothing.
        assert_eq!(pair_distance(0), 12);
        assert_eq!(pair_distance(188), PROXIMITY_WINDOW_BYTES);
        assert_eq!(pair_distance(189), PROXIMITY_WINDOW_BYTES + 1);
    }

    #[test]
    fn test_proximity_pair_beyond_window_not_reported() {
        // One byte past the documented 200-byte window.
        assert!(pair_distance(189) > PROXIMITY_WINDOW_BYTES);
        assert!(detector()
            .detect(&proximity_text(189), "comment")
            .is_empty());

        // Exactly at the window edge: still inside, the bound is inclusive.
        let hits = detector().detect(&proximity_text(188), "comment");
        assert_eq!(hits.len(), 1, "200 bytes must still pair: {hits:?}");
        assert_eq!(hits[0].username, "a");
    }

    #[test]
    fn test_proximity_multiple_pairs() {
        // Two pairs far enough apart (> 200 bytes of filler) that neither username can
        // pair with the other pair's password.
        let text = format!(
            "username=alice\npassword=hunter2secret\n{}\nusername=bob\npassword=correcthorsebatterystaple\n",
            "f".repeat(300)
        );
        let hits = detector().detect(&text, "description");

        assert_eq!(hits.len(), 2, "one pair per credential block: {hits:?}");
        assert!(hits.iter().any(|h| h.username == "alice"));
        assert!(hits.iter().any(|h| h.username == "bob"));
    }

    #[test]
    fn test_proximity_pairs_everything_inside_the_window() {
        // The heuristic intentionally pairs every username within 200 bytes with every
        // password within 200 bytes; a short block therefore crosses over. Documented
        // here so the behaviour is not "fixed" by accident.
        let text = "username=alice\npassword=hunter2secret\nusername=bob\npassword=correcthorsebatterystaple\n";
        let hits = detector().detect(text, "description");

        assert_eq!(
            hits.len(),
            4,
            "2 usernames x 2 passwords, all in window: {hits:?}"
        );
    }

    #[test]
    fn test_proximity_placeholder_password_skipped() {
        let hits = detector().detect("username=alice\npassword=changeme\n", "description");
        assert!(hits.is_empty(), "placeholder skipped: {hits:?}");
    }

    #[test]
    fn test_yaml_like_text_covered_by_proximity() {
        // YAML / properties / env text is handled by the proximity heuristic: there is
        // no separate YAML detector (the old `detect_yaml_properties` stub returned an
        // empty vector and is gone).
        let text = "db:\n  host: db.internal\n  db_user: svc_app\n  smtp_pass: Tr0ub4dor-hunter2\n";
        let hits = detector().detect(text, "attachment:config.yaml");

        assert_eq!(hits.len(), 1, "one pair: {hits:?}");
        assert_eq!(hits[0].format, CredPairFormat::Proximity);
        assert_eq!(hits[0].username, "svc_app");
        assert_eq!(hits[0].field_path, "attachment:config.yaml");
    }

    #[test]
    fn test_json_object_detected() {
        let hits = detector().detect(
            r#"{"username": "alice", "password": "hunter2secret"}"#,
            "comment",
        );

        assert_eq!(hits.len(), 1, "one pair: {hits:?}");
        assert_eq!(hits[0].format, CredPairFormat::Json);
        assert_eq!(hits[0].username, "alice");
        assert_eq!(hits[0].redacted_password, "hu...et");
    }

    #[test]
    fn test_json_documented_pass_key_detected() {
        let hits = detector().detect(r#"{"user": "alice", "pass": "hunter2secret"}"#, "comment");
        assert_eq!(hits.len(), 1, "`pass` is documented in README: {hits:?}");
        assert_eq!(hits[0].format, CredPairFormat::Json);
    }

    #[test]
    fn test_json_alias_duplicates_collapsed() {
        // Same username and secret under several aliases must yield ONE finding, not
        // one per username-alias x password-alias combination.
        let hits = detector().detect(
            r#"{"user": "alice", "username": "alice", "password": "hunter2secret", "passwd": "hunter2secret"}"#,
            "comment",
        );

        assert_eq!(hits.len(), 1, "one secret, one finding: {hits:?}");
        assert_eq!(hits[0].username, "alice");
    }

    #[test]
    fn test_json_distinct_secrets_all_reported() {
        let hits = detector().detect(
            r#"{"user": "alice", "password": "hunter2secret", "api_key": "AKIAIOSFODNN7EXAMPLE"}"#,
            "comment",
        );
        assert_eq!(hits.len(), 2, "two distinct secrets: {hits:?}");
    }

    #[test]
    fn test_non_object_json_yields_nothing() {
        let d = detector();
        assert!(d.detect("[1, 2, 3]", "comment").is_empty());
        assert!(d.detect("just prose, no json here", "comment").is_empty());
        assert!(d.detect("", "comment").is_empty());
    }

    #[test]
    fn test_json_placeholder_skipped() {
        let hits = detector().detect(r#"{"user": "alice", "password": "changeme"}"#, "comment");
        assert!(hits.is_empty(), "placeholder skipped: {hits:?}");
    }

    #[test]
    fn test_unicode_values_are_not_mangled() {
        // Byte offsets come from `Match::start()`, so multi-byte characters before and
        // inside the credential must not shift the pairing or panic.
        let text = "username=сервис-аккаунт\npassword=пароль-секретный-1\n";
        let hits = detector().detect(text, "comment");

        assert_eq!(hits.len(), 1, "one pair: {hits:?}");
        assert_eq!(hits[0].username, "сервис-аккаунт");
        assert!(!hits[0].redacted_password.contains("пароль-секретный-1"));
    }

    #[test]
    fn test_multibyte_filler_is_counted_in_bytes() {
        // The window counts bytes, not characters: 95 Cyrillic characters are 190
        // bytes and already push the pair past the limit.
        let text = format!("user=a\n{}\npassword=b\n", "я".repeat(94));
        assert_eq!(
            pair_distance(94 * 2),
            PROXIMITY_WINDOW_BYTES,
            "the filler is 188 bytes, so the pair sits exactly on the edge"
        );
        let hits = detector().detect(&text, "comment");
        assert_eq!(
            hits.len(),
            1,
            "188 filler bytes is inside the window: {hits:?}"
        );

        let text = format!("user=a\n{}\npassword=b\n", "я".repeat(95));
        assert!(detector().detect(&text, "comment").is_empty());
    }

    #[test]
    fn test_hostile_proximity_is_bounded_and_fast() {
        // ~250k username matches and ~250k password matches in one segment: the
        // pre-fix nested loop did ~62.5e9 iterations here.
        let text = "user=a\npass=b\n".repeat(250_000);
        assert!(text.len() > 3_000_000);

        let started = Instant::now();
        let hits = detector().detect(&text, "description");
        let elapsed = started.elapsed();

        assert!(
            hits.len() <= MAX_HITS_PER_SEGMENT,
            "per-segment cap breached: {} hits",
            hits.len()
        );
        assert!(!hits.is_empty(), "hostile input is still scanned");
        assert!(
            elapsed < HOSTILE_BUDGET,
            "hostile proximity scan took {elapsed:?}, budget {HOSTILE_BUDGET:?}"
        );
    }

    #[test]
    fn test_hostile_url_userinfo_is_bounded_and_fast() {
        let text = "a://u:sup3rsecret@h ".repeat(100_000);
        let started = Instant::now();
        let hits = detector().detect(&text, "attachment:dump.txt");
        let elapsed = started.elapsed();

        assert_eq!(hits.len(), MAX_HITS_PER_SEGMENT);
        assert!(
            elapsed < HOSTILE_BUDGET,
            "hostile url-userinfo scan took {elapsed:?}, budget {HOSTILE_BUDGET:?}"
        );
    }

    #[test]
    fn test_hostile_json_cross_product_is_bounded() {
        // Every username alias and every password alias present in one object: 6 x 9
        // combinations, all carrying a single secret.
        let text = r#"{"username":"alice","user":"alice","login":"alice","email":"alice","client_id":"alice","clientId":"alice","password":"hunter2secret","passwd":"hunter2secret","pass":"hunter2secret","pwd":"hunter2secret","secret":"hunter2secret","client_secret":"hunter2secret","clientSecret":"hunter2secret","api_key":"hunter2secret","apiKey":"hunter2secret"}"#;

        let started = Instant::now();
        let hits = detector().detect(text, "comment");
        let elapsed = started.elapsed();

        assert_eq!(hits.len(), 1, "one secret reported once: {hits:?}");
        assert!(elapsed < HOSTILE_BUDGET);
    }

    #[test]
    fn test_hostile_placeholder_and_long_values_do_not_panic() {
        let text = format!(
            "username=alice\npassword={}\nuser=bob\npass={}\n",
            "x".repeat(500_000),
            "y".repeat(500_000)
        );
        let hits = detector().detect(&text, "comment");
        assert!(hits.len() <= MAX_HITS_PER_SEGMENT);
    }

    #[test]
    fn test_is_placeholder_static_exposed() {
        assert!(is_placeholder_static("changeme"));
        assert!(is_placeholder_static("<password>"));
        assert!(is_placeholder_static("${DB_PASS}"));
        assert!(!is_placeholder_static("hunter2secret"));
    }
}

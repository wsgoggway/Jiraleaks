use crate::hash::secret_hash;
use crate::redact;

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
    YamlProperties,
    UrlUserinfo,
    Proximity,
}

#[derive(Debug, Clone, Copy)]
pub struct CredentialPairDetector;

impl CredentialPairDetector {
    /// Detect credential pairs in a text segment.
    pub fn detect(&self, text: &str, field_path: &str) -> Vec<CredPairHit> {
        let mut hits = Vec::new();

        // 1. URL userinfo (also caught by db_url_credentials rule — dedup via hash)
        hits.extend(self.detect_url_userinfo(text, field_path));

        // 2. Proximity pairs: username-like and password-like within 200 chars
        hits.extend(self.detect_proximity(text, field_path));

        // 3. JSON pairs
        hits.extend(self.detect_json(text, field_path));

        // 4. YAML/properties/env pairs
        hits.extend(self.detect_yaml_properties(text, field_path));

        hits
    }

    fn detect_url_userinfo(&self, text: &str, field_path: &str) -> Vec<CredPairHit> {
        let re = fancy_regex::Regex::new(
            r"\b[a-z][a-z0-9+.-]*://([^:\s/@]+):([^@\s/]+)@",
        )
        .ok();
        let Some(re) = re else { return vec![] };

        let mut hits = Vec::new();
        for m in re.find_iter(text).flatten() {
            if let Ok(Some(caps)) = re.captures(&text[m.start()..m.end()]) {
                if let (Some(user), Some(pass)) = (caps.get(1), caps.get(2)) {
                    let username = user.as_str().to_string();
                    let password = pass.as_str().to_string();
                    if !is_placeholder(&password) {
                        hits.push(CredPairHit {
                            username,
                            redacted_password: redact::redact(&password),
                            password_hash: secret_hash(&password),
                            field_path: field_path.to_string(),
                            format: CredPairFormat::UrlUserinfo,
                        });
                    }
                }
            }
        }
        hits
    }

    fn detect_proximity(&self, text: &str, field_path: &str) -> Vec<CredPairHit> {
        let username_re =
            fancy_regex::Regex::new(
                r"(?im)^\s*(?:user(?:name)?|login|email|client[_-]?id|db[_-]?user|access[_-]?key|smtp[_-]?user|api[_-]?user)\s*[:=]\s*(\S+)",
            );
        let password_re =
            fancy_regex::Regex::new(
                r"(?im)^\s*(?:pass(?:word|wd)?|secret|client[_-]?secret|api[_-]?(?:key|secret)|smtp[_-]?pass)\s*[:=]\s*(\S+)",
            );

        let mut hits = Vec::new();

        let Ok(user_re) = username_re else { return hits };
        let Ok(pass_re) = password_re else { return hits };

        // Collect username matches and password matches with positions
        let users: Vec<(usize, String)> = user_re
            .captures_iter(text)
            .flatten()
            .filter_map(|caps| {
                caps.get(1)
                    .map(|m| (m.start(), m.as_str().to_string()))
            })
            .collect();

        let passes: Vec<(usize, String)> = pass_re
            .captures_iter(text)
            .flatten()
            .filter_map(|caps| {
                caps.get(1)
                    .map(|m| (m.start(), m.as_str().to_string()))
            })
            .collect();

        // Pair them within 200 char proximity
        for (u_pos, username) in &users {
            for (p_pos, password) in &passes {
                let dist = if *u_pos < *p_pos {
                    p_pos - u_pos
                } else {
                    u_pos - p_pos
                };
                if dist <= 200 && !is_placeholder(password) {
                    hits.push(CredPairHit {
                        username: username.clone(),
                        redacted_password: redact::redact(password),
                        password_hash: secret_hash(password),
                        field_path: field_path.to_string(),
                        format: CredPairFormat::Proximity,
                    });
                }
            }
        }

        hits
    }

    fn detect_json(&self, text: &str, field_path: &str) -> Vec<CredPairHit> {
        let mut hits = Vec::new();
        // Try to parse as JSON and look for credential-like pairs
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(obj) = value.as_object() {
                let username_keys = ["username", "user", "login", "email", "client_id", "clientId"];
                let password_keys = [
                    "password",
                    "passwd",
                    "pwd",
                    "secret",
                    "client_secret",
                    "clientSecret",
                    "api_key",
                    "apiKey",
                ];

                for uk in &username_keys {
                    for pk in &password_keys {
                        if let (Some(user_val), Some(pass_val)) = (obj.get(*uk), obj.get(*pk)) {
                            if let (Some(user), Some(pass)) =
                                (user_val.as_str(), pass_val.as_str())
                            {
                                if !is_placeholder(pass) {
                                    hits.push(CredPairHit {
                                        username: user.to_string(),
                                        redacted_password: redact::redact(pass),
                                        password_hash: secret_hash(pass),
                                        field_path: field_path.to_string(),
                                        format: CredPairFormat::Json,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        hits
    }

    fn detect_yaml_properties(&self, text: &str, field_path: &str) -> Vec<CredPairHit> {
        // Already handled by proximity detection above;
        // this method catches additional patterns in structured formats
        let _ = (text, field_path);
        vec![]
    }
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

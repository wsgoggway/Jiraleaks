use serde_json::Value;

/// Extracted text segment with its field path.
#[derive(Debug, Clone)]
pub struct TextSegment {
    pub field_path: String,
    pub text: String,
    pub source_type: SourceType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    Description,
    Comment,
    Attachment,
    CustomField,
}

/// Extracts text from Jira issue fields.
/// Handles both wiki markup (Server/DC) and ADF (Cloud) formats.
#[derive(Debug, Clone)]
pub struct TextExtractor {
    max_text_size_kb: usize,
}

impl TextExtractor {
    pub fn new(max_text_size_kb: usize) -> Self {
        Self { max_text_size_kb }
    }

    pub fn extract(&self, _issue_key: &str, fields: &Value) -> Vec<TextSegment> {
        let mut segments = Vec::new();
        self.walk_fields(fields, "", &mut segments);
        segments
    }

    fn walk_fields(&self, value: &Value, path: &str, segments: &mut Vec<TextSegment>) {
        if let Value::Object(map) = value {
            for (key, val) in map {
                let new_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                self.walk_value(&new_path, val, segments);
            }
        }
    }

    fn walk_value(&self, path: &str, value: &Value, segments: &mut Vec<TextSegment>) {
        match value {
            Value::String(s) => {
                let source_type = classify_path(path);
                let text = self.truncate(s);
                segments.push(TextSegment {
                    field_path: path.to_string(),
                    text,
                    source_type,
                });
            }
            Value::Array(arr) => {
                for (i, val) in arr.iter().enumerate() {
                    let indexed = format!("{path}[{i}]");
                    self.walk_value(&indexed, val, segments);
                }
            }
            Value::Object(_) => {
                self.walk_fields(value, path, segments);
            }
            _ => {}
        }
    }

    fn truncate(&self, text: &str) -> String {
        let max_bytes = self.max_text_size_kb.saturating_mul(1024);
        if text.len() <= max_bytes {
            text.to_string()
        } else {
            // Never slice in the middle of a multi-byte character: a Cyrillic
            // or emoji payload must not panic the scanner.
            let cut_at = text.floor_char_boundary(max_bytes);
            tracing::warn!(
                original_len = text.len(),
                max_bytes,
                truncated_to = cut_at,
                "Text field truncated"
            );
            text[..cut_at].to_string()
        }
    }
}

fn classify_path(path: &str) -> SourceType {
    if path.starts_with("comment") || path.contains(".comment") {
        SourceType::Comment
    } else if path.starts_with("attachment") || path.contains(".attachment") {
        SourceType::Attachment
    } else if path.starts_with("description") {
        SourceType::Description
    } else {
        SourceType::CustomField
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_simple_fields() {
        let extractor = TextExtractor::new(2048);
        let fields = json!({
            "summary": "Test issue",
            "description": "Contains AKIAIOSFODNN7EXAMPLE",
            "customfield_10001": "some custom value",
            "comment": {
                "comments": [
                    {"body": "A comment with gh_token"},
                    {"body": "Another comment"}
                ]
            }
        });
        let segments = extractor.extract("TEST-1", &fields);
        assert!(segments
            .iter()
            .any(|s| s.text.contains("AKIAIOSFODNN7EXAMPLE")));
        assert!(segments.iter().any(|s| s.text.contains("gh_token")));
        assert_eq!(segments.len(), 5);
    }

    #[test]
    fn test_truncation() {
        let extractor = TextExtractor::new(1);
        let long_text = "A".repeat(2000);
        let fields = json!({"description": long_text});
        let segments = extractor.extract("T-1", &fields);
        assert_eq!(segments[0].text.len(), 1024);
    }

    #[test]
    fn test_truncation_on_multibyte_boundary_does_not_panic() {
        let extractor = TextExtractor::new(1);
        // 2 bytes per character: byte 1024 lands inside the 512th character.
        let long_text = "я".repeat(1000);
        let fields = json!({"description": long_text});
        let segments = extractor.extract("T-1", &fields);
        assert!(segments[0].text.len() <= 1024);
        assert_eq!(segments[0].text, "я".repeat(512));
    }

    #[test]
    fn test_truncation_with_emoji_does_not_panic() {
        let extractor = TextExtractor::new(1);
        // 4 bytes per emoji: byte 1024 lands inside the 256th emoji.
        let long_text = "🔥".repeat(500);
        let fields = json!({"description": long_text});
        let segments = extractor.extract("T-1", &fields);
        assert!(segments[0].text.len() <= 1024);
        assert_eq!(segments[0].text, "🔥".repeat(256));
    }
}

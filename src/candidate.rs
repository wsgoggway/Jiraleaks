//! The single owner of the candidate verdict: which filter rejected a candidate,
//! and why.
//!
//! Before this module the filter chain was split across three places — the rule
//! filters in [`crate::rules`], the post-scan steps in [`crate::pipeline`], and a
//! second placeholder dictionary in [`crate::credpair`] — and every rejection was
//! a bare `return false` that left no trace. The chain now lives here, split into
//! two halves that mirror the pipeline it serves:
//!
//! 1. [`Judge::rule_filters`] — everything a rule itself demands of a value
//!    (`min_length`, `min_entropy`, `denylist`, placeholder / `ignore_if_contains`,
//!    char classes, `context_keywords`, `validator`). Run inside
//!    [`crate::rules::RulesEngine::scan`], so a value that fails is never a hit.
//! 2. [`Judge::finalize`] — everything the pipeline decides after the scan
//!    (allowlist, the placeholder check on the surviving value, the global context
//!    boost, [`crate::finding::adjust_confidence`] and the `min_confidence`
//!    threshold). See [`Judge::finalize`] for the order, which is a contract.
//!
//! Both halves return a [`DropReason`] instead of a `false`: a rejected candidate
//! is now explainable in a debug log (`reason = %reason`) where before it simply
//! disappeared. Neither half prints, or ever carries, the secret itself.
//!
//! The two placeholder dictionaries that used to exist here — the rule-level
//! `contains` list in `rules.rs` and the equality list inside `credpair.rs` — are
//! one table now ([`PLACEHOLDER_WORDS`]), with the two original semantics kept as
//! explicit [`PlaceholderPolicy`] modes.

use std::fmt;
use std::ops::Range;

use crate::entropy;
use crate::finding::{adjust_confidence, Confidence};
use crate::redact;
use crate::rules::CompiledRule;
use crate::validators;

/// Byte radius of the context window inspected around a candidate value.
///
/// One constant for every window in the crate: the rule-level
/// [`context_keywords`] check and the global [`CONTEXT_WORDS`] boost must look at
/// the same text, or a rule and the pipeline would disagree about the candidate's
/// neighbourhood.
pub const CONTEXT_RADIUS: usize = 50;

/// Shannon entropy above which a value counts as "random-looking" for the global
/// confidence boost in [`Judge::finalize`].
///
/// Deliberately not the same knob as a rule's `min_entropy`, which *rejects* a
/// value rather than boosting it.
pub const ENTROPY_BOOST_THRESHOLD: f64 = 3.5;

/// Words that raise a candidate's confidence when they appear near it.
///
/// This is the crate's only copy of the list. The boost never rejects anything —
/// see [`Judge::finalize`] — so a missing word only ever costs confidence.
pub const CONTEXT_WORDS: &[&str] = &[
    "secret",
    "key",
    "token",
    "password",
    "passwd",
    "pwd",
    "credential",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
];

/// Why a candidate was rejected.
///
/// Every variant carries the numbers that made the check fail, so a debug log
/// explains the rejection without a re-run. No variant carries the value itself:
/// a `DropReason` is safe to log.
#[derive(Debug, Clone, PartialEq)]
pub enum DropReason {
    /// Value shorter than the rule's `min_length`, in characters.
    TooShort { min: usize, got: usize },
    /// Shannon entropy below the rule's `min_entropy`, in bits per character.
    LowEntropy { min: f64, got: f64 },
    /// Value contains one of the rule's `denylist` entries.
    Denylisted,
    /// Value is a placeholder: it matched the shared dictionary (rule-level
    /// `contains` semantics or the post-scan `exact` semantics, depending on which
    /// half of the chain rejected it).
    Placeholder,
    /// Value holds fewer characters of the named class than the rule requires.
    /// `required` is the rule field name (`min_digits`, `min_uppercase`,
    /// `min_lowercase`, `min_special_chars`).
    MissingCharClass {
        required: &'static str,
        min: usize,
        got: usize,
    },
    /// None of the rule's `context_keywords` appears in the window around the
    /// value.
    MissingContextKeyword,
    /// The rule's `validator` rejected the value.
    ValidatorRejected,
    /// An allowlist entry suppressed the value. `reason` is the entry's audit
    /// note when the allowlist can supply it.
    Allowlisted { reason: Option<String> },
    /// Value survived every filter but its adjusted confidence sits below the
    /// configured `min_confidence`.
    BelowMinConfidence { min: Confidence, got: Confidence },
}

impl fmt::Display for DropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DropReason::TooShort { min, got } => {
                write!(f, "too short: {got} characters, minimum {min}")
            }
            DropReason::LowEntropy { min, got } => write!(
                f,
                "entropy {got:.2} bits/char below the rule minimum {min:.2}"
            ),
            DropReason::Denylisted => f.write_str("matched the rule denylist"),
            DropReason::Placeholder => f.write_str("is a placeholder"),
            DropReason::MissingCharClass { required, min, got } => {
                write!(f, "{got} characters in class '{required}', minimum {min}")
            }
            DropReason::MissingContextKeyword => write!(
                f,
                "no context keyword within {CONTEXT_RADIUS} bytes of the value"
            ),
            DropReason::ValidatorRejected => f.write_str("rejected by the rule validator"),
            DropReason::Allowlisted { reason } => match reason {
                Some(reason) => write!(f, "allowlisted (reason: {reason})"),
                None => f.write_str("allowlisted"),
            },
            DropReason::BelowMinConfidence { min, got } => {
                write!(f, "confidence '{got}' is below the minimum '{min}'")
            }
        }
    }
}

/// The outcome of judging one candidate.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// The candidate becomes a finding.
    Keep {
        /// Confidence after [`adjust_confidence`], the value the finding carries.
        confidence: Confidence,
        /// Whether a [`CONTEXT_WORDS`] word was found in the window around the
        /// value — the flag that fed `adjust_confidence`. Reported so a caller can
        /// tell an earned confidence from a boosted one; it never changes the
        /// verdict on its own.
        boosted: bool,
    },
    /// The candidate is not a finding, for the stated reason.
    Drop(DropReason),
}

/// One candidate value to judge: the value, the text it was found in, and where.
///
/// A `Candidate` borrows; nothing is copied out of the scanned text.
#[derive(Clone)]
pub struct Candidate<'a> {
    /// The secret itself: the rule's capture group, or the whole match.
    pub value: &'a str,
    /// The scanned segment `value` was found in — the text the context windows of
    /// [`context_keywords`] and [`Judge::finalize`] are taken from.
    pub text: &'a str,
    /// Byte range of `value` **in `text`** (absolute offsets), as found by the
    /// scanner.
    pub value_span: Range<usize>,
    /// Extractor path of the scanned text (`description`,
    /// `comment.comments[0].body`, `attachment:dump.txt`).
    pub field_path: &'a str,
    /// Issue the candidate came from. Empty when the judge is called by the rules
    /// engine, which scans text without ever seeing an issue key; used only for
    /// the drop log, never for a decision.
    pub issue_key: &'a str,
}

/// Hand-written: `value` is a raw secret and `text` is the segment around it, so
/// `{:?}` must not print either (same reasoning as [`crate::rules::RawHit`]'s
/// masking `Debug`). The text is reported by length only.
impl fmt::Debug for Candidate<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Candidate")
            .field("value", &redact::redact(self.value))
            .field("text_len", &self.text.len())
            .field("value_span", &self.value_span)
            .field("field_path", &self.field_path)
            .field("issue_key", &self.issue_key)
            .finish()
    }
}

/// How a [`PlaceholderPolicy`] compares a value against the dictionary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceholderMode {
    /// Case-insensitive substring match — the rules engine's
    /// `ignore_if_contains` semantics: `xxxx-abcd` is a placeholder because it
    /// contains `xxxx`.
    Contains,
    /// Case-insensitive equality — the credential-pair detector's semantics: only
    /// the value `xxxx` itself is a placeholder, `xxxx-abcd` is a real secret.
    /// Template markers (`<...>`, `${...}`, `{{...}}`) count as placeholders too.
    Exact,
}

/// One entry of the shared placeholder dictionary: the word, and which modes it
/// belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaceholderWord {
    pub word: &'static str,
    /// Applies under [`PlaceholderMode::Contains`] (the rules engine's default
    /// `ignore_if_contains` list).
    pub contains: bool,
    /// Applies under [`PlaceholderMode::Exact`] (the credential-pair detector and
    /// the post-scan check in [`Judge::finalize`]).
    pub exact: bool,
}

impl PlaceholderWord {
    /// A word both readers knew.
    const fn shared(word: &'static str) -> Self {
        Self {
            word,
            contains: true,
            exact: true,
        }
    }

    /// A word only the rules engine knew.
    const fn rules_only(word: &'static str) -> Self {
        Self {
            word,
            contains: true,
            exact: false,
        }
    }

    /// A word only the credential-pair detector knew.
    const fn pair_only(word: &'static str) -> Self {
        Self {
            word,
            contains: false,
            exact: true,
        }
    }
}

/// The crate's only placeholder dictionary.
///
/// It is the union of the two lists that used to live apart: the 14 words of the
/// rules engine's default `ignore_if_contains` (`contains`) and the 10 words of the
/// credential-pair detector (`exact`). The entries are kept in their original
/// order, and each mode selects its own subset, so unifying the storage changed no
/// detection: `PlaceholderMode::Contains` yields exactly the old 14, `Exact`
/// exactly the old 10.
///
/// NOTE: no bare digit runs here — `Contains` semantics would reject any real token
/// embedding them (e.g. `1234567890:` telegram ids, `123456789012` slack
/// workspaces).
pub const PLACEHOLDER_WORDS: &[PlaceholderWord] = &[
    // The rules engine's default list, in its original order.
    PlaceholderWord::shared("example"),
    PlaceholderWord::shared("test"),
    PlaceholderWord::rules_only("sample"),
    PlaceholderWord::rules_only("demo"),
    PlaceholderWord::shared("dummy"),
    PlaceholderWord::shared("placeholder"),
    PlaceholderWord::shared("changeme"),
    PlaceholderWord::rules_only("your_key"),
    PlaceholderWord::rules_only("yourkey"),
    PlaceholderWord::rules_only("your-key"),
    PlaceholderWord::rules_only("xxxx"),
    PlaceholderWord::rules_only("foobar"),
    PlaceholderWord::shared("redacted"),
    PlaceholderWord::rules_only("fake"),
    // Words only the credential-pair detector knew, in its original order.
    PlaceholderWord::pair_only("password"),
    PlaceholderWord::pair_only("secret"),
    PlaceholderWord::pair_only("your_secret_here"),
    PlaceholderWord::pair_only("xxxxxx"),
];

/// A placeholder check bound to one mode of the shared dictionary.
///
/// Who uses which mode, and why the modes exist at all:
///
/// * `Contains` — the rules engine. [`CompiledRule::compile`] builds the
///   `ignore_if_contains` list a value is matched against from
///   [`PlaceholderPolicy::contains().words()`](PlaceholderPolicy::words), so the
///   default list has one source of truth. `rules.rs` matches the *whole effective
///   list* (defaults plus the rule's own entries), which is why the check itself
///   takes a word slice (see [`placeholder`]) instead of a policy.
/// * `Exact` — the credential-pair detector and the post-scan check inside
///   [`Judge::finalize`], both of which ask about a single value rather than about
///   text that may embed a marker.
///
/// The two modes are not interchangeable, and unifying them would change
/// detection: `xxxx` is a placeholder for the rules engine but a perfectly valid
/// (if weak) password for the pair detector, which is why the dictionary records
/// membership per mode instead of being one list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaceholderPolicy {
    mode: PlaceholderMode,
    words: &'static [PlaceholderWord],
}

impl PlaceholderPolicy {
    /// The rules engine's default `ignore_if_contains` policy.
    pub const fn contains() -> Self {
        Self {
            mode: PlaceholderMode::Contains,
            words: PLACEHOLDER_WORDS,
        }
    }

    /// The credential-pair detector's policy: equality, plus template markers.
    pub const fn exact() -> Self {
        Self {
            mode: PlaceholderMode::Exact,
            words: PLACEHOLDER_WORDS,
        }
    }

    pub const fn mode(&self) -> PlaceholderMode {
        self.mode
    }

    /// The dictionary this policy reads.
    pub const fn dictionary(&self) -> &'static [PlaceholderWord] {
        self.words
    }

    /// The words this policy's mode applies, in dictionary order.
    pub fn words(&self) -> impl Iterator<Item = &'static str> {
        let mode = self.mode;
        let words = self.words;
        words
            .iter()
            .filter(move |entry| entry.applies_to(mode))
            .map(|entry| entry.word)
    }

    /// Whether `value` is a placeholder under this policy.
    pub fn matches(&self, value: &str) -> bool {
        match self.mode {
            PlaceholderMode::Contains => {
                let lower = value.to_lowercase();
                self.words().any(|word| lower.contains(word))
            }
            PlaceholderMode::Exact => {
                let lower = value.to_lowercase();
                if self.words().any(|word| lower == word) {
                    return true;
                }
                // Template markers: a value that is nothing but a placeholder slot.
                // Part of the `Exact` mode only — the rules engine's
                // `ignore_if_contains` never treated `<...>` as a marker.
                is_template(value)
            }
        }
    }
}

impl PlaceholderWord {
    const fn applies_to(&self, mode: PlaceholderMode) -> bool {
        match mode {
            PlaceholderMode::Contains => self.contains,
            PlaceholderMode::Exact => self.exact,
        }
    }
}

/// Whether `value` is a template slot: `<...>`, `${...}` or `{{...}}`.
fn is_template(value: &str) -> bool {
    (value.starts_with('<') && value.ends_with('>'))
        || (value.starts_with("${") && value.ends_with('}'))
        || (value.starts_with("{{") && value.ends_with("}}"))
}

/// The window of `text` around `span`, grown by `radius` bytes on each side.
///
/// The crate's one implementation of that arithmetic: offsets are clamped into
/// `text` and backed off to character boundaries in both directions, so a span
/// that starts or ends inside a multi-byte character — or outside `text`
/// altogether — yields a valid slice instead of a panic. A span past the end of
/// `text` yields the empty tail.
pub fn context_window<'a>(text: &'a str, span: &Range<usize>, radius: usize) -> &'a str {
    let len = text.len();
    let start = text.floor_char_boundary(span.start.saturating_sub(radius).min(len));
    let end = text
        .ceil_char_boundary(span.end.saturating_add(radius).min(len))
        .max(start);
    &text[start..end]
}

// ── the individual checks ───────────────────────────────────────────────────
//
// Each one answers "may this candidate pass?" with `None` for yes and the reason
// for no, so the chain in `Judge` reads as a list of questions and a caller can
// run any single check on its own.

/// `rule.min_length`: character count, not bytes.
pub fn min_length(value: &str, min: Option<usize>) -> Option<DropReason> {
    let min = min?;
    let got = value.chars().count();
    (got < min).then_some(DropReason::TooShort { min, got })
}

/// `rule.min_entropy`: Shannon entropy in bits per character.
pub fn entropy(value: &str, min: Option<f64>) -> Option<DropReason> {
    let min = min?;
    let got = entropy::shannon(value);
    (got < min).then_some(DropReason::LowEntropy { min, got })
}

/// `rule.denylist`: case-insensitive substring match.
pub fn denylist(value: &str, denylist: &[String]) -> Option<DropReason> {
    if denylist.is_empty() {
        return None;
    }

    let lower = value.to_lowercase();
    denylist
        .iter()
        .any(|entry| lower.contains(&entry.to_lowercase()))
        .then_some(DropReason::Denylisted)
}

/// Placeholder / `ignore_if_contains`: case-insensitive substring match against an
/// explicit word list.
///
/// The list is a rule's *effective* `ignore_if_contains` — the shared dictionary in
/// [`PlaceholderMode::Contains`] form plus the rule's own entries (see
/// [`CompiledRule::compile`]) — which is why this takes words rather than a
/// [`PlaceholderPolicy`].
pub fn placeholder(value: &str, words: &[String]) -> Option<DropReason> {
    if words.is_empty() {
        return None;
    }

    let lower = value.to_lowercase();
    words
        .iter()
        .any(|word| lower.contains(&word.to_lowercase()))
        .then_some(DropReason::Placeholder)
}

/// `rule.validator`: the named validator accepts the value.
///
/// An unknown validator name accepts everything (see [`validators::validate`]).
pub fn validator(name: &str, value: &str) -> Option<DropReason> {
    (!validators::validate(name, value)).then_some(DropReason::ValidatorRejected)
}

/// The character-class requirements (`min_digits`, `min_uppercase`,
/// `min_lowercase`, `min_special_chars`), checked in that order.
///
/// Classes are counted over one pass; a character belongs to at most one class, and
/// only the rule's `special_chars` set counts as special.
pub fn char_classes(value: &str, rule: &CompiledRule) -> Option<DropReason> {
    let mut digits = 0usize;
    let mut upper = 0usize;
    let mut lower = 0usize;
    let mut special = 0usize;
    for c in value.chars() {
        if c.is_ascii_digit() {
            digits += 1;
        } else if c.is_ascii_uppercase() {
            upper += 1;
        } else if c.is_ascii_lowercase() {
            lower += 1;
        } else if rule.special_chars.contains(&c) {
            special += 1;
        }
    }

    let checks = [
        ("min_digits", rule.min_digits, digits),
        ("min_uppercase", rule.min_uppercase, upper),
        ("min_lowercase", rule.min_lowercase, lower),
        ("min_special_chars", rule.min_special_chars, special),
    ];
    for (required, min, got) in checks {
        if let Some(min) = min {
            if got < min {
                return Some(DropReason::MissingCharClass { required, min, got });
            }
        }
    }

    None
}

/// `rule.context_keywords`: at least one keyword appears within
/// [`CONTEXT_RADIUS`] bytes of the value.
///
/// A rule that declares keywords and finds none rejects the candidate — the
/// keywords are a requirement, not a boost. A rule with no keywords always passes.
pub fn context_keywords(
    text: &str,
    span: &Range<usize>,
    keywords: &[String],
) -> Option<DropReason> {
    if keywords.is_empty() {
        return None;
    }

    let window = context_window(text, span, CONTEXT_RADIUS).to_lowercase();
    let found = keywords
        .iter()
        .any(|keyword| window.contains(&keyword.to_lowercase()));

    (!found).then_some(DropReason::MissingContextKeyword)
}

/// Whether any [`CONTEXT_WORDS`] word sits within [`CONTEXT_RADIUS`] bytes of the
/// value — the global boost signal of [`Judge::finalize`].
pub fn has_context_word(text: &str, span: &Range<usize>) -> bool {
    let window = context_window(text, span, CONTEXT_RADIUS).to_lowercase();
    CONTEXT_WORDS.iter().any(|word| window.contains(word))
}

/// The two halves of the filter chain.
///
/// A judge holds no per-scan state, so one value serves the whole run.
#[derive(Debug, Clone, Copy)]
pub struct Judge {
    /// The dictionary the rules engine's default `ignore_if_contains` list is
    /// built from.
    rules_placeholders: PlaceholderPolicy,
    /// The dictionary and semantics of the post-scan placeholder check.
    value_placeholders: PlaceholderPolicy,
}

impl Default for Judge {
    fn default() -> Self {
        Self::new()
    }
}

impl Judge {
    pub const fn new() -> Self {
        Self {
            rules_placeholders: PlaceholderPolicy::contains(),
            value_placeholders: PlaceholderPolicy::exact(),
        }
    }

    /// The policy behind the rules engine's default placeholder list.
    pub const fn rules_placeholders(&self) -> PlaceholderPolicy {
        self.rules_placeholders
    }

    /// The policy of the post-scan placeholder check.
    pub const fn value_placeholders(&self) -> PlaceholderPolicy {
        self.value_placeholders
    }

    /// Half one: the filters a rule applies to a value it matched.
    ///
    /// This is what `RulesEngine::scan` uses to decide whether a regex match is a
    /// hit at all. The checks run in the order the rule declares them, and the
    /// first failure wins:
    ///
    /// 1. `min_length`
    /// 2. `min_entropy`
    /// 3. `denylist`
    /// 4. placeholder / `ignore_if_contains`
    /// 5. char classes (`min_digits`, `min_uppercase`, `min_lowercase`,
    ///    `min_special_chars`)
    /// 6. `context_keywords`
    /// 7. `validator`
    ///
    /// The order is a contract: it decides which [`DropReason`] a value that fails
    /// several checks reports, so reordering it changes what the debug logs say
    /// even when the kept set is identical.
    pub fn rule_filters(
        &self,
        rule: &CompiledRule,
        cand: &Candidate<'_>,
    ) -> Result<(), DropReason> {
        let value = cand.value;

        let reason = min_length(value, rule.min_length)
            .or_else(|| entropy(value, rule.min_entropy))
            .or_else(|| denylist(value, &rule.denylist))
            .or_else(|| placeholder(value, &rule.ignore_if_contains))
            .or_else(|| char_classes(value, rule))
            .or_else(|| context_keywords(cand.text, &cand.value_span, &rule.context_keywords))
            .or_else(|| rule.validator.as_deref().and_then(|v| validator(v, value)));

        match reason {
            Some(reason) => Err(reason),
            None => Ok(()),
        }
    }

    /// Half two: everything the pipeline decides about a surviving hit.
    ///
    /// The order below is a contract — it is the order the pipeline applied before
    /// this module existed, and it decides which reason a candidate that fails
    /// several steps reports:
    ///
    /// 1. **allowlist** — `Some(reason)` means the allowlist suppressed the value
    ///    and the verdict is [`DropReason::Allowlisted`]; nothing else runs. The
    ///    caller passes `None` for a value the allowlist did not match.
    /// 2. **placeholder** — the shared dictionary in
    ///    [`PlaceholderMode::Exact`] form. A placeholder does *not* drop the
    ///    candidate by itself: it forces the confidence to `low` through
    ///    [`adjust_confidence`], so a run whose `min_confidence` is `low` keeps it
    ///    (this is the historical behaviour, preserved deliberately).
    /// 3. **context boost** — whether a [`CONTEXT_WORDS`] word sits within
    ///    [`CONTEXT_RADIUS`] bytes of the value.
    /// 4. **`adjust_confidence`** — base confidence, the boost of step 3, entropy
    ///    above [`ENTROPY_BOOST_THRESHOLD`], and the placeholder flag of step 2.
    /// 5. **`min_confidence`** — a confidence below the configured floor drops the
    ///    candidate with [`DropReason::BelowMinConfidence`].
    ///
    /// `confidence` is the rule's own confidence (`low`/`medium`/`high` from the
    /// rule file), not a previous verdict. `rule_id` names the rule in the drop
    /// log; it never affects the decision.
    pub fn finalize(
        &self,
        rule_id: &str,
        confidence: Confidence,
        cand: &Candidate<'_>,
        allowlisted: Option<Option<String>>,
        min_confidence: Confidence,
    ) -> Verdict {
        if let Some(reason) = allowlisted {
            return self.drop(rule_id, cand, DropReason::Allowlisted { reason });
        }

        let is_placeholder = self.value_placeholders.matches(cand.value);
        let boosted = has_context_word(cand.text, &cand.value_span);
        let confidence = adjust_confidence(
            confidence,
            boosted,
            entropy::shannon(cand.value) > ENTROPY_BOOST_THRESHOLD,
            is_placeholder,
        );

        if confidence < min_confidence {
            return self.drop(
                rule_id,
                cand,
                DropReason::BelowMinConfidence {
                    min: min_confidence,
                    got: confidence,
                },
            );
        }

        Verdict::Keep {
            confidence,
            boosted,
        }
    }

    /// Log a rejection and turn it into a verdict.
    ///
    /// The log line is the point of this module: a dropped candidate used to vanish
    /// silently. It names the rule, the issue and the field, and never the value.
    fn drop(&self, rule_id: &str, cand: &Candidate<'_>, reason: DropReason) -> Verdict {
        tracing::debug!(
            rule_id = %rule_id,
            issue = %cand.issue_key,
            field_path = %cand.field_path,
            reason = %reason,
            "Candidate dropped"
        );
        Verdict::Drop(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate<'a>(value: &'a str, text: &'a str, span: Range<usize>) -> Candidate<'a> {
        Candidate {
            value,
            text,
            value_span: span,
            field_path: "description",
            issue_key: "APP-1",
        }
    }

    // ── context_window ──

    #[test]
    fn context_window_covers_the_whole_text_when_short() {
        let text = "key = secret";
        assert_eq!(context_window(text, &(6..12), CONTEXT_RADIUS), text);
    }

    #[test]
    fn context_window_stops_at_the_start_of_the_text() {
        let text = format!("{}tail", "x".repeat(200));
        let window = context_window(text.as_str(), &(200..204), CONTEXT_RADIUS);
        assert_eq!(window.len(), CONTEXT_RADIUS + 4);
        assert!(window.ends_with("tail"));
    }

    #[test]
    fn context_window_stops_at_the_end_of_the_text() {
        let text = format!("head{}", "x".repeat(200));
        let window = context_window(text.as_str(), &(0..4), CONTEXT_RADIUS);
        assert_eq!(window.len(), CONTEXT_RADIUS + 4);
        assert!(window.starts_with("head"));
    }

    #[test]
    fn context_window_does_not_split_cyrillic_characters() {
        // Every character is two bytes, so a ±50 byte window lands mid-character
        // and must be backed off to a boundary.
        let text = "я".repeat(100);
        let window = context_window(text.as_str(), &(100..102), CONTEXT_RADIUS);
        assert!(text.contains(window));
        assert!(window.chars().all(|c| c == 'я'));
    }

    #[test]
    fn context_window_clamps_a_span_past_the_end() {
        let text = "short";
        assert_eq!(context_window(text, &(100..200), CONTEXT_RADIUS), "");
        // A reversed span is not a shape the scanner produces; it must still be a
        // valid slice rather than a panic.
        #[allow(clippy::reversed_empty_ranges)]
        let reversed = 100..50;
        assert_eq!(context_window(text, &reversed, CONTEXT_RADIUS), "");
    }

    #[test]
    fn context_window_of_an_empty_text_is_empty() {
        assert_eq!(context_window("", &(0..0), CONTEXT_RADIUS), "");
    }

    // ── the shared dictionary ──

    #[test]
    fn both_modes_read_one_dictionary() {
        let contains = PlaceholderPolicy::contains();
        let exact = PlaceholderPolicy::exact();
        assert_eq!(
            contains.dictionary().as_ptr(),
            exact.dictionary().as_ptr(),
            "both policies must read the same table"
        );
        assert_eq!(contains.dictionary(), PLACEHOLDER_WORDS);
    }

    #[test]
    fn modes_select_their_original_word_sets() {
        let contains: Vec<&str> = PlaceholderPolicy::contains().words().collect();
        let exact: Vec<&str> = PlaceholderPolicy::exact().words().collect();

        assert_eq!(
            contains,
            vec![
                "example",
                "test",
                "sample",
                "demo",
                "dummy",
                "placeholder",
                "changeme",
                "your_key",
                "yourkey",
                "your-key",
                "xxxx",
                "foobar",
                "redacted",
                "fake",
            ],
            "the rules engine's default list is unchanged"
        );
        assert_eq!(
            exact,
            vec![
                "example",
                "test",
                "dummy",
                "placeholder",
                "changeme",
                "redacted",
                "password",
                "secret",
                "your_secret_here",
                "xxxxxx",
            ],
            "the credential-pair list is unchanged"
        );
    }

    #[test]
    fn contains_mode_is_substring_and_exact_mode_is_equality() {
        // A marker embedded in a longer value: rejected by the rules engine
        // (substring), kept by the pair detector (equality).
        assert!(PlaceholderPolicy::contains().matches("my-changeme-token"));
        assert!(!PlaceholderPolicy::exact().matches("my-changeme-token"));

        // Both modes are case-insensitive.
        assert!(PlaceholderPolicy::contains().matches("XXXX"));
        assert!(!PlaceholderPolicy::exact().matches("xxxx-abcd"));

        // A word only the pair detector knows is matched by equality only, and the
        // rules engine's list never held it at all.
        assert!(PlaceholderPolicy::exact().matches("your_secret_here"));
        assert!(!PlaceholderPolicy::exact().matches("prefix-your_secret_here"));
        assert!(!PlaceholderPolicy::contains().matches("your_secret_here"));
    }

    #[test]
    fn templates_are_exact_mode_only() {
        for value in ["<password>", "${DB_PASS}", "{{ password }}"] {
            assert!(PlaceholderPolicy::exact().matches(value), "{value}");
            assert!(!PlaceholderPolicy::contains().matches(value), "{value}");
        }
        assert!(!PlaceholderPolicy::exact().matches("<unclosed"));
        assert!(!PlaceholderPolicy::exact().matches("hunter2secret"));
    }

    // ── checks ──

    #[test]
    fn min_length_counts_characters() {
        assert_eq!(
            min_length("яя", Some(3)),
            Some(DropReason::TooShort { min: 3, got: 2 })
        );
        assert_eq!(min_length("яяя", Some(3)), None);
        assert_eq!(min_length("", None), None);
    }

    #[test]
    fn entropy_reports_both_numbers() {
        let reason = entropy("aaaaaaaaaa", Some(3.0)).expect("low entropy");
        match reason {
            DropReason::LowEntropy { min, got } => {
                assert_eq!(min, 3.0);
                assert!(got < 3.0);
            }
            other => panic!("wrong reason: {other:?}"),
        }
        assert_eq!(entropy("kX7mP2qR9sT4vW1y", Some(3.0)), None);
    }

    #[test]
    fn denylist_and_placeholder_match_case_insensitively() {
        let words = vec!["EXAMPLE".to_string()];
        assert_eq!(
            placeholder("my-example-key", &words),
            Some(DropReason::Placeholder)
        );
        assert_eq!(placeholder("my-real-key", &words), None);

        let deny = vec!["open".to_string()];
        assert_eq!(denylist("OPEN-sesame", &deny), Some(DropReason::Denylisted));
        assert_eq!(denylist("closed", &deny), None);
        assert_eq!(denylist("anything", &[]), None);
    }

    #[test]
    fn context_keywords_need_a_keyword_in_the_window() {
        let keywords = vec!["secret".to_string()];
        let text = "secret = abcdef";
        assert_eq!(context_keywords(text, &(9..15), &keywords), None);

        let far = format!("{}value", "x".repeat(200));
        assert_eq!(
            context_keywords(far.as_str(), &(200..205), &keywords),
            Some(DropReason::MissingContextKeyword)
        );
        // A rule without keywords never rejects.
        assert_eq!(context_keywords(text, &(9..15), &[]), None);
    }

    #[test]
    fn has_context_word_uses_the_global_list() {
        assert!(has_context_word("api_key = abc", &(10..13)));
        assert!(!has_context_word("abcdef", &(0..3)));
    }

    #[test]
    fn drop_reason_display_is_specific() {
        assert_eq!(
            DropReason::TooShort { min: 8, got: 3 }.to_string(),
            "too short: 3 characters, minimum 8"
        );
        assert_eq!(
            DropReason::MissingCharClass {
                required: "min_digits",
                min: 3,
                got: 1
            }
            .to_string(),
            "1 characters in class 'min_digits', minimum 3"
        );
        assert_eq!(
            DropReason::Allowlisted {
                reason: Some("docs".into())
            }
            .to_string(),
            "allowlisted (reason: docs)"
        );
        assert_eq!(
            DropReason::BelowMinConfidence {
                min: Confidence::High,
                got: Confidence::Low
            }
            .to_string(),
            "confidence 'low' is below the minimum 'high'"
        );
    }

    #[test]
    fn candidate_debug_never_prints_the_secret() {
        let text = "token = hunter2secret";
        let cand = candidate("hunter2secret", text, 8..21);
        let dbg = format!("{cand:?}");
        assert!(!dbg.contains("hunter2secret"), "leaked: {dbg}");
        assert!(dbg.contains("hu...et"));
        assert!(!dbg.contains(text), "the segment leaked: {dbg}");
    }
}

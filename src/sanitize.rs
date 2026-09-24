//! Neutralisation of attacker-controlled text for output sinks.
//!
//! Everything the scanner reports comes from Jira content written by other people:
//! issue keys, attachment names, field paths, comment bodies, and the snippets cut
//! out of them. For the operator's tooling that text is hostile input in two ways:
//!
//! * A terminal interprets control sequences, so an attachment named
//!   `\x1b[2K\x1b[1;32mCLEAN: no secrets found` can rewrite the lines a report just
//!   printed, and OSC 52 (`\x1b]52;c;<base64>\x07`) writes to the operator's
//!   clipboard. Both are printed verbatim by the summary report and by a plain
//!   `cat` of any report file.
//! * A spreadsheet treats `=`, `+`, `-` and `@` as the start of a formula, so a
//!   snippet of `=cmd|'/C calc'!A1` becomes command execution when the CSV report is
//!   opened in Excel or LibreOffice.
//!
//! The helpers here are deliberately conservative: ordinary text (including
//! non-ASCII text) passes through byte for byte, and only control characters and a
//! leading formula sigil are altered.

use std::borrow::Cow;

/// Longest body of a CSI (`ESC [`) sequence consumed before it is treated as
/// malformed. Real parameters are a handful of bytes.
const MAX_CSI_BODY_CHARS: usize = 64;

/// Longest body of an OSC/string-type sequence consumed before it is treated as
/// malformed. Real payloads (an OSC 52 clipboard write, an OSC 8 hyperlink) are at
/// most a few KiB.
const MAX_STRING_BODY_CHARS: usize = 8192;

/// Strip terminal control sequences and control characters from `text`.
///
/// Removes:
/// * CSI sequences (`ESC [` … final byte) and their 8-bit form (`U+009B`),
/// * OSC and the other string-type sequences (`ESC ]`, `ESC P`, `ESC ^`, `ESC _`,
///   and the 8-bit `U+0090`, `U+0098`, `U+009D`, `U+009E`, `U+009F`) together with
///   their payload — this is what neutralises OSC 52 clipboard writes,
/// * two-character `ESC` sequences,
/// * C0 controls, DEL and C1 controls, **except** `\n` and `\t`, which keep the
///   report readable.
///
/// Returns a borrowed slice when there is nothing to strip, so clean text costs no
/// allocation.
pub fn terminal(text: &str) -> Cow<'_, str> {
    sanitize(text, KeepNewlines::Yes)
}

/// Neutralise a value that will be written to a CSV cell.
///
/// Applies the same escape/control stripping as [`terminal`] (a report file is
/// frequently read with `cat`, `less` or a terminal spreadsheet, and a stray `\r`
/// can forge a row break in naive readers), then prefixes the whole field with an
/// apostrophe when the first visible character is a spreadsheet formula sigil —
/// `=`, `+`, `-` or `@` — so `=cmd|'/C calc'!A1` is written as text instead of
/// being evaluated on open. Leading whitespace does not defeat the check.
///
/// The prefix is placed at the very start of the field, so the cell content stays
/// unambiguous for both readers.
pub fn csv_field(text: &str) -> Cow<'_, str> {
    let stripped = sanitize(text, KeepNewlines::No);

    if starts_with_formula_sigil(&stripped) {
        Cow::Owned(format!("'{stripped}"))
    } else {
        stripped
    }
}

/// Whether `\n` and `\t` survive sanitisation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeepNewlines {
    Yes,
    No,
}

/// Shared escape/control stripper behind [`terminal`] and [`csv_field`].
fn sanitize(text: &str, keep: KeepNewlines) -> Cow<'_, str> {
    // `out` stays `None` for as long as nothing has been dropped, so clean text is
    // returned borrowed without ever being copied.
    let mut out: Option<String> = None;
    let mut chars = text.char_indices().peekable();

    while let Some((idx, ch)) = chars.next() {
        // C1 introducers outside the ESC family: 8-bit CSI and the string-type
        // sequences. They are handled before the plain control-character check.
        match ch {
            '\u{1b}' => {
                materialise(text, idx, &mut out);
                // The character after ESC is left in place: `skip_sequence` peeks it
                // to decide between `[`, a string introducer, and a plain sequence.
                skip_sequence(&mut chars);
                continue;
            }
            '\u{9b}' => {
                materialise(text, idx, &mut out);
                skip_csi_body(&mut chars);
                continue;
            }
            '\u{90}' | '\u{98}' | '\u{9d}' | '\u{9e}' | '\u{9f}' => {
                materialise(text, idx, &mut out);
                skip_string_body(&mut chars);
                continue;
            }
            _ => {}
        }

        // Newline and tab survive only when the caller asked for readable text; for a
        // CSV cell they are dropped like any other control character, so a value can
        // never forge a row break.
        let kept_whitespace = keep == KeepNewlines::Yes && (ch == '\n' || ch == '\t');
        if !kept_whitespace && is_control(ch) {
            // A dropped character: materialise the buffer so the removal is recorded.
            materialise(text, idx, &mut out);
            continue;
        }

        if let Some(buf) = out.as_mut() {
            buf.push(ch);
        }
    }

    match out {
        Some(out) => Cow::Owned(out),
        None => Cow::Borrowed(text),
    }
}

/// Start (or return) the output buffer, seeded with everything before `idx`.
///
/// Returns `&mut String` so callers can append further characters to it.
fn materialise<'a>(text: &str, idx: usize, out: &'a mut Option<String>) -> &'a mut String {
    out.get_or_insert_with(|| {
        let mut buf = String::with_capacity(text.len());
        buf.push_str(&text[..idx]);
        buf
    })
}

/// Consume the remainder of an escape sequence whose `ESC` has been seen.
fn skip_sequence(chars: &mut CharStream<'_>) {
    match peek_char(chars) {
        Some('[') => {
            chars.next();
            skip_csi_body(chars);
        }
        // OSC, DCS, SOS, PM, APC: a payload terminated by BEL or ST.
        Some(']') | Some('P') | Some('^') | Some('_') | Some('X') => {
            chars.next();
            skip_string_body(chars);
        }
        // Zero or more intermediate bytes (0x20..=0x2F), then one final byte
        // (0x30..=0x7E). Restricting the loop to the intermediate range keeps a plain
        // `ESC 7` from eating the printable text that follows it.
        Some(_) => {
            let mut guard = 0;
            while let Some(c) = peek_char(chars) {
                if ('\u{20}'..='\u{2f}').contains(&c) && guard < MAX_CSI_BODY_CHARS {
                    chars.next();
                    guard += 1;
                } else {
                    break;
                }
            }
            if let Some(c) = peek_char(chars) {
                if ('\u{30}'..='\u{7e}').contains(&c) {
                    chars.next();
                }
            }
        }
        None => {}
    }
}

/// Consume a CSI body up to and including its final byte (`0x40..=0x7E`).
///
/// A sequence that does not terminate within [`MAX_CSI_BODY_CHARS`] is malformed:
/// scanning resumes so that a stray `ESC [` cannot swallow the rest of a report.
fn skip_csi_body(chars: &mut CharStream<'_>) {
    for _ in 0..MAX_CSI_BODY_CHARS {
        match peek_char(chars) {
            Some(c) => {
                if ('\u{40}'..='\u{7e}').contains(&c) {
                    chars.next();
                    return;
                }
                if is_control(c) {
                    return;
                }
                chars.next();
            }
            None => return,
        }
    }
}

/// Consume an OSC/DCS-style payload terminated by BEL or ST (`ESC \`).
///
/// The payload is dropped entirely — that is the point for OSC 52, where the
/// payload *is* the attacker's clipboard content. Termination on a newline keeps an
/// unterminated sequence from eating the rest of a multi-line snippet, and
/// [`MAX_STRING_BODY_CHARS`] bounds the single-line case.
fn skip_string_body(chars: &mut CharStream<'_>) {
    for _ in 0..MAX_STRING_BODY_CHARS {
        match peek_char(chars) {
            Some('\u{7}') => {
                // BEL terminator.
                chars.next();
                return;
            }
            Some('\u{1b}') => {
                chars.next();
                if peek_char(chars) == Some('\\') {
                    chars.next();
                }
                return;
            }
            Some('\n') => return,
            Some(_) => {
                chars.next();
            }
            None => return,
        }
    }
}

/// Character stream used by the escape-skipping helpers.
type CharStream<'a> = std::iter::Peekable<std::str::CharIndices<'a>>;

/// The next character, without consuming it.
fn peek_char(chars: &mut CharStream<'_>) -> Option<char> {
    chars.peek().map(|(_, c)| *c)
}

/// C0 controls (including `\n`, `\t` and `\r`), DEL, and C1 controls.
fn is_control(ch: char) -> bool {
    (ch as u32) < 0x20 || ch == '\u{7f}' || ('\u{80}'..='\u{9f}').contains(&ch)
}

/// Whether the first non-whitespace character starts a spreadsheet formula.
fn starts_with_formula_sigil(text: &str) -> bool {
    matches!(
        text.trim_start().as_bytes().first(),
        Some(b'=' | b'+' | b'-' | b'@')
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- terminal ---------------------------------------------------------

    #[test]
    fn test_terminal_leaves_plain_text_untouched() {
        let text = "SEC-1234 comment: no findings in this attachment";
        assert!(matches!(terminal(text), Cow::Borrowed(_)));
        assert_eq!(terminal(text), text);
    }

    #[test]
    fn test_terminal_keeps_unicode_intact() {
        let text = "утечка: пароль найден в файле «config.yaml» — 100% подтверждено";
        assert_eq!(terminal(text), text);
    }

    #[test]
    fn test_terminal_strips_csi_colour_and_clear() {
        let text = "\u{1b}[2K\u{1b}[1;32mCLEAN\u{1b}[0m: no secrets found";
        assert_eq!(terminal(text), "CLEAN: no secrets found");
    }

    #[test]
    fn test_terminal_strips_osc52_clipboard_write() {
        // OSC 52 with a BEL terminator: payload is a base64 clipboard write.
        let text = "result: \u{1b}]52;c;aGFja2VkIGNsaXBib2FyZA==\u{7}ok";
        assert_eq!(terminal(text), "result: ok");
    }

    #[test]
    fn test_terminal_strips_osc52_with_st_terminator() {
        let text = "a\u{1b}]52;c;cGF5bG9hZA==\u{1b}\\b";
        assert_eq!(terminal(text), "ab");
    }

    #[test]
    fn test_terminal_strips_osc_without_terminator() {
        // Unterminated OSC must not swallow the following lines.
        let text = "line1\n\u{1b}]0;evil title\nline2\n";
        assert_eq!(terminal(text), "line1\n\nline2\n");
    }

    #[test]
    fn test_terminal_strips_c0_and_c1_controls() {
        let text = "a\u{0}b\u{7}c\u{8}de\u{7f}f\u{9b}31mg\u{84}h";
        assert_eq!(terminal(text), "abcdefgh");
    }

    #[test]
    fn test_terminal_keeps_newline_and_tab() {
        let text = "col1\tcol2\nrow2\tvalue";
        assert_eq!(terminal(text), text);
    }

    #[test]
    fn test_terminal_strips_stray_escape_without_eating_the_report() {
        // Malformed CSI: the escape is dropped, the text after it survives.
        let long = "x".repeat(MAX_CSI_BODY_CHARS + 10);
        let text = format!("before\u{1b}[{long} after");
        let cleaned = terminal(&text);
        assert!(cleaned.starts_with("before"));
        assert!(cleaned.ends_with("after"));
        assert!(!cleaned.contains('\u{1b}'));
    }

    // --- csv_field --------------------------------------------------------

    #[test]
    fn test_csv_field_plain_text_unchanged() {
        let text = "SEC-1234";
        assert!(matches!(csv_field(text), Cow::Borrowed(_)));
        assert_eq!(csv_field(text), text);
    }

    #[test]
    fn test_csv_field_unicode_unchanged() {
        let text = "snippet: пароль=секрет";
        assert_eq!(csv_field(text), text);
    }

    #[test]
    fn test_csv_field_neutralises_formula_sigils() {
        for hostile in [
            "=cmd|'/C calc'!A1",
            "+1+1",
            "-2+3",
            "@SUM(A1)",
            "=1+1",
            "@import(\"http://evil.example\")",
        ] {
            let cleaned = csv_field(hostile);
            assert!(
                cleaned.starts_with('\''),
                "{hostile:?} must be prefixed, got {cleaned:?}"
            );
            assert_eq!(cleaned, format!("'{hostile}"));
        }
    }

    #[test]
    fn test_csv_field_neutralises_sigil_after_leading_spaces() {
        assert_eq!(csv_field("   =cmd|'/C calc'!A1"), "'   =cmd|'/C calc'!A1");
        assert_eq!(csv_field(" =1+1"), "' =1+1");
        assert_eq!(csv_field("\t=1+1"), "'=1+1");
    }

    #[test]
    fn test_csv_field_strips_controls_and_breaks_formulas() {
        // A leading control character must not shield the sigil behind it.
        assert_eq!(csv_field("\r=1+1"), "'=1+1");
        assert_eq!(csv_field("\u{0}@SUM(A1)"), "'@SUM(A1)");
        // Embedded controls are removed, including newlines that could forge rows.
        assert_eq!(csv_field("line1\nline2"), "line1line2");
        assert_eq!(csv_field("a\u{1b}[31mb"), "ab");
    }

    #[test]
    fn test_csv_field_keeps_a_documentation_safe_leading_char() {
        // A leading `-` IS a formula sigil and is prefixed (see above); these are the
        // genuinely harmless leading characters.
        for benign in [
            "secret-hunter2",
            "snake_case=value",
            "value",
            "1+1",
            "  ok",
            "«quoted»",
            "",
        ] {
            let cleaned = csv_field(benign);
            assert!(
                !cleaned.starts_with('\''),
                "{benign:?} must not be prefixed, got {cleaned:?}"
            );
            assert_eq!(cleaned, benign);
        }
    }

    #[test]
    fn test_csv_field_handles_osc_payload() {
        assert_eq!(csv_field("\u{1b}]52;c;aGFja2Vk\u{7}=1+1"), "'=1+1");
    }
}

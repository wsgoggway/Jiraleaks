# Changelog

## [0.1.0] - 2026-08-07

### Added
- Kingfisher-inspired detection accuracy practices (offline; no network validation):
  - `ignore_if_contains` per-rule substring filter plus a global default placeholder list
    (`example`, `test`, `sample`, `demo`, `dummy`, `placeholder`, `changeme`, `your_key`,
    `yourkey`, `your-key`, `xxxx`, `foobar`, `redacted`, `fake`) applied to every rule;
    opt out per rule with `disable_default_placeholders: true` (used by `stripe_key`,
    where `test` is part of the `sk_test_`/`rk_test_` format).
  - Character-class requirements per rule: `min_digits`, `min_uppercase`,
    `min_lowercase`, `min_special_chars`, `special_chars`. `aws_secret_access_key`
    requires `min_digits: 3`; the generic assignment rules require `min_digits: 1`.
  - `examples` and `references` on rules; references surface on findings and JSON
    reports. Builtin rules enriched with examples/references from mongodb/kingfisher.
  - `github_token_checksum` validator (CRC32 + base62). Not attached to any builtin
    rule; available for user rules via the `validator:` field.
  - Confidence now upgrades Medium → High when a secret context keyword appears within
    ±50 chars and entropy is above threshold (previously the context signal was
    hardcoded false).

### Changed
- Removed the dead `allowed_context` field from the rule schema.
- `DEFAULT_PLACEHOLDERS` excludes bare digit runs so real tokens embedding them (Telegram
  bot ids, Slack workspace numbers) are not rejected.
- `tests/detection_quality.rs` fixtures use realistic non-placeholder values, since AWS
  `...EXAMPLE` keys are now correctly rejected by the placeholder filter.

### Fixed
- `AKIAIOSFODNN7EXAMPLE`-style documentation examples are no longer reported.

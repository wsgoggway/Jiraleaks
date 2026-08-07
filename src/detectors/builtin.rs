/// Built-in detection rules corpus (spec §10.9).
/// 20 rules covering common secret patterns.
pub const BUILTIN_RULES_YAML: &str = r##"
- rule_id: aws_access_key_id
  description: AWS Access Key ID
  severity: high
  confidence: high
  regex: '\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b'
  validator: aws_key_checksum
  references:
    - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
    - https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html
    - https://github.com/aws/aws-sdk-go-v2/blob/01b9289b1527ce7ad2f291250c55678f8578426b/aws/credentials.go

- rule_id: aws_secret_access_key
  description: AWS Secret Access Key
  severity: critical
  confidence: high
  regex: '\b[A-Za-z0-9/+]{40}\b'
  context_keywords:
    - aws_secret_access_key
    - aws secret
    - aws_secret
    - secret access key
  min_entropy: 3.0
  min_digits: 3
  references:
    - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
    - https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
    - https://github.com/praetorian-inc/noseyparker/blob/2e6e7f36ce36619852532bbe698d8cb7a26d2da7/crates/noseyparker/data/default/builtin/rules/aws.yml

- rule_id: github_token
  description: GitHub Personal Access Token (classic)
  severity: high
  confidence: high
  regex: '\bgh[pousr]_[A-Za-z0-9]{36,255}\b'
  examples:
    - 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
  references:
    - https://docs.github.com/en/rest/users?apiVersion=2022-11-28
    - https://github.com/projectdiscovery/nuclei-templates/blob/a165bbb8fd498d7dc59b755d8d5ba7561ac6f0c5/http/exposures/tokens/github/github-personal-access.yaml
    - https://github.com/projectdiscovery/nuclei-templates/blob/a165bbb8fd498d7dc59b755d8d5ba7561ac6f0c5/file/keys/github/github-personal-token.yaml

- rule_id: github_pat_v2
  description: GitHub Fine-grained PAT (v2)
  severity: high
  confidence: high
  regex: '\bgithub_pat_[0-9A-Za-z_]{82}\b'
  examples:
    - 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
  references:
    - https://docs.github.com/en/rest/users?apiVersion=2022-11-28
    - https://github.blog/security/application-security/behind-githubs-new-authentication-token-formats/
    - https://github.com/praetorian-inc/noseyparker/blob/2e6e7f36ce36619852532bbe698d8cb7a26d2da7/crates/noseyparker/data/default/builtin/rules/github.yml

- rule_id: gitlab_token
  description: GitLab Personal Access Token
  severity: high
  confidence: high
  regex: '\bglpat-[A-Za-z0-9_-]{20}\b'
  examples:
    - glpat-kSaPeOD_-T0JxMi3p28B
  references:
    - https://docs.gitlab.com/api/personal_access_tokens/
    - https://github.com/praetorian-inc/noseyparker/blob/2e6e7f36ce36619852532bbe698d8cb7a26d2da7/crates/noseyparker/data/default/builtin/rules/gitlab.yml

- rule_id: slack_token
  description: Slack Bot/User Token
  severity: high
  confidence: high
  regex: '\bxox[baprs]-[A-Za-z0-9-]{10,72}\b'
  examples:
    - xoxb-853BAAEE-1B2eDb6A4c75-01bB6Da1CE3E98f6fED5AeC07Dc3E94C
  references:
    - https://api.slack.com/methods/auth.test
    - https://api.slack.com/authentication/token-types

- rule_id: google_api_key
  description: Google API Key
  severity: medium
  confidence: high
  regex: '\bAIza[0-9A-Za-z_-]{35}\b'
  examples:
    - AIzaSyByz6BGQf8QtcQLml8spbyy8x5_327PTow
  references:
    - https://ai.google.dev/docs/gemini_api_overview
    - https://github.com/praetorian-inc/noseyparker/blob/2e6e7f36ce36619852532bbe698d8cb7a26d2da7/crates/noseyparker/data/default/builtin/rules/google.yml

- rule_id: private_key_block
  description: Private Key Block (PEM)
  severity: critical
  confidence: high
  regex: '(?s)-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----'
  examples:
    - |
      -----BEGIN RSA PRIVATE KEY-----
      b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
      NhAAAAAwEAAQAAAIEAtDSHFO5tfN+jYMJuiNvBaplkSI3eFqKMLOvXyVu+dmSEic6xyKWQ
      -----END RSA PRIVATE KEY-----
  references:
    - https://www.rfc-editor.org/rfc/rfc7468
    - https://github.com/praetorian-inc/noseyparker/blob/ca4ef4d2a4771f69e64daf7fbb4f8fafdd18f19d/crates/noseyparker/data/default/builtin/rules/pem.yml

- rule_id: jwt
  description: JSON Web Token
  severity: medium
  confidence: medium
  regex: '\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'
  validator: jwt_structure

- rule_id: telegram_bot_token
  description: Telegram Bot Token
  severity: high
  confidence: high
  regex: '\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b'
  examples:
    - tgram://110201543:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawd
  references:
    - https://core.telegram.org/bots/api#authorizing-your-bot
    - https://github.com/praetorian-inc/noseyparker/blob/ca4ef4d2a4771f69e64daf7fbb4f8fafdd18f19d/crates/noseyparker/data/default/builtin/rules/telegram.yml

- rule_id: stripe_key
  description: Stripe API Key
  severity: high
  confidence: high
  regex: '\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b'
  # "test" is part of the key format (sk_test_/rk_test_), not a placeholder marker
  disable_default_placeholders: true
  examples:
    - sk_live_f01c79xuuug7yodgzj5ws0h1x2kyvho3
  references:
    - https://stripe.com/docs/api/authentication
    - https://github.com/praetorian-inc/noseyparker/blob/ca4ef4d2a4771f69e64daf7fbb4f8fafdd18f19d/crates/noseyparker/data/default/builtin/rules/stripe.yml

- rule_id: npm_token
  description: NPM Access Token
  severity: medium
  confidence: high
  regex: '\bnpm_[A-Za-z0-9]{36,}\b'
  examples:
    - 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
  references:
    - https://docs.npmjs.com/about-access-tokens
    - https://github.blog/changelog/2022-12-06-limit-scope-of-npm-tokens-with-the-new-granular-access-tokens/

- rule_id: sendgrid_api_key
  description: SendGrid API Key
  severity: medium
  confidence: high
  regex: '\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b'
  examples:
    - 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
  references:
    - https://docs.sendgrid.com/ui/account-and-settings/api-keys
    - https://github.com/praetorian-inc/noseyparker/blob/ca4ef4d2a4771f69e64daf7fbb4f8fafdd18f19d/crates/noseyparker/data/default/builtin/rules/sendgrid.yml

- rule_id: jdbc_url_with_password
  description: JDBC URL with embedded credentials
  severity: high
  confidence: medium
  regex: '\bjdbc:[a-z0-9+]+://[^\s:/@]+:[^\s:/@]+@[^\s]+'

- rule_id: db_url_credentials
  description: Database URL with embedded credentials
  severity: high
  confidence: medium
  regex: '\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|mssql|amqp|elasticsearch)://[^\s:/@]*:[^\s:/@]+@[^\s/]+'

- rule_id: generic_password_assignment
  description: Generic password/secret assignment
  severity: medium
  confidence: medium
  regex: '(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\b\s*[:=]\s*[''"\x{2018}\x{2019}\x{201c}\x{201d}]?([^\s''"<>{}\x{2018}\x{2019}\x{201c}\x{201d}]{8,})[''"\x{2018}\x{2019}\x{201c}\x{201d}]?'
  capture_group: 2
  min_length: 8
  min_entropy: 2.0
  min_digits: 1

- rule_id: generic_api_key_assignment
  description: Generic API key assignment
  severity: low
  confidence: medium
  regex: '(?i)\bapi[_-]?key\b\s*[:=]\s*[''"\x{2018}\x{2019}\x{201c}\x{201d}]?([A-Za-z0-9_\-]{16,})[''"\x{2018}\x{2019}\x{201c}\x{201d}]?'
  capture_group: 1
  min_digits: 1

- rule_id: generic_secret_assignment
  description: Generic secret assignment
  severity: medium
  confidence: medium
  regex: '(?i)\b(?:secret|client[_-]?secret)\b\s*[:=]\s*[''"\x{2018}\x{2019}\x{201c}\x{201d}]?([^\s''"<>{}\x{2018}\x{2019}\x{201c}\x{201d}]{8,})[''"\x{2018}\x{2019}\x{201c}\x{201d}]?'
  capture_group: 1
  min_digits: 1

- rule_id: basic_auth_header
  description: HTTP Basic Auth header value
  severity: low
  confidence: medium
  regex: '\bBasic\s+[A-Za-z0-9+/]{16,}={0,2}\b'

- rule_id: bearer_token_generic
  description: Generic Bearer token
  severity: low
  confidence: low
  regex: '\bBearer\s+[A-Za-z0-9_\-\.=]{20,}\b'
"##;

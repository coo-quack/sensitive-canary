# Changelog

## Unreleased

### Features

- **Allow + Mask tag priority** — when both `[allow-*]` and `[mask-*]` tags appear in the same prompt, the first occurrence wins per category (`secret`, `pii`). `[allow-all]` and `[mask-all]` resolve both dimensions at once.

### Fixes

- Plugin install command corrected to `sensitive-canary@coo-quack`

---

## v0.1.0 (2026-02-22)

Initial release.

### Features

- **UserPromptSubmit hook** — scans every prompt for secrets and PII before it is sent to the Anthropic API
- **PreToolUse hook** — blocks `.env`/`.env.*` files by name; scans file contents and Bash commands for secrets and PII
- **25+ detection rules** — AWS keys, GitHub/GitLab PATs, Stripe keys, Slack/Discord/Telegram tokens, JWTs, SendGrid/Mailgun/Mailchimp keys, Anthropic/OpenAI API keys, database connection strings, and more
- **PII detection** — email addresses, credit card numbers (Luhn-validated), US SSNs, US/JP phone numbers, Japanese postal codes, private IPv4 addresses
- **Entropy filtering** — suppresses false positives on low-entropy generic-secret and env-assignment matches
- **Allow tags** — `[allow-secret]`, `[allow-pii]`, `[allow-all]` bypass specific categories per prompt
- **[mask-xxx] tag handling** — explains that prompt masking is unsupported and suggests the correct allow tag
- **Environment variable expansion** — Bash commands referencing `$VAR` / `${VAR}` have their env values scanned
- **Deduplication** — repeated occurrences of the same secret value produce a single finding

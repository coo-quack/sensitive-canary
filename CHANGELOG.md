## v0.5.2 (2026-03-31)

### Security

- Add `minimumReleaseAge` to renovate.json to prevent supply chain attacks
  - Waits 7 days before auto-merging dependency updates
  - Reduces risk of package takeover attacks
  - Blocks immediate auto-merge of newly published packages

---

## v0.5.2 (2026-03-31)

### Security

- Add `minimumReleaseAge` to renovate.json to prevent supply chain attacks
  - Waits 7 days before auto-merging dependency updates
  - Reduces risk of package takeover attacks
  - Blocks immediate auto-merge of newly published packages

---

# Changelog

## v0.5.1 (2026-03-15)

### Fixes

- Remove `marketplace.json` and sync marketplace via `repository_dispatch` on release
- Gate marketplace sync on actual release creation to prevent duplicate dispatches
- Update marketplace registration commands across README and docs to point to `coo-quack/claude-code-marketplace`
- Remove stale `marketplace.json` references from `CONTRIBUTING.md` and `README.md`
- Simplify backport workflow to direct main-to-develop merge

---

## v0.5.0 (2026-03-14)

### Features

- Add Google Cloud API Key (`gcp-api-key`) detection rule
- Add npm Access Token (`npm-token`) detection rule

### Fixes

- Prevent `openai-key` (legacy) rule from overlapping with `openai-project-key` and `anthropic-key` via negative lookahead
- Use nullish coalescing (`??`) in `entropy()` for correct semantics under `noUncheckedIndexedAccess`
- Remove unreachable `unique` filter in `user-prompt-submit-hook`
- Consolidate `randomBird()` calls in `block()` for consistent emoji across terminal and JSON output
- Fix fd leaks in file read and `/dev/tty` write paths with `try/finally`
- Use `bytesRead` return value from `fs.readSync` to avoid NUL-filled buffer tails
- Scan text prefix before first NUL byte in binary files instead of skipping entirely

### Performance

- Read only the last 64 KB of transcript files for allow-tag resolution
- Skip binary content after first NUL byte to avoid pointless regex scanning

### Documentation

- Unify documentation site structure with Getting Started and Troubleshooting pages
- Symlink `docs/contributing.md` to root `CONTRIBUTING.md`

---

## v0.4.6 (2026-03-12)

### Security

- Add explicit permissions to all workflow jobs
- Resolve Dependabot security alerts via pnpm overrides

---

## v0.4.5 (2026-03-12)

### Fixes

- Scope CI badge to main branch

---

## v0.4.4 (2026-03-12)

### Improvements

- Migrate from npm to pnpm
- Add Renovate configuration with automerge on CI success
- Add pnpm version specification for GitHub Actions

### Documentation

- Update install instructions from npm to pnpm
- Capitalize project title to Sensitive Canary across docs

### Fixes

- Fix capitalization in project title

---

## v0.4.3 (2026-02-23)

### Documentation

- Replace Japanese text with English in npm install instructions

---

## v0.4.2 (2026-02-23)

### Fixes

- **Scoped package name** — renamed npm package from `sensitive-canary` to `@coo-quack/sensitive-canary`
- **Homepage** — added `homepage` field pointing to the documentation site

---

## v0.4.1 (2026-02-23)

### Improvements

- **npm publish automation** — release workflow now publishes to npm with provenance on merge to main
- **Package metadata** — added `repository` and `files` fields, removed `private: true` for npm publishing
- **npm install docs** — added `npm install -g` setup instructions to README and docs

---

## v0.4.0 (2026-02-23)

### Features

- **Allow tags are now single-use** — allow tags are consumed after the first tool call, preventing unintended persistent bypass across multiple tool uses in the same turn

### Fixes

- **Random bird emoji in block messages** — PreToolUse block messages now use `randomBird()` instead of a hardcoded emoji, matching the existing behavior in other messages

### Docs

- **README restructured** — new section order: Why → Quick Start → What Happens → Detection Rules → How It Works → Allow Tags
- **Docs site headings unified** — "How It Works" → "What Happens", "What Gets Detected" → "Detection Rules" for consistency with README

---

## v0.3.1 (2026-02-23)

### Fixes

- **Bird emoji in PreToolUse block reason** — the bird emoji now appears in the block message shown by Claude Code, not only in the terminal output

---

## v0.3.0 (2026-02-23)

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

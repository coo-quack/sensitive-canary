# sensitive-canary

[![CI](https://github.com/coo-quack/sensitive-canary/actions/workflows/ci.yml/badge.svg)](https://github.com/coo-quack/sensitive-canary/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A security tool that uses Claude Code's hook system to block secrets and PII from being sent to the Anthropic API — whether they come from your prompts or from files Claude reads.

No proxy server. No background process. Native Claude Code hooks only.

📖 **[Documentation](https://coo-quack.github.io/sensitive-canary/)** — Installation guide, detection rules reference, and allow tag details.

---

## How It Works

### ① UserPromptSubmit hook

Runs just before a prompt is sent to the API.

```
User presses Enter
      ↓
UserPromptSubmit hook
      ↓ scans prompt
      ├─ secret / PII detected AND no matching [allow-xxx] tag → block (exit 2)
      └─ nothing detected OR tag present → pass (exit 0)
```

When blocked, the terminal shows what was detected and how to bypass it.

### ② PreToolUse hook

Runs just before Claude calls the `Read` or `Bash` tool.

```
Claude calls Read / Bash tool
      ↓
PreToolUse hook
      ↓
      ── Read tool ─────────────────────────────────────────────────────
      │  1. filename is .env / .env.* → blocked unconditionally
      │  2. file contents contain secret / PII → blocked
      └─ Bash tool ─────────────────────────────────────────────────────
         1. env var values referenced in the command contain secret / PII → blocked
         2. command string itself contains secret / PII (e.g. echo AKIA...) → blocked
         3. cat / head / tail / etc. targeting a file → file contents scanned
```

When blocked, Claude receives a JSON response explaining the reason and is prompted to tell the user.
The terminal also receives a direct message (via `/dev/tty`).

---

## Installation

### Requirements

- Node.js **22.6.0** or later (required for `--experimental-strip-types`)
- Claude Code 1.0.33 or later

### Plugin install (recommended)

Install in two commands from inside a Claude Code session:

**1. Register the marketplace**

```
/plugin marketplace add coo-quack/sensitive-canary
```

**2. Install the plugin**

```
/plugin install sensitive-canary@sensitive-canary
```

Done. The hooks are enabled automatically.

---

### Manual setup

If you prefer to configure hooks without the plugin system:

**1. Clone the repository**

```bash
git clone https://github.com/coo-quack/sensitive-canary.git ~/sensitive-canary
```

**2. Register the hooks in `~/.claude/settings.json`**

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "node --experimental-strip-types ~/sensitive-canary/src/user-prompt-submit-hook.ts"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Read|Bash",
        "hooks": [
          {
            "type": "command",
            "command": "node --experimental-strip-types ~/sensitive-canary/src/pre-tool-use-hook.ts"
          }
        ]
      }
    ]
  }
}
```

---

## Usage

### Prompt blocked

Prompts containing secrets or PII are blocked before being sent.

```
> My AWS key is AKIAIOSFODNN7EXAMPLE. Can you review this code?

⚠️  sensitive-canary: sensitive data detected — blocked

  [Secret] AWS Access Key ID (aws-access-key): AKIA****MPLE

To allow, add a tag to your prompt:
  [allow-secret]  — allow secrets
  [allow-all]     — bypass all sensitive-canary checks
```

To allow it through, add the suggested tag:

```
> [allow-secret] My AWS key is AKIAIOSFODNN7EXAMPLE. Can you review this code?
```

### .env file blocked

`.env` / `.env.*` files are blocked unconditionally, regardless of their contents.

```
> Read .env

📄 sensitive-canary: blocked — /path/to/.env

⚠️  Blocked: .env and .env.* files contain secrets and must not be read into the conversation.

To allow this, the user must add an allow tag to their next prompt:
  [allow-secret]  — allow secrets
  [allow-pii]     — allow PII
  [allow-all]     — bypass all sensitive-canary checks

Example: "[allow-secret] please read /path/to/.env"
```

### File content blocked

Non-`.env` files are also blocked if their contents contain secrets or PII.

```
> Read config.yaml

📄 sensitive-canary: blocked — /path/to/config.yaml

⚠️  Blocked: file contains sensitive data

  [Secret] AWS Access Key ID (aws-access-key): AKIA****MPLE
```

---

## Allow tags

To intentionally bypass a block, include the appropriate tag in your **current prompt**.

| Tag | Effect |
|---|---|
| `[allow-secret]` | Skip all secret-category checks |
| `[allow-pii]` | Skip all PII-category checks |
| `[allow-all]` | Skip all sensitive-canary checks |

**Important notes:**

- Tags are read from the **current user message only**. Tags in previous messages are ignored — there is no risk of an accidental persistent bypass.
- `[allow-secret]` does not bypass PII blocks (and vice versa).
- The name-based block on `.env`/`.env.*` files can be bypassed by any of the three allow tags.
- Allow tags filter the scan results — the scan itself always runs. The `.env`/`.env.*` name block is the only exception: when an allow tag is present, the file is passed through immediately without scanning.

---

## Detection rules

### Secrets (22 rules)

| Rule ID | Description |
|---|---|
| `aws-access-key` | AWS Access Key ID |
| `private-key` | PEM Private Key (RSA / EC / DSA / PGP / OpenSSH) |
| `github-pat` | GitHub Personal Access Token |
| `github-fine-grained` | GitHub Fine-Grained Token |
| `gitlab-pat` | GitLab Personal Access Token |
| `slack-token` | Slack Token |
| `slack-webhook` | Slack Webhook URL |
| `discord-webhook` | Discord Webhook URL |
| `telegram-bot-token` | Telegram Bot Token |
| `twilio-sid` | Twilio Account SID |
| `sendgrid-key` | SendGrid API Key |
| `mailgun-key` | Mailgun API Key |
| `mailchimp-key` | Mailchimp API Key |
| `stripe-secret-key` | Stripe Secret Key |
| `stripe-restricted-key` | Stripe Restricted Key |
| `openai-key` | OpenAI API Key (legacy format) |
| `openai-project-key` | OpenAI Project API Key (`sk-proj-` prefix) *(entropy ≥ 3.5)* |
| `anthropic-key` | Anthropic API Key |
| `jwt` | JSON Web Token (JWT) |
| `generic-secret` | Generic API key / secret assignment *(entropy ≥ 3.5)* |
| `env-assignment` | `.env`-style secret assignment *(entropy ≥ 3.0)* |
| `connection-string` | Database connection string with embedded credentials |

### PII (7 rules)

| Rule ID | Description | Validation |
|---|---|---|
| `pii-email` | Email address | — |
| `pii-credit-card` | Credit card number | Luhn check |
| `pii-ssn` | US Social Security Number | Invalid prefix exclusion |
| `pii-phone-us` | US phone number | — |
| `pii-phone-jp` | Japanese phone number | — |
| `pii-postal-jp` | Japanese postal code (`〒` prefix required) | — |
| `pii-ipv4` | IPv4 address (RFC 1918 private ranges only) | — |

Detection patterns are based on rule definitions from [gitleaks](https://github.com/gitleaks/gitleaks) and [TruffleHog](https://github.com/trufflesecurity/trufflehog).

---

## File structure

```
.claude-plugin/
  plugin.json                  plugin manifest
  marketplace.json             marketplace catalog
hooks/
  hooks.json                   Claude Code hook configuration
src/
  user-prompt-submit-hook.ts   UserPromptSubmit hook
  pre-tool-use-hook.ts         PreToolUse hook
  lib/
    inspector.ts               allow tag parsing, message scanning
    rules.ts                   secret and PII detection rule definitions
```

---

## Development

```bash
npm install        # install dependencies

npm test           # run tests
npm run test:watch # run tests in watch mode
npm run typecheck  # type check (tsc)
npm run lint       # lint with Biome (no changes)
npm run fix        # lint + auto-fix with Biome
npm run ci         # typecheck + lint + tests (for CI)
```

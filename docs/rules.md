# Detection Rules

sensitive-canary scans text against the following rules. Patterns are sourced from [gitleaks](https://github.com/gitleaks/gitleaks) and [TruffleHog](https://github.com/trufflesecurity/trufflehog) detector definitions.

## Secrets

### Cloud

| Rule ID | Description | Pattern |
|---------|-------------|---------|
| `aws-access-key` | AWS Access Key ID | `AKIA`, `ASIA`, `AGPA`, `AIDA`, `AROA`, … + 16 uppercase alphanumeric chars |

### Source Control

| Rule ID | Description |
|---------|-------------|
| `github-pat` | GitHub Personal Access Token (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` prefix) |
| `github-fine-grained` | GitHub Fine-Grained Token (`github_pat_` prefix) |
| `gitlab-pat` | GitLab Personal Access Token (`glpat-` prefix) |

### AI Services

| Rule ID | Description |
|---------|-------------|
| `openai-key` | OpenAI API Key — legacy format (`sk-` + 48 chars) |
| `openai-project-key` | OpenAI Project API Key (`sk-proj-` prefix, entropy-filtered) |
| `anthropic-key` | Anthropic API Key (`sk-ant-` prefix) |

### Communication

| Rule ID | Description |
|---------|-------------|
| `slack-token` | Slack Token (`xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` prefix) |
| `slack-webhook` | Slack Incoming Webhook URL |
| `discord-webhook` | Discord Webhook URL |
| `telegram-bot-token` | Telegram Bot Token |
| `twilio-sid` | Twilio Account SID |

### Payment

| Rule ID | Description |
|---------|-------------|
| `stripe-secret-key` | Stripe Secret Key (`sk_live_` / `sk_test_` prefix) |
| `stripe-restricted-key` | Stripe Restricted Key (`rk_live_` / `rk_test_` prefix) |

### Email Services

| Rule ID | Description |
|---------|-------------|
| `sendgrid-key` | SendGrid API Key (`SG.` prefix) |
| `mailgun-key` | Mailgun API Key (`key-` prefix) |
| `mailchimp-key` | Mailchimp API Key (32-char hex + `-usN` suffix) |

### Auth

| Rule ID | Description |
|---------|-------------|
| `jwt` | JSON Web Token (three Base64URL segments separated by `.`) |
| `private-key` | PEM Private Key header (`-----BEGIN … PRIVATE KEY-----`) |
| `connection-string` | Database connection string with embedded credentials |

### Generic / Env-based

| Rule ID | Description | Entropy threshold |
|---------|-------------|-------------------|
| `generic-secret` | `api_key`, `secret_key`, `access_token`, `api_secret` assignments | 3.5 |
| `env-assignment` | `.env`-style assignments for `SECRET`, `PASSWORD`, `TOKEN`, `API_KEY`, `PRIVATE_KEY` | 3.0 |

The entropy threshold filters out low-entropy values (e.g. `API_KEY=placeholder`) that are unlikely to be real secrets. Entropy is calculated using the Shannon entropy formula.

## PII

| Rule ID | Description | Notes |
|---------|-------------|-------|
| `pii-email` | Email Address | Standard RFC 5322-like pattern |
| `pii-credit-card` | Credit Card Number | Visa, Mastercard, Amex, Discover; validated with Luhn algorithm |
| `pii-ssn` | US Social Security Number | Excludes invalid prefixes (000, 666, 9xx) |
| `pii-phone-us` | US Phone Number | With or without country code |
| `pii-phone-jp` | Japanese Phone Number | Area code + subscriber number format |
| `pii-postal-jp` | Japanese Postal Code | Requires `〒` prefix to avoid false positives |
| `pii-ipv4` | Private IPv4 Address | RFC 1918 ranges only: `10.x`, `172.16–31.x`, `192.168.x` |

### Credit Card Validation

Credit card numbers are matched by pattern **and** validated using the [Luhn algorithm](https://en.wikipedia.org/wiki/Luhn_algorithm). This means valid-looking but invalid card numbers (e.g. `4111111111111112`) are not flagged.

## Allow Tags

All blocks can be bypassed by including an allow tag in your prompt. Allow tags are read only from the **current** user message — they do not carry over between turns.

| Tag | Bypasses |
|-----|----------|
| `[allow-secret]` | All findings with `category: secret` |
| `[allow-pii]` | All findings with `category: pii` |
| `[allow-all]` | All findings regardless of category |

**Note on mask tags:** `[mask-secret]`, `[mask-pii]`, and `[mask-all]` are recognised but not supported for prompts — Claude Code does not allow hooks to rewrite prompt content. If you use a mask tag, sensitive-canary will explain this and suggest the appropriate allow tag instead.

## .env File Blocking

`.env` and `.env.*` files (e.g. `.env.local`, `.env.production`) are blocked **unconditionally by filename** when Claude attempts to read them, regardless of content.

Files that end in `.env` but don't start with a dot (e.g. `production.env`) are handled by content scanning rather than name-based blocking.

Any allow tag (`[allow-secret]`, `[allow-pii]`, or `[allow-all]`) bypasses the name-based block.

## Bash Command Scanning

When Claude uses the `Bash` tool, sensitive-canary checks three things:

1. **Environment variables** — any `$VAR` or `${VAR}` references in the command are looked up in the current environment; if their values contain secrets or PII, the command is blocked.
2. **Command string** — the raw command is scanned (catches inline secrets like `echo AKIAIOSFODNN7EXAMPLE`).
3. **File-reading commands** — for `cat`, `head`, `tail`, `less`, `more`, `bat`, `nl`, the target files are read and scanned before the command runs.

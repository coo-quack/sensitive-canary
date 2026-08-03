# Detection Rules

Sensitive Canary scans text against the following rules. Patterns are sourced from [gitleaks](https://github.com/gitleaks/gitleaks) and [TruffleHog](https://github.com/trufflesecurity/trufflehog) detector definitions.

## Secrets

### Cloud

| Rule ID | Description | Pattern |
|---------|-------------|---------|
| `aws-access-key` | AWS Access Key ID | `AKIA`, `ASIA`, `AGPA`, `AIDA`, `AROA`, … + 16 uppercase alphanumeric chars |
| `gcp-api-key` | Google Cloud API Key | `AIza` + 35 alphanumeric/dash/underscore chars |

### Source Control

| Rule ID | Description |
|---------|-------------|
| `github-pat` | GitHub Personal Access Token (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` prefix) |
| `github-fine-grained` | GitHub Fine-Grained Token (`github_pat_` prefix) |
| `gitlab-pat` | GitLab Personal Access Token (`glpat-` prefix) |

### Package Registries

| Rule ID | Description |
|---------|-------------|
| `npm-token` | npm Access Token (`npm_` prefix + 36 alphanumeric chars) |

### AI Services

| Rule ID | Description |
|---------|-------------|
| `openai-key` | OpenAI API Key — legacy format (`sk-` + 48 chars) |
| `openai-project-key` | OpenAI Project API Key (`sk-proj-` prefix, entropy-filtered) |
| `anthropic-key` | Anthropic API Key (`sk-ant-` prefix) |
| `replicate-token` | Replicate API Token (`r8_` prefix) |
| `huggingface-token` | Hugging Face Access Token (`hf_` prefix) |
| `groq-key` | Groq API Key (`gsk_` prefix) |
| `openrouter-key` | OpenRouter API Key (`sk-or-v1-` prefix) |
| `xai-key` | xAI (Grok) API Key (`xai-` prefix) |
| `perplexity-key` | Perplexity API Key (`pplx-` prefix) |

### Cloud / IaaS

| Rule ID | Description |
|---------|-------------|
| `digitalocean-pat` | DigitalOcean Personal Access Token (`dop_v1_` prefix) |
| `supabase-key` | Supabase Personal Access Token (`sbp_` prefix) |

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
| `square-access-token` | Square Access Token (`EAAA` prefix) |

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

### SaaS / Developer Tools

| Rule ID | Description |
|---------|-------------|
| `mapbox-token` | Mapbox Token (`pk.` / `sk.` JWT prefix) |
| `sentry-user-token` | Sentry User Auth Token (`sntryu_` prefix) |
| `sentry-org-token` | Sentry Organization Auth Token (`sntrys_` JWT prefix) |
| `atlassian-token` | Atlassian (Jira/Confluence) API Token (`ATATT3` prefix) |
| `linear-key` | Linear API Key (`lin_api_` prefix) |
| `postman-key` | Postman API Key (`PMAK-` prefix) |

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
| `pii-ipv4` | Private IPv4 Address | RFC 1918 ranges only: `10.x`, `172.16–31.x`, `192.168.x` |
| `pii-ssn` | US Social Security Number | Excludes invalid area (000, 666, 9xx), group (00), and serial (0000) numbers |
| `pii-mynumber-jp` | Japanese Individual Number (My Number) | 12 digits, validated with weighted checksum (mod 11) |
| `pii-nir-fr` | French NIR / Social Security Number | 15 digits, validated with check key (mod 97); Corsica 2A/2B supported |
| `pii-codice-fiscale-it` | Italian Codice Fiscale | 16 alphanumeric chars, validated with control character (mod 26) |
| `pii-steuer-id-de` | German Steuer-Identifikationsnummer | 11 digits, validated with MOD 11,10 (ISO/IEC 7064) |
| `pii-dni-nie-es` | Spanish DNI / NIE | 8 digits + letter (DNI) or X/Y/Z + 7 digits + letter (NIE); validated with mod 23 |
| `pii-phone-us` | US Phone Number | With or without country code |
| `pii-phone-jp` | Japanese Phone Number | Area code + subscriber number format |
| `pii-phone-fr` | French Phone Number | Context-gated (requires nearby phone label) |
| `pii-phone-it` | Italian Phone Number | Context-gated |
| `pii-phone-de` | German Phone Number | Context-gated |
| `pii-phone-es` | Spanish Phone Number | Context-gated |
| `pii-postal-jp` | Japanese Postal Code | Requires `〒` prefix to avoid false positives |
| `pii-postal-code` | Postal Code (US ZIP / EU / KR) | Context-gated (requires nearby postal label) |
| `pii-rrn-kr` | Korean Resident Registration Number | 13 digits, validated with weighted checksum (mod 11) |
| `pii-brn-kr` | Korean Business Registration Number | 10 digits, validated with NTS standard checksum |
| `pii-resident-id-cn` | Chinese Resident Identity Card | 18 chars (17 digits + check), validated with GB 11643 MOD 11-2 |
| `pii-phone-kr` | Korean Phone Number | Context-gated |
| `pii-phone-cn` | Chinese Phone Number | Context-gated |
| `pii-postal-cn` | Chinese Postal Code (6-digit) | Context-gated |
| `pii-ipv4-public` | Public IPv4 Address | Context-gated; reserved/private ranges excluded |
| `pii-ipv6` | IPv6 Address | Context-gated; loopback, link-local, ULA, multicast excluded |

### National ID Validation

National ID numbers (JP My Number, FR NIR, IT Codice Fiscale, DE Steuer-IdNr., ES DNI/NIE) are matched by pattern **and** validated against their official checksum algorithm. A digit sequence that looks right but fails the checksum is not flagged. The algorithms follow each issuing authority's published spec:

- **My Number**: 地方公共団体情報システム機構 (J-LIS)
- **NIR**: INSEE / décret n°82-103 (97 − N mod 97)
- **Codice Fiscale**: Agenzia delle Entrate, DM 12 giugno 2007 (mod 26)
- **Steuer-IdNr.**: Bundeszentralamt für Steuern (ISO/IEC 7064 MOD 11,10)
- **DNI/NIE**: Ministerio del Interior, Orden INT/2058/2008 (mod 23)
- **Korean RRN**: 주민등록 사무편람, Ministry of the Interior and Safety (weighted mod 11)
- **Chinese Resident ID**: GB 11643-1999 (ISO 7064 MOD 11-2)
- **Korean BRN**: NTS (Hometax) standard algorithm

### Context Gating

Variable-length Italian and German phone numbers, and bare 5/9-digit postal codes, produce too many false positives on digit-only patterns. These rules carry a list of nearby context words (`phone`, `tel`, `ZIP`, `PLZ`, `CAP`, `postal`, … in each relevant language) and only fire when one of those words appears within a small window of the match. Only words that **directly indicate the PII type** are included; generic words such as `contact`, `host`, `server`, or `code` are excluded because they cause false positives. If no decisive context word is nearby, the match is dropped.

National ID numbers rely on their checksums instead and do not require context. Japanese postal codes keep their `〒` prefix requirement, which is a stricter form of the same idea.

Public IPv4 and IPv6 addresses are also context-gated, and additionally exclude reserved ranges (private, loopback, link-local, TEST-NET, multicast, documentation, etc.) so that example IPs like `8.8.8.8` and tutorials do not fire unless a label such as `ip`, `ipv4`, or `ipv6` is nearby. The existing `pii-ipv4` rule still flags RFC 1918 private ranges without context.

### Credit Card Validation

Credit card numbers are matched by pattern **and** validated using the [Luhn algorithm](https://en.wikipedia.org/wiki/Luhn_algorithm). This means valid-looking but invalid card numbers (e.g. `4111111111111112`) are not flagged.

## Allow Tags

All blocks can be bypassed by including an allow tag in your prompt. Allow tags are read only from the **current** user message — they do not carry over between turns.

| Tag | Bypasses |
|-----|----------|
| `[allow-secret]` | All findings with `category: secret` |
| `[allow-pii]` | All findings with `category: pii` |
| `[allow-all]` | All findings regardless of category |

Tags are **case-insensitive**: `[ALLOW-SECRET]` and `[Allow-Secret]` work the same as `[allow-secret]`.

### Mask Tags

`[mask-secret]`, `[mask-pii]`, and `[mask-all]` are recognised but **not supported**. Claude Code hooks cannot rewrite prompt content before it is sent to the API.

If you include a mask tag in your prompt, sensitive-canary shows an explanation and suggests the equivalent allow tag instead. The prompt is not sent until you resend with an allow tag or redact the value manually.

| Mask tag | Suggested allow tag |
|----------|---------------------|
| `[mask-secret]` | `[allow-secret]` |
| `[mask-pii]` | `[allow-pii]` |
| `[mask-all]` | `[allow-all]` |

### Allow + Mask Tag Priority

When both `[allow-*]` and `[mask-*]` tags appear in the same prompt, **the tag that appears first wins** for each category dimension (`secret`, `pii`).

| Example | secret | pii |
|---------|--------|-----|
| `[allow-secret] [mask-secret] …` | allow | — |
| `[mask-secret] [allow-secret] …` | mask (unsupported) | — |
| `[allow-all] [mask-secret] …` | allow | allow |
| `[mask-all] [allow-secret] …` | mask (unsupported) | mask (unsupported) |
| `[allow-secret] [mask-pii] …` | allow | mask (unsupported) |

`[allow-all]` and `[mask-all]` resolve both dimensions at once.

## Category Filtering

Set the `SENSITIVE_CANARY_CATEGORIES` environment variable (e.g. in the `env` block of Claude Code `settings.json`) to limit which rule categories are active:

| Value | Effect |
|-------|--------|
| `secret` | Scan for secrets only — PII rules are disabled |
| `pii` | Scan for PII only — secret rules and the name-based `.env`/`.env.*` block are disabled |
| `secret,pii` / `all` | Scan everything (default) |

Values are comma-separated and case-insensitive. Unset, empty, or containing no valid token means all categories are enabled. This persistent filter is applied before allow tags.

## .env File Blocking

`.env` and `.env.*` files (e.g. `.env.local`, `.env.production`) are blocked **by filename** when Claude attempts to read them, regardless of content. This name-based block is a secret guard: it only applies while the `secret` category is enabled via `SENSITIVE_CANARY_CATEGORIES`.

Files that end in `.env` but don't start with a dot (e.g. `production.env`) are handled by content scanning rather than name-based blocking.

Any allow tag (`[allow-secret]`, `[allow-pii]`, or `[allow-all]`) bypasses the name-based block. When an allow tag is present, the file is passed through **immediately without scanning** its contents.

## Bash Command Scanning

When Claude uses the `Bash` tool, sensitive-canary checks three things:

1. **Environment variables** — any `$VAR` or `${VAR}` references in the command are looked up in the current environment; if their values contain secrets or PII, the command is blocked.
2. **Command string** — the raw command is scanned (catches inline secrets like `echo AKIAIOSFODNN7EXAMPLE`).
3. **File-reading commands** — for `cat`, `head`, `tail`, `less`, `more`, `bat`, `nl`, the target files are read and scanned before the command runs. Compound commands using `|`, `;`, `&&`, `||` are split and each segment is checked independently.

## Custom Rules

All built-in rules are defined in `src/lib/default-config.json` as JSON data. You can add your own rules or override built-in ones without modifying the plugin source.

### Config file

Create `~/.config/sensitive-canary/config.json`, or set the `SENSITIVE_CANARY_CONFIG` environment variable to a custom path (e.g. in the `env` block of your Claude Code `settings.json`).

### Rule fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique identifier. Matching a built-in id overrides it. |
| `description` | string | yes | Human-readable label shown in block messages. |
| `regex` | string | yes | Regex source (not a `/literal/`). |
| `category` | `"secret"` \| `"pii"` | yes | Which category the rule belongs to. |
| `flags` | string | no | Regex flags. Default `"g"`. |
| `secretGroup` | number | no | Capture group containing the secret. Default 0 (full match). |
| `entropyThreshold` | number | no | Skip matches below this Shannon entropy (bits/char). |
| `requireContext` | boolean | no | Only fire when a context word is nearby. |
| `contextWords` | string[] | no | Words that satisfy `requireContext`. |
| `contextWindow` | number | no | Per-rule override for context scan width (tokens). |
| `validate` | string | no | Name of a built-in checksum validator. |

### Available validators

| Name | Algorithm |
|------|-----------|
| `luhn` | Luhn checksum (credit cards) |
| `mynumber-jp` | Japanese Individual Number (My Number) |
| `nir-fr` | French NIR / Social Security Number |
| `codice-fiscale-it` | Italian Codice Fiscale |
| `steuer-id-de` | German Steuer-Identifikationsnummer |
| `dni-nie-es` | Spanish DNI / NIE |
| `rrn-kr` | Korean Resident Registration Number |
| `brn-kr` | Korean Business Registration Number |
| `resident-id-cn` | Chinese Resident Identity Card |
| `public-ipv4` | Rejects reserved IPv4 ranges |
| `public-ipv6` | Rejects reserved IPv6 ranges |

### Global context window

Set `contextWindow` at the top level to override the default (3 tokens ≈ 24 characters):

```json
{
  "contextWindow": 5,
  "rules": []
}
```

### Examples

Add a custom secret pattern:

```json
{
  "rules": [
    {
      "id": "custom-api-key",
      "description": "My Service API Key",
      "regex": "MYSVC-[A-Za-z0-9]{32}",
      "category": "secret",
      "entropyThreshold": 3.5
    }
  ]
}
```

Add a context-gated PII rule:

```json
{
  "rules": [
    {
      "id": "employee-id",
      "description": "Employee ID",
      "regex": "EMP\\d{6}",
      "category": "pii",
      "requireContext": true,
      "contextWords": ["employee", "staff", "社員"]
    }
  ]
}
```

Override a built-in rule (same `id` replaces the original):

```json
{
  "rules": [
    {
      "id": "pii-email",
      "description": "Internal Email Only",
      "regex": "[A-Za-z0-9]+@internal\\.corp\\.(com|org)",
      "category": "pii"
    }
  ]
}
```

Invalid rules (bad regex, wrong types, missing required fields) are skipped with a warning on stderr. The rest of the config loads normally. Each rule is validated against a strict schema before compilation:

- **Required**: `id`, `description`, `regex` (non-empty strings), `category` (`"secret"` or `"pii"`)
- **Type-checked**: `flags` (string), `secretGroup` (non-negative integer), `entropyThreshold` (non-negative number), `validate` (string), `contextWords` (array of non-empty strings), `requireContext` (boolean), `contextWindow` (positive integer)
- **Cross-field**: `requireContext: true` without `contextWords` is rejected (empty `contextWords` would disable context gating, making the rule fire on every match)

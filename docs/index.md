---
layout: home

hero:
  name: Sensitive Canary
  text: Secrets and PII guard for Claude Code
  tagline: A security plugin that prevents unintended data leaks from Claude Code. Automatically detects and blocks AWS keys, tokens, email addresses, credit card numbers, and more before they are sent to the API.
  image:
    src: /logo.svg
    alt: Sensitive Canary
  actions:
    - theme: brand
      text: Get Started
      link: /install
    - theme: alt
      text: Detection Rules
      link: /rules
    - theme: alt
      text: GitHub
      link: https://github.com/coo-quack/sensitive-canary

features:
  - icon: 🔑
    title: Secret Detection
    details: Catches AWS keys, GitHub PATs, Stripe keys, JWTs, Anthropic/OpenAI API keys, database connection strings, and 15+ more credential types.
  - icon: 🕵️
    title: PII Detection
    details: Detects email addresses, credit card numbers, US SSNs, phone numbers, Japanese postal codes, and private IPv4 addresses.
  - icon: 🛡️
    title: Pre-Tool-Use Hook
    details: Scans files before Claude reads them. Blocks .env files by name and any file whose contents contain secrets or PII.
  - icon: 📨
    title: Prompt Submit Hook
    details: Scans every prompt before it is sent to the Anthropic API. Secrets or PII in your message are caught before they leave your machine.
  - icon: 🏷️
    title: Allow Tags
    details: Need to share a key intentionally? Add [allow-secret], [allow-pii], or [allow-all] to your prompt to bypass specific checks.
  - icon: 🐦
    title: Zero Config
    details: Install once as a Claude Code plugin. No API keys, no servers, no configuration files needed.
---

## Why Sensitive Canary?

Claude Code is a powerful development tool, but file reads and command executions can inadvertently send secrets and personal information to the Anthropic API. API keys in `.env` files, tokens embedded in config files, credentials pasted into the terminal — once sent to the API, they leave your machine.

**Sensitive Canary intercepts them before they are sent, preventing unintended data leaks.**

| Without Sensitive Canary | With Sensitive Canary |
|--------------------------|----------------------|
| `cat .env` → full contents sent to Claude ❌ | Blocked by name before Claude reads it ✅ |
| Paste `AKIAIOSFODNN7EXAMPLE` in prompt ❌ | Blocked before the API call is made ✅ |
| Tool result contains user@email.com ❌ | PII detected and blocked ✅ |
| `echo $API_KEY` with live key ❌ | Env var value scanned and blocked ✅ |

- **Two hooks** — `UserPromptSubmit` and `PreToolUse` cover both directions of risk
- **29 detection rules** — sourced from gitleaks and TruffleHog detector definitions
- **Entropy filtering** — reduces false positives on low-entropy values
- **Luhn validation** — credit card numbers are validated, not just pattern-matched
- **Local only** — all scanning runs in your terminal; nothing is sent anywhere

## Quick Start

Install with two commands inside a Claude Code session:

```bash
# 1. Register the marketplace
/plugin marketplace add coo-quack/sensitive-canary

# 2. Install the plugin
/plugin install sensitive-canary@coo-quack
```

After installation, restart Claude Code and the hooks are active. No additional configuration needed.

### What Happens

Just use Claude Code as usual. sensitive-canary runs in the background and automatically scans at three points:

- **On prompt submission** — checks your input for secrets and PII before it reaches the API
- **On file read** — checks file names and contents before Claude reads them
- **On command execution** — checks Bash commands and environment variable values for secrets

When sensitive data is detected, the action is blocked and the terminal shows what was found. To intentionally allow it, add `[allow-secret]` or `[allow-all]` to your prompt.

See [installation guide →](/install) for manual setup options.

## Detection Rules

| Category | Examples |
|----------|---------|
| **Cloud credentials** | AWS Access Key, GCP service account key |
| **Source control** | GitHub PAT, GitHub fine-grained token, GitLab PAT |
| **AI services** | Anthropic API key, OpenAI API key / project key |
| **Communication** | Slack token, Slack webhook, Discord webhook, Telegram bot token |
| **Payment** | Stripe secret/restricted key, credit card numbers (Luhn-validated) |
| **Email services** | SendGrid API key, Mailgun key, Mailchimp key |
| **Auth tokens** | JWT, database connection strings |
| **PII** | Email address, US SSN, US/JP phone, Japanese postal code, private IPv4 |

[View all detection rules →](/rules)

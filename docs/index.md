---
layout: home

hero:
  name: sensitive-canary
  text: Secrets and PII guard for Claude Code
  tagline: Automatically blocks AWS keys, tokens, emails, credit cards, and more before they leave your machine
  image:
    src: /logo.svg
    alt: sensitive-canary
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

## Why sensitive-canary?

Secrets and PII end up in AI conversations more often than you'd expect — pasted from a terminal, echoed in a config file, or embedded in a tool result. Once they reach the API, they leave your machine.

**sensitive-canary intercepts them first.**

| Without sensitive-canary | With sensitive-canary |
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

```bash
# Install as a Claude Code plugin
claude plugin install coo-quack/sensitive-canary
```

Once installed, sensitive-canary runs automatically on every session. See [installation →](/install) for manual setup options.

## What Gets Detected

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

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
      link: /getting-started
    - theme: alt
      text: Detection Rules
      link: /rules
    - theme: alt
      text: GitHub
      link: https://github.com/coo-quack/sensitive-canary

features:
  - icon: 🔑
    title: Secret Detection
    details: Catches AWS keys, GitHub PATs, Stripe keys, JWTs, Anthropic/OpenAI API keys, database connection strings, Replicate/Hugging Face/Groq/xAI tokens, DigitalOcean/Square/Sentry/Linear tokens, and 20+ more credential types.
  - icon: 🕵️
    title: PII Detection
    details: Detects email addresses, credit card numbers (Luhn-validated), US SSNs, phone numbers (JP/US/FR/IT/DE/ES/KR/CN), national IDs with checksum validation (My Number, NIR, Codice Fiscale, Steuer-IdNr., DNI/NIE, RRN, BRN, Chinese Resident ID), postal codes, and public IP addresses.
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
    details: Install once as a Claude Code plugin. No API keys, no servers. Optionally add custom rules via a JSON config file.
---

## Why Sensitive Canary?

Claude Code is a powerful development tool, but file reads and command executions can inadvertently send secrets and personal information to the Anthropic API. API keys in `.env` files, tokens embedded in config files, credentials pasted into the terminal — once sent to the API, they leave your machine.

**Sensitive Canary intercepts them before they are sent, preventing unintended data leaks.**

| Without Sensitive Canary | With Sensitive Canary |
|--------------------------|----------------------|
| `cat .env` → full contents sent to Claude ❌ | Blocked by name by default before Claude reads it ✅ |
| Paste `AKIAIOSFODNN7EXAMPLE` in prompt ❌ | Blocked before the API call is made ✅ |
| `Read customers.csv` full of email addresses ❌ | PII detected before Claude sees the file ✅ |
| `echo $API_KEY` with live key ❌ | Env var value scanned and blocked ✅ |

- **Two hooks** — `UserPromptSubmit` and `PreToolUse` cover both directions of risk
- **74 detection rules** — sourced from gitleaks and TruffleHog detector definitions
- **Context gating** — the noisiest PII rules (non-US/JP phone numbers, postal codes, public IP addresses) only fire when a relevant label is nearby; US and JP phone numbers and JP postal codes are matched without one
- **Entropy filtering** — reduces false positives on low-entropy values
- **Luhn validation** — credit card numbers are validated, not just pattern-matched
- **Local only** — all scanning runs in your terminal; nothing is sent anywhere

## Detection Rules

| Category | Examples |
|----------|---------|
| **Cloud credentials** | AWS Access Key, GCP API key |
| **Source control** | GitHub PAT, GitHub fine-grained token, GitLab PAT |
| **AI services** | Anthropic API key, OpenAI API key / project key, Replicate, Hugging Face, Groq, OpenRouter, xAI, Perplexity |
| **Communication** | Slack token, Slack webhook, Discord webhook, Telegram bot token |
| **Payment** | Stripe secret/restricted key, Square access token, credit card numbers (Luhn-validated) |
| **Email services** | SendGrid API key, Mailgun key, Mailchimp key |
| **Cloud / IaaS** | DigitalOcean PAT, Supabase PAT |
| **SaaS / Dev tools** | Mapbox, Sentry, Atlassian, Linear, Postman |
| **Auth tokens** | JWT, database connection strings |
| **PII** | Email, US SSN, phone (8 countries), national IDs (7 countries), postal codes, IP addresses |

[View all detection rules →](/rules)

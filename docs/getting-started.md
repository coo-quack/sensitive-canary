# Getting Started

Get Sensitive Canary protecting your Claude Code session in under a minute.

## Install

Install with two commands inside a Claude Code session:

```bash
# 1. Register the marketplace
/plugin marketplace add coo-quack/claude-code-marketplace

# 2. Install the plugin
/plugin install sensitive-canary@coo-quack
```

After installation, the hooks are active immediately. No restart or additional configuration needed.

For alternative installation methods (pnpm global, manual git clone), see the [Installation](/install) page.

## What Happens

Just use Claude Code as usual. Sensitive Canary runs in the background and automatically scans at three points:

- **On prompt submission** — checks your input for secrets and PII before it reaches the API
- **On file read** — checks file names and contents before Claude reads them
- **On command execution** — checks Bash commands and environment variable values for secrets

When sensitive data is detected, the action is blocked and the terminal shows what was found. To intentionally allow it, add `[allow-secret]` or `[allow-all]` to your prompt.

## Allow Tags

| Tag | Effect |
|-----|--------|
| `[allow-secret]` | Allow secrets through for this prompt |
| `[allow-pii]` | Allow PII through for this prompt |
| `[allow-all]` | Bypass all sensitive-canary checks for this prompt |

Tags apply only to the message they appear in. They do not persist across turns. For PreToolUse hooks, allow tags are single-use — they are consumed by the first tool call. If Claude needs to perform multiple tool calls for the same request, you may need to include the tag again.

## Configuration

Set `SENSITIVE_CANARY_CATEGORIES` in the `env` block of your Claude Code `settings.json` to limit which rule categories are active:

```json
{
  "env": {
    "SENSITIVE_CANARY_CATEGORIES": "secret"
  }
}
```

| Value | Effect |
|-------|--------|
| `secret` | Scan for secrets only — PII rules are disabled |
| `pii` | Scan for PII only — secret rules and the name-based `.env`/`.env.*` block are disabled |
| `secret,pii` / `all` | Scan everything (default) |

This persistent filter is applied before allow tags. A typical use is setting `secret` when PII rules are too noisy against test fixtures.

## Next Steps

- [Installation](/install) — alternative installation methods
- [Detection Rules](/rules) — all 31 detection rules explained

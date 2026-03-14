# Getting Started

Get Sensitive Canary protecting your Claude Code session in under a minute.

## Install

Install with two commands inside a Claude Code session:

```bash
# 1. Register the marketplace
/plugin marketplace add coo-quack/sensitive-canary

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

## Next Steps

- [Installation](/install) — alternative installation methods
- [Detection Rules](/rules) — all 31 detection rules explained

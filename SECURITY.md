# Security Policy

## Overview

Sensitive Canary is a **local-only security tool** that runs entirely within your terminal as Claude Code hooks. It does not:

- Send data to external servers
- Log data to files or remote services
- Store scanned content persistently
- Communicate over the network

All scanning is performed **locally** and **in-memory**.

---

## What Sensitive Canary Protects Against

Sensitive Canary intercepts secrets and PII before they leave your machine:

| Risk | Hook | How it helps |
|------|------|--------------|
| Secret in prompt | `UserPromptSubmit` | Blocks the prompt before the API call |
| PII in prompt | `UserPromptSubmit` | Blocks the prompt before the API call |
| Secret in file Claude reads | `PreToolUse` (Read) | Blocks the file read before contents are sent |
| `.env` file exposure | `PreToolUse` (Read) | Blocks by filename (secret category only) |
| Secret in Bash command | `PreToolUse` (Bash) | Blocks the command before execution |
| Secret in env var value | `PreToolUse` (Bash) | Expands and scans `$VAR` references |

---

## Limitations

sensitive-canary is a best-effort guard, not a guaranteed security boundary:

- **Pattern coverage** — Only secrets matching defined rules are detected. Unknown or novel credential formats may not be caught.
- **Entropy filtering** — Generic rules use Shannon entropy thresholds to reduce false positives. Low-entropy values that happen to be real secrets may pass through.
- **Allow tags** — Any block can be bypassed by the user with `[allow-secret]`, `[allow-pii]`, or `[allow-all]`. This is intentional — the tool assists, not enforces.
- **Hook execution** — If the Node.js process fails to start, the hook does not block the call. It does not exit 0 to do so: node exits with its own status (9 for an unknown flag), and Claude Code treats anything other than 2 as "do not block". A hook killed by the PreToolUse timeout is the same case, which is why the scan bounds what it reads and what its patterns can cost.
- **Parse errors** — If the hook input cannot be parsed, the hook exits 2 and the call is stopped. The check did not finish, and "unknown" is not "safe". Empty stdin is the one exception: there is nothing to check, so it exits 0.
- **Files holding NUL bytes** — every run of text between the NUL bytes is scanned, joined by newlines so that no rule matches across two unrelated runs. A file that holds a NUL is still judged on its name where the `.env` guard applies, since part-binary contents cannot speak for the name.
- **Scope** — The default matcher is `Read|Bash|Grep|mcp__.*`, so `Read`, `Bash`, `Grep` and every MCP tool are intercepted. A tool outside the matcher is not scanned at all, and a tool inside it is scanned for the input fields that name a file — see Known Limitations in the README for what that does not reach.
- **Tool results are not scanned** — there is no `PostToolUse` hook. What a tool returns, having been allowed, is not inspected.

---

## Sensitive Data Handling

All scanned content is processed in memory and immediately discarded. Detected findings are:

- Displayed in the terminal (redacted: first 4 + last 4 chars, middle masked as `****`)
- Returned to Claude as a structured block reason (redacted)
- Never written to disk or sent anywhere

---

## Reporting Security Issues

- **Email:** dev@quack.jp
- **GitHub:** [Open a security advisory](https://github.com/coo-quack/sensitive-canary/security/advisories/new)

Please do **not** open public GitHub issues for security vulnerabilities.
We aim to respond within 48 hours.

---

## Compliance

- GDPR-friendly (no personal data storage or transmission by this tool)
- All processing is local; no third-party services are involved

**Note:** Compliance is an organizational and process claim. Always follow your organization's security policies.

---

**Last Updated:** See Git history for this file.

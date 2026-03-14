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
| `.env` file exposure | `PreToolUse` (Read) | Blocks by filename, unconditionally |
| Secret in Bash command | `PreToolUse` (Bash) | Blocks the command before execution |
| Secret in env var value | `PreToolUse` (Bash) | Expands and scans `$VAR` references |

---

## Limitations

sensitive-canary is a best-effort guard, not a guaranteed security boundary:

- **Pattern coverage** — Only secrets matching defined rules are detected. Unknown or novel credential formats may not be caught.
- **Entropy filtering** — Generic rules use Shannon entropy thresholds to reduce false positives. Low-entropy values that happen to be real secrets may pass through.
- **Allow tags** — Any block can be bypassed by the user with `[allow-secret]`, `[allow-pii]`, or `[allow-all]`. This is intentional — the tool assists, not enforces.
- **Hook execution** — If the Node.js process fails to start (e.g., wrong Node version), the hook exits 0 (pass) to avoid blocking Claude entirely.
- **Parse errors** — If the hook input cannot be parsed (malformed JSON from Claude Code), the hook exits 0 (pass) as a fail-open fallback.
- **File size limit** — Only the first 1 MB of a file is scanned. Secrets beyond this boundary are not detected.
- **Binary files** — Binary files are detected by the presence of a NUL byte. Only the text portion before the first NUL is scanned; content after the NUL is not checked.
- **Scope** — Only `Read` and `Bash` tool calls are intercepted. Other tool types are not scanned.

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

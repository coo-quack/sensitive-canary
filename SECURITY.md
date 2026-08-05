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
| Secret in a file a Bash command would print | `PreToolUse` (Bash) | Resolves the file arguments of printing commands, including behind wrappers, inline scripts, redirections and substitutions |
| Whole environment printed | `PreToolUse` (Bash) | Scans every variable when a bare `env` or `printenv` would print it |
| Secret in a file Claude greps | `PreToolUse` (Grep) | Blocks when the target is a single file |
| Secret in a file an MCP tool would return | `PreToolUse` (MCP) | Scans input fields that name an existing file |

---

## Limitations

sensitive-canary is a best-effort guard, not a guaranteed security boundary:

- **Pattern coverage** — Only secrets matching defined rules are detected. Unknown or novel credential formats may not be caught.
- **Entropy filtering** — Generic rules use Shannon entropy thresholds to reduce false positives. Low-entropy values that happen to be real secrets may pass through.
- **Allow tags** — Any block can be bypassed by the user with `[allow-secret]`, `[allow-pii]`, or `[allow-all]`. This is intentional — the tool assists, not enforces.
- **Hook execution** — If the Node.js process fails to start (e.g., wrong Node version), the hook exits 0 (pass) to avoid blocking Claude entirely.
- **Parse errors** — If the hook input cannot be parsed (malformed JSON from Claude Code), the hook exits 0 (pass) as a fail-open fallback.
- **Binary files** — Binary files are detected by the presence of a NUL byte. Only the text portion before the first NUL is scanned; content after the NUL is not checked.
- **Scope** — `Read`, `Bash`, `Grep` and MCP tool calls are intercepted. Tools whose name says they write are skipped, as are tools not matched by the configured `matcher`.
- **Run-time paths** — a file is only found when its path appears literally in the command. A path held in a shell variable (`f=.env; cat "$f"`), arriving over a pipe (`find … | xargs cat`), or opened by a program the command merely starts (`python script.py`) is resolved after the hook has already decided.
- **Command classification** — the set of commands known to print file contents is a list, not an analysis. An unlisted command that prints a file is not caught, and `grep -r` over a directory is not scanned because no single file is named.
- **git history** — `git show HEAD:.env` names an object in history rather than a file on disk, so it is not scanned.

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

# Installation

sensitive-canary runs as a set of Claude Code hooks. The recommended way is to install it as a plugin.

## Claude Code Plugin

Run the following two commands inside a Claude Code session:

**1. Register the marketplace**

```
/plugin marketplace add coo-quack/sensitive-canary
```

**2. Install the plugin**

```
/plugin install sensitive-canary@coo-quack
```

Claude Code will download the plugin and register the hooks automatically. No restart is required.

## Manual Setup

If you prefer to configure hooks manually, clone the repository and point your hooks configuration at the scripts.

**1. Clone the repository**

```bash
git clone https://github.com/coo-quack/sensitive-canary.git ~/.claude/plugins/sensitive-canary
```

**2. Install dependencies**

```bash
cd ~/.claude/plugins/sensitive-canary
npm install
```

**3. Register hooks**

Add the following to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|Bash",
        "hooks": [
          {
            "type": "command",
            "command": "node --experimental-strip-types ~/.claude/plugins/sensitive-canary/src/pre-tool-use-hook.ts"
          }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "node --experimental-strip-types ~/.claude/plugins/sensitive-canary/src/user-prompt-submit-hook.ts"
          }
        ]
      }
    ]
  }
}
```

## Requirements

- Node.js **22.6.0** or later (required for `--experimental-strip-types`)
- Claude Code

Check your Node.js version:

```bash
node --version
```

## What Happens

sensitive-canary adds two hooks to your Claude Code session:

### UserPromptSubmit hook

Runs before every prompt is sent to the Anthropic API. If secrets or PII are detected in your message, the prompt is blocked and you'll see a message like:

```
🐦 sensitive-canary: sensitive data detected — blocked

  [Secret] AWS Access Key ID (aws-access-key): AKIA****MPLE

To allow, add a tag to your prompt:
  [allow-secret]  — allow secrets
  [allow-all]     — bypass all sensitive-canary checks
```

### PreToolUse hook

Runs before Claude uses the `Read` or `Bash` tool. It blocks:

- `.env` and `.env.*` files unconditionally (by filename)
- Any file whose contents contain secrets or PII
- `cat`, `head`, `tail`, and other file-reading commands targeting sensitive files
- Bash commands containing secrets inline (e.g. `echo AKIAIOSFODNN7EXAMPLE`)
- Environment variables referenced in Bash commands whose values contain secrets

## Allow Tags

When a block is triggered, sensitive-canary tells Claude which tag to suggest. You add the tag to your next prompt to bypass the specific check:

| Tag | Effect |
|-----|--------|
| `[allow-secret]` | Allow secrets through for this prompt |
| `[allow-pii]` | Allow PII through for this prompt |
| `[allow-all]` | Bypass all sensitive-canary checks for this prompt |

**Example:**

```
[allow-secret] Please review my .env.example file at /path/to/.env.example
```

Allow tags apply only to the message they appear in. They do not persist across turns. Tags are case-insensitive.

## Mask Tags

`[mask-secret]`, `[mask-pii]`, and `[mask-all]` are recognised but **not supported**. Claude Code hooks cannot rewrite prompt content before it is sent.

If you use a mask tag, sensitive-canary will display an explanation and list what was detected:

```
🐦 sensitive-canary: prompt masking is not supported

  [mask-secret] cannot mask prompt content.
  The following sensitive data was detected:

  [Secret] AWS Access Key ID (aws-access-key): AKIA****MPLE

  Please choose one of the following:

  1. Manually redact the values above and resubmit
  2. To send as-is, add an allow tag to your prompt:
       [allow-secret]  — allow secrets
       [allow-all]     — bypass all sensitive-canary checks
```

To proceed, either manually redact the sensitive value and resubmit, or replace the mask tag with the corresponding allow tag.

## Uninstall

To remove the plugin:

```bash
claude plugin remove sensitive-canary
```

For manual installs, remove the hooks entries from your hooks configuration and delete the cloned directory.

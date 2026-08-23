# Installation

Sensitive Canary runs as a set of Claude Code hooks. The recommended way is to install it as a plugin.

## Claude Code Plugin

Run the following two commands inside a Claude Code session:

**1. Register the marketplace**

```
/plugin marketplace add coo-quack/claude-code-marketplace
```

**2. Install the plugin**

```
/plugin install sensitive-canary@coo-quack
```

Claude Code will download the plugin and register the hooks automatically.

A session that is already running does not pick them up. It reports the install as successful and lists the plugin as enabled, and checks nothing until it is restarted — which is exactly the state this tool exists to prevent, and it is invisible. Start a new session, then check that it blocks.

**3. Check that it blocks**

An installation that checks nothing looks exactly like one that works, and only
exit 2 stops a tool call, so a hook that fails to start is silent. This step is
not optional.

```bash
printf -- '-----BEGIN RSA PRIVATE KEY-----\n' > /tmp/canary-check.txt
```

Ask Claude to read `/tmp/canary-check.txt`. It should refuse and say why. If it
reads the file and shows you what is in it, the hooks are not running — see
[Troubleshooting](/troubleshooting).

A private-key header is the fixture here because it carries no key material and
is recognised on its own. AWS's documented `AKIAIOSFODNN7EXAMPLE` will not do:
it appears in AWS's own setup guides and in READMEs that copy them, so this tool
reads it as documentation and allows it.

### Updating

Third-party marketplaces have auto-update disabled by default. To receive automatic updates:

1. Run `/plugin` → **Marketplaces** tab
2. Select the marketplace → **Enable auto-update**

You can also update manually from the same tab. See [Discover and install plugins](https://code.claude.com/docs/en/discover-plugins) for details.

## pnpm Install

Install globally via pnpm and configure hooks in your settings:

**1. Install the package**

```bash
pnpm add -g @coo-quack/sensitive-canary
```

Update to the latest version:

```bash
pnpm update -g @coo-quack/sensitive-canary
```

**2. Find where pnpm put it**

`pnpm root -g` does not name the directory the package ends up in — on pnpm 10
and later it returns a versioned root with no `node_modules` under it, and a
hook wired to that path fails to start. A hook that fails to start exits 1, and
only exit 2 blocks, so the mistake is silent. Ask where the file actually is:

```bash
find "$(pnpm root -g)" -path '*@coo-quack/sensitive-canary/dist/pre-tool-use-hook.js' 2>/dev/null
```

**3. Register hooks**

Put the directory that command prints — everything up to and including `dist` —
in place of `<dist>` below, in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|NotebookRead|Bash|Grep|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "node <dist>/pre-tool-use-hook.js"
          }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "node <dist>/user-prompt-submit-hook.js"
          }
        ]
      }
    ]
  }
}
```

These point at the compiled JavaScript the package ships. Node refuses to strip
types from a `.ts` file inside `node_modules`, and a hook that fails to start
exits non-zero without blocking — so an installation wired to `src/` looks
installed and checks nothing. The plugin install uses the `.ts` sources, which
sit outside `node_modules` and work.

**4. Check that it blocks**

An installation that checks nothing looks exactly like one that works, so this
step is not optional. Run the hook by hand and read the exit code:

```bash
printf -- '-----BEGIN RSA PRIVATE KEY-----\n' > /tmp/canary-check.txt
printf '{"tool_name":"Read","tool_input":{"file_path":"/tmp/canary-check.txt"}}' \
  | node <dist>/pre-tool-use-hook.js; echo "exit=$?"
```

`exit=2` means it is working. Anything else — 0, 1, or a module-not-found error
— means the path is wrong and nothing is being checked.

The fixture is a private-key header rather than a key: it carries no key
material and is recognised on its own. AWS's documented `AKIAIOSFODNN7EXAMPLE`
would report `exit=0` here, because this tool reads it as the documentation it
is — see [Rules](/rules).


## Manual Setup (git clone)

Clone the repository and point your hooks configuration at the scripts:

**1. Clone the repository**

```bash
git clone https://github.com/coo-quack/sensitive-canary.git ~/.claude/plugins/sensitive-canary
```

Update to the latest version:

```bash
cd ~/.claude/plugins/sensitive-canary && git pull
```

**2. Install dependencies**

```bash
cd ~/.claude/plugins/sensitive-canary
pnpm install
```

**3. Register hooks**

Add the following to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|NotebookRead|Bash|Grep|mcp__.*",
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

**4. Check that it blocks**

An installation that checks nothing looks exactly like one that works, so this
step is not optional. Run the hook by hand and read the exit code:

```bash
printf -- '-----BEGIN RSA PRIVATE KEY-----\n' > /tmp/canary-check.txt
printf '{"tool_name":"Read","tool_input":{"file_path":"/tmp/canary-check.txt"}}' \
  | node --experimental-strip-types ~/.claude/plugins/sensitive-canary/src/pre-tool-use-hook.ts; echo "exit=$?"
```

`exit=2` means it is working. Anything else — 0, 1, or a module-not-found error
— means the path is wrong and nothing is being checked. The same fixture works
for every install method; a private-key header is chosen because it carries no
key material and is recognised on its own — see the note under the plugin
install.

## Requirements

- Node.js **22.6.0** or later (required for `--experimental-strip-types`)
- Claude Code

Check your Node.js version:

```bash
node --version
```

## Configuration

Two environment variables change what the hooks scan. Set them in the `env` block of your Claude Code `settings.json`:

| Variable | Effect |
|----------|--------|
| `SENSITIVE_CANARY_CATEGORIES` | Limit which rule categories are active: `secret`, `pii`, or `secret,pii` / `all` (default) |
| `SENSITIVE_CANARY_CONFIG` | Path to a custom rules file that adds rules or overrides built-in ones |

A typical use of `SENSITIVE_CANARY_CATEGORIES` is `secret`, when the PII rules are too noisy against test fixtures. There is no per-rule or per-path exclusion environment variable: narrowing the scan means a category, or a config file that overrides the rule. See [Detection Rules](/rules) for both variables.

## What Happens

Sensitive Canary adds two hooks to your Claude Code session:

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

Runs before Claude uses `Read`, `NotebookRead`, `Bash`, `Grep` or any MCP tool. It blocks:

- `.env` and `.env.*` files by filename (a secret guard; only while the `secret` category is enabled)
- Any file whose contents contain secrets or PII
- `cat`, `head`, `tail`, and other file-reading commands targeting sensitive files
- Bash commands containing secrets inline (e.g. `echo ghp_…`)
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

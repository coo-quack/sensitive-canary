# Sensitive Canary

[![CI](https://github.com/coo-quack/sensitive-canary/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/coo-quack/sensitive-canary/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A security plugin that prevents unintended data leaks from Claude Code. Automatically detects and blocks secrets and PII — in prompts, file reads, and command executions — before they are sent to the Anthropic API.

No proxy server. No background process. Native Claude Code hooks only.

📖 **[Documentation](https://coo-quack.github.io/sensitive-canary/)** — Installation guide, detection rules reference, and allow tag details.

---

## Why sensitive-canary?

Claude Code is a powerful development tool, but file reads and command executions can inadvertently send secrets and personal information to the Anthropic API. API keys in `.env` files, tokens embedded in config files, credentials pasted into the terminal — once sent to the API, they leave your machine.

**sensitive-canary intercepts them before they are sent, preventing unintended data leaks.**

| Without sensitive-canary | With sensitive-canary |
|--------------------------|----------------------|
| `cat .env` → full contents sent to Claude ❌ | Blocked by name before Claude reads it ✅ |
| Paste `AKIAIOSFODNN7EXAMPLE` in prompt ❌ | Blocked before the API call is made ✅ |
| `Read customers.csv` full of email addresses ❌ | PII detected before Claude sees the file ✅ |
| `echo $API_KEY` with live key ❌ | Env var value scanned and blocked ✅ |
| `cat docker-compose.yml` with `POSTGRES_PASSWORD:` ❌ | Assignment detected in YAML and JSON too ✅ |

- **Two hooks** — `UserPromptSubmit` and `PreToolUse` cover both directions of risk
- **76 detection rules** — sourced from gitleaks and TruffleHog detector definitions
- **Checksum validation** — credit cards (Luhn) and national ID numbers (JP My Number, FR NIR, IT Codice Fiscale, DE Steuer-IdNr., ES DNI/NIE, KR RRN/BRN, CN Resident ID)
- **Context gating** — the noisiest rules only fire when a label is nearby: non-US/JP phone numbers, ZIP, EU/KR and Chinese postal codes, public IPv4 and IPv6, and the Korean resident and business numbers. US and Japanese phone numbers and Japanese postal codes are matched without a label, since their shapes are specific enough. RFC 1918 private addresses are not matched at all — they are non-routable, they identify nothing outside the network they belong to, and they fill the inventories, manifests and ssh configs this tool is most often pointed at
- **Not everything that looks like a secret is one** — published test card numbers, RFC 2606 domains (`example.com`), a value that is a variable reference (`PASSWORD: ${VAR}`), an ssh or scp target (`git@github.com`, `deploy@host`, `user@host:path`), and `.env.example` and its siblings are left alone. Each was blocking ordinary work. A template is exempt only when its contents can be read whole. One holding a NUL byte, running past the per-file cut, reached after the call's budget or deadline, or that is not a regular file at all is blocked on its name, since the contents are what the exemption relies on. A template name that exists on no disk is not blocked — there is nothing to read and nothing to leak
- **Entropy filtering** — reduces false positives on low-entropy values
- **Local only** — all scanning runs in your terminal; nothing is sent anywhere

---

## Quick Start

### Requirements

- Node.js **22.6.0** or later (required for `--experimental-strip-types`)
- Claude Code 1.0.33 or later

### Plugin install (recommended)

Install in two commands from inside a Claude Code session:

**1. Register the marketplace**

```
/plugin marketplace add coo-quack/claude-code-marketplace
```

**2. Install the plugin**

```
/plugin install sensitive-canary@coo-quack
```

The hooks are enabled for every session started after this. A session that was
already running does not pick them up — it reports the plugin as enabled and
checks nothing — so start a new one.

**Then check that it blocks.** An installation that checks nothing looks exactly
like one that works, and only exit 2 stops a tool call, so a hook that fails to
start is silent. Write a file holding `AKIA` followed by `IOSFODNN7EXAMPLE` and
ask Claude to read it. It should refuse and say why. If it shows you the key, the
hooks are not running.

> **Keeping up to date:** Third-party marketplaces have auto-update disabled by default. To receive automatic updates, run `/plugin` → **Marketplaces** tab → select the marketplace → **Enable auto-update**. You can also update manually from the same tab. See [Discover and install plugins](https://docs.anthropic.com/en/docs/claude-code/discover-plugins) for details.

<details>
<summary>npm install</summary>

Install locally via npm and configure hooks manually:

```bash
npm install -g @coo-quack/sensitive-canary
```

Update to the latest version:

```bash
npm update -g @coo-quack/sensitive-canary
```

Then add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "node $(npm root -g)/@coo-quack/sensitive-canary/dist/user-prompt-submit-hook.js"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Read|Bash|Grep|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "node $(npm root -g)/@coo-quack/sensitive-canary/dist/pre-tool-use-hook.js"
          }
        ]
      }
    ]
  }
}
```

> **Note:** These point at the compiled JavaScript the package ships. Node refuses to strip types from a `.ts` file inside `node_modules`, and a hook that fails to start exits non-zero without blocking — so an installation wired to `src/` looks installed and checks nothing. The plugin install uses the `.ts` sources, which sit outside `node_modules` and work.

</details>

<details>
<summary>Manual setup (git clone)</summary>

Clone the repository and configure hooks manually:

```bash
git clone https://github.com/coo-quack/sensitive-canary.git ~/sensitive-canary
```

Update to the latest version:

```bash
cd ~/sensitive-canary && git pull
```

Then add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "node --experimental-strip-types ~/sensitive-canary/src/user-prompt-submit-hook.ts"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Read|Bash|Grep|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "node --experimental-strip-types ~/sensitive-canary/src/pre-tool-use-hook.ts"
          }
        ]
      }
    ]
  }
}
```

</details>

---

## What Happens

### Prompt blocked

Prompts containing secrets or PII are blocked before being sent.

```
> My AWS key is AKIAIOSFODNN7EXAMPLE. Can you review this code?

🐤  sensitive-canary: sensitive data detected — blocked

  [Secret] AWS Access Key ID (aws-access-key): AKIA****MPLE

To allow, add a tag to your prompt:
  [allow-secret]  — allow secrets
  [allow-all]     — bypass all sensitive-canary checks
```

To allow it through, add the suggested tag:

```
> [allow-secret] My AWS key is AKIAIOSFODNN7EXAMPLE. Can you review this code?
```

### .env file blocked

`.env` and its siblings are blocked by filename, before anything is read. Template names — `.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `.env.defaults` — are the exception: they are meant to be committed, so they are read and judged on their contents like any other file. A template that turns out to hold a real credential is still blocked, and one whose contents cannot be read whole falls back to the name. This name-based block is a secret guard and only applies while the `secret` category is enabled (the default).

```
> Read .env

🐤 sensitive-canary: blocked — /path/to/.env

🚫 Blocked: .env and .env.* files contain secrets and must not be read into the conversation.

To allow this, the user must add an allow tag to their next prompt:
  [allow-secret]  — allow secrets
  [allow-pii]     — allow PII
  [allow-all]     — bypass all sensitive-canary checks

Example: "[allow-secret] please read /path/to/.env"
```

### File content blocked

Non-`.env` files are also blocked if their contents contain secrets or PII.

```
> Read config.yaml

🐤 sensitive-canary: blocked — /path/to/config.yaml

🚫 Blocked: file contains sensitive data

  [Secret] AWS Access Key ID (aws-access-key): AKIA****MPLE
```

### Allow tags

To intentionally bypass a block, include the appropriate tag in your **current prompt**.

| Tag | Effect |
|---|---|
| `[allow-secret]` | Skip all secret-category checks |
| `[allow-pii]` | Skip all PII-category checks |
| `[allow-all]` | Skip all sensitive-canary checks |

> **Note:** Tags are read from the **current user message only**. Tags in previous messages are ignored — there is no risk of an accidental persistent bypass. Tags are case-insensitive. `[allow-secret]` does not bypass PII blocks (and vice versa). The name-based block on `.env`/`.env.*` files is a secret guard, so `[allow-secret]` and `[allow-all]` lift it and `[allow-pii]` does not.

---

## Configuration

### `SENSITIVE_CANARY_CATEGORIES`

Limit which rule categories are active. Set it in the `env` block of your Claude Code `settings.json`:

```json
{
  "env": {
    "SENSITIVE_CANARY_CATEGORIES": "secret"
  }
}
```

| Value | Effect |
|---|---|
| `secret` | Scan for secrets only — PII rules are disabled |
| `pii` | Scan for PII only — secret rules and the name-based `.env`/`.env.*` block are disabled |
| `secret,pii` / `all` | Scan everything (default) |

Values are comma-separated and case-insensitive. Unset, empty, or containing no valid token means all categories are enabled.

This is a persistent filter, unlike allow tags which apply per prompt. The category filter is applied first, then allow tags. A typical use is setting `secret` when PII rules (credit card numbers, phone numbers, …) are too noisy against test fixtures.

---

## Custom Rules

All detection rules are defined in `src/lib/default-config.json` as data, not code. You can add your own rules or override built-in ones by creating a config file.

### Config file location

Create `~/.config/sensitive-canary/config.json`, or point to a custom path with the `SENSITIVE_CANARY_CONFIG` environment variable. Set it in the `env` block of your Claude Code `settings.json`:

```json
{
  "env": {
    "SENSITIVE_CANARY_CONFIG": "/path/to/my-rules.json"
  }
}
```

or export it in your shell:

```sh
export SENSITIVE_CANARY_CONFIG=/path/to/my-rules.json
```

### Adding a rule

Each rule is a JSON object with an `id`, `description`, `regex` (source string), and `category` (`"secret"` or `"pii"`):

```json
{
  "rules": [
    {
      "id": "custom-api-key",
      "description": "My Service API Key",
      "regex": "MYSVC-[A-Za-z0-9]{32}",
      "category": "secret"
    }
  ]
}
```

### Overriding a built-in rule

A user rule with the same `id` as a built-in rule replaces it. For example, to tighten the email regex:

```json
{
  "rules": [
    {
      "id": "pii-email",
      "description": "Internal Email",
      "regex": "[A-Za-z0-9]+@internal\\.corp\\.(com|org)",
      "category": "pii"
    }
  ]
}
```

### Context gating and validators

User rules support the same fields as built-in rules:

| Field | Type | Description |
|---|---|---|
| `requireContext` | boolean | Only fire when a nearby context word is found |
| `contextWords` | string[] | Words that satisfy the context requirement |
| `excludeContext` | string[] | Words that, found nearby, say the match is not what the rule is after — the mirror of `contextWords` |
| `contextWindow` | number | Override the global context window (default: 3 tokens) |
| `entropyThreshold` | number | Skip matches below this Shannon entropy |
| `secretGroup` | number | Capture group holding the secret. Omit for the whole match — writing `0` is not the same as omitting it, see [Detection Rules](https://coo-quack.github.io/sensitive-canary/rules.html) |
| `validate` | string | Name of a built-in checksum validator (see below) |
| `flags` | string | Regex flags. `g` is added if left out; `y` makes a rule match only at the very start of the text |

Available validators (referenced by name in the `validate` field):

`luhn`, `phone-jp`, `mynumber-jp`, `nir-fr`, `codice-fiscale-it`, `steuer-id-de`, `dni-nie-es`, `rrn-kr`, `brn-kr`, `resident-id-cn`, `public-ipv4`, `public-ipv6`

### Overriding the context window globally

Set `contextWindow` at the top level to change how many tokens of surrounding text are scanned for context words (default: 3):

```json
{
  "contextWindow": 5,
  "rules": []
}
```

Invalid rules (bad regex, wrong types, missing required fields) are skipped with a warning on stderr. The rest of the config still loads. Each rule is validated against a strict schema before compilation — `requireContext: true` without `contextWords` is also rejected, since empty `contextWords` would silently disable context gating and make the rule fire on every match.

---

## Detection rules

### Secrets (52 rules)

| Rule ID | Description |
|---|---|
| `openai-service-key` | OpenAI Service Account / Admin Key (`sk-svcacct-`, `sk-admin-`, `sk-proj-` prefix) |
| `azure-storage-key` | Azure Storage Account Key (`AccountKey=` + 88-char base64) |
| `azure-sas-key` | Azure Shared Access Key for Service Bus, Event Hubs and IoT Hub (`SharedAccessKey=` + 44-char base64). Separate from the storage account key, which is 88 characters |
| `google-oauth-secret` | Google OAuth Client Secret (`GOCSPX-` prefix) |
| `flyio-token` | Fly.io API Token (`FlyV1 fm2_` prefix) |
| `databricks-token` | Databricks Personal Access Token (`dapi` + 32 hex) |
| `vault-token` | HashiCorp Vault Token (`hvs.` / `hvb.` prefix) |
| `shopify-token` | Shopify Access Token (`shpat_`, `shpss_`, `shpca_`, `shppa_` prefix) |
| `doppler-token` | Doppler Token (`dp.pt.`, `dp.st.`, … prefix) |
| `grafana-token` | Grafana Cloud / Service Account Token (`glc_`, `glsa_` prefix) |
| `notion-token` | Notion Integration Token (`ntn_` prefix) |
| `aws-access-key` | AWS Access Key ID |
| `gcp-api-key` | Google Cloud API Key |
| `private-key` | PEM Private Key (RSA / EC / DSA / PGP / OpenSSH) |
| `private-key-base64` | PEM private key that has been base64-encoded — how one appears in a kubeconfig, a Kubernetes Secret or a Terraform state, where the `-----BEGIN` header never shows in the text |
| `url-basic-auth` | Credentials in the userinfo field of an http(s) URL — a git remote, a `.netrc`, a private registry, a `curl` invocation. RFC 3986 deprecates the form for this reason |
| `github-pat` | GitHub Personal Access Token |
| `github-fine-grained` | GitHub Fine-Grained Token |
| `gitlab-pat` | GitLab Personal Access Token |
| `npm-token` | npm Access Token |
| `slack-token` | Slack Token |
| `slack-webhook` | Slack Webhook URL |
| `discord-webhook` | Discord Webhook URL |
| `telegram-bot-token` | Telegram Bot Token |
| `twilio-sid` | Twilio Account SID |
| `sendgrid-key` | SendGrid API Key |
| `mailgun-key` | Mailgun API Key |
| `mailchimp-key` | Mailchimp API Key |
| `stripe-secret-key` | Stripe Secret Key |
| `stripe-restricted-key` | Stripe Restricted Key |
| `openai-key` | OpenAI API Key (legacy format) |
| `openai-project-key` | OpenAI Project API Key (`sk-proj-` prefix) *(entropy ≥ 3.5)* |
| `anthropic-key` | Anthropic API Key |
| `replicate-token` | Replicate API Token |
| `huggingface-token` | Hugging Face Access Token |
| `groq-key` | Groq API Key |
| `openrouter-key` | OpenRouter API Key |
| `xai-key` | xAI (Grok) API Key |
| `perplexity-key` | Perplexity API Key |
| `digitalocean-pat` | DigitalOcean Personal Access Token |
| `square-access-token` | Square Access Token |
| `mapbox-token` | Mapbox Token |
| `sentry-user-token` | Sentry User Auth Token |
| `sentry-org-token` | Sentry Organization Auth Token |
| `atlassian-token` | Atlassian API Token |
| `linear-key` | Linear API Key |
| `postman-key` | Postman API Key |
| `supabase-key` | Supabase Personal Access Token |
| `jwt` | JSON Web Token (JWT) |
| `generic-secret` | Generic API key / secret assignment *(entropy ≥ 3.5)* |
| `env-assignment` | `.env`-style secret assignment *(entropy ≥ 3.0)* |
| `connection-string` | Database connection string with embedded credentials |

### PII (24 rules)

| Rule ID | Description | Validation |
|---|---|---|
| `pii-email` | Email address | — |
| `pii-credit-card` | Credit card number | Luhn check |
| `pii-ssn` | US Social Security Number | Invalid prefix exclusion |
| `pii-mynumber-jp` | Japanese Individual Number (My Number) | Checksum (weighted mod 11) |
| `pii-nir-fr` | French NIR / Social Security Number | Check key (mod 97) |
| `pii-codice-fiscale-it` | Italian Codice Fiscale | Control character (mod 26) |
| `pii-steuer-id-de` | German Steuer-Identifikationsnummer | MOD 11,10 |
| `pii-dni-nie-es` | Spanish DNI / NIE | Control letter (mod 23) |
| `pii-phone-us` | US phone number | — |
| `pii-phone-jp` | Japanese phone number | — |
| `pii-phone-fr` | French phone number | Context-gated |
| `pii-phone-it` | Italian phone number | Context-gated |
| `pii-phone-de` | German phone number | Context-gated |
| `pii-phone-es` | Spanish phone number | Context-gated |
| `pii-postal-jp` | Japanese postal code (`〒` prefix required) | — |
| `pii-postal-code` | Postal code (US ZIP / EU / KR) | Context-gated |
| `pii-rrn-kr` | Korean Resident Registration Number | Checksum (weighted mod 11) |
| `pii-brn-kr` | Korean Business Registration Number | Checksum (NTS standard algorithm) |
| `pii-resident-id-cn` | Chinese Resident Identity Card | Check digit (GB 11643 MOD 11-2) |
| `pii-phone-kr` | Korean phone number | Context-gated |
| `pii-phone-cn` | Chinese phone number | Context-gated |
| `pii-postal-cn` | Chinese postal code (6-digit) | Context-gated |
| `pii-ipv4-public` | Public IPv4 address | Context-gated, reserved ranges excluded |
| `pii-ipv6` | IPv6 address | Context-gated, reserved ranges excluded |

Detection patterns are based on rule definitions from [gitleaks](https://github.com/gitleaks/gitleaks) and [TruffleHog](https://github.com/trufflesecurity/trufflehog).

National ID checksum algorithms follow the official specs from each issuing authority: 地方公共団体情報システム機構 (J-LIS) for My Number, INSEE for NIR, Agenzia delle Entrate for Codice Fiscale, Bundeszentralamt für Steuern for Steuer-IdNr., the Ministerio del Interior for DNI/NIE, the Ministry of the Interior and Safety for the Korean RRN, GB 11643-1999 for the Chinese Resident Identity Card, and the NTS (Hometax) standard algorithm for the Korean BRN.

### Context gating

Phone numbers (IT, DE, FR, ES, KR, CN), bare 5/9-digit and Chinese 6-digit postal codes, and public IP addresses produce too many false positives on digit-only patterns. These rules carry a list of context words (phone, ZIP, PLZ, CAP, IP, etc. in the relevant languages) and only fire when one of those words appears near the match. National ID numbers rely on their checksums instead and do not need context. Japanese postal codes keep their `〒` prefix requirement, which is a stricter form of the same idea.

---

## How It Works

### ① UserPromptSubmit hook

Runs just before a prompt is sent to the API.

```
User presses Enter
      ↓
UserPromptSubmit hook
      ↓ scans prompt
      ├─ secret / PII detected AND no matching [allow-xxx] tag → block (exit 2)
      └─ nothing detected OR tag present → pass (exit 0)
```

When blocked, the terminal shows what was detected and how to bypass it.

### ② PreToolUse hook

Runs just before Claude calls the `Read`, `Bash` or `Grep` tool, or any MCP tool.

```
Claude calls Read / Bash / Grep / MCP tool
      ↓
PreToolUse hook
      ↓
      ── Read tool ─────────────────────────────────────────────────────
      │  1. filename is .env / .env.* → blocked (secret category only)
      │  2. file contents contain secret / PII → blocked
      │
      ├─ Bash tool ──────────────────────────────────────────────────────
      │  1. env var values referenced in the command contain secret / PII → blocked
      │  2. a bare env / printenv would print the whole environment → every
      │     variable is scanned
      │  3. command string itself contains secret / PII (e.g. echo AKIA...) → blocked
      │  4. the command is located past any wrapper (sudo, env VAR=1, timeout,
      │     nice, xargs) and any leading VAR=value assignment
      │  5. inline scripts (-c, -e, -pe) are parsed and scanned
      │  6. file paths from input redirections, command substitutions and chained
      │     commands are extracted and scanned
      │  7. printing commands (cat, head, tail, sed, awk, grep, rg, cut, sort,
      │     base64, xxd, strings, diff, comm, dd, and git subcommands) targeting
      │     a named file → file contents scanned
      │
      └─ every other tool, Grep and mcp__* included ─────────────────────
         1. input fields naming an existing file are scanned for
            secret / PII → blocked
```

A value is scanned when either its field name says path or the value itself is shaped like one.

The field names are `path`, `paths`, `file`, `files`, `filepath`, `filename`, `filenames`, `absolutepath`, `notebookpath` and `sourcepath`, compared with separators and case removed — so `file_path`, `filePath` and `filepath` are one name. Beyond those, any value containing a `/` is treated as a path whatever its field is called, which is what covers a tool carrying its path under `target`, `document` or `uri`.

The `/` is what separates a path from a word, and it is there so that a search pattern is not read as a path: `{ "pattern": ".env" }` is a search for the text `.env`, not a read of the file, and `.env` exists in most checkouts. The cost is that a bare filename under an unlisted field name is still missed.

Values are found up to four levels down and inside arrays, both of strings and of objects, so `{ "path": "…" }`, `{ "paths": ["…"] }`, `{ "args": ["/abs/…"] }` and `{ "args": { "paths": [{ "path": "…" }] } }` are all covered. A field naming a directory is left alone.

Which tools reach the hook at all is the matcher's business, and the default (`Read|Bash|Grep|mcp__.*`) sends it `Read`, `Bash`, `Grep` and every MCP tool. Widen the matcher and the same field search applies to whatever else arrives.

Commands that only measure a file (`wc`, `cksum`, `sha256sum`) are not treated as reads, whether the file is named or fed in over `<`: they print counts and digests, never the bytes. Neither are the tools that surface no file contents — `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `TodoWrite`, `Glob`, `WebFetch`, `WebSearch`, `ExitPlanMode`, `AskUserQuestion` — nor any tool whose name leads with a write verb, such as `mcp__fs__write_file` or `createPage`.

Neither is a command that sends its result back to the file it was handed. `sed -i`, `perl -i` and `ruby -i` (bundled forms such as `perl -pi -e` and `perl -lpi` included) edit in place and write nothing to stdout. A bundle is read one letter at a time, continuing only past switches that command is known to accept without a value — so `sed -Ei` and `perl -lpi` are in-place edits, while `perl -Ilib -pe` and `perl -MList::Util -pe` are reads. A letter the list does not know stops the reading and the file is scanned, which is the safe way to be wrong. `git log <file>` is not a read either — it prints who changed the file and when — unless a patch is asked for with `-p`, `-u`, `--patch`, `-U<n>`, `--unified=<n>`, one of the merge-diff forms (`-c`, `-m`, `--cc`, `--diff-merges`), or `-L`, which prints the lines of one named file.

When blocked, the hook exits 2, which stops the tool call, and writes the reason to stderr, which is where Claude reads it from. The reason names what was detected and which allow tag lifts the block, and asks Claude to pass that on to the user.
The terminal also receives a direct message (via `/dev/tty`).

### Known Limitations

- **Heredoc bodies** — a heredoc body is treated as text, not as commands, so `cat > deploy.sh <<'EOF'` writing a script that mentions `.env` is not itself a read. The trade-off is that a heredoc which *feeds* commands to another shell (`ssh host <<'EOF'` with a `cat /etc/secrets` in the body) is not inspected either.
- **A tool that runs a command is read for the command, by field name** — `command`, `commands`, `cmd`, `script`, `code`, `commandline` and `shellcommand`, each read with punctuation and case ignored, so `command_line`, `command-line`, `commandLine` and `command.line` are the same name. A shell-running MCP server that names the field something else hands its command past unread.
- **Only the first 1 MiB of a file is scanned** — a file is read up to a 1 MiB cut rather than to its end, because a hook that does not return is killed by the PreToolUse timeout, and a killed hook does not block the call. The cut is in bytes, so a file of multi-byte characters gives up sooner in characters. A secret past it is missed, and so is one that straddles it, since the cut lands mid-match; the 64 KB transcript tail read makes the same trade. What the cut does *not* bound is the work done on what it read: that is a property of each rule's pattern, and `docs/rules.md` covers why three of them carry length bounds.
- **A write-named tool that also returns contents** — the exemption reads a tool's name, and assumes a name led by a write verb means the tool surfaces no file contents. `update` and `copy` are where those two things come apart: `mcp__*__update_file` and `mcp__*__copy_file` open a file to do their work, and one that returned the result would not be scanned. Scanning them instead would block writing to a file that already holds a secret, which is not a leak, so the exemption stays as it is.
- **A bare filename under an unlisted field name** — a value is treated as a path when its field name says so or when it contains a `/`. A tool passing `{ "target": "secrets.txt" }` satisfies neither, so it is not scanned. Requiring the `/` is deliberate: without it, a search for the text `.env` would be blocked as though the file had been read.
- **git history references** — `git show HEAD:.env` and similar references to objects in git history (not on disk) are not scanned, since the object does not exist as a file path.
- **Unlisted commands** — the set of commands known to print file contents is a list, not an analysis of the command. A printing command that is not on the list is not caught.
- **A template holding a real credential is blocked** — `.env.example` and its siblings are exempt from the name guard, not from the scan. Placeholders (`your-token-here`, `REPLACE_ME`, `changeme`, `<token>`, `postgres://user:password@localhost/db`) are recognised and left alone, but a template committed with a live key is blocked like any other file, through printing commands (`grep KEY .env.example`) as much as through `Read`. Use `[allow-secret]` if that is deliberate.
- **Anything past the first NUL byte of a file** — a file's text prefix is scanned and the rest is dropped, so that a binary is not ground through every rule. A file that uses NUL as a separator rather than as binary content is therefore barely scanned: `/proc/self/environ` on Linux holds the whole environment, and only the first variable of it is seen.
- **Anything that is not a regular file** — a directory, a FIFO, a process substitution (`/dev/fd/63`) and `/dev/stdin` are not read, so `cat` of one is not scanned. The directory case is what leaves the Grep tool's `path` and a recursive `grep -r pattern src/` alone, both of which would otherwise mean reading every file underneath. Reading them can never reach the end of the file: `cat /dev/zero` held the hook open until Claude Code's PreToolUse timeout killed it, and a killed hook does not block the call. Not scanning them is the lesser of the two, since a hang lets the call through as well.
- **`~user/…` is not expanded** — `~` and `~/…` are resolved to the home directory, but the form naming another user needs the password database, and guessing would name the wrong file.
- **A file whose text is not bytes the scanner reads as text** — scanning stops at the first NUL byte, which is what keeps a binary from being ground through every pattern. UTF-16 is the exception and is decoded first, by its byte-order mark or by which side of each byte pair the zeros fall on. A file that carries no zeros at all in its first sixteen kilobytes — text in a script with no Latin characters and no line breaks — is not recognised as UTF-16 and is read to its first zero byte.
- **A shell construct that names the file only at run time** — `for f in secrets; do cat "$f"; done` and `find . -name secrets -exec cat {} +` both name the file in the command line, but the hook classifies the command it can see, and in these the reading command is `cat` reached through a loop or through `find`'s own argument list.
- **At most 64 MiB is read across one tool call** — the per-file cut bounds one file; this bounds the call. A glob naming three hundred large files took half a minute, which is long enough for the PreToolUse timeout to kill the hook, and a killed hook does not block. Files past the budget are not scanned, so naming enough large files before the one that matters is a way past the scan.
- **A relative path is resolved against the directory Claude Code reports** — and against a literal `cd` at the start of the same command. A `cd` later in the line, one inside a subshell, and one whose argument is a variable, a glob or `-` are all left alone, because where they land cannot be worked out here. A directory changed some other way is the same case.
- **`**` reaches one level, not every level** — a pattern crossing directories is expanded as a single `*`, because expanding it properly walked a whole tree until the hook was killed. `cat **/secrets` sees `*/secrets`.
- **One tool call stops reading after five seconds** — whatever it has read by then is what was scanned. A byte budget bounds the reading; this bounds the walking as well, and both are ways past the scan for anyone willing to name enough files first.
- **A glob is expanded by the hook, not by the shell** — `cat *.env` is expanded here to decide what to scan, a moment before the shell expands it and against the hook's own working directory. A file created in between is missed, and at most 256 matches of one pattern are scanned.
- **Paths held in shell variables** — a path is only scanned when it appears literally in the command. `f=.env; cat "$f"` resolves at run time, after the hook has already decided.
- **Paths arriving over a pipe** — `find . -name '.env' | xargs cat` names no file the hook can see.
- **Programs that read files themselves** — `python script.py` is not scanned, because running a script does not print its source; whatever the script opens at run time is beyond the hook's reach.
- **A flag's separate value is collected as a path** — on a printing command, only a few flags are known to take a value, so every other flag's value becomes a path candidate: the `5` in `head -n 5 f` and in `cut -c 5 f`. A pattern-first command is different — `grep -A 5 f` spends the `5` as the pattern instead, and only `f` is collected. Harmless in practice, since only paths that exist as regular files are read — a file named `5` in the working directory would be scanned, and nothing else is.
- **A command a wrapper hands off to may be mistaken for its argument, or the reverse** — the search past `sudo`, `timeout` and the others takes the first name it can classify, because a wrapper flag's value (`sudo -u root cat f`) cannot be told apart from a command name. So an unclassified command's arguments are searched too: `sudo mycmd cat f` resolves to `cat` and scans `f`. `echo`, `printf`, `true`, `false` and `:` are known to print their arguments rather than open them, and stop the search; any other unclassified name does not.
- **Inline program text is followed four levels deep** — each `-c` / `-e` script inside another costs one level, so a read buried five interpreters down is not reached. Nested command substitutions are not bounded this way.
- **Best effort only** — detection is not exhaustive. Arbitrary shell metacharacters, eval chains, and complex expansions may not be fully tracked.

---

## Allow Tags (detailed)

Allow tags filter the scan results — the scan still runs, including for a `.env` file whose name guard a tag has lifted. Lifting the name guard is not the same as skipping the check: `[allow-secret]` on a `.env` holding an email address still blocks on the address.

### Mask tags

`[mask-secret]`, `[mask-pii]`, and `[mask-all]` are recognised but **not supported**. Claude Code hooks cannot rewrite prompt content, so masking before sending is not possible.

If you include a mask tag, sensitive-canary will explain this and list what was detected:

```
> [mask-secret] My key is AKIAIOSFODNN7EXAMPLE, can you review this?

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

### Allow + Mask tag priority

When both `[allow-*]` and `[mask-*]` tags appear in the same prompt, **the tag that appears first wins** for each category (`secret`, `pii`). `[allow-all]` and `[mask-all]` resolve both categories at once.

| Example | Result |
|---------|--------|
| `[allow-secret] [mask-secret] …` | secret allowed |
| `[mask-secret] [allow-secret] …` | masking not supported error |
| `[allow-secret] [mask-pii] …` | secret allowed, PII mask error |

---

## File structure

```
.claude-plugin/
  plugin.json                  plugin manifest
hooks/
  hooks.json                   Claude Code hook configuration
src/
  user-prompt-submit-hook.ts   UserPromptSubmit hook
  pre-tool-use-hook.ts         PreToolUse hook
  lib/
    inspector.ts               allow tag parsing, message scanning
    rules.ts                   secret and PII detection rule definitions
    default-config.json        the rules themselves, as data
    shell.ts                   shell syntax: tokens, quoting, heredocs, substitutions
    bash-commands.ts           what each command does with the files it is given
    tool-inputs.ts             which input fields of a tool name a file
```

---

## Development

```bash
pnpm install        # install dependencies

pnpm test           # run tests
pnpm run test:watch # run tests in watch mode
pnpm run typecheck  # type check (tsc)
pnpm run lint       # lint with Biome (no changes)
pnpm run fix        # lint + auto-fix with Biome
pnpm run ci         # typecheck + lint + tests (for CI)
```

The lockfile is pnpm's, and every CI job installs with pnpm, so `npm install`
here ignores it, writes a second lockfile, and resolves a different tree from the
one that is tested. `CONTRIBUTING.md` has the rest of the workflow.

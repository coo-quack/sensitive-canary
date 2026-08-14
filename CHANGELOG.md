# Changelog

## Unreleased

### Features

- Parse Bash commands as shell syntax rather than by splitting on whitespace.
  The tokenizer understands quotes (including `$'…'` and `$"…"`), heredoc
  bodies, command and process substitutions, subshells, shell keywords,
  redirection operators and their file-descriptor prefixes. Several ordinary
  ways of naming a file were invisible to the old split: a path with a space in
  it, `cat <secrets` with no space, a `cat` on the second line of a multi-line
  command, `(cat secrets)`, `while cat secrets; do :; done`, and
  `echo $(cat secrets)`
- Tokens record whether they came from a redirection operator or from a word, so
  a quoted `>` is read as an operand. `grep ">" secrets`, an ordinary way to
  search a file for a `>` character, previously had `secrets` skipped as though
  it were an output target
- Scan the value of a variable referenced through an expansion that carries a
  suffix, such as `${TOKEN:-fallback}` or `${TOKEN#prefix}`. Only the bare
  `$TOKEN` and `${TOKEN}` forms were recognised before
- Expand the set of commands whose operands are treated as files written to
  stdout, from seven to around forty: `tac`, `rev`, `strings`, `xxd`, `od`,
  `hexdump`, `base64`, `cut`, `sort`, `uniq`, `shuf`, `column`, `paste`, `fold`,
  `fmt`, `pr`, `expand`, `unexpand`, `iconv`, the `z*cat` family, `diff`, `comm`,
  `join`, `look`, plus a second class whose first non-flag argument is a pattern
  or script and whose remaining arguments are files (`sed`, `awk`, `grep`, `rg`,
  `ag`, `jq`, `yq`). In-place editing is exempt: `sed -i`, `perl -i` and
  `ruby -i` (including bundled forms such as `perl -pi -e` and `perl -lpi`) send
  the result back to the file and write nothing to stdout. A bundle is read one
  letter at a time, continuing only past switches that command accepts without a
  value — the letters differ per command, so `sed -Ei` counts while
  `perl -Ilib -pe` and `perl -MList::Util -pe` are reads rather than in-place
  edits. A letter the list does not know stops the reading and the file is
  scanned. `grep -i` is unaffected — its `-i` is case-insensitive matching, and
  it still prints
- Locate the command past a wrapper (`sudo`, `env VAR=1`, `timeout N`, `nice`,
  `xargs`, `stdbuf`) and past a leading `VAR=value` assignment, so the wrapped
  command is classified instead of the wrapper
- Parse and scan inline program text from `-c` / `-e` / `-pe`, both as a nested
  command line and for the quoted path literals in it, which is what catches
  `python3 -c "open('.env').read()"`
- Scan the file operands of git subcommands that print contents (`show`, `diff`,
  `blame`, `annotate`, `grep`, `cat-file`) and of `dd if=`. `git log` counts only
  when a patch is asked for (`-p`, `--patch`, `-U<n>`, and the merge-diff forms):
  without one it prints who changed the file and when, never a line of it
- Scan every environment variable when a bare `env` or `printenv` would print the
  whole environment, including behind a wrapper (`sudo printenv`) and when the
  output is redirected
- Treat commands that only measure a file (`wc`, `cksum`, `md5sum`, `sha1sum`,
  `sha256sum`) as non-reads, whether the file is named or fed in over `<`
- Inspect the file inputs of every tool other than `Read` and `Bash`, `Grep` and
  the MCP tools included. An input field naming an existing regular file is
  scanned before the call: `path`, `paths`, `file`, `files`, `filepath`,
  `filename`, `filenames`, `absolutepath`, `notebookpath` and `sourcepath`,
  compared with separators and case removed so that `file_path`, `filePath` and
  `filepath` are one name. Beyond those names, any value containing a `/` is
  treated as a path whatever its field is called, which covers a tool carrying
  one under `target`, `document` or `uri`. The `/` is what keeps a search
  pattern from being read as a path — `{ "pattern": ".env" }` searches for that
  text rather than reading the file — at the cost of missing a bare filename
  under an unlisted name. Found up to four levels down and inside arrays, of
  strings and of objects alike. A field naming a directory is left alone.
  Exempt are the tools that surface no file contents (`Write`, `Edit`, `MultiEdit`,
  `NotebookEdit`, `TodoWrite`, `Glob`, `WebFetch`, `WebSearch`, `ExitPlanMode`,
  `AskUserQuestion`) and tools whose name leads with a write verb (`write_file`,
  `createPage`): naming a file they do not read is not a leak. The default
  matcher becomes `Read|Bash|Grep|mcp__.*`
- Add an opt-in integration test that runs the hook inside a real headless
  Claude Code session and asserts both halves of the block contract: the read is
  stopped, and the reason reaches Claude. Every other test spawns the hook and
  reads its output itself, which says nothing about whether the runtime acts on
  it. Set `SENSITIVE_CANARY_INTEGRATION=1` to run it; it needs credentials and
  network, so CI skips it
- The PreToolUse block reason is written to stderr instead of to a stdout
  `{"decision":"block"}` payload. Both reach Claude on the current version, but
  the documentation describes stdout as ignored on a non-zero exit and takes the
  PreToolUse decision from `hookSpecificOutput` rather than a top-level
  `decision` field, so the old form depended on undescribed behaviour. Blocking
  is unchanged: exit 2 is what stops the call
- Heredoc bodies are treated as text, not commands: writing a script that
  mentions `.env` via `cat > deploy.sh <<EOF` is not a read. Known limitation: a
  heredoc that feeds commands to a remote shell (`ssh host <<EOF`) is not caught,
  written up under "② PreToolUse hook" in the README

### Fixes

- Make the email rule near-linear on its worst input. The local part
  (`[A-Za-z0-9._%+-]+`) spans the word boundary at every dot, so on a long run
  of digits and separators with no `@` — a log full of IP addresses or version
  numbers is exactly that — every boundary cost a greedy consume of the rest
  of the text plus a character-at-a-time backtrack in search of the `@`:
  O(n²), half a minute for 200 KB, and effectively forever for a multi-MB
  file. The local part is now bounded at 64 characters (RFC 5321's limit, so
  no deliverable address is lost) and the domain is matched as dot-separated
  labels, which leaves nothing to backtrack over
- Bound the `connection-string` credentials too. `[^@\s]+` crosses both `:` and
  `/`, so a line of `mongodb://` with no `@` in it ran to the end of the text
  from every occurrence: 188 KB took 2.3s, and 1 MiB through the hook took 98s
  and returned exit 0. Six adversarial shapes in the tests never reached it,
  which is the shape list being caught short rather than the guard working — the
  seventh was written for this syntax
- Bound the `env-assignment` pattern's name the same way. It read `[A-Z_]*`
  before its keyword and `[A-Z_0-9]*` after, so a run of capitals with no `=`
  backtracked from every position: 59 KB took 381ms, 234 KB 6.9s, 1 MiB 125s.
  1 MiB is what the file cap allows through, so capping the read did not stop
  the hook being killed — measured, a 1 MiB file of repeated `SECRET` was still
  killed at 40 seconds with the cap in place. Every rule in the config is now
  run against seven adversarial shapes in the tests, so this shape fails before
  a release rather than after one
- Read a file into a buffer of the cap's size rather than of the size `stat`
  reports. procfs and sysfs entries are regular files that report zero bytes and
  produce content anyway, so `/proc/self/environ` — the whole environment, on
  the path this hook exists to guard — would have been read as empty and passed.
  `readFileSync`, which this replaced, read to EOF and did not have the problem
- Scan only the first 1 MiB of a file rather than reading it whole.
  `readFileSync` has no size limit, so a large enough file kept the hook from
  ever returning — and a hook killed by Claude Code's PreToolUse timeout does
  not block the call, which made the hang a way through. A secret past the cut
  is missed, the same trade the transcript's 64 KB tail read already makes
- Scan the file operand of a pattern-first command when the pattern flag carries
  its value written against it. `grep -eaws secrets`, `grep -faws secrets` and
  `sed -e's/a/b/' secrets` scanned nothing: the attached spelling was not
  recognised, so nothing marked the pattern as supplied and the file that
  followed was consumed as the pattern. The separate (`grep -e aws`) and `=`
  (`--regexp=aws`) spellings were already handled
- Stop reading a path that names something other than a regular file. Reading
  `/dev/zero` never reaches the end of the file, so the hook did not return and
  Claude Code's PreToolUse timeout killed it — and a killed hook does not block
  the call, which made the hang a way through. The tool-input side already
  stat'd first; the Bash side now does too. On the paths that name a file
  outright — `Read` and a Bash command — `.env` and `.env.*` are still blocked
  on the name alone, before anything is opened. A tool input naming no existing
  file is left alone as before, since its "path" may be a URL route or an object
  key. What is no longer read is a FIFO, a process substitution or `/dev/stdin`,
  which is now listed under Known Limitations
- Read `--` as the end of option parsing. `grep -- -aws secrets` searches for
  `-aws` in `secrets`, but `-aws` was taken for a flag, so nothing marked the
  pattern as supplied and `secrets` was consumed in its place rather than
  scanned. Without the `--` the same tokens mean what they did before: the file
  is the pattern and the command reads stdin
- Scan a variable named inside another expansion's suffix. `${A:-$TOKEN}` prints
  `$TOKEN` whenever `A` is unset, but each expansion was matched whole, so the
  skip to the closing brace swallowed the suffix and the name in it. Every `$` a
  name follows now counts, which also takes in an unclosed `${TOKEN`: searching
  a checkout for template references with `grep -rn '${TOKEN' .` is blocked when
  that variable holds a secret. A false block, and the same direction the hook
  already errs in for `echo '$TOKEN'`
- `.claude-plugin/plugin.json` declared `0.5.1` while `package.json` declared
  `0.7.0`: the release checklist asks for both, and the bump was missed for
  0.6.0 and 0.7.0. The plugin manifest now matches the released version
- Also treat the rest of the digest commands as measuring a file rather than
  printing it: `sha512sum < secrets` was scanned while `sha256sum < secrets` was
  not, because only four of the family were listed. `sha224sum`, `sha384sum`,
  `sha512sum`, `b2sum`, `shasum`, `md5` and `sum` join them

### CI

- Add a `versions` job that fails when `package.json` and
  `.claude-plugin/plugin.json` declare different versions, or when either
  declares nothing that looks like one
- Check `vitest.config.ts` the way `src/` is checked. It sits at the repository
  root, and both `tsc` and `biome` were scoped to `src`, so the file that decides
  how the tests run was neither typechecked nor linted
- Run CI on pushes to `main` and `develop`, not only on pull requests. The
  commit a merge makes belongs to no PR, so nothing built it: two branches that
  are green apart can still be red together

---

## v0.7.0 (2026-08-04)

### Features

- Add multi-region PII detection rules (25 PII rules, up from 7)
  - National IDs with checksum validation: Japanese My Number, French NIR, Italian Codice Fiscale, German Steuer-IdNr., Spanish DNI/NIE, Korean RRN and BRN, Chinese Resident Identity Card
  - Phone numbers for JP, US, FR, IT, DE, ES, KR, CN
  - Postal codes for JP, US/EU/KR (5/9-digit), and CN (6-digit)
  - Public IPv4 and IPv6 addresses (reserved ranges excluded)
- Add context gating for noisy rules
  - Rules with `requireContext` only fire when a nearby context word (phone, ZIP, IP, etc.) is found within a small window around the match (default: 3 tokens ≈ 24 characters)
  - Reduces false positives on bare digit sequences without sacrificing detection when labels are present
- Move all rule definitions to JSON (`src/lib/default-config.json`)
  - Rules are now data, not code — the full set can be inspected and modified without editing TypeScript
  - Checksum validators remain in code and are referenced by name from the config
- Add user-defined custom rules via config file
  - Create `~/.config/sensitive-canary/config.json` or set `SENSITIVE_CANARY_CONFIG` to a custom path
  - Add new rules, override built-in rules by id, and set a custom `contextWindow`
  - Invalid rules are skipped with a warning; the rest of the config loads normally
- Expand secret detection coverage (39 secret rules, up from 24)
  - AI services: Replicate, Hugging Face, Groq, OpenRouter, xAI (Grok), Perplexity
  - Cloud / IaaS: DigitalOcean PAT, Supabase PAT
  - Payment: Square access token
  - SaaS / Dev tools: Mapbox, Sentry (user + org tokens), Atlassian, Linear, Postman

### Fixes

- Fix My Number checksum: when the weighted-sum remainder is 0 or 1, the check digit is 0 (not invalid). Valid My Numbers ending in 0 were previously rejected.
- Correct spec source abbreviation: JIPTEC → J-LIS (地方公共団体情報システム機構)
- Harden `compileRule`: force `g` flag on regex, validate `regex` field, warn on unknown validator name
- Add strict schema validation for user-defined rules (required fields, optional field types, cross-field constraints)
- Pass `secretValue` (not full match) to validator so `secretGroup` + `validate` works in user rules

### Dependencies

- Update pnpm to v11.19.0 and refresh the lockfile

---

## v0.6.0 (2026-08-02)

### Features

- Add `SENSITIVE_CANARY_CATEGORIES` environment variable to limit which rule categories are active
  - Accepts `secret`, `pii`, `secret,pii`, or `all` (comma-separated, case-insensitive); unset/empty/invalid means all categories
  - Useful for reducing PII false positives (e.g. credit card or phone number rules firing on test fixtures) by scanning secrets only
  - The name-based `.env`/`.env.*` block is a secret guard and is disabled when the `secret` category is not enabled

---

## v0.5.3 (2026-06-27)

### CI

- Rework the main→develop sync to open a PR with auto-merge, using a minted GitHub App token so the created PR triggers CI
- Disable persist-credentials in the sync workflow so the App token push works

### Dependencies

- Pin pnpm via the `packageManager` field and update pnpm to v11 (security)
- Update node to v24, vite to v8, typescript to v6, and other dev dependencies and GitHub Actions

---

## v0.5.2 (2026-03-31)

### Security

- Add `minimumReleaseAge` to renovate.json to prevent supply chain attacks
  - Waits 7 days before auto-merging dependency updates
  - Reduces risk of package takeover attacks
  - Blocks immediate auto-merge of newly published packages

---

## v0.5.1 (2026-03-15)

### Fixes

- Remove `marketplace.json` and sync marketplace via `repository_dispatch` on release
- Gate marketplace sync on actual release creation to prevent duplicate dispatches
- Update marketplace registration commands across README and docs to point to `coo-quack/claude-code-marketplace`
- Remove stale `marketplace.json` references from `CONTRIBUTING.md` and `README.md`
- Simplify backport workflow to direct main-to-develop merge

---

## v0.5.0 (2026-03-14)

### Features

- Add Google Cloud API Key (`gcp-api-key`) detection rule
- Add npm Access Token (`npm-token`) detection rule

### Fixes

- Prevent `openai-key` (legacy) rule from overlapping with `openai-project-key` and `anthropic-key` via negative lookahead
- Use nullish coalescing (`??`) in `entropy()` for correct semantics under `noUncheckedIndexedAccess`
- Remove unreachable `unique` filter in `user-prompt-submit-hook`
- Consolidate `randomBird()` calls in `block()` for consistent emoji across terminal and JSON output
- Fix fd leaks in file read and `/dev/tty` write paths with `try/finally`
- Use `bytesRead` return value from `fs.readSync` to avoid NUL-filled buffer tails
- Scan text prefix before first NUL byte in binary files instead of skipping entirely

### Performance

- Read only the last 64 KB of transcript files for allow-tag resolution
- Skip binary content after first NUL byte to avoid pointless regex scanning

### Documentation

- Unify documentation site structure with Getting Started and Troubleshooting pages
- Symlink `docs/contributing.md` to root `CONTRIBUTING.md`

---

## v0.4.6 (2026-03-12)

### Security

- Add explicit permissions to all workflow jobs
- Resolve Dependabot security alerts via pnpm overrides

---

## v0.4.5 (2026-03-12)

### Fixes

- Scope CI badge to main branch

---

## v0.4.4 (2026-03-12)

### Improvements

- Migrate from npm to pnpm
- Add Renovate configuration with automerge on CI success
- Add pnpm version specification for GitHub Actions

### Documentation

- Update install instructions from npm to pnpm
- Capitalize project title to Sensitive Canary across docs

### Fixes

- Fix capitalization in project title

---

## v0.4.3 (2026-02-23)

### Documentation

- Replace Japanese text with English in npm install instructions

---

## v0.4.2 (2026-02-23)

### Fixes

- **Scoped package name** — renamed npm package from `sensitive-canary` to `@coo-quack/sensitive-canary`
- **Homepage** — added `homepage` field pointing to the documentation site

---

## v0.4.1 (2026-02-23)

### Improvements

- **npm publish automation** — release workflow now publishes to npm with provenance on merge to main
- **Package metadata** — added `repository` and `files` fields, removed `private: true` for npm publishing
- **npm install docs** — added `npm install -g` setup instructions to README and docs

---

## v0.4.0 (2026-02-23)

### Features

- **Allow tags are now single-use** — allow tags are consumed after the first tool call, preventing unintended persistent bypass across multiple tool uses in the same turn

### Fixes

- **Random bird emoji in block messages** — PreToolUse block messages now use `randomBird()` instead of a hardcoded emoji, matching the existing behavior in other messages

### Docs

- **README restructured** — new section order: Why → Quick Start → What Happens → Detection Rules → How It Works → Allow Tags
- **Docs site headings unified** — "How It Works" → "What Happens", "What Gets Detected" → "Detection Rules" for consistency with README

---

## v0.3.1 (2026-02-23)

### Fixes

- **Bird emoji in PreToolUse block reason** — the bird emoji now appears in the block message shown by Claude Code, not only in the terminal output

---

## v0.3.0 (2026-02-23)

### Features

- **Allow + Mask tag priority** — when both `[allow-*]` and `[mask-*]` tags appear in the same prompt, the first occurrence wins per category (`secret`, `pii`). `[allow-all]` and `[mask-all]` resolve both dimensions at once.

### Fixes

- Plugin install command corrected to `sensitive-canary@coo-quack`

---

## v0.1.0 (2026-02-22)

Initial release.

### Features

- **UserPromptSubmit hook** — scans every prompt for secrets and PII before it is sent to the Anthropic API
- **PreToolUse hook** — blocks `.env`/`.env.*` files by name; scans file contents and Bash commands for secrets and PII
- **25+ detection rules** — AWS keys, GitHub/GitLab PATs, Stripe keys, Slack/Discord/Telegram tokens, JWTs, SendGrid/Mailgun/Mailchimp keys, Anthropic/OpenAI API keys, database connection strings, and more
- **PII detection** — email addresses, credit card numbers (Luhn-validated), US SSNs, US/JP phone numbers, Japanese postal codes, private IPv4 addresses
- **Entropy filtering** — suppresses false positives on low-entropy generic-secret and env-assignment matches
- **Allow tags** — `[allow-secret]`, `[allow-pii]`, `[allow-all]` bypass specific categories per prompt
- **[mask-xxx] tag handling** — explains that prompt masking is unsupported and suggests the correct allow tag
- **Environment variable expansion** — Bash commands referencing `$VAR` / `${VAR}` have their env values scanned
- **Deduplication** — repeated occurrences of the same secret value produce a single finding

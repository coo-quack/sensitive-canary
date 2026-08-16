# Changelog

## v0.8.0 (2026-08-16)

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
- Detect a PEM private key that has been base64-encoded, under the new
  `private-key-base64` rule. `-----BEGIN` never appears in the text, so
  `client-key-data` in a kubeconfig, `tls.key` in a Kubernetes Secret and a key
  held in Terraform state were all invisible to the plaintext rule. Three bytes
  encode to four characters, so the header looks different depending on where it
  sits relative to that boundary: the rule carries all three forms, since
  matching one would find one key in three. Swept over 986 real files on a
  developer machine, it found four keys in a kubeconfig and nothing else
- Detect credentials in the userinfo half of an http(s) URL, under the new
  `url-basic-auth` rule — a git remote, a `.netrc`, a private registry, a `curl`
  invocation. RFC 3986 §3.2.1 deprecates the form for the same reason. The
  placeholder machinery already covers the near neighbours, so
  `https://user:password@localhost`, `https://x-access-token:${GH_TOKEN}@…` and
  `https://USERNAME:PASSWORD@example.com` stay quiet; the same sweep of 986 real
  files flagged none of them
- Count the hash in a Telegram bot token loosely. The pattern asked for exactly
  33 characters after `AA` — not a minimum, an exact count — so a 32-character
  token and a 35-character one were both invisible, and the bot id was capped at
  ten digits. Now 6–12 digits and 30–40 characters, with word boundaries at
  either end
- Read `mongodb+srv://` as a connection string. The rule listed `mongodb` but
  not the SRV scheme, which is the one MongoDB Atlas hands out
- Recognise the AWS key prefixes `ABIA`, `ACCA`, `APKA` and `ASCA` alongside the
  nine already listed

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
  and returned exit 0. Every adversarial shape then in the tests walked past it,
  which is the shape list being caught short rather than the guard working, so
  one written for this syntax was added
- Bound the `env-assignment` pattern's name the same way. It read `[A-Z_]*`
  before its keyword and `[A-Z_0-9]*` after, so a run of capitals with no `=`
  backtracked from every position: 59 KB took 381ms, 234 KB 6.9s, 1 MiB 125s.
  1 MiB is what the file cap allows through, so capping the read did not stop
  the hook being killed — measured, a 1 MiB file of repeated `SECRET` was still
  killed at 40 seconds with the cap in place. Every rule in the config is now
  run against a list of adversarial shapes in the tests, so this shape fails before
  a release rather than after one
- Read a file into a buffer of the cap's size rather than of the size `stat`
  reports. procfs and sysfs entries are regular files that report zero bytes and
  produce content anyway, so their content was read as empty and passed.
  `readFileSync`, which this replaced, read to EOF and did not have the problem.
  Reading such a file is not the same as scanning it whole: the NUL rule stops at
  the first separator, so `/proc/self/environ` is read and only its first
  variable is looked at, which is now listed under Known Limitations
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
- Put back what quieting the rules had taken out. A corpus of five hundred
  generated values, run against this release and against v0.7.0, found a hundred
  and twenty-seven inputs the old version detected and this one did not — none of
  which the thirty-two cases chosen by hand had caught. Restored:
  - an address near an excluded word. One word within a couple of dozen
    characters was erasing every address near it, three at a time in a CSV. The
    exclusion is now the three shapes that are really hostnames: a VCS user, an
    address straight after `ssh`/`scp`/`rsync`/`sftp`, and the `host:path` form
  - a bare private address. Requiring a label lost `192.168.1.50`,
    `X-Forwarded-For: 10.0.0.5` and `remote_addr=…`; what says an address is a
    machine is the command around it, so that is what excludes it now, and a
    `host:port` pair is a service rather than a person
  - an assignment that is not at the start of a line: `docker run -e PASSWORD=…`,
    `cd /app && PASSWORD=…`, a single-quoted value, a value with a trailing
    semicolon or comma, and one indented past sixteen columns. `DB_PASS` counts
    as well as `DB_PASSWORD`
  - a Square token after `key_` or in a query string, which a boundary counting
    `_` and `=` as base64 had erased
  - the Korean resident and business numbers without their separators, which is
    how they are stored. Context keeps a timestamp out instead
  - a postal code next to the word `max`, and a connection string whose password
    runs past 256 characters
- Read a command that arrives as an argv array on the `Bash` tool too, not only
  on an MCP one. The same command was scanned or not depending on who sent it
- Block a `.env` template whose contents cannot be read whole. The exemption
  assumed the contents would be scanned instead, and a NUL byte or a file past
  the per-file cut stopped that — so `.env.nul.example` and `.env.big.example`
  passed on their names after all
- Expand `**` as a single `*` rather than refusing it. Refusing it meant `cat **`
  was scanned not at all, while the shell expanded it and read the files
- Read a command field that arrives as an argv array or nested under another key.
  Only a top-level string was read, so `{"command":["cat",".env"]}` and
  `{"args":{"command":"cat .env"}}` went past — both by a name with no slash in
  it, which the path rules do not collect either
- Stop reading after five seconds. A byte budget bounds what is read and not what
  is walked, and a pattern reaching one level under a home directory took ten
  seconds, which is close enough to the PreToolUse timeout to matter
- Stop blocking ordinary work. Measured over sixty-four commands from a working
  day, the hook blocked sixteen of them; it now blocks five, and four of those
  five are this repository's own README and changelog, which contain an
  AWS-shaped key as documentation. What changed:
  - an address is not a person when an `ssh`, `scp`, `rsync`, `clone` or `git@`
    is next to it, and `example.com` and the other RFC 2606 domains are nobody's
    mail
  - a private IPv4 needs a person nearby (`client`, `user`, `visitor`) rather
    than the word "address", which made `kubectl port-forward --address 10.0.0.1`
    a finding
  - the published test card numbers are not cards
  - `cap` is an English word as well as an Italian postal one, so sizes and
    limits nearby say it is not a postal code
  - the Korean resident and business numbers are written with their separators;
    without that, a millisecond timestamp in a log was a finding
  - a Square token inside a longer run of base64 is a slice of something else,
    which is what made `cat ~/.ssh/known_hosts` a finding
  - a value that is a variable reference (`PASSWORD: ${VAR}`) names a secret
    rather than being one
  - `.env.example`, `.env.sample`, `.env.template`, `.env.dist` and
    `.env.defaults` are not blocked by name. Their contents are still scanned, so
    a template with a real key in it is still caught — by what is in it
- **`[allow-secret]` lifted PII blocks, which the README says it cannot.**
  Deduplication ran before the allow tag, and it keys on the value — so a string
  that a secret rule and a PII rule both match lost the PII finding first, and
  the tag then removed what was left. The two hooks had the order the other way
  round from each other; the prompt hook was right
- **A pasted log could lift the guard on the key in the same message.** The
  prompt hook read tags from the raw prompt while the other hook read them from
  what the user typed, so a fenced log or a README quoting `[allow-secret]`
  decided them. One implementation now answers for both
- **Input the check could not read was treated as input the check approved.**
  Two characters missing from the end of a payload passed a key through. Empty
  stdin is still nothing to check; bytes that will not parse now stop the call
- **A filename could put lines into the text Claude reads.** POSIX allows a
  newline in a path and a path is attacker-chosen, so a file could be named such
  that the block message grew a line saying the block was a false positive.
  Escape sequences went the same way and could clear the screen first. Control
  characters are escaped on the way out now, and the finding list is capped —
  one rule that matched everywhere produced forty thousand lines
- **A single rule from a config file could hang the hook.** The scan budget is
  checked between rules and cannot interrupt one match, so `(a+)+$` ran for
  hours and the hook was killed — which does not block. A V8-side timeout does
  interrupt a running match, at 0.06ms per scan
- A config path that is a FIFO blocked the read forever, and a config with more
  than about 120,000 rules threw while the module was still loading, before any
  handler existed. Both exited without blocking
- **`tail` printed the part that was not scanned.** The per-file cap reads the
  first megabyte; `tail -2 app.log` shows the last lines, which on a large log is
  where a failure has just printed a connection string. Both ends are read now.
  What is still missed is the middle of a file larger than both windows
- `view` and `vimdiff` print a file the way `less` does and were not on the list
- The documentation said the hooks are active immediately after installing the
  plugin. A session that is already running does not pick them up: it reports the
  plugin as enabled and checks nothing. It also said a PreToolUse allow tag is
  consumed by the first tool call — it lasts until a tool result is recorded, so
  calls issued together are all covered by one. And it said a `.env` with an
  allow tag is passed through without scanning, which is the opposite of what the
  code does. All three are corrected, and the step that proves a hook is really
  running is now on the recommended install path rather than only the pnpm one
- The `phone-jp` validator existed and was named in neither document; a test now
  holds both documents to the registry. Added a section on the ways a rule goes
  quiet without warning — `secretGroup: 0` is not the same as omitting it, an
  `entropyThreshold` above 8 rejects everything, `flags: "y"` matches only at the
  start of the text, and a large `contextWindow` widens `excludeContext` too
- **The same defect was still in `env-assignment`, and worse.** Its value
  capture was open-ended, so a megabyte of `TOKEN=TOKEN=…` took six minutes —
  past any hook timeout, and a killed hook does not block. The capture is atomic
  now (`(?=(X))\1`, since every character the delimiter test accepts is one the
  class already excludes, so retrying a shorter run could never succeed) and
  capped, with a single character deciding whether the value simply ran past the
  cap. 373 seconds to 2 milliseconds, and a fifty-thousand-character value is
  still found
- **The hook stopped every tool call, with no way out, when its working
  directory had been removed.** `process.cwd()` throws there, and it was called
  while the module was still loading — before the transcript is read — so the
  message advising an allow tag described something that could not be honoured.
  A build script that runs `rm -rf dist` from inside `dist`, or a
  `git worktree remove`, is enough. There is nothing sensitive about a missing
  directory: a relative path simply has no base
- **A tag written in backticks did not work, and the documentation writes them
  that way.** Treating inline code as quoting refused the form this project
  teaches, and refused it silently — the block that followed advised adding the
  tag it had just ignored. Fenced blocks still quote rather than issue, so a
  pasted log cannot lift the guard
- `<bash-input>` was missing from the elements that are not user input, an
  unclosed element was not stripped at all, and a line the runtime wrote as an
  assistant turn was read as user input if the message inside it claimed the
  role
- A UTF-16 file whose first characters are Japanese or Chinese has no zero byte
  among them, and five hundred pairs of prefix decided the whole file. The
  window is wider, the threshold is on the asymmetry rather than the rate, and
  whether the result reads as text is what settles it
- A FIFO named as the transcript blocked the read forever; a write to a closed
  stderr threw on the way out of a block and turned it into a pass; and a
  payload of `null` parsed successfully and then threw on the first field read
- **Twenty-six wrong blocks out of six hundred real files.** A value that is a
  URL, a path, an identifier, a header name, a number or a dotted setting name
  is no longer read as the secret its variable is named after — `secret_name`,
  `VAULT_TOKEN_PATH` and `TOKEN_HEADER_NAME` describe a secret rather than
  holding one, and a key whose last word is `PROJECT` or `ENDPOINT` says so
  outright. The shape test applies only where a rule captured a free-form value:
  a Slack webhook is a URL and a secret both, and asking whether it looks like a
  URL is the wrong question
- A connection string with `${PGPASSWORD}` still in it holds no credential at
  all, and `postgres:postgres@` is what a compose file ships with
- A context word is a label, not a fragment of the identifier beside the number.
  `extract-zip` supplied "zip" and `golang.org/x/mobile` supplied "mobile", so a
  version number beside either read as a postal code or a telephone number —
  which is to say lockfiles and `go.sum` could not be read at all. Nor could
  `name@version`, which is an address by shape
- Twelve identical digits satisfy the My Number checksum by arithmetic rather
  than by being anyone's number, and `01-02-2024` is a date. A Japanese
  telephone number has ten digits or eleven, and 0120 belongs to a business
- **A megabyte of `eyJ` used to kill the hook, and a killed hook does not
  block.** Two rules were shaped `{n,}` followed by a literal that may never
  come, which makes the engine retry the whole tail from every start position.
  `eyJ` recurs every three characters, so one 400 KiB file was enough to spend
  the PreToolUse timeout and take the rest of the call with it — including the
  `.env` name guard, by naming the padding first. A JWT begins at a token
  boundary, and saying so leaves one start instead of a third of a million: a
  megabyte went from 104 seconds to 27 milliseconds. The Mapbox, Sentry and
  Square patterns had the same shape and are bounded too
- A scan that runs past ten seconds now stops the call rather than finishing
  quietly. Bounding those patterns fixed the two rules that could do it; this is
  so the next rule of that shape is caught instead of repeating it. The check
  sits between rules, since a single match cannot be interrupted
- **An allow tag could be issued by something other than the user.** Claude Code
  records the output of a `!` command, slash-command names and system reminders
  as user messages, so `[allow-all]` appearing in any of them lifted the guard
  for the next tool call — `grep -r allow-all` was enough. A tag inside a code
  fence no longer counts either: a pasted log is quoting the tag, not asking for
  it
- **A UTF-16 file was not scanned at all.** Every other byte is NUL, and the
  scan stops at the first one, so the contents came to one character. PowerShell
  5.1 writes UTF-16LE by default, which makes redirecting a command's output to
  a file a way past this. Little-endian, big-endian and byte-order-marked files
  are all read now; genuinely binary files are still left alone
- `Read` with a `file_path` that is not a string exited 0, while the same shape
  under any other tool name reached the shared collector and blocked
- **A crash no longer passes the call through.** Only exit 2 blocks, and an
  unforeseen error exits 1 — so any bug anywhere in a hook silently switched the
  protection off, which is the failure this tool exists to prevent. Both hooks
  now stop the call instead, with a message saying the check did not finish
  rather than claiming a finding. Input the hooks do understand is unaffected;
  `[allow-all]` gets past it
- **A prompt that is not a string is read rather than dropped.** Not throwing on
  `{"prompt":{"text":"…"}}` was only half the fix: coercing it to the empty
  string exited 0, which is the same silence the exception produced. Every
  string inside the value is collected now, to a bounded depth, so object,
  array and content-block prompts are scanned like a plain one
- A field named `command.line` or `command line` was walked past while
  `file.path` was read correctly — the two collectors normalised field names
  with a regex each, and the one for commands dropped only `-` and `_`
- The placeholder recognition added above could be used to smuggle a live
  credential: it asked whether a value *contained* a placeholder word, so
  `changeme_` in front of a real key switched the rule off. The whole value has
  to be placeholder now
- Widening the Stripe and OpenAI rules swallowed two rules whole:
  `stripe-restricted-key` became a strict subset of `stripe-secret-key`, and
  `openai-project-key` stopped being reported at all. Both fire again
- **Private IPv4 addresses are no longer detected.** An RFC 1918 address is
  non-routable and identifies nothing outside the network it belongs to, and the
  rule spent its time on ansible inventories, ssh configs, Kubernetes manifests
  and docker-compose files — five such files, all blocked before, all quiet now.
  Public addresses are unchanged and still require a nearby label. Anyone who
  wants the old behaviour can add the rule back through the config file; the
  `excludeContext` field it used is documented now and still serves the postal
  code rule. 75 rules to 74
- The release could not publish. GitHub runs every `run:` step as `bash -e {0}`,
  and the smoke test added last round pipes into a hook that exits 2 on purpose,
  so errexit killed the step before the assertion that expected the 2. The gate
  written to make the release safer made it impossible; every invocation now
  captures its status instead of letting the pipeline decide the step's fate
- The release gates now run against the tarball `npm publish` would upload, not
  the checked-out tree. Deleting `"dist/"` from the `files` field used to pass
  every gate while shipping a package whose hooks cannot start — verified by
  doing it, along with dropping `hooks/` and shipping the tests
- `hooks/hooks.json` — the file the plugin install path reads, and the only one
  still pointing at the TypeScript sources — had no gate at all. Emptying it left
  every check green. The release now parses it, requires both events, and
  resolves every command's path inside the tarball
- Recognise a value written to be replaced. Half of a realistic `.env.example`
  was blocked on its contents (`your-password-here`, `REPLACE_ME_WITH_REAL`,
  `django-insecure-...`, `postgres://user:password@localhost/db`), which defeats
  exempting the name: the file exists to be committed and read. Ten realistic
  templates now read clean, and one holding a live key is still blocked. Only
  secret rules consult the list, and `example` is deliberately not on it — AWS's
  own documented key ends in it and is still a key
- An address stopped being found when a remote-shell word appeared anywhere
  within forty characters: `rsync failed, notify alice@corp.io` was silently
  dropped. The exemption now covers the operand position only — `ssh user@host`
  and at most two arguments in between — and the `host:path` forms of scp and
  rsync are left to the trailing-colon rule that already handled them
- Cover the credit card brands the rule claimed and did not match. The Discover
  branch required seventeen digits, so no Discover, JCB or Diners card could
  reach it, and Mastercard's 2-series (2221-2720) and UnionPay were absent
  outright — five brands undetected. Ranges follow Discover's published IIN
  summary, which also puts the Discover range at 644-658, so 659 is no longer
  claimed
- Slack's rotated tokens (`xoxe-`), app-level tokens (`xapp-`) and workflow
  tokens (`xwfp-`) were not matched; nor were Stripe restricted, organization
  and webhook-signing secrets, nor eight of GitLab's ten token prefixes
- Mapbox and Sentry tokens were written to shapes those services do not issue —
  Mapbox delimits into three parts of which the first is the literal `pk`, `sk`
  or `tk`, and a Sentry org token is underscore-separated, not dotted. Neither
  rule had ever matched a real token
- A Square token longer than sixty characters was missed. Square's contract
  allows up to 1024; the length had been pinned at exactly what appears in the
  wild
- Codice fiscale: omocodia substitutes letters for digits at the seven numeric
  positions when two people would share the first fifteen characters, and both
  the pattern and the checksum guard demanded digits there — so every such code,
  each issued to a real person, was missed
- Add two more from a format survey: an Azure Shared Access Key
  (`SharedAccessKey=` + 44-char base64, for Service Bus, Event Hubs and IoT Hub,
  which is a different length from the 88-character storage account key) and a
  Google OAuth client secret (`GOCSPX-`). Google's `ya29.` access tokens and
  `1//` refresh tokens are deliberately not matched: Google documents no format
  for them beyond a size cap and reserves the right to change it, so a pattern
  would be a guess that reads as a guarantee
- Add nine rules for credentials that no rule covered: OpenAI service-account and
  admin keys, Azure Storage account keys, Fly.io, Databricks, HashiCorp Vault,
  Shopify, Doppler, Grafana and Notion tokens. 64 rules to 73
- Stop repeating the blocked command back to Claude. The reason a block gives
  carried the first eighty characters of the command, so blocking
  `export GITHUB_TOKEN=ghp_…` handed the token to the model inside the sentence
  explaining that it had been withheld. The detection lines were already
  redacted; the line above them was not
- Read a command out of a tool input field. Only `Bash` was ever parsed as a
  command, so an MCP server that runs a shell — `{"command":"cat .env"}` — was
  looked at as a path, found not to be a file, and let through, with the default
  matcher sending every `mcp__*` tool down that path. `command`, `cmd`, `script`
  and `code` are read now, the last for the paths quoted inside it
- Treat an input of the wrong type as absent rather than throwing. A `command`
  that is a number, a `prompt` that is an object, a `cwd` that is an array: each
  threw, and an exception exits 1, which does not block —
  `{"prompt":{"text":"<a key>"}}` went through unscanned
- Anchor the assignment rule to the start of a line and require its value to be a
  value. Widening it to `:` and lower case made it read ordinary code:
  `function check(token: ShellToken)` was a secret, and the plugin could not read
  its own source — 97 findings across 17 files of this repository, now none
- Resolve a relative path against the directory the tool runs in. The payload
  carries a `cwd` and nothing read it, so `cat secrets.txt` named a path relative
  to wherever the hook process happened to start and was dropped as a file that
  is not there. A literal `cd` earlier in the same command moves the base too,
  which is what `cd build && cat secrets` needs
- Read an assignment written with `:` and with a lower-case name. The rule wanted
  `[A-Z_]` and `=`, so a `docker-compose.yml` full of `POSTGRES_PASSWORD: …`, an
  `appsettings.json` with `"client_secret": …` and an `~/.aws/credentials` with
  `aws_secret_access_key = …` all passed — the three file shapes this tool exists
  to guard
- Keep a substitution among the operands instead of ending the segment at it.
  `cat <(echo hi) secrets` left `secrets` in a segment of its own, where it was
  read as a command name; the comment at that line said the only cost was
  reaching the inner command twice
- Bound the work of one tool call at 64 MiB across every file it reads, and skip a
  file already read. A glob naming three hundred large files took half a minute,
  and five overlapping globs read the same files five times
- Lift the `.env` name block only for a tag that allows secrets. `parseAllowTags`
  reads `[allow-<anything>]`, and the guard asked only whether any tag was
  present, so `[allow-pii]` and a mistyped `[allow-pi]` both turned it off. It no
  longer skips the content scan either: a tag for one category was silently
  covering the other
- Expand `~` and `~/…` to the home directory. `cat ~/.aws/credentials` named a
  path that exists on no disk, so it was dropped as a file that is not there —
  and `~/.ssh/id_rsa`, `~/.npmrc` and `~/.netrc` went the same way
- Expand `{a,b}` as well as `*`, `?` and `[`. `cat .env{,.bak}` reached the name
  guard as the single name `.env{`, which is not an `.env` file, so the guard
  that reads names rather than disks did not fire
- Keep the literal candidate beside a glob's matches. Returning only the matches
  was a way through this hook did not have before the expansion existed:
  `cat /nonexistent/.env.*` matches nothing, so nothing was scanned and the
  `.env` name guard never ran, and a file really named `report[2].txt` was read
  as a character class and expanded to `report2.txt`
- Read a shell's bundled `-c`. `bash -lc 'cat secrets'` runs what `bash -c`
  runs, and only the exact spelling was recognised, so the inline code went
  unparsed. The letters before the `c` have to be valueless switches
- Step past `eval` the way the other wrappers are stepped past
- Read `$(<secrets)`, which has no command in it at all: bash reads the file and
  substitutes its contents, so the redirection is the only thing there
- Scan the quoted literals inside an awk or sed program.
  `awk 'BEGIN{while((getline l < "secrets")>0) print l}'` names a file without
  ever passing it as an operand
- Detect `-----BEGIN ENCRYPTED PRIVATE KEY-----` and the SSH2 spelling, which
  `openssl genpkey -aes256` writes and the rule did not list
- Expand a glob before deciding whether it names a file. `cat sec*` collected
  `sec*`, found nothing on disk by that name, and allowed the read; `cat .env*`
  did the same, one character away from `cat .env`, which is blocked on its name.
  A pattern is now expanded and each match is scanned, up to 256 of them
- Read a redirection that stands before the command. `< secrets cat` is `cat`
  reading `secrets`, but the operator was skipped and its target taken for the
  command name, so the real command went unclassified and nothing of it was
  collected — while `cat < secrets` blocked
- Scan the file named inside a `git log -L` range. `-L1,10:secrets` prints the
  lines of that file, and the file is written inside the flag's own argument
  where neither the flag nor the operand handling would look for it
- Read `--` as the end of option parsing for the in-place test too. In
  `sed -- -i secrets`, `-i` is the script and `secrets` is a file sed prints; read
  as the in-place flag, the command counted as writing and the file was skipped
- Collect a path from an array inside an array. `{ "paths": [["…"]] }` fell
  between the string branch and the object branch and was never looked at
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

### Documentation

- The file structure in `README.md` listed two files under `src/lib/`, from
  before this release added three more and moved the rules into JSON
- The development commands in `README.md` were `npm`, while `CONTRIBUTING.md`
  and every CI job are `pnpm`. The lockfile is pnpm's, so following the README
  ignored it, wrote a second lockfile, and resolved a different tree from the one
  that is tested

### CI

- Publish compiled JavaScript. Node refuses to strip types from a `.ts` file
  inside `node_modules`, so an npm install wired to `src/` started the hook,
  failed with `ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING`, exited 1 — and a
  non-zero exit that is not 2 does not block. The tool looked installed and
  checked nothing. `dist/` now ships beside `src/`, the npm instructions point at
  it, and no type stripper or `tsx` download is involved. The plugin install
  keeps using the sources, which sit outside `node_modules` and work
- Run the release path's own gates. `release.yml` is reached by a push to `main`
  and is not chained to the pull-request build, so a red branch could publish. It
  now runs the audit, the version-agreement check whose absence let the plugin
  manifest ship stale twice, a build, and a smoke test that starts both published
  hooks with plain `node`
- Stop shipping the tests. `files` carried `src/`, which carried `__tests__`:
  more than half the tarball, and none of it useful to anyone installing

- Add a `versions` job that fails when `package.json` and
  `.claude-plugin/plugin.json` declare different versions, or when either
  declares nothing that looks like one
- Check `vitest.config.ts` the way `src/` is checked. It sits at the repository
  root, and both `tsc` and `biome` were scoped to `src`, so the file that decides
  how the tests run was neither typechecked nor linted
- Run CI on pushes to `main` and `develop`, not only on pull requests. The
  commit a merge makes belongs to no PR, so nothing built it: two branches that
  are green apart can still be red together
- Fail the release when the marketplace catalog does not pin this plugin to
  `main`. `/plugin install` serves the entry's `ref`, and with no `ref` that is
  the repository's default branch — `develop`. Every gate in `release.yml`
  guards `main` and npm, and none of them was on the path a plugin user installs
  from, so a merge into `develop` reached users directly
- Anchor the version shape test at both ends, in `ci.yml` and `release.yml`
  alike. `^[0-9]+\.[0-9]+\.[0-9]+` with no `$` accepts anything at all after a
  valid prefix, and `release.yml` splices that value into four `run:` scripts:
  `0.8.0"; curl … | sh; echo "`, `0.8.0 && rm -rf /` and `0.8.0$(id)` were all
  accepted by the old test and are all rejected by the new one. The version is
  now validated in the job that captures it, before it reaches `$GITHUB_OUTPUT`,
  and every step that uses it reads it from `env:` rather than by interpolation
- Create the git tag before publishing to npm, and let npm alone decide whether
  a version is released. npm refuses to republish, so a publish that landed and
  was followed by a failing step could not be retried — the tag it never created
  had to be made by hand, and the release job declined to act on a re-run
- Give `release.yml` a `concurrency` group, so two pushes to `main` in quick
  succession cannot race over the tag and the publish. Nothing is cancelled: a
  release half-way through is worse than one that waits
- Put a `timeout-minutes` on every job in both workflows. A hung step otherwise
  holds a runner for the six-hour default
- Assert that the published `UserPromptSubmit` hook allows a clean prompt. Every
  assertion made of it was that it exits 2, so a hook that exits 2
  unconditionally — blocking every prompt the user types — would have shipped
  green
- Install with `--frozen-lockfile` in CI. A lockfile CI is allowed to rewrite is
  a lockfile CI does not check
- Fail the lint on warnings, and check `docs/.vitepress/` the way `src/` is
  checked. `biome lint` exits 0 on a warning, so the dead `tokenize` in
  `src/lib/rules.ts` — superseded by `contextTokens`, and carrying a comment
  describing the behaviour that replaced it — sat in the tree reported and
  ignored. Two rules are turned off rather than obeyed: `useLiteralKeys`
  contradicts this project's `noPropertyAccessFromIndexSignature`, and applying
  it broke the typecheck; `noTemplateCurlyInString` is off for the test tree,
  which cannot test `${VAR}` handling without writing one

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

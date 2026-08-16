#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { extractCommandRefs } from "./lib/bash-commands.ts";
import { detectUtf16, looksBinary, utf8Runs } from "./lib/encoding.ts";
import {
  applyAllowTags,
  dedupeFindings,
  findingsToLines,
  forOutput,
  randomBird,
} from "./lib/inspector.ts";
import {
  beginScanBudget,
  enabledCategoriesFromEnv,
  type Finding,
  scan,
} from "./lib/rules.ts";
import {
  extractEnvVarNames,
  extractQuotedLiterals,
  tokenizeCommand,
} from "./lib/shell.ts";
import {
  collectPathFields,
  isWritingTool,
  normalizeFieldName,
  TOOLS_WITHOUT_FILE_OUTPUT,
} from "./lib/tool-inputs.ts";
import { loadAllowTagsFromTranscript } from "./lib/transcript.ts";

// A hook that crashes exits 1, and only exit 2 blocks — so until now any
// unforeseen error was a silent pass, which is the failure this whole tool
// exists to prevent. What went wrong is unknown at this point, and "unknown" is
// not "safe": the check did not finish, so the call is stopped rather than let
// through. `[allow-all]` gets past it, and the message says the check failed
// rather than claiming a finding.
function failClosed(error: unknown): never {
  try {
    process.stderr.write(
      `\n🐤 sensitive-canary: the check could not complete — ${
        error instanceof Error ? error.message : String(error)
      }\n\n` +
        "  Nothing was scanned, so nothing can be vouched for. Stopping rather\n" +
        "  than passing it through. Add [allow-all] to your prompt to proceed\n" +
        "  anyway, and please report this.\n",
    );
  } catch {
    // A closed stderr must not turn the block back into a pass.
  }
  process.exit(2);
}

process.on("uncaughtException", failClosed);
process.on("unhandledRejection", failClosed);

interface HookInput {
  transcript_path?: string;
  // The directory Claude Code runs the tool in. A relative path in a command is
  // relative to this, and reading it is the difference between scanning
  // `cat secrets.txt` and dropping it as a file that is not there.
  cwd?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown> & {
    file_path?: string;
    command?: string;
  };
}

// Whether a tool is searching, and named nothing to search. `Grep` is the one
// Claude Code ships; an MCP server offering the same thing is recognised by the
// shape of its input rather than by name, since the names are the server's to
// choose. A pattern with no path is a search of the working directory.
function searchesWithoutAPath(
  tool: string,
  input: Record<string, unknown>,
): boolean {
  const searchTerm =
    typeof input["pattern"] === "string" ||
    typeof input["query"] === "string" ||
    typeof input["regex"] === "string";
  return searchTerm && (tool === "Grep" || tool.startsWith("mcp__"));
}

// ── Constants ─────────────────────────────────────────────────────────────────

// Maximum bytes scanned from the head of a file. readFileSync has no size
// limit, so a file of any size was read whole and every rule run over all of
// it — on a multi-GB log that is the hang this hook cannot afford, because a
// killed hook does not block the call (see isRegularFile). A secret past the
// cut is missed; the transcript read above makes the same trade for its tail.
const MAX_FILE_SCAN_BYTES = 1_048_576; // 1 MiB

// Total bytes one hook invocation will read across every file it scans. The
// per-file cap bounds one file; nothing bounded the number of files, and a glob
// naming three hundred of them took half a minute — long enough for the
// PreToolUse timeout to kill the hook, which does not block the call.
//
// Files past the budget are not scanned, so the budget is also a way through:
// eight files of a megabyte each, named before the one that matters, used to
// spend it. Sixty-four megabytes is about two seconds of scanning here, which
// keeps the hook well inside the timeout while making that trick need sixty-four
// files rather than eight. It does not remove it — written up as a limitation.
const MAX_TOTAL_SCAN_BYTES = 64 * 1_048_576; // 64 MiB

// Input field names that carry something to run rather than something to read.
// Compared with separators and case removed, the way path field names are.
const COMMAND_FIELD_NAMES = new Set([
  "command",
  "commands",
  "cmd",
  "script",
  "code",
  "shellcommand",
  "commandline",
]);

// How far into a nested input a command field is looked for. The same depth the
// path fields use, and for the same reason: a tool wraps its arguments.
const MAX_COMMAND_FIELD_DEPTH = 4;

const ENABLED_CATEGORIES = enabledCategoriesFromEnv();

// Mutable for one run of the process: what has been read, and what has already
// been looked at. Overlapping globs named the same file five times over.
const scanned = new Set<string>();
let bytesScanned = 0;

// When this invocation has to stop reading files, whatever it has read.
//
// A byte budget bounds the reading and not the walking, and a pattern reaching
// one level under a home directory took ten seconds — close enough to the
// PreToolUse timeout to matter, and a hook killed by that timeout does not
// block. This is checked between files, so it bounds the reading of many files
// where a byte count would not. It does not bound a single `globSync` call,
// which cannot be interrupted: a pattern several directories deep still costs
// what the walk costs. Files after the deadline are not scanned, and a `.env`
// name reached after it falls back on the name.
// Both clocks start when the payload arrives, not when the process does. The
// wait for stdin is the runtime's, and counting it against the scan meant a
// slow handover spent the whole allowance before a single file was read — five
// seconds of it and nothing was scanned, on an exit code of 0.
let DEADLINE = Number.POSITIVE_INFINITY;

function startTheClock(): void {
  DEADLINE = Date.now() + 5_000;
  // One budget for the whole invocation rather than one per `scan()` call: a
  // call is made per environment variable and per end of each file, so the
  // payload sets how many there are.
  beginScanBudget();
}

// The directory a relative path is relative to. Set from the payload before any
// scanning; `process.cwd()` is where the hook was started, which is not
// necessarily where the command will run.
let baseDirectory = currentDirectoryOrRoot();

// `process.cwd()` throws when the directory the hook was started in has been
// removed, which a build script does every time it runs `rm -rf dist` from
// inside `dist`, and `git worktree remove` does to a worktree. That throw
// happens while this module is still being evaluated — before the transcript is
// read — so it stopped every tool call with a message telling the user to add
// an allow tag that could not possibly be honoured. There is nothing sensitive
// about a missing directory: a relative path simply has no base, and one that
// resolves to nothing is scanned as the name it is.
function currentDirectoryOrRoot(): string {
  try {
    return process.cwd();
  } catch {
    return path.sep;
  }
}

// ── .env pattern ──────────────────────────────────────────────────────────────

// .env and .env.* (e.g. .env.local, .env.production) match the env filename pattern.
// The block only applies while the "secret" category is enabled (see shouldBlockEnvFile).
// Files that merely end in .env (e.g. production.env) are handled by content scanning.
// Said in two places — the name guard and the partial-read guard — and a
// difference between them would read as two different rules.
const ENV_BLOCK_REASON =
  "🚫 Blocked: .env and .env.* files contain secrets and must not be read into the conversation.";

// Suffixes that say a file is the template rather than the filled-in thing.
// These are committed on purpose, carry placeholders, and a tool that refuses to
// read `.env.example` is refusing the file people write in order to explain the
// other one. Their contents are still scanned like any file's, so a template
// with a real key in it is still caught — by what is in it, not by its name.
const ENV_TEMPLATE_SUFFIXES = [
  ".example",
  ".sample",
  ".template",
  ".dist",
  ".defaults",
];

// Any `.env` name, template or not.
function isEnvName(filePath: string): boolean {
  if (!filePath) return false;
  const base = path.basename(filePath);
  return base === ".env" || base.startsWith(".env.");
}

// The same names, minus the templates. Stated in terms of `isEnvName` rather
// than repeating the test: the two answered the question separately, so a change
// to one silently disagreed with the other.
function isBlockedEnvFile(filePath: string): boolean {
  if (!isEnvName(filePath)) return false;
  const base = path.basename(filePath);
  return !ENV_TEMPLATE_SUFFIXES.some((suffix) => base.endsWith(suffix));
}

// The .env name-based block is a secret guard: it only applies while the
// "secret" category is enabled.
function shouldBlockEnvFile(filePath: string): boolean {
  return ENABLED_CATEGORIES.has("secret") && isBlockedEnvFile(filePath);
}

// ── Output helpers ────────────────────────────────────────────────────────────

// Build the allow-tag hint lines shown to Claude.
// showAllTags: when true, always show [allow-secret] and [allow-pii] hints
// regardless of findings content (used for .env name blocks).
function buildAllowHints(
  exampleContext: string,
  findings: Finding[],
  showAllTags = false,
): string[] {
  const hasSecret =
    showAllTags || findings.some((f) => f.category === "secret");
  const hasPii = showAllTags || findings.some((f) => f.category === "pii");

  const lines: string[] = [];
  if (hasSecret) lines.push("  [allow-secret]  — allow secrets");
  if (hasPii) lines.push("  [allow-pii]     — allow PII");
  lines.push("  [allow-all]     — bypass all sensitive-canary checks");
  lines.push("");

  const example =
    hasSecret && hasPii
      ? "allow-all"
      : hasSecret
        ? "allow-secret"
        : hasPii
          ? "allow-pii"
          : "allow-all";
  lines.push(`Example: "[${example}] ${exampleContext}"`);

  return lines;
}

function block(
  source: string,
  detectionLines: string[],
  allowHints: string[],
): never {
  const bird = randomBird();
  const terminalMessage = [
    "",
    `${bird} sensitive-canary: blocked — ${forOutput(source)}`,
    "",
    ...detectionLines,
    "",
  ].join("\n");

  try {
    const fd = fs.openSync("/dev/tty", "w");
    try {
      fs.writeSync(fd, terminalMessage);
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    // No controlling terminal. The reason written to stderr below carries the
    // same detection lines, so there is nothing to fall back to.
  }

  const reasonLines = [
    `${bird} sensitive-canary blocked: ${forOutput(source)}`,
    "",
    ...detectionLines,
    "",
    "To allow this, the user must add an allow tag to their next prompt:",
    ...allowHints,
    "",
    "Please tell the user about this block and suggest the appropriate tag.",
  ];

  // Exit 2 blocks the tool call and stderr is the documented way to say why.
  //
  // The reason used to be written to stdout as `{"decision":"block", …}`. That
  // does reach Claude on the current version — measured with a probe hook, not
  // assumed — but the documentation says stdout is ignored on a non-zero exit
  // and that PreToolUse takes its decision from `hookSpecificOutput`, not from a
  // top-level `decision` field. So the old form worked by way of behaviour no
  // longer described anywhere, and a release could drop it without breaking a
  // documented contract. Blocking would survive that (exit 2 is the block), but
  // the reason and the allow-tag guidance would not.
  //
  // When both channels carry text, stdout wins and stderr is discarded, so
  // writing both would leave the documented one dead. Hence stderr alone.
  // Wrapped, and the exit is outside it: a closed stderr made this write throw,
  // and an exception exits 1, which passes the call through. The block became
  // its opposite because the message could not be delivered.
  try {
    process.stderr.write(`${reasonLines.join("\n")}\n`);
  } catch {
    // Nothing to say and nowhere to say it. The verdict stands.
  }
  process.exit(2);
}

// ── Core scan logic ───────────────────────────────────────────────────────────

// Characters that make a token a pattern rather than a filename. `{` is here
// because the shell expands `{a,b}` too, and `cat .env{,.bak}` reached the name
// guard as the single name `.env{`.
const GLOB_METACHARACTERS = /[*?[{]/;

// How many matches of one pattern are scanned. This bounds the reading, not the
// walk: `globSync` builds the whole expansion before this takes a slice of it, so
// a pattern over a large tree still costs the walk.
const MAX_GLOB_MATCHES = 256;

// The paths a candidate stands for.
//
// A token carrying glob metacharacters names whatever the shell will expand it
// to, and the file is in the expansion, not in the token: `cat sec*` collected
// `sec*`, found no file by that name, and allowed the read. `cat .env*` did the
// same, one character away from `cat .env`, which is blocked on its name — so
// the guard this hook is most sure of was a wildcard away from being skipped.
//
// Expanded here rather than in the tokenizer because it needs the filesystem,
// which is also why it can differ from what the shell will do a moment later.
function expandCandidate(candidate: string): string[] {
  const literal = path.resolve(
    baseDirectory,
    expandPath(fromFileUrl(candidate)),
  );
  if (!GLOB_METACHARACTERS.test(literal)) return [literal];
  // `**` matches across directories, and expanding it walked a whole tree:
  // `cat ~/**/*` ran until the hook was killed, which is the failure this file
  // spends a `stat` per path to avoid. Refusing it outright was worse — the
  // shell still expands it and reads the files, so `cat **` was scanned not at
  // all. Collapsed to one `*`, which costs a listing per matching directory the
  // way every other pattern here does, and reaches one level rather than every
  // level. Written up as a limitation.
  const pattern = literal.replace(/\*{2,}/g, "*");
  let matches: string[] = [];
  try {
    matches = fs.globSync(pattern).slice(0, MAX_GLOB_MATCHES);
  } catch {
    matches = [];
  }
  // The literal is kept as well as the expansion, and returning only the matches
  // was a way through that this hook did not have before the expansion existed:
  // `cat /nonexistent/.env.*` matches nothing, so nothing was scanned and the
  // `.env` name guard — which reads the name, not the disk — never ran. A file
  // really named `report[2].txt` was lost the same way, since glob reads `[2]`
  // as a character class and expands it to `report2.txt`.
  return [literal, ...matches];
}

// A `file://` URI names a path, and MCP tools pass one under `uri` where another
// would pass `path`. Resolved as a relative path it named nothing, so it fell to
// the not-a-file check before the `.env` name guard could read it.
function fromFileUrl(candidate: string): string {
  if (!candidate.startsWith("file://")) return candidate;
  try {
    return fileURLToPath(candidate);
  } catch {
    return candidate;
  }
}

// `$VAR` and `${VAR}` in a path, substituted from this process's environment,
// which is the one the command will inherit.
//
// An unset variable is left as written rather than removed: a shell expands it
// to nothing, and the shortened path names a different file. Finding nothing is
// the safer of the two wrong answers.
function expandShellVars(candidate: string): string {
  return candidate.replace(
    /\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g,
    (whole, braced: string | undefined, bare: string | undefined) =>
      process.env[braced ?? bare ?? ""] ?? whole,
  );
}

// A path as the shell will see it: variables substituted, then `~` and `~/…`
// resolved to the home directory. `~user/…` is left alone, since resolving it
// needs the password database.
function expandPath(candidate: string): string {
  const expanded = expandShellVars(candidate);
  if (expanded === "~") return os.homedir();
  if (!expanded.startsWith("~/")) return expanded;
  return path.join(os.homedir(), expanded.slice(2));
}

// The regular files directly inside a directory, for the tools that read a
// directory's contents — `grep -r`, and a Grep whose `path` names a folder.
//
// One level, and capped at the same limit a glob is, because the walk is the
// part that cannot be interrupted. `readdirSync` rather than a glob: `*` does
// not match a leading dot, and `.env` is the file this most needs to find.
//
// Binaries are skipped here, though a file the user names outright is still
// scanned whole. Nobody asked for these: they are swept up because the
// directory was named, and a folder of images cost three seconds and reported
// the compressed bytes as email addresses.
function filesDirectlyUnder(candidate: string): string[] {
  try {
    return (
      fs
        .readdirSync(candidate, { withFileTypes: true })
        .filter((entry) => entry.isFile())
        .slice(0, MAX_GLOB_MATCHES)
        .map((entry) => path.join(candidate, entry.name))
        // An `.env` is kept whatever its bytes look like, because `scanFile`
        // judges it on its name when the contents cannot speak for it. Dropping
        // it here runs first, so a binary-looking one would never reach that
        // guard — and eight bytes of NUL are all it takes to look binary.
        .filter((file) => isEnvName(file) || !looksBinary(file))
    );
  } catch {
    // Not a directory, or not readable.
    return [];
  }
}

// Every command an input carries, whatever shape it arrives in.
//
// Reading only top-level strings left two shapes through, and both reach the
// `.env` name guard by a name with no slash in it, which the path rules do not
// collect: an argv array (`{"command":["cat",".env"]}`) and a command nested
// under another key (`{"args":{"command":"cat .env"}}`). Depth-limited the way
// path fields are, for the same reason.
function collectCommandFields(
  input: Record<string, unknown>,
  depth = 0,
): string[] {
  if (depth > MAX_COMMAND_FIELD_DEPTH) return [];
  const found: string[] = [];
  for (const [key, value] of Object.entries(input)) {
    const named = COMMAND_FIELD_NAMES.has(normalizeFieldName(key));
    if (named && typeof value === "string") {
      found.push(value);
    } else if (named && Array.isArray(value)) {
      // An argv array is one command line with the spaces taken out.
      const argv = value.filter((v): v is string => typeof v === "string");
      if (argv.length > 0) found.push(argv.join(" "));
    } else if (value !== null && typeof value === "object") {
      found.push(
        ...collectCommandFields(value as Record<string, unknown>, depth + 1),
      );
    }
  }
  return found;
}

// Whether a path names something whose bytes can be read to the end.
//
// A character device or a FIFO can be opened and read from forever: `cat
// /dev/zero` never returns, and neither did the hook, until Claude Code's
// PreToolUse timeout killed it. A killed hook does not block the call, so a hang
// is a fail-open — the one failure mode worth spending a `stat` on every path to
// avoid.
function isDirectory(candidate: string): boolean {
  try {
    return fs.statSync(candidate).isDirectory();
  } catch {
    return false;
  }
}

function isRegularFile(candidate: string): boolean {
  try {
    return fs.statSync(candidate).isFile();
  } catch {
    return false;
  }
}

// Scan a candidate only when it names an existing regular file. A tool input
// whose "path" means something else (a URL route, an object key) names nothing on
// disk, so it is dropped here and never reaches the `.env` name guard — which is
// the difference from the Bash path, where a name that exists on no disk is still
// blocked. Existing files go on to `scanFile` and are name-guarded there.
function scanIfRegularFile(
  candidate: string | undefined,
  allowTags: Set<string>,
  options: { namesOnly?: boolean } = {},
): void {
  if (!candidate) return;
  for (const p of expandCandidate(candidate)) {
    if (isRegularFile(p)) {
      if (options.namesOnly)
        blockUnreadEnvFile(p, allowTags, SEARCH_ROOT_ENV_REASON);
      else scanFile(p, allowTags);
      continue;
    }
    for (const child of filesDirectlyUnder(p)) {
      if (options.namesOnly)
        blockUnreadEnvFile(child, allowTags, SEARCH_ROOT_ENV_REASON);
      else scanFile(child, allowTags);
    }
  }
}

const UNREAD_ENV_REASON =
  "Its contents were not read — it is not a regular file, or the scan for this call had already stopped — so the name is what decides.";

const SEARCH_ROOT_ENV_REASON =
  "The search names no path, so it runs here and prints from whatever it matches. This file was not read; it is the name that decides.";

// A `.env` file that will not be read is judged on its name, template or not.
function blockUnreadEnvFile(
  filePath: string,
  allowTags: Set<string>,
  reason: string = UNREAD_ENV_REASON,
): void {
  if (!isEnvName(filePath) || !ENABLED_CATEGORIES.has("secret")) return;
  // A path that names nothing has nothing to leak. `cat .env.example` in a
  // checkout without one is an ordinary command, and the plain `.env` guard
  // above already decides the names that are blocked whether they exist or not.
  if (!fs.existsSync(filePath)) return;
  if (allowTags.has("secret") || allowTags.has("all")) return;
  block(
    filePath,
    [ENV_BLOCK_REASON, "", reason],
    buildAllowHints(`please read ${forOutput(filePath)}`, [], true),
  );
}

// The values a command would print, whichever tool is running it.
function scanEnvironment(names: string[], allowTags: Set<string>): void {
  for (const varName of names) {
    const value = process.env[varName];
    if (!value) continue;
    const findings = dedupeFindings(
      applyAllowTags(scan(value, ENABLED_CATEGORIES), allowTags),
    );
    if (findings.length === 0) continue;
    block(
      "bash command",
      [
        `🚫 Blocked: environment variable $${varName} contains sensitive data`,
        "",
        ...findingsToLines(findings),
      ],
      buildAllowHints("please run the command", findings),
    );
  }
}

// Files named outright, then the ones a pattern has to be expanded to find.
//
// Expanding a pattern costs what the walk costs and cannot be interrupted, so a
// deep one spent the call's whole deadline — and every file named after it in
// the same command went unscanned. `cat ~/*/*/*/*/* secrets` read nothing of
// `secrets`. Ordering does not make the walk cheaper; it stops one token
// starving the rest.
function scanPathsLiteralsFirst(
  paths: string[],
  allowTags: Set<string>,
  opts?: { onlyExisting?: boolean },
): void {
  const scanOne = (candidate: string): void => {
    if (opts?.onlyExisting) {
      scanIfRegularFile(candidate, allowTags);
      return;
    }
    scanFile(candidate, allowTags);
    // `grep -r AKIA .` names a directory, and `scanFile` has nothing to read
    // from one.
    for (const child of filesDirectlyUnder(candidate)) {
      scanFile(child, allowTags);
    }
  };
  const patterns: string[] = [];
  for (const candidate of paths) {
    if (GLOB_METACHARACTERS.test(candidate)) patterns.push(candidate);
    else for (const p of expandCandidate(candidate)) scanOne(p);
  }
  for (const candidate of patterns) {
    for (const p of expandCandidate(candidate)) scanOne(p);
  }
}

function scanFile(filePath: string, allowTags: Set<string>): void {
  if (shouldBlockEnvFile(filePath)) {
    // The guard is a secret guard — `shouldBlockEnvFile` already asks whether the
    // secret category is on — so the tag that lifts it has to be one that allows
    // secrets. Any tag at all used to lift it, and `parseAllowTags` reads
    // `[allow-<anything>]`, so `[allow-banana]` and a mistyped `[allow-pi]` both
    // turned the guard off.
    //
    // Lifting the name guard is not permission to skip the file: `[allow-secret]`
    // says nothing about the PII in it, and returning here skipped the content
    // scan along with the name. So this falls through, and `applyAllowTags`
    // below drops the findings the tag really covers.
    if (!allowTags.has("secret") && !allowTags.has("all")) {
      block(
        filePath,
        [ENV_BLOCK_REASON],
        buildAllowHints(`please read ${forOutput(filePath)}`, [], true),
      );
    }
  }

  // The name guard above runs first and on the name alone, so `cat .env.missing`
  // is still blocked. Everything past here opens the file.
  //
  // Each of these is a way of not reading it: something that is not a regular
  // file, a budget already spent, a deadline already passed. For a `.env` name
  // the contents were what the template exemption relied on, so when they are
  // not going to be read the name decides — otherwise naming enough large files
  // first was a way past the guard, and so was a FIFO called `.env.x.example`.
  if (!isRegularFile(filePath)) {
    blockUnreadEnvFile(filePath, allowTags);
    return;
  }
  if (scanned.has(filePath)) return;
  scanned.add(filePath);
  if (bytesScanned >= MAX_TOTAL_SCAN_BYTES) {
    blockUnreadEnvFile(filePath, allowTags);
    return;
  }
  if (Date.now() > DEADLINE) {
    blockUnreadEnvFile(filePath, allowTags);
    return;
  }

  let content: string;
  let tailContent = "";
  let readWasPartial = false;
  try {
    // The buffer is the cap, not the reported size. Sizing it from `stat` made
    // the read believe the file: procfs and sysfs entries are regular files that
    // report a size of zero and produce content anyway, so their content was
    // read as empty and passed. `readFileSync` handled that case by reading to
    // EOF, and replacing it took the handling with it.
    //
    // The cap is what bounds it: the first megabyte and, on a larger file, the
    // last. Every run of text between NUL separators inside those windows is
    // scanned, so a NUL-separated file such as `/proc/self/environ` is read
    // through rather than cut at its first entry.
    const buf = Buffer.alloc(MAX_FILE_SCAN_BYTES);
    const fd = fs.openSync(filePath, "r");
    let raw: Buffer;
    let tail: Buffer | null = null;
    try {
      const bytesRead = fs.readSync(fd, buf, 0, buf.length, 0);
      raw = buf.subarray(0, bytesRead);
      // The end as well as the beginning, when there is more than the cap
      // between them. `tail -2 app.log` prints the last two lines and the cap
      // reads the first megabyte, so on a large log the scan looked at exactly
      // the part that was not shown — and the last lines of a log are where a
      // failure has just printed a connection string.
      const size = fs.fstatSync(fd).size;
      if (size > MAX_FILE_SCAN_BYTES) {
        const end = Buffer.alloc(MAX_FILE_SCAN_BYTES);
        const read = fs.readSync(
          fd,
          end,
          0,
          end.length,
          size - MAX_FILE_SCAN_BYTES,
        );
        tail = end.subarray(0, read);
      }
    } finally {
      fs.closeSync(fd);
    }
    bytesScanned += raw.length;
    if (tail !== null) {
      bytesScanned += tail.length;
      const tailUtf16 = detectUtf16(tail);
      const windows: string[] = [];
      if (tailUtf16 !== null) {
        const text = tailUtf16.bytes.toString("utf16le");
        // Past the last NUL rather than up to the first: this window is the end
        // of the file, so what follows a separator is the part that gets
        // printed.
        const nul = text.lastIndexOf("\0");
        windows.push(nul === -1 ? text : text.slice(nul + 1));
      }
      if (tailUtf16 === null || !tailUtf16.fromBom)
        windows.push(utf8Runs(tail));
      tailContent = windows.join("\n");
    }
    // UTF-16 puts a NUL in every other byte, so the rule below stopped after one
    // character and the file went through unread. PowerShell 5.1 writes UTF-16LE
    // by default, which makes `Get-Something > creds.txt` a file this tool did
    // not look at. Detected by the byte-order mark, or by NULs falling on one
    // side of every pair through the prefix.
    const utf16 = detectUtf16(raw);
    // Whether the file was read to its end. Recorded here and acted on below,
    // outside the catch: `block` exits the process, and anything it threw on the
    // way — a closed stderr, say — would be swallowed by the `catch` and turn a
    // block into a pass.
    //
    // A NUL counts as partial for the `.env` template guard below even though
    // every run is scanned: the guard turns on whether the contents can speak
    // for the name, and a file that is part binary cannot. The NUL that counts
    // is one in the text, not one in the bytes — UTF-16 is half NUL by
    // construction, and reading those bytes directly makes every UTF-16 file
    // partial.
    const hitTheCut = raw.length >= MAX_FILE_SCAN_BYTES;
    if (utf16 === null) {
      readWasPartial = raw.indexOf(0) !== -1 || hitTheCut;
      content = utf8Runs(raw);
    } else {
      const text = utf16.bytes.toString("utf16le").replace(/^\uFEFF/, "");
      const nul = text.indexOf("\0");
      readWasPartial = nul !== -1 || hitTheCut;
      const decoded = nul === -1 ? text : text.split("\0").join("\n");
      // Without a byte-order mark that reading is a guess, and the NUL counts
      // it rests on cannot tell a UTF-8 file carrying a few NULs from a page of
      // Japanese UTF-16. Both readings are scanned rather than one of them
      // chosen: the cost is a second pass over the prefix, and what it buys is
      // that a wrong guess hides nothing. Sixteen bytes of NUL in front of a
      // file are otherwise enough to decode the rest of it out of reach of
      // every rule.
      content = utf16.fromBom ? decoded : `${decoded}\n${utf8Runs(raw)}`;
    }
  } catch {
    return;
  }

  // Exempting a template name from the guard assumed the contents would be read
  // instead. A NUL byte and the per-file cut both stop that, and a file named
  // `.env.something.example` carrying either was passing on its name after all.
  // When the read is partial, the name is what is left to decide on.
  if (
    readWasPartial &&
    isEnvName(filePath) &&
    ENABLED_CATEGORIES.has("secret") &&
    !allowTags.has("secret") &&
    !allowTags.has("all")
  ) {
    block(
      filePath,
      [
        ENV_BLOCK_REASON,
        "",
        "This one is named as a template, which is normally read. It could not be read whole — it holds a NUL byte or runs past the scan limit — so the name is what decides.",
      ],
      buildAllowHints(`please read ${forOutput(filePath)}`, [], true),
    );
  }

  // A second window over the same file, judged on its own: a finding in either
  // end is a finding.
  if (tailContent.length > 0) {
    const tailFindings = dedupeFindings(
      applyAllowTags(scan(tailContent, ENABLED_CATEGORIES), allowTags),
    );
    if (tailFindings.length > 0) {
      block(
        filePath,
        [
          "🚫 Blocked: file contains sensitive data",
          "",
          ...findingsToLines(tailFindings),
        ],
        buildAllowHints(`please read ${forOutput(filePath)}`, tailFindings),
      );
    }
  }

  if (content.length === 0) return;

  // Allow first, then dedupe. The other way round, a value that a secret rule
  // and a PII rule both match loses the PII finding to deduplication before the
  // tag is consulted, and `[allow-secret]` then removes the secret finding too —
  // so the tag lifted a PII block, which the README says it cannot.
  const findings = dedupeFindings(
    applyAllowTags(scan(content, ENABLED_CATEGORIES), allowTags),
  );
  if (findings.length === 0) return;

  block(
    filePath,
    [
      "🚫 Blocked: file contains sensitive data",
      "",
      ...findingsToLines(findings),
    ],
    buildAllowHints(`please read ${forOutput(filePath)}`, findings),
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk: string) => (raw += chunk));
process.stdin.on("end", () => {
  startTheClock();
  let data: HookInput;
  try {
    // Empty stdin is nothing to check. Bytes that do not parse are a check that
    // could not read its input, which is not the same as safe: two characters
    // missing from the end of a payload used to pass a key through.
    if (raw.trim().length === 0) process.exit(0);
    const parsed: unknown = JSON.parse(raw);
    // `JSON.parse("null")` succeeds and returns null, which then threw on the
    // first field read. A payload that is not an object names nothing, so
    // there is nothing to scan and nothing to stop.
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed))
      process.exit(0);
    data = parsed as HookInput;
  } catch (error) {
    // The check never started, so it vouches for nothing. Everything else that
    // cannot finish stops the call; input that will not parse is the same case.
    failClosed(error);
  }

  const tool = typeof data.tool_name === "string" ? data.tool_name : "";
  // Before anything resolves a path: a relative path in a command is relative to
  // where Claude Code will run it, not to where this hook was started.
  if (typeof data.cwd === "string" && data.cwd) baseDirectory = data.cwd;

  const input = data.tool_input ?? {};

  const allowTags = data.transcript_path
    ? loadAllowTagsFromTranscript(data.transcript_path)
    : new Set<string>();

  if (tool === "Read") {
    // Through the same expansion as everything else: this branch resolved
    // nothing, so a relative `file_path`, a `~`, a `file://` URI and a pattern
    // all named something that is not on disk.
    //
    // And through the same collector, so a `file_path` that is not a string is
    // read rather than dropped. Coercing it to "" exited 0 here while every
    // other tool name reached `collectPathFields` and blocked — the same shape,
    // two answers.
    for (const target of collectPathFields(input)) {
      for (const candidate of expandCandidate(target)) {
        scanFile(candidate, allowTags);
      }
    }
    process.exit(0);
  }

  if (tool === "Bash") {
    // A tool input is whatever the tool declares, so a `command` that is not a
    // string is a shape this really receives. It used to throw, and an exception
    // exits 1, which does not block: the call went through unscanned.
    const command = Array.isArray(input.command)
      ? input.command
          .filter((v): v is string => typeof v === "string")
          .join(" ")
      : typeof input.command === "string"
        ? input.command
        : "";
    // `cd build && cat secrets` runs the read somewhere else, and the payload's
    // cwd is where the command starts rather than where it ends up.
    //
    // Only a `cd` before the first other command counts. Folding every `cd` in
    // the line moved the base for reads that happen earlier — `cat secrets && cd
    // /tmp` resolved against `/tmp` and found nothing — and for a `cd` inside a
    // subshell, which the shell undoes on the way out. The tokenizer ends a
    // segment at a paren, so a subshell's `cd` is not distinguishable once split;
    // a command that opens with one is left resolving against the payload's cwd.
    if (!command.trimStart().startsWith("(")) {
      for (const segment of tokenizeCommand(command)) {
        const [head, target] = segment;
        // `head.redirect` is defensive rather than reachable: the tokenizer
        // marks a token as a redirect only when it built it from `<` or `>`, so
        // no input produces one whose value is `cd`. Kept because the guard
        // costs nothing and the tokenizer is free to change.
        if (head?.value !== "cd" || head.redirect) break;
        if (target === undefined || target.redirect) break;
        // `cd -`, `cd b*ld` and a `cd` into an unset variable name a directory
        // this cannot work out. Following one anyway moves the base somewhere
        // the command will not read, and every relative path after it resolves
        // against the wrong directory.
        const destination = expandPath(target.value);
        if (
          target.value === "-" ||
          target.value === "--" ||
          destination.includes("$") ||
          GLOB_METACHARACTERS.test(destination)
        ) {
          break;
        }
        // A `cd` the shell will fail is a `cd` that does not happen. Following
        // it moved the base somewhere neither the command nor this will read.
        const moved = path.resolve(baseDirectory, destination);
        if (!isDirectory(moved)) break;
        baseDirectory = moved;
      }
    }
    const refs = extractCommandRefs(command);

    // A bare `env` or `printenv` prints everything, so every variable is in play.
    const envVarNames = refs.dumpsEnvironment
      ? Object.keys(process.env)
      : [...new Set([...extractEnvVarNames(command), ...refs.envVars])];

    scanEnvironment(envVarNames, allowTags);

    const cmdFindings = dedupeFindings(
      applyAllowTags(scan(command, ENABLED_CATEGORIES), allowTags),
    );
    if (cmdFindings.length > 0) {
      block(
        "bash command",
        [
          "🚫 Blocked: bash command contains sensitive data",
          "",
          ...findingsToLines(cmdFindings),
        ],
        buildAllowHints("please run the command", cmdFindings),
      );
    }

    scanPathsLiteralsFirst(refs.paths, allowTags);
    // `rg PATTERN` and `grep -r PATTERN` name nothing and print from the working
    // directory. Judged on names alone, for the reason set out where the same
    // thing is done for the search tools.
    if (refs.searchesWorkingDirectory) {
      scanIfRegularFile(baseDirectory, allowTags, { namesOnly: true });
    }

    process.exit(0);
  }

  // Every other tool, Grep and the MCP tools included: those can return file
  // contents the same way Read does, so a field naming an existing file is
  // scanned before the call. Grep needs no branch of its own — its `path` is one
  // of the fields collected here, and it is neither exempt nor named as a writer.
  if (!TOOLS_WITHOUT_FILE_OUTPUT.has(tool)) {
    // An MCP server that runs a shell takes the command as an input field, and
    // an IDE bridge takes code the same way. Only `Bash` was read as a command,
    // so `mcp__desktop-commander__start_process` with `{"command":"cat .env"}`
    // was looked at as a path, found not to be a file, and let through — with
    // the default matcher sending every `mcp__*` tool here.
    for (const value of collectCommandFields(input)) {
      // What the command says, as well as what it opens. A key in an argument
      // list is a key whichever tool runs the shell.
      const commandFindings = dedupeFindings(
        applyAllowTags(scan(value, ENABLED_CATEGORIES), allowTags),
      );
      if (commandFindings.length > 0) {
        block(
          `${tool} command`,
          [
            "🚫 Blocked: tool command contains sensitive data",
            "",
            ...findingsToLines(commandFindings),
          ],
          buildAllowHints("please run the command", commandFindings),
        );
      }

      const refs = extractCommandRefs(value);
      // Code is not a command line: `print(open("secrets").read())` has no
      // command in it this can classify, and the path is a quoted literal — the
      // same shape inline `-c` text is read for.
      refs.paths.push(...extractQuotedLiterals(value));
      scanPathsLiteralsFirst(refs.paths, allowTags, { onlyExisting: true });

      // A command names an environment as readily as a file. The Bash branch
      // has always scanned the variables a command would print; a tool that
      // runs a shell was collected for paths and nothing else, so
      // `{"command":"printenv"}` handed the environment back whole.
      scanEnvironment(
        refs.dumpsEnvironment
          ? Object.keys(process.env)
          : [...new Set([...extractEnvVarNames(value), ...refs.envVars])],
        allowTags,
      );
    }

    // The write-verb exemption is about a tool's *output*: naming a file it only
    // writes to is not a leak. A command is not output — `create_process` runs
    // what it is handed — so the command fields above are read whatever the name
    // says, and only the path fields are exempt.
    if (!isWritingTool(tool)) {
      const candidates = collectPathFields(input);
      for (const candidate of candidates) {
        scanIfRegularFile(candidate, allowTags);
      }
      // A search tool given no path searches where it is run, and that is its
      // ordinary form: `Grep {pattern}` with no `path` is what Claude reaches
      // for first. With no field to collect there is nothing to scan, so the
      // directory the search prints from is the one directory never looked at.
      //
      // Names only. A directory the user pointed at is one they asked about, and
      // reading its files is answering the question they asked; a directory
      // nobody named is every repository anyone searches, and content-scanning
      // those stopped an ordinary `rg TODO` in a third of the checkouts on this
      // machine — a README quoting a connection string is enough. The name guard
      // keeps the case worth keeping, since a `.env` sitting in the search root
      // is both the likeliest leak and the one no pattern has to match for.
      if (candidates.length === 0 && searchesWithoutAPath(tool, input)) {
        scanIfRegularFile(baseDirectory, allowTags, { namesOnly: true });
      }
    }
  }

  process.exit(0);
});

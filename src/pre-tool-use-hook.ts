#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { extractCommandRefs } from "./lib/bash-commands.ts";
import {
  applyAllowTags,
  dedupeFindings,
  findingsToLines,
  type Message,
  parseAllowTags,
  randomBird,
} from "./lib/inspector.ts";
import { enabledCategoriesFromEnv, type Finding, scan } from "./lib/rules.ts";
import {
  extractEnvVarNames,
  extractQuotedLiterals,
  tokenizeCommand,
} from "./lib/shell.ts";
import {
  collectPathFields,
  isWritingTool,
  TOOLS_WITHOUT_FILE_OUTPUT,
} from "./lib/tool-inputs.ts";

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

interface TranscriptLine {
  message?: Message;
}

// ── Constants ─────────────────────────────────────────────────────────────────

// Maximum bytes to read from the tail of a transcript file.
const MAX_TRANSCRIPT_TAIL_BYTES = 65_536; // 64 KB

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

const ENABLED_CATEGORIES = enabledCategoriesFromEnv();

// Mutable for one run of the process: what has been read, and what has already
// been looked at. Overlapping globs named the same file five times over.
const scanned = new Set<string>();
let bytesScanned = 0;

// The directory a relative path is relative to. Set from the payload before any
// scanning; `process.cwd()` is where the hook was started, which is not
// necessarily where the command will run.
let baseDirectory = process.cwd();

// ── Transcript ────────────────────────────────────────────────────────────────

// Returns true when the message contains at least one text content block
// (or is a plain string). Tool-result-only messages are not real user input.
function hasTextContent(msg: Message): boolean {
  if (typeof msg.content === "string") return true;
  return msg.content.some((b) => b.type === "text");
}

// Load allow tags from the Claude Code session transcript.
// Transcript format (JSONL): { "type": "user"|"assistant", "message": { role, content }, … }
// Only the most recent user *text* message is consulted, and only if no tool_result
// entries have been recorded after it. This means allow tags are consumed by the first
// tool call — subsequent tool calls in the same AI turn will be blocked.
function loadAllowTagsFromTranscript(transcriptPath: string): Set<string> {
  let raw: string;
  try {
    const stat = fs.statSync(transcriptPath);
    if (stat.size <= MAX_TRANSCRIPT_TAIL_BYTES) {
      raw = fs.readFileSync(transcriptPath, "utf8");
    } else {
      const buf = Buffer.alloc(MAX_TRANSCRIPT_TAIL_BYTES);
      const fd = fs.openSync(transcriptPath, "r");
      try {
        const bytesRead = fs.readSync(
          fd,
          buf,
          0,
          MAX_TRANSCRIPT_TAIL_BYTES,
          stat.size - MAX_TRANSCRIPT_TAIL_BYTES,
        );
        raw = buf.subarray(0, bytesRead).toString("utf8");
      } finally {
        fs.closeSync(fd);
      }
    }
  } catch {
    return new Set();
  }

  let lastUserMessage: Message | null = null;
  let toolResultAfterLastText = false;
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed) as TranscriptLine;
      const msg = parsed.message;
      if (msg?.role === "user" && msg.content !== undefined) {
        if (hasTextContent(msg)) {
          lastUserMessage = msg;
          toolResultAfterLastText = false;
        } else {
          toolResultAfterLastText = true;
        }
      }
    } catch {
      // skip malformed lines
    }
  }

  if (!lastUserMessage || toolResultAfterLastText) return new Set();
  return parseAllowTags([lastUserMessage]);
}

// ── .env pattern ──────────────────────────────────────────────────────────────

// .env and .env.* (e.g. .env.local, .env.production) match the env filename pattern.
// The block only applies while the "secret" category is enabled (see shouldBlockEnvFile).
// Files that merely end in .env (e.g. production.env) are handled by content scanning.
function isBlockedEnvFile(filePath: string): boolean {
  if (!filePath) return false;
  const base = path.basename(filePath);
  return base === ".env" || base.startsWith(".env.");
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
    `${bird} sensitive-canary: blocked — ${source}`,
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
    `${bird} sensitive-canary blocked: ${source}`,
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
  process.stderr.write(`${reasonLines.join("\n")}\n`);
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
    expandTilde(fromFileUrl(candidate)),
  );
  if (!GLOB_METACHARACTERS.test(literal)) return [literal];
  // `**` is what walked a whole tree: `cat ~/**/*` ran until the hook was killed,
  // which is the failure this file spends a `stat` per path to avoid. A single
  // `*` in a directory component costs one listing per matching directory, which
  // is what `cat services/*/config.yml` in a monorepo needs.
  if (literal.includes("**")) return [literal];
  let matches: string[] = [];
  try {
    matches = fs.globSync(literal).slice(0, MAX_GLOB_MATCHES);
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

// `~` and `~/…` stand for the home directory, and nothing here expanded them, so
// `cat ~/.aws/credentials` named a path that exists on no disk and was dropped
// as a file that is not there. `~user/…` is left alone: resolving it needs the
// password database, and guessing at it would name the wrong file.
function expandTilde(candidate: string): string {
  if (candidate === "~") return os.homedir();
  if (!candidate.startsWith("~/")) return candidate;
  return path.join(os.homedir(), candidate.slice(2));
}

// Whether a path names something whose bytes can be read to the end.
//
// A character device or a FIFO can be opened and read from forever: `cat
// /dev/zero` never returns, and neither did the hook, until Claude Code's
// PreToolUse timeout killed it. A killed hook does not block the call, so a hang
// is a fail-open — the one failure mode worth spending a `stat` on every path to
// avoid.
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
): void {
  if (!candidate) return;
  for (const p of expandCandidate(candidate)) {
    if (isRegularFile(p)) scanFile(p, allowTags);
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
        [
          "🚫 Blocked: .env and .env.* files contain secrets and must not be read into the conversation.",
        ],
        buildAllowHints(`please read ${filePath}`, [], true),
      );
    }
  }

  // The name guard above runs first and on the name alone, so `cat .env.missing`
  // is still blocked. Everything past here opens the file.
  if (!isRegularFile(filePath)) return;
  if (scanned.has(filePath)) return;
  scanned.add(filePath);
  if (bytesScanned >= MAX_TOTAL_SCAN_BYTES) return;

  let content: string;
  try {
    // The buffer is the cap, not the reported size. Sizing it from `stat` made
    // the read believe the file: procfs and sysfs entries are regular files that
    // report a size of zero and produce content anyway, so their content was
    // read as empty and passed. `readFileSync` handled that case by reading to
    // EOF, and replacing it took the handling with it.
    //
    // What this does not do is scan such a file whole. The NUL rule below stops
    // at the first separator, so `/proc/self/environ` is read but only its first
    // variable is looked at. Written up under Known Limitations.
    const buf = Buffer.alloc(MAX_FILE_SCAN_BYTES);
    const fd = fs.openSync(filePath, "r");
    let raw: Buffer;
    try {
      const bytesRead = fs.readSync(fd, buf, 0, buf.length, 0);
      raw = buf.subarray(0, bytesRead);
    } finally {
      fs.closeSync(fd);
    }
    // Binary files: scan only the text prefix before the first NUL byte
    bytesScanned += raw.length;
    const nulIndex = raw.indexOf(0);
    content = (nulIndex === -1 ? raw : raw.subarray(0, nulIndex)).toString(
      "utf8",
    );
    if (content.length === 0) return;
  } catch {
    return;
  }

  const findings = applyAllowTags(
    dedupeFindings(scan(content, ENABLED_CATEGORIES)),
    allowTags,
  );
  if (findings.length === 0) return;

  block(
    filePath,
    [
      "🚫 Blocked: file contains sensitive data",
      "",
      ...findingsToLines(findings),
    ],
    buildAllowHints(`please read ${filePath}`, findings),
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk: string) => (raw += chunk));
process.stdin.on("end", () => {
  let data: HookInput;
  try {
    data = JSON.parse(raw) as HookInput;
  } catch {
    process.exit(0);
  }

  const tool = data.tool_name ?? "";
  // Before anything resolves a path: a relative path in a command is relative to
  // where Claude Code will run it, not to where this hook was started.
  if (typeof data.cwd === "string" && data.cwd) baseDirectory = data.cwd;

  const input = data.tool_input ?? {};

  const allowTags = data.transcript_path
    ? loadAllowTagsFromTranscript(data.transcript_path)
    : new Set<string>();

  if (tool === "Read") {
    const target = typeof input.file_path === "string" ? input.file_path : "";
    // Through the same expansion as everything else: this branch resolved
    // nothing, so a relative `file_path`, a `~`, a `file://` URI and a pattern
    // all named something that is not on disk.
    for (const candidate of expandCandidate(target)) {
      scanFile(candidate, allowTags);
    }
    process.exit(0);
  }

  if (tool === "Bash") {
    // A tool input is whatever the tool declares, so a `command` that is not a
    // string is a shape this really receives. It used to throw, and an exception
    // exits 1, which does not block: the call went through unscanned.
    const command = typeof input.command === "string" ? input.command : "";
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
        if (head?.value !== "cd" || head.redirect) break;
        if (target === undefined || target.redirect) break;
        // `cd -`, `cd b*ld` and a `cd` into a variable name a directory this
        // cannot work out, and resolving them anyway pointed the scan at some
        // other directory entirely.
        if (target.value === "-" || GLOB_METACHARACTERS.test(target.value)) {
          break;
        }
        baseDirectory = path.resolve(baseDirectory, expandTilde(target.value));
      }
    }
    const refs = extractCommandRefs(command);

    // A bare `env` or `printenv` prints everything, so every variable is in play.
    const envVarNames = refs.dumpsEnvironment
      ? Object.keys(process.env)
      : [...new Set([...extractEnvVarNames(command), ...refs.envVars])];

    for (const varName of envVarNames) {
      const value = process.env[varName];
      if (!value) continue;
      const findings = applyAllowTags(
        dedupeFindings(scan(value, ENABLED_CATEGORIES)),
        allowTags,
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

    const cmdFindings = applyAllowTags(
      dedupeFindings(scan(command, ENABLED_CATEGORIES)),
      allowTags,
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

    for (const fp of refs.paths) {
      for (const p of expandCandidate(fp)) scanFile(p, allowTags);
    }

    process.exit(0);
  }

  // Every other tool, Grep and the MCP tools included: those can return file
  // contents the same way Read does, so a field naming an existing file is
  // scanned before the call. Grep needs no branch of its own — its `path` is one
  // of the fields collected here, and it is neither exempt nor named as a writer.
  if (!TOOLS_WITHOUT_FILE_OUTPUT.has(tool) && !isWritingTool(tool)) {
    // An MCP server that runs a shell takes the command as an input field, and
    // an IDE bridge takes code the same way. Only `Bash` was read as a command,
    // so `mcp__desktop-commander__start_process` with `{"command":"cat .env"}`
    // was looked at as a path, found not to be a file, and let through — with
    // the default matcher sending every `mcp__*` tool here.
    for (const [key, value] of Object.entries(input)) {
      if (typeof value !== "string") continue;
      if (!COMMAND_FIELD_NAMES.has(key.toLowerCase().replace(/[-_]/g, ""))) {
        continue;
      }
      const refs = extractCommandRefs(value);
      // Code is not a command line: `print(open("secrets").read())` has no
      // command in it this can classify, and the path is a quoted literal — the
      // same shape inline `-c` text is read for.
      refs.paths.push(...extractQuotedLiterals(value));
      for (const fp of refs.paths) {
        for (const candidate of expandCandidate(fp)) {
          scanIfRegularFile(candidate, allowTags);
        }
      }
    }

    for (const candidate of collectPathFields(input)) {
      scanIfRegularFile(candidate, allowTags);
    }
  }

  process.exit(0);
});

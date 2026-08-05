#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import {
  applyAllowTags,
  dedupeFindings,
  findingsToLines,
  type Message,
  parseAllowTags,
  randomBird,
} from "./lib/inspector.ts";
import { enabledCategoriesFromEnv, type Finding, scan } from "./lib/rules.ts";

interface HookInput {
  transcript_path?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown> & {
    file_path?: string;
    command?: string;
    path?: string;
  };
}

interface TranscriptLine {
  message?: Message;
}

// ── Constants ─────────────────────────────────────────────────────────────────

// Maximum bytes to read from the tail of a transcript file.
const MAX_TRANSCRIPT_TAIL_BYTES = 65_536; // 64 KB

const ENABLED_CATEGORIES = enabledCategoriesFromEnv();

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

// ── Bash helpers ──────────────────────────────────────────────────────────────

// Commands that write the contents of every non-flag argument to stdout.
// `wc` is deliberately absent: it reports counts, never the bytes themselves.
const FILE_READ_COMMANDS = new Set([
  "cat",
  "head",
  "tail",
  "less",
  "more",
  "bat",
  "nl",
  "tac",
  "rev",
  "strings",
  "xxd",
  "od",
  "hexdump",
  "base64",
  "cut",
  "sort",
  "uniq",
  "shuf",
  "column",
  "paste",
  "fold",
  "fmt",
  "pr",
  "expand",
  "unexpand",
  "iconv",
  "zcat",
  "gzcat",
  "bzcat",
  "xzcat",
  "zstdcat",
  "diff",
  "comm",
  "join",
  "look",
]);

// Commands whose first non-flag argument is a pattern, expression or script,
// and whose remaining non-flag arguments are files written to stdout.
const PATTERN_FIRST_READ_COMMANDS = new Set([
  "sed",
  "awk",
  "gawk",
  "grep",
  "egrep",
  "fgrep",
  "rg",
  "ag",
  "jq",
  "yq",
  "perl",
  "ruby",
  "python",
  "python3",
  "node",
  "deno",
  "bun",
]);

// Commands that run another command. They are stripped so the wrapped command
// is classified instead: `sudo cat secrets` is treated as `cat secrets`.
const WRAPPER_COMMANDS = new Set([
  "sudo",
  "doas",
  "command",
  "builtin",
  "exec",
  "nohup",
  "time",
  "nice",
  "ionice",
  "stdbuf",
  "xargs",
  "env",
]);

// Wrappers that take one operand of their own before the wrapped command
// (`timeout 5 cat f`, `flock /tmp/lock cat f`).
const WRAPPER_COMMANDS_WITH_OPERAND = new Set(["timeout", "flock"]);

// Interpreters that accept inline program text, which is scanned both as a
// nested command line and for quoted path literals.
const INLINE_CODE_COMMANDS = new Set([
  "sh",
  "bash",
  "zsh",
  "dash",
  "ksh",
  "python",
  "python3",
  "perl",
  "ruby",
  "node",
  "deno",
  "bun",
  "php",
]);

const POSIX_SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh"]);

// git subcommands that can write file contents to stdout. Blob references such
// as `git show HEAD:.env` name history, not the working tree, and stay
// uncovered — only paths that exist on disk are scanned.
const GIT_READ_SUBCOMMANDS = new Set([
  "show",
  "diff",
  "log",
  "blame",
  "annotate",
  "grep",
  "cat-file",
  "difftool",
  "stash",
]);

// Recursion limit for command substitutions and inline scripts.
const MAX_NESTING_DEPTH = 4;

// References a single Bash command makes to data the hook can inspect.
interface CommandRefs {
  // File paths whose contents the command may write to stdout.
  paths: string[];
  // Environment variables the command names explicitly.
  envVars: string[];
  // Whether the command dumps the whole environment (bare `env` / `printenv`).
  dumpsEnvironment: boolean;
}

// Variable names referenced by the command, including expansion forms that carry
// a suffix such as `${TOKEN:-fallback}` or `${TOKEN#prefix}`.
function extractEnvVarNames(command: string): string[] {
  const names = new Set<string>();
  const re = /\$\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}|\$([A-Za-z_][A-Za-z0-9_]*)/g;
  for (const match of command.matchAll(re)) {
    const name = match[1] ?? match[2];
    if (name) names.add(name);
  }
  return [...names];
}

// Split a command line into segments (at |, ;, &, &&, || and newlines) and each
// segment into tokens with quotes removed. Redirection operators become tokens of
// their own so that `wc -l <f` and `wc -l < f` tokenize alike. Substitutions are
// left in place; extractSubstitutions handles them against the raw string.
function tokenizeCommand(command: string): string[][] {
  const segments: string[][] = [];
  let tokens: string[] = [];
  let current = "";
  let hasCurrent = false;
  let i = 0;

  const endToken = (): void => {
    if (hasCurrent) {
      tokens.push(current);
      current = "";
      hasCurrent = false;
    }
  };
  const endSegment = (): void => {
    endToken();
    if (tokens.length > 0) segments.push(tokens);
    tokens = [];
  };

  while (i < command.length) {
    const ch = command[i] as string;

    if (ch === "\\") {
      const next = command[i + 1];
      if (next !== undefined && next !== "\n") {
        current += next;
        hasCurrent = true;
      }
      i += next === undefined ? 1 : 2;
      continue;
    }

    if (ch === "'" || ch === '"') {
      i++;
      hasCurrent = true;
      while (i < command.length && command[i] !== ch) {
        if (ch === '"' && command[i] === "\\" && command[i + 1] !== undefined) {
          current += command[i + 1];
          i += 2;
          continue;
        }
        current += command[i];
        i++;
      }
      i++; // closing quote, or end of input for an unbalanced one
      continue;
    }

    if (ch === "|" || ch === ";" || ch === "&" || ch === "\n") {
      endSegment();
      while (i < command.length && /[|;&\n\s]/.test(command[i] as string)) i++;
      continue;
    }

    if (ch === "<" || ch === ">") {
      endToken();
      let op = ch;
      i++;
      while (i < command.length && command[i] === ch) {
        op += ch;
        i++;
      }
      tokens.push(op);
      continue;
    }

    if (ch === " " || ch === "\t" || ch === "\r") {
      endToken();
      i++;
      continue;
    }

    current += ch;
    hasCurrent = true;
    i++;
  }

  endSegment();
  return segments;
}

// Inner text of every command substitution, process substitution and backtick
// expression, innermost first. Each is a command line in its own right.
function extractSubstitutions(command: string): string[] {
  const found: string[] = [];
  let remaining = command;

  for (let pass = 0; pass < 8; pass++) {
    const before = remaining;
    remaining = remaining
      .replace(/\$\(([^()]*)\)/g, (_, inner: string) => {
        found.push(inner);
        return " ";
      })
      .replace(/<\(([^()]*)\)/g, (_, inner: string) => {
        found.push(inner);
        return " ";
      })
      .replace(/`([^`]*)`/g, (_, inner: string) => {
        found.push(inner);
        return " ";
      });
    if (remaining === before) break;
  }

  return found;
}

// Index of the token naming the command actually being run, after stripping
// wrappers such as `sudo`, `env VAR=1`, `timeout 5` and `xargs -0`.
function resolveCommandStart(tokens: string[]): number {
  let i = 0;

  while (i < tokens.length) {
    const name = path.basename(tokens[i] as string);

    if (WRAPPER_COMMANDS_WITH_OPERAND.has(name)) {
      i++;
      while (i < tokens.length && (tokens[i] as string).startsWith("-")) i++;
      i++; // the wrapper's own operand (duration, lock file)
      continue;
    }

    if (WRAPPER_COMMANDS.has(name)) {
      i++;
      while (i < tokens.length) {
        const next = tokens[i] as string;
        if (next.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(next)) {
          i++;
          continue;
        }
        break;
      }
      continue;
    }

    return i;
  }

  return tokens.length;
}

// True when `token` introduces inline program text for `cmd`. POSIX shells only
// take code after -c; other interpreters also use -e and combined forms (-pe).
function isInlineCodeFlag(cmd: string, token: string): boolean {
  if (token === "-c" || token === "--command" || token === "--eval")
    return true;
  if (POSIX_SHELLS.has(cmd)) return false;
  if (token === "-r") return true; // php -r
  return /^-[A-Za-z]*[eE]$/.test(token);
}

// Quoted literals inside inline program text — the ".env" in
// `python3 -c "print(open('.env').read())"`. Literals containing whitespace are
// skipped: those are messages and patterns, not paths.
function extractQuotedLiterals(code: string): string[] {
  const literals: string[] = [];
  for (const match of code.matchAll(/'([^']*)'|"([^"]*)"/g)) {
    const value = match[1] ?? match[2];
    if (value && value.length <= 4096 && !/\s/.test(value)) {
      literals.push(value);
    }
  }
  return literals;
}

// Everything a Bash command reveals that the hook can inspect before it runs:
// the files whose contents it may print, and the environment it may expose.
function extractCommandRefs(command: string, depth = 0): CommandRefs {
  const paths: string[] = [];
  const envVars: string[] = [];
  let dumpsEnvironment = false;

  if (depth > MAX_NESTING_DEPTH) return { paths, envVars, dumpsEnvironment };

  const merge = (refs: CommandRefs): void => {
    paths.push(...refs.paths);
    envVars.push(...refs.envVars);
    dumpsEnvironment = dumpsEnvironment || refs.dumpsEnvironment;
  };

  // `echo $(cat secrets)` reads secrets just as `cat secrets` does.
  for (const inner of extractSubstitutions(command)) {
    merge(extractCommandRefs(inner, depth + 1));
  }

  for (const tokens of tokenizeCommand(command)) {
    // `env` and `printenv` with no command to run print the environment itself.
    const leadName = path.basename(tokens[0] as string);
    if (leadName === "env" || leadName === "printenv") {
      const named = tokens
        .slice(1)
        .filter(
          (t) => !t.startsWith("-") && !t.startsWith("<") && !t.startsWith(">"),
        );
      const assignments = named.filter((t) =>
        /^[A-Za-z_][A-Za-z0-9_]*=/.test(t),
      );
      const rest = named.filter((t) => !assignments.includes(t));
      if (
        rest.length === 0 &&
        (leadName === "printenv" || !assignments.length)
      ) {
        dumpsEnvironment = true;
      } else if (leadName === "printenv") {
        envVars.push(...rest);
      }
    }

    const start = resolveCommandStart(tokens);
    const cmdToken = tokens[start];
    if (cmdToken === undefined) continue;

    const cmd = path.basename(cmdToken);
    const operands = tokens.slice(start + 1);

    // `sed -i` edits in place and writes nothing to stdout.
    if (
      cmd === "sed" &&
      operands.some((t) => /^-i/.test(t) || t === "--in-place")
    ) {
      continue;
    }

    const isFileReadCmd = FILE_READ_COMMANDS.has(cmd);
    const isPatternFirst = PATTERN_FIRST_READ_COMMANDS.has(cmd);
    const isInlineCodeCmd = INLINE_CODE_COMMANDS.has(cmd);
    const isGit = cmd === "git";

    let skipNext = false;
    let collectNext = false;
    let codeNext = false;
    let patternSkipped = false;
    let gitSubcommandSeen = false;
    let gitReadsFiles = false;

    for (const tok of operands) {
      if (skipNext) {
        skipNext = false;
        continue;
      }
      if (collectNext) {
        collectNext = false;
        paths.push(tok);
        continue;
      }
      if (codeNext) {
        codeNext = false;
        // The expression came from -e/-c, so a later operand is a file, not the
        // script `perl file` would have run.
        patternSkipped = true;
        merge(extractCommandRefs(tok, depth + 1));
        paths.push(...extractQuotedLiterals(tok));
        continue;
      }

      if (tok === "<") {
        collectNext = true; // stdin is fed from the next token
        continue;
      }
      if (tok.startsWith("<")) {
        skipNext = true; // heredoc / herestring delimiter, not a path
        continue;
      }
      if (tok.startsWith(">")) {
        skipNext = true; // output target, never read
        continue;
      }

      if (isInlineCodeCmd && isInlineCodeFlag(cmd, tok)) {
        codeNext = true;
        continue;
      }

      if (tok.startsWith("-")) continue;

      if (isGit) {
        if (!gitSubcommandSeen) {
          gitSubcommandSeen = true;
          gitReadsFiles = GIT_READ_SUBCOMMANDS.has(tok);
          continue;
        }
        if (gitReadsFiles) paths.push(tok);
        continue;
      }

      const ddInput = /^if=(.+)$/.exec(tok);
      if (ddInput?.[1]) {
        paths.push(ddInput[1]);
        continue;
      }

      if (isPatternFirst && !patternSkipped) {
        patternSkipped = true; // the pattern, expression or script name
        continue;
      }

      if (isFileReadCmd || isPatternFirst) paths.push(tok);
    }
  }

  return {
    paths: [...new Set(paths)],
    envVars: [...new Set(envVars)],
    dumpsEnvironment,
  };
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
    process.stderr.write(terminalMessage);
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

  process.stdout.write(
    `${JSON.stringify({
      decision: "block",
      reason: reasonLines.join("\n"),
    })}\n`,
  );
  process.exit(2);
}

// ── Tool input inspection ─────────────────────────────────────────────────────

// Tools that never surface the contents of a file they name. Scanning these
// would block writing to a file that already holds a secret, which is not a leak.
const TOOLS_WITHOUT_FILE_OUTPUT = new Set([
  "Write",
  "Edit",
  "MultiEdit",
  "NotebookEdit",
  "TodoWrite",
  "Glob",
  "WebFetch",
  "WebSearch",
  "ExitPlanMode",
  "AskUserQuestion",
]);

// Input field names that commonly carry a filesystem path.
const PATH_FIELD_NAMES = new Set([
  "file_path",
  "filePath",
  "path",
  "file",
  "filename",
  "fileName",
  "absolute_path",
  "notebook_path",
  "source",
  "src",
  "paths",
  "files",
]);

function collectPathFields(
  input: Record<string, unknown>,
  depth = 0,
): string[] {
  if (depth > 2) return [];
  const found: string[] = [];

  for (const [key, value] of Object.entries(input)) {
    if (typeof value === "string") {
      if (PATH_FIELD_NAMES.has(key)) found.push(value);
    } else if (Array.isArray(value)) {
      if (PATH_FIELD_NAMES.has(key)) {
        found.push(...value.filter((v): v is string => typeof v === "string"));
      }
    } else if (value !== null && typeof value === "object") {
      found.push(
        ...collectPathFields(value as Record<string, unknown>, depth + 1),
      );
    }
  }

  return found;
}

// ── Core scan logic ───────────────────────────────────────────────────────────

// Scan a candidate only when it names an existing regular file. Tools whose
// "path" means something else (a URL route, an object key) are left alone.
function scanIfRegularFile(
  candidate: string | undefined,
  allowTags: Set<string>,
): void {
  if (!candidate) return;
  try {
    if (!fs.statSync(candidate).isFile()) return;
  } catch {
    return;
  }
  scanFile(candidate, allowTags);
}

function scanFile(filePath: string, allowTags: Set<string>): void {
  if (shouldBlockEnvFile(filePath)) {
    if (allowTags.size > 0) return;
    block(
      filePath,
      [
        "🚫 Blocked: .env and .env.* files contain secrets and must not be read into the conversation.",
      ],
      buildAllowHints(`please read ${filePath}`, [], true),
    );
  }

  let content: string;
  try {
    const raw = fs.readFileSync(filePath);
    // Binary files: scan only the text prefix before the first NUL byte
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
  const input = data.tool_input ?? {};

  const allowTags = data.transcript_path
    ? loadAllowTagsFromTranscript(data.transcript_path)
    : new Set<string>();

  if (tool === "Read") {
    scanFile(input.file_path ?? "", allowTags);
    process.exit(0);
  }

  if (tool === "Bash") {
    const command = input.command ?? "";
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
        `bash command: ${command.slice(0, 80)}`,
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
        `bash command: ${command.slice(0, 80)}`,
        [
          "🚫 Blocked: bash command contains sensitive data",
          "",
          ...findingsToLines(cmdFindings),
        ],
        buildAllowHints("please run the command", cmdFindings),
      );
    }

    for (const fp of refs.paths) {
      scanFile(fp, allowTags);
    }

    process.exit(0);
  }

  if (tool === "Grep") {
    scanIfRegularFile(input.path, allowTags);
    process.exit(0);
  }

  // Any other tool, MCP tools included: those can return file contents the same
  // way Read does, so a field naming an existing file is scanned before the call.
  if (!TOOLS_WITHOUT_FILE_OUTPUT.has(tool)) {
    for (const candidate of collectPathFields(input)) {
      scanIfRegularFile(candidate, allowTags);
    }
  }

  process.exit(0);
});

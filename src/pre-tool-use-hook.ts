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

// Commands that read a file but report only measurements of it. Their stdin is
// not echoed either, so a redirection into one of them is not a read.
const COUNT_ONLY_COMMANDS = new Set([
  "wc",
  "cksum",
  "md5sum",
  "sha1sum",
  "sha256sum",
]);

// Commands whose first non-flag argument is a pattern, expression or script,
// and whose remaining non-flag arguments are files written to stdout.
// General-purpose runtimes (`python`, `node`, `deno`, `bun`) are absent: they
// execute their first argument rather than print it, and the files named after
// it are argv, not output. Their inline code (`-c`, `-e`) is still scanned via
// INLINE_CODE_COMMANDS.
const PATTERN_OR_SCRIPT_FIRST_COMMANDS = new Set([
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
// uncovered — only paths that exist on disk are scanned. `difftool` hands off
// to an external tool and `stash` prints no file contents, so neither is here:
// classifying them would push tokens like the `pop` in `git stash pop` as paths.
const GIT_READ_SUBCOMMANDS = new Set([
  "show",
  "diff",
  "log",
  "blame",
  "annotate",
  "grep",
  "cat-file",
]);

// Global git flags that carry a separate value before the subcommand
// (`git -C repo show f`, `git -c k=v show f`). Attached forms (`--git-dir=x`)
// are single flag tokens and need no entry here.
const GIT_GLOBAL_FLAGS_WITH_OPERAND = new Set([
  "-C",
  "-c",
  "--git-dir",
  "--work-tree",
  "--namespace",
  "--exec-path",
  "--config-env",
]);

// Recursion limit for command substitutions and inline scripts. Nesting costs
// one level per substitution, so `$( $( … ) )` is followed four deep.
const MAX_NESTING_DEPTH = 4;

// Longest quoted literal inside inline code still treated as a path candidate.
const MAX_QUOTED_LITERAL_LENGTH = 4096;

// Depth to which a tool's input object is searched for path-bearing fields.
const MAX_PATH_FIELD_DEPTH = 2;

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

    if (
      ch === "'" ||
      ch === '"' ||
      (ch === "$" && (command[i + 1] === "'" || command[i + 1] === '"'))
    ) {
      // $'...' (ANSI-C) and $"..." (locale) are quoting syntax: the `$` is not
      // part of the token. Inside $'...', backslash escapes are decoded.
      let quote = ch;
      let ansiC = false;
      if (ch === "$") {
        quote = command[i + 1] as string;
        ansiC = quote === "'";
        i += 2;
      } else {
        i++;
      }
      hasCurrent = true;
      while (i < command.length && command[i] !== quote) {
        if (command[i] === "\\" && command[i + 1] !== undefined) {
          if (quote === '"' || ansiC) {
            current += ansiC
              ? decodeAnsiCEscape(command, i)
              : (command[i + 1] as string);
            i += ansiC ? ansiCEscapeLength(command, i) : 2;
            continue;
          }
          // plain single quotes keep backslashes literal
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
      // A file-descriptor prefix belongs to the operator, not to a token of its
      // own: `env 2>err` has to tokenize like `env >err`, or the `2` reads as
      // env's subcommand and the environment dump goes unnoticed. The number
      // names neither a file nor a command, so it is dropped. Only digits
      // written against the operator count, leaving `sort 1 >out` alone.
      if (hasCurrent && /^\d+$/.test(current)) {
        current = "";
        hasCurrent = false;
      }
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

// Length of the ANSI-C escape starting at `command[i]` (a backslash), so the
// tokenizer can skip the whole sequence: \xHH is 4 chars, anything else is 2.
function ansiCEscapeLength(command: string, i: number): number {
  return command[i + 1] === "x" &&
    /^[0-9A-Fa-f]{2}$/.test(command.slice(i + 2, i + 4))
    ? 4
    : 2;
}

// Decode the ANSI-C escape starting at `command[i]` (a backslash). Covers the
// escapes that appear in paths: \\, \', \", \xHH and the common letter escapes.
function decodeAnsiCEscape(command: string, i: number): string {
  const esc = command[i + 1] as string;
  if (esc === "x" && /^[0-9A-Fa-f]{2}$/.test(command.slice(i + 2, i + 4))) {
    return String.fromCharCode(
      Number.parseInt(command.slice(i + 2, i + 4), 16),
    );
  }
  const simple: Record<string, string> = {
    "\\": "\\",
    "'": "'",
    '"': '"',
    n: "\n",
    t: "\t",
    r: "\r",
    "0": "\0",
  };
  return simple[esc] ?? esc;
}

// One heredoc delimiter introduced by a command line. `allowTabs` marks the
// `<<-` form, whose closing delimiter may be tab-indented.
interface HeredocDelimiter {
  delim: string;
  allowTabs: boolean;
}

// The delimiter word starting at `line[from]`, with quote removal applied the way
// the shell does it: `<<EOF`, `<<'EOF'`, `<<"EOF"` and `<<E"O"F` all end their
// body at the line `EOF`. The word ends at whitespace or a shell metacharacter.
//
// A narrower character class (`[A-Za-z0-9_.]`) used to cut the word short, and the
// truncated delimiter then never matched the real closing line: stripHeredocBodies
// swallowed the rest of the command, so `cat > f <<EOF-1 … EOF-1` followed by
// `cat .env` hid the read entirely.
function readHeredocDelimiter(
  line: string,
  from: number,
): { delim: string; next: number } {
  let delim = "";
  let i = from;

  while (i < line.length) {
    const ch = line[i] as string;
    if (ch === "'" || ch === '"') {
      i++;
      while (i < line.length && line[i] !== ch) {
        if (ch === '"' && line[i] === "\\" && line[i + 1] !== undefined) {
          delim += line[i + 1];
          i += 2;
          continue;
        }
        delim += line[i];
        i++;
      }
      i++; // closing quote, or end of line for an unbalanced one
      continue;
    }
    if (ch === "\\" && line[i + 1] !== undefined) {
      delim += line[i + 1];
      i += 2;
      continue;
    }
    if (/[\s|&;()<>`]/.test(ch)) break;
    delim += ch;
    i++;
  }

  return { delim, next: i };
}

// Heredoc delimiters introduced by one command line, in order. `<<-` allows a
// tab-indented closing delimiter; `<<<` is a herestring and is not a heredoc.
// Matches outside quotes only, so `echo "a <<EOF b"` is not a heredoc start.
function findHeredocDelimiters(line: string): HeredocDelimiter[] {
  const found: HeredocDelimiter[] = [];
  let quote: string | null = null;
  let i = 0;

  while (i < line.length) {
    const ch = line[i] as string;
    if (quote !== null) {
      if (quote === '"' && ch === "\\") i++;
      else if (ch === quote) quote = null;
      i++;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      i++;
      continue;
    }
    if (ch === "\\") {
      i += 2;
      continue;
    }
    if (ch === "<" && line[i + 1] === "<") {
      let j = i + 2;
      let allowTabs = false;
      if (line[j] === "-") {
        allowTabs = true;
        j++;
      }
      if (line[j] === "<") {
        i = j; // herestring
        continue;
      }
      while (line[j] === " " || line[j] === "\t") j++;
      const { delim, next } = readHeredocDelimiter(line, j);
      if (delim) found.push({ delim, allowTabs });
      i = next;
      continue;
    }
    i++;
  }

  return found;
}

// Remove heredoc bodies from a command line. A body is text, not commands —
// `cat > deploy.sh <<EOF` followed by a script that mentions `.env` reads
// nothing, and scanning the body as shell blocked exactly that everyday case.
// The trade-off: a heredoc that *feeds* commands to a remote shell
// (`ssh host <<EOF\ncat /secret\nEOF`) is no longer caught. Documented as a
// known limitation in the README.
function stripHeredocBodies(command: string): string {
  const lines = command.split("\n");
  const kept: string[] = [];
  const pending: HeredocDelimiter[] = [];

  for (const line of lines) {
    if (pending.length > 0) {
      const first = pending[0] as HeredocDelimiter;
      const cmp = first.allowTabs ? line.replace(/^\t+/, "") : line;
      if (cmp === first.delim) pending.shift();
      continue;
    }
    pending.push(...findHeredocDelimiters(line));
    kept.push(line);
  }

  return kept.join("\n");
}

// Substitution syntaxes whose inner text is a command line in its own right.
// Command substitution and backticks expand inside double quotes; the process
// substitutions do not, so `echo "<(cat f)"` is a literal string.
const SUBSTITUTIONS = [
  { open: "$(", close: ")", expandsInDoubleQuotes: true },
  { open: "<(", close: ")", expandsInDoubleQuotes: false },
  { open: ">(", close: ")", expandsInDoubleQuotes: false },
  { open: "`", close: "`", expandsInDoubleQuotes: true },
];

// Index of the character closing a substitution whose body starts at `from`.
// Parentheses are counted rather than matched with a regex, because a body
// carries parentheses of its own: `$(python3 -c "print(open('.env').read())")`
// was cut short at the first `)` by the old `[^()]*` pattern, and the read it
// contained was never scanned. Quotes and backslashes inside the body are
// respected. An unbalanced substitution runs to the end of the string.
function findSubstitutionEnd(
  command: string,
  from: number,
  close: string,
): number {
  let depth = 0;
  let quote: string | null = null;

  for (let i = from; i < command.length; i++) {
    const ch = command[i] as string;
    if (ch === "\\" && quote !== "'") {
      i++;
      continue;
    }
    if (quote !== null) {
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (close === "`") {
      if (ch === "`") return i;
      continue;
    }
    if (ch === "(") depth++;
    else if (ch === ")") {
      if (depth === 0) return i;
      depth--;
    }
  }

  return command.length;
}

// Inner text of every outermost command substitution, process substitution and
// backtick expression. Each is a command line in its own right; nested ones are
// reached because extractCommandRefs recurses into what this returns.
function extractSubstitutions(command: string): string[] {
  const found: string[] = [];
  let quote: string | null = null;
  let i = 0;

  while (i < command.length) {
    const ch = command[i] as string;

    if (ch === "\\") {
      i += quote === "'" ? 1 : 2;
      continue;
    }
    if (quote === "'") {
      if (ch === quote) quote = null;
      i++;
      continue;
    }
    if (quote === '"' && ch === '"') {
      quote = null;
      i++;
      continue;
    }
    if (quote === null && (ch === "'" || ch === '"')) {
      quote = ch;
      i++;
      continue;
    }

    const opener = SUBSTITUTIONS.find(
      (s) =>
        command.startsWith(s.open, i) &&
        (quote === null || s.expandsInDoubleQuotes),
    );
    if (opener === undefined) {
      i++;
      continue;
    }

    const bodyStart = i + opener.open.length;
    const end = findSubstitutionEnd(command, bodyStart, opener.close);
    found.push(command.slice(bodyStart, end));
    i = end + 1;
  }

  return found;
}

// True for a redirection operator token: `<`, `>`, `<<`, `>>`, `<<<`. The
// tokenizer emits each on its own, with any file-descriptor prefix dropped, and
// the token after one is a target or a heredoc delimiter rather than an operand.
function isRedirectionOperator(token: string): boolean {
  return /^[<>]+$/.test(token);
}

// True for a token that cannot name a command: a flag, a redirection operator,
// or a `VAR=value` assignment placed before one.
function isNonCommandToken(token: string): boolean {
  if (token.startsWith("-") || token.startsWith("<") || token.startsWith(">")) {
    return true;
  }
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(token);
}

// Commands whose operands this hook knows how to interpret. Derived from
// classifyCommand so the two cannot silently disagree. `env` and `printenv`
// are absent on purpose: they are wrappers as often as they are commands, and
// inspectEnvironmentCommand handles the cases where they print the environment.
function isClassifiableCommand(name: string): boolean {
  const b = classifyCommand(name);
  return (
    b.printsOperands ||
    b.firstOperandIsPatternOrScript ||
    b.takesInlineCode ||
    b.printsNothing ||
    b.isGit ||
    b.isDd
  );
}

// Commands a wrapper may hand off to. Beyond the classifiable ones, `env` and
// `printenv` count here — and only here — so wrapper operands do not hide an
// environment dump: `sudo -u root printenv` must still find printenv.
function isWrapperTarget(name: string): boolean {
  return isClassifiableCommand(name) || name === "env" || name === "printenv";
}

// Index of the token naming the command whose operands matter.
//
// The lead command is the first token that is not a flag, redirection or
// `VAR=value` assignment. Only a known wrapper (`sudo`, `env`, `timeout`, …)
// is peeled, by searching the rest of the segment for the first token this
// hook can classify (`env` and `printenv` included, so their detection behind
// wrapper operands works); anything else is treated as the command itself. Searching
// unconditionally mistook operands for commands: `echo cat secrets` resolved
// to `cat`, and a file that was never read was scanned and blocked. Wrappers
// are still not peeled by counting their flags: `sudo -u root cat f` would
// mistake `root` for the command, and `timeout -s KILL 5 cat f` would
// mistake `5`. Falling back to the lead leaves an unknown command classified
// as itself.
function findCommandIndex(tokens: string[]): number {
  let lead = -1;
  for (let i = 0; i < tokens.length; i++) {
    if (isNonCommandToken(tokens[i] ?? "")) continue;
    lead = i;
    break;
  }
  if (lead === -1) return 0;

  const leadName = path.basename(tokens[lead] ?? "");
  if (
    !WRAPPER_COMMANDS.has(leadName) &&
    !WRAPPER_COMMANDS_WITH_OPERAND.has(leadName)
  ) {
    return lead;
  }

  for (let i = lead + 1; i < tokens.length; i++) {
    const tok = tokens[i] ?? "";
    if (isNonCommandToken(tok)) continue;
    if (isWrapperTarget(path.basename(tok))) return i;
  }
  return lead;
}

// `env` and `printenv` print the environment unless they are being used to run
// another command. `sudo printenv` counts; `env FOO=1 cat f` does not. The
// command is located with findCommandIndex, so wrapper flags and operands
// (`sudo -u root printenv`, `timeout 5 env`) cannot hide it.
function inspectEnvironmentCommand(tokens: string[]): {
  dumps: boolean;
  named: string[];
} {
  const nothing = { dumps: false, named: [] };

  const start = findCommandIndex(tokens);
  const cmdToken = tokens[start];
  if (cmdToken === undefined) return nothing;

  const name = path.basename(cmdToken);
  if (name !== "env" && name !== "printenv") return nothing;

  // `printenv` prints the whole environment unless it is given variables to
  // print. A redirection target is not one of them: `printenv > out.txt` prints
  // everything, and counting `out.txt` as a named variable left the environment
  // unscanned.
  if (name === "printenv") {
    const rest = tokens.slice(start + 1);
    const named: string[] = [];
    for (let j = 0; j < rest.length; j++) {
      const t = rest[j] ?? "";
      if (isRedirectionOperator(t)) {
        j++; // its target, or a heredoc delimiter
        continue;
      }
      if (isNonCommandToken(t)) continue; // flags
      named.push(t);
    }
    return named.length === 0
      ? { dumps: true, named: [] }
      : { dumps: false, named };
  }

  // `env` prints the environment unless a subcommand follows its own
  // arguments: assignments (`FOO=1`), flags, and the values of flags that
  // take one (`-u FOO`, `-C dir`) are all env's own. The `-S` split string
  // is the subcommand itself (`env -S "cat f"` runs cat), so it rules a dump
  // out. With no subcommand the whole environment is printed — `env FOO=1`
  // and `env -u FOO` included. Exception: `-i` starts from an empty
  // environment, so only the given assignments (already scanned as command
  // text) print.
  const rest = tokens.slice(start + 1);
  let ignoreEnvironment = false;
  let hasCommand = false;
  for (let j = 0; j < rest.length; j++) {
    const t = rest[j] ?? "";
    if (t === "-i" || t === "--ignore-environment") {
      ignoreEnvironment = true;
      continue;
    }
    if (isRedirectionOperator(t)) {
      j++; // redirection operator: its target is env's own argument here
      continue;
    }
    if (t === "-u" || t === "--unset" || t === "-C" || t === "--chdir") {
      j++; // flag value
      continue;
    }
    if (t === "-S" || t === "--split-string") {
      hasCommand = true; // the split string is the subcommand
      break;
    }
    if (isNonCommandToken(t)) continue; // flags and FOO=1 assignments
    hasCommand = true;
    break;
  }
  return { dumps: !hasCommand && !ignoreEnvironment, named: [] };
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
// `python3 -c "print(open('.env').read())"`. Literals containing line breaks or
// tabs are skipped: those are messages and patterns, not paths. Spaces are
// kept, so a path like `open('my secret.txt')` is still found.
function extractQuotedLiterals(code: string): string[] {
  const literals: string[] = [];
  for (const match of code.matchAll(/'([^']*)'|"([^"]*)"/g)) {
    const value = match[1] ?? match[2];
    if (
      value &&
      value.length <= MAX_QUOTED_LITERAL_LENGTH &&
      !/[\t\r\n]/.test(value)
    ) {
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

  // Heredoc bodies are text, not commands; strip them before any other pass.
  const text = stripHeredocBodies(command);

  // `echo $(cat secrets)` reads secrets just as `cat secrets` does.
  for (const inner of extractSubstitutions(text)) {
    merge(extractCommandRefs(inner, depth + 1));
  }

  for (const tokens of tokenizeCommand(text)) {
    const environment = inspectEnvironmentCommand(tokens);
    if (environment.dumps) dumpsEnvironment = true;
    envVars.push(...environment.named);

    merge(collectSegmentRefs(tokens, depth));
  }

  return {
    paths: [...new Set(paths)],
    envVars: [...new Set(envVars)],
    dumpsEnvironment,
  };
}

// What this hook knows about how a command treats its operands.
interface CommandBehaviour {
  // Every non-flag operand is a file written to stdout.
  printsOperands: boolean;
  // The first non-flag operand is a pattern or script name, the rest are files.
  firstOperandIsPatternOrScript: boolean;
  // -c / -e introduce inline program text.
  takesInlineCode: boolean;
  // Reads a file but prints only a measurement of it, and does not echo stdin.
  printsNothing: boolean;
  // `git <subcommand> [paths]`.
  isGit: boolean;
  // `dd if=<file>` names its input in an assignment-style operand.
  isDd: boolean;
}

// Single place where a command name becomes a behaviour, so a name added to one
// list cannot silently disagree with another.
function classifyCommand(cmd: string): CommandBehaviour {
  return {
    printsOperands: FILE_READ_COMMANDS.has(cmd),
    firstOperandIsPatternOrScript: PATTERN_OR_SCRIPT_FIRST_COMMANDS.has(cmd),
    takesInlineCode: INLINE_CODE_COMMANDS.has(cmd),
    printsNothing: COUNT_ONLY_COMMANDS.has(cmd),
    isGit: cmd === "git",
    isDd: cmd === "dd",
  };
}

// File paths one segment of a command line may print, plus anything found inside
// inline program text it carries.
function collectSegmentRefs(tokens: string[], depth: number): CommandRefs {
  const paths: string[] = [];
  const envVars: string[] = [];
  let dumpsEnvironment = false;

  const start = findCommandIndex(tokens);
  const cmdToken = tokens[start];
  if (cmdToken === undefined) return { paths, envVars, dumpsEnvironment };

  const cmd = path.basename(cmdToken);
  const operands = tokens.slice(start + 1);

  // `sed -i` edits in place and writes nothing to stdout.
  if (
    cmd === "sed" &&
    operands.some((t) => /^-i/.test(t) || t === "--in-place")
  ) {
    return { paths, envVars, dumpsEnvironment };
  }

  // `env -S "cmd args"` splits the string into the command it runs, so scan
  // inside it the way inline code is scanned.
  if (cmd === "env") {
    for (let k = 0; k < operands.length; k++) {
      const t = operands[k];
      if (t !== "-S" && t !== "--split-string") continue;
      const script = operands[k + 1];
      if (script === undefined) continue;
      const inner = extractCommandRefs(script, depth + 1);
      paths.push(...inner.paths);
      envVars.push(...inner.envVars);
      dumpsEnvironment = dumpsEnvironment || inner.dumpsEnvironment;
      k++;
    }
  }

  const behaviour = classifyCommand(cmd);

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
      const inner = extractCommandRefs(tok, depth + 1);
      paths.push(...inner.paths, ...extractQuotedLiterals(tok));
      envVars.push(...inner.envVars);
      dumpsEnvironment = dumpsEnvironment || inner.dumpsEnvironment;
      continue;
    }

    if (tok === "<") {
      // stdin is fed from the next token, unless nothing of it is printed
      collectNext = !behaviour.printsNothing;
      skipNext = behaviour.printsNothing;
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

    if (behaviour.takesInlineCode && isInlineCodeFlag(cmd, tok)) {
      codeNext = true;
      continue;
    }

    if (tok.startsWith("-")) {
      // A global git flag with a separate value consumes the next token too:
      // in `git -C repo show f`, `repo` is not the subcommand.
      if (
        behaviour.isGit &&
        !gitSubcommandSeen &&
        GIT_GLOBAL_FLAGS_WITH_OPERAND.has(tok)
      ) {
        skipNext = true;
      }
      continue;
    }

    if (behaviour.isGit) {
      if (!gitSubcommandSeen) {
        gitSubcommandSeen = true;
        gitReadsFiles = GIT_READ_SUBCOMMANDS.has(tok);
        continue;
      }
      if (gitReadsFiles) paths.push(tok);
      continue;
    }

    // `if=<file>` names an input only for `dd`; other commands taking an
    // `if=` argument are not reading the file it names.
    if (behaviour.isDd) {
      const ddInput = /^if=(.+)$/.exec(tok);
      if (ddInput?.[1]) {
        paths.push(ddInput[1]);
        continue;
      }
    }

    if (behaviour.firstOperandIsPatternOrScript && !patternSkipped) {
      patternSkipped = true; // the pattern, expression or script name
      continue;
    }

    if (behaviour.printsOperands || behaviour.firstOperandIsPatternOrScript) {
      paths.push(tok);
    }
  }

  return { paths, envVars, dumpsEnvironment };
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

// A tool whose name says it writes is treated like the built-in Write and Edit:
// naming a file it does not read is not a leak. Matched on the tool name because
// an MCP tool's semantics are not otherwise knowable from its input. For MCP
// tools (`mcp__<server>__<tool>`) only the tool component is matched — a server
// named "editor" or "readwrite" must not exempt every read tool it offers.
const WRITING_TOOL_NAME =
  /(write|create|edit|update|append|delete|remove|move|rename|mkdir|copy)/i;

function isWritingTool(tool: string): boolean {
  const name = tool.startsWith("mcp__")
    ? (tool.split("__").pop() ?? tool)
    : tool;
  return WRITING_TOOL_NAME.test(name);
}

// Input field names that commonly carry a filesystem path.
const PATH_FIELD_NAMES = new Set([
  "file_path",
  "filePath",
  "path",
  "paths",
  "file",
  "absolute_path",
  "notebook_path",
]);

function collectPathFields(
  input: Record<string, unknown>,
  depth = 0,
): string[] {
  if (depth > MAX_PATH_FIELD_DEPTH) return [];
  const found: string[] = [];

  for (const [key, value] of Object.entries(input)) {
    if (typeof value === "string") {
      if (PATH_FIELD_NAMES.has(key)) found.push(value);
    } else if (Array.isArray(value)) {
      if (PATH_FIELD_NAMES.has(key)) {
        found.push(...value.filter((v): v is string => typeof v === "string"));
      }
      // Paths also arrive as objects inside an array, e.g.
      // `{ paths: [{ path: "…" }] }` — recurse into those elements too.
      for (const item of value) {
        if (item !== null && typeof item === "object" && !Array.isArray(item)) {
          found.push(
            ...collectPathFields(item as Record<string, unknown>, depth + 1),
          );
        }
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
  if (!TOOLS_WITHOUT_FILE_OUTPUT.has(tool) && !isWritingTool(tool)) {
    for (const candidate of collectPathFields(input)) {
      scanIfRegularFile(candidate, allowTags);
    }
  }

  process.exit(0);
});

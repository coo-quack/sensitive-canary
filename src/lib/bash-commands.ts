// What this hook knows about how each command treats its operands.
//
// The tables are the knowledge: which commands print a file they are handed,
// which take a pattern first, which run another command. extractCommandRefs
// turns a command line into the files it may print and the environment it may
// expose, leaving the parsing to shell.ts.

import path from "node:path";
import {
  extractQuotedLiterals,
  extractSubstitutions,
  isNonCommandToken,
  isRedirectionOperator,
  type ShellToken,
  stripHeredocBodies,
  tokenizeCommand,
} from "./shell.ts";

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
// General-purpose runtimes (`python`, `node`, `deno`, `bun`, and `perl` and
// `ruby` when they run a program file) are absent: they execute their first
// argument rather than print it, and the files named after it are argv, not
// output. Their inline code (`-c`, `-e`) is still scanned via
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
]);

// Flags that hand a pattern-first command its pattern or script, so no operand
// is standing in for it. Without this, `grep --regexp=aws secrets` and
// `sed --expression='s/a/b/' secrets` consumed the file as the pattern and never
// scanned it. The separate-value forms name a pattern or a pattern file, neither
// of which is printed, so their value is skipped rather than collected.
const PATTERN_SUPPLYING_FLAGS = new Set([
  "-e",
  "--regexp",
  "--expression",
  "-f",
  "--file",
  "--from-file",
]);

// Flags of a read command whose separate value names a file to write, not one to
// read: `sort -o out.txt in.txt` prints nothing of `out.txt`, and scanning it
// blocked a command that only ever writes there.
//
// Keyed per command rather than by flag name, because the same letter means
// different things: `-o` is an output file for these three but an octal-format
// flag taking no value for `od` and `hexdump`, so a shared list would swallow
// the operand of `od -o secrets` and miss the read.
const WRITE_TARGET_FLAGS: Record<string, Set<string>> = {
  sort: new Set(["-o", "--output"]),
  shuf: new Set(["-o", "--output"]),
  iconv: new Set(["-o", "--output"]),
};

// Interpreters whose file operands are input to a one-liner given inline:
// `perl -pe 's/a/b/' f` and `ruby -pe '…' f` print f. Hand them a program file
// instead and the operands are argv — `perl script.pl data.txt` prints neither —
// so their operands count as reads only once inline code has been seen.
const INLINE_CODE_READS_OPERANDS = new Set(["perl", "ruby"]);

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
  "blame",
  "annotate",
  "grep",
  "cat-file",
]);

// `git log <file>` prints who changed the file and when, never a line of it, so
// it belongs with the subcommands above only when a patch is asked for. Treating
// it as a read unconditionally blocked an everyday way of looking at history.
//
// The flags are the ones that produce a diff: `-U<n>` and `--unified=<n>` imply
// `--patch`, and the merge-diff forms print one too. A flag not listed here
// leaves the file unscanned, so the list errs towards including anything that
// might print contents — `git -c k=v log f` matches `-c` and is scanned, which
// is the harmless direction to be wrong in.
function gitLogPrintsFileContents(operands: ShellToken[]): boolean {
  return operands.some(({ value }) => {
    if (value === "-p" || value === "-u" || value === "-c" || value === "-m") {
      return true;
    }
    return (
      value.startsWith("--patch") ||
      value.startsWith("-U") ||
      value.startsWith("--unified") ||
      value.startsWith("--cc") ||
      value.startsWith("--diff-merges")
    );
  });
}

// Whether a git subcommand writes the contents of the files named after it.
function gitSubcommandPrintsFiles(
  subcommand: string,
  operands: ShellToken[],
): boolean {
  if (subcommand === "log") return gitLogPrintsFileContents(operands);
  return GIT_READ_SUBCOMMANDS.has(subcommand);
}

// Commands whose `-i` rewrites the files it is handed instead of printing them.
// Not every `-i` means that: `grep -i` matches case-insensitively and still
// prints, which is why this is a list rather than a check on the flag alone.
// `perl` and `ruby` bundle their short flags, so the in-place flag arrives as
// `-pi` as often as `-i`, and `perl -i.bak` carries its backup suffix attached.
const IN_PLACE_EDIT_COMMANDS = new Set(["sed", "perl", "ruby"]);

function editsInPlace(cmd: string, operands: ShellToken[]): boolean {
  if (!IN_PLACE_EDIT_COMMANDS.has(cmd)) return false;
  return operands.some(
    ({ value }) => value === "--in-place" || /^-[A-Za-z]*i/.test(value),
  );
}

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

// Recursion limit for inline program text: each `-c` / `-e` script inside
// another costs one level. Nested command substitutions are not bounded by it,
// since the tokenizer ends a segment at a paren and reaches the inner command
// without recursing. `depth` counts nesting, so the command line itself is 0 and
// four levels of inline text below it are inspected.
const MAX_NESTING_DEPTH = 4;

// References a single Bash command makes to data the hook can inspect.
export interface CommandRefs {
  // File paths whose contents the command may write to stdout.
  paths: string[];
  // Environment variables the command names explicitly.
  envVars: string[];
  // Whether the command dumps the whole environment (bare `env` / `printenv`).
  dumpsEnvironment: boolean;
}

// What this hook knows about how a command treats its operands.
interface CommandBehaviour {
  // Every non-flag operand is a file written to stdout.
  printsOperands: boolean;
  // The first non-flag operand is a pattern or script name, the rest are files.
  firstOperandIsPatternOrScript: boolean;
  // -c / -e introduce inline program text.
  takesInlineCode: boolean;
  // Operands following inline program text are input files written to stdout.
  inlineCodeReadsOperands: boolean;
  // Reads a file but prints only a measurement of it, and does not echo stdin.
  printsNoFileContents: boolean;
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
    inlineCodeReadsOperands: INLINE_CODE_READS_OPERANDS.has(cmd),
    printsNoFileContents: COUNT_ONLY_COMMANDS.has(cmd),
    isGit: cmd === "git",
    isDd: cmd === "dd",
  };
}

// Commands whose operands this hook knows how to interpret. Derived from
// classifyCommand so the two cannot silently disagree. `env` and `printenv`
// are absent on purpose: they are wrappers as often as they are commands, and
// inspectEnvironmentCommand handles the cases where they print the environment.
function isClassifiableCommand(name: string): boolean {
  const behaviour = classifyCommand(name);
  // Any behaviour at all means the operands are understood. Read from the object
  // rather than listed field by field, so adding a field cannot leave this
  // function silently disagreeing with classifyCommand.
  return Object.values(behaviour).some(Boolean);
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
function findCommandIndex(tokens: ShellToken[]): number {
  let lead = -1;
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token === undefined || isNonCommandToken(token)) continue;
    lead = i;
    break;
  }
  if (lead === -1) return 0;

  const leadName = path.basename(tokens[lead]?.value ?? "");
  if (
    !WRAPPER_COMMANDS.has(leadName) &&
    !WRAPPER_COMMANDS_WITH_OPERAND.has(leadName)
  ) {
    return lead;
  }

  for (let i = lead + 1; i < tokens.length; i++) {
    const tok = tokens[i];
    if (tok === undefined || isNonCommandToken(tok)) continue;
    if (isWrapperTarget(path.basename(tok.value))) return i;
  }
  return lead;
}

// `env` and `printenv` print the environment unless they are being used to run
// another command. `sudo printenv` counts; `env FOO=1 cat f` does not. The
// command is located with findCommandIndex, so wrapper flags and operands
// (`sudo -u root printenv`, `timeout 5 env`) cannot hide it.
function inspectEnvironmentCommand(tokens: ShellToken[]): {
  dumps: boolean;
  named: string[];
} {
  const nothing = { dumps: false, named: [] };

  const start = findCommandIndex(tokens);
  const cmdToken = tokens[start];
  if (cmdToken === undefined) return nothing;

  const name = path.basename(cmdToken.value);
  if (name !== "env" && name !== "printenv") return nothing;

  // `printenv` prints the whole environment unless it is given variables to
  // print. A redirection target is not one of them: `printenv > out.txt` prints
  // everything, and counting `out.txt` as a named variable left the environment
  // unscanned.
  if (name === "printenv") {
    const rest = tokens.slice(start + 1);
    const named: string[] = [];
    for (let j = 0; j < rest.length; j++) {
      const t = rest[j];
      if (t === undefined) continue;
      if (isRedirectionOperator(t)) {
        j++; // its target, or a heredoc delimiter
        continue;
      }
      if (isNonCommandToken(t)) continue; // flags
      named.push(t.value);
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
    const t = rest[j];
    if (t === undefined) continue;
    const value = t.value;
    if (value === "-i" || value === "--ignore-environment") {
      ignoreEnvironment = true;
      continue;
    }
    if (isRedirectionOperator(t)) {
      j++; // redirection operator: its target is env's own argument here
      continue;
    }
    if (
      value === "-u" ||
      value === "--unset" ||
      value === "-C" ||
      value === "--chdir"
    ) {
      j++; // flag value
      continue;
    }
    if (value === "-S" || value === "--split-string") {
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

// Everything a Bash command reveals that the hook can inspect before it runs:
// the files whose contents it may print, and the environment it may expose.
export function extractCommandRefs(command: string, depth = 0): CommandRefs {
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

// File paths one segment of a command line may print, plus anything found inside
// inline program text it carries.
function collectSegmentRefs(tokens: ShellToken[], depth: number): CommandRefs {
  const paths: string[] = [];
  const envVars: string[] = [];
  let dumpsEnvironment = false;

  const start = findCommandIndex(tokens);
  const cmdToken = tokens[start];
  if (cmdToken === undefined) return { paths, envVars, dumpsEnvironment };

  const cmd = path.basename(cmdToken.value);
  const operands = tokens.slice(start + 1);

  // In-place editing sends the result back to the file, so nothing reaches
  // stdout and nothing is read into the conversation.
  if (editsInPlace(cmd, operands)) {
    return { paths, envVars, dumpsEnvironment };
  }

  // `env -S "cmd args"` splits the string into the command it runs, so scan
  // inside it the way inline code is scanned.
  if (cmd === "env") {
    for (let k = 0; k < operands.length; k++) {
      const t = operands[k]?.value;
      if (t !== "-S" && t !== "--split-string") continue;
      const script = operands[k + 1]?.value;
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
  let inlineCodeSeen = false;
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
      paths.push(tok.value);
      continue;
    }
    if (codeNext) {
      codeNext = false;
      // The expression came from -e/-c, so a later operand is a file, not the
      // script `perl file` would have run.
      patternSkipped = true;
      if (behaviour.inlineCodeReadsOperands) inlineCodeSeen = true;
      const inner = extractCommandRefs(tok.value, depth + 1);
      paths.push(...inner.paths, ...extractQuotedLiterals(tok.value));
      envVars.push(...inner.envVars);
      dumpsEnvironment = dumpsEnvironment || inner.dumpsEnvironment;
      continue;
    }

    if (tok.redirect) {
      if (tok.value === "<") {
        // stdin is fed from the next token, unless nothing of it is printed
        collectNext = !behaviour.printsNoFileContents;
        skipNext = behaviour.printsNoFileContents;
      } else {
        // A heredoc or herestring delimiter, or an output target: never read.
        skipNext = true;
      }
      continue;
    }

    if (behaviour.takesInlineCode && isInlineCodeFlag(cmd, tok.value)) {
      codeNext = true;
      continue;
    }

    if (tok.value.startsWith("-")) {
      // A global git flag with a separate value consumes the next token too:
      // in `git -C repo show f`, `repo` is not the subcommand.
      if (
        behaviour.isGit &&
        !gitSubcommandSeen &&
        GIT_GLOBAL_FLAGS_WITH_OPERAND.has(tok.value)
      ) {
        skipNext = true;
      }

      // The value of an output flag is written, not read.
      if (WRITE_TARGET_FLAGS[cmd]?.has(tok.value)) skipNext = true;

      // The pattern arrived as a flag, so no operand stands in for it. An
      // attached value (`--regexp=aws`) is already part of this token; a
      // separate one is a pattern or a pattern file, and neither is printed.
      if (behaviour.firstOperandIsPatternOrScript) {
        const [flag] = tok.value.split("=", 1) as [string];
        if (PATTERN_SUPPLYING_FLAGS.has(flag)) {
          patternSkipped = true;
          if (!tok.value.includes("=")) skipNext = true;
        }
      }
      continue;
    }

    if (behaviour.isGit) {
      if (!gitSubcommandSeen) {
        gitSubcommandSeen = true;
        gitReadsFiles = gitSubcommandPrintsFiles(tok.value, operands);
        continue;
      }
      if (gitReadsFiles) paths.push(tok.value);
      continue;
    }

    // `if=<file>` names an input only for `dd`; other commands taking an
    // `if=` argument are not reading the file it names.
    if (behaviour.isDd) {
      const ddInput = /^if=(.+)$/.exec(tok.value);
      if (ddInput?.[1]) {
        paths.push(ddInput[1]);
        continue;
      }
    }

    if (behaviour.firstOperandIsPatternOrScript && !patternSkipped) {
      patternSkipped = true; // the pattern, expression or script name
      continue;
    }

    if (
      behaviour.printsOperands ||
      behaviour.firstOperandIsPatternOrScript ||
      inlineCodeSeen
    ) {
      paths.push(tok.value);
    }
  }

  return { paths, envVars, dumpsEnvironment };
}

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
  type ShellToken,
  stripHeredocBodies,
  tokenizeCommand,
} from "./shell.ts";

// Commands that write the contents of every non-flag argument to stdout.
// `wc` is deliberately absent: it reports counts, never the bytes themselves.
export const FILE_READ_COMMANDS = new Set([
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
// The rest of the digest family, and the BSD spellings, were missing. Naming a
// file, that costs nothing — an unclassified command's operands are not
// collected either. Over `<` it did: stdin is collected for any command not
// known to print no contents, so `sha512sum < secrets` was scanned while
// `sha256sum < secrets` was not. The wrong direction is only a false block, but
// the two spellings disagreeing is not something to leave in a table.
export const COUNT_ONLY_COMMANDS = new Set([
  "wc",
  "cksum",
  "sum",
  "md5",
  "md5sum",
  "shasum",
  "sha1sum",
  "sha224sum",
  "sha256sum",
  "sha384sum",
  "sha512sum",
  "b2sum",
]);

// Commands whose first non-flag argument is a pattern, expression or script,
// and whose remaining non-flag arguments are files written to stdout.
// General-purpose runtimes (`python`, `node`, `deno`, `bun`, and `perl` and
// `ruby` when they run a program file) are absent: they execute their first
// argument rather than print it, and the files named after it are argv, not
// output. Their inline code (`-c`, `-e`) is still scanned via
// INLINE_CODE_COMMANDS.
export const PATTERN_OR_SCRIPT_FIRST_COMMANDS = new Set([
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
export const PATTERN_SUPPLYING_FLAGS = new Set([
  "-e",
  "--regexp",
  "--expression",
  "-f",
  "--file",
  "--from-file",
]);

// Whether a flag token supplies the pattern, and whether its value is already
// attached to it.
//
// Three spellings carry a value: separate (`-e aws`, `--regexp aws`), attached
// after `=` (`--regexp=aws`), and attached directly to a short flag
// (`-eaws`, `sed -e's/a/b/'`). Only the first two were recognised, so an attached
// short value left `patternSkipped` unset and the file that followed was eaten as
// the pattern — `grep -eaws secrets` and `sed -e's/a/b/' secrets` scanned nothing.
function patternSupplyingFlag(token: string): "attached" | "separate" | null {
  const equals = token.indexOf("=");
  const beforeEquals = equals === -1 ? token : token.slice(0, equals);
  if (PATTERN_SUPPLYING_FLAGS.has(beforeEquals)) {
    return equals === -1 ? "separate" : "attached";
  }
  // A short flag with its value written against it. Long flags are excluded:
  // `--file-name` is not `--file` with `-name` attached.
  if (!token.startsWith("--") && token.length > 2) {
    if (PATTERN_SUPPLYING_FLAGS.has(token.slice(0, 2))) return "attached";
  }
  return null;
}

// Flags of a read command whose separate value names a file to write, not one to
// read: `sort -o out.txt in.txt` prints nothing of `out.txt`, and scanning it
// blocked a command that only ever writes there.
//
// Keyed per command rather than by flag name, because the same letter means
// different things: `-o` is an output file for these three but an octal-format
// flag taking no value for `od` and `hexdump`, so a shared list would swallow
// the operand of `od -o secrets` and miss the read.
export const WRITE_TARGET_FLAGS: Record<string, Set<string>> = {
  sort: new Set(["-o", "--output"]),
  shuf: new Set(["-o", "--output"]),
  iconv: new Set(["-o", "--output"]),
};

// Interpreters whose file operands are input to a one-liner given inline:
// `perl -pe 's/a/b/' f` and `ruby -pe '…' f` print f. Hand them a program file
// instead and the operands are argv — `perl script.pl data.txt` prints neither —
// so their operands count as reads only once inline code has been seen.
export const INLINE_CODE_READS_OPERANDS = new Set(["perl", "ruby"]);

// Commands that run another command. They are stripped so the wrapped command
// is classified instead: `sudo cat secrets` is treated as `cat secrets`.
export const WRAPPER_COMMANDS = new Set([
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
export const INLINE_CODE_COMMANDS = new Set([
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

export const POSIX_SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh"]);

// git subcommands that can write file contents to stdout. Blob references such
// as `git show HEAD:.env` name history, not the working tree, and stay
// uncovered — only paths that exist on disk are scanned. `difftool` hands off
// to an external tool and `stash` prints no file contents, so neither is here:
// classifying them would push tokens like the `pop` in `git stash pop` as paths.
export const GIT_READ_SUBCOMMANDS = new Set([
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

// Commands whose `-i` rewrites the files it is handed instead of printing them,
// each with the short switches it accepts without a value.
//
// Being on this list at all is what makes `-i` mean in-place: `grep -i` matches
// case-insensitively and still prints. The letters are what let a bundle be read
// one at a time in search of the `i`.
//
// One table rather than two. A separate set of command names said the same thing
// as these keys, and the two could disagree — adding `awk` to the set alone made
// `awk -i` an in-place edit, which a test had to be written to catch. Nothing can
// disagree with itself.
//
// Per command, because the letters differ and sharing one set got it wrong in
// both directions: `E`, `r` and `z` are valueless for `sed` but absent from a
// set chosen for `perl`, so the everyday `sed -Ei` was read as a non-in-place
// command and its file scanned; while `0` was present for `perl -0777`, which
// made `sed -0i` — not a sed flag at all — look like an in-place edit and left
// its file unscanned.
//
// A letter that is not here stops the reading, whether it takes a value or the
// list simply does not know it. That is the fail-closed direction: the command
// is then treated as one that prints, and its operands are scanned.
// `e` is absent from every line on purpose: it introduces a script for all three,
// and a sed script contains `i` as its insert command, so reading past `-e` would
// find an `i` in the program text and call the command an in-place edit.
export const IN_PLACE_EDITORS: Record<string, string> = {
  sed: "anszEru",
  perl: "aclnpsStTuUvwWX",
  ruby: "acdlnpsSTUvwWy",
};

// True when `cmd` edits in place given `value` as one of its flags: `-i`,
// `-i.bak`, or a bundle reaching `i` past that command's valueless switches
// (`-pi`, `-lpi`, `-Ei`).
//
// A command absent from the table is not an in-place editor at all, so no flag of
// it counts — `grep -i` and `grep --in-place` alike.
//
// `--in-place` is sed's alone. Accepting it from every command in the table meant
// `perl --in-place=.bak -pe 'x' secrets` and the same for `ruby` were treated as
// in-place edits and their files went unscanned, though neither interpreter has
// that flag: perl and ruby spell it `-i`, and would reject the long form.
export function isInPlaceFlag(cmd: string, value: string): boolean {
  const valueless = IN_PLACE_EDITORS[cmd];
  if (valueless === undefined) return false;

  if (cmd === "sed" && value.replace(/=.*/, "") === "--in-place") return true;
  if (!value.startsWith("-") || value.startsWith("--")) return false;

  for (const ch of value.slice(1)) {
    if (ch === "i") return true;
    if (!valueless.includes(ch)) return false;
  }
  return false;
}

function editsInPlace(cmd: string, operands: ShellToken[]): boolean {
  return operands.some(({ value }) => isInPlaceFlag(cmd, value));
}

// Global git flags that carry a separate value before the subcommand
// (`git -C repo show f`, `git -c k=v show f`). Attached forms (`--git-dir=x`)
// are single flag tokens and need no entry here.
export const GIT_GLOBAL_FLAGS_WITH_OPERAND = new Set([
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

// Fold one set of refs into another. A command line yields refs from several
// places — its substitutions, each of its segments, the inline code it carries,
// an `env -S` string — and combining them is the same three lines each time,
// which is how it came to be written out three times with a closure alongside.
function mergeRefs(into: CommandRefs, refs: CommandRefs): void {
  into.paths.push(...refs.paths);
  into.envVars.push(...refs.envVars);
  into.dumpsEnvironment = into.dumpsEnvironment || refs.dumpsEnvironment;
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
//
// Not every per-command decision belongs here, and two deliberately stay out.
// isClassifiableCommand below reads this record generically — any truthy field
// means "operands understood" — which is what lets a new field be added without
// updating it, and also what a field has to respect to live here:
//
//   - `WRITE_TARGET_FLAGS[cmd]` would arrive as a Set, truthy even when empty,
//     making every command classifiable and stopping the wrapper search at the
//     first operand it meets.
//   - `cmd === "env"` for the `-S` string would make `env` classifiable, and
//     `env` is left out on purpose: it is a wrapper as often as a command.
//
// Both are therefore read from their tables at the point of use rather than
// folded in here. Anything added to this record must be a boolean that means
// "this hook understands what the command does with its operands".
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

// Commands that write their operands out without ever opening them.
//
// These matter only to the wrapper search below, as the point where it has to
// stop: everything after one of them is its own argument list. Without that
// stop, `sudo echo cat secrets` walked past `echo` looking for a name it could
// classify, found `cat` among echo's arguments, and blocked a command that
// reads nothing.
//
// The set is deliberately short and cannot be complete — any command this hook
// does not classify might be the one a wrapper handed off to, and the search
// still walks past those. That is the direction to be wrong in: it collects
// paths that are not read rather than missing a read, and `sudo -u root cat f`
// depends on it, because `root` is not distinguishable from a command name.
//
// Treat this as a stopgap rather than a list to grow. Each name added buys one
// more false positive and leaves the general case untouched, and a list that
// accumulates one report at a time is the shape of a rule nobody wrote down. The
// real fix is to model each wrapper's own arguments — the flags that take a
// value, and the leading operand of `timeout` and `flock` — so the command
// position is determinate and no allowlist is needed. That was not done here
// because an incomplete table of those flags fails the other way, missing reads
// instead of over-reporting them. If a third false positive of this shape turns
// up, do that instead of adding a sixth name.
export const ARGUMENT_ONLY_COMMANDS = new Set([
  "echo",
  "printf",
  "true",
  "false",
  ":",
]);

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
//
// The search past a wrapper carries the same hazard one step further in, which
// is why it stops at an ARGUMENT_ONLY_COMMANDS name: `sudo echo cat secrets`
// otherwise resolved to the `cat` sitting in echo's arguments. Past any other
// unclassifiable name the search continues, since that name may be a wrapper
// flag's value rather than the command.
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
    const name = path.basename(tok.value);
    if (isWrapperTarget(name) || ARGUMENT_ONLY_COMMANDS.has(name)) return i;
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
      if (t.redirect) {
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
    if (t.redirect) {
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
  const refs: CommandRefs = { paths: [], envVars: [], dumpsEnvironment: false };

  if (depth > MAX_NESTING_DEPTH) return refs;

  // Heredoc bodies are text, not commands; strip them before any other pass.
  const text = stripHeredocBodies(command);

  // `echo $(cat secrets)` reads secrets just as `cat secrets` does.
  for (const inner of extractSubstitutions(text)) {
    mergeRefs(refs, extractCommandRefs(inner, depth + 1));
  }

  for (const tokens of tokenizeCommand(text)) {
    const environment = inspectEnvironmentCommand(tokens);
    if (environment.dumps) refs.dumpsEnvironment = true;
    refs.envVars.push(...environment.named);

    mergeRefs(refs, collectSegmentRefs(tokens, depth));
  }

  return {
    paths: [...new Set(refs.paths)],
    envVars: [...new Set(refs.envVars)],
    dumpsEnvironment: refs.dumpsEnvironment,
  };
}

// File paths one segment of a command line may print, plus anything found inside
// inline program text it carries.
function collectSegmentRefs(tokens: ShellToken[], depth: number): CommandRefs {
  const refs: CommandRefs = { paths: [], envVars: [], dumpsEnvironment: false };

  const start = findCommandIndex(tokens);
  const cmdToken = tokens[start];
  if (cmdToken === undefined) return refs;

  const cmd = path.basename(cmdToken.value);
  const operands = tokens.slice(start + 1);

  // In-place editing sends the result back to the file, so nothing reaches
  // stdout and nothing is read into the conversation.
  if (editsInPlace(cmd, operands)) {
    return refs;
  }

  // `env -S "cmd args"` splits the string into the command it runs, so scan
  // inside it the way inline code is scanned.
  if (cmd === "env") {
    for (let k = 0; k < operands.length; k++) {
      const t = operands[k]?.value;
      if (t !== "-S" && t !== "--split-string") continue;
      const script = operands[k + 1]?.value;
      if (script === undefined) continue;
      mergeRefs(refs, extractCommandRefs(script, depth + 1));
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
  let optionsEnded = false;

  for (const tok of operands) {
    if (skipNext) {
      skipNext = false;
      continue;
    }
    if (collectNext) {
      collectNext = false;
      refs.paths.push(tok.value);
      continue;
    }
    if (codeNext) {
      codeNext = false;
      // The expression came from -e/-c, so a later operand is a file, not the
      // script `perl file` would have run.
      patternSkipped = true;
      if (behaviour.inlineCodeReadsOperands) inlineCodeSeen = true;
      mergeRefs(refs, extractCommandRefs(tok.value, depth + 1));
      refs.paths.push(...extractQuotedLiterals(tok.value));
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

    // `--` ends option parsing: every token after it is an operand, whatever it
    // is spelled like. `grep -- -aws secrets` searches for `-aws` in `secrets`,
    // so the file is a file — read as a flag, `-aws` left the pattern
    // unaccounted for and `secrets` was consumed in its place.
    if (!optionsEnded && tok.value === "--") {
      optionsEnded = true;
      continue;
    }

    if (
      !optionsEnded &&
      behaviour.takesInlineCode &&
      isInlineCodeFlag(cmd, tok.value)
    ) {
      codeNext = true;
      continue;
    }

    if (!optionsEnded && tok.value.startsWith("-")) {
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

      // The pattern arrived as a flag, so no operand stands in for it.
      if (behaviour.firstOperandIsPatternOrScript) {
        const supply = patternSupplyingFlag(tok.value);
        if (supply !== null) {
          patternSkipped = true;
          // Only a flag still waiting for its value consumes the next token. A
          // value already attached — `--regexp=aws`, or `-eaws` — is part of
          // this one.
          if (supply === "separate") skipNext = true;
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
      if (gitReadsFiles) refs.paths.push(tok.value);
      continue;
    }

    // `if=<file>` names an input only for `dd`; other commands taking an
    // `if=` argument are not reading the file it names.
    if (behaviour.isDd) {
      const ddInput = /^if=(.+)$/.exec(tok.value);
      if (ddInput?.[1]) {
        refs.paths.push(ddInput[1]);
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
      refs.paths.push(tok.value);
    }
  }

  return refs;
}

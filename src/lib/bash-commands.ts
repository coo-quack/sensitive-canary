// What this hook knows about how each command treats its operands.
//
// The tables are the knowledge: which commands print a file they are handed,
// which take a pattern first, which run another command. extractCommandRefs
// turns a command line into the files it may print and the environment it may
// expose, leaving the parsing to shell.ts.

import path from "node:path";
import {
  ARGUMENT_ONLY_COMMANDS,
  asksForRecursion,
  type CommandRefs,
  classifyCommand,
  editsInPlace,
  GIT_GLOBAL_FLAGS_WITH_OPERAND,
  GREP_FAMILY,
  gitLineRangeFile,
  gitSubcommandPrintsFiles,
  INLINE_CODE_COMMANDS,
  isWrapperTarget,
  MAX_NESTING_DEPTH,
  mergeRefs,
  POSIX_SHELLS,
  patternSupplyingFlag,
  RECURSIVE_BY_DEFAULT,
  WRAPPER_COMMANDS,
  WRITE_TARGET_FLAGS,
} from "./command-tables.ts";
import { addProgramEnvironment } from "./program-environment.ts";
import {
  blankComments,
  extractQuotedLiterals,
  extractSubstitutions,
  findComments,
  isNonCommandToken,
  type ShellSegment,
  type ShellToken,
  splitHeredocBodies,
  tokenizeSegments,
} from "./shell.ts";

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
  const lead = leadCommandIndex(tokens);
  if (lead === -1) return 0;

  const leadName = path.basename(tokens[lead]?.value ?? "");
  if (!WRAPPER_COMMANDS.has(leadName)) return lead;

  for (let i = lead + 1; i < tokens.length; i++) {
    const tok = tokens[i];
    if (tok === undefined || isNonCommandToken(tok)) continue;
    const name = path.basename(tok.value);
    if (isWrapperTarget(name) || ARGUMENT_ONLY_COMMANDS.has(name)) return i;
  }
  return lead;
}

// Index of the first token that is not a flag, redirection, keyword or
// `VAR=value` assignment, or -1 when there is none. `function NAME` is skipped
// as a keyword with its name, so `function f { env; }` leads with `env`, as
// `f() { env; }` does.
function leadCommandIndex(tokens: ShellToken[]): number {
  // A redirection may come before the command — `< secrets cat` is `cat` reading
  // `secrets`. The operator is skipped as a non-command token, but its target is
  // an ordinary word, so `secrets` was taken for the command name and the real
  // one went unclassified: nothing of its operands was collected, and a spelling
  // away from `cat < secrets`, which blocks.
  let skipRedirectTarget = false;
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token === undefined) continue;
    if (skipRedirectTarget) {
      skipRedirectTarget = false;
      continue;
    }
    if (token.redirect) {
      skipRedirectTarget = true;
      continue;
    }
    if (token.value === "function") {
      i++; // its name
      continue;
    }
    if (isNonCommandToken(token)) continue;
    return i;
  }
  return -1;
}

// Shell builtins that print variables with their values. Given no names,
// `export` (with or without `-p`), `declare`, `typeset` and zsh's `local` list
// every variable, and so does a bare `set`; the hook sees only its own
// environment, so a listing is scanned as a dump of that. Given names,
// `declare -p NAME`, `export -p NAME` in zsh and zsh's `typeset NAME` print
// those, so the names are scanned, while a bare `export NAME` prints nothing.
// `-f` and `-F` list functions instead. An operand that is not a plain name
// (`"$v"`, `${!AWS_*}`, a zsh `-m` pattern such as `'AWS*'`) names what only
// the shell decides, so it is scanned as a dump. A builtin cannot
// run behind `sudo` or `env`, only behind the prefixes below, and
// `command -v set` only describes it.
const BUILTIN_PREFIXES = new Set([
  "builtin",
  "command",
  "time",
  "noglob",
  "nocorrect",
]);
const VARIABLE_LISTING_BUILTINS = new Set([
  "export",
  "declare",
  "typeset",
  "local",
  "set",
]);

function inspectVariableBuiltin(
  tokens: ShellToken[],
): { dumps: boolean; named: string[] } | null {
  let start = leadCommandIndex(tokens);
  while (BUILTIN_PREFIXES.has(tokens[start]?.value ?? "")) {
    // The prefix's own flags and redirections come before the command.
    const rest = tokens.slice(start + 1);
    const next = leadCommandIndex(rest);
    const own = next === -1 ? rest : rest.slice(0, next);
    if (own.some((t) => t.value === "-v" || t.value === "-V")) return null;
    start = next === -1 ? -1 : start + 1 + next;
  }
  const name = tokens[start]?.value;
  if (name === undefined || !VARIABLE_LISTING_BUILTINS.has(name)) return null;

  const flags: string[] = [];
  const operands: string[] = [];
  const rest = tokens.slice(start + 1);
  for (let j = 0; j < rest.length; j++) {
    const t = rest[j];
    if (t === undefined) continue;
    if (t.redirect) {
      j++; // its target
      continue;
    }
    if (/^[-+]/.test(t.value)) flags.push(t.value);
    else operands.push(t.value);
  }
  if (name === "set")
    return { dumps: flags.length === 0 && operands.length === 0, named: [] };
  if (operands.length === 0)
    return { dumps: !flags.some((f) => /^-.*[fF]/.test(f)), named: [] };
  const printsNamed = name !== "export" || flags.some((f) => /^-.*p/.test(f));
  if (!printsNamed) return { dumps: false, named: [] };
  const named: string[] = [];
  for (const o of operands) {
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(o)) continue; // an assignment
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(o)) return { dumps: true, named: [] };
    named.push(o);
  }
  return { dumps: false, named };
}

// `env` and `printenv` print the environment unless they are being used to run
// another command. `sudo printenv` counts; `env FOO=1 cat f` does not. The
// command is located with findCommandIndex, so wrapper flags and operands
// (`sudo -u root printenv`, `timeout 5 env`) cannot hide it. The shell builtins
// that list variables are read first.
function inspectEnvironmentCommand(tokens: ShellToken[]): {
  dumps: boolean;
  named: string[];
} {
  const nothing = { dumps: false, named: [] };

  const builtin = inspectVariableBuiltin(tokens);
  if (builtin !== null) return builtin;

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
  if (POSIX_SHELLS.has(cmd)) {
    // A shell bundles its switches too: `bash -lc 'cat secrets'` runs the same
    // string `bash -c` would, and only the exact spelling was recognised. The
    // letters before the `c` have to be switches that take no value of their
    // own, or the `c` is part of something else's value.
    return /^-[abefhilmnpuvxCPT]*c$/.test(token);
  }
  if (token === "-r") return true; // php -r
  // `node -p` and `bun -p` evaluate the expression and print its value.
  if ((cmd === "node" || cmd === "bun") && /^(?:-p|--print)$/.test(token))
    return true;
  return /^-[A-Za-z]*[eE]$/.test(token);
}

// The command line with its comments blanked, or null when it has none. The
// first reading takes a comment's words for arguments: a quote in one folds the
// lines after it into a single word, and even a plain one hides what the
// command does without it — `env # list` reads as env running `list`, and
// `grep -r foo # search` as a grep of two files rather than of the working
// directory.
function withCommentsBlanked(command: string): string | null {
  return findComments(command).length > 0 ? blankComments(command) : null;
}

// Everything a Bash command reveals that the hook can inspect before it runs:
// the files whose contents it may print, and the environment it may expose.
//
// The command is read as it always was. When it has a comment, it is read a
// second time with its comments blanked, and the two readings' refs are
// merged. The second reading has none of the comment's words, so merging can
// only add scanning to the first reading's result.
export function extractCommandRefs(command: string, depth = 0): CommandRefs {
  const refs = readCommandLine(command, depth);

  const blanked = withCommentsBlanked(command);
  if (blanked !== null) mergeRefs(refs, readCommandLine(blanked, depth));

  return {
    paths: [...new Set(refs.paths)],
    envVars: [...new Set(refs.envVars)],
    dumpsEnvironment: refs.dumpsEnvironment,
    searchesWorkingDirectory: refs.searchesWorkingDirectory,
  };
}

// One reading of a command line, as extractCommandRefs has always made it.
function readCommandLine(command: string, depth: number): CommandRefs {
  const refs: CommandRefs = {
    paths: [],
    envVars: [],
    dumpsEnvironment: false,
    searchesWorkingDirectory: false,
  };

  if (depth > MAX_NESTING_DEPTH) return refs;

  // Heredoc bodies are text, not commands, unless an interpreter reads one as
  // its program (stdinPrograms); strip them before any other pass.
  const { text, bodies } = splitHeredocBodies(command);

  // `echo $(cat secrets)` reads secrets just as `cat secrets` does.
  for (const inner of extractSubstitutions(text)) {
    mergeRefs(refs, extractCommandRefs(inner, depth + 1));
  }

  // Both readings are scanned, and their refs merged, so a mistake in either
  // can only add scanning. The default is kept because POSIX sh reads `&>` as
  // `&` then `>`, and a command behind that `&` runs. The joined reading is
  // what bash does with `2>&1`, `>|` and `&>`. Where the two agree, a
  // segment is identical and is processed once.
  const readings = [
    tokenizeSegments(text),
    tokenizeSegments(text, { joinRedirections: true }),
  ];
  const seen = new Set<string>();
  const programsRead = new Set<string>();
  for (const segments of readings) {
    // `echo env | bash` runs what echo prints, read the way `bash -c` is. The
    // readings mostly find the same programs, and each is read once.
    for (const { interpreter, text } of stdinPrograms(segments, bodies)) {
      const key = `${interpreter}\0${text}`;
      if (programsRead.has(key)) continue;
      programsRead.add(key);
      readProgram(refs, interpreter, text, depth);
    }

    for (const { tokens } of segments) {
      const key = JSON.stringify(tokens);
      if (seen.has(key)) continue;
      seen.add(key);

      const environment = inspectEnvironmentCommand(tokens);
      if (environment.dumps) refs.dumpsEnvironment = true;
      refs.envVars.push(...environment.named);

      mergeRefs(refs, collectSegmentRefs(tokens, depth));
    }
  }

  return refs;
}

// A program and the interpreter that runs it.
interface StdinProgram {
  interpreter: string;
  text: string;
}

// The text a command line hands a shell or interpreter on stdin, which it runs
// as its program: a here-string (`bash <<< env`), the heredoc bodies when one
// of them feeds an interpreter (`bash <<'EOF'`), and what an earlier command
// writes into a pipe the interpreter reads, when that text is on the command
// line: what `echo` and `printf` print, and the here-strings and heredocs
// handed to anything else (`cat <<'EOF' | bash`). `cat script | bash` runs a
// file's contents, as `bash script` does, and is left alone.
//
// Each of these is over-read rather than matched exactly, so a mistake can only
// add scanning. The bodies are read for a heredoc on any interpreter in the
// line, or on any command before one that reads a pipe, since pairing one body
// with one `<<` would have to agree with the shell's order across both
// readings. What reaches a pipe is everything those commands wrote earlier on
// the line, not only in the segment just before it: in `{ echo env; } | bash`
// that segment is the closing brace. The operands of `echo` and `printf` are
// read joined by spaces, as `echo` prints them, and for `printf` through its
// format as well.
// Text holding a backslash escape is read again with it decoded, which
// `printf`, `echo -e` and zsh's `echo` do. Text that only exists once the
// command runs is not read: a variable (`echo $v | bash`), a substitution
// (`bash <<< $(…)`, `bash < <(echo env)`), or the output of several commands
// joined into one line (`(echo -n en; echo v) | bash`).
function stdinPrograms(
  segments: ShellSegment[],
  bodies: string[],
): StdinProgram[] {
  const programs: StdinProgram[] = [];
  const written: string[] = [];
  let heredocWritten = false;
  // The interpreters a heredoc on the line may feed.
  const heredocReaders = new Set<string>();

  for (const { tokens, afterPipe } of segments) {
    const start = findCommandIndex(tokens);
    const cmd = path.basename(tokens[start]?.value ?? "");
    // `source /dev/stdin` and `. /dev/stdin` run what they are piped too.
    const interpreter =
      INLINE_CODE_COMMANDS.has(cmd) || cmd === "source" || cmd === ".";
    if (interpreter && afterPipe) {
      for (const text of written) programs.push({ interpreter: cmd, text });
      if (heredocWritten) heredocReaders.add(cmd);
    }

    const hereStrings: string[] = [];
    let heredoc = false;
    const words: string[] = [];
    for (let k = 0; k < tokens.length; k++) {
      const t = tokens[k];
      if (t === undefined) continue;
      if (t.redirect) {
        const target = tokens[k + 1];
        if (t.value === "<<<" && target !== undefined && !target.redirect)
          hereStrings.push(target.value);
        if (t.value === "<<") heredoc = true;
        k++; // its target, or a heredoc delimiter
        continue;
      }
      if (k > start) words.push(t.value);
    }

    if (interpreter) {
      for (const text of hereStrings) programs.push({ interpreter: cmd, text });
      if (heredoc) heredocReaders.add(cmd);
      continue;
    }
    for (const text of hereStrings) written.push(text);
    if (heredoc) heredocWritten = true;
    if (cmd === "echo" || cmd === "printf") {
      const texts = [words.join(" ")];
      if (cmd === "printf" && words.length > 0) texts.push(printfOutput(words));
      for (const text of texts) {
        written.push(text);
        const decoded = decodeEscapes(text);
        if (decoded !== text) written.push(decoded);
      }
    }
  }
  for (const interpreter of heredocReaders)
    for (const text of bodies) programs.push({ interpreter, text });
  return programs;
}

// What `printf FORMAT ARGS…` prints, as far as the text goes: each conversion
// takes the next argument, and the format is reused while arguments remain, so
// `printf 'e%sv' n` prints `env`. Escapes are left to decodeEscapes.
function printfOutput(words: string[]): string {
  const [format = "", ...args] = words[0] === "--" ? words.slice(1) : words;
  const conversion = /%%|%[-+ #0]*\d*(?:\.\d*)?[a-zA-Z]/g;
  let out = "";
  let next = 0;
  do {
    out += format.replace(conversion, (spec) =>
      spec === "%%" ? "%" : (args[next++] ?? ""),
    );
  } while (next > 0 && next < args.length);
  return out;
}

// The backslash escapes `printf`, `echo -e` and zsh's `echo` turn into
// characters: `\n`, `\t` and the like, an octal byte (`\156`, or `\0156` for
// echo) and a hex one (`\x65`).
function decodeEscapes(text: string): string {
  const named: Record<string, string> = {
    a: "\x07",
    b: "\b",
    f: "\f",
    n: "\n",
    r: "\r",
    t: "\t",
    v: "\v",
    "\\": "\\",
  };
  return text.replace(
    /\\(?:0([0-7]{1,3})|([0-7]{1,3})|x([0-9A-Fa-f]{1,2})|([abfnrtv\\]))/g,
    (_, echoOctal?: string, octal?: string, hex?: string, letter?: string) => {
      if (letter !== undefined) return named[letter] ?? letter;
      const code =
        hex !== undefined
          ? Number.parseInt(hex, 16)
          : Number.parseInt(echoOctal ?? octal ?? "0", 8);
      return String.fromCharCode(code);
    },
  );
}

// Program text `interpreter` runs, from `-c` or on stdin: read as a command
// line, for the paths its quoted literals may name, and for what it does with
// the environment.
function readProgram(
  refs: CommandRefs,
  interpreter: string,
  program: string,
  depth: number,
): void {
  mergeRefs(refs, extractCommandRefs(program, depth + 1));
  refs.paths.push(...extractQuotedLiterals(program));
  addProgramEnvironment(refs, interpreter, program);
}

// File paths one segment of a command line may print, plus anything found inside
// inline program text it carries.
function collectSegmentRefs(tokens: ShellToken[], depth: number): CommandRefs {
  const refs: CommandRefs = {
    paths: [],
    envVars: [],
    dumpsEnvironment: false,
    searchesWorkingDirectory: false,
  };

  const start = findCommandIndex(tokens);
  const cmdToken = tokens[start];
  if (cmdToken === undefined) return refs;

  const cmd = path.basename(cmdToken.value);
  const operands = tokens.slice(start + 1);

  // `< secrets cat` puts the redirection before the command, so its target is
  // not among the operands and the loop below never sees it. The command still
  // reads it.
  //
  // `$(<secrets)` has no command at all: bash reads the file and substitutes its
  // contents. There the whole token list is in front of the "command", which is
  // the redirection operator itself.
  const beforeCommand = cmdToken.redirect ? tokens.length : start;
  for (let i = 0; i < beforeCommand; i++) {
    if (tokens[i]?.redirect !== true) continue;
    if (tokens[i]?.value !== "<") continue;
    const target = tokens[i + 1];
    if (target === undefined || target.redirect) continue;
    if (!classifyCommand(cmd).printsNoFileContents) {
      refs.paths.push(target.value);
    }
  }

  // In-place editing sends the result back to the file, so nothing reaches
  // stdout and nothing is read into the conversation.
  if (editsInPlace(cmd, operands)) {
    return refs;
  }

  // `eval 'cat secrets'` is a command line in a single word, the same shape
  // `env -S` carries. Stepping past `eval` finds that word as the command name,
  // which classifies as nothing at all.
  if (cmd === "eval") {
    for (const operand of operands) {
      if (operand.redirect) continue;
      mergeRefs(refs, extractCommandRefs(operand.value, depth + 1));
      refs.paths.push(...extractQuotedLiterals(operand.value));
    }
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
  let lineRangeNext = false;

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
      // script `perl file` would have run. That is `inlineCodeSeen` below: no
      // command takes inline code *and* a leading pattern, an assumption the
      // tests pin, so there is no pattern here to mark as supplied.
      if (behaviour.inlineCodeReadsOperands) inlineCodeSeen = true;
      readProgram(refs, cmd, tok.value, depth);
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

    // `git log -L1,10:f` prints the lines of `f` themselves, and the file is
    // written inside the range spec after the last `:`. The flag branch below
    // consumes any `-`-shaped token, so this has to come before it, and the
    // operand branch would never see the file anyway.
    if (
      behaviour.isGit &&
      (tok.value.startsWith("-L") || tok.value.startsWith("--line-range"))
    ) {
      const inFlag = gitLineRangeFile(tok.value);
      if (inFlag !== null) refs.paths.push(inFlag);
      else lineRangeNext = true;
      continue;
    }
    if (lineRangeNext) {
      lineRangeNext = false;
      const separate = gitLineRangeFile(tok.value);
      if (separate !== null) refs.paths.push(separate);
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
      // An awk or sed program can name a file inside itself, the way inline code
      // does: `awk 'BEGIN{ while ((getline l < "secrets") > 0) print l }'` reads
      // one without ever naming it as an operand.
      refs.paths.push(...extractQuotedLiterals(tok.value));
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

  // A searcher handed no file searches where it is run. `rg PATTERN` and
  // `grep -r PATTERN` are the ordinary forms and name nothing, so the loop above
  // collects the pattern and stops with no path — and the tree they print from
  // is the working directory. The caller is what knows which directory that is.
  if (
    refs.paths.length === 0 &&
    (RECURSIVE_BY_DEFAULT.has(cmd) ||
      (GREP_FAMILY.has(cmd) && asksForRecursion(operands)))
  ) {
    refs.searchesWorkingDirectory = true;
  }

  return refs;
}

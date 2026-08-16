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
  isWrapperTarget,
  MAX_NESTING_DEPTH,
  mergeRefs,
  POSIX_SHELLS,
  patternSupplyingFlag,
  RECURSIVE_BY_DEFAULT,
  WRAPPER_COMMANDS,
  WRITE_TARGET_FLAGS,
} from "./command-tables.ts";
import {
  extractQuotedLiterals,
  extractSubstitutions,
  isNonCommandToken,
  type ShellToken,
  stripHeredocBodies,
  tokenizeCommand,
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
  let lead = -1;
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
    if (isNonCommandToken(token)) continue;
    lead = i;
    break;
  }
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
  if (POSIX_SHELLS.has(cmd)) {
    // A shell bundles its switches too: `bash -lc 'cat secrets'` runs the same
    // string `bash -c` would, and only the exact spelling was recognised. The
    // letters before the `c` have to be switches that take no value of their
    // own, or the `c` is part of something else's value.
    return /^-[abefhilmnpuvxCPT]*c$/.test(token);
  }
  if (token === "-r") return true; // php -r
  return /^-[A-Za-z]*[eE]$/.test(token);
}

// Everything a Bash command reveals that the hook can inspect before it runs:
// the files whose contents it may print, and the environment it may expose.
export function extractCommandRefs(command: string, depth = 0): CommandRefs {
  const refs: CommandRefs = {
    paths: [],
    envVars: [],
    dumpsEnvironment: false,
    searchesWorkingDirectory: false,
  };

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
    searchesWorkingDirectory: refs.searchesWorkingDirectory,
  };
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

// What this hook knows about how each command treats its operands.
//
// The set below is the knowledge: the commands that write the contents of the
// files they are handed to stdout. extractFilePathsFromCommand turns a command
// line into the paths such a command may print, leaving the parsing to shell.ts.

import path from "node:path";
import {
  extractSubstitutions,
  isNonCommandToken,
  isRedirectionOperator,
  stripHeredocBodies,
  tokenizeCommand,
} from "./shell.ts";

const FILE_READ_COMMANDS = new Set([
  "cat",
  "head",
  "tail",
  "less",
  "more",
  "bat",
  "nl",
]);

// How deep a chain of nested command substitutions is followed. `depth` counts
// nesting, so the command line itself is 0 and four levels of substitution below
// it are inspected.
const MAX_NESTING_DEPTH = 4;

// Paths whose contents a command on this line may write to stdout.
export function extractFilePathsFromCommand(
  command: string,
  depth = 0,
): string[] {
  if (depth > MAX_NESTING_DEPTH) return [];
  const paths: string[] = [];

  // Heredoc bodies are text, not commands; strip them before any other pass.
  const text = stripHeredocBodies(command);

  // `echo $(cat secrets)` reads secrets just as `cat secrets` does.
  for (const inner of extractSubstitutions(text)) {
    paths.push(...extractFilePathsFromCommand(inner, depth + 1));
  }

  for (const tokens of tokenizeCommand(text)) {
    // The command is the first token that is not a flag, a redirection or a
    // `VAR=value` assignment, and not a keyword standing where a name would.
    const lead = tokens.findIndex((t) => !isNonCommandToken(t));
    if (lead === -1) continue;
    const leadName = path.basename(tokens[lead]?.value ?? "");
    if (!FILE_READ_COMMANDS.has(leadName)) continue;

    let skipNext = false;
    let collectNext = false;
    for (const tok of tokens.slice(lead + 1)) {
      if (skipNext) {
        skipNext = false;
        continue;
      }
      if (collectNext) {
        collectNext = false;
        paths.push(tok.value);
        continue;
      }
      if (isRedirectionOperator(tok)) {
        // `<` feeds stdin from the next token; every other form names an output
        // target or a heredoc delimiter.
        if (tok.value === "<") collectNext = true;
        else skipNext = true;
        continue;
      }
      if (tok.value.startsWith("-")) continue;
      paths.push(tok.value);
    }
  }

  return [...new Set(paths)];
}

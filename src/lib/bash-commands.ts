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

// Recursion limit for command substitutions.
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
    if (!FILE_READ_COMMANDS.has(path.basename(tokens[lead] ?? ""))) continue;

    let skipNext = false;
    let collectNext = false;
    for (const tok of tokens.slice(lead + 1)) {
      if (skipNext) {
        skipNext = false;
        continue;
      }
      if (collectNext) {
        collectNext = false;
        paths.push(tok);
        continue;
      }
      if (tok === "<") {
        collectNext = true; // stdin is fed from the next token
        continue;
      }
      if (isRedirectionOperator(tok)) {
        skipNext = true; // an output target or a heredoc delimiter
        continue;
      }
      if (tok.startsWith("-")) continue;
      paths.push(tok);
    }
  }

  return [...new Set(paths)];
}

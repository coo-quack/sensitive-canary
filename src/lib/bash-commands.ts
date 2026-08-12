// What this hook knows about how each command treats its operands.
//
// The set below is the knowledge: the commands that write the contents of the
// files they are handed to stdout. extractFilePathsFromCommand turns a command
// line into the paths such a command may print.

import path from "node:path";

const FILE_READ_COMMANDS = new Set([
  "cat",
  "head",
  "tail",
  "less",
  "more",
  "bat",
  "nl",
]);

export function extractFilePathsFromCommand(command: string): string[] {
  const paths: string[] = [];
  const segments = command.split(/\s*[|;&]+\s*/);

  for (const seg of segments) {
    const tokens = seg.trim().split(/\s+/).filter(Boolean);
    if (tokens.length < 2) continue;

    const cmd = path.basename(tokens[0] ?? "");
    if (!FILE_READ_COMMANDS.has(cmd)) continue;

    let skipNext = false;
    for (let i = 1; i < tokens.length; i++) {
      if (skipNext) {
        skipNext = false;
        continue;
      }
      const tok = tokens[i];
      if (!tok) continue;
      if (tok.startsWith("-")) continue;
      if (tok === ">" || tok === ">>" || tok === "<") {
        skipNext = true;
        continue;
      }
      paths.push(tok);
    }
  }

  return [...new Set(paths)];
}

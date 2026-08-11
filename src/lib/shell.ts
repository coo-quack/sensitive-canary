// Shell syntax, and nothing about what any particular command means.
//
// Right now that is only the variable references a command line makes. It is its
// own module because the questions are different: this one answers "what are the
// pieces of this command line", and bash-commands.ts answers "what does a
// command do with the pieces it is handed".

// Variable names referenced by the command.
export function extractEnvVarNames(command: string): string[] {
  const names = new Set<string>();
  const re = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g;
  for (const match of command.matchAll(re)) {
    const name = match[1] ?? match[2];
    if (name) names.add(name);
  }
  return [...names];
}

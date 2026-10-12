// What a program in an interpreter's own language does with the environment:
// whether it prints the whole of it, and which variables it reads by name.
//
// The shell builtins are bash-commands.ts. This is the same question asked of
// the code Python, JavaScript (node, deno, bun), Ruby, Perl and PHP run with
// `-c`, `-e`, `-p` or `-r`, or are handed on stdin, where `print(os.environ)`
// prints every value as `env` does and `os.environ["TOKEN"]` prints one.

import type { CommandRefs } from "./command-tables.ts";

const NAME = "[A-Za-z_][A-Za-z0-9_]*";

// A quoted name, as a lookup spells it: `"TOKEN"`, `'TOKEN'`, or a template
// literal without substitutions.
const QUOTED_NAME = `(['"\`])(?<name>${NAME})\\1`;

// One way a program reaches the environment. Each match of `use` is a use of
// it. A use followed by one of the `lookups` reads only the variable it names
// (the `name` group); any other use, including a lookup whose name is not a
// literal, is taken as the whole environment, since which variable it reads is
// decided only when the program runs.
interface EnvironmentAccess {
  use: RegExp;
  lookups: RegExp[];
}

// A lookup, matched where a use of the object ends.
function lookup(source: string): RegExp {
  return new RegExp(source, "y");
}

// Python and Ruby end a statement at a line break, so `x = os.environ` followed
// by a line starting `["TOKEN"]` is the whole object: a lookup is looked for on
// the same line only.
const PYTHON_MAPPING_LOOKUPS = [
  lookup(`[ \\t]*\\[\\s*${QUOTED_NAME}\\s*\\]`),
  lookup(`[ \\t]*\\.[ \\t]*(?:get|pop|setdefault)[ \\t]*\\(\\s*${QUOTED_NAME}`),
];
const PYTHON_CALL_LOOKUPS = [lookup(`[ \\t]*\\(\\s*${QUOTED_NAME}`)];

// Any object's `environ` and `getenv`, not only `os.`'s: the module is as
// often reached as `import os as o` or `__import__("os")`.
const PYTHON: EnvironmentAccess[] = [
  { use: /\.\s*environb?\b/g, lookups: PYTHON_MAPPING_LOOKUPS },
  { use: /\.\s*getenvb?\b/g, lookups: PYTHON_CALL_LOOKUPS },
];

// `from os import environ, getenv` makes the bare names the same objects. They
// are looked for in the program with its `from os import` statements removed,
// since the import itself is not a use.
const PYTHON_IMPORTED: EnvironmentAccess[] = [
  { use: /(?<![\w.])environb?\b/g, lookups: PYTHON_MAPPING_LOOKUPS },
  { use: /(?<![\w.])getenvb?\b/g, lookups: PYTHON_CALL_LOOKUPS },
];
const FROM_OS_IMPORT = /\bfrom\s+os\s+import\b[^\n;]*/g;

// The names `from os import environ as e` gives them, which are the same
// objects again.
function importedAliases(imports: string[]): EnvironmentAccess[] {
  const aliases: EnvironmentAccess[] = [];
  for (const statement of imports) {
    for (const [, object, alias] of statement.matchAll(
      new RegExp(`\\b(environ|getenv)b?\\s+as\\s+(${NAME})`, "g"),
    )) {
      aliases.push({
        use: new RegExp(`(?<![\\w.])${alias}\\b`, "g"),
        lookups:
          object === "environ" ? PYTHON_MAPPING_LOOKUPS : PYTHON_CALL_LOOKUPS,
      });
    }
  }
  return aliases;
}

const JAVASCRIPT: EnvironmentAccess[] = [
  {
    // `require("process").env` and `process["env"]` are `process.env` too, and
    // Bun's `Bun.env` and `import.meta.env` are the same object. A property
    // is reached with `.` or `?.`, with blanks around it.
    use: /\b(?:process|Bun|import\s*\.\s*meta)\s*\??\.\s*env\b|\bprocess\s*(?:\?\.\s*)?\[\s*(['"`])env\1\s*\]|\brequire\(\s*(['"`])(?:node:)?process\2\s*\)\s*\??\.\s*env\b/g,
    lookups: [
      // A property read, but not a method call: `process.env.toString()` is
      // the whole object.
      lookup(`\\s*\\??\\.\\s*(?<name>${NAME})\\b(?!\\s*\\()`),
      lookup(`\\s*(?:\\?\\.\\s*)?\\[\\s*${QUOTED_NAME}\\s*\\]`),
    ],
  },
  {
    // `const { env } = process` and `const p = require("process")` take the
    // object out under another name.
    use: /=\s*(?:process|require\(\s*(['"`])(?:node:)?process\1\s*\))(?![\w$.[])/g,
    lookups: [],
  },
  {
    use: /\bDeno\s*\??\.\s*env\b/g,
    lookups: [lookup(`\\s*\\??\\.\\s*get\\(\\s*${QUOTED_NAME}`)],
  },
];

// `process` itself, not followed by a property: printing it prints its `env`,
// and `const p = process` or `const { env } = process` takes the environment
// out under another name. Read only when the program is known to be
// JavaScript, since elsewhere `process` is an ordinary variable.
const JAVASCRIPT_PROCESS: EnvironmentAccess[] = [
  { use: /(?<![\w$.])process\b(?!\s*(?:\??\.|\[))/g, lookups: [] },
];

// `ENV` followed by `.` or `[`, which is how it is read in Ruby and rarely how
// the word appears anywhere else.
const RUBY_SPELLED: EnvironmentAccess[] = [
  {
    use: /(?<![\w$@%.-])ENV(?=[ \t]*\[|\.)/g,
    lookups: [
      lookup(`[ \\t]*\\[\\s*${QUOTED_NAME}\\s*\\]`),
      lookup(`\\.fetch[(\\s]\\s*${QUOTED_NAME}`),
    ],
  },
];

// A bare `ENV` (`p ENV`), read only when the program is known to be Ruby: in a
// shell command or another language the word is too common.
const RUBY_BARE: EnvironmentAccess[] = [
  {
    use: /(?<![\w$@%.-])ENV\b(?![ \t]*\[|\.)/g,
    lookups: [],
  },
];

const PERL: EnvironmentAccess[] = [
  // `%ENV`, `\%ENV` and a slice `@ENV{…}` are the whole hash.
  { use: /[%@]ENV\b/g, lookups: [] },
  {
    use: /\$ENV(?=\s*\{)/g,
    lookups: [
      lookup(`\\s*\\{\\s*${QUOTED_NAME}\\s*\\}`),
      lookup(`\\s*\\{\\s*(?<name>${NAME})\\s*\\}`),
    ],
  },
];

const PHP: EnvironmentAccess[] = [
  {
    // `getenv()` with no name returns every variable.
    use: /\bgetenv\b/g,
    lookups: [lookup(`\\s*\\(\\s*${QUOTED_NAME}`)],
  },
  {
    // The CLI copies the environment into `$_SERVER`, and into `$_ENV` when
    // `variables_order` asks for it.
    use: /\$_(?:ENV|SERVER)\b/g,
    lookups: [lookup(`\\s*\\[\\s*${QUOTED_NAME}\\s*\\]`)],
  },
  // `$GLOBALS['_SERVER']` is `$_SERVER` again.
  { use: /\$GLOBALS\b/g, lookups: [] },
  { use: /\bphpinfo\b/g, lookups: [] },
];

// The language each interpreter in INLINE_CODE_COMMANDS speaks, apart from the
// shells, whose programs bash-commands.ts reads as command lines.
const LANGUAGE_RULES: Record<string, EnvironmentAccess[]> = {
  python: PYTHON,
  python3: PYTHON,
  node: [...JAVASCRIPT, ...JAVASCRIPT_PROCESS],
  deno: [...JAVASCRIPT, ...JAVASCRIPT_PROCESS],
  bun: [...JAVASCRIPT, ...JAVASCRIPT_PROCESS],
  ruby: [...RUBY_SPELLED, ...RUBY_BARE],
  perl: PERL,
  php: PHP,
};

// The interpreters whose programs are read here, for the test that keeps this
// table in step with INLINE_CODE_COMMANDS.
export const PROGRAM_INTERPRETERS = Object.keys(LANGUAGE_RULES);

// A program whose language is not known, such as a tool's `code` field, is read
// with every language's rules but the bare Ruby `ENV` and JavaScript `process`.
const ANY_LANGUAGE: EnvironmentAccess[] = [
  ...PYTHON,
  ...JAVASCRIPT,
  ...RUBY_SPELLED,
  ...PERL,
  ...PHP,
];

// Whether `program` prints the whole environment, and the variables it reads by
// name. `interpreter` is the command that runs it, or null when that is not
// known. A shell, or a command that is not an interpreter, reads nothing here.
export interface ProgramEnvironment {
  dumps: boolean;
  named: string[];
}

export function inspectProgramEnvironment(
  interpreter: string | null,
  program: string,
): ProgramEnvironment {
  let rules = ANY_LANGUAGE;
  if (interpreter !== null) {
    if (!Object.hasOwn(LANGUAGE_RULES, interpreter))
      return { dumps: false, named: [] };
    rules = LANGUAGE_RULES[interpreter] as EnvironmentAccess[];
  }

  const readings: [EnvironmentAccess[], string][] = [[rules, program]];
  const imports = program.match(FROM_OS_IMPORT);
  if ((interpreter === null || rules === PYTHON) && imports !== null) {
    readings.push([
      [...PYTHON_IMPORTED, ...importedAliases(imports)],
      program.replace(FROM_OS_IMPORT, ""),
    ]);
  }

  const named = new Set<string>();
  for (const [accesses, text] of readings) {
    for (const { use, lookups } of accesses) {
      for (const found of text.matchAll(use)) {
        const end = found.index + found[0].length;
        let name: string | undefined;
        for (const read of lookups) {
          read.lastIndex = end;
          name = read.exec(text)?.groups?.["name"];
          if (name !== undefined) break;
        }
        if (name === undefined) return { dumps: true, named: [] };
        named.add(name);
      }
    }
  }
  return { dumps: false, named: [...named] };
}

// Add what `interpreter` running `program` does with the environment to `refs`.
export function addProgramEnvironment(
  refs: CommandRefs,
  interpreter: string | null,
  program: string,
): void {
  const environment = inspectProgramEnvironment(interpreter, program);
  if (environment.dumps) refs.dumpsEnvironment = true;
  refs.envVars.push(...environment.named);
}

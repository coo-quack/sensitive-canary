import { describe, expect, it } from "vitest";
import { INLINE_CODE_COMMANDS, POSIX_SHELLS } from "../command-tables.ts";
import {
  inspectProgramEnvironment,
  PROGRAM_INTERPRETERS,
} from "../program-environment.ts";

// Every program marked as a dump or naming TOKEN printed the value of a
// variable exported into a clean environment when run by python3, node, bun,
// ruby, perl or php; `$_ENV` is the exception, empty under PHP's default
// `variables_order` and read anyway.
describe("inspectProgramEnvironment", () => {
  it.each([
    ["python3", "import os; print(os.environ)"],
    ["python3", "import os; print(dict(os.environ))"],
    ["python", "import os; print(os.environb)"],
    ["python3", "import os; [print(v) for v in os.environ.values()]"],
    ["python3", "import os; k = 'TOKEN'; print(os.environ[k])"],
    ["python3", "import os; print(os.getenv(name))"],
    ["python3", "from os import environ; print(environ)"],
    ["python3", "import os as o; print(o.environ)"],
    ["python3", "import os; print(os. environ)"],
    ["python3", 'import os; x = os.environ\n["TOKEN"]; print(x)'],
    ["node", "console.log(process?.env)"],
    ["node", "console.log(process . env)"],
    ["node", "console.log(process?.['env'])"],
    ["ruby", 'x = ENV\n["TOKEN"]; p x'],
    ["php", "print_r($GLOBALS['_SERVER']);"],
    ["python3", "from os import environ as e; print(e)"],
    ["python3", "from os import getenv as g; print(g(k))"],
    ["node", "console.log(process)"],
    ["node", "const p = process; console.log(p.env)"],
    ["node", 'console.log(require("process"))'],
    ["python3", 'print(__import__("os").environ)'],
    ["python3", "from os import environ as e; print(environ.copy())"],
    ["node", "console.log(process.env)"],
    ["node", "process.env"],
    ["node", "console.log(JSON.stringify(process.env))"],
    ["node", "console.log(process.env[name])"],
    ["node", "console.log(process.env.toString())"],
    ["node", "const {env} = process; console.log(env)"],
    ["node", "const { env: e } = require('node:process'); console.log(e)"],
    ["node", "console.log(require('process').env)"],
    ["node", "console.log(process['env'])"],
    ["bun", "console.log(Bun.env)"],
    ["bun", "console.log(import.meta.env)"],
    ["deno", "console.log(Deno.env.toObject())"],
    ["ruby", "p ENV"],
    ["ruby", "p ENV.to_h"],
    ["ruby", "ENV.each { |k, v| puts v }"],
    ["ruby", "puts ENV[name]"],
    ["perl", "print %ENV"],
    ["perl", 'print "$_=$ENV{$_}\\n" for keys %ENV'],
    ["perl", "print join ',', @ENV{qw(A B)}"],
    ["php", "print_r(getenv());"],
    ["php", "print_r($_SERVER);"],
    ["php", "print_r($_ENV);"],
    ["php", "echo $_SERVER[$k];"],
    ["php", "phpinfo();"],
  ])("%s %j dumps the environment", (interpreter, program) => {
    expect(inspectProgramEnvironment(interpreter, program)).toEqual({
      dumps: true,
      named: [],
    });
  });

  it.each([
    ["python3", 'import os; print(os.environ["TOKEN"])', ["TOKEN"]],
    ["python3", "import os; print(os.environ.get('TOKEN', ''))", ["TOKEN"]],
    ["python3", 'import os; print(os.getenv("TOKEN"))', ["TOKEN"]],
    ["python3", 'from os import environ\nprint(environ["TOKEN"])', ["TOKEN"]],
    ["python3", "from os import getenv; print(getenv('TOKEN'))", ["TOKEN"]],
    ["python3", "from os import environ as e\nprint(e['TOKEN'])", ["TOKEN"]],
    ["node", "process.env.TOKEN", ["TOKEN"]],
    ["node", "process?.env?.TOKEN", ["TOKEN"]],
    ["deno", "Deno.env.get('TOKEN')", ["TOKEN"]],
    ["node", "console.log(process.env?.TOKEN)", ["TOKEN"]],
    [
      "node",
      'console.log(process.env["TOKEN"], process.env.HOME)',
      ["TOKEN", "HOME"],
    ],
    ["deno", 'console.log(Deno.env.get("TOKEN"))', ["TOKEN"]],
    ["ruby", 'puts ENV["TOKEN"]', ["TOKEN"]],
    ["ruby", "puts ENV.fetch('TOKEN')", ["TOKEN"]],
    ["perl", "print $ENV{TOKEN}", ["TOKEN"]],
    ["perl", 'print $ENV{"TOKEN"}', ["TOKEN"]],
    ["php", 'echo getenv("TOKEN");', ["TOKEN"]],
    ["php", "echo $_SERVER['TOKEN'];", ["TOKEN"]],
  ])("%s %j reads %j", (interpreter, program, named) => {
    expect(inspectProgramEnvironment(interpreter, program)).toEqual({
      dumps: false,
      named,
    });
  });

  it.each([
    ["python3", "print(1)"],
    ["python3", "environ = {}; print(environ)"],
    ["node", "console.log(env)"],
    ["node", "process.exit(0)"],
    ["node", "require('child_process').execSync('ls')"],
    ["ruby", "puts ENVIRONMENT"],
    ["perl", "print $ENVX"],
    ["bash", "echo process.env; p ENV"],
    ["sh", "printenv"],
    ["cat", "os.environ"],
  ])("%s %j reads nothing", (interpreter, program) => {
    expect(inspectProgramEnvironment(interpreter, program)).toEqual({
      dumps: false,
      named: [],
    });
  });

  // A program in a language the hook is not told, such as a tool's code field.
  describe("with no interpreter", () => {
    it.each([
      "print(os.environ)",
      "console.log(process.env)",
      "p ENV.to_h",
      "print %ENV",
      "print_r(getenv());",
      "from os import environ; print(environ)",
      "const {env} = process",
    ])("%j dumps the environment", (program) => {
      expect(inspectProgramEnvironment(null, program).dumps).toBe(true);
    });

    it.each([
      ['print(os.environ["TOKEN"])', ["TOKEN"]],
      ["process.env.TOKEN", ["TOKEN"]],
      ['ENV["TOKEN"]', ["TOKEN"]],
    ])("%j reads %j", (program, named) => {
      expect(inspectProgramEnvironment(null, program)).toEqual({
        dumps: false,
        named,
      });
    });

    // A bare `ENV`, and `process` itself, are too common words outside Ruby
    // and JavaScript.
    it.each([
      "p ENV",
      "docker run -e ENV=prod app",
      "echo ENV",
      "process = subprocess.run(cmd)\nprint(process.stdout)",
    ])("%j reads nothing", (program) => {
      expect(inspectProgramEnvironment(null, program).dumps).toBe(false);
    });
  });
});

// Two drafts of these rules were quadratic: `\s*` on both sides of an optional
// `?.` split a run of blanks every way there is, and `[^{}]*` on both sides of
// `env` in a destructuring pattern did the same to a long brace. 320 KB of
// either took over a minute, long enough for the hook to be killed and the call
// let through. Fixed, each takes milliseconds; the limit sits far from both.
describe("adversarial inputs", () => {
  it.each([
    [null, `process${" ".repeat(320_000)}`],
    ["node", `process${" ".repeat(320_000)}`],
    ["node", `{${"env ".repeat(80_000)}`],
    [null, `{${"env ".repeat(80_000)}`],
  ])(
    "%s stays near-linear on %#",
    (interpreter, program) => {
      const start = performance.now();
      inspectProgramEnvironment(interpreter, program);
      expect(performance.now() - start).toBeLessThan(10_000);
    },
    30_000,
  );
});

// The table has a rule set for every interpreter that is not a shell, and for
// nothing else.
it("reads every interpreter in INLINE_CODE_COMMANDS but the shells", () => {
  expect([...PROGRAM_INTERPRETERS].sort()).toEqual(
    [...INLINE_CODE_COMMANDS].filter((c) => !POSIX_SHELLS.has(c)).sort(),
  );
});

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { TOOLS_WITHOUT_FILE_OUTPUT } from "../lib/tool-inputs.ts";
import {
  AWS_KEY,
  runGrepHook,
  runToolHook,
  TOKEN_VALUE,
  useFixtureDir,
} from "./hook-harness.ts";

const writeFixture = useFixtureDir("tool-inputs");

describe("pre-tool-use-hook — Grep and MCP tool inputs", () => {
  describe("Grep tool", () => {
    it("should block on file with secret", () => {
      const file = writeFixture("grep_tool.txt", `key=${AWS_KEY}`);
      const result = runGrepHook(file);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("should allow on clean file", () => {
      const file = writeFixture("clean_grep.txt", "normal content");
      const result = runGrepHook(file);
      expect(result.exitCode).toBe(0);
    });

    it("should block on .env file", () => {
      const file = writeFixture(".env", `TOKEN=${TOKEN_VALUE}`);
      const result = runGrepHook(file);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // Isolated subdirectories rather than the shared fixture dir, which by this
    // point holds a `.env` another test wrote.
    it("blocks on a directory holding a secret", () => {
      const dir = writeFixture.path("grep-dir-secret");
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "config.txt"), `key=${AWS_KEY}`, "utf8");
      const result = runGrepHook(dir);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("allows a directory of clean files", () => {
      const dir = writeFixture.path("grep-dir-clean");
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "notes.txt"), "nothing to see", "utf8");
      writeFileSync(join(dir, "readme.md"), "# hello", "utf8");
      const result = runGrepHook(dir);
      expect(result.exitCode).toBe(0);
    });

    it("should allow on non-existent path", () => {
      const result = runGrepHook(writeFixture.path("nonexistent.txt"));
      expect(result.exitCode).toBe(0);
    });

    // The sweep skips binaries so that a folder of images is not ground through
    // every rule, and that skip ran before the name guard. Eight bytes at the
    // head of a `.env` were enough to drop it out of the sweep, which took the
    // strongest guard in the tool with it. The name is judged whatever the bytes
    // look like; it is the contents that the guard stops trusting.
    it("blocks a .env whose bytes look binary", () => {
      const dir = writeFixture.path("grep-dir-nul-env");
      mkdirSync(dir, { recursive: true });
      writeFileSync(
        join(dir, ".env"),
        Buffer.concat([
          Buffer.from([0, 1, 2, 3, 0, 5, 0, 7]),
          Buffer.from(`TOKEN=${TOKEN_VALUE}\n`),
        ]),
      );
      const result = runGrepHook(dir);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // `Grep {pattern}` with no `path` is the form Claude reaches for first, and
    // it searches wherever the tool runs. With no field to collect there was
    // nothing to scan, so the directory the search prints from was the one
    // directory never looked at.
    it("blocks a pathless search when a .env sits where it runs", () => {
      const dir = writeFixture.path("grep-nopath-env");
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, ".env"), `TOKEN=${TOKEN_VALUE}\n`, "utf8");
      const result = runToolHook("Grep", { pattern: "TODO" }, { cwd: dir });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // Names only, and this is the case that says so. A directory nobody named is
    // every repository anyone searches; content-scanning those stopped a plain
    // `rg TODO` in a third of the checkouts it was measured against, because a
    // changelog quoting a connection string is enough.
    it("allows a pathless search over ordinary files that mention secrets", () => {
      const dir = writeFixture.path("grep-nopath-prose");
      mkdirSync(dir, { recursive: true });
      writeFileSync(
        join(dir, "CHANGELOG.md"),
        `- redact a key such as ${AWS_KEY} in the terminal\n`,
        "utf8",
      );
      const result = runToolHook("Grep", { pattern: "TODO" }, { cwd: dir });
      expect(result.exitCode).toBe(0);
    });

    // A path that was named keeps the content scan: the user pointed at the
    // directory, and reading it is answering what they asked.
    it("still content-scans a directory the search names", () => {
      const dir = writeFixture.path("grep-named-prose");
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "notes.md"), `key=${AWS_KEY}\n`, "utf8");
      const result = runGrepHook(dir);
      expect(result.exitCode).toBe(2);
    });

    // The other direction, so the case above is not passing on the sweep having
    // stopped skipping binaries altogether.
    it("still allows a directory of binaries with no env name", () => {
      const dir = writeFixture.path("grep-dir-binaries");
      mkdirSync(dir, { recursive: true });
      for (const name of ["a.bin", "b.bin", "c.bin"]) {
        writeFileSync(
          join(dir, name),
          Buffer.from([0, 1, 2, 3, 0, 255, 0, 7, 9, 0, 0, 0, 254, 0, 3]),
        );
      }
      const result = runGrepHook(dir);
      expect(result.exitCode).toBe(0);
    });
  });

  describe("other tools and MCP", () => {
    it("mcp__filesystem__read_text_file should block on secret", () => {
      const file = writeFixture("mcp_secret.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__filesystem__read_text_file", {
        path: file,
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("mcp tool with nested path should block", () => {
      const file = writeFixture("mcp_nested.txt", `secret=${TOKEN_VALUE}`);
      const result = runToolHook("mcp__example__tool", {
        arguments: { file_path: file },
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("mcp tool with path objects inside an array should block", () => {
      const file = writeFixture("mcp_array.txt", `secret=${TOKEN_VALUE}`);
      const result = runToolHook("mcp__example__tool", {
        paths: [{ path: file }],
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // A distinct shape from the array of objects above, reached by a different
    // branch of the collector.
    it("mcp tool with an array of path strings should block", () => {
      const file = writeFixture("mcp_str_array.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__example__tool", { paths: [file] });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // Field names are compared with separators and case removed, so a tool
    // spelling the same field differently is still seen. Listing the spellings
    // meant `file_path` and `filePath` were covered and `filepath` was not.
    it.each([
      ["filepath", "alias_filepath.txt"],
      ["FILE_PATH", "alias_shout.txt"],
      ["filename", "alias_filename.txt"],
      ["source_path", "alias_source.txt"],
      ["absolutePath", "alias_abs_camel.txt"],
    ])("mcp tool naming the field %s should block", (field, fixture) => {
      const file = writeFixture(fixture, `key=${AWS_KEY}`);
      const result = runToolHook("mcp__example__tool", { [field]: file });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("mcp tool with a path four levels down should block", () => {
      const file = writeFixture("mcp_deep.txt", `secret=${TOKEN_VALUE}`);
      const result = runToolHook("mcp__example__tool", {
        a: { b: { c: { path: file } } },
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // The bound is there so a deeply nested input cannot make the hook walk an
    // arbitrary tree before a tool call; past it, a path is not found.
    it("mcp tool with a path below the depth bound should allow", () => {
      const file = writeFixture("mcp_too_deep.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__example__tool", {
        a: { b: { c: { d: { e: { path: file } } } } },
      });
      expect(result.exitCode).toBe(0);
    });

    // The field-name list can only hold names someone thought of, so a value
    // shaped like a path is collected whatever its field is called.
    it.each(["target", "document", "uri", "input", "attachment"])(
      "mcp tool naming an absolute path under %s should block",
      (field) => {
        const file = writeFixture(`shape_${field}.txt`, `key=${AWS_KEY}`);
        const result = runToolHook("mcp__example__tool", { [field]: file });
        expect(result.exitCode).toBe(2);
        expect(result.blocked).toBe(true);
      },
    );

    it("mcp tool with an unlisted field holding an array of paths should block", () => {
      const file = writeFixture("shape_array.txt", `secret=${TOKEN_VALUE}`);
      const result = runToolHook("mcp__example__tool", { args: [file] });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // The other half of that rule, and the reason it is not "any string": a
    // search pattern is not a path. `.env` exists in most checkouts, so
    // collecting every string would block a search for the text `.env` as
    // though it were a read of the file.
    it("a search pattern that names an existing file should allow", () => {
      writeFixture(".env", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__example__search", { pattern: ".env" });
      expect(result.exitCode).toBe(0);
    });

    it("a bare word under an unlisted field should allow", () => {
      writeFixture("secrets", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__example__search", { query: "secrets" });
      expect(result.exitCode).toBe(0);
    });

    it("mcp tool with nonexistent path should allow", () => {
      const result = runToolHook("mcp__example__tool", {
        path: "/api/v1/users",
      });
      expect(result.exitCode).toBe(0);
    });

    it("Write tool should allow (write operations are not checked)", () => {
      const file = writeFixture("write_target.txt", "");
      const result = runToolHook("Write", {
        file_path: file,
        content: "x",
      });
      expect(result.exitCode).toBe(0);
    });

    it("Glob tool should allow (not checked)", () => {
      const file = writeFixture("glob_target.txt", `key=${AWS_KEY}`);
      const result = runToolHook("Glob", {
        pattern: "*.ts",
        path: file,
      });
      expect(result.exitCode).toBe(0);
    });

    it("TodoWrite tool should allow (not checked)", () => {
      const result = runToolHook("TodoWrite", {
        todos: [],
      });
      expect(result.exitCode).toBe(0);
    });
  });

  describe("write-shaped MCP tools are exempt", () => {
    it("mcp__fs__write_file should allow", () => {
      const file = writeFixture("mcp_write.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__fs__write_file", {
        path: file,
        contents: "x",
      });
      expect(result.exitCode).toBe(0);
    });

    it("mcp__fs__move_file should allow", () => {
      const file = writeFixture("mcp_move.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__fs__move_file", { path: file });
      expect(result.exitCode).toBe(0);
    });

    it("mcp__fs__read_file should still block", () => {
      const file = writeFixture("mcp_read.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__fs__read_file", { path: file });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // A run of capitals is one word. Splitting on every capital left
    // `WRITE_FILE` as single letters, so its first word was `W` and a write tool
    // was scanned like a read.
    it.each(["WRITE_FILE", "UPDATE-FILE", "copyFile"])(
      "%s should allow",
      (tool) => {
        const file = writeFixture(`caps_${tool}.txt`, `key=${AWS_KEY}`);
        const result = runToolHook(`mcp__fs__${tool}`, { path: file });
        expect(result.exitCode).toBe(0);
      },
    );

    it("mcp__fs__READ_FILE should still block", () => {
      const file = writeFixture("caps_read.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__fs__READ_FILE", { path: file });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // The write-name heuristic matches the tool component only: a server named
    // "editor" or "readwrite" must not exempt the read tools it offers.
    it("mcp__editor__read_file should block (server name is not the tool name)", () => {
      const file = writeFixture("mcp_editor.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__editor__read_file", { path: file });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("mcp__readwrite__read_file should block (server name is not the tool name)", () => {
      const file = writeFixture("mcp_readwrite.txt", `key=${TOKEN_VALUE}`);
      const result = runToolHook("mcp__readwrite__read_file", { path: file });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // The exemption needs the verb to lead the name. As a substring test each of
    // these read a file while being treated as a tool that only writes.
    it("mcp__x__get_updates should block: it reads", () => {
      const file = writeFixture("mcp_get_updates.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__x__get_updates", { path: file });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("mcp__x__read_and_write_file should block: it reads too", () => {
      const file = writeFixture("mcp_read_and_write.txt", `key=${TOKEN_VALUE}`);
      const result = runToolHook("mcp__x__read_and_write_file", { path: file });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("mcp__x__readwrite should block", () => {
      const file = writeFixture("mcp_rw.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__x__readwrite", { path: file });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("mcp__x__createPage should allow (camelCase write verb leads)", () => {
      const file = writeFixture("mcp_camel.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__x__createPage", { path: file });
      expect(result.exitCode).toBe(0);
    });

    it("TodoWrite stays exempt through the explicit list", () => {
      const file = writeFixture("todo_write.txt", `key=${AWS_KEY}`);
      const result = runToolHook("TodoWrite", { path: file });
      expect(result.exitCode).toBe(0);
    });

    // One case per entry, generated, so an entry added here brings its own and
    // an entry removed takes its own away. Six of the ten appeared in no test:
    // `MultiEdit`, `NotebookEdit`, `WebFetch`, `WebSearch`, `ExitPlanMode` and
    // `AskUserQuestion`. Four of them — the last three and `Glob` — begin with
    // no write verb, so this list is the only thing exempting them, and their
    // removal would start scanning a tool that returns no file contents.
    it.each([...TOOLS_WITHOUT_FILE_OUTPUT])(
      "%s is not scanned even when its input names a secret-bearing file",
      (tool) => {
        const file = writeFixture(`exempt_${tool}.txt`, `key=${AWS_KEY}`);
        expect(runToolHook(tool, { path: file }).exitCode).toBe(0);
      },
    );

    // A tool that runs a shell takes the command as an input field, and only
    // `Bash` was ever read as one. With the default matcher sending every
    // `mcp__*` tool here, an MCP shell server handed its command straight past.
    it.each(["command", "cmd", "script", "shell_command", "commandLine"])(
      "a %s field is read as a command line",
      (field) => {
        const file = writeFixture(`cmdfield_${field}.txt`, `key=${AWS_KEY}`);
        const result = runToolHook("mcp__shell__run", {
          [field]: `cat ${file}`,
        });
        expect(result.exitCode).toBe(2);
      },
    );

    // Code is not a command line: the path is a quoted literal in it.
    it("a code field is read for the paths quoted inside it", () => {
      const file = writeFixture("codefield.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__ide__executeCode", {
        code: `print(open("${file}").read())`,
      });
      expect(result.exitCode).toBe(2);
    });

    // A tool that runs a shell prints an environment as readily as a file. The
    // Bash branch has always scanned the variables a command would print; a
    // command field was collected for paths and nothing else, so `printenv`
    // handed the environment back whole.
    it("a command field is scanned for the environment it would print", () => {
      const result = runToolHook(
        "mcp__shell__run",
        { command: "printenv" },
        {
          env: { PATH: process.env["PATH"] ?? "", LEAKED: AWS_KEY },
          replaceEnv: true,
        },
      );
      expect(result.exitCode).toBe(2);
    });

    it("a command field naming one variable is scanned for that variable", () => {
      const result = runToolHook(
        "mcp__shell__run",
        { command: "echo $LEAKED" },
        {
          env: { PATH: process.env["PATH"] ?? "", LEAKED: AWS_KEY },
          replaceEnv: true,
        },
      );
      expect(result.exitCode).toBe(2);
    });

    // The write-verb exemption covers a tool's output, not what it runs.
    it("a write-verb name does not exempt the command it is given", () => {
      const file = writeFixture("createproc.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__x__create_process", {
        command: `cat ${file}`,
      });
      expect(result.exitCode).toBe(2);
    });

    it("a write-verb name still exempts the paths it is given", () => {
      const file = writeFixture("writepath.txt", `key=${AWS_KEY}`);
      expect(runToolHook("mcp__fs__write_file", { path: file }).exitCode).toBe(
        0,
      );
    });

    // An argv array is a command line with the spaces taken out. Deleting this
    // branch entirely left every test passing.
    it("a command given as an argv array is scanned", () => {
      const file = writeFixture("argv.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__shell__exec", {
        command: ["cat", file],
      });
      expect(result.exitCode).toBe(2);
    });

    it("an argv array joins into one line rather than one token", () => {
      const result = runToolHook(
        "mcp__shell__exec",
        { command: ["echo", "$LEAKED"] },
        {
          env: { PATH: process.env["PATH"] ?? "", LEAKED: AWS_KEY },
          replaceEnv: true,
        },
      );
      expect(result.exitCode).toBe(2);
    });

    it("an argv array of non-strings is not a command", () => {
      expect(
        runToolHook("mcp__shell__exec", { command: [1, 2, 3] }).exitCode,
      ).toBe(0);
    });

    // One normalization for both collectors. The command side dropped only
    // `-` and `_`, so a field called `command.line` was walked past while the
    // path side read `file.path` correctly.
    it.each([
      "command",
      "command_line",
      "command-line",
      "commandLine",
      "command.line",
      "command line",
      "COMMAND LINE",
    ])("a field called %s is a command", (key) => {
      const file = writeFixture("named.txt", `key=${AWS_KEY}`);
      expect(
        runToolHook("mcp__shell__run", { [key]: `cat ${file}` }).exitCode,
      ).toBe(2);
    });

    // Every other tool name reached the shared collector and blocked; the Read
    // branch coerced a non-string to "" and exited 0. The same shape, two
    // answers.
    it.each([
      ["an array", (p: string) => [p]],
      ["an object", (p: string) => ({ inner: p })],
      ["an array of objects", (p: string) => [{ path: p }]],
    ])("Read with a file_path that is %s is still read", (_label, shape) => {
      const file = writeFixture("readshape.txt", `key=${AWS_KEY}`);
      expect(runToolHook("Read", { file_path: shape(file) }).exitCode).toBe(2);
    });

    // A tool wraps its arguments, so the search goes into them. Only the top
    // level had a test, and the depth limit could be set to zero unnoticed.
    it.each([
      [1, { args: { command: "cat FILE" } }],
      [2, { params: { args: { command: "cat FILE" } } }],
      [3, { a: { b: { c: { command: "cat FILE" } } } }],
    ])("a command nested %i deep is scanned", (_depth, shape) => {
      const file = writeFixture("nested.txt", `key=${AWS_KEY}`);
      const input = JSON.parse(
        JSON.stringify(shape).replace("cat FILE", `cat ${file}`),
      ) as Record<string, unknown>;
      expect(runToolHook("mcp__shell__run", input).exitCode).toBe(2);
    });

    // A field that is not one of those names is not run through the parser.
    it("a query field is not read as a command", () => {
      const file = writeFixture("queryfield.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__search__find", {
        query: `cat ${file}`,
      });
      expect(result.exitCode).toBe(0);
    });

    // The same input under a tool that is on neither list is scanned, which is
    // what says the cases above are measuring the exemption rather than
    // something about the payload.
    it("a tool on neither list is scanned for the same input", () => {
      const file = writeFixture("not_exempt.txt", `key=${AWS_KEY}`);
      expect(runToolHook("SomeOtherTool", { path: file }).exitCode).toBe(2);
    });
  });
});

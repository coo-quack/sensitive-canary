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

    it("should allow on directory path (known limitation)", () => {
      const result = runGrepHook(writeFixture.path());
      expect(result.exitCode).toBe(0);
    });

    it("should allow on non-existent path", () => {
      const result = runGrepHook(writeFixture.path("nonexistent.txt"));
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

    // The same input under a tool that is on neither list is scanned, which is
    // what says the cases above are measuring the exemption rather than
    // something about the payload.
    it("a tool on neither list is scanned for the same input", () => {
      const file = writeFixture("not_exempt.txt", `key=${AWS_KEY}`);
      expect(runToolHook("SomeOtherTool", { path: file }).exitCode).toBe(2);
    });
  });
});

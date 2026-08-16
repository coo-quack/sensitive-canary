// What Claude Code is told to run, and for which tools.
//
// The hook can be perfect and reach nothing. `hooks.json` is the only thing
// that decides whether the runtime calls it, and until now no test read it: a
// tool name dropped from the matcher, or a path that no longer resolves, would
// ship and every other test in this suite would still pass. The install guide
// exists because that failure is silent; so does this file.

import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { TOOLS_WITHOUT_FILE_OUTPUT } from "../lib/tool-inputs.ts";
import { runToolHook } from "./hook-harness.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const readJson = (relative: string): Record<string, unknown> =>
  JSON.parse(readFileSync(join(ROOT, relative), "utf8"));

interface HookCommand {
  type?: string;
  command?: string;
}
interface HookEntry {
  matcher?: string;
  hooks?: HookCommand[];
}

const manifest = readJson("hooks/hooks.json");
const events = manifest["hooks"] as Record<string, HookEntry[]>;

describe("hooks.json", () => {
  it("registers both events", () => {
    expect(Object.keys(events).sort()).toEqual([
      "PreToolUse",
      "UserPromptSubmit",
    ]);
  });

  // The path Claude Code will run. `${CLAUDE_PLUGIN_ROOT}` is the checkout, so
  // the file has to exist relative to this repository under the same name.
  it.each(Object.entries(events))(
    "%s runs a file that exists",
    (_event, entries) => {
      for (const entry of entries) {
        for (const hook of entry.hooks ?? []) {
          expect(hook.type).toBe("command");
          const script = /\$\{CLAUDE_PLUGIN_ROOT\}\/([^"']+)/.exec(
            hook.command ?? "",
          )?.[1];
          expect(script, hook.command).toBeDefined();
          expect(isAbsolute(script ?? "x")).toBe(false);
          expect(existsSync(join(ROOT, script ?? "")), script).toBe(true);
        }
      }
    },
  );

  // Every tool the hook has something to say about has to reach it. The matcher
  // is a regular expression over the tool name, so it is tested by running the
  // names rather than by reading it.
  const matcher = new RegExp(
    `^(?:${(events["PreToolUse"] ?? [])[0]?.matcher ?? "(?!)"})$`,
  );

  it.each([
    "Read",
    "Bash",
    "Grep",
    "mcp__filesystem__read_text_file",
    "mcp__desktop-commander__start_process",
  ])("%s reaches the hook", (tool) => {
    expect(matcher.test(tool)).toBe(true);
  });

  // The other direction, so the matcher is not quietly `.*`: a tool that only
  // writes has nothing to leak, and sending every call here would cost a
  // process spawn on each one.
  it.each([...TOOLS_WITHOUT_FILE_OUTPUT].filter((t) => !t.startsWith("mcp__")))(
    "%s does not",
    (tool) => {
      expect(matcher.test(tool)).toBe(false);
    },
  );

  // A tool the matcher lets through must actually be handled, not merely
  // reached. `Grep` was in the matcher long before its pathless form was
  // scanned.
  it.each(["Read", "Grep"])("%s is handled once it arrives", (tool) => {
    const result = runToolHook(tool, { pattern: "x", path: ROOT });
    expect(result.exitCode === 0 || result.exitCode === 2).toBe(true);
  });
});

describe("plugin.json", () => {
  const plugin = readJson(".claude-plugin/plugin.json");
  const pkg = readJson("package.json");

  it("declares the same version as package.json", () => {
    expect(plugin["version"]).toBe(pkg["version"]);
  });

  it("declares a version at all", () => {
    expect(String(plugin["version"])).toMatch(/^\d+\.\d+\.\d+(?:[-+].*)?$/);
  });

  it("names the package this repository publishes", () => {
    expect(plugin["name"]).toBe(String(pkg["name"]).replace(/^@[^/]+\//, ""));
  });
});

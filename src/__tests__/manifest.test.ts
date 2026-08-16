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
import {
  PATH_FIELD_NAMES,
  TOOLS_WITHOUT_FILE_OUTPUT,
} from "../lib/tool-inputs.ts";
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
  //
  // Both ways of applying it. Whether Claude Code anchors the match is not
  // something this repository can check, and the difference is not academic:
  // unanchored, `NotebookRead` is caught by the substring `Read`, and the
  // `notebook_path` field this hook reads would be reached by accident. Every
  // name that has to arrive is written out, so the answer is the same either
  // way.
  const source = (events["PreToolUse"] ?? [])[0]?.matcher ?? "(?!)";
  const anchored = new RegExp(`^(?:${source})$`);
  const matcher = new RegExp(source);

  it.each([
    "Read",
    "NotebookRead",
    "Bash",
    "Grep",
    "mcp__filesystem__read_text_file",
    "mcp__desktop-commander__start_process",
  ])("%s reaches the hook however the matcher is applied", (tool) => {
    expect(anchored.test(tool), "anchored").toBe(true);
    expect(matcher.test(tool), "unanchored").toBe(true);
  });

  // A field the hook knows how to read belongs to a tool that can reach it.
  // `notebook_path` was handled long before anything said `NotebookRead` was
  // meant to arrive.
  it("the notebook path field belongs to a tool the matcher names", () => {
    expect(PATH_FIELD_NAMES.has("notebookpath")).toBe(true);
    expect(source).toContain("NotebookRead");
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

// The install guide is a second manifest, kept by hand. A plugin install reads
// `hooks/hooks.json`; an npm or from-source install is whatever the reader
// copied out of the documentation, and the two are only the same while someone
// remembers. They were not: `NotebookRead` was added to the matcher and to the
// tests above, and all four documented snippets kept the matcher without it —
// green here, and a narrower guard for everyone who installs by the guide.
//
// README.md ships inside the npm package, so a stale snippet there is published
// rather than merely posted.
describe("the documented matcher", () => {
  const matcher = (events["PreToolUse"] ?? [])[0]?.matcher ?? "";

  it.each(["README.md", "docs/install.md"])(
    "%s registers the matcher hooks.json declares",
    (relative) => {
      const text = readFileSync(join(ROOT, relative), "utf8");
      const quoted = [...text.matchAll(/"matcher":\s*"([^"]+)"/g)].map(
        (m) => m[1],
      );
      // A guide that stopped showing a matcher would otherwise pass by having
      // nothing to disagree with.
      expect(quoted.length).toBeGreaterThan(0);
      for (const found of quoted) expect(found).toBe(matcher);
    },
  );

  // The prose beside the snippets names the same default. It drifted with them.
  it("README describes the matcher it tells the reader to paste", () => {
    const text = readFileSync(join(ROOT, "README.md"), "utf8");
    expect(text).toContain(`the default (\`${matcher}\`)`);
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

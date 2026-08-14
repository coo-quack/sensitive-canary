// Shared way to run the PreToolUse hook as a child process and read its verdict,
// and to give it a file to read. The hook test files use these so that "run the
// hook" and "write a fixture" each have one meaning and one options shape, rather
// than a same-named helper per file.

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll } from "vitest";

// fileURLToPath rather than `.pathname`, which leaves a checkout under a path
// with spaces percent-encoded and hands `node` a filename that does not exist.
// Exported so the integration test resolves the hook the same way: two copies of
// this line meant one of them could be left behind.
export const HOOK = fileURLToPath(
  new URL("../pre-tool-use-hook.ts", import.meta.url),
);
const NODE_FLAGS = ["--experimental-strip-types"];

export interface RunOptions {
  // Variables to add to the child environment.
  env?: Record<string, string>;
  // Use `env` as the whole child environment instead of adding to the parent's.
  // Include PATH when setting this, or `node` will not be found.
  replaceEnv?: boolean;
  // Transcript the hook should read allow tags from.
  transcriptPath?: string;
  // The directory the tool runs in, as the runtime reports it. A relative path
  // in a command is relative to this.
  cwd?: string;
}

export interface HookResult {
  // 0 allows the tool call, 2 blocks it.
  exitCode: number;
  stdout: string;
  stderr: string;
  // Whether the tool call was blocked. Named for the outcome rather than for the
  // payload it is read from, so a test says what it means and does not have to
  // change if the way a block is returned ever does.
  blocked: boolean;
  // The text Claude receives on a block. Read from stderr, which is where a
  // hook exiting 2 is heard; on an allowed call there is none, so a config
  // warning printed to stderr is not mistaken for a reason.
  reason: string | null;
}

// A hook that never returns is a fail-open in production, where Claude Code's
// PreToolUse timeout kills it and lets the call through. `spawnSync` blocks the
// worker, so without a limit here the same hang stops the test run rather than
// failing it, and vitest's per-test timeout cannot interrupt it. A killed run
// reports no status, which becomes -1 and fails whatever the test expected.
const HOOK_TIMEOUT_MS = 15_000;

// Spawn the hook with a raw stdin payload and assemble its verdict.
function spawnHook(input: string, opts?: RunOptions): HookResult {
  const result = spawnSync("node", [...NODE_FLAGS, HOOK], {
    input,
    encoding: "utf8",
    env: opts?.replaceEnv ? (opts.env ?? {}) : { ...process.env, ...opts?.env },
    timeout: HOOK_TIMEOUT_MS,
  });
  const exitCode = result.status ?? -1;
  return {
    exitCode,
    stdout: result.stdout,
    stderr: result.stderr,
    blocked: exitCode === 2,
    reason: exitCode === 2 ? result.stderr : null,
  };
}

// Feed the hook a raw stdin payload, for cases where the payload is not valid
// JSON and so cannot be described as a tool call.
export function runHookWithRawInput(input: string): HookResult {
  return spawnHook(input);
}

// Run the hook against an arbitrary tool call.
export function runToolHook(
  toolName: string,
  toolInput: Record<string, unknown>,
  opts?: RunOptions,
): HookResult {
  const input = JSON.stringify({
    transcript_path: opts?.transcriptPath,
    cwd: opts?.cwd,
    tool_name: toolName,
    tool_input: toolInput,
  });
  return spawnHook(input, opts);
}

// A tool call carrying a single `file_path`, as Read does.
export function runHook(
  toolName: string,
  filePath: string,
  opts?: RunOptions,
): HookResult {
  return runToolHook(toolName, { file_path: filePath }, opts);
}

export function runBashHook(command: string, opts?: RunOptions): HookResult {
  return runToolHook("Bash", { command }, opts);
}

export function runGrepHook(searchPath: string, opts?: RunOptions): HookResult {
  return runToolHook("Grep", { pattern: "foo", path: searchPath }, opts);
}

// A temp directory for one test file's fixtures, made before its tests and
// removed after them, with the `writeFixture` that belongs to it.
//
// Three test files opened with the same twenty lines, differing only in the
// mkdtemp prefix. This module already exists so that running the hook has one
// meaning rather than one per file; writing a file for it to scan is the same
// kind of thing.
export interface FixtureWriter {
  // Write a fixture and return its absolute path.
  (name: string, content: string): string;
  // A path inside the directory without writing anything — the directory itself
  // when no name is given. For the cases that need a target which is not a
  // regular file: a directory, or a name that does not exist.
  path(name?: string): string;
}

export function useFixtureDir(label: string): FixtureWriter {
  let dir = "";
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), `sensitive-canary-${label}-`));
  });
  afterAll(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  const write = (name: string, content: string): string => {
    const p = join(dir, name);
    writeFileSync(p, content, "utf8");
    return p;
  };
  return Object.assign(write, {
    path: (name?: string) => (name === undefined ? dir : join(dir, name)),
  });
}

// Assembled so the full strings never appear in a test file's source. The
// integration test deliberately uses neither: a canonical key is recited from
// memory by a live session, which its leak assertion cannot tell from a leak.
export const AWS_KEY = ["AKIA", "IOSFODNN7", "EXAMPLE"].join("");
export const TOKEN_VALUE = [
  "ghp_",
  "1234567890abcdefghij",
  "klmnopqrstuvwxyz",
].join("");

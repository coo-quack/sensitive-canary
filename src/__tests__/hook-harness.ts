// Shared way to run the PreToolUse hook as a child process and read its verdict.
// Both hook test files use it so that "run the hook" has one meaning and one
// options shape, rather than a same-named helper per file.

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

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
  // The text the hook offers Claude on a block, from its stdout payload.
  reason: string | null;
}

// Spawn the hook with a raw stdin payload and assemble its verdict.
function spawnHook(input: string, opts?: RunOptions): HookResult {
  const result = spawnSync("node", [...NODE_FLAGS, HOOK], {
    input,
    encoding: "utf8",
    env: opts?.replaceEnv ? (opts.env ?? {}) : { ...process.env, ...opts?.env },
  });
  const exitCode = result.status ?? -1;
  return {
    exitCode,
    stdout: result.stdout,
    stderr: result.stderr,
    blocked: exitCode === 2,
    reason: parseReason(result.stdout),
  };
}

// The hook's block payload carries the reason it offers Claude. A run that
// allowed the call writes nothing, so there is nothing to parse.
function parseReason(stdout: string): string | null {
  try {
    return (JSON.parse(stdout) as { reason?: string }).reason ?? null;
  } catch {
    return null;
  }
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

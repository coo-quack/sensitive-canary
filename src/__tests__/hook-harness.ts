// Shared way to run the PreToolUse hook as a child process and read its verdict.
// Both hook test files use it so that "run the hook" has one meaning and one
// options shape, rather than a same-named helper per file.

import { spawnSync } from "node:child_process";

const HOOK = new URL("../pre-tool-use-hook.ts", import.meta.url).pathname;
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
  decision: string | null;
  reason: string | null;
}

// Spawn the hook with a raw stdin payload and assemble its verdict.
function spawnHook(input: string, opts?: RunOptions): HookResult {
  const result = spawnSync("node", [...NODE_FLAGS, HOOK], {
    input,
    encoding: "utf8",
    env: opts?.replaceEnv ? (opts.env ?? {}) : { ...process.env, ...opts?.env },
  });
  const { decision, reason } = parseHookOutput(result.stdout);
  return {
    exitCode: result.status ?? -1,
    stdout: result.stdout,
    stderr: result.stderr,
    decision,
    reason,
  };
}

// Feed the hook a raw stdin payload, for cases where the payload is not valid
// JSON and so cannot be described as a tool call.
export function runHookWithRawInput(input: string): HookResult {
  return spawnHook(input);
}

export function parseHookOutput(stdout: string): {
  decision: string | null;
  reason: string | null;
} {
  try {
    const parsed = JSON.parse(stdout) as { decision?: string; reason?: string };
    return { decision: parsed.decision ?? null, reason: parsed.reason ?? null };
  } catch {
    return { decision: null, reason: null };
  }
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

// The only test that exercises the other side of the hook contract.
//
// Every other test spawns the hook and reads its output itself, so the whole
// suite can pass while Claude Code ignores everything the hook says. Nothing
// there distinguishes a channel the runtime reads from one it does not. This
// test runs a real headless session with the hook installed and asserts both
// halves of the contract: the read is stopped, and the reason arrives.
//
// Its negative control was run by hand — a hook that exits 2 with no output at
// all makes the session report only `No stderr output`, and the assertion below
// fails. So the test is not vacuous.
//
// It needs credentials and network, so it is opt-in: set
// SENSITIVE_CANARY_INTEGRATION=1 to run it. CI skips it. Run it by hand when the
// block contract changes — see the "Integration test" section in CONTRIBUTING.md.

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { HOOK } from "./hook-harness.ts";

const ENABLED = process.env["SENSITIVE_CANARY_INTEGRATION"] === "1";

// Not the canonical AKIAIOSFODNN7EXAMPLE the other tests use. That string is
// famous enough that the session recites it from memory when asked about AWS
// keys, and the assertion below cannot tell a recital from a leak. This value
// has the same shape and is not in any model's training data.
const AWS_KEY = ["AKIA", "3QF7ZLM2", "VXKD9WTB"].join("");

// A headless session is a network round trip; give it room.
const TIMEOUT_MS = 180_000;

let dir: string;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "sensitive-canary-integration-"));
  writeFileSync(join(dir, "config.txt"), `aws_key=${AWS_KEY}\n`, "utf8");
  writeFileSync(
    join(dir, "settings.json"),
    JSON.stringify({
      hooks: {
        PreToolUse: [
          {
            matcher: "Read|Bash|Grep|mcp__.*",
            hooks: [
              {
                // A hook command is run by a shell, so the path is quoted: a
                // checkout under a directory with spaces would otherwise arrive
                // as two arguments.
                type: "command",
                command: `node --experimental-strip-types "${HOOK}"`,
              },
            ],
          },
        ],
      },
    }),
    "utf8",
  );
});

afterAll(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
});

// `claude -p` with the hook registered through --settings, run inside the
// fixture directory so the file is a plain relative path in the workspace.
// bypassPermissions keeps the run from stalling on a prompt no one can answer;
// hooks still run, which is the point.
function runHeadless(prompt: string): string {
  const result = spawnSync(
    "claude",
    [
      "-p",
      prompt,
      "--settings",
      join(dir, "settings.json"),
      "--permission-mode",
      "bypassPermissions",
    ],
    { encoding: "utf8", cwd: dir, timeout: TIMEOUT_MS },
  );

  // A session that never ran would satisfy the leak assertion for the wrong
  // reason — no output cannot contain a secret — and then fail the second one
  // with nothing to explain why. Say so here instead, and separate the ways it
  // can happen: a missing CLI, a run that never came back, and a run that came
  // back unhappy each need a different thing done about them.
  const error = result.error as (Error & { code?: string }) | undefined;
  if (error?.code === "ENOENT") {
    throw new Error(
      "`claude` is not on PATH. The integration test drives the real CLI; install it, or leave SENSITIVE_CANARY_INTEGRATION unset to skip.",
    );
  }
  if (error?.code === "ETIMEDOUT") {
    throw new Error(
      `\`claude -p\` did not finish within ${TIMEOUT_MS} ms and was killed. A headless session is a network round trip — check connectivity before raising the timeout.`,
    );
  }
  if (error) {
    throw new Error(`could not run \`claude -p\`: ${error.message}`);
  }

  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;

  // A non-zero exit means the session itself failed, not that the hook blocked
  // anything: the hook's block is reported inside a session that still exits 0.
  // The output is passed through because whatever went wrong is in it.
  if (result.status !== 0) {
    throw new Error(
      `\`claude -p\` exited ${result.status}:\n${output.trim() || "(no output)"}`,
    );
  }
  if (output.trim() === "") {
    throw new Error("`claude -p` exited 0 but produced no output.");
  }
  return output;
}

describe.skipIf(!ENABLED)("PreToolUse hook in a live session", () => {
  it(
    "stops the read and tells Claude why",
    () => {
      const output = runHeadless(
        "Read config.txt and tell me the value of aws_key.",
      );

      // Half one: the secret did not reach the conversation.
      expect(output).not.toContain(AWS_KEY);

      // Half two: the reason arrived. The allow-tag guidance is asserted rather
      // than the word "sensitive-canary", which also appears in the message
      // written to the terminal and would pass on that alone.
      expect(output.toLowerCase()).toContain("allow-secret");
    },
    TIMEOUT_MS,
  );
});

import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  AWS_KEY,
  runBashHook,
  runHook,
  runHookWithRawInput,
  useFixtureDir,
  useTranscripts,
} from "./hook-harness.ts";

const fixture = useFixtureDir("pre-tool-use");
const writeFixture = fixture;
const _tmpDirOf = () => fixture.path();
const writeTranscript = useTranscripts(fixture);
const _writeTranscriptWithToolResults = writeTranscript.withToolResults;
const _writeRawTranscript = writeTranscript.raw;

// ── non-Read/non-Bash tools ───────────────────────────────────────────────────

describe("pre-tool-use-hook — non-Read/non-Bash tools", () => {
  it("always allows Write", () => {
    const { exitCode } = runHook("Write", "/some/path");
    expect(exitCode).toBe(0);
  });

  it("always allows Edit", () => {
    const { exitCode } = runHook("Edit", "/some/path");
    expect(exitCode).toBe(0);
  });
});

// ── which channel a block is reported on ──────────────────────────────────────

// The reason goes on stderr alone. Writing to both channels would leave the
// documented one dead, because stdout wins and stderr is discarded when both
// carry text — measured with probe hooks, and the reason this hook writes one.
// Nothing asserted the stdout half of that, so a payload could come back on
// stdout and every other test would still pass.
describe("pre-tool-use-hook — block channel", () => {
  it("reports the reason on stderr and writes nothing to stdout", () => {
    const p = writeFixture(".env", "DEBUG=true\n");
    const { exitCode, stdout, stderr } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(stdout).toBe("");
    expect(stderr).toContain("allow-secret");
  });

  // An allowed call cannot be recognised by an empty stderr: node's type
  // stripping is experimental, so it warns there on every run. That is why the
  // harness reads the reason only when the exit code says a block happened,
  // rather than treating whatever is on stderr as one.
  it("says nothing about a block when the call is allowed", () => {
    const p = writeFixture("channel-clean.txt", "nothing here\n");
    const { exitCode, stdout, stderr, reason } = runHook("Read", p);
    expect(exitCode).toBe(0);
    expect(stdout).toBe("");
    expect(reason).toBeNull();
    expect(stderr).not.toContain("allow-secret");
    expect(stderr).not.toContain("Blocked");
  });
});

// The reason a block gives is sent to Claude. It used to carry the first eighty
// characters of the command, so blocking `export GITHUB_TOKEN=ghp_…` handed the
// token to the model in the sentence explaining that it had been withheld.
describe("pre-tool-use-hook — what the block reason contains", () => {
  const KEY = ["ghp_", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"].join("");

  it("does not repeat the command it blocked", () => {
    const result = runBashHook(`export GITHUB_TOKEN=${KEY}`);
    expect(result.exitCode).toBe(2);
    expect(result.reason).not.toContain(KEY);
    expect(result.reason).toContain("bash command");
  });

  it("still names the rule that fired", () => {
    const result = runBashHook(`export GITHUB_TOKEN=${KEY}`);
    expect(result.reason).toContain("github-pat");
  });
});

// An input field of the wrong type used to throw, and an exception exits 1,
// which does not block.
describe("pre-tool-use-hook — input shapes the runtime can send", () => {
  it.each([
    ['{"tool_name":"Bash","tool_input":{"command":123}}', "a numeric command"],
    ['{"tool_name":"Bash","tool_input":{"command":["cat","f"]}}', "an array"],
    ['{"tool_name":"Bash","tool_input":{"command":null}}', "a null command"],
    [
      '{"tool_name":"Bash","tool_input":{"command":"ls"},"cwd":5}',
      "a numeric cwd",
    ],
    ['{"tool_name":"Bash","tool_input":null}', "a null tool_input"],
  ])("%s (%s) does not crash", (payload) => {
    expect(runHookWithRawInput(payload).exitCode).toBe(0);
  });
});

describe("pre-tool-use-hook — an unforeseen error", () => {
  const writeFixture = useFixtureDir("fail-closed");

  // A scan that cannot finish is the error this is really for: the budget
  // throws, and the throw has to stop the call rather than pass it through.
  it("a scan that cannot finish stops the call", () => {
    const config = writeFixture(
      "slow.json",
      JSON.stringify({
        rules: Array.from({ length: 8 }, (_, i) => ({
          id: `slow-${i}`,
          description: "deliberately slow",
          regex:
            "(?<!x)eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}",
          category: "secret",
        })),
      }),
    );
    // Spawned directly rather than through the harness: the harness caps a run
    // at fifteen seconds so a hang fails the test instead of stopping the run,
    // and this case has to be allowed to reach the ten-second budget.
    const result = spawnSync(
      process.execPath,
      [
        "--experimental-strip-types",
        fileURLToPath(new URL("../pre-tool-use-hook.ts", import.meta.url)),
      ],
      {
        input: JSON.stringify({
          tool_name: "Bash",
          tool_input: { command: `echo ${"eyJ".repeat(21_845)}` },
        }),
        env: { ...process.env, SENSITIVE_CANARY_CONFIG: config },
        encoding: "utf8",
        timeout: 90_000,
      },
    );
    const { status: exitCode, stderr } = result;
    expect(exitCode).toBe(2);
    expect(stderr).toContain("the check could not complete");
    expect(stderr).not.toContain("sensitive data detected");
  }, 120_000);

  // Input the hook does understand is unaffected: this must not become a hook
  // that blocks everything. `null` parses, and a payload that is not an object
  // names nothing — treating "nothing to scan" as a threat is the misfire this
  // guard must not make.
  it.each(["", "   ", "{}", "[]", "null", "42", '{"tool_name":"Read"}'])(
    "%s is still allowed",
    (payload) => {
      expect(runHookWithRawInput(payload).exitCode).toBe(0);
    },
  );

  // Bytes that do not parse are a check that could not read its input, which is
  // not the same as safe: two characters missing from the end of a payload used
  // to pass a key through.
  it.each([
    "not json",
    '{"tool_name":"Read","tool_input":{"file_path":"/etc/hosts"}',
    '{"tool_name":',
  ])("%s stops the call", (payload) => {
    expect(runHookWithRawInput(payload).exitCode).toBe(2);
  });
});

// ── SENSITIVE_CANARY_CATEGORIES ───────────────────────────────────────────────

describe("pre-tool-use-hook — SENSITIVE_CANARY_CATEGORIES", () => {
  it("pii-only: allows reading .env files (secret guard disabled)", () => {
    const dir = join(fixture.path(), "pii-only-env");
    mkdirSync(dir, { recursive: true });
    const p = join(dir, ".env");
    writeFileSync(p, "DEBUG=true\n", "utf8");
    const { exitCode } = runHook("Read", p, {
      env: { SENSITIVE_CANARY_CATEGORIES: "pii" },
    });
    expect(exitCode).toBe(0);
  });

  it("pii-only: allows a file containing only secrets", () => {
    const p = writeFixture("pii-only-secret.txt", `key=${AWS_KEY}`);
    const { exitCode } = runHook("Read", p, {
      env: { SENSITIVE_CANARY_CATEGORIES: "pii" },
    });
    expect(exitCode).toBe(0);
  });

  it("pii-only: still blocks a file containing PII", () => {
    const p = writeFixture("pii-only-pii.txt", "card: 4532015112830366");
    const { exitCode, blocked } = runHook("Read", p, {
      env: { SENSITIVE_CANARY_CATEGORIES: "pii" },
    });
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
  });

  it("secret-only: allows a file containing only PII", () => {
    const p = writeFixture("secret-only-pii.txt", "card: 4532015112830366");
    const { exitCode } = runHook("Read", p, {
      env: { SENSITIVE_CANARY_CATEGORIES: "secret" },
    });
    expect(exitCode).toBe(0);
  });

  it("secret-only: still blocks a file containing secrets", () => {
    const p = writeFixture("secret-only-secret.txt", `key=${AWS_KEY}`);
    const { exitCode, blocked } = runHook("Read", p, {
      env: { SENSITIVE_CANARY_CATEGORIES: "secret" },
    });
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
  });

  it("secret-only: allows a bash command containing only PII", () => {
    const { exitCode } = runBashHook("echo 4532015112830366", {
      env: { SENSITIVE_CANARY_CATEGORIES: "secret" },
    });
    expect(exitCode).toBe(0);
  });

  it("unset: blocks both secrets and PII (default behavior)", () => {
    const p = writeFixture(
      "default-both.txt",
      `key=${AWS_KEY}\ncard: 4532015112830366`,
    );
    const { exitCode, reason } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(reason).toContain("aws-access-key");
    expect(reason).toContain("pii-credit-card");
  });
});

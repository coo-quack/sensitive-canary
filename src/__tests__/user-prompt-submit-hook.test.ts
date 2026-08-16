import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { AWS_KEY } from "./hook-harness.ts";

// fileURLToPath, not `.pathname`: a checkout under a path with a space in
// it comes back percent-encoded from the latter and the spawn fails.
const HOOK = fileURLToPath(
  new URL("../user-prompt-submit-hook.ts", import.meta.url),
);
const NODE_FLAGS = ["--experimental-strip-types"];

function runHook(prompt: string, opts?: { env?: Record<string, string> }) {
  const result = spawnSync("node", [...NODE_FLAGS, HOOK], {
    input: JSON.stringify({ prompt }),
    encoding: "utf8",
    env: { ...process.env, ...opts?.env },
  });
  return {
    exitCode: result.status ?? -1,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

// Every case in this file used a one-line prompt, so a cap on how much of it is
// scanned would not have shown up. A pasted log or `.env` is the case the hook
// exists for, and it is long.
// A prompt that is not a string used to throw; not throwing left it coerced to
// the empty string, which exits 0 — the same silence as never running.
describe("user-prompt-submit-hook — the shapes a prompt arrives in", () => {
  const run = (payload: unknown): number => {
    const result = spawnSync(
      process.execPath,
      ["--experimental-strip-types", HOOK],
      { input: JSON.stringify(payload), encoding: "utf8" },
    );
    return result.status ?? -1;
  };

  it.each([
    ["a string", { prompt: `key=${AWS_KEY}` }],
    ["an object", { prompt: { text: `key=${AWS_KEY}` } }],
    ["an array", { prompt: [`key=${AWS_KEY}`] }],
    ["content blocks", { prompt: [{ type: "text", text: `key=${AWS_KEY}` }] }],
    ["nested", { prompt: { a: { b: `key=${AWS_KEY}` } } }],
  ])("a secret in %s is blocked", (_label, payload) => {
    expect(run(payload)).toBe(2);
  });

  it.each([
    ["a clean string", { prompt: "ls -la" }],
    ["null", { prompt: null }],
    ["a number", { prompt: 42 }],
    ["nothing", {}],
  ])("%s is allowed", (_label, payload) => {
    expect(run(payload)).toBe(0);
  });

  // The walk is bounded, so a deep value cannot make the hook chase a tree.
  it("a prompt nested past the bound is not walked", () => {
    let deep: unknown = `key=${AWS_KEY}`;
    for (let i = 0; i < 8; i++) deep = { next: deep };
    expect(run({ prompt: deep })).toBe(0);
  });
});

describe("user-prompt-submit-hook — how much of the prompt is scanned", () => {
  const KEY = AWS_KEY;

  it.each([
    ["8 KB", 8 * 1024],
    ["64 KB", 64 * 1024],
    ["256 KB", 256 * 1024],
  ])("finds a key after %s of text", (_label, padding) => {
    const { exitCode } = runHook(
      `${"lorem ipsum ".repeat(padding / 12)}${KEY}`,
    );
    expect(exitCode).toBe(2);
  });

  it("finds a key on the last line of a pasted file", () => {
    const lines = Array.from({ length: 5000 }, (_, i) => `line ${i}`);
    const { exitCode } = runHook(`${lines.join("\n")}\nkey=${KEY}\n`);
    expect(exitCode).toBe(2);
  });
});

// A prompt that is not a string used to throw. Not throwing was only half the
// fix: these tests asked for exit 0, and exit 0 on a payload holding a key is
// the same silence the exception produced. The cases that carry a key moved to
// the block above, which asks for the block. What is left here is what really
// has nothing to scan.
// The same contract on the other hook.
// The same contract on this hook, which had the order right and must keep it.
describe("user-prompt-submit-hook — a tag lifts only its own category", () => {
  const BOTH = "API_TOKEN=alice.dupont@realcompany.co.jp";
  const run = (text: string): number => {
    const result = spawnSync(process.execPath, [...NODE_FLAGS, HOOK], {
      input: JSON.stringify({ prompt: text }),
      encoding: "utf8",
    });
    return result.status ?? -1;
  };

  it.each([
    ["no tag", BOTH],
    ["[allow-secret]", `[allow-secret] ${BOTH}`],
    ["[allow-pii]", `[allow-pii] ${BOTH}`],
  ])("%s does not let it through", (_label, text) => {
    expect(run(text)).toBe(2);
  });

  it("[allow-all] does", () => {
    expect(run(`[allow-all] ${BOTH}`)).toBe(0);
  });
});

describe("user-prompt-submit-hook — an unforeseen error", () => {
  const raw = (payload: string) =>
    spawnSync(process.execPath, ["--experimental-strip-types", HOOK], {
      input: payload,
      encoding: "utf8",
    });

  // A payload that is not an object carries no prompt, so there is nothing to
  // scan and nothing to stop. The handler is for a check that started and could
  // not finish, which the other hook's tests cover through the scan budget.
  it.each(["", "   ", "{}"])("%s is still allowed", (payload) => {
    expect(raw(payload).status).toBe(0);
  });

  // Input the check could not read is not input the check approved.
  it.each(["not json", '{"prompt":"x"', "{"])(
    "%s stops the call",
    (payload) => {
      expect(raw(payload).status).toBe(2);
    },
  );

  it("the handler is installed", () => {
    const source = readFileSync(HOOK, "utf8");
    expect(source).toContain('process.on("uncaughtException"');
    expect(source).toContain('process.on("unhandledRejection"');
  });
});

describe("user-prompt-submit-hook — a prompt of the wrong type", () => {
  const raw = (payload: string) => {
    const result = spawnSync("node", [...NODE_FLAGS, HOOK], {
      input: payload,
      encoding: "utf8",
    });
    return result.status ?? -1;
  };

  it.each([
    '{"prompt":12345}',
    '{"prompt":true}',
    '{"prompt":null}',
    '{"prompt":[]}',
    '{"prompt":{}}',
    "{}",
  ])("%s is allowed and does not crash", (payload) => {
    expect(raw(payload)).toBe(0);
  });
});

describe("user-prompt-submit-hook — allow (exit 0)", () => {
  it("passes a clean prompt", () => {
    const { exitCode } = runHook("hello, can you help me?");
    expect(exitCode).toBe(0);
  });

  it("passes an empty prompt", () => {
    const { exitCode } = runHook("");
    expect(exitCode).toBe(0);
  });

  it("passes with [allow-all] tag even if secret is present", () => {
    const { exitCode } = runHook(`[allow-all] my key is ${AWS_KEY}`);
    expect(exitCode).toBe(0);
  });

  it("passes with [allow-secret] tag when only secrets are present", () => {
    const { exitCode } = runHook(`[allow-secret] my key is ${AWS_KEY}`);
    expect(exitCode).toBe(0);
  });

  it("passes with [allow-pii] tag when only PII is present", () => {
    const { exitCode } = runHook(
      "[allow-pii] please email ada@analytical-engines.org",
    );
    expect(exitCode).toBe(0);
  });
});

describe("user-prompt-submit-hook — block (exit 2)", () => {
  it("blocks a prompt with an AWS access key", () => {
    const { exitCode, stderr } = runHook(`my key is ${AWS_KEY}`);
    expect(exitCode).toBe(2);
    expect(stderr).toContain("aws-access-key");
    expect(stderr).toContain("blocked");
  });

  it("blocks a prompt with a JWT", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const { exitCode, stderr } = runHook(`token: ${jwt}`);
    expect(exitCode).toBe(2);
    expect(stderr).toContain("jwt");
  });

  it("blocks a prompt with an email address", () => {
    const { exitCode, stderr } = runHook(
      "please email ada@analytical-engines.org",
    );
    expect(exitCode).toBe(2);
    expect(stderr).toContain("pii-email");
  });

  it("blocks a prompt with a credit card number", () => {
    const { exitCode, stderr } = runHook("card: 4532015112830366");
    expect(exitCode).toBe(2);
    expect(stderr).toContain("pii-credit-card");
  });

  it("shows [allow-secret] and [allow-all] hints for a secret", () => {
    const { stderr } = runHook(`key=${AWS_KEY}`);
    expect(stderr).toContain("[allow-secret]");
    expect(stderr).toContain("[allow-all]");
  });

  it("shows [allow-pii] and [allow-all] hints for PII", () => {
    const { stderr } = runHook("email: ada@analytical-engines.org");
    expect(stderr).toContain("[allow-pii]");
    expect(stderr).toContain("[allow-all]");
  });

  it("shows both [allow-secret] and [allow-pii] hints when both are detected", () => {
    const { stderr } = runHook(
      `key=${AWS_KEY} and email ada@analytical-engines.org`,
    );
    expect(stderr).toContain("[allow-secret]");
    expect(stderr).toContain("[allow-pii]");
    expect(stderr).toContain("[allow-all]");
  });

  it("deduplicates the same secret appearing multiple times", () => {
    const { stderr } = runHook(`A=${AWS_KEY} B=${AWS_KEY}`);
    // aws-access-key finding should appear only once in the output
    const count = (stderr ?? "").split("aws-access-key").length - 1;
    expect(count).toBe(1);
  });

  it("[allow-pii] does not bypass a secret block", () => {
    const { exitCode } = runHook(`[allow-pii] my key is ${AWS_KEY}`);
    expect(exitCode).toBe(2);
  });

  it("[allow-secret] does not bypass a PII block", () => {
    const { exitCode } = runHook(
      "[allow-secret] please email ada@analytical-engines.org",
    );
    expect(exitCode).toBe(2);
  });

  it("[allow-secret] with mixed content still blocks PII", () => {
    const { exitCode } = runHook(
      `[allow-secret] key=${AWS_KEY} and email ada@analytical-engines.org`,
    );
    expect(exitCode).toBe(2);
  });
});

describe("user-prompt-submit-hook — [mask-xxx] tags", () => {
  it("[mask-secret] with secret shows the actual tag in message", () => {
    const { exitCode, stderr } = runHook(`[mask-secret] my key is ${AWS_KEY}`);
    expect(exitCode).toBe(2);
    expect(stderr).toContain("prompt masking is not supported");
    expect(stderr).toContain("[mask-secret]");
    expect(stderr).toContain("[allow-secret]");
  });

  it("[mask-pii] with PII shows the actual tag in message", () => {
    const { exitCode, stderr } = runHook(
      "[mask-pii] please email ada@analytical-engines.org",
    );
    expect(exitCode).toBe(2);
    expect(stderr).toContain("prompt masking is not supported");
    expect(stderr).toContain("[mask-pii]");
    expect(stderr).toContain("[allow-pii]");
  });

  it("[mask-all] with any sensitive data shows masking not supported", () => {
    const { exitCode, stderr } = runHook(`[mask-all] my key is ${AWS_KEY}`);
    expect(exitCode).toBe(2);
    expect(stderr).toContain("prompt masking is not supported");
    expect(stderr).toContain("[mask-all]");
  });

  it("[mask-secret] with only PII falls through to normal block", () => {
    const { exitCode, stderr } = runHook(
      "[mask-secret] please email ada@analytical-engines.org",
    );
    expect(exitCode).toBe(2);
    expect(stderr).not.toContain("prompt masking is not supported");
    expect(stderr).toContain("sensitive data detected");
  });

  it("[mask-pii] with only secrets falls through to normal block", () => {
    const { exitCode, stderr } = runHook(`[mask-pii] my key is ${AWS_KEY}`);
    expect(exitCode).toBe(2);
    expect(stderr).not.toContain("prompt masking is not supported");
    expect(stderr).toContain("sensitive data detected");
  });

  it("[mask-secret] with clean prompt passes through", () => {
    const { exitCode } = runHook("[mask-secret] hello, can you help me?");
    expect(exitCode).toBe(0);
  });

  it("[mask-unknown] with sensitive data falls through to normal block", () => {
    const { exitCode, stderr } = runHook(`[mask-unknown] my key is ${AWS_KEY}`);
    expect(exitCode).toBe(2);
    expect(stderr).not.toContain("prompt masking is not supported");
    expect(stderr).toContain("sensitive data detected");
  });
});

describe("user-prompt-submit-hook — first-occurrence tag priority", () => {
  it("[allow-secret] before [mask-secret] → passes through (exit 0)", () => {
    const { exitCode } = runHook(
      `[allow-secret] [mask-secret] my key is ${AWS_KEY}`,
    );
    expect(exitCode).toBe(0);
  });

  it("[mask-secret] before [allow-secret] → shows masking not supported (exit 2)", () => {
    const { exitCode, stderr } = runHook(
      `[mask-secret] [allow-secret] my key is ${AWS_KEY}`,
    );
    expect(exitCode).toBe(2);
    expect(stderr).toContain("prompt masking is not supported");
  });

  it("[allow-all] before [mask-secret] → passes through (exit 0)", () => {
    const { exitCode } = runHook(
      `[allow-all] [mask-secret] my key is ${AWS_KEY}`,
    );
    expect(exitCode).toBe(0);
  });

  it("[mask-all] before [allow-secret] → shows masking not supported (exit 2)", () => {
    const { exitCode, stderr } = runHook(
      `[mask-all] [allow-secret] my key is ${AWS_KEY}`,
    );
    expect(exitCode).toBe(2);
    expect(stderr).toContain("prompt masking is not supported");
  });

  it("[allow-secret] [mask-pii] → secret allowed, pii masked → masking not supported (exit 2)", () => {
    const { exitCode, stderr } = runHook(
      `[allow-secret] [mask-pii] key ${AWS_KEY} email ada@analytical-engines.org`,
    );
    expect(exitCode).toBe(2);
    expect(stderr).toContain("prompt masking is not supported");
    expect(stderr).toContain("[mask-pii]");
    expect(stderr).not.toContain("[mask-secret]");
  });

  it("[mask-pii] [allow-secret] → secret: allow, pii: mask → masking not supported for email (exit 2)", () => {
    const { exitCode, stderr } = runHook(
      `[mask-pii] [allow-secret] key ${AWS_KEY} email ada@analytical-engines.org`,
    );
    expect(exitCode).toBe(2);
    expect(stderr).toContain("prompt masking is not supported");
    expect(stderr).toContain("[mask-pii]");
  });

  it("[allow-pii] before [mask-pii] → pii allowed, secret still blocked (exit 2)", () => {
    const { exitCode, stderr } = runHook(
      `[allow-pii] [mask-pii] key ${AWS_KEY} email ada@analytical-engines.org`,
    );
    expect(exitCode).toBe(2);
    expect(stderr).toContain("sensitive data detected");
    expect(stderr).not.toContain("prompt masking is not supported");
  });
});

describe("user-prompt-submit-hook — malformed input", () => {
  // Bytes that do not parse mean the check could not read its input, which is
  // not the same as nothing being there.
  it("stops the call on invalid JSON", () => {
    const result = spawnSync(process.execPath, [...NODE_FLAGS, HOOK], {
      input: "not json",
      encoding: "utf8",
    });
    expect(result.status).toBe(2);
  });
});

describe("user-prompt-submit-hook — SENSITIVE_CANARY_CATEGORIES", () => {
  it("pii-only: passes a prompt containing only secrets", () => {
    const { exitCode } = runHook(`my key is ${AWS_KEY}`, {
      env: { SENSITIVE_CANARY_CATEGORIES: "pii" },
    });
    expect(exitCode).toBe(0);
  });

  it("pii-only: still blocks a prompt containing PII", () => {
    const { exitCode, stderr } = runHook("my card is 4532015112830366", {
      env: { SENSITIVE_CANARY_CATEGORIES: "pii" },
    });
    expect(exitCode).toBe(2);
    expect(stderr).toContain("sensitive data detected");
  });

  it("secret-only: passes a prompt containing only PII", () => {
    const { exitCode } = runHook("my card is 4532015112830366", {
      env: { SENSITIVE_CANARY_CATEGORIES: "secret" },
    });
    expect(exitCode).toBe(0);
  });

  it("secret-only: still blocks a prompt containing secrets", () => {
    const { exitCode, stderr } = runHook(`my key is ${AWS_KEY}`, {
      env: { SENSITIVE_CANARY_CATEGORIES: "secret" },
    });
    expect(exitCode).toBe(2);
    expect(stderr).toContain("sensitive data detected");
  });

  it("unset: blocks both secrets and PII (default behavior)", () => {
    const { exitCode, stderr } = runHook(
      `key ${AWS_KEY} card 4532015112830366`,
    );
    expect(exitCode).toBe(2);
    expect(stderr).toContain("aws-access-key");
    expect(stderr).toContain("pii-credit-card");
  });
});

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const HOOK = new URL("../pre-tool-use-hook.ts", import.meta.url).pathname;
const NODE_FLAGS = ["--experimental-strip-types"];

// ── helpers ───────────────────────────────────────────────────────────────────

function parseHookOutput(stdout: string) {
  try {
    const parsed = JSON.parse(stdout) as { decision?: string; reason?: string };
    return { decision: parsed.decision ?? null, reason: parsed.reason ?? null };
  } catch {
    return { decision: null, reason: null };
  }
}

let transcriptSeq = 0;

function writeTranscript(userMessages: string[]): string {
  const lines = userMessages.map((content) =>
    JSON.stringify({
      type: "user",
      message: { role: "user", content },
    }),
  );
  const p = join(tmpDir, `transcript-${++transcriptSeq}.jsonl`);
  writeFileSync(p, lines.join("\n"), "utf8");
  return p;
}

function writeTranscriptWithToolResults(
  entries: Array<{ text: string } | { toolResult: string }>,
): string {
  const lines = entries.map((entry) => {
    if ("text" in entry) {
      return JSON.stringify({
        type: "user",
        message: { role: "user", content: entry.text },
      });
    }
    return JSON.stringify({
      type: "user",
      message: {
        role: "user",
        content: [{ type: "tool_result", content: entry.toolResult }],
      },
    });
  });
  const p = join(tmpDir, `transcript-${++transcriptSeq}.jsonl`);
  writeFileSync(p, lines.join("\n"), "utf8");
  return p;
}

function runHook(
  toolName: string,
  filePath: string,
  opts?: { transcriptPath?: string },
) {
  const input = JSON.stringify({
    transcript_path: opts?.transcriptPath,
    tool_name: toolName,
    tool_input: { file_path: filePath },
  });
  const result = spawnSync("node", [...NODE_FLAGS, HOOK], {
    input,
    encoding: "utf8",
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

function runBashHook(
  command: string,
  opts?: { env?: Record<string, string>; transcriptPath?: string },
) {
  const input = JSON.stringify({
    transcript_path: opts?.transcriptPath,
    tool_name: "Bash",
    tool_input: { command },
  });
  const result = spawnSync("node", [...NODE_FLAGS, HOOK], {
    input,
    encoding: "utf8",
    env: { ...process.env, ...opts?.env },
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

// ── temp directory for fixture files ─────────────────────────────────────────

let tmpDir: string;

beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "sensitive-canary-test-"));
});

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function writeFixture(name: string, content: string) {
  const p = join(tmpDir, name);
  writeFileSync(p, content, "utf8");
  return p;
}

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

// ── .env / .env.* — unconditional name block ──────────────────────────────────

describe("pre-tool-use-hook — .env/.env.* unconditional block", () => {
  it("blocks .env regardless of content", () => {
    const p = writeFixture(".env", "DEBUG=true\nNODE_ENV=development\n");
    const { exitCode, decision } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("blocks .env.local regardless of content", () => {
    const p = writeFixture(".env.local", "DEBUG=true\n");
    const { exitCode, decision } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("blocks .env.production regardless of content", () => {
    const p = writeFixture(".env.production", "DEBUG=true\n");
    const { exitCode, decision } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("includes [allow-secret], [allow-pii], and [allow-all] hints in reason", () => {
    const p = writeFixture(".env.hints", "KEY=value");
    const { reason } = runHook("Read", p);
    expect(reason).toContain("[allow-secret]");
    expect(reason).toContain("[allow-pii]");
    expect(reason).toContain("[allow-all]");
  });

  it("includes a bird emoji in .env block reason", () => {
    const p = writeFixture(".env.bird", "KEY=value");
    const { reason } = runHook("Read", p);
    expect(reason).toMatch(/[🐦🐧🐤🐔]/u);
  });
});

// ── clean file ────────────────────────────────────────────────────────────────

describe("pre-tool-use-hook — clean file", () => {
  it("allows a file with no sensitive data", () => {
    const p = writeFixture("clean.txt", "hello world");
    const { exitCode } = runHook("Read", p);
    expect(exitCode).toBe(0);
  });

  it("allows a non-existent file (let Node handle the error)", () => {
    const { exitCode } = runHook("Read", "/tmp/does-not-exist-xyz.txt");
    expect(exitCode).toBe(0);
  });
});

// ── secrets/PII in file contents ──────────────────────────────────────────────

describe("pre-tool-use-hook — sensitive content blocking", () => {
  it("blocks a file containing an AWS key", () => {
    const p = writeFixture("config.txt", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n");
    const { exitCode, decision, reason } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
    expect(reason).toContain("aws-access-key");
  });

  it("blocks a file containing an email address", () => {
    const p = writeFixture("contacts.txt", "Email: user@example.com\n");
    const { exitCode, decision } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("blocks a file containing a private IP", () => {
    const p = writeFixture("infra.txt", "server: 192.168.1.100\n");
    const { exitCode, decision } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("includes [allow-secret] and [allow-all] hints in reason for a secret", () => {
    const p = writeFixture("key.txt", "key=AKIAIOSFODNN7EXAMPLE\n");
    const { reason } = runHook("Read", p);
    expect(reason).toContain("[allow-secret]");
    expect(reason).toContain("[allow-all]");
  });

  it("includes a bird emoji in the reason", () => {
    const p = writeFixture("bird.txt", "key=AKIAIOSFODNN7EXAMPLE\n");
    const { reason } = runHook("Read", p);
    expect(reason).toMatch(/[🐦🐧🐤🐔]/u);
  });

  it("includes [allow-pii] and [allow-all] hints in reason for PII", () => {
    const p = writeFixture("pii.txt", "Email: user@example.com\n");
    const { reason } = runHook("Read", p);
    expect(reason).toContain("[allow-pii]");
    expect(reason).toContain("[allow-all]");
  });

  it("deduplicates repeated secrets — finding line appears only once", () => {
    const p = writeFixture(
      "dup.txt",
      "A=AKIAIOSFODNN7EXAMPLE\nB=AKIAIOSFODNN7EXAMPLE\n",
    );
    const { reason } = runHook("Read", p);
    const count = (reason ?? "").split("[Secret]").length - 1;
    expect(count).toBe(1);
  });
});

// ── Bash tool — env var expansion ────────────────────────────────────────────

describe("pre-tool-use-hook — Bash tool (env var expansion)", () => {
  it("blocks echo $TOKEN when TOKEN contains an AWS key", () => {
    const { exitCode, decision } = runBashHook("echo $TOKEN", {
      env: { TOKEN: "AKIAIOSFODNN7EXAMPLE" },
    });
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("includes the variable name and rule in reason", () => {
    const { reason } = runBashHook("echo $MY_SECRET", {
      env: { MY_SECRET: "AKIAIOSFODNN7EXAMPLE" },
    });
    expect(reason).toContain("$MY_SECRET");
    expect(reason).toContain("aws-access-key");
  });

  // biome-ignore lint/suspicious/noTemplateCurlyInString: intentional literal — testing ${VAR} bash syntax
  it("blocks ${TOKEN} brace syntax", () => {
    // biome-ignore lint/suspicious/noTemplateCurlyInString: intentional literal — the string is passed as a bash command
    const { exitCode } = runBashHook("curl -H 'Auth: ${API_TOKEN}'", {
      env: { API_TOKEN: "AKIAIOSFODNN7EXAMPLE" },
    });
    expect(exitCode).toBe(2);
  });

  it("allows echo $TOKEN when TOKEN value is clean", () => {
    const { exitCode } = runBashHook("echo $TOKEN", {
      env: { TOKEN: "nothing_sensitive_here" },
    });
    expect(exitCode).toBe(0);
  });

  it("allows echo $TOKEN when TOKEN is unset", () => {
    const { exitCode } = runBashHook("echo $TOKEN");
    expect(exitCode).toBe(0);
  });

  it("ignores special shell variables like $? and $0", () => {
    const { exitCode } = runBashHook("exit $?; echo $0");
    expect(exitCode).toBe(0);
  });
});

// ── Bash tool — command string scanning ──────────────────────────────────────

describe("pre-tool-use-hook — Bash tool (command string)", () => {
  it("allows a harmless Bash command", () => {
    const { exitCode } = runBashHook("ls -la /tmp");
    expect(exitCode).toBe(0);
  });

  it("blocks a Bash command containing an AWS key (e.g. echo)", () => {
    const { exitCode, decision } = runBashHook("echo AKIAIOSFODNN7EXAMPLE");
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("includes aws-access-key in reason for inline secret", () => {
    const { reason } = runBashHook("echo AKIAIOSFODNN7EXAMPLE");
    expect(reason).toContain("aws-access-key");
  });

  it("includes a bird emoji in the reason for Bash block", () => {
    const { reason } = runBashHook("echo AKIAIOSFODNN7EXAMPLE");
    expect(reason).toMatch(/[🐦🐧🐤🐔]/u);
  });
});

// ── Bash tool — file-reading command blocking ─────────────────────────────────

describe("pre-tool-use-hook — Bash tool (file-reading commands)", () => {
  it.each([
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "bat",
    "nl",
  ])("blocks %s on a file with secrets", (cmd) => {
    const p = writeFixture(
      `creds-${cmd}.txt`,
      "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n",
    );
    const { exitCode, decision } = runBashHook(`${cmd} ${p}`);
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("blocks cat on a file with PII", () => {
    const p = writeFixture("contacts-bash.txt", "Email: user@example.com\n");
    const { exitCode, decision } = runBashHook(`cat ${p}`);
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("allows cat on a clean file", () => {
    const p = writeFixture("clean-bash.txt", "nothing sensitive here\n");
    const { exitCode } = runBashHook(`cat ${p}`);
    expect(exitCode).toBe(0);
  });

  it("allows cat on a non-existent file (let shell handle the error)", () => {
    const { exitCode } = runBashHook("cat /tmp/does-not-exist-xyz.txt");
    expect(exitCode).toBe(0);
  });

  it("blocks cat in a compound command (pipe) on a file with secrets", () => {
    const p = writeFixture("pipe-secret.txt", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n");
    const { exitCode, decision } = runBashHook(`cat ${p} | grep KEY`);
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("allows cat in a compound command (pipe) on a clean file", () => {
    const p = writeFixture("pipe-clean.txt", "nothing sensitive here\n");
    const { exitCode } = runBashHook(`cat ${p} | grep text`);
    expect(exitCode).toBe(0);
  });

  it("blocks cat on a .env.* file by name", () => {
    const p = writeFixture(".env.bash-name", "DEBUG=true\n");
    const { exitCode, decision } = runBashHook(`cat ${p}`);
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("[allow-pii] bypasses cat on a .env.* file", () => {
    const transcript = writeTranscript(["[allow-pii] show me the env"]);
    const p = writeFixture(".env.bash-pii", "DEBUG=true\n");
    const { exitCode } = runBashHook(`cat ${p}`, {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(0);
  });
});

// ── allow tag bypass (transcript) ────────────────────────────────────────────

describe("pre-tool-use-hook — allow tag bypass via transcript", () => {
  // ── Read tool ──────────────────────────────────────────────────────────────

  it("[allow-all] bypasses .env name block", () => {
    const transcript = writeTranscript([
      "[allow-all] please read the .env file",
    ]);
    const p = writeFixture(".env.bypass-all", "KEY=AKIAIOSFODNN7EXAMPLE\n");
    const { exitCode } = runHook("Read", p, { transcriptPath: transcript });
    expect(exitCode).toBe(0);
  });

  it("[allow-secret] bypasses .env name block", () => {
    const transcript = writeTranscript(["[allow-secret] read the env file"]);
    const p = writeFixture(".env.bypass-secret", "KEY=AKIAIOSFODNN7EXAMPLE\n");
    const { exitCode } = runHook("Read", p, { transcriptPath: transcript });
    expect(exitCode).toBe(0);
  });

  it("[allow-pii] also bypasses .env name block", () => {
    const transcript = writeTranscript(["[allow-pii] read the env file"]);
    const p = writeFixture(".env.bypass-pii", "KEY=value");
    const { exitCode } = runHook("Read", p, { transcriptPath: transcript });
    expect(exitCode).toBe(0);
  });

  it("[allow-secret] bypasses secrets in content scan", () => {
    const transcript = writeTranscript(["[allow-secret] check the config"]);
    const p = writeFixture(
      "config-allow-secret2.txt",
      "key=AKIAIOSFODNN7EXAMPLE\n",
    );
    const { exitCode } = runHook("Read", p, { transcriptPath: transcript });
    expect(exitCode).toBe(0);
  });

  it("[allow-pii] bypasses PII in content scan", () => {
    const transcript = writeTranscript(["[allow-pii] ok"]);
    const p = writeFixture("pii-allow.txt", "email=user@example.com\n");
    const { exitCode } = runHook("Read", p, { transcriptPath: transcript });
    expect(exitCode).toBe(0);
  });

  it("[allow-pii] bypasses PII but not secrets in content scan", () => {
    const transcript = writeTranscript(["[allow-pii] ok"]);
    const p = writeFixture(
      "mixed-allow-pii.txt",
      "email=user@example.com\nkey=AKIAIOSFODNN7EXAMPLE\n",
    );
    const { exitCode, decision } = runHook("Read", p, {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("[allow-all] in the latest message is respected even with older messages", () => {
    const transcript = writeTranscript([
      "please help me with the config",
      "[allow-all] yes read everything",
    ]);
    const p = writeFixture(
      "config-allow-latest.txt",
      "key=AKIAIOSFODNN7EXAMPLE\n",
    );
    const { exitCode } = runHook("Read", p, { transcriptPath: transcript });
    expect(exitCode).toBe(0);
  });

  it("old [allow-all] in a past message is NOT respected when latest message has no tag", () => {
    const transcript = writeTranscript([
      "[allow-all] read this file",
      "now do something else",
    ]);
    const p = writeFixture(
      "config-old-allow.txt",
      "key=AKIAIOSFODNN7EXAMPLE\n",
    );
    const { exitCode, decision } = runHook("Read", p, {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("blocks when transcript path is missing (no allow tags)", () => {
    const p = writeFixture(
      "config-no-transcript.txt",
      "key=AKIAIOSFODNN7EXAMPLE\n",
    );
    const { exitCode, decision } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("blocks when transcript path points to non-existent file", () => {
    const p = writeFixture(
      "config-bad-transcript.txt",
      "key=AKIAIOSFODNN7EXAMPLE\n",
    );
    const { exitCode, decision } = runHook("Read", p, {
      transcriptPath: "/tmp/no-such-transcript.jsonl",
    });
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  // ── Bash tool ──────────────────────────────────────────────────────────────

  it("[allow-secret] bypasses inline secret block in Bash command", () => {
    const transcript = writeTranscript(["[allow-secret] echo the key"]);
    const { exitCode } = runBashHook("echo AKIAIOSFODNN7EXAMPLE", {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(0);
  });

  it("[allow-secret] bypasses env var secret block in Bash command", () => {
    const transcript = writeTranscript(["[allow-secret] ok"]);
    const { exitCode } = runBashHook("echo $TOKEN", {
      env: { TOKEN: "AKIAIOSFODNN7EXAMPLE" },
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(0);
  });

  it("[allow-all] bypasses env var secret block in Bash command", () => {
    const transcript = writeTranscript(["[allow-all] ok"]);
    const { exitCode } = runBashHook("echo $TOKEN", {
      env: { TOKEN: "AKIAIOSFODNN7EXAMPLE" },
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(0);
  });

  it("[allow-all] bypasses cat on a file with secrets via Bash", () => {
    const transcript = writeTranscript(["[allow-all] show me the config"]);
    const p = writeFixture(
      "creds-bash-allow.txt",
      "key=AKIAIOSFODNN7EXAMPLE\n",
    );
    const { exitCode } = runBashHook(`cat ${p}`, {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(0);
  });
});

// ── allow tag consumed after first tool call ──────────────────────────────────

describe("pre-tool-use-hook — allow tag single-use (consumed by first tool call)", () => {
  it("[allow-all] works when no tool_result has been recorded yet", () => {
    const transcript = writeTranscriptWithToolResults([
      { text: "[allow-all] read the config file" },
    ]);
    const p = writeFixture(
      "config-first-call.txt",
      "key=AKIAIOSFODNN7EXAMPLE\n",
    );
    const { exitCode } = runHook("Read", p, { transcriptPath: transcript });
    expect(exitCode).toBe(0);
  });

  it("[allow-all] is consumed after a tool_result — second call is blocked", () => {
    const transcript = writeTranscriptWithToolResults([
      { text: "[allow-all] read all the config files" },
      { toolResult: "file contents from first read" },
    ]);
    const p = writeFixture(
      "config-second-call.txt",
      "key=AKIAIOSFODNN7EXAMPLE\n",
    );
    const { exitCode, decision } = runHook("Read", p, {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("[allow-secret] is consumed after a tool_result", () => {
    const transcript = writeTranscriptWithToolResults([
      { text: "[allow-secret] check these files" },
      { toolResult: "first tool result" },
    ]);
    const p = writeFixture("secret-consumed.txt", "key=AKIAIOSFODNN7EXAMPLE\n");
    const { exitCode, decision } = runHook("Read", p, {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("[allow-pii] is consumed after a tool_result", () => {
    const transcript = writeTranscriptWithToolResults([
      { text: "[allow-pii] read the contacts" },
      { toolResult: "previous tool output" },
    ]);
    const p = writeFixture("pii-consumed.txt", "email=user@example.com\n");
    const { exitCode, decision } = runHook("Read", p, {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("blocks when latest real user message has no allow tag despite earlier allow", () => {
    const transcript = writeTranscriptWithToolResults([
      { text: "[allow-all] read everything" },
      { toolResult: "some result" },
      { text: "now do something else" },
      { toolResult: "another result" },
    ]);
    const p = writeFixture(
      "no-allow-after-new-msg.txt",
      "key=AKIAIOSFODNN7EXAMPLE\n",
    );
    const { exitCode, decision } = runHook("Read", p, {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("[allow-all] consumed for Bash after tool_result", () => {
    const transcript = writeTranscriptWithToolResults([
      { text: "[allow-all] run the commands" },
      { toolResult: "result of first command" },
    ]);
    const { exitCode, decision } = runBashHook("echo AKIAIOSFODNN7EXAMPLE", {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("[allow-all] works for Bash when no tool_result yet", () => {
    const transcript = writeTranscriptWithToolResults([
      { text: "[allow-all] run the command" },
    ]);
    const { exitCode } = runBashHook("echo AKIAIOSFODNN7EXAMPLE", {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(0);
  });
});

// ── malformed input ───────────────────────────────────────────────────────────

describe("pre-tool-use-hook — malformed input", () => {
  it("exits 0 on invalid JSON", () => {
    const result = spawnSync("node", [...NODE_FLAGS, HOOK], {
      input: "not json",
      encoding: "utf8",
    });
    expect(result.status).toBe(0);
  });
});

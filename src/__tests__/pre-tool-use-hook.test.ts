import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runBashHook, runHook, runHookWithRawInput } from "./hook-harness.ts";

// ── helpers ───────────────────────────────────────────────────────────────────

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

// ── .env / .env.* — secret name block ─────────────────────────────────────────

describe("pre-tool-use-hook — .env/.env.* name block (secret category)", () => {
  it("blocks .env regardless of content", () => {
    const p = writeFixture(".env", "DEBUG=true\nNODE_ENV=development\n");
    const { exitCode, blocked } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
  });

  it("blocks .env.local regardless of content", () => {
    const p = writeFixture(".env.local", "DEBUG=true\n");
    const { exitCode, blocked } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
  });

  it("blocks .env.production regardless of content", () => {
    const p = writeFixture(".env.production", "DEBUG=true\n");
    const { exitCode, blocked } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
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
    const { exitCode, blocked, reason } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
    expect(reason).toContain("aws-access-key");
  });

  it("blocks a file containing an email address", () => {
    const p = writeFixture("contacts.txt", "Email: user@example.com\n");
    const { exitCode, blocked } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
  });

  it("blocks a file containing a private IP", () => {
    const p = writeFixture("infra.txt", "server: 192.168.1.100\n");
    const { exitCode, blocked } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
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

// ── binary file handling ─────────────────────────────────────────────────────

describe("pre-tool-use-hook — binary file handling", () => {
  it("blocks when a secret appears before the first NUL byte", () => {
    const content = Buffer.concat([
      Buffer.from("key=AKIAIOSFODNN7EXAMPLE\n"),
      Buffer.from([0x00]),
      Buffer.from("binary data"),
    ]);
    const p = join(tmpDir, "binary-secret-before-nul.bin");
    writeFileSync(p, content);
    const { exitCode, blocked } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
  });

  it("allows a binary file when no secret appears before the first NUL byte", () => {
    const content = Buffer.concat([
      Buffer.from("clean text\n"),
      Buffer.from([0x00]),
      Buffer.from("AKIAIOSFODNN7EXAMPLE"),
    ]);
    const p = join(tmpDir, "binary-secret-after-nul.bin");
    writeFileSync(p, content);
    const { exitCode } = runHook("Read", p);
    expect(exitCode).toBe(0);
  });

  it("allows a binary file that starts with NUL", () => {
    const content = Buffer.concat([
      Buffer.from([0x00]),
      Buffer.from("AKIAIOSFODNN7EXAMPLE"),
    ]);
    const p = join(tmpDir, "binary-nul-start.bin");
    writeFileSync(p, content);
    const { exitCode } = runHook("Read", p);
    expect(exitCode).toBe(0);
  });
});

// ── transcript tail read ────────────────────────────────────────────────────

describe("pre-tool-use-hook — transcript tail read (64 KB)", () => {
  it("[allow-all] in a large transcript (>64KB) is respected when near the end", () => {
    // Build a transcript larger than 64KB with the allow tag in the last message
    const filler = JSON.stringify({
      type: "user",
      message: { role: "user", content: "x".repeat(1024) },
    });
    const fillerLines = Array.from({ length: 70 }, () => filler).join("\n");
    const allowLine = JSON.stringify({
      type: "user",
      message: { role: "user", content: "[allow-all] read everything" },
    });
    const transcriptContent = `${fillerLines}\n${allowLine}\n`;
    const tp = join(tmpDir, "large-transcript.jsonl");
    writeFileSync(tp, transcriptContent, "utf8");

    const p = writeFixture(
      "large-transcript-test.txt",
      "key=AKIAIOSFODNN7EXAMPLE\n",
    );
    const { exitCode } = runHook("Read", p, { transcriptPath: tp });
    expect(exitCode).toBe(0);
  });
});

// ── Bash tool — env var expansion ────────────────────────────────────────────

describe("pre-tool-use-hook — Bash tool (env var expansion)", () => {
  it("blocks echo $TOKEN when TOKEN contains an AWS key", () => {
    const { exitCode, blocked } = runBashHook("echo $TOKEN", {
      env: { TOKEN: "AKIAIOSFODNN7EXAMPLE" },
    });
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
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
    const { exitCode, blocked } = runBashHook("echo AKIAIOSFODNN7EXAMPLE");
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
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
  it.each(["cat", "head", "tail", "less", "more", "bat", "nl"])(
    "blocks %s on a file with secrets",
    (cmd) => {
      const p = writeFixture(
        `creds-${cmd}.txt`,
        "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n",
      );
      const { exitCode, blocked } = runBashHook(`${cmd} ${p}`);
      expect(exitCode).toBe(2);
      expect(blocked).toBe(true);
    },
  );

  it("blocks cat on a file with PII", () => {
    const p = writeFixture("contacts-bash.txt", "Email: user@example.com\n");
    const { exitCode, blocked } = runBashHook(`cat ${p}`);
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
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
    const { exitCode, blocked } = runBashHook(`cat ${p} | grep KEY`);
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
  });

  it("allows cat in a compound command (pipe) on a clean file", () => {
    const p = writeFixture("pipe-clean.txt", "nothing sensitive here\n");
    const { exitCode } = runBashHook(`cat ${p} | grep text`);
    expect(exitCode).toBe(0);
  });

  it("blocks cat on a .env.* file by name", () => {
    const p = writeFixture(".env.bash-name", "DEBUG=true\n");
    const { exitCode, blocked } = runBashHook(`cat ${p}`);
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
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
    const { exitCode, blocked } = runHook("Read", p, {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
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
    const { exitCode, blocked } = runHook("Read", p, {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
  });

  it("blocks when transcript path is missing (no allow tags)", () => {
    const p = writeFixture(
      "config-no-transcript.txt",
      "key=AKIAIOSFODNN7EXAMPLE\n",
    );
    const { exitCode, blocked } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
  });

  it("blocks when transcript path points to non-existent file", () => {
    const p = writeFixture(
      "config-bad-transcript.txt",
      "key=AKIAIOSFODNN7EXAMPLE\n",
    );
    const { exitCode, blocked } = runHook("Read", p, {
      transcriptPath: "/tmp/no-such-transcript.jsonl",
    });
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
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
    const { exitCode, blocked } = runHook("Read", p, {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
  });

  it("[allow-secret] is consumed after a tool_result", () => {
    const transcript = writeTranscriptWithToolResults([
      { text: "[allow-secret] check these files" },
      { toolResult: "first tool result" },
    ]);
    const p = writeFixture("secret-consumed.txt", "key=AKIAIOSFODNN7EXAMPLE\n");
    const { exitCode, blocked } = runHook("Read", p, {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
  });

  it("[allow-pii] is consumed after a tool_result", () => {
    const transcript = writeTranscriptWithToolResults([
      { text: "[allow-pii] read the contacts" },
      { toolResult: "previous tool output" },
    ]);
    const p = writeFixture("pii-consumed.txt", "email=user@example.com\n");
    const { exitCode, blocked } = runHook("Read", p, {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
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
    const { exitCode, blocked } = runHook("Read", p, {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
  });

  it("[allow-all] consumed for Bash after tool_result", () => {
    const transcript = writeTranscriptWithToolResults([
      { text: "[allow-all] run the commands" },
      { toolResult: "result of first command" },
    ]);
    const { exitCode, blocked } = runBashHook("echo AKIAIOSFODNN7EXAMPLE", {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
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
    const { exitCode } = runHookWithRawInput("not json");
    expect(exitCode).toBe(0);
  });
});

// ── SENSITIVE_CANARY_CATEGORIES ───────────────────────────────────────────────

describe("pre-tool-use-hook — SENSITIVE_CANARY_CATEGORIES", () => {
  it("pii-only: allows reading .env files (secret guard disabled)", () => {
    const dir = join(tmpDir, "pii-only-env");
    mkdirSync(dir, { recursive: true });
    const p = join(dir, ".env");
    writeFileSync(p, "DEBUG=true\n", "utf8");
    const { exitCode } = runHook("Read", p, {
      env: { SENSITIVE_CANARY_CATEGORIES: "pii" },
    });
    expect(exitCode).toBe(0);
  });

  it("pii-only: allows a file containing only secrets", () => {
    const p = writeFixture("pii-only-secret.txt", "key=AKIAIOSFODNN7EXAMPLE");
    const { exitCode } = runHook("Read", p, {
      env: { SENSITIVE_CANARY_CATEGORIES: "pii" },
    });
    expect(exitCode).toBe(0);
  });

  it("pii-only: still blocks a file containing PII", () => {
    const p = writeFixture("pii-only-pii.txt", "card: 4111111111111111");
    const { exitCode, blocked } = runHook("Read", p, {
      env: { SENSITIVE_CANARY_CATEGORIES: "pii" },
    });
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
  });

  it("secret-only: allows a file containing only PII", () => {
    const p = writeFixture("secret-only-pii.txt", "card: 4111111111111111");
    const { exitCode } = runHook("Read", p, {
      env: { SENSITIVE_CANARY_CATEGORIES: "secret" },
    });
    expect(exitCode).toBe(0);
  });

  it("secret-only: still blocks a file containing secrets", () => {
    const p = writeFixture(
      "secret-only-secret.txt",
      "key=AKIAIOSFODNN7EXAMPLE",
    );
    const { exitCode, blocked } = runHook("Read", p, {
      env: { SENSITIVE_CANARY_CATEGORIES: "secret" },
    });
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
  });

  it("secret-only: allows a bash command containing only PII", () => {
    const { exitCode } = runBashHook("echo 4111111111111111", {
      env: { SENSITIVE_CANARY_CATEGORIES: "secret" },
    });
    expect(exitCode).toBe(0);
  });

  it("unset: blocks both secrets and PII (default behavior)", () => {
    const p = writeFixture(
      "default-both.txt",
      "key=AKIAIOSFODNN7EXAMPLE\ncard: 4111111111111111",
    );
    const { exitCode, reason } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(reason).toContain("aws-access-key");
    expect(reason).toContain("pii-credit-card");
  });
});

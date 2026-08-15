import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  AWS_KEY,
  runBashHook,
  runHook,
  runHookWithRawInput,
  runToolHook,
  useFixtureDir,
} from "./hook-harness.ts";

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
    const p = writeFixture(
      "contacts.txt",
      "Email: ada@analytical-engines.org\n",
    );
    const { exitCode, blocked } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
  });

  // A private address is not personal data, and an inventory full of them is
  // the file this tool is most often pointed at.
  it("allows a file of private IPs", () => {
    const p = writeFixture("infra.txt", "server: client 192.168.1.100\n");
    expect(runHook("Read", p).exitCode).toBe(0);
  });

  it("blocks a file containing a labelled public IP", () => {
    const p = writeFixture("access.log", "client IP address 8.8.8.8\n");
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
    const p = writeFixture("pii.txt", "Email: ada@analytical-engines.org\n");
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

// ── large file head read (1 MiB) ─────────────────────────────────────────────

describe("pre-tool-use-hook — large file head read (1 MiB)", () => {
  // readFileSync has no size limit, so a file of arbitrary size was read whole
  // and ground through every rule — a hang on a multi-GB log, and a hang is a
  // fail-open. Only the first 1 MiB is scanned now; a secret past the cut is
  // missed, the same trade the transcript tail read above already makes.
  it("blocks a secret within the first 1 MiB", () => {
    const p = writeFixture(
      "large-within-head.txt",
      `${"x".repeat(512 * 1024)}\nkey=AKIAIOSFODNN7EXAMPLE\n`,
    );
    const { exitCode } = runHook("Read", p);
    expect(exitCode).toBe(2);
  });

  it("does not see a secret past the 1 MiB cut", () => {
    const p = writeFixture(
      "large-beyond-head.txt",
      `${"x".repeat(1100 * 1024)}\nkey=AKIAIOSFODNN7EXAMPLE\n`,
    );
    const { exitCode } = runHook("Read", p);
    expect(exitCode).toBe(0);
  });

  // Sizing the buffer from `stat` rather than from the cap made the read believe
  // the file. procfs entries are regular files that report zero bytes and give
  // content anyway, so the read came back empty and the call was allowed.
  // `readFileSync`, which the cap replaced, read to EOF instead.
  //
  // There is no procfs on macOS, so this is the case CI runs and a developer's
  // machine skips — and CI is what corrected it. The first version read
  // `/proc/self/environ` with the key somewhere in the middle and expected a
  // block; it got an allow, because the content is NUL-separated and everything
  // past the first NUL is dropped as binary. So the key goes in the first
  // variable, which is what makes this a test of the read rather than of the
  // truncation. What the truncation costs is a limitation of its own, written up
  // in the README.
  it.skipIf(process.platform !== "linux")(
    "reads a regular file that reports a size of zero",
    () => {
      const { exitCode } = runBashHook("cat /proc/self/environ", {
        // First, so it lands before the first NUL. `replaceEnv` keeps the order.
        env: {
          LEAKED_KEY: "AKIAIOSFODNN7EXAMPLE",
          PATH: process.env["PATH"] ?? "",
        },
        replaceEnv: true,
      });
      expect(exitCode).toBe(2);
    },
  );
});

// The `.env` name block is a secret guard — `shouldBlockEnvFile` asks whether the
// secret category is on — so the tag that lifts it has to allow secrets. Any tag
// at all used to lift it, and `parseAllowTags` reads `[allow-<anything>]`, so a
// mistyped `[allow-pi]` turned off the guard the README leads with.
describe("pre-tool-use-hook — which allow tag lifts the .env block", () => {
  const writeFixture = useFixtureDir("env-allow-tags");

  const withTag = (tag: string, file: string): number => {
    const transcript = writeFixture(
      `t-${tag}.jsonl`,
      `${JSON.stringify({ message: { role: "user", content: `[allow-${tag}] read it` } })}\n`,
    );
    return runHook("Read", file, { transcriptPath: transcript }).exitCode;
  };

  it.each(["secret", "all"])("[allow-%s] lifts it", (tag) => {
    const file = writeFixture(".env", "TOKEN=whatever");
    expect(withTag(tag, file)).toBe(0);
  });

  it.each(["pii", "banana", "pi"])("[allow-%s] does not lift it", (tag) => {
    const file = writeFixture(".env", "TOKEN=whatever");
    expect(withTag(tag, file)).toBe(2);
  });
});

// README states these as contracts, and each survived being changed: the depth
// limit set to 1, the glob match cap set to 1, the transcript tail cut to 1 KB.
describe("pre-tool-use-hook — the documented limits", () => {
  const writeFixture = useFixtureDir("limits");

  // Four levels of inline text are inspected; the fifth is not.
  it("inline code is followed four levels deep and no further", () => {
    const file = writeFixture("depth.txt", `key=${AWS_KEY}`);
    const four = `sh -c "sh -c \\"sh -c 'cat ${file}'\\""`;
    expect(runBashHook(four).exitCode).toBe(2);
    const five = `sh -c "sh -c \\"sh -c 'sh -c \\\\"cat ${file}\\\\"'\\""`;
    expect(runBashHook(five).exitCode).toBe(0);
  });

  // A glob's matches are scanned up to the cap. Two files, both secret-bearing,
  // in a directory of their own: at a cap of 1 the second would go unread.
  it("more than one match of a pattern is scanned", () => {
    const dir = writeFixture.path();
    writeFixture("g-clean.txt", "nothing here");
    writeFixture("g-secret.txt", `key=${AWS_KEY}`);
    expect(runBashHook(`cat ${dir}/g-*.txt`).exitCode).toBe(2);
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

// Exempting a template name assumed the contents would be read instead. Two
// things stop them being read whole, and a file carrying either was passing on
// its name after all.
describe("pre-tool-use-hook — .env templates", () => {
  const writeFixture = useFixtureDir("env-templates");

  it("a template holding placeholders is readable", () => {
    const p = writeFixture(".env.example", "TOKEN=changeme\n");
    expect(runHook("Read", p).exitCode).toBe(0);
  });

  it("a template holding a real key is not", () => {
    const p = writeFixture(".env.example", `AWS=${AWS_KEY}\n`);
    expect(runHook("Read", p).exitCode).toBe(2);
  });

  it("a template whose contents cannot be read past a NUL is not", () => {
    const p = writeFixture(".env.nul.example", `\0AWS=${AWS_KEY}\n`);
    expect(runHook("Read", p).exitCode).toBe(2);
  });

  it("a template larger than the per-file cut is not", () => {
    const p = writeFixture(
      ".env.big.example",
      `${"x".repeat(1_100_000)}\nAWS=${AWS_KEY}\n`,
    );
    expect(runHook("Read", p).exitCode).toBe(2);
  });

  // Every way of not reading a template falls back on its name. Filling the byte
  // budget first was a way past the guard, and so was a FIFO with a template
  // name — the contents are what the exemption relies on.
  // Named outright, so the ordering that puts literals before patterns does not
  // rescue it: the padding really is read first and really does spend the
  // budget, which is the case this guards.
  it("a template reached after the byte budget is blocked", () => {
    const dir = writeFixture.path();
    const pad = "the quick brown fox ".repeat(55_000);
    const names: string[] = [];
    for (let i = 0; i < 70; i++) {
      names.push(writeFixture(`pad${i}.log`, pad));
    }
    const template = writeFixture(".env.late.example", "TOKEN=changeme\n");
    expect(runBashHook(`cat ${names.join(" ")} ${template}`).exitCode).toBe(2);
    expect(dir.length).toBeGreaterThan(0);
  });

  // The name-based fallback has three gates and a precondition, and deleting any
  // of the four left the suite green.
  it("a template that does not exist is not blocked", () => {
    const absent = writeFixture.path(".env.absent.example");
    expect(runBashHook(`cat ${absent}`).exitCode).toBe(0);
  });

  it("the fallback is off when secrets are not a category", () => {
    const fifo = writeFixture.path(".env.cat.fifo");
    execFileSync("mkfifo", [fifo]);
    expect(
      runHook("Read", fifo, { env: { SENSITIVE_CANARY_CATEGORIES: "pii" } })
        .exitCode,
    ).toBe(0);
  });

  // The tag that lifts a secret guard has to allow secrets. Any tag at all
  // lifted it once, so a mistyped one turned off the guard the README leads
  // with, and this path had no test of its own.
  it.each(["pii", "banana", "everything"])(
    "[allow-%s] does not lift the fallback",
    (tag) => {
      // A template name, so the primary guard steps aside and the fallback is
      // the thing being asked.
      const fifo = writeFixture.path(`.env.${tag}.example`);
      execFileSync("mkfifo", [fifo]);
      expect(
        runHook("Read", fifo, {
          transcriptPath: writeTranscript([`[allow-${tag}] read it`]),
        }).exitCode,
      ).toBe(2);
    },
  );

  it.each(["secret", "all"])("[allow-%s] does lift it", (tag) => {
    const fifo = writeFixture.path(`.env.lift-${tag}.example`);
    execFileSync("mkfifo", [fifo]);
    expect(
      runHook("Read", fifo, {
        transcriptPath: writeTranscript([`[allow-${tag}] read it`]),
      }).exitCode,
    ).toBe(0);
  });

  it("the fallback honours an allow tag", () => {
    const fifo = writeFixture.path(".env.tag.fifo");
    execFileSync("mkfifo", [fifo]);
    expect(
      runHook("Read", fifo, {
        transcriptPath: writeTranscript(["[allow-secret] read it"]),
      }).exitCode,
    ).toBe(0);
  });

  // `.env.` with the dot: without it `.environment` reads as an environment
  // file, and only a path that is never read shows the difference.
  it("a fifo named .environment is not an env file", () => {
    const fifo = writeFixture.path(".environment");
    execFileSync("mkfifo", [fifo]);
    expect(runHook("Read", fifo).exitCode).toBe(0);
  });

  // Literals before patterns is what stops one expensive glob starving the
  // rest, and reversing the order left the suite green.
  it("a file named outright is scanned before a pattern", () => {
    const dir = writeFixture.path();
    const pad = "the quick brown fox ".repeat(55_000);
    for (let i = 0; i < 70; i++) writeFixture(`fill${i}.log`, pad);
    const secret = writeFixture("zz-named.txt", `key=${AWS_KEY}`);
    expect(runBashHook(`cat ${secret} ${dir}/fill*.log`).exitCode).toBe(2);
  });

  it("a fifo with a template name is blocked", () => {
    const fifo = writeFixture.path(".env.fifo.example");
    execFileSync("mkfifo", [fifo]);
    expect(runHook("Read", fifo).exitCode).toBe(2);
  });

  // `endsWith`, not `includes`: `.env.distributed` ends in neither template
  // suffix and is a real environment file.
  it.each([
    ".env",
    ".env.production",
    ".env.local",
    ".env.distributed",
    ".env.exampleish",
  ])("%s is still blocked on its name", (name) => {
    const p = writeFixture(name, "TOKEN=changeme\n");
    expect(runHook("Read", p).exitCode).toBe(2);
  });
});

// A relative path is relative to where the tool runs, which the payload carries.
// Nothing asserted that, so deleting the line that reads it left the suite green
// while every relative path went unscanned.
// A `cd` the shell would refuse does not move the shell, so the read that
// follows happens where it started. Following it anyway left the relative path
// resolving against nothing, and so unscanned. Tested here rather than in the
// parser: the guard asks the filesystem, which the parser cannot.
describe("pre-tool-use-hook — a cd that would not happen", () => {
  const writeFixture = useFixtureDir("cd-guard");

  it("a cd into a directory that does not exist leaves the base alone", () => {
    writeFixture("relative-secret.txt", `key=${AWS_KEY}`);
    expect(
      runBashHook("cd /definitely-not-here && cat relative-secret.txt", {
        cwd: writeFixture.path(),
      }).exitCode,
    ).toBe(2);
  });

  it("a cd through an unexpanded variable leaves the base alone", () => {
    writeFixture("var-secret.txt", `key=${AWS_KEY}`);
    expect(
      runBashHook("cd $TARGET && cat var-secret.txt", {
        cwd: writeFixture.path(),
      }).exitCode,
    ).toBe(2);
  });

  it("a cd into a file rather than a directory leaves the base alone", () => {
    const notADirectory = writeFixture("not-a-dir", "x");
    writeFixture("file-secret.txt", `key=${AWS_KEY}`);
    expect(
      runBashHook(`cd ${notADirectory} && cat file-secret.txt`, {
        cwd: writeFixture.path(),
      }).exitCode,
    ).toBe(2);
  });

  // The directory test alone would let this through: a directory really named
  // `$TARGET` exists, so following the unexpanded name lands somewhere real —
  // just not where the shell would have gone.
  it("a variable is not followed even when a directory bears its name", () => {
    const literal = writeFixture.path("$TARGET");
    mkdirSync(literal, { recursive: true });
    writeFileSync(join(literal, "decoy.txt"), "nothing here\n", "utf8");
    writeFixture("decoy.txt", `key=${AWS_KEY}`);
    expect(
      runBashHook("cd $TARGET && cat decoy.txt", {
        cwd: writeFixture.path(),
      }).exitCode,
    ).toBe(2);
  });

  // The directory test alone would let this through: a directory really named
  // `$TARGET` exists, so following the unexpanded name lands somewhere real —
  // just not where the shell would have gone.
  it("a variable is not followed even when a directory bears its name", () => {
    const literal = writeFixture.path("$TARGET");
    mkdirSync(literal, { recursive: true });
    writeFileSync(join(literal, "decoy.txt"), "nothing here\n", "utf8");
    writeFixture("decoy.txt", `key=${AWS_KEY}`);
    expect(
      runBashHook("cd $TARGET && cat decoy.txt", {
        cwd: writeFixture.path(),
      }).exitCode,
    ).toBe(2);
  });

  // And the base does move when the shell's would.
  it("a cd into a directory that exists moves the base", () => {
    const inner = writeFixture.path("inner");
    mkdirSync(inner, { recursive: true });
    writeFileSync(join(inner, "moved-secret.txt"), `key=${AWS_KEY}`, "utf8");
    expect(
      runBashHook("cd inner && cat moved-secret.txt", {
        cwd: writeFixture.path(),
      }).exitCode,
    ).toBe(2);
  });
});

describe("pre-tool-use-hook — the directory a relative path is relative to", () => {
  const writeFixture = useFixtureDir("cwd");

  it("a relative path in a command resolves against the payload's cwd", () => {
    const dir = writeFixture.path();
    writeFixture("creds.txt", `key=${AWS_KEY}`);
    const result = runToolHook(
      "Bash",
      { command: "cat creds.txt" },
      { cwd: dir },
    );
    expect(result.exitCode).toBe(2);
  });

  it("a relative path in a Read resolves against it too", () => {
    const dir = writeFixture.path();
    writeFixture("read-me.txt", `key=${AWS_KEY}`);
    const result = runToolHook(
      "Read",
      { file_path: "read-me.txt" },
      { cwd: dir },
    );
    expect(result.exitCode).toBe(2);
  });

  it("a leading cd moves it", () => {
    const dir = writeFixture.path();
    writeFixture("cd-target.txt", `key=${AWS_KEY}`);
    expect(runBashHook(`cd ${dir} && cat cd-target.txt`).exitCode).toBe(2);
  });

  // A `cd` after the read, inside a subshell, or with an argument this cannot
  // resolve, all leave the base where it was — pointing the scan somewhere else
  // is how a read stops being seen.
  it.each([
    "cat cd-after.txt && cd /tmp",
    "(cd /tmp && ls) && cat cd-after.txt",
    "cd - && cat cd-after.txt",
    "cd $SOMEWHERE && cat cd-after.txt",
  ])("%s still scans against the payload's cwd", (command) => {
    const dir = writeFixture.path();
    writeFixture("cd-after.txt", `key=${AWS_KEY}`);
    expect(runToolHook("Bash", { command }, { cwd: dir }).exitCode).toBe(2);
  });

  // Two files of the same name in different directories are two files.
  it("the same basename in two directories is scanned twice", () => {
    const dir = writeFixture.path();
    const { mkdirSync, writeFileSync } = require("node:fs");
    mkdirSync(`${dir}/a`, { recursive: true });
    mkdirSync(`${dir}/b`, { recursive: true });
    writeFileSync(`${dir}/a/notes.md`, "nothing here");
    writeFileSync(`${dir}/b/notes.md`, `key=${AWS_KEY}`);
    expect(
      runBashHook(`cat ${dir}/a/notes.md ${dir}/b/notes.md`).exitCode,
    ).toBe(2);
  });
});

// ── path shapes the shell expands ────────────────────────────────────────────

// Each of these names a real file once the shell is done with it, and each was
// allowed: the candidate was collected and then dropped, because nothing on disk
// is called `~/secrets.txt` or `.env{,.bak}`.
describe("pre-tool-use-hook — shell expansion of a path", () => {
  const writeFixture = useFixtureDir("expansion");

  it("~ is the home directory", () => {
    const dir = writeFixture.path();
    writeFixture("secrets.txt", `key=${AWS_KEY}`);
    const result = runBashHook("cat ~/secrets.txt", { env: { HOME: dir } });
    expect(result.exitCode).toBe(2);
  });

  it("a brace expansion names both files", () => {
    writeFixture(".env", "TOKEN=whatever");
    const result = runBashHook(`cat ${writeFixture.path()}/.env{,.bak}`);
    expect(result.exitCode).toBe(2);
    expect(result.blocked).toBe(true);
  });

  // The literal is kept beside the expansion. Returning only the matches lost
  // two things the hook had before expansion existed.
  it("a pattern matching nothing is still blocked on its name", () => {
    const result = runBashHook(
      `cat ${writeFixture.path()}/nothing-here/.env.*`,
    );
    expect(result.exitCode).toBe(2);
    expect(result.blocked).toBe(true);
  });

  it("a file whose name contains glob characters is scanned", () => {
    const file = writeFixture("report[2].txt", `key=${AWS_KEY}`);
    expect(runBashHook(`cat ${file}`).exitCode).toBe(2);
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
    const p = writeFixture(
      "contacts-bash.txt",
      "Email: ada@analytical-engines.org\n",
    );
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

  // The `.env` block is a secret guard, so the PII tag does not lift it. It used
  // to, along with every other bracketed word beginning `allow-`.
  it("[allow-pii] does not bypass cat on a .env.* file", () => {
    const transcript = writeTranscript(["[allow-pii] show me the env"]);
    const p = writeFixture(".env.bash-pii", "DEBUG=true\n");
    const { exitCode } = runBashHook(`cat ${p}`, {
      transcriptPath: transcript,
    });
    expect(exitCode).toBe(2);
  });

  it("[allow-secret] bypasses cat on a .env.* file", () => {
    const transcript = writeTranscript(["[allow-secret] show me the env"]);
    const p = writeFixture(".env.bash-secret", "DEBUG=true\n");
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

  it("[allow-pii] does not bypass the .env name block", () => {
    const transcript = writeTranscript(["[allow-pii] read the env file"]);
    const p = writeFixture(".env.bypass-pii", "KEY=value");
    const { exitCode } = runHook("Read", p, { transcriptPath: transcript });
    expect(exitCode).toBe(2);
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
    const p = writeFixture(
      "pii-allow.txt",
      "email=ada@analytical-engines.org\n",
    );
    const { exitCode } = runHook("Read", p, { transcriptPath: transcript });
    expect(exitCode).toBe(0);
  });

  it("[allow-pii] bypasses PII but not secrets in content scan", () => {
    const transcript = writeTranscript(["[allow-pii] ok"]);
    const p = writeFixture(
      "mixed-allow-pii.txt",
      "email=ada@analytical-engines.org\nkey=AKIAIOSFODNN7EXAMPLE\n",
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
    const p = writeFixture(
      "pii-consumed.txt",
      "email=ada@analytical-engines.org\n",
    );
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

// Only exit 2 blocks. An unforeseen error exits 1, which passes — so a crash
// anywhere in the hook silently switched the protection off. It now stops the
// call instead, since an unfinished check vouches for nothing.
// Claude Code writes what the user did not type into the transcript as user
// messages: the output of a `!` command, slash-command names, system reminders.
// A tag in any of those lifted the guard for the next tool call, so `grep -r
// allow-all` switched the protection off.
describe("pre-tool-use-hook — where an allow tag may come from", () => {
  const writeFixture = useFixtureDir("tag-source");

  const withTranscript = (content: string): number => {
    const secret = writeFixture("leak.txt", `key=${AWS_KEY}`);
    return runHook("Read", secret, {
      transcriptPath: writeTranscript([content]),
    }).exitCode;
  };

  it("a tag the user typed lifts the guard", () => {
    expect(withTranscript("[allow-all] please read it")).toBe(0);
  });

  it.each([
    "local-command-stdout",
    "local-command-stderr",
    "command-name",
    "command-args",
    "bash-stdout",
    "system-reminder",
  ])("a tag inside <%s> does not", (element) => {
    expect(
      withTranscript(`<${element}>saw [allow-all] in there</${element}>`),
    ).toBe(2);
  });

  // Quoted, not issued: a pasted log or diff is not the user asking.
  it.each([
    "here is a log:\n```\n2026-01-01 saw [allow-all]\n```\nplease read it",
    "~~~\n[allow-all]\n~~~",
    "```sh\ngrep -r '[allow-all]' .\n```",
  ])("a tag inside a fence does not", (content) => {
    expect(withTranscript(content)).toBe(2);
  });

  // Backticks around the tag are how this project's own documentation writes
  // it, so treating them as quoting refused the form it teaches — and refused
  // it silently, since the block then advised adding the tag it had ignored.
  it.each([
    "`[allow-all]` please read it",
    "please read it with `[allow-all]`",
    "use `[allow-secret]` for that",
  ])("a tag in backticks still lifts the guard", (content) => {
    expect(withTranscript(content)).toBe(0);
  });

  // A line the runtime wrote as an assistant turn is not user input.
  it("a tag on an assistant line does not lift the guard", () => {
    const secret = writeFixture("assistant.txt", `key=${AWS_KEY}`);
    const transcript = writeFixture(
      "assistant.jsonl",
      `${JSON.stringify({ type: "assistant", message: { role: "user", content: "[allow-all] go" } })}\n`,
    );
    expect(
      runHook("Read", secret, { transcriptPath: transcript }).exitCode,
    ).toBe(2);
  });

  // An opening tag with nothing closing it takes the rest of the message.
  it("a tag after an unclosed synthetic element does not", () => {
    expect(
      withTranscript("<local-command-stdout>output [allow-all] more"),
    ).toBe(2);
  });

  // The wrapper must not swallow the rest of the message.
  it("a tag beside synthetic content still lifts the guard", () => {
    expect(
      withTranscript(
        "<local-command-stdout>output</local-command-stdout>\n[allow-all] now read it",
      ),
    ).toBe(0);
  });
});

// A file whose every other byte is NUL used to stop the scan after one
// character. PowerShell 5.1 writes UTF-16LE by default.
describe("pre-tool-use-hook — UTF-16", () => {
  const writeFixture = useFixtureDir("utf16");

  const writeBytes = (name: string, bytes: Buffer): string => {
    const p = writeFixture.path(name);
    writeFileSync(p, bytes);
    return p;
  };

  const utf16le = (text: string): Buffer => Buffer.from(text, "utf16le");

  it.each([
    ["little-endian", (t: string) => utf16le(t)],
    ["big-endian", (t: string) => Buffer.from(utf16le(t)).swap16()],
    [
      "with a byte-order mark",
      (t: string) => Buffer.concat([Buffer.from([0xff, 0xfe]), utf16le(t)]),
    ],
  ])("a secret in a %s file is found", (label, encode) => {
    const p = writeBytes(
      `${label.replace(/\W/g, "")}.txt`,
      encode(`key=${AWS_KEY}\n`),
    );
    expect(runHook("Read", p).exitCode).toBe(2);
  });

  it("a clean UTF-16 file is allowed", () => {
    const p = writeBytes("clean.txt", utf16le("hello, nothing here\n"));
    expect(runHook("Read", p).exitCode).toBe(0);
  });

  // The byte-order mark decides it outright, and each branch needs a case only
  // it can answer: without the swap, a big-endian marked file reads as noise;
  // without the little-endian branch, a file whose text is Japanese has no NUL
  // in its opening pairs to fall back on.
  it("a big-endian file with a mark is swapped", () => {
    const p = writeBytes(
      "be-bom.txt",
      Buffer.concat([
        Buffer.from([0xfe, 0xff]),
        Buffer.from(utf16le(`key=${AWS_KEY}\n`)).swap16(),
      ]),
    );
    expect(runHook("Read", p).exitCode).toBe(2);
  });

  it("a little-endian file with a mark and no ASCII prefix is read", () => {
    const p = writeBytes(
      "le-bom-cjk.txt",
      Buffer.concat([
        Buffer.from([0xff, 0xfe]),
        utf16le(`${"あ".repeat(9000)}\nkey=${AWS_KEY}\n`),
      ]),
    );
    expect(runHook("Read", p).exitCode).toBe(2);
  });

  // A file whose first characters are Japanese has no zero byte in them at all,
  // and five hundred pairs of prefix decided the whole file.
  it.each([
    ["little-endian", (t: string) => utf16le(t)],
    ["big-endian", (t: string) => Buffer.from(utf16le(t)).swap16()],
  ])("a %s file that opens with Japanese is read", (_label, encode) => {
    const p = writeBytes(
      `cjk-${_label}.txt`,
      encode(`${"あ".repeat(512)}\nkey=${AWS_KEY}\n`),
    );
    expect(runHook("Read", p).exitCode).toBe(2);
  });

  // One stray NUL is not evidence of an encoding. Reading a UTF-8 file as
  // UTF-16 turns text the scan could read into nonsense it cannot.
  it("a UTF-8 file with a single NUL in it is not read as UTF-16", () => {
    const p = writeBytes(
      "one-nul.txt",
      Buffer.concat([
        Buffer.from(`key=${AWS_KEY}\n`),
        Buffer.from([0x00]),
        Buffer.from("binary data"),
      ]),
    );
    expect(runHook("Read", p).exitCode).toBe(2);
  });

  it("a UTF-16 template stopped by a NUL falls back on its name", () => {
    const p = writeBytes(
      ".env.utf16.example",
      Buffer.concat([
        // A byte-order mark, because a NUL character in UTF-16 is `00 00` — one
        // byte on each side of the pair — so the parity heuristic could never
        // see this file, only the mark can.
        Buffer.from([0xff, 0xfe]),
        utf16le("TOKEN=changeme\n"),
        Buffer.from([0x00, 0x00]),
        utf16le("more\n"),
      ]),
    );
    expect(runHook("Read", p).exitCode).toBe(2);
  });

  it("a UTF-16 template past the per-file cut falls back on its name", () => {
    const p = writeBytes(
      ".env.big.example",
      utf16le(`${"a".repeat(1_100_000)}\nTOKEN=changeme\n`),
    );
    expect(runHook("Read", p).exitCode).toBe(2);
  });

  it("a UTF-16 template read whole is still readable", () => {
    const p = writeBytes(
      ".env.small.example",
      Buffer.concat([Buffer.from([0xff, 0xfe]), utf16le("TOKEN=changeme\n")]),
    );
    expect(runHook("Read", p).exitCode).toBe(0);
  });

  it("a genuinely binary file is not decoded as text", () => {
    const p = writeBytes(
      "blob.bin",
      Buffer.from([0, 1, 2, 3, 0, 255, 0, 7, 9, 0, 0, 0]),
    );
    expect(runHook("Read", p).exitCode).toBe(0);
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
  it.each(["not json", "", "{}", "[]", "null", "42", '{"tool_name":"Read"}'])(
    "%s is still allowed",
    (payload) => {
      expect(runHookWithRawInput(payload).exitCode).toBe(0);
    },
  );
});

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
    const { exitCode } = runBashHook("echo 4532015112830366", {
      env: { SENSITIVE_CANARY_CATEGORIES: "secret" },
    });
    expect(exitCode).toBe(0);
  });

  it("unset: blocks both secrets and PII (default behavior)", () => {
    const p = writeFixture(
      "default-both.txt",
      "key=AKIAIOSFODNN7EXAMPLE\ncard: 4532015112830366",
    );
    const { exitCode, reason } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(reason).toContain("aws-access-key");
    expect(reason).toContain("pii-credit-card");
  });
});

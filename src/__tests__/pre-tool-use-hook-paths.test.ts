import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AWS_KEY,
  runBashHook,
  runToolHook,
  useFixtureDir,
  useTranscripts,
} from "./hook-harness.ts";

const fixture = useFixtureDir("pre-tool-use-paths");
const writeFixture = fixture;
const _tmpDirOf = () => fixture.path();
const writeTranscript = useTranscripts(fixture);
const _writeTranscriptWithToolResults = writeTranscript.withToolResults;
const _writeRawTranscript = writeTranscript.raw;

// Working out which file a command names, before any of it is read: the
// directory a relative path is relative to, a `cd` that may or may not happen,
// and what the shell would expand.

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
      env: { TOKEN: `${AWS_KEY}` },
    });
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
  });

  it("includes the variable name and rule in reason", () => {
    const { reason } = runBashHook("echo $MY_SECRET", {
      env: { MY_SECRET: `${AWS_KEY}` },
    });
    expect(reason).toContain("$MY_SECRET");
    expect(reason).toContain("aws-access-key");
  });

  it("blocks ${TOKEN} brace syntax", () => {
    const { exitCode } = runBashHook("curl -H 'Auth: ${API_TOKEN}'", {
      env: { API_TOKEN: `${AWS_KEY}` },
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
    const { exitCode, blocked } = runBashHook(`echo ${AWS_KEY}`);
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
  });

  it("includes aws-access-key in reason for inline secret", () => {
    const { reason } = runBashHook(`echo ${AWS_KEY}`);
    expect(reason).toContain("aws-access-key");
  });

  it("includes a bird emoji in the reason for Bash block", () => {
    const { reason } = runBashHook(`echo ${AWS_KEY}`);
    expect(reason).toMatch(/[🐦🐧🐤🐔]/u);
  });
});

// ── Bash tool — file-reading command blocking ─────────────────────────────────

describe("pre-tool-use-hook — Bash tool (file-reading commands)", () => {
  it.each(["cat", "head", "tail", "less", "more", "bat", "nl"])(
    "blocks %s on a file with secrets",
    (cmd) => {
      const p = writeFixture(`creds-${cmd}.txt`, `AWS_KEY=${AWS_KEY}\n`);
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
    const p = writeFixture("pipe-secret.txt", `AWS_KEY=${AWS_KEY}\n`);
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

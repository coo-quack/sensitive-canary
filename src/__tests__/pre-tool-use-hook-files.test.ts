import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AWS_KEY,
  runBashHook,
  runHook,
  useFixtureDir,
  useTranscripts,
} from "./hook-harness.ts";

const fixture = useFixtureDir("pre-tool-use-files");
const writeFixture = fixture;
const _tmpDirOf = () => fixture.path();
const writeTranscript = useTranscripts(fixture);
const _writeTranscriptWithToolResults = writeTranscript.withToolResults;
const _writeRawTranscript = writeTranscript.raw;

// Reading a file: which bytes are looked at, how they are decoded, and what
// happens at each limit. A file the hook cannot read whole is the case these
// are mostly about — the caps, the encodings, and the names that decide when
// the contents cannot.

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
    const p = writeFixture("config.txt", `AWS_KEY=${AWS_KEY}\n`);
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
    const p = writeFixture("key.txt", `key=${AWS_KEY}\n`);
    const { reason } = runHook("Read", p);
    expect(reason).toContain("[allow-secret]");
    expect(reason).toContain("[allow-all]");
  });

  it("includes a bird emoji in the reason", () => {
    const p = writeFixture("bird.txt", `key=${AWS_KEY}\n`);
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
    const p = writeFixture("dup.txt", `A=${AWS_KEY}\nB=${AWS_KEY}\n`);
    const { reason } = runHook("Read", p);
    const count = (reason ?? "").split("[Secret]").length - 1;
    expect(count).toBe(1);
  });
});

// ── binary file handling ─────────────────────────────────────────────────────

describe("pre-tool-use-hook — binary file handling", () => {
  it("blocks when a secret appears before the first NUL byte", () => {
    const content = Buffer.concat([
      Buffer.from(`key=${AWS_KEY}\n`),
      Buffer.from([0x00]),
      Buffer.from("binary data"),
    ]);
    const p = join(fixture.path(), "binary-secret-before-nul.bin");
    writeFileSync(p, content);
    const { exitCode, blocked } = runHook("Read", p);
    expect(exitCode).toBe(2);
    expect(blocked).toBe(true);
  });

  it("blocks a secret that appears after the first NUL byte", () => {
    const content = Buffer.concat([
      Buffer.from("clean text\n"),
      Buffer.from([0x00]),
      Buffer.from(`${AWS_KEY}`),
    ]);
    const p = join(fixture.path(), "binary-secret-after-nul.bin");
    writeFileSync(p, content);
    const { exitCode } = runHook("Read", p);
    expect(exitCode).toBe(2);
  });

  it("blocks a secret in a file that starts with NUL", () => {
    const content = Buffer.concat([
      Buffer.from([0x00]),
      Buffer.from(`${AWS_KEY}`),
    ]);
    const p = join(fixture.path(), "binary-nul-start.bin");
    writeFileSync(p, content);
    const { exitCode } = runHook("Read", p);
    expect(exitCode).toBe(2);
  });

  // The other direction: reading past the NULs scans a binary in full, and one
  // holding no credential has to stay readable.
  it("allows a binary file with no secret in it", () => {
    const content = Buffer.alloc(64 * 1024);
    for (let i = 0; i < content.length; i++) content[i] = i % 256;
    const p = join(fixture.path(), "binary-clean.bin");
    writeFileSync(p, content);
    const { exitCode } = runHook("Read", p);
    expect(exitCode).toBe(0);
  });

  it("allows a real compiled binary", () => {
    const p = join(fixture.path(), "binary-real.bin");
    writeFileSync(p, readFileSync(process.execPath).subarray(0, 512 * 1024));
    const { exitCode } = runHook("Read", p);
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
      `${"x".repeat(512 * 1024)}\nkey=${AWS_KEY}\n`,
    );
    const { exitCode } = runHook("Read", p);
    expect(exitCode).toBe(2);
  });

  // Two windows, not one: the first megabyte and the last. `tail -2 app.log`
  // prints the end, and the head-only read looked at exactly the part that was
  // not shown — the end of a log being where a failure has just printed a
  // connection string.
  it("sees a secret in the last megabyte of a large file", () => {
    const p = writeFixture(
      "large-tail.txt",
      `${"x".repeat(4 * 1024 * 1024)}\nkey=${AWS_KEY}\n`,
    );
    expect(runHook("Read", p).exitCode).toBe(2);
  });

  it("sees it through a command that reads the end", () => {
    const p = writeFixture(
      "large-tail-cmd.txt",
      `${"x".repeat(4 * 1024 * 1024)}\nkey=${AWS_KEY}\n`,
    );
    expect(runBashHook(`tail -2 ${p}`).exitCode).toBe(2);
  });

  // What is still missed is the middle, and only when the file is larger than
  // both windows together.
  it("does not see a secret between the two windows", () => {
    const p = writeFixture(
      "large-middle.txt",
      `${"x".repeat(2 * 1024 * 1024)}\nkey=${AWS_KEY}\n${"y".repeat(2 * 1024 * 1024)}`,
    );
    expect(runHook("Read", p).exitCode).toBe(0);
  });

  it("a large file with nothing in it is still allowed", () => {
    const p = writeFixture("large-clean.txt", "x".repeat(4 * 1024 * 1024));
    expect(runHook("Read", p).exitCode).toBe(0);
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
          LEAKED_KEY: `${AWS_KEY}`,
          PATH: process.env["PATH"] ?? "",
        },
        replaceEnv: true,
      });
      expect(exitCode).toBe(2);
    },
  );
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

  // Without a mark the encoding is a guess, and the counts it rests on read a
  // UTF-8 file carrying a few NULs the same as a page of Japanese. Eight pairs
  // of them in front — sixteen bytes — decoded the rest of the file into
  // characters no rule matches, which is the whole of the tool switched off per
  // file. Both readings are scanned now, so the guess costs a pass and hides
  // nothing.
  it.each([1, 7, 8, 64, 300])(
    "a UTF-8 secret behind %i NUL pairs is still found",
    (pairs) => {
      const p = writeBytes(
        `nul-prefix-${pairs}.txt`,
        Buffer.concat([
          Buffer.from("A\0".repeat(pairs), "binary"),
          Buffer.from(`key=${AWS_KEY}\n`),
        ]),
      );
      expect(runHook("Read", p).exitCode).toBe(2);
    },
  );

  // The other side of the same guess. Japanese is full of U+xx00 characters —
  // `一` is U+4E00 — so one per line puts thirty NULs on the minority side of a
  // thirty-line document. Capping that side at a small count read the file as
  // something other than UTF-16, and an ASCII key sitting in it was scanned only
  // as the mojibake its bytes make in UTF-8.
  it("a UTF-16 document whose text is Japanese is read as UTF-16", () => {
    const line = "設定ファイルです。認証情報の一覧。\n";
    const p = writeBytes(
      "ja-no-bom.txt",
      utf16le(`${line.repeat(30)}AWS_KEY=${AWS_KEY}\n`),
    );
    expect(runHook("Read", p).exitCode).toBe(2);
  });

  it("the same Japanese document without a secret is allowed", () => {
    const line = "設定ファイルです。認証情報は含みません。\n";
    const p = writeBytes("ja-clean.txt", utf16le(line.repeat(30)));
    expect(runHook("Read", p).exitCode).toBe(0);
  });
});

// The five-second deadline, which nothing reached.
//
// Two clocks bound one invocation: a ten-second scan budget, which throws, and
// this one, which stops reading between files. Only the budget had a case, so
// the deadline could be deleted or its comparison inverted and the whole suite
// stayed green — on a guard whose job is to keep the hook inside Claude Code's
// PreToolUse timeout, because a hook killed by that timeout does not block.
//
// What makes it observable is the `.env` fallback. A file skipped for time is
// silently not scanned, which reads the same as a file that was clean; an
// `.env` reached after the deadline is blocked on its name instead.
describe("pre-tool-use-hook — the deadline between files", () => {
  const writeFixture = useFixtureDir("deadline");

  // A rule that backtracks, so a modest file costs seconds rather than
  // milliseconds. Several files rather than one big one: the deadline is
  // checked between files, and a single file long enough to pass it also runs
  // past the scan budget, which throws first and proves the wrong guard.
  it("an .env reached after the deadline is blocked on its name", () => {
    const slowConfig = writeFixture(
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
    const slow = [1, 2, 3].map((n) =>
      writeFixture(`slow-${n}.txt`, "eyJ".repeat(7_000)),
    );
    // A template name, so the plain `.env` guard does not decide it: this one
    // is exempt while its contents can be read, and blocked on its name when
    // they cannot. That is what makes the deadline observable.
    const env = writeFixture(
      ".env.after-deadline.example",
      "TOKEN=your-token-here\n",
    );

    // Named in order, which `scanPathsLiteralsFirst` keeps, so the deadline is
    // spent before the `.env` is reached.
    const result = runBashHook(`cat ${slow.join(" ")} ${env}`, {
      env: { SENSITIVE_CANARY_CONFIG: slowConfig },
    });

    expect(result.exitCode).toBe(2);
    expect(result.reason).toContain(
      "the scan for this call had already stopped",
    );
  }, 30_000);

  // The other direction, so the case above is not passing on the `.env` name
  // alone: given time to read it, a template of placeholders is allowed.
  it("the same .env is read when there is time to read it", () => {
    const env = writeFixture(".env.in-time.example", "TOKEN=your-token-here\n");
    expect(runBashHook(`cat ${env}`).exitCode).toBe(0);
  });
});

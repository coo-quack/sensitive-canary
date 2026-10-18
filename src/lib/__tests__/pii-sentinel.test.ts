// The pii-sentinel client and the hooks' use of it, against a fake server.
//
// The hooks are spawned asynchronously here rather than through the shared
// harness: `spawnSync` would hold this worker's event loop, and the fake server
// answering the hook lives on that loop.

import { spawn } from "node:child_process";
import {
  chmodSync,
  chownSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import http from "node:http";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  checkSocket,
  groupIsPrivate,
  judge,
  readPiiSentinelConfig,
  trustedNssSources,
  UnsafeSocketError,
} from "../pii-sentinel.ts";

const PRE_TOOL_USE = fileURLToPath(
  new URL("../../pre-tool-use-hook.ts", import.meta.url),
);
const USER_PROMPT = fileURLToPath(
  new URL("../../user-prompt-submit-hook.ts", import.meta.url),
);

// macOS caps a Unix socket path near 104 bytes, and $TMPDIR there is long.
const dir = mkdtempSync(
  join(process.platform === "darwin" ? "/tmp" : tmpdir(), "sc-ps-"),
);
const socket = join(dir, "s.sock");

interface Received {
  text: string;
  rules: unknown;
  host: string | undefined;
}

let received: Received[] = [];
let answer: (text: string) => { status: number; body: unknown } = () => ({
  status: 200,
  body: { sensitivity: { level: "none" }, categories: {}, findings: [] },
});

const handler: http.RequestListener = (req, res) => {
  let raw = "";
  req.on("data", (c) => (raw += c));
  req.on("end", () => {
    const body = JSON.parse(raw) as { text: string; rules: unknown };
    received.push({
      text: body.text,
      rules: body.rules,
      host: req.headers.host,
    });
    const { status, body: out } = answer(body.text);
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(out));
  });
};
const server = http.createServer(handler);
const others: http.Server[] = [];

// A fake server on another socket path, for the directories made below.
function serveAt(path: string): Promise<void> {
  const s = http.createServer(handler);
  others.push(s);
  return new Promise((resolve) => s.listen(path, resolve));
}

beforeAll(() => new Promise<void>((resolve) => server.listen(socket, resolve)));
afterAll(() => {
  server.close();
  for (const s of others) s.close();
  rmSync(dir, { recursive: true, force: true });
});
afterEach(() => {
  received = [];
  answer = () => ({
    status: 200,
    body: { sensitivity: { level: "none" }, categories: {}, findings: [] },
  });
});

function high(findings: unknown[] = []) {
  return {
    status: 200,
    body: {
      sensitivity: { level: "high" },
      categories: { health_info: 0.99, person_name: 0.98, credentials: 0.01 },
      findings,
    },
  };
}

function writeConfig(name: string, piiSentinel: unknown): string {
  const path = join(dir, name);
  writeFileSync(path, JSON.stringify({ piiSentinel }));
  return path;
}

// A directory under our 0700 test directory with the given mode.
function makeDir(name: string, mode: number): string {
  const path = join(dir, name);
  mkdirSync(path);
  chmodSync(path, mode);
  return path;
}

function runHook(
  hook: string,
  payload: unknown,
  env: Record<string, string>,
): Promise<{ code: number; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn("node", ["--experimental-strip-types", hook], {
      env: { ...process.env, ...env },
    });
    let stderr = "";
    child.stderr.on("data", (c) => (stderr += c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? -1, stderr }));
    child.stdin.end(JSON.stringify(payload));
  });
}

function readFile(
  path: string,
  env: Record<string, string>,
  transcriptPath?: string,
) {
  return runHook(
    PRE_TOOL_USE,
    {
      tool_name: "Read",
      tool_input: { file_path: path },
      transcript_path: transcriptPath,
    },
    env,
  );
}

const MEDICAL = "山本一郎さんは精密検査の結果、2型糖尿病と診断されました。\n";

describe("readPiiSentinelConfig", () => {
  it("is null without an entry and fills in the defaults", () => {
    expect(readPiiSentinelConfig(undefined)).toBeNull();
    expect(readPiiSentinelConfig({ socket: "/tmp/x.sock" })).toEqual({
      socket: "/tmp/x.sock",
      timeoutMs: 3000,
      maxChars: 20000,
      blockOn: "high",
      onUnavailable: "block",
    });
  });

  it.each([
    [[], "must be an object"],
    [{}, "must be a path"],
    [{ socket: "" }, "must be a path"],
    [{ socket: "/a", timeoutMs: 50 }, "timeoutMs"],
    [{ socket: "/a", maxChars: 1.5 }, "maxChars"],
    [{ socket: "/a", blockOn: "none" }, "blockOn"],
    [{ socket: "/a", onUnavailable: "ignore" }, "onUnavailable"],
  ])("refuses %j", (raw, message) => {
    expect(readPiiSentinelConfig(raw)).toContain(message);
  });

  it.each([
    [{ url: "http://example.com:8765" }],
    [{ url: "http://127.0.0.1:8765" }],
    [{ url: "http://[::1]:8765" }],
    [{ socket: "/a", url: "http://127.0.0.1:1" }],
    [{ url: null }],
  ])("refuses %j as no longer supported", (raw) => {
    expect(readPiiSentinelConfig(raw)).toContain(
      '"url" was removed in sensitive-canary v0.10.0',
    );
  });
});

describe("judge", () => {
  it("sends the head of each text without the rules and reads the verdict", async () => {
    answer = () => high([{ type: "person_name", value: "山…", pii: true }]);
    const config = readPiiSentinelConfig({ socket, maxChars: 10 });
    if (config === null || typeof config === "string")
      throw new Error(String(config));
    const { verdicts, unavailable } = await judge(
      [{ source: "a.txt", text: MEDICAL }],
      config,
    );
    expect(unavailable).toBeNull();
    expect(received).toEqual([
      { text: MEDICAL.slice(0, 10), rules: false, host: "localhost" },
    ]);
    expect(verdicts[0]).toMatchObject({
      level: "high",
      categories: ["health_info", "person_name"],
      findings: [{ type: "person_name", value: "山…" }],
    });
  });

  it("reports a server that is not there or answers badly", async () => {
    const missing = readPiiSentinelConfig({
      socket: join(dir, "missing.sock"),
    });
    if (missing === null || typeof missing === "string")
      throw new Error(String(missing));
    expect(await judge([{ source: "a", text: "x" }], missing)).toMatchObject({
      unavailable: expect.stringContaining("ENOENT"),
      refused: null,
    });
    answer = () => ({ status: 413, body: { error: "too large" } });
    const config = readPiiSentinelConfig({ socket });
    if (config === null || typeof config === "string")
      throw new Error(String(config));
    expect(
      (await judge([{ source: "a", text: "x" }], config)).unavailable,
    ).toContain("413");
  });

  // The socket timeout restarts with every byte, so a server that writes one
  // byte every 100 ms and never finishes would hold the hook for as long as it
  // liked. timeoutMs is a total, and the call has to end near it. The server
  // records when its response socket closes, which only happens once the
  // client has destroyed the request, so the cut-off itself is what is checked.
  it("a server that trickles bytes is cut off at timeoutMs in total", async () => {
    const trickle = join(dir, "trickle.sock");
    let serverSawClose: (at: number) => void = () => {};
    const serverClosed = new Promise<number>((resolve) => {
      serverSawClose = resolve;
    });
    const s = http.createServer((req, res) => {
      req.resume();
      res.writeHead(200, { "Content-Type": "application/json" });
      const timer = setInterval(() => res.write(" "), 100);
      res.on("close", () => {
        clearInterval(timer);
        serverSawClose(Date.now());
      });
    });
    others.push(s);
    await new Promise<void>((resolve) => s.listen(trickle, resolve));
    const config = readPiiSentinelConfig({ socket: trickle, timeoutMs: 300 });
    if (config === null || typeof config === "string")
      throw new Error(String(config));
    const start = Date.now();
    const { unavailable } = await judge([{ source: "a", text: "x" }], config);
    const rejectedAt = Date.now();
    expect(unavailable).toContain("no answer within");
    expect(rejectedAt - start).toBeLessThan(1_500);
    const closedAt = await Promise.race([
      serverClosed,
      new Promise<null>((resolve) => setTimeout(() => resolve(null), 2_000)),
    ]);
    expect(closedAt).not.toBeNull();
    expect((closedAt as number) - rejectedAt).toBeLessThan(1_000);
  });
});

describe("socket checks", () => {
  it("accepts a socket in a directory only we can write to", async () => {
    const d = makeDir("private", 0o700);
    const path = join(d, "p.sock");
    await serveAt(path);
    answer = () => high();
    const config = readPiiSentinelConfig({ socket: path });
    if (config === null || typeof config === "string")
      throw new Error(String(config));
    const { verdicts, unavailable } = await judge(
      [{ source: "a", text: MEDICAL }],
      config,
    );
    expect(unavailable).toBeNull();
    expect(verdicts[0]?.level).toBe("high");
  });

  it("refuses a socket in a directory other users can write to, and sends nothing", async () => {
    const d = makeDir("open-0777", 0o777);
    const path = join(d, "o.sock");
    await serveAt(path);
    const config = readPiiSentinelConfig({ socket: path });
    if (config === null || typeof config === "string")
      throw new Error(String(config));
    const { unavailable, refused } = await judge(
      [{ source: "a", text: MEDICAL }],
      config,
    );
    expect(refused).toContain("can be written by other users");
    // The physical path: on macOS /tmp is a link to /private/tmp.
    expect(refused).toMatch(/run `chmod go-w \S*\/open-0777`/);
    expect(unavailable).toBeNull();
    expect(received).toEqual([]);
  });

  it("applies the group rule to a socket in a group-writable directory", async () => {
    // The rule depends on the group of the directory on this machine: a group
    // that is ours alone is accepted, any other group is refused.
    const d = makeDir("group-0770", 0o770);
    const path = join(d, "g.sock");
    await serveAt(path);
    const { gid } = statSync(d);
    if (await groupIsPrivate(gid, process.getgid?.() ?? -1)) {
      await expect(checkSocket(path)).resolves.toBeUndefined();
    } else {
      await expect(checkSocket(path)).rejects.toThrow(
        "can be written by its group",
      );
      await expect(checkSocket(path)).rejects.toBeInstanceOf(UnsafeSocketError);
    }
  });

  it("accepts a socket in a sticky directory others can write to", async () => {
    const d = makeDir("sticky-1777", 0o1777);
    const path = join(d, "t.sock");
    await serveAt(path);
    await expect(checkSocket(path)).resolves.toBeUndefined();
  });

  it("accepts a symlink we own in a sticky directory to our socket", async () => {
    const d = makeDir("sticky-link", 0o1777);
    const link = join(d, "link.sock");
    symlinkSync(socket, link);
    await expect(checkSocket(link)).resolves.toBeUndefined();
  });

  it("refuses a regular file as not a socket", async () => {
    const file = join(dir, "plain.txt");
    writeFileSync(file, "x");
    await expect(checkSocket(file)).rejects.toThrow("is not a socket");
    await expect(checkSocket(file)).rejects.not.toBeInstanceOf(
      UnsafeSocketError,
    );
  });

  it("reports a missing socket as ENOENT", async () => {
    await expect(checkSocket(join(dir, "gone.sock"))).rejects.toThrow("ENOENT");
  });

  // Only root can hand a directory to another user, so this runs as root (the
  // Linux container run) and is skipped elsewhere.
  it.runIf(process.getuid?.() === 0)(
    "refuses a directory that belongs to another user",
    async () => {
      const d = makeDir("theirs", 0o755);
      const path = join(d, "x.sock");
      await serveAt(path);
      chownSync(d, 65534, 65534);
      const refusal = checkSocket(path);
      await expect(refusal).rejects.toThrow(
        "belongs to another user: move the socket to a directory you own",
      );
      await expect(checkSocket(path)).rejects.toBeInstanceOf(UnsafeSocketError);
    },
  );

  it("refuses an abstract socket name", async () => {
    await expect(checkSocket("\0pii-sentinel")).rejects.toThrow("abstract");
    await expect(checkSocket("\0pii-sentinel")).rejects.toBeInstanceOf(
      UnsafeSocketError,
    );
  });
});

describe("PreToolUse hook with pii-sentinel", () => {
  const file = join(dir, "medical.txt");
  beforeAll(() => writeFileSync(file, MEDICAL));

  it("blocks a file the server judges high", async () => {
    answer = () => high();
    const env = { SENSITIVE_CANARY_CONFIG: writeConfig("c1.json", { socket }) };
    const result = await readFile(file, env);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain(
      "pii-sentinel judged this file high sensitivity",
    );
    expect(result.stderr).toContain("[allow-pii]");
    expect(received.map((r) => r.text)).toEqual([MEDICAL]);
  });

  it("allows a file below blockOn", async () => {
    answer = () => ({
      status: 200,
      body: { sensitivity: { level: "low" }, categories: {}, findings: [] },
    });
    const env = { SENSITIVE_CANARY_CONFIG: writeConfig("c2.json", { socket }) };
    expect((await readFile(file, env)).code).toBe(0);
  });

  it("makes no call without the entry, with the PII category off, or under [allow-pii]", async () => {
    answer = () => high();
    const noEntry = join(dir, "empty.json");
    writeFileSync(noEntry, "{}");
    expect(
      (await readFile(file, { SENSITIVE_CANARY_CONFIG: noEntry })).code,
    ).toBe(0);
    const config = writeConfig("c3.json", { socket });
    const secretOnly = {
      SENSITIVE_CANARY_CONFIG: config,
      SENSITIVE_CANARY_CATEGORIES: "secret",
    };
    expect((await readFile(file, secretOnly)).code).toBe(0);
    const transcript = join(dir, "t.jsonl");
    writeFileSync(
      transcript,
      `${JSON.stringify({ type: "user", message: { role: "user", content: "[allow-pii] read it" } })}\n`,
    );
    expect(
      (await readFile(file, { SENSITIVE_CANARY_CONFIG: config }, transcript))
        .code,
    ).toBe(0);
    expect(received).toEqual([]);
  });

  it("blocks when the server does not answer, unless told to fall back", async () => {
    const missing = join(dir, "missing.sock");
    const blocked = await readFile(file, {
      SENSITIVE_CANARY_CONFIG: writeConfig("c4.json", { socket: missing }),
    });
    expect(blocked.code).toBe(2);
    expect(blocked.stderr).toContain("pii-sentinel did not answer");
    const allowed = await readFile(file, {
      SENSITIVE_CANARY_CONFIG: writeConfig("c5.json", {
        socket: missing,
        onUnavailable: "allow",
      }),
    });
    expect(allowed.code).toBe(0);
  });

  // The server behind a refused socket may be running, so falling back on the
  // rules would skip it for as long as the socket stays there.
  it.each(["block", "allow"])(
    "blocks on a refused socket with onUnavailable %j",
    async (onUnavailable) => {
      const d = makeDir(`refused-hook-${onUnavailable}`, 0o777);
      const path = join(d, "r.sock");
      await serveAt(path);
      const result = await readFile(file, {
        SENSITIVE_CANARY_CONFIG: writeConfig(`c7-${onUnavailable}.json`, {
          socket: path,
          onUnavailable,
        }),
      });
      expect(result.code).toBe(2);
      expect(result.stderr).toContain("pii-sentinel socket at");
      expect(result.stderr).toContain("can be written by other users");
      expect(result.stderr).toMatch(
        new RegExp(`chmod go-w \\S*/refused-hook-${onUnavailable}\``),
      );
      expect(result.stderr).toContain('"onUnavailable" does not apply');
      expect(result.stderr).not.toContain("did not answer");
      expect(received).toEqual([]);
    },
  );

  it("blocks on an entry it cannot use and names the config file", async () => {
    const config = writeConfig("c6.json", { url: "http://127.0.0.1:1" });
    const result = await readFile(file, { SENSITIVE_CANARY_CONFIG: config });
    expect(result.code).toBe(2);
    expect(result.stderr).toContain(
      `"piiSentinel" entry in the sensitive-canary config (${config})`,
    );
    expect(result.stderr).toContain(
      '"url" was removed in sensitive-canary v0.10.0',
    );
  });
});

describe("UserPromptSubmit hook with pii-sentinel", () => {
  it("blocks a prompt the server judges high, and [allow-pii] lifts it", async () => {
    answer = () => high();
    const env = { SENSITIVE_CANARY_CONFIG: writeConfig("p1.json", { socket }) };
    const blocked = await runHook(
      USER_PROMPT,
      { prompt: `${MEDICAL}この文面を整えて` },
      env,
    );
    expect(blocked.code).toBe(2);
    expect(blocked.stderr).toContain(
      "pii-sentinel judged this prompt high sensitivity",
    );
    const allowed = await runHook(
      USER_PROMPT,
      { prompt: `[allow-pii] ${MEDICAL}` },
      env,
    );
    expect(allowed.code).toBe(0);
    expect(received).toHaveLength(1);
  });

  it("blocks on a refused socket even with onUnavailable allow, and [allow-pii] lifts it", async () => {
    const d = makeDir("refused-prompt", 0o777);
    const path = join(d, "r.sock");
    await serveAt(path);
    const env = {
      SENSITIVE_CANARY_CONFIG: writeConfig("p3.json", {
        socket: path,
        onUnavailable: "allow",
      }),
    };
    const blocked = await runHook(USER_PROMPT, { prompt: "hello" }, env);
    expect(blocked.code).toBe(2);
    expect(blocked.stderr).toContain("pii-sentinel socket was refused");
    expect(blocked.stderr).toContain("can be written by other users");
    const allowed = await runHook(
      USER_PROMPT,
      { prompt: "[allow-pii] hello" },
      env,
    );
    expect(allowed.code).toBe(0);
    expect(received).toEqual([]);
  });

  it("allows a prompt when the server is not there and onUnavailable is allow", async () => {
    const env = {
      SENSITIVE_CANARY_CONFIG: writeConfig("p4.json", {
        socket: join(dir, "missing.sock"),
        onUnavailable: "allow",
      }),
    };
    expect((await runHook(USER_PROMPT, { prompt: "hello" }, env)).code).toBe(0);
  });

  it("blocks on an entry it cannot use and names the config file", async () => {
    const config = writeConfig("p2.json", { url: "http://127.0.0.1:1" });
    const result = await runHook(
      USER_PROMPT,
      { prompt: "hello" },
      { SENSITIVE_CANARY_CONFIG: config },
    );
    expect(result.code).toBe(2);
    expect(result.stderr).toContain(`"piiSentinel" entry in ${config}`);
    expect(result.stderr).toContain(
      '"url" was removed in sensitive-canary v0.10.0',
    );
  });
});

// Which nsswitch.conf setups leave the group provable. `files` and `systemd`
// are read here; every other source can add a member nothing here can see.
describe("trustedNssSources", () => {
  it.each([
    ["files alone", "passwd: files\ngroup: files\n", ["files"]],
    [
      "comments and other databases",
      "# local only\npasswd: files # users\ngroup: files\nhosts: files dns\nnetgroup: nis\n",
      ["files"],
    ],
    [
      "an action between sources",
      "passwd: files [NOTFOUND=return]\ngroup: files [ NOTFOUND=return ]\n",
      ["files"],
    ],
    [
      "space before the colon and tabs",
      "passwd :\tfiles\ngroup\t: files\n",
      ["files"],
    ],
    [
      "the Debian and Ubuntu default",
      "passwd: files systemd\ngroup: files systemd\n",
      ["files", "systemd"],
    ],
    [
      "an initgroups line of files",
      "passwd: files\ngroup: files\ninitgroups: files\n",
      ["files"],
    ],
  ])("trusts %s", (_label, conf, expected) => {
    expect([...(trustedNssSources(conf) ?? [])].sort()).toEqual(expected);
  });

  it.each([
    [
      "the Fedora default",
      "passwd: files sss systemd\ngroup: files [SUCCESS=merge] sss [SUCCESS=merge] systemd\n",
    ],
    ["LDAP for groups", "passwd: files\ngroup: files ldap\n"],
    ["LDAP for accounts", "passwd: files ldap\ngroup: files\n"],
    ["compat, which reads NIS entries", "passwd: compat\ngroup: compat\n"],
    ["winbind", "passwd: files winbind\ngroup: files winbind\n"],
    [
      "an initgroups line with another source",
      "passwd: files\ngroup: files\ninitgroups: files sss\n",
    ],
    [
      "a second line with another source",
      "passwd: files\ngroup: files\ngroup: ldap\n",
    ],
    [
      "a line in another case",
      "passwd: files\ngroup: files\nGROUP: files ldap\n",
    ],
    ["a database with no source", "passwd: files\ngroup:\n"],
    [
      "a database with only an action",
      "passwd: files\ngroup: [NOTFOUND=return]\n",
    ],
    ["no group line", "passwd: files\n"],
    ["no passwd line", "group: files\n"],
    ["the group line commented out", "passwd: files\n# group: files\n"],
    ["an empty file", ""],
  ])("does not trust %s", (_label, conf) => {
    expect(trustedNssSources(conf)).toBeNull();
  });
});

// groupIsPrivate against a system laid out in a temp directory, so what is
// tested does not depend on the machine running the tests.
describe("groupIsPrivate", () => {
  const me = userInfo().username;
  const gid = 4242;
  let n = 0;

  // A system where our group is ours alone in /etc/group and /etc/passwd,
  // with `nsswitch` as its nsswitch.conf and `userdb` as files under it.
  const system = (
    nsswitch: string | null,
    userdb: Record<string, string> = {},
    files: { group?: string; passwd?: string } = {},
  ): string => {
    const root = join(dir, `root-${n++}`);
    mkdirSync(join(root, "etc"), { recursive: true });
    if (nsswitch !== null)
      writeFileSync(join(root, "etc/nsswitch.conf"), nsswitch);
    writeFileSync(
      join(root, "etc/group"),
      files.group ?? `root:x:0:\n${me}:x:${gid}:\n`,
    );
    writeFileSync(
      join(root, "etc/passwd"),
      files.passwd ??
        `root:x:0:0::/root:/bin/sh\n${me}:x:1000:${gid}::/h:/bin/sh\n`,
    );
    for (const [path, body] of Object.entries(userdb)) {
      mkdirSync(join(root, path, ".."), { recursive: true });
      writeFileSync(join(root, path), body);
    }
    return root;
  };
  const FILES = "passwd: files\ngroup: files\n";
  const SYSTEMD = "passwd: files systemd\ngroup: files systemd\n";

  it("trusts our own group when the files say it is ours", async () => {
    expect(await groupIsPrivate(gid, gid, system(FILES))).toBe(true);
    expect(await groupIsPrivate(gid, gid, system(SYSTEMD))).toBe(true);
  });

  it("does not trust a group that is not our own", async () => {
    expect(await groupIsPrivate(gid, gid + 1, system(FILES))).toBe(false);
  });

  it.each([
    ["another member", { group: `${me}:x:${gid}:${me},bob\n` }],
    ["another name", { group: `staff:x:${gid}:\n` }],
    ["no entry", { group: "root:x:0:\n" }],
    [
      "another account's primary group",
      {
        passwd: `${me}:x:1000:${gid}::/h:/bin/sh\nbob:x:1001:${gid}::/h:/bin/sh\n`,
      },
    ],
  ])("does not trust a group with %s in the files", async (_label, files) => {
    expect(await groupIsPrivate(gid, gid, system(FILES, {}, files))).toBe(
      false,
    );
  });

  // The nsswitch.conf check is what makes the files the whole answer.
  it.each([
    ["no nsswitch.conf", null],
    ["sss", "passwd: files sss\ngroup: files sss\n"],
    ["ldap", "passwd: files\ngroup: files ldap\n"],
  ])("does not trust our own group with %s", async (_label, conf) => {
    expect(await groupIsPrivate(gid, gid, system(conf))).toBe(false);
  });

  // nss-systemd's static records add members by being there. Each directory it
  // reads gets a case, so dropping one from the list is noticed.
  it.each(["etc/userdb", "run/userdb", "run/host/userdb", "usr/lib/userdb"])(
    "does not trust our group with a membership file in %s",
    async (where) => {
      const root = system(SYSTEMD, { [`${where}/bob:${me}.membership`]: "{}" });
      expect(await groupIsPrivate(gid, gid, root)).toBe(false);
    },
  );

  it.each([
    [
      "a group record with our gid under another name",
      "staff.group",
      { groupName: "staff", gid },
    ],
    [
      "a group record of ours with another member",
      `${me}.group`,
      { groupName: me, gid, members: [me, "bob"] },
    ],
    [
      "a user record with our gid",
      "bob.user",
      { userName: "bob", uid: 1001, gid },
    ],
    [
      "a user record with our gid as its uid and no gid",
      "bob.user",
      { userName: "bob", uid: gid },
    ],
    [
      "a user record in our group",
      "bob.user",
      { userName: "bob", uid: 1001, gid: 1001, memberOf: [me] },
    ],
    [
      "a user record with our gid in a binding",
      "bob.user",
      { userName: "bob", uid: 1001, binding: { abc: { gid } } },
    ],
    [
      "a user record in our group on one machine",
      "bob.user",
      {
        userName: "bob",
        uid: 1001,
        gid: 1001,
        perMachine: [{ memberOf: [me] }],
      },
    ],
  ])("does not trust our group with %s", async (_label, name, record) => {
    const root = system(SYSTEMD, {
      [`etc/userdb/${name}`]: JSON.stringify(record),
    });
    expect(await groupIsPrivate(gid, gid, root)).toBe(false);
  });

  it("does not trust our group when a record cannot be parsed", async () => {
    const root = system(SYSTEMD, { "etc/userdb/bob.user": "{" });
    expect(await groupIsPrivate(gid, gid, root)).toBe(false);
  });

  // Records that say nothing about our group leave it ours, so the cases above
  // are not passing on every record being refused.
  it("trusts our group alongside records that leave it alone", async () => {
    const root = system(SYSTEMD, {
      [`etc/userdb/${me}:${me}.membership`]: "{}",
      [`etc/userdb/bob:staff.membership`]: "{}",
      [`etc/userdb/${me}.user`]: JSON.stringify({
        userName: me,
        uid: 1000,
        gid,
      }),
      [`etc/userdb/${me}.group`]: JSON.stringify({
        groupName: me,
        gid,
        members: [me],
      }),
      "etc/userdb/bob.user": JSON.stringify({
        userName: "bob",
        uid: 1001,
        gid: 1001,
        memberOf: ["staff"],
      }),
      "etc/userdb/staff.group": JSON.stringify({ groupName: "staff", gid: 50 }),
      "etc/userdb/bob.user-privileged": "not read",
      "etc/userdb/README": "not a record",
    });
    expect(await groupIsPrivate(gid, gid, root)).toBe(true);
  });

  // Without nss-systemd in nsswitch.conf the records are never consulted, by
  // the system or here.
  it("ignores the records when nsswitch.conf does not name systemd", async () => {
    const root = system(FILES, { [`etc/userdb/bob:${me}.membership`]: "{}" });
    expect(await groupIsPrivate(gid, gid, root)).toBe(true);
  });

  it.skipIf(process.getuid?.() === 0)(
    "does not trust our group when a record directory cannot be read",
    async () => {
      const root = system(SYSTEMD, { "etc/userdb/x.user": "{}" });
      chmodSync(join(root, "etc/userdb"), 0o000);
      try {
        expect(await groupIsPrivate(gid, gid, root)).toBe(false);
      } finally {
        chmodSync(join(root, "etc/userdb"), 0o755);
      }
    },
  );
});

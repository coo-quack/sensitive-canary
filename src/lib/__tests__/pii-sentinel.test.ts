// The pii-sentinel client and the hooks' use of it, against a fake server.
//
// The hooks are spawned asynchronously here rather than through the shared
// harness: `spawnSync` would hold this worker's event loop, and the fake server
// answering the hook lives on that loop.

import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { judge, readPiiSentinelConfig } from "../pii-sentinel.ts";

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

const server = http.createServer((req, res) => {
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
});

beforeAll(() => new Promise<void>((resolve) => server.listen(socket, resolve)));
afterAll(() => {
  server.close();
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
    [{}, "exactly one"],
    [{ socket: "/a", url: "http://127.0.0.1:1" }, "exactly one"],
    [{ url: "http://example.com:8765" }, "127.0.0.1"],
    [{ url: "https://127.0.0.1:8765" }, "127.0.0.1"],
    [{ socket: "/a", timeoutMs: 50 }, "timeoutMs"],
    [{ socket: "/a", maxChars: 1.5 }, "maxChars"],
    [{ socket: "/a", blockOn: "none" }, "blockOn"],
    [{ socket: "/a", onUnavailable: "ignore" }, "onUnavailable"],
  ])("refuses %j", (raw, message) => {
    expect(readPiiSentinelConfig(raw)).toContain(message);
  });

  it("accepts a loopback URL", () => {
    const config = readPiiSentinelConfig({ url: "http://[::1]:8765" });
    expect(typeof config === "object" && config?.url?.hostname).toBe("[::1]");
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
    expect(
      (await judge([{ source: "a", text: "x" }], missing)).unavailable,
    ).toContain("ENOENT");
    answer = () => ({ status: 413, body: { error: "too large" } });
    const config = readPiiSentinelConfig({ socket });
    if (config === null || typeof config === "string")
      throw new Error(String(config));
    expect(
      (await judge([{ source: "a", text: "x" }], config)).unavailable,
    ).toContain("413");
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

  it("blocks on an entry it cannot use", async () => {
    const result = await readFile(file, {
      SENSITIVE_CANARY_CONFIG: writeConfig("c6.json", {
        url: "http://example.com:1",
      }),
    });
    expect(result.code).toBe(2);
    expect(result.stderr).toContain('"piiSentinel" entry');
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
});

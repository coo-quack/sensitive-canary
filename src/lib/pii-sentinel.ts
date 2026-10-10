// Asking a running pii-sentinel server (https://github.com/coo-quack/pii-sentinel)
// whether a text is sensitive, as a second opinion after the rules.
//
// Nothing here starts, installs or updates that server: the user runs
// `pii-sentinel serve` themselves, and this only calls it. It is consulted only
// when the user config has a `piiSentinel` entry and the PII category is
// enabled, so without that entry the hooks behave exactly as they did and no
// connection is ever made.
//
// The rules catch values by their shape; the model reads the text and judges
// the document — a diagnosis next to a name is sensitive although neither
// matches a rule. It is told to skip its own copy of the rules, which run here.

import type { Stats } from "node:fs";
import { lstat, readFile, readlink } from "node:fs/promises";
import http from "node:http";
import { userInfo } from "node:os";
import type { Finding } from "./rules.ts";
import { userConfigFromCache } from "./rules.ts";

export type Level = "none" | "low" | "high";

export interface PiiSentinelConfig {
  socket: string;
  timeoutMs: number;
  maxChars: number;
  blockOn: Exclude<Level, "none">;
  onUnavailable: "block" | "allow";
}

export interface Verdict {
  source: string;
  level: Level;
  categories: string[];
  findings: { type: string; value: string }[];
}

export interface Judgement {
  verdicts: Verdict[];
  // Why the server could not answer, when it could not.
  unavailable: string | null;
}

const RANK: Record<Level, number> = { none: 0, low: 1, high: 2 };
// The kernel follows at most this many symbolic links while resolving a path.
const MAX_LINKS = 40;
const DEFAULTS = {
  timeoutMs: 3_000,
  maxChars: 20_000,
  blockOn: "high",
  onUnavailable: "block",
} as const;

// The validated settings, `null` when the entry is absent, or the reason the
// entry cannot be used. A broken entry is not ignored the way a broken rule is:
// the user asked for the check, and quietly not running it is the silent pass
// this tool exists to prevent.
export function readPiiSentinelConfig(
  raw: unknown = userConfigFromCache()?.piiSentinel,
): PiiSentinelConfig | null | string {
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== "object" || Array.isArray(raw))
    return '"piiSentinel" must be an object';
  const r = raw as Record<string, unknown>;
  // A TCP port cannot be checked: any program can listen on it, so the text
  // would go to whatever answers. Only a socket file can be checked for owner.
  if (r["url"] !== undefined)
    return '"url" is no longer supported: the hook cannot tell whether the program on a TCP port is your pii-sentinel server. Use "socket" with a path in a directory only you can write to.';
  const socket = r["socket"];
  if (typeof socket !== "string" || socket === "")
    return '"socket" must be a path';
  const config: PiiSentinelConfig = { ...DEFAULTS, socket };
  for (const [key, min, max] of [
    ["timeoutMs", 100, 60_000],
    ["maxChars", 1, 1_000_000],
  ] as const) {
    const value = r[key];
    if (value === undefined) continue;
    if (
      !Number.isInteger(value) ||
      (value as number) < min ||
      (value as number) > max
    )
      return `"${key}" must be an integer from ${min} to ${max}`;
    config[key] = value as number;
  }
  if (r["blockOn"] !== undefined) {
    if (r["blockOn"] !== "high" && r["blockOn"] !== "low")
      return '"blockOn" must be "high" or "low"';
    config.blockOn = r["blockOn"];
  }
  if (r["onUnavailable"] !== undefined) {
    if (r["onUnavailable"] !== "block" && r["onUnavailable"] !== "allow")
      return '"onUnavailable" must be "block" or "allow"';
    config.onUnavailable = r["onUnavailable"];
  }
  return config;
}

function post(
  config: PiiSentinelConfig,
  text: string,
  timeoutMs: number,
): Promise<unknown> {
  const body = Buffer.from(JSON.stringify({ text, rules: false }));
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        socketPath: config.socket,
        path: "/scan",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": body.length,
          // The server refuses a Host that is not a loopback name.
          Host: "localhost",
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          if (res.statusCode !== 200) {
            reject(
              new Error(`answered ${res.statusCode}: ${text.slice(0, 200)}`),
            );
            return;
          }
          try {
            resolve(JSON.parse(text));
          } catch {
            reject(new Error("answered with something that is not JSON"));
          }
        });
        res.on("error", reject);
      },
    );
    req.on("timeout", () =>
      req.destroy(new Error(`no answer within ${timeoutMs} ms`)),
    );
    req.on("error", reject);
    req.end(body);
  });
}

interface Directory {
  path: string;
  st: Stats;
  // Other users can add or replace entries in it.
  shared: boolean;
}

// Refuses a socket that another user could have put in the path, before any
// text is sent. The kernel resolves the path again at connect time, so the walk
// mirrors it one component at a time: each directory on the way must be safe,
// and so must the socket. Only the path is checked, not the server behind it,
// so the owner of the directory is trusted to run the server.
export async function checkSocket(path: string): Promise<void> {
  // An abstract name has no file to check; it is refused on every platform.
  if (path.startsWith("\0"))
    throw new Error(
      "an abstract socket name is refused: use a socket file in a directory only you can write to",
    );
  // Windows has no owners or modes to compare.
  const uid = process.getuid?.();
  if (uid === undefined) return;
  const gid = process.getgid?.() ?? -1;

  const root = await directory("/", await lstat("/"), uid, gid);
  let stack: Directory[] = [root];
  let links = 0;
  let leaf: Stats | null = null;
  let pending = (
    path.startsWith("/") ? path : `${process.cwd()}/${path}`
  ).split("/");
  while (pending.length > 0) {
    const name = pending.shift() as string;
    if (name === "" || name === ".") continue;
    if (name === "..") {
      // Stack holds physical directories, so ".." goes to the real parent.
      if (stack.length > 1) stack.pop();
      continue;
    }
    const parent = stack[stack.length - 1] as Directory;
    const entry = parent.path === "/" ? `/${name}` : `${parent.path}/${name}`;
    const st = await lstat(entry);
    // In a directory others can write to, an entry can be renamed or replaced
    // by anyone but its owner. Only a sticky directory keeps it safe, and then
    // the entry must still be ours before it is followed.
    if (parent.shared && parent.st.mode & 0o1000) owned(st, entry, uid);
    if (st.isSymbolicLink()) {
      if (++links > MAX_LINKS)
        throw new Error(`too many symbolic links in ${path}`);
      const target = await readlink(entry);
      if (target.startsWith("/")) stack = [root];
      pending = [...target.split("/"), ...pending];
      continue;
    }
    if (pending.length > 0) {
      if (!st.isDirectory()) throw new Error(`${entry} is not a directory`);
      stack.push(await directory(entry, st, uid, gid));
    } else {
      leaf = st;
    }
  }
  if (leaf === null || !leaf.isSocket())
    throw new Error(`${path} is not a socket`);
  owned(leaf, path, uid);
}

// Every directory the walk goes through: owned by us or root, and not writable
// by others unless the sticky bit keeps each entry to its owner.
async function directory(
  path: string,
  st: Stats,
  uid: number,
  gid: number,
): Promise<Directory> {
  owned(st, path, uid);
  const shared = await writableByOthers(st, gid);
  if (shared && !(st.mode & 0o1000))
    throw new Error(`${path} can be written by other users`);
  return { path, st, shared };
}

function owned(st: Stats, path: string, uid: number): void {
  if (st.uid !== uid && st.uid !== 0)
    throw new Error(`${path} belongs to another user`);
}

// Group write counts as "others can write" unless the group is ours alone.
async function writableByOthers(st: Stats, gid: number): Promise<boolean> {
  if (st.mode & 0o002) return true;
  if (st.mode & 0o020) return !(await groupIsPrivate(st.gid, gid));
  return false;
}

// True only when the group is provably ours: its gid is ours, the /etc/group
// entries for it are named after us and list no one else, and no other account
// has it as its primary group. Anything that cannot be read counts as shared.
async function groupIsPrivate(group: number, own: number): Promise<boolean> {
  if (group !== own) return false;
  try {
    const me = userInfo().username;
    const gid = String(group);
    const entries = (await readFile("/etc/group", "utf8"))
      .split("\n")
      .map((line) => line.split(":"))
      .filter((fields) => fields[2] === gid);
    const ours =
      entries.length > 0 &&
      entries.every(
        (fields) =>
          fields[0] === me &&
          (fields[3] ?? "")
            .split(",")
            .every((member) => member === "" || member === me),
      );
    if (!ours) return false;
    const accounts = (await readFile("/etc/passwd", "utf8"))
      .split("\n")
      .map((line) => line.split(":"));
    return accounts.every((fields) => fields[3] !== gid || fields[0] === me);
  } catch {
    return false;
  }
}

function toVerdict(source: string, report: unknown): Verdict {
  const r = report as {
    sensitivity?: { level?: unknown };
    categories?: unknown;
    findings?: unknown;
  };
  const level = r?.sensitivity?.level;
  if (level !== "none" && level !== "low" && level !== "high")
    throw new Error("answered without a sensitivity level");
  const categories =
    r.categories && typeof r.categories === "object"
      ? Object.entries(r.categories as Record<string, unknown>)
          .filter(([, p]) => typeof p === "number" && p >= 0.5)
          .map(([name]) => name)
      : [];
  const findings = Array.isArray(r.findings)
    ? r.findings
        .filter(
          (f): f is { type: string; value: string; pii?: unknown } =>
            typeof f?.type === "string" && typeof f?.value === "string",
        )
        .filter((f) => f.pii !== false)
        .map(({ type, value }) => ({ type, value }))
    : [];
  return { source, level, categories, findings };
}

// Ask about each text in turn within one deadline for the whole call. Only the
// first `maxChars` characters of each are sent: the server takes about a second
// for twenty thousand, and a hook that runs past the PreToolUse timeout is
// killed, which lets the call through.
export async function judge(
  texts: { source: string; text: string }[],
  config: PiiSentinelConfig,
): Promise<Judgement> {
  const deadline = Date.now() + config.timeoutMs;
  const verdicts: Verdict[] = [];
  for (const { source, text } of texts) {
    if (text.trim() === "") continue;
    const left = deadline - Date.now();
    if (left <= 0)
      return {
        verdicts,
        unavailable: `no answer within ${config.timeoutMs} ms`,
      };
    try {
      await checkSocket(config.socket);
      verdicts.push(
        toVerdict(
          source,
          await post(config, text.slice(0, config.maxChars), left),
        ),
      );
    } catch (e) {
      return {
        verdicts,
        unavailable: e instanceof Error ? e.message : String(e),
      };
    }
  }
  return { verdicts, unavailable: null };
}

export function reachesBlockLevel(
  level: Level,
  config: PiiSentinelConfig,
): boolean {
  return RANK[level] >= RANK[config.blockOn];
}

// The model's findings in the shape the rule findings are reported in, so the
// block message and the allow tags treat them the same way: they are PII, and
// `[allow-pii]` lifts them.
export function verdictFindings(verdict: Verdict): Finding[] {
  const level: Finding = {
    ruleId: "pii-sentinel",
    description: `document judged ${verdict.level}${verdict.categories.length ? ` (${verdict.categories.join(", ")})` : ""}`,
    category: "pii",
    matchRedacted: verdict.source,
    secretValue: `pii-sentinel:${verdict.source}`,
  };
  return [
    level,
    ...verdict.findings.map((f) => ({
      ruleId: "pii-sentinel",
      description: f.type.replaceAll("_", " "),
      category: "pii" as const,
      matchRedacted: f.value,
      secretValue: `pii-sentinel:${verdict.source}:${f.type}:${f.value}`,
    })),
  ];
}

export function connectionTarget(config: PiiSentinelConfig): string {
  return `unix:${config.socket}`;
}

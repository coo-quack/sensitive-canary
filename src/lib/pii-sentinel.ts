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
import { lstat, readdir, readFile, readlink } from "node:fs/promises";
import http from "node:http";
import { userInfo } from "node:os";
import { join } from "node:path";
import type { Category, Finding } from "./rules.ts";
import { redact, userConfigFromCache } from "./rules.ts";

type Level = "none" | "low" | "high";

// The categories `blockOn: "identifiable"` knows. An identifier reaches a
// person on its own; an attribute does so once it is linked to a name. The
// noun is what a block reason calls the category. A category blocks on its
// probability only when the user names it in `identifiableThresholds`; the
// finding types flagged `blocksAsFinding` block on their own.
const CATEGORY = {
  email_or_phone: {
    kind: "identifier",
    noun: "an e-mail address or phone number",
    blocksAsFinding: false,
  },
  government_id: {
    kind: "identifier",
    noun: "a government ID",
    blocksAsFinding: false,
  },
  financial_account: {
    kind: "identifier",
    noun: "a financial account",
    blocksAsFinding: false,
  },
  sns_handle: {
    kind: "identifier",
    noun: "a social media handle",
    blocksAsFinding: false,
  },
  ip_address_of_a_person: {
    kind: "identifier",
    noun: "an IP address",
    blocksAsFinding: false,
  },
  postal_address: {
    kind: "attribute",
    noun: "a postal address",
    blocksAsFinding: true,
  },
  date_of_birth: {
    kind: "attribute",
    noun: "a date of birth",
    blocksAsFinding: true,
  },
  employment_info: {
    kind: "attribute",
    noun: "a workplace",
    blocksAsFinding: false,
  },
  precise_location: {
    kind: "attribute",
    noun: "a precise location",
    blocksAsFinding: false,
  },
} satisfies Record<
  string,
  {
    kind: "identifier" | "attribute";
    noun: string;
    blocksAsFinding: boolean;
  }
>;
type IdentifiableCategory = keyof typeof CATEGORY;
// The probability each category blocks at, for the categories the user named.
// A category left out does not block on its probability.
type Thresholds = Partial<Record<IdentifiableCategory, number>>;
const IDENTIFIABLE_CATEGORIES = Object.keys(CATEGORY) as IdentifiableCategory[];

// The finding types that block on their own under "identifiable" when the
// server marks them `pii: true`: the rows flagged `blocksAsFinding`, so the
// table is the one place that says which they are.
const BLOCKING_FINDING_TYPES = new Set<string>(
  IDENTIFIABLE_CATEGORIES.filter((c) => CATEGORY[c].blocksAsFinding),
);

export interface PiiSentinelConfig {
  socket: string;
  timeoutMs: number;
  maxChars: number;
  blockOn: "high" | "low" | "identifiable";
  identifiableThresholds: Thresholds;
  onUnavailable: "block" | "allow";
}

export interface Verdict {
  source: string;
  level: Level;
  categories: string[];
  // Every numeric category the server answered, not only those at 0.5 or above.
  probabilities: Record<string, number>;
  findings: { type: string; value: string; pii: boolean }[];
}

interface Judgement {
  verdicts: Verdict[];
  // Why the server could not answer, when it could not.
  unavailable: string | null;
  // Why the socket was refused, when another user could have put it in place.
  // No text was sent, and `onUnavailable` does not apply: the server may be
  // running, so a fallback to the rules would skip the check for as long as
  // the socket stays where it is, with nothing said.
  refused: string | null;
}

// A socket another user could have put in place. Kept apart from a server
// that is not there, which `onUnavailable` covers. Each message ends with how
// to fix that refusal, since the fix differs with the cause.
export class UnsafeSocketError extends Error {}

// What both hooks say under a refusal, after the reason.
export const REFUSED_SOCKET_NOTE =
  'Another user could have put that socket in place, so nothing was sent. Fix the path as the reason says, or remove the "piiSentinel" entry. "onUnavailable" does not apply: the server may be running, and falling back on the rules would skip it without a word.';

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
  raw: unknown,
): PiiSentinelConfig | null | string {
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== "object" || Array.isArray(raw))
    return '"piiSentinel" must be an object';
  const r = raw as Record<string, unknown>;
  // A TCP port cannot be checked: any program can listen on it, so the text
  // would go to whatever answers. Only a socket file can be checked for owner.
  if (r["url"] !== undefined)
    return '"url" was removed in sensitive-canary v0.10.0: the hook cannot tell whether the program on a TCP port is your pii-sentinel server. Replace it with "socket", the path of the server\'s Unix socket in a directory only you can write to.';
  const socket = r["socket"];
  if (typeof socket !== "string" || socket === "")
    return '"socket" must be a path';
  const config: PiiSentinelConfig = {
    ...DEFAULTS,
    socket,
    identifiableThresholds: {},
  };
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
    if (
      r["blockOn"] !== "high" &&
      r["blockOn"] !== "low" &&
      r["blockOn"] !== "identifiable"
    )
      return '"blockOn" must be "high", "low" or "identifiable"';
    config.blockOn = r["blockOn"];
  }
  if (r["identifiableThresholds"] !== undefined) {
    const thresholds = readThresholds(r["identifiableThresholds"]);
    if (typeof thresholds === "string") return thresholds;
    config.identifiableThresholds = {
      ...config.identifiableThresholds,
      ...thresholds,
    };
  }
  if (r["onUnavailable"] !== undefined) {
    if (r["onUnavailable"] !== "block" && r["onUnavailable"] !== "allow")
      return '"onUnavailable" must be "block" or "allow"';
    config.onUnavailable = r["onUnavailable"];
  }
  return config;
}

// A map from category name to a probability from 0 to 1. Only the identifier
// and attribute categories are accepted: a threshold set on another category
// is refused rather than ignored, since it would look as if it applied.
function readThresholds(raw: unknown): Thresholds | string {
  const names = IDENTIFIABLE_CATEGORIES.join(", ");
  if (typeof raw !== "object" || raw === null || Array.isArray(raw))
    return `"identifiableThresholds" must be an object from category name to a number from 0 to 1 (${names})`;
  const thresholds: Thresholds = {};
  for (const [name, value] of Object.entries(raw)) {
    if (!(IDENTIFIABLE_CATEGORIES as readonly string[]).includes(name))
      return `"identifiableThresholds" names "${name}", which is not an identifier or attribute category: use one of ${names}`;
    if (
      typeof value !== "number" ||
      !Number.isFinite(value) ||
      value < 0 ||
      value > 1
    )
      return `"identifiableThresholds.${name}" must be a number from 0 to 1`;
    thresholds[name as IdentifiableCategory] = value;
  }
  return thresholds;
}

function post(
  config: PiiSentinelConfig,
  text: string,
  timeoutMs: number,
): Promise<unknown> {
  const body = Buffer.from(JSON.stringify({ text, rules: false }));
  const timeoutError = () => new Error(`no answer within ${timeoutMs} ms`);
  return new Promise((resolve, reject) => {
    // Every way out of the request goes through here, so the wall-clock timer
    // below is cleared once the promise has settled.
    const settle = (action: () => void): void => {
      clearTimeout(deadline);
      action();
    };
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
        res.on("end", () =>
          settle(() => {
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
          }),
        );
        res.on("error", (e) => settle(() => reject(e)));
      },
    );
    // The socket timeout below restarts with every byte, so a server that
    // trickles one out never trips it. The timer is the limit on the whole
    // post: it rejects, and it destroys the request so the socket is closed.
    req.on("timeout", () => req.destroy(timeoutError()));
    req.on("error", (e) => settle(() => reject(e)));
    const deadline = setTimeout(() => {
      const err = timeoutError();
      settle(() => reject(err));
      req.destroy(err);
    }, timeoutMs);
    deadline.unref();
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
    throw new UnsafeSocketError(
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
    if (parent.shared && (parent.st.mode & 0o1000) !== 0) owned(st, entry, uid);
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
  const writers = await describeOtherWriters(st, gid);
  if (writers !== null && !(st.mode & 0o1000))
    throw new UnsafeSocketError(
      `${path} can be written by ${writers}: run \`chmod go-w ${path}\` or move the socket to a directory only you can write to`,
    );
  return { path, st, shared: writers !== null };
}

function owned(st: Stats, path: string, uid: number): void {
  if (st.uid !== uid && st.uid !== 0)
    throw new UnsafeSocketError(
      `${path} belongs to another user: move the socket to a directory you own`,
    );
}

// Who besides us can write to the directory, in words for the refusal, or null
// when no one can. Group write counts unless the group is ours alone.
async function describeOtherWriters(
  st: Stats,
  gid: number,
): Promise<string | null> {
  if (st.mode & 0o002) return "other users";
  if (st.mode & 0o020 && !(await groupIsPrivate(st.gid, gid)))
    return `its group (gid ${st.gid}), which cannot be shown to contain only you`;
  return null;
}

// True only when the group is provably ours: its gid is ours, the /etc/group
// entries for it are named after us and list no one else, and no other account
// has it as its primary group. Anything that cannot be read counts as shared.
//
// Those files are the whole answer only when /etc/nsswitch.conf takes accounts
// and groups from them alone, or from them and nss-systemd. LDAP, sssd, NIS and
// winbind add members /etc/group does not show, and a local group's gid
// colliding with a directory group's is an ordinary accident there, so any of
// them makes the group unprovable. nss-systemd adds what its static JSON
// records say, and those are read here too. Where there is no
// /etc/nsswitch.conf, macOS among them, the group is never provably ours.
//
// `root` is where the system's files are looked up, so tests can lay out a
// system of their own.
export async function groupIsPrivate(
  group: number,
  own: number,
  root = "/",
): Promise<boolean> {
  if (group !== own) return false;
  try {
    const sources = trustedNssSources(
      await readFile(join(root, "etc/nsswitch.conf"), "utf8"),
    );
    if (sources === null) return false;
    const me = userInfo().username;
    const gid = String(group);
    const entries = (await readFile(join(root, "etc/group"), "utf8"))
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
    const accounts = (await readFile(join(root, "etc/passwd"), "utf8"))
      .split("\n")
      .map((line) => line.split(":"));
    if (!accounts.every((fields) => fields[3] !== gid || fields[0] === me))
      return false;
    return !sources.has("systemd") || (await userdbIsPrivate(root, group, me));
  } catch {
    return false;
  }
}

// The sources /etc/nsswitch.conf names for accounts and groups, or null when
// any of them is one whose members cannot be read here, or when `passwd` or
// `group` has no line: a missing line falls back to a default that differs
// between C libraries. `initgroups`, which glibc consults for another account's
// supplementary groups, falls back to `group` when it has no line of its own.
// Actions such as `[NOTFOUND=return]` are not sources. Names are matched in any
// case and with space before the colon, so a line spelled differently is
// checked rather than missed.
export function trustedNssSources(nsswitch: string): Set<string> | null {
  const found = new Set<string>();
  for (const database of ["passwd", "group", "initgroups"]) {
    const head = new RegExp(`^${database}\\s*:`, "i");
    const lines = nsswitch
      .split("\n")
      .map((line) => line.replace(/#.*/, "").trim())
      .filter((line) => head.test(line));
    if (lines.length === 0) {
      if (database === "initgroups") continue;
      return null;
    }
    for (const line of lines) {
      const sources = line
        .slice(line.indexOf(":") + 1)
        .replace(/\[[^\]]*\]/g, " ")
        .split(/\s+/)
        .filter((source) => source !== "");
      if (sources.length === 0) return null;
      for (const source of sources) {
        if (source !== "files" && source !== "systemd") return null;
        found.add(source);
      }
    }
  }
  return found;
}

// Where nss-systemd reads static JSON user and group records (nss-systemd(8)).
const USERDB_DIRECTORIES = [
  "etc/userdb",
  "run/userdb",
  "run/host/userdb",
  "usr/lib/userdb",
];

// False when nss-systemd's static records put anyone else in our group: a
// `user:group.membership` file, which counts by existing; a group record with
// our gid under another name or with other members; or a user record whose
// primary group is ours or that lists our group in `memberOf`. A user record's
// fields can also sit under `binding` and `perMachine`, so those are read as
// well. Records that services hand out over Varlink, systemd-homed's among
// them, are not files and are not read.
async function userdbIsPrivate(
  root: string,
  gid: number,
  me: string,
): Promise<boolean> {
  for (const directory of USERDB_DIRECTORIES) {
    let names: string[];
    try {
      names = await readdir(join(root, directory));
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") continue;
      return false;
    }
    for (const name of names) {
      if (name.endsWith(".membership")) {
        const [user, group] = name.slice(0, -".membership".length).split(":");
        if (group === me && user !== me) return false;
        continue;
      }
      const kind = name.endsWith(".user")
        ? "user"
        : name.endsWith(".group")
          ? "group"
          : null;
      if (kind === null) continue;
      const record: unknown = JSON.parse(
        await readFile(join(root, directory, name), "utf8"),
      );
      if (typeof record !== "object" || record === null) return false;
      const r = record as Record<string, unknown>;
      const views = [
        r,
        ...Object.values(
          typeof r["binding"] === "object" && r["binding"] !== null
            ? (r["binding"] as Record<string, unknown>)
            : {},
        ),
        ...(Array.isArray(r["perMachine"]) ? r["perMachine"] : []),
      ].filter(
        (view): view is Record<string, unknown> =>
          typeof view === "object" && view !== null,
      );
      if (kind === "group") {
        const named = r["groupName"] === me;
        for (const view of views) {
          if (view["gid"] === gid && !named) return false;
          const members = view["members"];
          if (
            named &&
            Array.isArray(members) &&
            members.some((member) => member !== me)
          )
            return false;
        }
      } else {
        if (r["userName"] === me) continue;
        for (const view of views) {
          if ((view["gid"] ?? view["uid"]) === gid) return false;
          const memberOf = view["memberOf"];
          if (Array.isArray(memberOf) && memberOf.includes(me)) return false;
        }
      }
    }
  }
  return true;
}

// A finding's type is written into the block reason, so it is kept only when it
// is a short identifier. Anything else is a server putting text where a name
// goes, and the block reason says "finding" in its place.
const FINDING_TYPE = /^[a-z0-9_]{1,40}$/i;

function toVerdict(
  source: string,
  report: unknown,
  config: PiiSentinelConfig,
): Verdict {
  const r = report as {
    sensitivity?: { level?: unknown };
    categories?: unknown;
    findings?: unknown;
  };
  const level = r?.sensitivity?.level;
  if (level !== "none" && level !== "low" && level !== "high")
    throw new Error("answered without a sensitivity level");
  const probabilities: Record<string, number> = {};
  const reported = r.categories;
  const isMap =
    reported !== null &&
    typeof reported === "object" &&
    !Array.isArray(reported);
  // Under "identifiable" the categories are always required, whether or not a
  // threshold is set: a malformed answer is unavailable, not a pass.
  if (config.blockOn === "identifiable") {
    if (!isMap) throw new Error("answered without categories");
    for (const [name, p] of Object.entries(reported)) {
      if (typeof p !== "number" || !Number.isFinite(p) || p < 0 || p > 1)
        throw new Error(
          `answered with a probability for ${FINDING_TYPE.test(name) ? name : "a category"} that is not a number from 0 to 1`,
        );
      probabilities[name] = p;
    }
  } else if (isMap)
    for (const [name, p] of Object.entries(reported))
      if (typeof p === "number") probabilities[name] = p;
  const categories = Object.entries(probabilities)
    .filter(([, p]) => p >= 0.5)
    .map(([name]) => name);
  // Under "identifiable" a finding of a blocking type must carry a string value
  // and a boolean pii. One that does not is a malformed answer, so it is
  // unavailable rather than dropped, which would pass the text unchecked.
  if (config.blockOn === "identifiable" && Array.isArray(r.findings))
    for (const f of r.findings as {
      type?: unknown;
      value?: unknown;
      pii?: unknown;
    }[]) {
      if (
        typeof f?.type === "string" &&
        BLOCKING_FINDING_TYPES.has(f.type) &&
        (typeof f.value !== "string" || typeof f.pii !== "boolean")
      )
        throw new Error(
          "answered with a finding of a blocking type whose value or pii is not the expected kind",
        );
    }
  const findings = Array.isArray(r.findings)
    ? r.findings
        .filter(
          (f): f is { type: string; value: string; pii?: unknown } =>
            typeof f?.type === "string" && typeof f?.value === "string",
        )
        .filter((f) => f.pii !== false)
        .map(({ type, value, pii }) => ({
          type: FINDING_TYPE.test(type) ? type : "finding",
          value,
          pii: pii === true,
        }))
    : [];
  return { source, level, categories, probabilities, findings };
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
  // Checked once, inside the deadline and before any text leaves. A socket
  // that is not there is reported like a server that did not answer.
  try {
    await checkSocket(config.socket);
  } catch (e) {
    const reason = e instanceof Error ? e.message : String(e);
    return e instanceof UnsafeSocketError
      ? { verdicts, unavailable: null, refused: reason }
      : { verdicts, unavailable: reason, refused: null };
  }
  for (const { source, text } of texts) {
    if (text.trim() === "") continue;
    const left = deadline - Date.now();
    if (left <= 0)
      return {
        verdicts,
        unavailable: `no answer within ${config.timeoutMs} ms`,
        refused: null,
      };
    try {
      verdicts.push(
        toVerdict(
          source,
          await post(config, text.slice(0, config.maxChars), left),
          config,
        ),
      );
    } catch (e) {
      return {
        verdicts,
        unavailable: e instanceof Error ? e.message : String(e),
        refused: null,
      };
    }
  }
  return { verdicts, unavailable: null, refused: null };
}

// Whether the level blocks. Under "identifiable" only "high" does: the
// identifiers and attributes are judged by the thresholds the user names.
function reachesBlockLevel(level: Level, config: PiiSentinelConfig): boolean {
  const blockLevel =
    config.blockOn === "identifiable" ? "high" : config.blockOn;
  return RANK[level] >= RANK[blockLevel];
}

// The identifier and attribute categories at or above their thresholds. Only
// for a category the user named, and only for a category the server answered:
// an absent one is not treated as zero, so a threshold of 0 cannot block on it.
function identifiableHits(
  verdict: Verdict,
  config: PiiSentinelConfig,
): IdentifiableCategory[] {
  if (config.blockOn !== "identifiable") return [];
  return IDENTIFIABLE_CATEGORIES.filter((category) => {
    const threshold = config.identifiableThresholds[category];
    const probability = verdict.probabilities[category];
    return (
      threshold !== undefined &&
      probability !== undefined &&
      probability >= threshold
    );
  });
}

// A finding that blocks on its own: under "identifiable", a finding of a
// blocking type that the server marks `pii: true`, whatever the level and the
// probabilities. Under "high" and "low" findings never block by themselves.
function isBlockingFinding(
  finding: Verdict["findings"][number],
  config: PiiSentinelConfig,
): boolean {
  return (
    config.blockOn === "identifiable" &&
    finding.pii &&
    BLOCKING_FINDING_TYPES.has(finding.type)
  );
}

function blockingFindings(
  verdict: Verdict,
  config: PiiSentinelConfig,
): Verdict["findings"] {
  return verdict.findings.filter((f) => isBlockingFinding(f, config));
}

export function verdictBlocks(
  verdict: Verdict,
  config: PiiSentinelConfig,
): boolean {
  return (
    reachesBlockLevel(verdict.level, config) ||
    identifiableHits(verdict, config).length > 0 ||
    blockingFindings(verdict, config).length > 0
  );
}

// The reason a category block gives. An identifier identifies a person by
// itself; an attribute does so once it is linked to a name, which the reason
// says, since the name may be in this conversation or another.
function categoryReason(category: IdentifiableCategory): string {
  const { kind, noun } = CATEGORY[category];
  return kind === "identifier"
    ? `${noun}, which identifies a person on its own`
    : `${noun}, which identifies a person once it is linked to a name, in this conversation or another`;
}

// What a blocked verdict was judged for, as the hooks say it after
// "pii-sentinel": the level, or the identifiers and attributes that reached
// their thresholds. `subject` is "this file" or "this prompt".
export function blockPhrase(
  verdict: Verdict,
  config: PiiSentinelConfig,
  subject: string,
): string {
  return reachesBlockLevel(verdict.level, config)
    ? `judged ${subject} ${verdict.level} sensitivity`
    : `found identifiers or attributes that can pin a person down in ${subject}`;
}

// The model's findings in the shape the rule findings are reported in, so the
// block message and the allow tags treat them the same way: they are PII, and
// `[allow-pii]` lifts them. A level block and each category block are findings
// too, so the message says why the verdict was blocked.
export function verdictFindings(
  verdict: Verdict,
  config: PiiSentinelConfig,
): Finding[] {
  const findings: Finding[] = [];
  if (reachesBlockLevel(verdict.level, config))
    findings.push({
      ruleId: "pii-sentinel",
      description: `document judged ${verdict.level}${verdict.categories.length ? ` (${verdict.categories.join(", ")})` : ""}`,
      category: "pii",
      matchRedacted: verdict.source,
      secretValue: `pii-sentinel:${verdict.source}`,
    });
  const nameSuffix = verdict.categories.includes("person_name")
    ? "; a name is present"
    : "";
  // A category that a blocking finding already names is not repeated.
  const blockingTypes = new Set(
    blockingFindings(verdict, config).map((f) => f.type),
  );
  for (const category of identifiableHits(verdict, config)) {
    if (blockingTypes.has(category)) continue;
    // identifiableHits returns only answered categories.
    const probability = verdict.probabilities[category] ?? 0;
    findings.push({
      ruleId: "pii-sentinel",
      description: `document names ${categoryReason(category)}${nameSuffix}`,
      category: "pii",
      matchRedacted: probability.toFixed(2),
      secretValue: `pii-sentinel:${verdict.source}:${category}:${probability}`,
    });
  }
  // One reason line per blocking type, however many spans of it there are.
  const shownBlockingTypes = new Set<string>();
  return [
    ...findings,
    ...verdict.findings.flatMap((f) => {
      if (isBlockingFinding(f, config)) {
        if (shownBlockingTypes.has(f.type)) return [];
        shownBlockingTypes.add(f.type);
      }
      return [
        {
          ruleId: "pii-sentinel",
          description: isBlockingFinding(f, config)
            ? `document names ${categoryReason(f.type as IdentifiableCategory)}${nameSuffix}`
            : f.type.replaceAll("_", " "),
          category: "pii" as const,
          // Redacted as a rule finding's value is: the block reason reaches the model
          // and the terminal, and the file or prompt it names was never read.
          matchRedacted: redact(f.value),
          secretValue: `pii-sentinel:${verdict.source}:${f.type}:${f.value}`,
        },
      ];
    }),
  ];
}

export function connectionTarget(config: PiiSentinelConfig): string {
  return `unix:${config.socket}`;
}

// What the pii-sentinel check decided about a set of texts, before a hook has
// written it out. The hooks word and block differently, but they agree on
// which of these outcomes applies, and in what order they are checked.
export type PiiSentinelDecision =
  | { kind: "pass" }
  | { kind: "settings"; problem: string }
  | { kind: "refused"; target: string; reason: string }
  | {
      kind: "judged";
      verdict: Verdict;
      findings: Finding[];
      // What the block says it judged, as blockPhrase words it for `subject`.
      phrase: string;
    }
  | { kind: "unavailable"; target: string; reason: string };

const PASS: PiiSentinelDecision = { kind: "pass" };

// Asks the user's pii-sentinel server about texts the rules let through. Only
// with a `piiSentinel` entry in the config and the PII category on; `[allow-pii]`
// lifts it. A server that does not answer blocks unless the entry says otherwise:
// the user asked for the check, and a check that silently did not run is a pass.
// A socket another user could have put in place blocks whatever the entry says,
// since the server behind it may well be running.
export async function consultPiiSentinel(
  texts: { source: string; text: string }[],
  allowTags: ReadonlySet<string>,
  enabledCategories: ReadonlySet<Category>,
  subject: string,
): Promise<PiiSentinelDecision> {
  if (texts.length === 0 || !enabledCategories.has("pii")) return PASS;
  if (allowTags.has("pii")) return PASS;
  const config = readPiiSentinelConfig(userConfigFromCache()?.piiSentinel);
  if (config === null) return PASS;
  if (typeof config === "string") return { kind: "settings", problem: config };
  const { verdicts, unavailable, refused } = await judge(texts, config);
  if (refused !== null)
    return {
      kind: "refused",
      target: connectionTarget(config),
      reason: refused,
    };
  for (const verdict of verdicts) {
    if (!verdictBlocks(verdict, config)) continue;
    return {
      kind: "judged",
      verdict,
      findings: verdictFindings(verdict, config),
      phrase: blockPhrase(verdict, config, subject),
    };
  }
  if (unavailable !== null && config.onUnavailable === "block")
    return {
      kind: "unavailable",
      target: connectionTarget(config),
      reason: unavailable,
    };
  return PASS;
}

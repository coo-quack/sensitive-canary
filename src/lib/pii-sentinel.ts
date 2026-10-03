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

import http from "node:http";
import type { Finding } from "./rules.ts";
import { userConfigFromCache } from "./rules.ts";

export type Level = "none" | "low" | "high";

export interface PiiSentinelConfig {
  socket?: string;
  url?: URL;
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
const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);
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
  const config: PiiSentinelConfig = { ...DEFAULTS };
  if ((r["socket"] === undefined) === (r["url"] === undefined))
    return 'set exactly one of "socket" and "url"';
  if (r["socket"] !== undefined) {
    if (typeof r["socket"] !== "string" || r["socket"] === "")
      return '"socket" must be a path';
    config.socket = r["socket"];
  } else {
    let url: URL;
    try {
      url = new URL(String(r["url"]));
    } catch {
      return '"url" is not a URL';
    }
    // Only this machine: the text being checked is exactly what must not leave it.
    if (url.protocol !== "http:" || !LOOPBACK.has(url.hostname))
      return '"url" must be http:// on 127.0.0.1, localhost or [::1]';
    config.url = url;
  }
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
  const target = config.socket
    ? { socketPath: config.socket }
    : {
        host: config.url?.hostname.replace(/^\[|\]$/g, ""),
        port: config.url?.port || 80,
      };
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        ...target,
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
  return config.socket ? `unix:${config.socket}` : String(config.url);
}

#!/usr/bin/env node

import { blockOnUnhandledError, failClosed } from "./lib/fail-closed.ts";
import {
  allowTagLines,
  applyAllowTags,
  dedupeFindings,
  type Finding,
  findingsToLines,
  randomBird,
  resolveTagPriority,
  typedTextOf,
} from "./lib/inspector.ts";
import {
  blockPhrase,
  connectionTarget,
  judge,
  REFUSED_SOCKET_NOTE,
  readPiiSentinelConfig,
  verdictBlocks,
  verdictFindings,
} from "./lib/pii-sentinel.ts";
import {
  beginScanBudget,
  enabledCategoriesFromEnv,
  scan,
  USER_CONFIG_PATH,
} from "./lib/rules.ts";

blockOnUnhandledError();

interface HookInput {
  prompt?: unknown;
}

// Every string in the value, in document order. There is no depth limit: a limit
// stopped the walk and let everything below it through unscanned. The walk uses
// an explicit stack, so a deep value cannot overflow it, and each node is visited
// once, so the work is linear in the size of the payload. Keys are not scanned.
function collectStrings(value: unknown): string[] {
  const found: string[] = [];
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const current = stack.pop();
    if (typeof current === "string") {
      found.push(current);
    } else if (Array.isArray(current) || isObject(current)) {
      const children = Array.isArray(current)
        ? current
        : Object.values(current);
      // Pushed last to first, so the first child is the next one popped.
      for (let i = children.length - 1; i >= 0; i--) stack.push(children[i]);
    }
  }
  return found;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object";
}

const ENABLED_CATEGORIES = enabledCategoriesFromEnv();

function blockPrompt(lines: string[]): never {
  try {
    process.stderr.write(
      [
        "",
        `${randomBird()} sensitive-canary: ${lines[0]}`,
        "",
        ...lines.slice(1),
        "",
      ].join("\n"),
    );
  } catch {
    // The verdict stands without the message.
  }
  process.exit(2);
}

// Ask the user's pii-sentinel server about a prompt the rules let through. Only
// with a `piiSentinel` entry in the config and the PII category on; `[allow-pii]`
// lifts it. See the PreToolUse hook for why a silent server blocks by default.
async function consultPiiSentinel(
  prompt: string,
  allow: Set<string>,
): Promise<void> {
  if (prompt.trim() === "" || !ENABLED_CATEGORIES.has("pii")) return;
  if (allow.has("pii") || allow.has("all")) return;
  const config = readPiiSentinelConfig();
  if (config === null) return;
  if (typeof config === "string")
    blockPrompt([
      `the "piiSentinel" entry in ${USER_CONFIG_PATH} cannot be used — blocked`,
      `  ${config}`,
      "",
      "Fix the entry, or remove it to stop asking pii-sentinel.",
    ]);
  const { verdicts, unavailable, refused } = await judge(
    [{ source: "prompt", text: prompt }],
    config,
  );
  if (refused !== null)
    blockPrompt([
      "the pii-sentinel socket was refused — blocked",
      `  ${connectionTarget(config)}: ${refused}`,
      "",
      REFUSED_SOCKET_NOTE,
      "To send this prompt anyway, add [allow-pii] to it.",
    ]);
  const verdict = verdicts[0];
  if (verdict && verdictBlocks(verdict, config)) {
    const findings = verdictFindings(verdict, config);
    blockPrompt([
      `pii-sentinel ${blockPhrase(verdict, config, "this prompt")} — blocked`,
      ...findingsToLines(findings),
      "",
      "To allow, add a tag to your prompt:",
      ...allowTagLines(findings),
    ]);
  }
  if (unavailable !== null && config.onUnavailable === "block")
    blockPrompt([
      "pii-sentinel did not answer — blocked",
      `  ${connectionTarget(config)}: ${unavailable}`,
      "",
      'Start it with `pii-sentinel serve`, set "onUnavailable": "allow" in the "piiSentinel" entry, or add [allow-pii] to your prompt.',
    ]);
}

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk: string) => (raw += chunk));
// The handler is async because the pii-sentinel server is asked over a socket.
// An async listener's throw is a rejected promise, not an uncaught exception,
// and on Node 24 a rejection here ended the process with 0 — a scan that could
// not finish passed the call. Caught explicitly so it stops the call instead.
process.stdin.on("end", () => {
  main().catch(failClosed);
});

async function main(): Promise<void> {
  // Started here rather than at module load: the wait for stdin belongs to the
  // runtime, and counting it against the scan let a slow handover spend the
  // whole allowance before anything was read.
  beginScanBudget();
  let data: HookInput;
  try {
    // Empty stdin is nothing to check. Bytes that do not parse are a check that
    // could not read its input, which is not the same as safe: two characters
    // missing from the end of a payload are enough to hide a key.
    if (raw.trim().length === 0) process.exit(0);
    const parsed: unknown = JSON.parse(raw);
    // `JSON.parse("null")` succeeds and returns null, which then threw on the
    // first field read. A payload that is not an object carries no prompt.
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed))
      process.exit(0);
    data = parsed as HookInput;
  } catch (error) {
    // The check never started, so it vouches for nothing. Everything else that
    // cannot finish stops the call; input that will not parse is the same case.
    failClosed(error);
  }

  // Whatever the runtime sends. Not throwing on a prompt that is not a string
  // was only half of it: coercing to "" made the hook exit 0 on the shapes it
  // could not read, which is the same silence as never running. Every string
  // inside the value is collected instead, to a bounded depth, so
  // `{"prompt":{"text":"…"}}` and `{"prompt":["…"]}` are read like a prompt.
  const prompt = collectStrings(data.prompt).join("\n");

  const allFindings = scan(prompt, ENABLED_CATEGORIES);

  // From what the user typed, not from what they pasted: a fenced log or a
  // README quoting `[allow-secret]` would otherwise lift the guard on the key in
  // the same message. Both hooks read tags this way, so the same text gets the
  // same answer whichever one sees it.
  const { effectiveAllow, effectiveMask } = resolveTagPriority(
    typedTextOf(prompt),
  );

  const afterAllow: Finding[] = dedupeFindings(
    applyAllowTags(allFindings, effectiveAllow),
  );

  if (afterAllow.length === 0) {
    await consultPiiSentinel(prompt, effectiveAllow);
    process.exit(0);
  }

  const maskableFindings = afterAllow.filter(
    (f) =>
      (f.category === "secret" && effectiveMask.has("secret")) ||
      (f.category === "pii" && effectiveMask.has("pii")),
  );

  if (maskableFindings.length > 0) {
    const usedTags = effectiveMask.has("all")
      ? "[mask-all]"
      : (["secret", "pii"] as const)
          .filter((d) => effectiveMask.has(d))
          .map((d) => `[mask-${d}]`)
          .join(", ");
    const maskBlockLines = [
      "",
      `${randomBird()} sensitive-canary: prompt masking is not supported`,
      "",
      `  ${usedTags} cannot mask prompt content.`,
      "  The following sensitive data was detected:",
      "",
      ...findingsToLines(afterAllow),
      "",
      "  Please choose one of the following:",
      "",
      "  1. Manually redact the values above and resubmit",
      "  2. To send as-is, add an allow tag to your prompt:",
      ...allowTagLines(afterAllow, { indent: "       " }),
      "",
    ];
    process.stderr.write(maskBlockLines.join("\n"));
    process.exit(2);
  }

  const blockLines = [
    "",
    `${randomBird()} sensitive-canary: sensitive data detected — blocked`,
    "",
    ...findingsToLines(afterAllow),
    "",
    "To allow, add a tag to your prompt:",
    ...allowTagLines(afterAllow),
    "",
  ];

  process.stderr.write(blockLines.join("\n"));

  process.exit(2);
}

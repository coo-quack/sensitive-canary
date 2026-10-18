#!/usr/bin/env node

import { blockOnUnhandledError } from "./lib/fail-closed.ts";
import { parsePayload, readStdin } from "./lib/hook-payload.ts";
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
import { consultPiiSentinel, REFUSED_SOCKET_NOTE } from "./lib/pii-sentinel.ts";
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

// A prompt the rules let through is asked of the pii-sentinel server as well.
// Whether it is asked, and what the answer blocks on, is decided in
// lib/pii-sentinel.ts. Only the wording of each block is this hook's.
async function blockOnPiiSentinel(
  prompt: string,
  allow: Set<string>,
): Promise<void> {
  // An empty prompt is nothing to send. Left to the check, the socket would still
  // be looked at, and a refused socket would block a prompt with nothing in it.
  const texts =
    prompt.trim() === "" ? [] : [{ source: "prompt", text: prompt }];
  const decision = await consultPiiSentinel(texts, allow, ENABLED_CATEGORIES);
  if (decision.kind === "pass") return;
  if (decision.kind === "settings") {
    blockPrompt([
      `the "piiSentinel" entry in ${USER_CONFIG_PATH} cannot be used — blocked`,
      `  ${decision.problem}`,
      "",
      "Fix the entry, or remove it to stop asking pii-sentinel.",
    ]);
  }
  if (decision.kind === "refused") {
    blockPrompt([
      "the pii-sentinel socket was refused — blocked",
      `  ${decision.target}: ${decision.reason}`,
      "",
      REFUSED_SOCKET_NOTE,
      "To send this prompt anyway, add [allow-pii] to it.",
    ]);
  }
  if (decision.kind === "judged") {
    blockPrompt([
      `pii-sentinel judged this prompt ${decision.verdict.level} sensitivity — blocked`,
      ...findingsToLines(decision.findings),
      "",
      "To allow, add a tag to your prompt:",
      ...allowTagLines(decision.findings),
    ]);
  }
  if (decision.kind === "unavailable") {
    blockPrompt([
      "pii-sentinel did not answer — blocked",
      `  ${decision.target}: ${decision.reason}`,
      "",
      'Start it with `pii-sentinel serve`, set "onUnavailable": "allow" in the "piiSentinel" entry, or add [allow-pii] to your prompt.',
    ]);
  }
}

readStdin(main);

async function main(raw: string): Promise<void> {
  // Started here rather than at module load: the wait for stdin belongs to the
  // runtime, and counting it against the scan let a slow handover spend the
  // whole allowance before anything was read.
  beginScanBudget();
  const data = parsePayload(raw) as HookInput;

  // Whatever the runtime sends. Not throwing on a prompt that is not a string
  // was only half of it: coercing to "" made the hook exit 0 on the shapes it
  // could not read, which is the same silence as never running. Every string
  // inside the value is collected instead, at whatever depth it sits, so
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
    await blockOnPiiSentinel(prompt, effectiveAllow);
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

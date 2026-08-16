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
  beginScanBudget,
  enabledCategoriesFromEnv,
  scan,
} from "./lib/rules.ts";

blockOnUnhandledError();

interface HookInput {
  prompt?: unknown;
}

// Depth at which a prompt stops being searched. The bound is here so a deeply
// nested value cannot make the hook walk an arbitrary tree before every prompt.
const MAX_PROMPT_DEPTH = 4;

function collectStrings(value: unknown, depth = 0): string[] {
  if (typeof value === "string") return [value];
  if (depth >= MAX_PROMPT_DEPTH) return [];
  if (Array.isArray(value))
    return value.flatMap((item) => collectStrings(item, depth + 1));
  if (value !== null && typeof value === "object")
    return Object.values(value as Record<string, unknown>).flatMap((item) =>
      collectStrings(item, depth + 1),
    );
  return [];
}

const ENABLED_CATEGORIES = enabledCategoriesFromEnv();

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk: string) => (raw += chunk));
process.stdin.on("end", () => {
  // Started here rather than at module load: the wait for stdin belongs to the
  // runtime, and counting it against the scan let a slow handover spend the
  // whole allowance before anything was read.
  beginScanBudget();
  let data: HookInput;
  try {
    // Empty stdin is nothing to check. Bytes that do not parse are a check that
    // could not read its input, which is not the same as safe: two characters
    // missing from the end of a payload used to pass a key through.
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

  if (allFindings.length === 0) process.exit(0);

  // From what the user typed, not from what they pasted: a fenced log or a
  // README quoting `[allow-secret]` used to lift the guard on the key in the
  // same message. The other hook already read tags this way, so the two gave
  // different answers to the same text.
  const { effectiveAllow, effectiveMask } = resolveTagPriority(
    typedTextOf(prompt),
  );

  const afterAllow: Finding[] = dedupeFindings(
    applyAllowTags(allFindings, effectiveAllow),
  );

  if (afterAllow.length === 0) process.exit(0);

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
      ...findingsToLines(dedupeFindings(maskableFindings)),
      "",
      "  Please choose one of the following:",
      "",
      "  1. Manually redact the values above and resubmit",
      "  2. To send as-is, add an allow tag to your prompt:",
      ...allowTagLines(maskableFindings, { indent: "       " }),
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
});

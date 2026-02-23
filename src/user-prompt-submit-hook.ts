#!/usr/bin/env node

/**
 * Claude Code UserPromptSubmit hook.
 *
 * - Secrets/PII detected → exit 2 (block)
 * - [allow-xxx] tag present → exit 0 (allow)
 * - Nothing detected       → exit 0 (allow)
 */

import {
  applyAllowTags,
  dedupeFindings,
  type Finding,
  findingsToLines,
  randomBird,
  resolveTagPriority,
} from "./lib/inspector.ts";
import { scan } from "./lib/rules.ts";

interface HookInput {
  prompt?: string;
}

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk: string) => (raw += chunk));
process.stdin.on("end", () => {
  let data: HookInput;
  try {
    data = JSON.parse(raw) as HookInput;
  } catch {
    process.exit(0);
  }

  const prompt = data.prompt ?? "";

  // Scan for secrets/PII
  const allFindings = scan(prompt, "prompt");

  if (allFindings.length === 0) process.exit(0);

  // Resolve effective allow/mask tags based on first-occurrence priority.
  // For each category dimension, whichever tag type appears first in the
  // prompt wins. [allow-all] / [mask-all] resolve both dimensions at once.
  const { effectiveAllow, effectiveMask } = resolveTagPriority(prompt);

  // Apply effective allow tags
  const afterAllow: Finding[] = dedupeFindings(
    applyAllowTags(allFindings, effectiveAllow),
  );

  if (afterAllow.length === 0) process.exit(0);

  // [mask-xxx] tag: prompt masking is not supported — inform user
  // Only for findings whose dimension was resolved to mask (not allow).
  const maskableFindings = afterAllow.filter(
    (f) =>
      (f.category === "secret" && effectiveMask.has("secret")) ||
      (f.category === "pii" && effectiveMask.has("pii")),
  );

  if (maskableFindings.length > 0) {
    const hasSecret = maskableFindings.some((f) => f.category === "secret");
    const hasPii = maskableFindings.some((f) => f.category === "pii");
    const usedTags = (["secret", "pii"] as const)
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
      ...(hasSecret ? ["       [allow-secret]  — allow secrets"] : []),
      ...(hasPii ? ["       [allow-pii]     — allow PII"] : []),
      "       [allow-all]     — bypass all sensitive-canary checks",
      "",
    ];
    process.stderr.write(maskBlockLines.join("\n"));
    process.exit(2);
  }

  // Findings not covered by allow or mask — block
  const unique: Finding[] = afterAllow.filter(
    (f) =>
      !(f.category === "secret" && effectiveMask.has("secret")) &&
      !(f.category === "pii" && effectiveMask.has("pii")),
  );

  if (unique.length === 0) process.exit(0);

  const hasSecret = unique.some((f) => f.category === "secret");
  const hasPii = unique.some((f) => f.category === "pii");

  const blockLines = [
    "",
    `${randomBird()} sensitive-canary: sensitive data detected — blocked`,
    "",
    ...findingsToLines(unique),
    "",
    "To allow, add a tag to your prompt:",
    ...(hasSecret ? ["  [allow-secret]  — allow secrets"] : []),
    ...(hasPii ? ["  [allow-pii]     — allow PII"] : []),
    "  [allow-all]     — bypass all sensitive-canary checks",
    "",
  ];

  process.stderr.write(blockLines.join("\n"));

  process.exit(2);
});

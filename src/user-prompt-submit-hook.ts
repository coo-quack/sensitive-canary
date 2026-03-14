#!/usr/bin/env node

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

  const allFindings = scan(prompt);

  if (allFindings.length === 0) process.exit(0);

  const { effectiveAllow, effectiveMask } = resolveTagPriority(prompt);

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
    const hasSecret = maskableFindings.some((f) => f.category === "secret");
    const hasPii = maskableFindings.some((f) => f.category === "pii");
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
      ...(hasSecret ? ["       [allow-secret]  — allow secrets"] : []),
      ...(hasPii ? ["       [allow-pii]     — allow PII"] : []),
      "       [allow-all]     — bypass all sensitive-canary checks",
      "",
    ];
    process.stderr.write(maskBlockLines.join("\n"));
    process.exit(2);
  }

  const hasSecret = afterAllow.some((f) => f.category === "secret");
  const hasPii = afterAllow.some((f) => f.category === "pii");

  const blockLines = [
    "",
    `${randomBird()} sensitive-canary: sensitive data detected — blocked`,
    "",
    ...findingsToLines(afterAllow),
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

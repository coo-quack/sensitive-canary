import type { Finding } from "./rules.ts";

const BIRD_EMOJIS = ["🐦", "🐧", "🐤", "🐔"];

export function randomBird(): string {
  return BIRD_EMOJIS[Math.floor(Math.random() * BIRD_EMOJIS.length)] ?? "🐦";
}

export type { Finding };

type TextBlock = { type: "text"; text: string };
type ToolResultBlock = {
  type: "tool_result";
  content: string | ContentBlock[];
};
type ToolUseBlock = { type: "tool_use"; input: Record<string, unknown> };
type ContentBlock = TextBlock | ToolResultBlock | ToolUseBlock;

export interface Message {
  role: string;
  content: string | ContentBlock[];
}

function parseTagsOfType(prefix: string, messages: Message[]): Set<string> {
  const tags = new Set<string>();
  const pattern = new RegExp(`\\[${prefix}-([^\\]]+)\\]`, "gi");

  for (const msg of messages) {
    if (msg.role !== "user") continue;
    const texts =
      typeof msg.content === "string"
        ? [msg.content]
        : msg.content
            .filter((b): b is TextBlock => b.type === "text")
            .map((b) => b.text);

    for (const text of texts) {
      for (const [, tag] of text.matchAll(pattern)) {
        if (tag) tags.add(tag.toLowerCase());
      }
    }
  }
  return tags;
}

export function parseAllowTags(messages: Message[]): Set<string> {
  return parseTagsOfType("allow", messages);
}

// Resolve effective allow/mask tags based on first-occurrence priority.
// For each category dimension ("secret", "pii"), the first matching tag wins.
// [allow-all] / [mask-all] resolve both dimensions at once.
//
//   "[allow-secret] [mask-secret] ..." → secret: allow
//   "[mask-secret] [allow-secret] ..." → secret: mask
//   "[allow-secret] [mask-pii]   ..." → secret: allow, pii: mask
export function resolveTagPriority(prompt: string): {
  effectiveAllow: Set<string>;
  effectiveMask: Set<string>;
} {
  const pattern = /\[(allow|mask)-(all|secret|pii)\]/gi;
  const effectiveAllow = new Set<string>();
  const effectiveMask = new Set<string>();
  const resolved = new Set<string>();

  for (const [, kind, tag] of prompt.matchAll(pattern)) {
    if (!kind || !tag) continue;
    const k = kind.toLowerCase() as "allow" | "mask";
    const t = tag.toLowerCase();
    const dims = t === "all" ? ["secret", "pii"] : [t];

    for (const dim of dims) {
      if (!resolved.has(dim)) {
        resolved.add(dim);
        (k === "allow" ? effectiveAllow : effectiveMask).add(dim);
      }
    }
  }

  if (effectiveAllow.has("secret") && effectiveAllow.has("pii")) {
    effectiveAllow.add("all");
  }
  if (effectiveMask.has("secret") && effectiveMask.has("pii")) {
    effectiveMask.add("all");
  }

  return { effectiveAllow, effectiveMask };
}

export function applyAllowTags(
  findings: Finding[],
  allowTags: Set<string>,
): Finding[] {
  if (allowTags.size === 0) return findings;
  if (allowTags.has("all")) return [];
  return findings.filter((f) => !allowTags.has(f.category));
}

export function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    if (seen.has(f.secretValue)) return false;
    seen.add(f.secretValue);
    return true;
  });
}

export function findingsToLines(findings: Finding[]): string[] {
  return findings.map((f) => {
    const tag = f.category === "pii" ? "PII" : "Secret";
    return `  [${tag}] ${f.description} (${f.ruleId}): ${f.matchRedacted}`;
  });
}

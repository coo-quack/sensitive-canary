import { type Finding, scan } from "./rules.ts";

const BIRD_EMOJIS = ["🐦", "🐧", "🐤", "🐔"] as const;

export function randomBird(): string {
  return BIRD_EMOJIS[Math.floor(Math.random() * BIRD_EMOJIS.length)] as string;
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

/**
 * Parse [prefix-xxx] tags from user message texts.
 */
function parseTagsOfType(prefix: string, messages: Message[]): Set<string> {
  const tags = new Set<string>();
  if (!Array.isArray(messages)) return tags;

  const pattern = new RegExp(`\\[${prefix}-([^\\]]+)\\]`, "gi");

  for (const msg of messages) {
    if (msg.role !== "user") continue;
    const texts: string[] =
      typeof msg.content === "string"
        ? [msg.content]
        : Array.isArray(msg.content)
          ? (msg.content as ContentBlock[])
              .filter((b): b is TextBlock => b.type === "text")
              .map((b) => b.text)
          : [];

    for (const text of texts) {
      for (const [, tag] of text.matchAll(pattern)) {
        if (tag) tags.add(tag.toLowerCase());
      }
    }
  }
  return tags;
}

/**
 * Parse [allow-xxx] bypass tags from user message texts.
 * Supported forms:
 *   [allow-all]    — skip all rules
 *   [allow-pii]    — skip all PII rules
 *   [allow-secret] — skip all secret rules
 */
export function parseAllowTags(messages: Message[]): Set<string> {
  return parseTagsOfType("allow", messages);
}

/**
 * Parse [mask-xxx] tags from user message texts.
 * Supported forms:
 *   [mask-all]    — mask all sensitive data
 *   [mask-pii]    — mask PII
 *   [mask-secret] — mask secrets
 */
export function parseMaskTags(messages: Message[]): Set<string> {
  return parseTagsOfType("mask", messages);
}

/**
 * Resolve effective allow and mask tags based on first-occurrence priority.
 *
 * For each category dimension ("secret", "pii"), the first matching tag wins.
 * [allow-all] / [mask-all] resolve both dimensions at once.
 *
 * Examples:
 *   "[allow-secret] [mask-secret] ..." → secret: allow (allow came first)
 *   "[mask-secret] [allow-secret] ..." → secret: mask  (mask came first)
 *   "[allow-all]   [mask-secret] ..." → secret: allow, pii: allow
 *   "[allow-secret] [mask-pii]   ..." → secret: allow, pii: mask
 */
export function resolveTagPriority(prompt: string): {
  effectiveAllow: Set<string>;
  effectiveMask: Set<string>;
} {
  const pattern = /\[(allow|mask)-(all|secret|pii)\]/gi;
  const effectiveAllow = new Set<string>();
  const effectiveMask = new Set<string>();
  const resolved = new Set<string>(); // dimensions already decided: "secret", "pii"

  for (const [, kind, tag] of prompt.matchAll(pattern)) {
    if (!kind || !tag) continue;
    const dimensions: string[] =
      tag.toLowerCase() === "all" ? ["secret", "pii"] : [tag.toLowerCase()];

    for (const dim of dimensions) {
      if (!resolved.has(dim)) {
        resolved.add(dim);
        if (kind.toLowerCase() === "allow") {
          effectiveAllow.add(dim);
        } else {
          effectiveMask.add(dim);
        }
      }
    }
  }

  // Add "all" to effectiveAllow when both dimensions are allowed
  // (applyAllowTags checks allowTags.has("all") for a fast-path return)
  if (effectiveAllow.has("secret") && effectiveAllow.has("pii")) {
    effectiveAllow.add("all");
  }

  return { effectiveAllow, effectiveMask };
}

/**
 * Filter findings by allow tags.
 */
export function applyAllowTags(
  findings: Finding[],
  allowTags: Set<string>,
): Finding[] {
  if (allowTags.size === 0) return findings;
  if (allowTags.has("all")) return [];
  return findings.filter((f) => !allowTags.has(f.category));
}

/**
 * Deduplicate findings by secretValue, keeping the first occurrence.
 */
export function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    if (seen.has(f.secretValue)) return false;
    seen.add(f.secretValue);
    return true;
  });
}

/**
 * Format findings as human-readable lines for display.
 */
export function findingsToLines(findings: Finding[]): string[] {
  return findings.map((f) => {
    const tag = f.category === "pii" ? "PII" : "Secret";
    return `  [${tag}] ${f.description} (${f.ruleId}): ${f.matchRedacted}`;
  });
}

/**
 * Extract plain text strings from a single message content value.
 */
function extractTexts(
  content: string | ContentBlock[],
  basePath: string,
): Array<{ text: string; location: string }> {
  const results: Array<{ text: string; location: string }> = [];

  if (typeof content === "string") {
    results.push({ text: content, location: basePath });
    return results;
  }

  if (!Array.isArray(content)) return results;

  for (let i = 0; i < content.length; i++) {
    const block = content[i];
    const path = `${basePath}[${i}]`;

    if (!block || typeof block !== "object") continue;

    if (block.type === "text") {
      results.push({ text: block.text, location: `${path}.text` });
    } else if (block.type === "tool_result") {
      const inner = block.content;
      if (typeof inner === "string") {
        results.push({ text: inner, location: `${path}.content` });
      } else if (Array.isArray(inner)) {
        for (let j = 0; j < inner.length; j++) {
          const ib = inner[j];
          if (ib && ib.type === "text") {
            results.push({
              text: (ib as TextBlock).text,
              location: `${path}.content[${j}].text`,
            });
          }
        }
      }
    } else if (block.type === "tool_use") {
      if (block.input && typeof block.input === "object") {
        results.push({
          text: JSON.stringify(block.input),
          location: `${path}.input`,
        });
      }
    }
  }

  return results;
}

/**
 * Scan all user messages for secrets/PII, respecting allow tags.
 */
export function scanMessages(messages: Message[]): Finding[] {
  if (!Array.isArray(messages)) return [];

  const allowTags = parseAllowTags(messages);
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    if (!msg || !msg.content) continue;
    if (msg.role !== "user") continue;

    const texts = extractTexts(msg.content, `messages[${i}].content`);

    for (const { text, location } of texts) {
      const results = scan(text, location);
      for (const finding of results) {
        const key = `${finding.ruleId}:${finding.secretValue}`;
        if (!seen.has(key)) {
          seen.add(key);
          findings.push(finding);
        }
      }
    }
  }

  return applyAllowTags(findings, allowTags);
}

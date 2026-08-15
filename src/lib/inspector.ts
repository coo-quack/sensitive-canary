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

// What the user actually typed, as opposed to what the runtime wrote around it
// or what the user quoted. Both hooks read tags out of this: they answered the
// question separately once, and the prompt hook read the raw text, so a pasted
// log containing `[allow-secret]` lifted the guard on the same message's key.
//
// Claude Code writes things the user did not type into the transcript as user
// messages with plain string content: the output of a `!` command, the name and
// arguments of a slash command, and system reminders. A tag in any of those
// switched the protection off — `grep -r allow-all` was enough.
export const SYNTHETIC_ELEMENT_NAMES =
  "local-command-stdout|local-command-stderr|command-name|command-message|command-args|bash-input|bash-output|bash-stdout|bash-stderr|system-reminder";

const SYNTHETIC_USER_ELEMENTS = new RegExp(
  `<(${SYNTHETIC_ELEMENT_NAMES})>[\\s\\S]*?<\\/\\1>`,
  "g",
);

// An opening tag with nothing closing it takes the rest of the message with it.
// Pairs alone would have left an unclosed one — a truncated capture, or output
// that happens to contain the tag — reading as the user speaking.
const UNCLOSED_SYNTHETIC_ELEMENT = new RegExp(
  `<(?:${SYNTHETIC_ELEMENT_NAMES})>[\\s\\S]*$`,
  "g",
);

// Text inside a fence is being quoted, not issued: a pasted log or diff that
// happens to contain the tag is not the user asking for it.
//
// Backticks around a single word are not the same thing. The documentation here
// writes the tags that way — `[allow-secret]` — so stripping them refused the
// form the project itself teaches, and refused it silently: the block that
// followed advised adding the tag it had just ignored.
const FENCED_CODE = /```[\s\S]*?```|~~~[\s\S]*?~~~/g;

// What the user actually typed, with the above taken out.
export function userTypedText(msg: Message): string {
  const blocks =
    typeof msg.content === "string"
      ? [msg.content]
      : msg.content.filter((b) => b.type === "text").map((b) => b.text ?? "");
  return blocks
    .join("\n")
    .replace(SYNTHETIC_USER_ELEMENTS, " ")
    .replace(UNCLOSED_SYNTHETIC_ELEMENT, " ")
    .replace(FENCED_CODE, " ");
}

// The same rules over a bare string, for the prompt, which is not a message.
export function typedTextOf(text: string): string {
  return userTypedText({ role: "user", content: text });
}

// Anything that reaches a terminal or reaches Claude, with the characters that
// would let it pretend to be something else taken out. A path is attacker-chosen
// — a repository, an archive, a dependency can all put one on disk — and POSIX
// allows a newline in it, so a file could be named such that the block message
// grew extra lines saying the block was a false positive. Escape sequences got
// through the same way and can clear the screen before printing whatever they
// like.
export function forOutput(text: string): string {
  return text.replace(
    // biome-ignore lint/suspicious/noControlCharactersInRegex: that is the point
    /[\u0000-\u001f\u007f-\u009f]/g,
    (ch) => `\\x${ch.charCodeAt(0).toString(16).padStart(2, "0")}`,
  );
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

// One line per finding, capped. A rule that matches everywhere produced forty
// thousand lines of stderr, which buries the block it is trying to explain.
const MAX_FINDING_LINES = 50;

export function findingsToLines(findings: Finding[]): string[] {
  const lines = findings.slice(0, MAX_FINDING_LINES).map((f) => {
    const tag = f.category === "pii" ? "PII" : "Secret";
    return `  [${tag}] ${forOutput(f.description)} (${forOutput(f.ruleId)}): ${forOutput(f.matchRedacted)}`;
  });
  if (findings.length > lines.length)
    lines.push(`  … and ${findings.length - lines.length} more`);
  return lines;
}

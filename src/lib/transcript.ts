// Which line of the transcript is the user speaking, and what tags they wrote.
//
// A tag lifts the checks, so the question this file answers is the most
// dangerous one in the product: everything the runtime writes under the user's
// role — a compaction summary, a skill body, the output of a `!` command, a
// background task reporting back — has to be told apart from someone typing.

import fs from "node:fs";
import {
  type Message,
  resolveTagPriority,
  userTypedText,
} from "./inspector.ts";

// Maximum bytes to read from the tail of a transcript file.
const MAX_TRANSCRIPT_TAIL_BYTES = 65_536; // 64 KB

export interface TranscriptLine {
  type?: unknown;
  // Runtime-written lines that carry the user's role without the user having
  // typed them: a compaction summary, and a meta line such as a skill body.
  isCompactSummary?: unknown;
  isMeta?: unknown;
  // Where the line came from. `human` is someone at a keyboard; the other
  // values name the runtime writing under the user's role.
  origin?: { kind?: unknown } | null;
  message?: Message;
}

// Whether a transcript line records something a person typed.
//
// The field is only present on lines that have one, so a line without it is
// left to the other tests rather than rejected: most user lines carry tool
// results and have no origin, and an older runtime writes none at all.
export function wasTypedByAHuman(line: TranscriptLine): boolean {
  const kind = line.origin?.kind;
  return kind === undefined || kind === null || kind === "human";
}

// Returns true when the message carries text the user typed. A message that is
// only tool results, or only the machinery above, is not user input.
function hasTextContent(msg: Message): boolean {
  if (
    typeof msg.content !== "string" &&
    !msg.content.some((b) => b.type === "text")
  )
    return false;
  return userTypedText(msg).trim().length > 0;
}

// Load allow tags from the Claude Code session transcript.
// Transcript format (JSONL): { "type": "user"|"assistant", "message": { role, content }, … }
// Only the most recent user *text* message is consulted, and only if no tool_result
// entries have been recorded after it. This means allow tags are consumed by the first
// tool call — subsequent tool calls in the same AI turn will be blocked.
export function loadAllowTagsFromTranscript(
  transcriptPath: string,
): Set<string> {
  let raw: string;
  try {
    const stat = fs.statSync(transcriptPath);
    // A FIFO here would block the read until something wrote to it, and a hook
    // that never returns is killed by the timeout, which does not block.
    if (!stat.isFile()) return new Set();
    if (stat.size <= MAX_TRANSCRIPT_TAIL_BYTES) {
      raw = fs.readFileSync(transcriptPath, "utf8");
    } else {
      const buf = Buffer.alloc(MAX_TRANSCRIPT_TAIL_BYTES);
      const fd = fs.openSync(transcriptPath, "r");
      try {
        const bytesRead = fs.readSync(
          fd,
          buf,
          0,
          MAX_TRANSCRIPT_TAIL_BYTES,
          stat.size - MAX_TRANSCRIPT_TAIL_BYTES,
        );
        raw = buf.subarray(0, bytesRead).toString("utf8");
      } finally {
        fs.closeSync(fd);
      }
    }
  } catch {
    return new Set();
  }

  let lastUserMessage: Message | null = null;
  let toolResultAfterLastText = false;
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed) as TranscriptLine;
      const msg = parsed.message;
      // A line the runtime wrote as an assistant turn is not user input,
      // whatever the message inside it says its role is. Absent rather than
      // contradictory is fine: the field is rejected only when it names some
      // other kind of line.
      //
      // `isCompactSummary` and `isMeta` are two the runtime writes as the user
      // without the user having typed them. A compaction summary is a
      // re-injection of earlier turns, so a tag anyone discussed at any point in
      // the conversation comes back armed; a meta line carries skill bodies and
      // other file content, so writing a `SKILL.md` would be enough to lift
      // every check. Neither is someone asking for anything.
      //
      // `origin.kind` says outright which lines those are, and it is asked
      // before any of the rest: a background task reporting back arrives as
      // `task-notification`, carrying an agent's free-form prose under the
      // user's role. Prose about these very tags is enough, so a report that
      // quotes the documentation arms the guard it is describing.
      //
      // Only lines that carry the field are judged by it. Most do not — a tool
      // result has no origin — and treating absent as non-human would ignore
      // every transcript written by a runtime that predates it.
      if (
        (parsed.type === undefined || parsed.type === "user") &&
        parsed.isCompactSummary !== true &&
        parsed.isMeta !== true &&
        wasTypedByAHuman(parsed) &&
        msg?.role === "user" &&
        msg.content !== undefined
      ) {
        if (hasTextContent(msg)) {
          lastUserMessage = msg;
          toolResultAfterLastText = false;
        } else {
          toolResultAfterLastText = true;
        }
      }
    } catch {
      // skip malformed lines
    }
  }

  if (!lastUserMessage || toolResultAfterLastText) return new Set();
  // Through the same resolution the prompt hook uses, over the typed text
  // rather than the raw content. Collecting every tag instead meant this hook
  // did not see mask tags at all, so `[mask-secret] [allow-secret]` stopped the
  // prompt and then allowed the tool call it was stopping.
  return resolveTagPriority(userTypedText(lastUserMessage)).effectiveAllow;
}

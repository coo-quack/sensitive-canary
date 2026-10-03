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

// The transcript is read backwards from its end, a chunk at a time, until the
// latest line written under the user's role turns up. Reading a fixed 64 KB tail
// stopped working when the runtime began writing its attachments — the skill
// list, memory, CLAUDE.md — as lines after the prompt: those alone run past
// 100 KB, so the prompt that carried `[allow-pii]` was out of reach on the very
// first tool call, and the tag did nothing.
const TRANSCRIPT_CHUNK_BYTES = 65_536; // 64 KB

// How far back the search goes. Past this the tag is not honoured, which is the
// strict side to fail on: a missed tag blocks, a misread one would let through.
const MAX_TRANSCRIPT_SCAN_BYTES = 8 * 1_048_576; // 8 MiB

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
function isUserLine(parsed: TranscriptLine): parsed is TranscriptLine & {
  message: Message;
} {
  const msg = parsed.message;
  return (
    (parsed.type === undefined || parsed.type === "user") &&
    parsed.isCompactSummary !== true &&
    parsed.isMeta !== true &&
    wasTypedByAHuman(parsed) &&
    msg?.role === "user" &&
    msg.content !== undefined
  );
}

// The latest line written under the user's role, searching back from the end of
// the file; null when there is none within reach. Lines are split on the
// newline byte, which never occurs inside a UTF-8 sequence, so a chunk boundary
// cannot cut a character in a way that matters: the part before it is carried
// into the next chunk and parsed whole.
function latestUserLine(fd: number, size: number): TranscriptLine | null {
  let position = size;
  let carry = Buffer.alloc(0);
  let read = 0;
  const judge = (bytes: Buffer): TranscriptLine | null => {
    const text = bytes.toString("utf8").trim();
    if (!text) return null;
    try {
      const parsed = JSON.parse(text) as TranscriptLine;
      return isUserLine(parsed) ? parsed : null;
    } catch {
      // A malformed line, or the cut end of one: skipped, as it always was.
      return null;
    }
  };
  while (position > 0 && read < MAX_TRANSCRIPT_SCAN_BYTES) {
    const length = Math.min(
      TRANSCRIPT_CHUNK_BYTES,
      position,
      MAX_TRANSCRIPT_SCAN_BYTES - read,
    );
    position -= length;
    read += length;
    const chunk = Buffer.alloc(length);
    const got = fs.readSync(fd, chunk, 0, length, position);
    const data = Buffer.concat([chunk.subarray(0, got), carry]);
    let end = data.length;
    for (let i = data.length - 1; i >= 0; i--) {
      if (data[i] !== 0x0a) continue;
      const found = judge(data.subarray(i + 1, end));
      if (found) return found;
      end = i;
    }
    carry = data.subarray(0, end);
  }
  // The first line of the file has no newline in front of it.
  return position === 0 ? judge(carry) : null;
}

// Load allow tags from the Claude Code session transcript.
// Transcript format (JSONL): { "type": "user"|"assistant", "message": { role, content }, … }
// Only the most recent user *text* message is consulted, and only if no tool_result
// entries have been recorded after it. This means allow tags are consumed by the first
// tool call — subsequent tool calls in the same AI turn will be blocked.
export function loadAllowTagsFromTranscript(
  transcriptPath: string,
): Set<string> {
  let line: TranscriptLine | null;
  try {
    const stat = fs.statSync(transcriptPath);
    // A FIFO here would block the read until something wrote to it, and a hook
    // that never returns is killed by the timeout, which does not block.
    if (!stat.isFile()) return new Set();
    const fd = fs.openSync(transcriptPath, "r");
    try {
      line = latestUserLine(fd, stat.size);
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return new Set();
  }

  // A tool result after the prompt means the tags have been spent on an earlier
  // call; see the comment above this function.
  if (!line?.message || !hasTextContent(line.message)) return new Set();
  const lastUserMessage = line.message;
  // Through the same resolution the prompt hook uses, over the typed text
  // rather than the raw content. Collecting every tag instead meant this hook
  // did not see mask tags at all, so `[mask-secret] [allow-secret]` stopped the
  // prompt and then allowed the tool call it was stopping.
  return resolveTagPriority(userTypedText(lastUserMessage)).effectiveAllow;
}

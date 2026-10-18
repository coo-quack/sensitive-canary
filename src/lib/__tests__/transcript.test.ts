import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadAllowTagsFromTranscript } from "../transcript.ts";

// The reader's own constants, restated so the tests can place lines against the
// chunk edges and the scan reach. A change to either one should fail here first.
const CHUNK_BYTES = 65_536;
const SCAN_REACH_BYTES = 8 * 1_048_576;

const userLine = (text: string): string =>
  `${JSON.stringify({ type: "user", message: { role: "user", content: text } })}\n`;

// One long line that is not JSON: the reader skips it after a single parse. Many
// short lines would cost a failed parse each, and that is the slow part here.
const filler = (bytes: number): string => `${"x".repeat(bytes - 1)}\n`;

let dir: string;
let transcript: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "transcript-test-"));
  transcript = path.join(dir, "session.jsonl");
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("loadAllowTagsFromTranscript — reading back from the end", () => {
  it("finds the tag when more than one chunk of lines follows the prompt", () => {
    fs.writeFileSync(
      transcript,
      userLine("[allow-pii] please") + filler(CHUNK_BYTES + 1000),
    );
    expect(loadAllowTagsFromTranscript(transcript)).toEqual(new Set(["pii"]));
  });

  it("reads a prompt that straddles a chunk edge whole", () => {
    // The prompt starts 20 bytes before the edge of the last chunk and ends
    // after it, so its first part is only in the chunk before.
    const prompt = userLine("[allow-secret] done");
    const tailBytes = CHUNK_BYTES - 20;
    const edge = prompt.length - 20;
    expect(edge).toBeGreaterThan(0);
    expect(edge).toBeLessThan(prompt.length);
    fs.writeFileSync(transcript, prompt + filler(tailBytes));
    expect(loadAllowTagsFromTranscript(transcript)).toEqual(
      new Set(["secret"]),
    );
  });

  it("uses the latest user line, not an earlier one with a tag", () => {
    fs.writeFileSync(
      transcript,
      userLine("[allow-pii] earlier") + filler(100) + userLine("nothing here"),
    );
    expect(loadAllowTagsFromTranscript(transcript)).toEqual(new Set());
  });

  it("honours a tag within the last 8 MiB of the transcript", () => {
    // The file is 9 MiB and the prompt starts 2 MiB in: past the first megabyte
    // the reader never looks at, and inside the last 8 MiB it does read.
    const before = 2 * 1_048_576;
    const after = 7 * 1_048_576;
    fs.writeFileSync(
      transcript,
      filler(before) + userLine("[allow-pii] late") + filler(after),
    );
    expect(loadAllowTagsFromTranscript(transcript)).toEqual(new Set(["pii"]));
  });

  it("does not honour a tag further back than the 8 MiB reach", () => {
    fs.writeFileSync(
      transcript,
      userLine("[allow-pii] far back") + filler(SCAN_REACH_BYTES + 1024),
    );
    expect(loadAllowTagsFromTranscript(transcript)).toEqual(new Set());
  });
});

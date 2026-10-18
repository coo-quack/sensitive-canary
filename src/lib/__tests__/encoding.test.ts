import { describe, expect, it } from "vitest";
import { detectUtf16, utf16GuessRuns } from "../encoding.ts";

// Little-endian UTF-16 of Latin text: each letter is followed by a NUL, so every
// NUL falls on the same side of its pair.
const latin = (text: string, bom = false): Buffer =>
  Buffer.from(`${bom ? "﻿" : ""}${text}`, "utf16le");

describe("detectUtf16 — the NUL threshold", () => {
  it("decides UTF-16 from eight NULs on one side of the pairs", () => {
    const bytes = latin("abcdefgh");
    const reading = detectUtf16(bytes);
    expect(reading?.fromBom).toBe(false);
    expect(reading?.bytes.equals(bytes)).toBe(true);
  });

  it("gives no verdict with seven NULs", () => {
    expect(detectUtf16(latin("abcdefg"))).toBeNull();
  });
});

describe("detectUtf16 — byte-order marks", () => {
  it("reads a little-endian mark as the bytes as they are", () => {
    const bytes = latin("abc", true);
    const reading = detectUtf16(bytes);
    expect(reading?.fromBom).toBe(true);
    expect(reading?.bytes.equals(bytes)).toBe(true);
  });

  it("swaps a big-endian file, so its mark leads the text once read", () => {
    const bigEndian = Buffer.from(latin("abc", true)).swap16();
    const reading = detectUtf16(bigEndian);
    expect(reading?.fromBom).toBe(true);
    expect(reading?.bytes.toString("utf16le")).toBe("﻿abc");
  });

  it("decides a marked file even when its text has too few NULs to guess from", () => {
    const reading = detectUtf16(latin("a", true));
    expect(reading?.fromBom).toBe(true);
  });
});

describe("utf16GuessRuns — the undecided case", () => {
  it("reads a file under the threshold in both byte orders", () => {
    expect(utf16GuessRuns(latin("abcdefg"))).toEqual([
      "abcdefg",
      "愀戀挀搀攀昀最",
    ]);
  });

  it("gives no guesses once the NULs decide the file", () => {
    expect(utf16GuessRuns(latin("abcdefgh"))).toEqual([]);
  });

  it("gives no guesses for a file with no NUL in it", () => {
    expect(utf16GuessRuns(Buffer.from("plain text, no NUL bytes"))).toEqual([]);
  });
});

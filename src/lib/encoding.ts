// How a file's bytes are read as text.
//
// A file is not labelled with its encoding, so these decide. The decisions are
// deliberately loose and the caller reads the bytes both ways when the verdict
// is a guess: the alternative is a wrong guess that decodes a credential into
// characters no rule matches, which is the whole scan switched off for that
// file.

import fs from "node:fs";

// The bytes as little-endian UTF-16, with whether a byte-order mark said so.
//
// The mark decides it outright. Without one, the question is whether every NUL
// falls on the same side of each pair — which it does in UTF-16 text, because
// the high byte of a Latin character is zero. Requiring most pairs to carry one
// is too strong: a file whose first few hundred characters are Japanese or
// Chinese has neither byte zero. One NUL on a consistent side is enough to ask
// the question; whether the answer is text is what settles it.
//
// A guess this loose is wrong sometimes, so `fromBom` marks the ones that are
// guesses and the caller scans the bytes both ways rather than betting on it.
export type Utf16Reading = { bytes: Buffer; fromBom: boolean };

export function detectUtf16(raw: Buffer): Utf16Reading | null {
  if (raw.length < 4) return null;
  // Swapping is done on a copy: `raw` is a view into the shared read buffer.
  const swapped = (): Buffer =>
    Buffer.from(raw)
      .subarray(0, raw.length & ~1)
      .swap16();
  if (raw[0] === 0xff && raw[1] === 0xfe) return { bytes: raw, fromBom: true };
  if (raw[0] === 0xfe && raw[1] === 0xff)
    return { bytes: swapped(), fromBom: true };

  // Far enough in to reach a newline or a space. Five hundred pairs of Japanese
  // carry no zero byte at all, and that prefix decided the whole file.
  const pairs = Math.min(raw.length >> 1, 8192);
  let evenNuls = 0;
  let oddNuls = 0;
  for (let i = 0; i < pairs; i++) {
    if (raw[i * 2] === 0) evenNuls++;
    if (raw[i * 2 + 1] === 0) oddNuls++;
  }
  // Several, not one: a single stray NUL is not an encoding.
  const MINIMUM_NULS = 8;
  if (Math.max(evenNuls, oddNuls) < MINIMUM_NULS) return null;

  // How much the minority side holds is not asked. Characters in the U+xx00
  // rows put a NUL on that side, and Japanese is full of them — `一` is U+4E00,
  // and a full-width space is U+3000 — so any threshold tight enough to exclude
  // a binary also excludes an ordinary Japanese document. The counts cannot
  // separate those two cases, so the question is left to `readsAsText`, and
  // being wrong costs only a pass: the caller reads the bytes both ways
  // whenever the verdict did not come from a byte-order mark.
  //
  // Which side leads picks the order the two byte orders are tried in, not
  // whether they are tried.
  const orderings: Buffer[] =
    oddNuls >= evenNuls ? [raw, swapped()] : [swapped(), raw];
  for (const candidate of orderings) {
    if (readsAsText(candidate)) return { bytes: candidate, fromBom: false };
  }
  return null;
}

// Whether the runs of text between the NUL bytes read as something someone
// wrote. A `.env` written by a tool that terminates its values, and a log with
// a stray zero in it, both pass; a JPEG's compressed bytes do not.
export function readsAsUtf8Text(raw: Buffer): boolean {
  const sample = utf8Runs(raw.subarray(0, 4096));
  if (sample.length === 0) return false;
  let bad = 0;
  for (const ch of sample) {
    const code = ch.codePointAt(0) ?? 0;
    const isControl =
      (code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) ||
      code === 0x7f;
    if (isControl || code === 0xfffd) bad++;
  }
  return bad / sample.length < 0.05;
}

// Every run of text between the NUL bytes, joined by newlines so that no rule
// matches across two unrelated runs.
export function utf8Runs(raw: Buffer): string {
  const text = raw.toString("utf8");
  return text.indexOf("\0") === -1 ? text : text.split("\0").join("\n");
}

// Whether these bytes decoded as UTF-16 look like something someone wrote. A
// binary file can have its NULs on one side by chance; text decoded from the
// wrong encoding is mostly control characters and replacement characters, and
// this is what separates the two.
export function readsAsText(le: Buffer): boolean {
  const sample = le.subarray(0, 4096).toString("utf16le");
  if (sample.length === 0) return false;
  let bad = 0;
  for (const ch of sample) {
    const code = ch.codePointAt(0) ?? 0;
    const isControl =
      (code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) ||
      code === 0x7f;
    if (isControl || code === 0xfffd || (code >= 0xe000 && code <= 0xf8ff))
      bad++;
  }
  return bad / sample.length < 0.05;
}

// Whether the first few kilobytes hold a NUL byte that UTF-16 does not explain.
// UTF-16 text is half NUL by construction, and a `.env` written by PowerShell is
// the file a sweep least wants to skip.
const BINARY_SNIFF_BYTES = 4096;

export function looksBinary(filePath: string): boolean {
  let fd: number | undefined;
  try {
    fd = fs.openSync(filePath, "r");
    const head = Buffer.alloc(BINARY_SNIFF_BYTES);
    const read = fs.readSync(fd, head, 0, head.length, 0);
    const bytes = head.subarray(0, read);
    if (!bytes.includes(0)) return false;
    // Neither reading, rather than the UTF-16 verdict alone. That verdict is
    // deliberately loose — the file scan covers a wrong guess by reading the
    // bytes both ways — and a sweep has no such second chance, so it asks the
    // question the answer is wanted for: does anything here read as text?
    const utf16 = detectUtf16(bytes);
    if (utf16 !== null && readsAsText(utf16.bytes)) return false;
    return !readsAsUtf8Text(bytes);
  } catch {
    // Unreadable. Nothing to sweep, and the named-file path still guards it.
    return true;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

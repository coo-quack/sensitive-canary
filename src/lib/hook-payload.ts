// How both hooks take in the payload Claude Code writes to their stdin.
//
// One copy, for the same reason as fail-closed.ts: the handover, the parse and
// the exit codes for an empty or non-object payload have to agree in both hooks,
// or one of them fails open where the other does not.

import { failClosed } from "./fail-closed.ts";

// Reads all of stdin, then hands the text to `handle`. The handler is async
// because the pii-sentinel server is asked over a socket. A rejection must end
// the process with 2, since a scan that cannot finish has to block the call, so
// it is caught here rather than left to the runtime.
export function readStdin(handle: (raw: string) => Promise<void>): void {
  let raw = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => (raw += chunk));
  process.stdin.on("end", () => {
    handle(raw).catch(failClosed);
  });
}

// The payload as an object. Empty stdin is nothing to check. Bytes that do not
// parse are a check that could not read its input, which is not the same as
// safe: two characters missing from the end of a payload are enough to hide a
// key. A payload that is not an object names nothing, so there is nothing to
// scan and nothing to stop.
export function parsePayload(raw: string): Record<string, unknown> {
  try {
    if (raw.trim().length === 0) process.exit(0);
    // A null payload is read as empty, since `JSON.parse("null")` is valid JSON
    // and carries no field to check.
    const parsed: unknown = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed))
      process.exit(0);
    return parsed as Record<string, unknown>;
  } catch (error) {
    // The check never started, so it vouches for nothing. Everything else that
    // cannot finish stops the call; input that will not parse is the same case.
    failClosed(error);
  }
}

// What both hooks do when the check itself goes wrong.
//
// A hook that crashes exits 1, and only exit 2 blocks, so an unforeseen error
// is a silent pass — the failure this whole tool exists to prevent. What went
// wrong is unknown at this point, and "unknown" is not "safe": the check did
// not finish, so the call is stopped rather than let through. `[allow-all]`
// gets past it, and the message says the check failed rather than claiming a
// finding.
//
// One copy, because two would be two rules: the wording, the exit code and
// which events are handled all have to be the same in both hooks, and a fix
// applied to one of two copies is a hook that fails open on the other.

export function failClosed(error: unknown): never {
  try {
    process.stderr.write(
      `\n🐤 sensitive-canary: the check could not complete — ${
        error instanceof Error ? error.message : String(error)
      }\n\n` +
        "  Nothing was scanned, so nothing can be vouched for. Stopping rather\n" +
        "  than passing it through. Add [allow-all] to your prompt to proceed\n" +
        "  anyway, and please report this.\n",
    );
  } catch {
    // A closed stderr must not turn the block back into a pass.
  }
  process.exit(2);
}

// Registered by both hooks as their first statement. A rejection that nothing
// awaited reaches the process the same way an exception does, and either one
// arriving unhandled is the pass this exists to stop.
export function blockOnUnhandledError(): void {
  process.on("uncaughtException", failClosed);
  process.on("unhandledRejection", failClosed);
}

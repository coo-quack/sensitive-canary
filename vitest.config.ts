import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // A git worktree checked out under `.claude/` is a full copy of this

    // repository, so without this the whole suite runs a second time from

    // inside it and every count doubles.

    exclude: ["**/node_modules/**", "**/dist/**", ".claude/**"],
    // Above the harness's own limit on the hook, so the harness is what stops a
    // hanging hook and the test fails on the verdict it asserted. vitest's
    // default is 5s, which is below that limit and also below what a loaded
    // machine takes to spawn the hook a hundred and forty times: a case that
    // spawns `perl` under load has timed out here while passing on its own.
    //
    // A timeout is a backstop, not a budget. Nothing here should come close.
    testTimeout: 30_000,
  },
});

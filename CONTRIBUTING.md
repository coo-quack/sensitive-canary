# Contributing

Thanks for your interest in contributing to Sensitive Canary!

## Development Setup

```bash
git clone https://github.com/coo-quack/sensitive-canary.git
cd sensitive-canary
pnpm install
```

## Commands

```bash
pnpm test          # Run tests
pnpm run test:watch # Run tests in watch mode
pnpm run typecheck  # Type check with tsc
pnpm run lint       # Check with Biome
pnpm run fix        # Lint + auto-fix with Biome
pnpm run ci         # typecheck + lint + tests (full CI check)
```

## Branching Strategy

```
main
 ├── develop          ← integration branch
 │    └── <type>/*   ← everything that is not an urgent production fix
 └── hotfix/*        ← urgent production fixes
```

Name the branch for the kind of change, using the same `<type>` vocabulary as the
Conventional Commits requirement below: `feat/`, `fix/`, `refactor/`, `test/`,
`docs/`, `ci/`, `chore/`. `feature/` is accepted as a synonym of `feat/`. What
matters is that the prefix says what sort of change it is, so that a list of open
branches reads the way the commit history does.

### Normal development

```
<type>/short-description  →  develop  →  main (release)
```

1. Branch from `develop`: `git checkout -b feat/your-feature develop`
2. Open a PR targeting `develop`
3. After review and approval, merge into `develop`
4. When ready to release, open a PR from `develop` → `main`

### Hotfix

For urgent fixes that must go directly to production:

1. Branch from `main`: `git checkout -b hotfix/fix-description main`
2. Apply the fix and open a PR targeting `main`
3. After review and approval, merge into `main`
4. A backport PR to `develop` is created automatically by CI

If the backport PR has conflicts, resolve them manually before merging.

## Adding a New Detection Rule

1. Add the rule to `src/lib/default-config.json` — define `id`, `description`, `regex`, `category`, and optionally `entropyThreshold` and `flags`. `src/lib/rules.ts` reads that file; it holds the checksum validators, not the rules
2. Add tests to `src/lib/__tests__/rules.test.ts` — cover true positives, false negatives, and entropy filtering
   - If the pattern carries a `*`, `+` or `{n,}` on a character class, work out what input makes it backtrack and add that shape to `no rule is quadratic` in the same file. A pattern that does not return is a way past the hook, not a slow scan — see the note in `docs/rules.md`
3. Update `README.md` — add to the detection rules table
4. Update `docs/rules.md` — add full reference entry
5. Update `CHANGELOG.md` — add the rule under `## Unreleased` (see [Changelog](#changelog))

## Changelog

Changes land under a `## Unreleased` heading at the top of `CHANGELOG.md`, in the
same `### Features` / `### Fixes` / `### CI` / `### Documentation` sections a
released version uses. The
release turns that heading into `## vX.Y.Z (YYYY-MM-DD)` rather than writing the
notes from scratch, so an entry is written by the PR that makes the change, while
the reason for it is still at hand.

## Release Checklist

When bumping a version, open a PR from `develop` → `main` with:

1. Update `version` in `package.json` and `.claude-plugin/plugin.json` — the `versions` job in CI fails when the two disagree, or when either declares no version
   - Correcting a mismatch is the one version edit that does not need a release PR: the two files disagreeing is a bug, and CI is red until it is fixed
2. Rename `## Unreleased` in `CHANGELOG.md` to `## vX.Y.Z (YYYY-MM-DD)`
   - `docs/changelog.md` is a symlink to `CHANGELOG.md` — do not edit it separately
   - This content is automatically used as the GitHub Release notes by `release.yml`
3. Review `docs/rules.md` — add/update any changed rules
4. Review `README.md` — update rule counts and tables if needed
5. Run the integration test (see below) — CI never does, and it is the only check that the block still reaches Claude

After merging into `main`, `release.yml` automatically:
- Creates a git tag `vX.Y.Z`
- Creates a GitHub Release with notes extracted from `CHANGELOG.md`

The documentation site is also redeployed automatically on merge to `main`.

## Integration test

`src/__tests__/pre-tool-use-hook.integration.test.ts` runs the hook inside a real headless Claude Code session. It is the only test that checks Claude Code acts on what the hook says — the rest spawn the hook and read its output themselves, which passes whether or not the runtime reads that channel.

It needs credentials and network, so it is opt-in and CI skips it:

```bash
SENSITIVE_CANARY_INTEGRATION=1 pnpm test src/__tests__/pre-tool-use-hook.integration.test.ts
```

Run it by hand whenever the way a block is returned changes — the exit code, the channel the reason is written to, or the shape of the payload.

## Pull Requests

- Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `hotfix:`, etc.)
- All tests must pass (`pnpm test`)
- Lint must pass (`pnpm run lint`)
- One approval required to merge

## Code Style

Enforced by [Biome](https://biomejs.dev/). Run `pnpm run fix` before committing.

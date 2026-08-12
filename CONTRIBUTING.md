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
 │    └── feature/*  ← new features and non-urgent fixes
 └── hotfix/*        ← urgent production fixes
```

### Normal development

```
feature/your-feature  →  develop  →  main (release)
```

1. Branch from `develop`: `git checkout -b feature/your-feature develop`
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

1. Add the rule to `src/lib/rules.ts` — define `id`, `description`, `regex`, `category`, and optionally `entropyThreshold`
2. Add tests to `src/lib/__tests__/rules.test.ts` — cover true positives, false negatives, and entropy filtering
3. Update `README.md` — add to the detection rules table
4. Update `docs/rules.md` — add full reference entry
5. Update `CHANGELOG.md` — note the new rule under the next version

## Release Checklist

When bumping a version, open a PR from `develop` → `main` with:

1. Update `version` in `package.json` and `.claude-plugin/plugin.json` — the `versions` job in CI fails when the two disagree
2. Update `CHANGELOG.md` with a new `## vX.Y.Z (YYYY-MM-DD)` section
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

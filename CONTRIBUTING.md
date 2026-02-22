# Contributing

Thanks for your interest in contributing to sensitive-canary!

## Development Setup

```bash
git clone https://github.com/coo-quack/sensitive-canary.git
cd sensitive-canary
npm install
```

## Commands

```bash
npm test           # Run tests
npm run test:watch # Run tests in watch mode
npm run typecheck  # Type check with tsc
npm run lint       # Check with Biome
npm run fix        # Lint + auto-fix with Biome
npm run ci         # typecheck + lint + tests (full CI check)
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

1. Update `version` in `package.json` and `.claude-plugin/plugin.json`
2. Update `CHANGELOG.md` with a new `## vX.Y.Z (YYYY-MM-DD)` section
   - `docs/changelog.md` is a symlink to `CHANGELOG.md` — do not edit it separately
3. Review `docs/rules.md` — add/update any changed rules
4. Review `README.md` — update rule counts and tables if needed

Merging into `main` automatically deploys the documentation site.

## Pull Requests

- Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `hotfix:`, etc.)
- All tests must pass (`npm test`)
- Lint must pass (`npm run lint`)
- One approval required to merge

## Code Style

Enforced by [Biome](https://biomejs.dev/). Run `npm run fix` before committing.

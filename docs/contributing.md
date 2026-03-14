# Contributing

Thanks for your interest in contributing to Sensitive Canary!

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

## Pull Requests

- Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `hotfix:`, etc.)
- All tests must pass (`npm test`)
- Lint must pass (`npm run lint`)
- One approval required to merge

## Code Style

Enforced by [Biome](https://biomejs.dev/). Run `npm run fix` before committing.

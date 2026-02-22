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

## Adding a New Detection Rule

1. Add the rule to `src/lib/rules.ts` — define `id`, `description`, `regex`, `category`, and optionally `entropyThreshold`
2. Add tests to `src/lib/__tests__/rules.test.ts` — cover true positives, false negatives, and entropy filtering
3. Update `README.md` — add to the detection rules table
4. Update `docs/rules.md` — add full reference entry
5. Update `CHANGELOG.md` — note the new rule under the next version

## Release Checklist

When bumping a version, create a `release/vX.Y.Z` branch and open a PR with:

1. Update `version` in `package.json` and `.claude-plugin/plugin.json`
2. Update `CHANGELOG.md` with a new `## vX.Y.Z (YYYY-MM-DD)` section
   - `docs/changelog.md` is a symlink to `CHANGELOG.md` — do not edit it separately
3. Review `docs/rules.md` — add/update any changed rules
4. Review `README.md` — update rule counts and tables if needed

## Pull Requests

- Branch from `main`
- Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, etc.)
- All tests must pass (`npm test`)
- Lint must pass (`npm run lint`)
- One approval required to merge

## Code Style

Enforced by [Biome](https://biomejs.dev/). Run `npm run fix` before committing.

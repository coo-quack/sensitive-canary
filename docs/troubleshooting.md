# Troubleshooting

## Node.js version too old

Sensitive Canary requires Node.js **22.6.0** or later for `--experimental-strip-types`.

```bash
node --version
```

Install or update from [nodejs.org](https://nodejs.org/).

## Hooks not running after install

1. **Check plugin status** — run `/plugin` and verify sensitive-canary is listed and enabled. Plugin hooks should activate immediately after install without a restart. If they still don't work, try restarting Claude Code.
2. **Check hooks config** — for manual installs, verify the hooks entries exist in `~/.claude/settings.json`

## False positives

If legitimate content is being blocked:

- Add `[allow-secret]`, `[allow-pii]`, or `[allow-all]` to your prompt to bypass the check for that message
- Allow tags apply only to the current message and do not persist
- For PreToolUse hooks, allow tags are single-use — they are consumed by the first tool call. If Claude performs multiple tool calls, you may need to include the tag again

## .env file blocking

This is by design. `.env` and `.env.*` files are blocked by filename, regardless of their contents, but only while the `secret` category is enabled (the default). `[allow-secret]` or `[allow-all]` will lift this block if you need Claude to read an `.env` file intentionally. `[allow-pii]` will not: the block is a secret guard.

## Plugin not found after marketplace registration

Verify the marketplace was registered correctly:

1. Run `/plugin` and check the **Marketplaces** tab
2. Ensure `coo-quack/claude-code-marketplace` appears in the list
3. Try running `/plugin install sensitive-canary@coo-quack` again

## Still stuck?

[Open an issue](https://github.com/coo-quack/sensitive-canary/issues) on GitHub.

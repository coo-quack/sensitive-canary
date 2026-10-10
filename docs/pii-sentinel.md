# pii-sentinel (optional)

The rules find personal data by its shape: an e-mail address, a card number, a phone number. They cannot tell that a
diagnosis next to a name is sensitive. [pii-sentinel](https://github.com/coo-quack/pii-sentinel) is a local model
that reads the text and judges a document `none`, `low` or `high`. sensitive-canary can ask it about every file it
reads and every prompt, after the rules have passed them.

sensitive-canary does not install, start or update pii-sentinel, and adds no dependency. Run the server yourself
(it needs [uv](https://docs.astral.sh/uv/); the first start downloads the model, about 1.2 GB):

```bash
mkdir -m 700 ~/.pii-sentinel
uvx --from git+https://github.com/coo-quack/pii-sentinel@v0.3.0 \
  pii-sentinel serve --model coo-quack/mmBERT-pii-sentinel --socket ~/.pii-sentinel/pii-sentinel.sock
```

Then point the [config file](#config-file-location) at it. The config needs the absolute path, because `~` is not
expanded there (replace `/Users/you` with your home directory):

```json
{
  "piiSentinel": {
    "socket": "/Users/you/.pii-sentinel/pii-sentinel.sock"
  }
}
```

| Key | Default | Meaning |
|---|---|---|
| `socket` | | The server's Unix socket, as an absolute path. |
| `blockOn` | `"high"` | Block at this level or above (`"high"` or `"low"`). |
| `timeoutMs` | `3000` | How long one hook call waits for the server, in total. |
| `maxChars` | `20000` | How much of each file or prompt is sent; the model judges the beginning. |
| `onUnavailable` | `"block"` | What to do when the server does not answer: `"block"`, or `"allow"` to rely on the rules alone. |

- It is asked only when the entry is present and the `pii` category is enabled. Without the entry nothing changes.
- `[allow-pii]` and `[allow-all]` lift its blocks, as they lift the PII rules.
- A server that does not answer blocks by default: you asked for the check, and a check that silently did not run
  would be a pass. Start the server before Claude Code, or set `"onUnavailable": "allow"`.
- Before sending any text, the hook checks the socket. Every directory on its path must belong to you or root, and a
  directory that other users can write to is refused unless it has the sticky bit, as `/tmp` does. Group write counts
  as writable by others unless the group contains only you, so fix a refusal with `chmod go-w <directory>`. The socket
  itself must be a socket file owned by you or root.
- `url` is no longer supported. The hook cannot tell whether the program on a TCP port is your server, so a config
  with `url` blocks with the reason. Replace it with `socket`.
- An entry that cannot be used (a typo, a `url`) blocks too, with the reason.
- The text goes only to the local server, which never logs or stores it. Command lines and environment variables are
  not sent; the rules cover them.


# pii-sentinel (optional)

The rules find personal data by its shape: an e-mail address, a card number, a phone number. They cannot tell that a
diagnosis next to a name is sensitive. [pii-sentinel](https://github.com/coo-quack/pii-sentinel) is a local model
that reads the text and judges a document `none`, `low` or `high`. sensitive-canary can ask it about every file it
reads and every prompt, after the rules have passed them.

sensitive-canary does not install, start or update pii-sentinel, and adds no dependency. Run the server yourself
(it needs [uv](https://docs.astral.sh/uv/); the first start downloads the model, about 1.2 GB):

```bash
mkdir -p -m 700 ~/.pii-sentinel
uvx --from git+https://github.com/coo-quack/pii-sentinel@v0.3.0 \
  pii-sentinel serve --model coo-quack/mmBERT-pii-sentinel --socket ~/.pii-sentinel/pii-sentinel.sock
```

Then point the [config file](https://github.com/coo-quack/sensitive-canary#config-file-location) at it. The config needs the absolute path, because `~` is not
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
| `blockOn` | `"high"` | Block at this level or above (`"high"` or `"low"`). `"identifiable"` (experimental) blocks at `"high"`, and also on a `date_of_birth` or `postal_address` finding marked `pii: true`, and on an identifier or attribute that reaches its `identifiableThresholds` value (see below). Switching from `"low"` drops the level block at `low` (see below). |
| `identifiableThresholds` | `{}` | Under `"identifiable"`, the probability (0 to 1) at which each category you name blocks. Other names are refused. No category is named by default, so probabilities block nothing until you name one. A threshold of 1 in effect turns a category off, and 0 blocks whenever the server reports it. |
| `timeoutMs` | `3000` | How long one hook call waits for the server, in total. |
| `maxChars` | `20000` | How much of each file or prompt is sent; the model judges the beginning. |
| `onUnavailable` | `"block"` | What to do when the server does not answer: `"block"`, or `"allow"` to rely on the rules alone. A refused socket blocks either way. |

- It is asked only when the entry is present and the `pii` category is enabled. Without the entry nothing changes.
- `[allow-pii]` and `[allow-all]` lift its blocks, as they lift the PII rules.
- A server that does not answer blocks by default: you asked for the check, and a check that silently did not run
  would be a pass. Start the server before Claude Code, or set `"onUnavailable": "allow"`.
- Before sending any text, the hook checks the socket. Every directory on its path must belong to you or root, and a
  directory that other users can write to is refused unless it has the sticky bit, as `/tmp` does. Group write counts
  as writable by others unless the group contains only you, so fix a refusal with `chmod go-w <directory>`. Group membership is read from `/etc/group` and `/etc/passwd`, plus the static records of `nss-systemd` under `/etc/userdb` and the other directories it reads, and is trusted only when `/etc/nsswitch.conf` names no source other than `files` and `systemd` for `passwd`, `group` and `initgroups`. Any other source, such as `sss`, `ldap`, `nis`, `compat` or `winbind`, can add members none of those files show, so with one of them (Fedora's default lists `sss`), and on macOS, which has no `nsswitch.conf`, a group-writable directory is always refused. Memberships that systemd services hand out over Varlink, such as systemd-homed's, are not read. On Windows these checks are skipped. The socket
  itself must be a socket file owned by you or root. A refused socket blocks even with `"onUnavailable": "allow"`:
  the server behind it may be running, and falling back on the rules would skip it without a word.
- `url` was removed in v0.10.0. The hook cannot tell whether the program on a TCP port is your server, so a config
  with `url` blocks with the reason. Replace it with `socket`.
- An entry that cannot be used (a typo) blocks too, with the reason.
- The text goes only to the local server, which never logs or stores it. Command lines and environment variables are
  not sent; the rules cover them.

## Blocking on identifiers and attributes

`"blockOn": "identifiable"` is experimental and opt-in. The level still blocks at `high`, as it does under `"high"`. Under `"identifiable"`, a file or prompt is also blocked, whatever its level, in these two cases:

- A `date_of_birth` or `postal_address` finding is marked `pii: true`. This is the findings path, and it needs pii-sentinel 0.5.0 or later. Version 0.4.0 returns neither finding type, so nothing changes with it.
- A category the user names in `identifiableThresholds` reaches the probability set for it. This is the probability path. No category is named by default, so the probabilities block nothing until you name one.

The categories are of two kinds:

- **Identifiers**, which identify a person on their own: `email_or_phone`, `government_id`, `financial_account`, `sns_handle` and `ip_address_of_a_person`.
- **Attributes**, which identify a person once they are linked to a name: `postal_address`, `date_of_birth`, `employment_info` and `precise_location`.

`person_name` alone never blocks, since names appear in most development text (commit authors, code owners, comments). When it is also at or above 0.5, the block reason adds `; a name is present`.

The block reason names the category and says why it identifies a person, for example `document names a date of birth, which identifies a person once it is linked to a name, in this conversation or another`. A finding's block reason gives the category sentence with the value redacted.

`identifiableThresholds` names a category and the probability it blocks at, from 0 to 1. For example, `{ "date_of_birth": 0.9 }` blocks a file the server reads as a date of birth at 0.9 or above, whatever its level, and leaves every other category alone. Setting all nine categories to 0.5 gives the blocking that 0.14.0 had by default. A name outside the list above is refused with the config, so a threshold cannot be set on a category that is never consulted.

Under `"identifiable"`, an answer without `categories`, or with a value that is not a number from 0 to 1, is unavailable whatever the thresholds, so `onUnavailable` applies. Under `"high"` and `"low"` such an answer is read as before.

The block does not depend on whose data it is. A date of birth or postal address that is the user's own blocks as anyone's would. A workplace blocks only through its probability, when `employment_info` is named, since the findings path does not use it.

Switching from `"low"` to `"identifiable"` drops the level block at `low`. A name with an e-mail address that the model judges `low` blocked under `"low"`; under `"identifiable"` the e-mail address blocks only if `email_or_phone` is named and reaches its threshold, and the name alone still passes.

Measured on 600 local source files with pii-sentinel 0.5.1 on CPU, with the nine categories at 0.5 (the 0.14.0 default). The sample was random, drawn from TypeScript, JavaScript, Python, Go, Ruby, shell and Markdown files under 200 KB. The probability path blocked 64 files that `high` did not, and 49 of those were false positives. 55 crossed the `sns_handle` threshold (import paths, GitHub URLs, package names, TODO initials) and 11 crossed the `email_or_phone` threshold (example addresses, names in references). A file can cross both, so these counts do not sum to 49. Without thresholds, the findings path blocked one file beyond `high` on the same 600: a minified script with a false `postal_address` finding.

On the benchmark negatives (250 texts), the same configuration blocked 56 that `high` did not. 30 of them came from `date_of_birth` findings on the dates of birth of historical figures, which the findings path still blocks under `"identifiable"`. The other 26 came from probabilities alone, mostly on test card numbers, placeholder IDs and reserved-domain e-mail addresses. On the own samples (108 negatives), it blocked 2 beyond `high`, both on the `financial_account` probability for test card numbers.

Latency on CPU, per request: a median of 51 ms for the benchmark and own-sample texts, and for the source files cut at 20,000 characters a median of 1.8 s and a 95th percentile of 12 s.

The probability path therefore stays opt-in. Its false positives come from the probability heads on ordinary development text, so name a category only after measuring it on your own text.

pii-sentinel's own measurement found `postal_address` usable only when the server marks it `pii: true`, since it otherwise fires on business addresses. From pii-sentinel 0.5.0, a company's address, such as a head office in a footer, comes back with `pii: false` (label `ADDRESS_CORPORATE`), so `"identifiable"` does not block on it. The `pii-address-jp` rule is unaffected: it finds a Japanese postal address by its shape, a company's included, so that address is still blocked by the rule.

`[allow-pii]` and `[allow-all]` lift an identifiable block, as they lift any pii-sentinel block.

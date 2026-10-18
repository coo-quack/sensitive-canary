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
| `blockOn` | `"high"` | Block at this level or above (`"high"` or `"low"`). `"identifiable"` blocks at `"high"`, and also when an identifier or attribute reaches its `identifiableThresholds` value (see below). Switching from `"low"` drops the level block at `low` (see below). |
| `identifiableThresholds` | `0.5` for each | Under `"identifiable"`, the probability (0 to 1) at which each category blocks, by name. Other names are refused. A threshold of 1 in effect turns a category off, and 0 blocks whenever the server reports it. The defaults are provisional (see below). |
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

`"blockOn": "identifiable"` is experimental and opt-in. `"high"` stays the default, so the level alone decides the block.

Under `"identifiable"`, a file or prompt is blocked when its level is `high`, and also when one of these categories is at or above its threshold, whatever the level:

- **Identifiers**, which identify a person on their own: `email_or_phone`, `government_id`, `financial_account`, `sns_handle` and `ip_address_of_a_person`.
- **Attributes**, which identify a person once they are linked to a name: `postal_address`, `date_of_birth`, `employment_info` and `precise_location`.

`person_name` alone never blocks, since names appear in most development text (commit authors, code owners, comments). When it is also at or above 0.5, the block reason adds `; a name is present`.

The block reason names the category and says why it identifies a person, for example `document names a date of birth, which identifies a person once it is linked to a name, in this conversation or another`. `identifiableThresholds` gives the probability each category must reach, from 0 to 1, and the default is 0.5 for each. A name outside the list above is refused with the config, so a threshold cannot be set on a category that is never consulted.

Switching from `"low"` to `"identifiable"` drops the level block at `low`. A name with an e-mail address that the model judges `low` blocked under `"low"`; under `"identifiable"` the e-mail address blocks only if the server reports `email_or_phone` at or above its threshold, and the name alone still passes.

A category the server does not report never blocks. An answer without `categories` counts as the server not answering under `"identifiable"`, so `onUnavailable` applies, and a category value that is not a number from 0 to 1 does the same. Under `"high"` and `"low"` such an answer is read as before.

Member and customer numbers, and schools, have no pii-sentinel category. A member or customer number is found by the `pii-customer-number` rule; a school is not covered.

The defaults are provisional. They are placeholders until the measured thresholds from [coo-quack/pii-sentinel#46](https://github.com/coo-quack/pii-sentinel/issues/46) are reported, and they will be replaced before this option is recommended. Until then the thresholds have not been measured, so the rate of false positives at 0.5 is unknown.

Measured so far (coo-quack/pii-sentinel#46): the evaluation set has no gold spans for the five attribute heads, so they were measured against a proxy, the writer's brief, with 7 to 8 positive test documents per head. At thresholds chosen on dev, `postal_address` had precision 0.15 and recall 0.50, `employment_info` 0.60 and 0.43, and `ip_address_of_a_person` 1.00 and 0.50 (4 flags). `sns_handle` found nothing, and `date_of_birth` had no dev positives. None meets the bar for blocking (precision 0.7, recall 0.5, ten positives). So today the attribute categories add little: the labelled-attribute rules (`pii-date-of-birth`, `pii-customer-number`, `pii-address-jp`) carry the attributes, and the value of `"identifiable"` is in the identifier categories. The option will not become the default until pii-sentinel learns attribute spans.

`[allow-pii]` and `[allow-all]` lift an identifiable block, as they lift any pii-sentinel block.

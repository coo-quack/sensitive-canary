import { describe, expect, it } from "vitest";
import { scan } from "../rules.ts";
import { AWS_KEY, DEFAULT_RULES, ruleIds } from "./rule-fixtures.ts";

// What the shipped patterns match, at the edges of what they claim to. Every
// rule has one example and the suite runs it; an example sits in the middle of
// its range, so the cases here are the ones an example cannot reach — a length
// one over the guess, a range's last prefix, a grouping nobody thought of.

describe("numbers that are not people", () => {
  it.each([
    ["000000000000", "twelve zeros"],
    ["checksum 000000000000 ok", "twelve zeros in a sentence"],
    ["111111111111", "twelve ones"],
  ])("%s is not a My Number (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-mynumber-jp");
  });

  it("a real My Number still is one", () => {
    expect(ruleIds("My Number: 123456789018")).toContain("pii-mynumber-jp");
  });

  it.each([
    ["01-02-2024", "a date"],
    ["09-15-2025", "another date"],
    ["build 0000 0000 0000", "a zero-padded id"],
    ["0120-123-4567", "a freephone number, which belongs to a business"],
  ])("%s is not a Japanese telephone number (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-phone-jp");
  });

  it.each(["090-1234-5678", "03-1234-5678", "080 1234 5678"])(
    "%s still is one",
    (line) => {
      expect(ruleIds(line)).toContain("pii-phone-jp");
    },
  );
});

// Formats confirmed against each vendor's own documentation, after a survey
// found the rules here were written to shapes those vendors do not issue.
describe("credential formats", () => {
  // Every branch of the card rule, in both directions. Luhn gates all of them,
  // so each number below is Luhn-valid and none is published test data.
  it.each([
    ["36123456789013", "Diners, 14 digits"],
    ["6011000991300009", "Discover 6011"],
    ["6450000000000002", "Discover 644-658"],
    ["3530111333300000", "JCB 3528-3589"],
    ["2223003122003222", "Mastercard 2-series"],
    ["6221260000000000", "UnionPay 62"],
    ["8171990000000008", "UnionPay 81"],
  ])("%s is a card (%s)", (number) => {
    expect(ruleIds(`card ${number}`)).toContain("pii-credit-card");
  });

  // Discover's published range stops at 658. Treating "65" as a two-digit
  // prefix claims 659, which belongs to nobody here.
  it("659 is not a Discover range", () => {
    expect(ruleIds("card 6591111111111116")).not.toContain("pii-credit-card");
  });

  // Token rotation introduced xoxe-; xapp- is app-level; xwfp- is a workflow
  // token. The character class held only b, a, p, r and s.
  it.each(["xoxb", "xoxp", "xoxe", "xapp", "xwfp"])(
    "a Slack %s- token is found",
    (prefix) => {
      expect(ruleIds(`${prefix}-1-${"a".repeat(40)}`)).toContain("slack-token");
    },
  );

  it.each([
    "glpat",
    "glrt",
    "gldt",
    "gloas",
    "glcbt",
    "glptt",
    "glimt",
    "glagent",
  ])("a GitLab %s- token is found", (prefix) => {
    expect(ruleIds(`${prefix}-${"a".repeat(20)}`)).toContain("gitlab-pat");
  });

  // A restricted key has a rule of its own; widening the secret-key rule to
  // cover `rk_` too left that rule unable to fire.
  it("a restricted key is the restricted-key rule, not the secret-key one", () => {
    expect(ruleIds(`rk_live_${"a".repeat(24)}`)).toEqual([
      "stripe-restricted-key",
    ]);
  });

  it.each([
    [`sk_live_${"a".repeat(24)}`, "a secret key"],
    [`sk_org_${"a".repeat(24)}`, "an organization key"],
    [`whsec_${"a".repeat(32)}`, "a webhook signing secret"],
  ])("%s is a Stripe secret (%s)", (token) => {
    expect(ruleIds(token)).toContain("stripe-secret-key");
  });

  // Mapbox documents the token as header.payload.signature where the header is
  // the literal pk, sk or tk — two dots, not three. Requiring three matched
  // nothing Mapbox issues.
  it.each(["pk", "sk", "tk"])("a Mapbox %s. token is found", (prefix) => {
    expect(ruleIds(`${prefix}.eyJ1IjoiYWJjIn0.${"a".repeat(22)}`)).toContain(
      "mapbox-token",
    );
  });

  // sentry-cli splits the token on underscores and requires exactly three
  // parts. The rule was written for dots.
  it("a Sentry org token is underscore-separated", () => {
    expect(ruleIds(`sntrys_eyJpYXQiOjEuMH0=_${"c".repeat(43)}`)).toContain(
      "sentry-org-token",
    );
  });
});

// A word anywhere within forty characters suppressed the address. The suppression
// belongs to the operand position: `ssh user@host` is a host, `rsync failed,
// notify alice@corp.io` is an address. The host:path forms of scp and rsync are
// already handled by the trailing colon.
describe("an address near a remote-shell command", () => {
  it.each([
    "rsync failed, notify alice@acmecorp.io",
    "# sftp creds, ask carol@acmecorp.io",
    "See ssh(1). Maintainer: bob@acmecorp.io",
    "the ssh key belongs to dave@acmecorp.io",
    "scp is slow; email erin@acmecorp.io",
  ])("%s is an address", (text) => {
    expect(ruleIds(text)).toContain("pii-email");
  });

  // An address is never an argument on the way to another address: without that,
  // the first host swallows the second one's exemption.
  it("only the host is exempt, not what follows it", () => {
    expect(
      ruleIds("ssh deploy@bastion.acmecorp.io admin@acmecorp.io"),
    ).toContain("pii-email");
  });

  it.each([
    "ssh deploy@bastion.acmecorp.io",
    "ssh -i ~/.ssh/id_ed25519 deploy@bastion.acmecorp.io",
    "ssh -o StrictHostKeyChecking=no deploy@bastion.acmecorp.io",
    "scp build.tar ops@files.acmecorp.io:/srv/",
    "rsync -a ops@files.acmecorp.io:/srv/ .",
    "sftp ops@files.acmecorp.io",
  ])("%s is a host", (text) => {
    expect(ruleIds(text)).not.toContain("pii-email");
  });
});

describe("keywords and boundaries are read as words, not substrings", () => {
  const flags = (t: string): string[] => scan(t).map((f) => f.ruleId);
  const V = "Xk9mP2qR7vL4nW1s";

  it.each([`COMPASS=${V}`, `BYPASS=${V}`, `PASSENGER_NAME=${V}`])(
    "%s is not a password",
    (text) => {
      expect(flags(text)).not.toContain("env-assignment");
    },
  );

  it.each([`DB_PASS=${V}`, `DB_PASSWORD=${V}`, `MYSQL_PASSWD=${V}`])(
    "%s is",
    (text) => {
      expect(flags(text)).toContain("env-assignment");
    },
  );

  // The lookbehind used to allow exactly one space.
  it.each([
    "ssh deploy@prod.acme-corp.net",
    "ssh  deploy@prod.acme-corp.net",
    "ssh -p 22 deploy@prod.acme-corp.net",
    "scp -r build ops@files.acme-corp.net:/srv/",
    "rsync -avz ops@files.acme-corp.net:/srv/ .",
  ])("%s is a host, not a person", (text) => {
    expect(flags(text)).not.toContain("pii-email");
  });

  it("an address further from the command is still a person", () => {
    const text = `ssh into the box, then write to ${"x".repeat(45)} ada@analytical-engines.org`;
    expect(flags(text)).toContain("pii-email");
  });

  // Square's own contract puts the maximum at 1024, so a token longer than the
  // sixty seen in the wild is a token, not a false positive. Pinning the length
  // at exactly sixty let every longer one through.
  it.each([64, 128, 512])("a %i-character Square token is one", (length) => {
    expect(flags(`EAAA${"b".repeat(length - 4)}`)).toContain(
      "square-access-token",
    );
  });

  // The boundary still has work to do: a longer standard-base64 blob that opens
  // with these four characters is not a token.
  it("a standard-base64 blob beginning EAAA is not one", () => {
    expect(flags(`data:${`EAAA${"b".repeat(60)}`}/x+y=`)).not.toContain(
      "square-access-token",
    );
  });

  it.each([
    `key_EAAA${"b".repeat(60)}`,
    `https://x.io/a?token=EAAA${"b".repeat(60)}`,
  ])("%s is one", (text) => {
    expect(flags(text)).toContain("square-access-token");
  });
});

// Every rule needs a value it must catch, or the id list proves only that a name
// is present. Four of the nine added in this release had their patterns made
// unmatchable and the suite stayed green, because nothing here asked them to
// find anything.
describe("every rule catches something", () => {
  const EXAMPLES: Record<string, string> = {
    "aws-access-key": `${AWS_KEY}`,
    "gcp-api-key": `AIzaSyC${"A".repeat(32)}`,
    "github-pat": `ghp_${"A".repeat(36)}`,
    "github-fine-grained": `github_pat_${"A".repeat(82)}`,
    "gitlab-pat": `glpat-${"A".repeat(20)}`,
    "npm-token": `npm_${"A".repeat(36)}`,
    "openai-key": `sk-${"A".repeat(48)}`,
    "openai-project-key": "sk-proj-Xk9mP2qR7vL4nW1sYj3cBz8dEf5gHiKoNpQuTxMn",
    "openai-service-key": `sk-svcacct-${"A".repeat(40)}`,
    "anthropic-key": `sk-ant-${"A".repeat(95)}`,
    "replicate-token": `r8_${"A".repeat(37)}`,
    "huggingface-token": `hf_${"A".repeat(34)}`,
    "groq-key": `gsk_${"A".repeat(52)}`,
    "openrouter-key": `sk-or-v1-${"a".repeat(64)}`,
    "xai-key": `xai-${"A".repeat(80)}`,
    "perplexity-key": `pplx-${"A".repeat(48)}`,
    "digitalocean-pat": `dop_v1_${"a".repeat(64)}`,
    "supabase-key": `sbp_${"a".repeat(40)}`,
    "slack-token": "xoxb-123456789012-ABCDEFGHIJ",
    "slack-webhook": `https://hooks.slack.com/services/TABCDEFGH/BABCDEFGHIJ/${"A".repeat(24)}`,
    "discord-webhook": `https://discord.com/api/webhooks/123456789012345678/${"A".repeat(68)}`,
    "telegram-bot-token": `12345678:AA${"A".repeat(33)}`,
    "twilio-sid": `AC${"a".repeat(32)}`,
    "stripe-secret-key": `sk_live_${"A".repeat(24)}`,
    "stripe-restricted-key": `rk_test_${"A".repeat(24)}`,
    "square-access-token": `EAAA${"a".repeat(60)}`,
    "sendgrid-key": `SG.${"A".repeat(22)}.${"B".repeat(43)}`,
    "mailgun-key": `key-${"a".repeat(32)}`,
    "mailchimp-key": `${"a".repeat(32)}-us1`,
    jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "private-key": "-----BEGIN RSA PRIVATE KEY-----",
    "connection-string": "postgres://admin:hunter2xyz@db.internal/app",
    "mapbox-token": `pk.eyJ${"a".repeat(20)}.${"b".repeat(20)}.${"c".repeat(20)}`,
    "sentry-user-token": `sntryu_${"a".repeat(64)}`,
    "sentry-org-token": `sntrys_eyJpYXQiOjEuMH0=_${"c".repeat(43)}`,
    "atlassian-token": `ATATT3${"a".repeat(180)}`,
    "linear-key": `lin_api_${"a".repeat(40)}`,
    "postman-key": `PMAK-${"a".repeat(24)}-${"b".repeat(34)}`,
    "azure-storage-key": `AccountKey=${"a".repeat(86)}==`,
    "private-key-base64": `LS0tLS1CRUdJTi${"QUJDRA".repeat(9)}`,
    "url-basic-auth":
      "https://admin:s3cr3tP4ssw0rdX9@internal.corp.example.com",
    "azure-sas-key": `SharedAccessKey=${"a".repeat(43)}=`,
    "google-oauth-secret": "GOCSPX-aBcD1234eFgH5678iJkL",
    "flyio-token": `FlyV1 fm2_${"a".repeat(50)}`,
    "databricks-token": `dapi${"0123456789abcdef".repeat(2)}`,
    "vault-token": `hvs.${"A".repeat(30)}`,
    "shopify-token": `shpat_${"0123456789abcdef".repeat(2)}`,
    "doppler-token": `dp.pt.${"A".repeat(44)}`,
    "grafana-token": `glsa_${"A".repeat(40)}`,
    "notion-token": `ntn_${"A".repeat(44)}`,
    "generic-secret": "api_key = Xk9mP2qR7vL4nW1sYj3cBz8d",
    "env-assignment": "DB_PASSWORD=Xk9mP2qR7vL4nW1sYj3cBz8d",
    "pii-email": "contact alice@analytical-engines.org",
    "pii-credit-card": "card 4532015112830366",
    "pii-ipv4-public": "the client IP address is 8.8.8.8",
    "pii-ipv6": "ipv6: 2001:4860:4860::8888",
    "pii-ssn": "SSN 123-45-6789",
    "pii-mynumber-jp": "My Number: 123456789018",
    "pii-nir-fr": "NIR 188022B12345659",
    "pii-codice-fiscale-it": "codice fiscale RSSMRA85M01H501Q",
    "pii-steuer-id-de": "Steuer-IdNr. 12345678903",
    "pii-dni-nie-es": "DNI 12345678Z",
    "pii-rrn-kr": "주민등록번호 900101-1234568",
    "pii-brn-kr": "사업자등록번호 220-81-62517",
    "pii-resident-id-cn": "身份证 11010519491231002X",
    "pii-phone-us": "call 415-555-0132",
    "pii-phone-jp": "03-1234-5678",
    "pii-phone-fr": "tél: 01 23 45 67 89",
    "pii-phone-it": "telefono: 0212345678",
    "pii-phone-de": "Telefon: 0301234567",
    "pii-phone-es": "teléfono: 612345678",
    "pii-phone-kr": "phone 010-1234-5678",
    "pii-phone-cn": "电话 13800138000",
    "pii-postal-jp": "〒100-0001",
    "pii-postal-code": "ZIP 94107",
    "pii-postal-cn": "postal code 100000",
  };

  it("has an example for every shipped rule", () => {
    const missing = DEFAULT_RULES.map((r) => r.id).filter(
      (id) => !(id in EXAMPLES),
    );
    expect(missing).toEqual([]);
  });

  it.each(DEFAULT_RULES.map((r) => r.id))("%s finds its example", (id) => {
    const example = EXAMPLES[id];
    if (example === undefined) throw new Error(`no example for ${id}`);
    expect(scan(example).map((f) => f.ruleId)).toContain(id);
  });

  // A credential longer than the pattern guessed must not become invisible.
  //
  // This is the defect the Square rule had, generalised: an exact length with a
  // negative lookahead behind it has no shorter match to fall back to, so one
  // character over the guess stopped the token matching at all. Every vendor
  // length in this file is a guess about someone else's format, so the check is
  // run over every rule rather than the ones anyone suspected — the example is
  // padded with more of the characters it already ends in.
  // The rules a longer value legitimately does not belong to. Each is exact
  // because the format is, not because a length was guessed: a checksum fixes
  // the digits, or the credential is a fixed-width field. Anything not listed
  // has to survive the padding, so a new rule with a guessed upper bound fails
  // here rather than going quiet in a release.
  const LONGER_IS_A_DIFFERENT_THING: Record<string, string> = {
    "aws-access-key": "twenty characters exactly; a longer run is not a key",
    "databricks-token": "dapi and thirty-two hex; longer is a digest",
    "shopify-token": "a prefix and thirty-two hex; longer is a digest",
    "twilio-sid": "thirty-four characters; longer is a certificate digest",
    "pii-email": "padding the end writes a different domain",
    "pii-credit-card": "the checksum fixes the digits",
    "pii-ssn": "nine digits; a longer run is not one",
    "pii-mynumber-jp": "twelve digits with a check digit",
    "pii-nir-fr": "fifteen digits with a two-digit key",
    "pii-codice-fiscale-it": "sixteen characters, checksummed",
    "pii-steuer-id-de": "eleven digits with a check digit",
    "pii-dni-nie-es": "eight digits and a checksum letter",
    "pii-rrn-kr": "thirteen digits with a check digit",
    "pii-brn-kr": "ten digits with a check digit",
    "pii-resident-id-cn": "eighteen characters with a check digit",
    "pii-phone-us": "a dialling plan fixes the length",
    "pii-phone-jp": "ten or eleven digits",
    "pii-phone-fr": "ten digits",
    "pii-phone-it": "a dialling plan fixes the length",
    "pii-phone-de": "a dialling plan fixes the length",
    "pii-phone-es": "nine digits",
    "pii-postal-code": "five digits",
    "pii-postal-cn": "six digits",
    "pii-ipv4-public": "four octets",
  };

  // The list above is a list, so it is held to the rules that exist: an id left
  // in it after its rule is renamed or dropped would silently stop anything
  // being checked.
  it("exempts only rules that are shipped", () => {
    const ids = new Set(DEFAULT_RULES.map((r) => r.id));
    const stale = Object.keys(LONGER_IS_A_DIFFERENT_THING).filter(
      (id) => !ids.has(id),
    );
    expect(stale).toEqual([]);
  });

  const alphabetFor = (example: string): string => {
    const tail = example.slice(-12);
    if (/^[0-9]+$/.test(tail)) return "0123456789";
    if (/^[a-f0-9]+$/i.test(tail)) return "abcdef0123456789";
    if (/^[a-z0-9]+$/.test(tail)) return "abcdefghijklmnopqrstuvwxyz0123456789";
    return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  };

  const padded = (example: string, extra: number): string => {
    const alphabet = alphabetFor(example);
    let out = example;
    for (let i = 0; i < extra; i++) out += alphabet[i % alphabet.length];
    return out;
  };

  it.each(
    DEFAULT_RULES.map((r) => r.id).filter(
      (id) => !(id in LONGER_IS_A_DIFFERENT_THING),
    ),
  )("%s still finds a value that runs longer", (id) => {
    const example = EXAMPLES[id];
    if (example === undefined) throw new Error(`no example for ${id}`);
    for (const extra of [1, 8, 64]) {
      expect(
        scan(padded(example, extra)).map((f) => f.ruleId),
        `${id} with ${extra} more characters`,
      ).toContain(id);
    }
  });
});

// Every rule has an example, and the test above enforces that. What no example
// does is sit on a boundary: each is one value from the middle of the range, so
// a range written one digit short, a length guessed too tight, or a grouping
// nobody thought of all pass the suite. Every bug in this block was found that
// way and none of them by the examples.
describe("rule boundaries", () => {
  // A Luhn-valid PAN of a given length, built digit by digit so the check digit
  // is right and no card-shaped literal is written down.
  const pan = (prefix: string, length: number): string => {
    const body = prefix.split("");
    while (body.length < length - 1) body.push(String((body.length * 7) % 10));
    let sum = 0;
    let double = true;
    for (let i = body.length - 1; i >= 0; i--) {
      let d = Number(body[i]);
      if (double) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
      double = !double;
    }
    return body.join("") + String((10 - (sum % 10)) % 10);
  };

  const grouped = (digits: string, sizes: number[]): string => {
    const groups: string[] = [];
    let at = 0;
    for (const n of sizes) {
      groups.push(digits.slice(at, at + n));
      at += n;
    }
    return groups.join(" ");
  };

  const found = (text: string, id: string): boolean =>
    scan(text).some((f) => f.ruleId === id);

  // `5[0-8][0-9]` covered 6500–6589 and stopped: a range ending at 6589 belongs
  // to no issuing scheme, and the last hundred prefixes went unmatched.
  it.each(["6500", "6589", "6590", "6599"])(
    "a Discover PAN beginning %s is matched",
    (prefix) => {
      expect(found(pan(prefix, 16), "pii-credit-card")).toBe(true);
    },
  );

  // Every alternative assumed groups of four. A card is copied the way it is
  // printed, and neither of these is printed in fours.
  it("an Amex PAN written 4-6-5 is matched", () => {
    expect(found(grouped(pan("3782", 15), [4, 6, 5]), "pii-credit-card")).toBe(
      true,
    );
  });

  it("a Diners PAN written 4-6-4 is matched", () => {
    expect(found(grouped(pan("3600", 14), [4, 6, 4]), "pii-credit-card")).toBe(
      true,
    );
  });

  // An exact length with a negative lookahead behind it does not degrade: one
  // character over and there is no shorter match to fall back to, so the token
  // stops matching altogether rather than matching partly.
  const filler = (n: number): string =>
    "A1b2C3d4E5f6G7h8I9j0".repeat(60).slice(0, n);

  it.each([
    ["sq0csp-", 43],
    ["sq0csp-", 44],
    ["sq0csp-", 64],
    ["sq0atp-", 22],
    ["sq0atp-", 61],
  ])("a Square token %s with %i characters is matched", (prefix, n) => {
    expect(found(prefix + filler(n), "square-access-token")).toBe(true);
  });

  it.each([60, 200])("a Square EAAA token of %i characters is matched", (n) => {
    expect(found(`EAAA${filler(n)}`, "square-access-token")).toBe(true);
  });

  // No boundary at all, which is its own kind of missing boundary: the pattern
  // matched inside a longer run of hex and accepted upper case, so a certificate
  // fingerprint was a Twilio SID.
  it("a Twilio SID inside a longer hex string is not a SID", () => {
    const hex = `AC${"0123456789ABCDEF".repeat(2)}`;
    expect(found(`SHA256:${hex}AA`, "twilio-sid")).toBe(false);
  });

  it("a Twilio SID on its own is one", () => {
    expect(found(`AC${"0123456789abcdef".repeat(2)}`, "twilio-sid")).toBe(true);
  });
});

// ── the two rules whose patterns were rewritten for speed ────────────────────

// Both were changed by bounding a quantifier, which is a change to what they
// match as much as to how long they take. The performance cases above would
// pass just as well if the patterns had stopped matching anything at all.
describe("pii-email after bounding the local part", () => {
  const email = (text: string): boolean =>
    scan(text).some((f) => f.ruleId === "pii-email");

  it.each([
    ["ada@analytical-engines.org", "the plain form"],
    ["Alice.Smith@Example.COM", "mixed case"],
    ["user+tag@analytical-engines.org", "plus addressing"],
    ["user.name@sub.analytical-engines.co.uk", "several domain labels"],
    ["a@b.co", "the shortest real shape"],
    [
      "user_name%foo-bar@analytical-engines.org",
      "every character of the local part",
    ],
    ["see<ada@analytical-engines.org>now", "embedded in surrounding text"],
    [
      `${"a".repeat(64)}@analytical-engines.org`,
      "a local part at RFC 5321's limit",
    ],
  ])("%s is detected (%s)", (text) => {
    expect(email(text)).toBe(true);
  });

  // What bounding the local part costs. 65 characters before the `@` with no
  // dot to restart the boundary is not a deliverable address, and it is also a
  // way to write one this rule will not see.
  it("a local part past the limit is not detected", () => {
    expect(email(`${"a".repeat(65)}@analytical-engines.org`)).toBe(false);
  });

  // A dot restarts the word boundary, so a long address with dots in it is
  // still found — the limit applies to one unbroken run, not to the whole
  // local part.
  it("a long local part broken by dots is still detected", () => {
    const local = Array.from({ length: 10 }, () => "a".repeat(20)).join(".");
    expect(email(`${local}@analytical-engines.org`)).toBe(true);
  });

  // Domains without a dot were never matched, before this change or after it.
  it.each(["user@localhost", "user@example", "user@[192.168.0.1]"])(
    "%s is not detected, as before",
    (text) => {
      expect(email(text)).toBe(false);
    },
  );
});

// `openssl genpkey -aes256` writes this header, and it was not one of the forms
// the rule listed.
describe("encrypted private key headers", () => {
  it.each([
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
  ])("%s is detected", (header) => {
    expect(scan(header).some((f) => f.ruleId === "private-key")).toBe(true);
  });

  it("a header that is not a private key is not detected", () => {
    expect(
      scan("-----BEGIN CERTIFICATE-----").some(
        (f) => f.ruleId === "private-key",
      ),
    ).toBe(false);
  });
});

// A survey of how five vendors actually format their credentials found five
// shapes the rules did not see. Each is held here in both directions: the value
// that must be found, and the near neighbour that must stay quiet. Widening a
// pattern until it matches is easy, and a pattern that matches everything
// protects nothing.
describe("the credential shapes the rules used to miss", () => {
  const hits = (text: string, ruleId: string): boolean =>
    scan(text).some((f) => f.ruleId === ruleId);

  describe("telegram-bot-token counts the hash loosely", () => {
    // The pattern asked for exactly 33 characters after `AA`. Not at least 33 —
    // exactly, so a 32-character token and a 35-character one were both
    // invisible, and the length that did work was the one nobody writes down.
    it.each([
      ["32", "110201543:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"],
      ["35", "8012345678:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawXyz"],
      ["a six-digit bot id", "123456:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"],
    ])("%s characters after AA is a token", (_label, token) => {
      expect(hits(token, "telegram-bot-token")).toBe(true);
    });

    it.each([
      ["a bot id with no hash", "1234567890:AA"],
      [
        "too few digits before the colon",
        "12345:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw",
      ],
    ])("%s is not", (_label, text) => {
      expect(hits(text, "telegram-bot-token")).toBe(false);
    });
  });

  it("connection-string reads the SRV scheme MongoDB Atlas hands out", () => {
    expect(
      hits(
        "mongodb+srv://svc:Xk2p9QmR7t@cluster0.abcd.mongodb.net/db",
        "connection-string",
      ),
    ).toBe(true);
  });

  describe("aws-access-key knows the prefixes it was missing", () => {
    it.each(["ABIA", "ACCA", "APKA", "ASCA", "AKIA"])("%s", (prefix) => {
      expect(hits(`${prefix}3QF7TZ9KLMN2PQRS`, "aws-access-key")).toBe(true);
    });

    it("a four-letter run that is not a prefix is not a key", () => {
      expect(hits("AZZA3QF7TZ9KLMN2PQRS", "aws-access-key")).toBe(false);
    });

    // AWS writes `EXAMPLE` where the random part would end, in every setup
    // guide it publishes. A block on one of those reads exactly like a block on
    // a live key, and this project's own documentation is full of them.
    it.each([
      ["the documented access key", ["AKIA", "IOSFODNN7", "EXAMPLE"].join("")],
      ["the documented session key", ["ASIA", "IOSFODNN7", "EXAMPLE"].join("")],
      ["another from the docs", ["AKIA", "I44QH8DHB", "EXAMPLE"].join("")],
    ])("%s is documentation, not a credential", (_label, key) => {
      expect(hits(key, "aws-access-key")).toBe(false);
    });
  });

  describe("private-key-base64 at each base64 alignment", () => {
    const pem = [
      "-----BEGIN RSA PRIVATE KEY-----",
      "MIIEowIBAAKCAQEAwK3vJ9m5Q8xY2nB4dF6hL0pR7sT1uV3wX5yZ8aC2eG4iK6mO",
      "-----END RSA PRIVATE KEY-----",
      "",
    ].join("\n");

    // Three bytes encode to four characters, so where the header sits relative
    // to that boundary decides what it looks like once encoded. Matching one
    // alignment would find one key in three.
    it.each([0, 1, 2])("%i bytes ahead of the header", (offset) => {
      const encoded = Buffer.from("x".repeat(offset) + pem, "utf8").toString(
        "base64",
      );
      expect(hits(`client-key-data: ${encoded}`, "private-key-base64")).toBe(
        true,
      );
    });

    it("the plaintext header is still the plaintext rule's to find", () => {
      expect(hits(pem, "private-key")).toBe(true);
      expect(hits(pem, "private-key-base64")).toBe(false);
    });
  });

  describe("url-basic-auth", () => {
    it.each([
      [
        "a private registry",
        "https://deploy:Xk2p9QmR7tLw@registry.internal.example.com/v2/",
      ],
      [
        "a git remote",
        "git clone https://svcacct:ghp_A1b2C3d4E5f6G7h8@github.com/org/repo.git",
      ],
    ])("%s is a finding", (_label, text) => {
      expect(hits(text, "url-basic-auth")).toBe(true);
    });

    // The rule captures no group, so the shape tests that need one do not run
    // over it. `isPlaceholder` does — it is applied to every secret rule — and
    // it is the whole of what keeps these quiet. Each was measured: without it
    // all four are findings.
    it.each([
      [
        "a generic pair against localhost",
        "https://user:password@localhost:8080",
      ],
      [
        "a reference the shell never expanded",
        "https://x-access-token:${GH_TOKEN}@github.com/org/repo.git",
      ],
      [
        "an environment variable",
        "https://admin:$REGISTRY_PASSWORD@registry.example.com",
      ],
      [
        "the words a document tells you to replace",
        "https://USERNAME:PASSWORD@example.com/path",
      ],
    ])("%s is not", (_label, text) => {
      expect(scan(text)).toEqual([]);
    });
  });
});

describe("credential formats the vendors document", () => {
  const hits = (text: string, ruleId: string): boolean =>
    scan(text).some((f) => f.ruleId === ruleId);
  const b64 = (n: number): string =>
    "aB3d5f7h9jK2m4n6p8r0stUvwx1y3z5A7c9e1g3iQwErTyUiOpAsDfGhJkLzXcVbNm"
      .repeat(4)
      .slice(0, n);
  const hex = (n: number): string =>
    "a3d5f7b9c2e4a6d8f0b1c3e5a7d9f0b2".repeat(4).slice(0, n);
  // Assembled rather than written out. GitHub's push protection reads these
  // three as live tokens and refuses the push, which is the shapes being right.
  const glft = ["gl", "ft-"].join("");
  const grRunner = ["GR", "1348941"].join("");
  const sqOauth = ["sq", "0atp-"].join("");
  const sqSecret = ["sq", "0csp-"].join("");

  it.each([
    ["linear-key", "mixed case", `lin_api_${b64(40)}`],
    ["notion-token", "the legacy secret_ token", `secret_${b64(43)}`],
    ["digitalocean-pat", "an OAuth access token", `doo_v1_${hex(64)}`],
    ["digitalocean-pat", "an OAuth refresh token", `dor_v1_${hex(64)}`],
    ["gitlab-pat", "a feed token", `${glft}${b64(20)}`],
    ["gitlab-pat", "a runner registration token", `${grRunner}${b64(20)}`],
    ["flyio-token", "a token with no auth scheme in front", `fm2_${b64(120)}`],
    ["flyio-token", "an fo1_ token", `fo1_${b64(43)}`],
    ["flyio-token", "underscore inside the body", `fm2_aB3d5f7h_${b64(60)}`],
    ["square-access-token", "an OAuth token", `${sqOauth}${b64(24)}`],
    ["square-access-token", "a client secret", `${sqSecret}${b64(43)}`],
    ["huggingface-token", "an organization token", `api_org_${b64(34)}`],
    ["twilio-sid", "an uppercase Account SID", `AC${hex(32).toUpperCase()}`],
    ["twilio-sid", "an API Key SID", `SK${hex(32)}`],
    [
      "postman-key",
      "uppercase hex",
      `PMAK-${hex(24).toUpperCase()}-${hex(34).toUpperCase()}`,
    ],
    [
      "replicate-token",
      "a hyphen in the body",
      "r8_aB3d5f7h9jK2m4n6-8r0stUvwx1y3z5A7c9e1",
    ],
    ["azure-sas-key", "an IoT DPS 64-byte key", `SharedAccessKey=${b64(86)}==`],
    ["azure-sas-key", "a 16-byte key", `SharedAccessKey=${b64(22)}==`],
  ])("%s finds %s", (ruleId, _label, value) => {
    expect(hits(value, ruleId)).toBe(true);
  });

  it.each([
    [
      "digitalocean-pat",
      "dox_v1_ is not a DigitalOcean prefix",
      `dox_v1_${hex(64)}`,
    ],
    ["twilio-sid", "AB is not a Twilio prefix", `AB${hex(32)}`],
    ["replicate-token", "r9_ is not a Replicate prefix", `r9_${b64(37)}`],
  ])("%s does not find %s", (ruleId, _label, value) => {
    expect(hits(value, ruleId)).toBe(false);
  });

  // The whole key, not a prefix of it. `{95}` matched 102 of the 108 characters
  // and left the tail outside the match.
  it("anthropic-key matches the key to its end", () => {
    const key = `sk-ant-api03-${b64(93).replace(/[+/]/g, "x")}AA`;
    const finding = scan(key).find((f) => f.ruleId === "anthropic-key");
    expect(finding?.secretValue).toHaveLength(key.length);
  });
});

// ISO/IEC 7812 allows 10–19 digits and the brands use most of that range. The
// pattern encoded one length per brand, so a 19-digit UnionPay or JCB card —
// and every Maestro card — went unmatched.
describe("card numbers at every length their brand issues", () => {
  const luhnCheck = (body: string): string => {
    let sum = 0;
    let double = true;
    for (let i = body.length - 1; i >= 0; i--) {
      let d = Number(body[i]);
      if (double) d = d * 2 > 9 ? d * 2 - 9 : d * 2;
      double = !double;
      sum += d;
    }
    return String((10 - (sum % 10)) % 10);
  };
  const pan = (prefix: string, total: number): string => {
    let body = prefix;
    let n = 7;
    while (body.length < total - 1) {
      n = (n * 7 + 3) % 10;
      body += String(n);
    }
    return body + luhnCheck(body);
  };
  const found = (value: string): boolean =>
    scan(`card ${value}`).some((f) => f.ruleId === "pii-credit-card");

  it.each([
    ["visa", "4539", [13, 16, 19]],
    ["amex", "3782", [15]],
    ["discover", "6011", [16, 17, 18, 19]],
    ["jcb", "3528", [16, 17, 18, 19]],
    ["diners", "3056", [14, 16, 17, 18, 19]],
    ["unionpay", "6212", [16, 17, 18, 19]],
    ["maestro", "6759", [12, 13, 14, 15, 16, 17, 18, 19]],
  ] as [string, string, number[]][])("%s", (_brand, prefix, lengths) => {
    for (const total of lengths) {
      expect(found(pan(prefix, total)), `${total} digits`).toBe(true);
    }
  });

  it("a nineteen-digit run that fails Luhn is not a card", () => {
    expect(found("6212272727272727270")).toBe(false);
  });

  it("a thirteen-digit millisecond timestamp is not a card", () => {
    expect(found("1755300000000")).toBe(false);
  });

  it("groups separated by spaces and by hyphens are both found", () => {
    const digits = pan("4539", 19);
    const spaced = digits.replace(/(.{4})/g, "$1 ").trim();
    const hyphenated = digits.replace(/(.{4})/g, "$1-").replace(/-$/, "");
    expect(found(spaced)).toBe(true);
    expect(found(hyphenated)).toBe(true);
  });
});

describe("connection-string after bounding the credentials", () => {
  const conn = (text: string): boolean =>
    scan(text).some((f) => f.ruleId === "connection-string");

  it.each([
    "mongodb://user:pass@host/db",
    "postgres://u:p@h:5432/d",
    "postgresql://u:p@h/d",
    "mysql://root:secret@localhost",
    "redis://default:abc123@127.0.0.1:6379",
    "see mongodb://user:pass@host in the log",
  ])("%s is detected", (text) => {
    expect(conn(text)).toBe(true);
  });

  it.each([
    ["mongodb://host/db", "no credentials"],
    ["https://user:pass@host", "a scheme the rule does not cover"],
    ["mongodb://user@host", "no password"],
  ])("%s is not detected (%s)", (text) => {
    expect(conn(text)).toBe(false);
  });

  // What the bound costs: a userinfo field longer than 256 characters. A
  // password that long is not what a connection string carries, and the
  // alternative is the quantifier running to the end of the file.
  it("credentials longer than the bound are not detected", () => {
    expect(conn(`mongodb://user:${"p".repeat(1025)}@host`)).toBe(false);
    expect(conn(`mongodb://user:${"p".repeat(1024)}@host`)).toBe(true);
  });
});

describe("env-assignment after bounding the name", () => {
  const assigned = (text: string): boolean =>
    scan(text).some((f) => f.ruleId === "env-assignment");

  it.each([
    "API_KEY=abcdefgh12345",
    "SECRET=abcdefgh12345",
    "MY_SECRET_TOKEN = supersecretvalue",
    "DB_PASSWORD=hunter2xyz",
    "PRIVATE_KEY=Xk9mP2qR7vL4nW1s",
    "AWS_SECRET_ACCESS_KEY_2=abcdefghijkl",
  ])("%s is detected", (text) => {
    expect(assigned(text)).toBe(true);
  });

  it.each([
    ["NOTASECRET=short", "a value under eight characters"],
    ["SECRET=", "no value at all"],
  ])("%s is not detected (%s)", (text) => {
    expect(assigned(text)).toBe(false);
  });

  // The bound is on the run of capitals either side of the keyword. A name
  // longer than that is not an environment variable anyone writes, and saying
  // so here is what stops the bound being loosened to "fix" a case nobody has.
  it("a name with more than 64 capitals before the keyword is not detected", () => {
    expect(assigned(`${"A".repeat(65)}SECRET=abcdefgh12345`)).toBe(false);
    expect(assigned(`${"A".repeat(64)}SECRET=abcdefgh12345`)).toBe(true);
  });
});

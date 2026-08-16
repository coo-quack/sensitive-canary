import { describe, expect, it } from "vitest";
import { scan } from "../rules.ts";
import {
  entropy,
  isNotSecretShaped,
  MIN_MEAN_WORD_LENGTH,
  readsAsWords,
  SHORTEST_MEASURABLE_SEGMENT,
} from "../shapes.ts";
import { isRealAwsKey } from "../validators.ts";
import { AWS_KEY, ruleIds } from "./rule-fixtures.ts";

// The guards that decide a match is not a credential after all. Each one waves
// a value through, so each is a way past every rule it runs over.

// ── entropy ───────────────────────────────────────────────────────────────────

describe("entropy", () => {
  it("returns 0 for a single repeated character", () => {
    expect(entropy("aaaa")).toBe(0);
  });

  it("returns a higher value for a more varied string", () => {
    expect(entropy("abcdefgh")).toBeGreaterThan(entropy("aaaabbbb"));
  });

  it("'password' entropy is below 3.0 (env-assignment threshold)", () => {
    expect(entropy("password")).toBeLessThan(3.0);
  });

  it("random-looking value entropy is above 3.5 (generic-secret threshold)", () => {
    expect(entropy("Xk9mP2qR7vL4nW1s")).toBeGreaterThan(3.5);
  });
});

// Half of a realistic `.env.example` was blocked on its contents, which defeats
// the point of exempting the name: the file exists to be committed and read.
describe("a value written to be replaced", () => {
  it.each([
    "DB_PASSWORD=your-password-here",
    "API_TOKEN=REPLACE_ME_WITH_REAL",
    "GITHUB_TOKEN=your_token_here",
    "SECRET_KEY=django-insecure-CHANGE-THIS-IN-PRODUCTION",
    "DATABASE_URL=postgres://user:password@localhost:5432/db",
    "TOKEN=<your-token>",
    "API_KEY=${SOME_OTHER_VAR}",
    "CLIENT_SECRET=xxxxxxxxxxxxxxxx",
  ])("%s is a placeholder", (line) => {
    expect(scan(line)).toHaveLength(0);
  });

  // At least one part has to be a marker. Without that, a value assembled only
  // from the ordinary words around secrets reads as a placeholder, and those
  // are the values a real one is easily mistaken for.
  it.each([
    "API_KEY=access-refresh-client-auth",
    "SECRET=production-staging-local",
    "TOKEN=api-key-token-secret",
  ])("%s has no marker in it and is not a placeholder", (line) => {
    expect(scan(line).length).toBeGreaterThan(0);
  });

  // The list is deliberately short of `example`: AWS documents a key that ends
  // in it, and that key is still a key.
  it.each([
    `key=${AWS_KEY}`,
    "aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
    "POSTGRES_PASSWORD: Sup3rS3cretDbPassw0rd",
    "export GITHUB_TOKEN=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    "DB_PASSWORD=hunter2xyzabc",
    "postgres://admin:s3cr3tP4ss@db.corp.internal/app",
  ])("%s is not", (line) => {
    expect(scan(line).length).toBeGreaterThan(0);
  });

  // Only secret rules consult the list. An address is not a placeholder because
  // somebody named a mailbox after a marker word.
  it.each([
    "contact todo@analytical-engines.org",
    "write to placeholder@analytical-engines.org",
  ])("%s is still an address", (line) => {
    expect(ruleIds(line)).toContain("pii-email");
  });
});

// A survey of six hundred files from real repositories found twenty-six wrong
// blocks. These are them, by the shape that caused each.
describe("a value that is not the secret its name suggests", () => {
  it.each([
    [
      "TOKEN_ENDPOINT=https://login.microsoftonline.com/common/oauth2/v2.0/token",
      "a public endpoint",
    ],
    ['"token_url": "https://sts.googleapis.com/v1/token"', "a public URL"],
    ['"subject_token_type": "urn:ietf:params:oauth:token-type:jwt"', "a URN"],
    ['secret_name = "BACKEND_SERVICE_API_KEY"', "the name of a secret"],
    ['secret_id   = "PROJECT_DB_PASSWORD"', "the id of a secret"],
    ["TOKEN_HEADER_NAME=X-Auth-Token", "a header name"],
    ["VAULT_TOKEN_PATH=/var/run/secrets/vault/token", "a path"],
    [
      "AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/token",
      "a documented variable",
    ],
    ["PASSWORD_MIN_LENGTH=12345678", "a number"],
    ["SECRET_MANAGER_PROJECT=my-company-production", "a project name"],
    ['const TOKEN_STORAGE_KEY = "app.auth.token.v2";', "a storage key"],
    ["JWT_SECRET_ISSUER=https://auth.corp.example", "an issuer"],
  ])("%s is not a secret (%s)", (line) => {
    expect(scan(line)).toHaveLength(0);
  });

  // A rule with a fixed prefix has already said what it found: a Slack webhook
  // is a URL and a secret, and the shape test must not be asked about it.
  //
  // Assembled rather than written out: GitHub's push protection refuses a commit
  // containing one, which is a fair summary of why the rule exists.
  it.each([
    [
      [
        "https://hooks.slack.com",
        "services",
        "T00000000",
        "B00000000",
        "X".repeat(24),
      ].join("/"),
      "slack-webhook",
    ],
    [
      "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
      "env-assignment",
    ],
    ["GITHUB_TOKEN=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "github-pat"],
    ["DB_PASSWORD=Sup3rS3cretDbPassw0rd", "env-assignment"],
  ])("%s is still found by %s", (line, ruleId) => {
    expect(ruleIds(line)).toContain(ruleId);
  });
});

describe("a connection string nobody has filled in", () => {
  it.each([
    "postgres://user:password@localhost:5432/appdb",
    "postgres://postgres:postgres@localhost:5432/appdb",
    "postgres://root:root@127.0.0.1:5432/test",
    "postgres://${PGUSER}:${PGPASSWORD}@${PGHOST}/${PGDATABASE}",
    "postgres://$DB_USER:$DB_PASS@$DB_HOST/app",
    '"postgres://{}:{}@{}:{}/{}"',
  ])("%s carries no credential", (line) => {
    expect(ruleIds(line)).not.toContain("connection-string");
  });

  it.each([
    "postgres://admin:s3cr3tP4ss@db.corp.internal/app",
    "mysql://root:secret@localhost",
    "postgres://user:password@prod.corp.internal/app",
  ])("%s does", (line) => {
    expect(ruleIds(line)).toContain("connection-string");
  });
});

// `name@version` is the shape of every line in a lockfile, and it is also the
// shape of an address. No hostname begins with a label that is only digits.
describe("a package specifier is not an address", () => {
  it.each([
    "playwright-core@1.35.1.patch",
    "eslint@8.57.0",
    "@babel/core@7.24.0",
    "typescript@5.4.2",
    "golang.org/x/mobile@0.0.0",
  ])("%s is a package", (text) => {
    expect(ruleIds(text)).not.toContain("pii-email");
  });

  it.each([
    "alice@analytical-engines.org",
    "ada.lovelace@analytical-engines.org",
    "user@123abc.com",
  ])("%s is an address", (text) => {
    expect(ruleIds(text)).toContain("pii-email");
  });
});

// A context word is a label, not a fragment of the identifier beside the number.
describe("a label, not a package name", () => {
  it.each([
    [
      "      devtools-protocol: 0.0.869402\n      extract-zip: 2.0.1",
      "a lockfile",
    ],
    [
      "golang.org/x/mobile v0.0.0-201903121516-09-d3739f865fa6/go.mod",
      "a go.sum line",
    ],
    ["adm-zip: 0.5.518000", "another package"],
  ])("%s supplies no context (%s)", (line) => {
    expect(scan(line)).toHaveLength(0);
  });

  it.each([
    ["postal code 518000 Shenzhen", "pii-postal-cn"],
    ["邮编 518000", "pii-postal-cn"],
    ["mobile: 010-1234-5678", "pii-phone-kr"],
  ])("%s still is one (%s)", (line, ruleId) => {
    expect(ruleIds(line)).toContain(ruleId);
  });
});

// The two guards that decide a match is not a secret after all. Each waves a
// value through, so each is a way past every rule it runs over, and what they
// are asked has to be narrower than the shape they were written from.
describe("the guards that wave a value through", () => {
  describe("AWS documentation keys", () => {
    const body = ["IOSFODNN7", "EXAMPLE"].join("");

    it.each(["AKIA", "ASIA", "AIDA", "AROA"])(
      "%s with the documented body is documentation",
      (prefix) => {
        expect(isRealAwsKey(prefix + body)).toBe(false);
      },
    );

    // The bodies differ between AWS's own guides, so the suffix is the test and
    // not a list of them. Narrowing it to one body was tried and reverted: it
    // blocked `AKIAI44QH8DHBEXAMPLE`, which is as much documentation as the
    // other two, and a list exempts the bodies someone wrote down rather than
    // the convention AWS keeps to.
    //
    // What the suffix costs is written down here so that it stays a decision:
    // a live key whose last seven characters spell the word is exempt.
    it("a key ending in EXAMPLE is treated as documentation", () => {
      expect(isRealAwsKey(["AKIA", "3QF7TZ9KL", "EXAMPLE"].join(""))).toBe(
        false,
      );
    });

    it("a real key is a real key", () => {
      expect(isRealAwsKey(["AKIA", "3QF7TZ9KLMN2", "PQRS"].join(""))).toBe(
        true,
      );
    });
  });

  describe("dotted values", () => {
    const random = (n: number): string =>
      "A1b2C3d4E5f6G7h8I9j0".repeat(10).slice(0, n);

    it.each([
      "process.env.API_KEY",
      "user.password_digest",
      "response.data.accessToken",
      "this.options.tokenizer",
      "config.database.connectionString",
      "settings.oauth2ClientSecretIdentifier",
      "value.toLowerCase",
      "a.b",
    ])("%s is a reference to a value, not a value", (identifier) => {
      expect(isNotSecretShaped(identifier)).toBe(true);
    });

    // Dotted credentials exist, so the shape alone cannot stand for "this is
    // code". A name is words; a token changes case or slips in a digit every
    // character or two.
    it.each([
      ["a dotted API token", ["tok", random(28), random(28)].join(".")],
      ["a two-part dotted secret", ["k", random(24)].join(".")],
      [
        "five dot-separated parts",
        [random(30), random(20), random(22), random(40), random(22)].join("."),
      ],
    ])("%s is not a reference", (_label, value) => {
      expect(isNotSecretShaped(value)).toBe(false);
    });
  });
});

// The rule was widened to read `:` and lower case, and that made it read
// ordinary code: `function check(token: ShellToken)` became a secret, and the
// plugin could not read its own source — 97 findings across 17 files of this
// repository. It is anchored to the start of a line now, and its value has to be
// a value rather than an expression.
describe("env-assignment does not read code as a secret", () => {
  const assigned = (text: string): boolean =>
    scan(text).some((f) => f.ruleId === "env-assignment");

  it.each([
    "function check(token: ShellToken): boolean {",
    "  tokens: ShellToken[]",
    "  token: ShellToken;",
    "  accessToken: string;",
    "  secretGroup: 2,",
    "  const token = tokens[i];",
    "  const hasSecret =\n    showAllTags || findings.some(f)",
  ])("%s is not a secret", (text) => {
    expect(assigned(text)).toBe(false);
  });

  it.each([
    "POSTGRES_PASSWORD: Sup3rS3cretDbPassw0rd",
    '  "client_secret": "Xk9mP2qR7vL4nW1sYj3c"',
    "aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
    "export GITHUB_TOKEN=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz01",
    "  DB_PASSWORD: hunter2xyzabc",
  ])("%s is", (text) => {
    expect(assigned(text)).toBe(true);
  });

  // The whole point of anchoring: the plugin has to be able to read itself.
  it("does not flag this repository's own source", async () => {
    const { readFileSync } = await import("node:fs");
    const { dirname, join } = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const src = join(dirname(fileURLToPath(import.meta.url)), "..");
    for (const file of ["shell.ts", "bash-commands.ts", "tool-inputs.ts"]) {
      const text = readFileSync(join(src, file), "utf8");
      const hits = scan(text).filter((f) => f.ruleId === "env-assignment");
      expect(
        hits.map((f) => f.ruleId),
        file,
      ).toEqual([]);
    }
  });
});

// A threshold tested at one point says nothing about where it sits. Each of
// these was chosen from a measurement, and the pair of cases is what stops it
// drifting: the UTF-16 defect in this release was exactly a number with a case
// on one side of it and none on the other.
describe("each threshold, from both sides", () => {
  // A segment shorter than this is a word by default, because the statistic has
  // nothing to average over. At the length itself it is measured.
  describe("the shortest segment worth measuring", () => {
    // Alternating case, which fails the word test wherever it is applied. Below
    // the length it is not applied, which is the whole of the difference.
    const alternating = (length: number): string =>
      Array.from({ length }, (_, i) => (i % 2 === 0 ? "a" : "B")).join("");

    it("a segment one under the length is taken on trust", () => {
      expect(readsAsWords(alternating(SHORTEST_MEASURABLE_SEGMENT - 1))).toBe(
        true,
      );
    });

    it("a segment at the length is measured", () => {
      expect(readsAsWords(alternating(SHORTEST_MEASURABLE_SEGMENT))).toBe(
        false,
      );
    });
  });

  // Mean word length: how many characters run between one camelCase boundary
  // and the next.
  describe("the mean word length that separates a name from a token", () => {
    // Words of a chosen size, so the mean lands either side of the threshold by
    // construction rather than by luck.
    const wordsOf = (size: number, count: number): string =>
      Array.from(
        { length: count },
        (_, i) => (i === 0 ? "a" : "A") + "b".repeat(size - 1),
      ).join("");

    it("words shorter than the threshold read as a token", () => {
      const value = wordsOf(2, 6);
      expect(value.length / 6).toBeLessThan(MIN_MEAN_WORD_LENGTH);
      expect(readsAsWords(value)).toBe(false);
    });

    it("words longer than the threshold read as a name", () => {
      const value = wordsOf(3, 4);
      expect(value.length / 4).toBeGreaterThan(MIN_MEAN_WORD_LENGTH);
      expect(readsAsWords(value)).toBe(true);
    });

    // And the consequence, which is what the threshold is for.
    it("a dotted name is a reference and a dotted token is not", () => {
      expect(isNotSecretShaped(`config.${wordsOf(3, 4)}`)).toBe(true);
      expect(isNotSecretShaped(`config.${wordsOf(2, 6)}`)).toBe(false);
    });
  });
});

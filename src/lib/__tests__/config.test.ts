import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  compileRule,
  enabledCategoriesFromEnv,
  parseCategories,
  scan,
} from "../rules.ts";
import { VALIDATOR_NAMES } from "../validators.ts";
import { DEFAULT_RULES } from "./rule-fixtures.ts";

// Loading and compiling rules: the schema a rule has to satisfy, what a user
// config may override, and what the registry and the documentation owe each
// other.

// ── parseCategories ───────────────────────────────────────────────────────────

describe("parseCategories", () => {
  it("defaults to all categories when unset", () => {
    expect(parseCategories(undefined)).toEqual(new Set(["secret", "pii"]));
  });

  it("defaults to all categories when empty", () => {
    expect(parseCategories("")).toEqual(new Set(["secret", "pii"]));
  });

  it("parses a single category", () => {
    expect(parseCategories("secret")).toEqual(new Set(["secret"]));
    expect(parseCategories("pii")).toEqual(new Set(["pii"]));
  });

  it("parses a comma-separated list", () => {
    expect(parseCategories("secret,pii")).toEqual(new Set(["secret", "pii"]));
  });

  it("treats 'all' as every category", () => {
    expect(parseCategories("all")).toEqual(new Set(["secret", "pii"]));
    expect(parseCategories("secret,all")).toEqual(new Set(["secret", "pii"]));
  });

  it("is case-insensitive and trims whitespace", () => {
    expect(parseCategories(" Secret , PII ")).toEqual(
      new Set(["secret", "pii"]),
    );
  });

  it("falls back to all when no valid token is present", () => {
    expect(parseCategories("foo,bar")).toEqual(new Set(["secret", "pii"]));
  });
});

// ── enabledCategoriesFromEnv ──────────────────────────────────────────────────

describe("enabledCategoriesFromEnv", () => {
  const ENV_KEY = "SENSITIVE_CANARY_CATEGORIES";
  const original = process.env[ENV_KEY];

  afterEach(() => {
    if (original === undefined) {
      delete process.env[ENV_KEY];
    } else {
      process.env[ENV_KEY] = original;
    }
  });

  it("returns all categories when the env var is unset", () => {
    delete process.env[ENV_KEY];
    expect(enabledCategoriesFromEnv()).toEqual(new Set(["secret", "pii"]));
  });

  it("returns the parsed categories when the env var is set", () => {
    process.env[ENV_KEY] = "pii";
    expect(enabledCategoriesFromEnv()).toEqual(new Set(["pii"]));
  });
});

// Both documents name every validator the registry offers. `phone-jp` was added
// and named in neither, so a user writing a rule could not know it existed.
describe("the documents and the registry agree", () => {
  const docText = (name: string): string =>
    readFileSync(fileURLToPath(new URL(name, import.meta.url)), "utf8");
  const readmeText = docText("../../../README.md");
  const rulesDocText = docText("../../../docs/rules.md");

  it("every validator is named in both documents", () => {
    const undocumented = VALIDATOR_NAMES.filter(
      (name: string) =>
        !readmeText.includes(`\`${name}\``) ||
        !rulesDocText.includes(`\`${name}\``),
    );
    expect(undocumented).toEqual([]);
  });

  // The counts the README puts in its section headings. A rule added to the
  // config and not to the table below it leaves the heading wrong, which is how
  // a reader finds out whether the list they are reading is the list that ships.
  it.each([
    ["Secrets", "secret" as const],
    ["PII", "pii" as const],
  ])("the %s heading states the number that ships", (heading, category) => {
    const shipped = DEFAULT_RULES.filter((r) => r.category === category).length;
    expect(readmeText).toContain(`### ${heading} (${shipped} rules)`);
  });

  // The step the install guide calls not optional. Its fixture has to be one
  // this tool actually blocks — AWS's documented key was the fixture until the
  // `aws-key` validator started reading it as the documentation it is, at which
  // point the guide told every new user their installation was broken.
  it("the install guide verifies with something that is blocked", () => {
    const installText = docText("../../../docs/install.md");
    const fixtures = [...installText.matchAll(/printf -- '([^']+)'/g)].map(
      (m) => (m[1] ?? "").replace(/\\n/g, "\n"),
    );
    expect(fixtures.length).toBeGreaterThan(0);
    for (const fixture of fixtures) {
      expect(scan(fixture), `printf -- '${fixture.trim()}'`).not.toEqual([]);
    }
  });

  // Both documents describe the same tag resolution, and one of them was left
  // behind when it changed. Each has to say which way it goes, and neither may
  // still say the other.
  it.each([
    ["README.md", () => readmeText],
    ["docs/rules.md", () => rulesDocText],
  ])("%s states the tag priority that ships", (_name, text) => {
    expect(text()).toContain("the last one wins");
    expect(text()).not.toContain("appears first wins");
  });

  // A configuration can switch a rule off without warning, in ways somebody
  // would write on purpose. Validation accepts all of them — deliberately, since
  // each is legitimate somewhere — so the documentation is what has to warn, and
  // this is what holds it to that.
  it.each([
    ["entropyThreshold` above 8", { entropyThreshold: 100 }],
    ["flags` containing `y`", { flags: "gy" }],
    ["secretGroup` pointing at a group", { secretGroup: 7 }],
  ])("%s compiles, and the documentation says what it costs", (note, extra) => {
    expect(() =>
      compileRule({
        id: "aws-access-key",
        description: "AWS",
        regex: "\\b(AKIA)[A-Z0-9]{16}\\b",
        category: "secret",
        ...extra,
      }),
    ).not.toThrow();
    expect(rulesDocText).toContain(note);
  });

  it("and that section exists to be found", () => {
    expect(rulesDocText).toContain("goes quiet without saying so");
  });
});

describe("the shipped rules", () => {
  it("are exactly these seventy-six", () => {
    expect(DEFAULT_RULES.map((r) => r.id).sort()).toEqual([
      "anthropic-key",
      "atlassian-token",
      "aws-access-key",
      "azure-sas-key",
      "azure-storage-key",
      "connection-string",
      "databricks-token",
      "digitalocean-pat",
      "discord-webhook",
      "doppler-token",
      "env-assignment",
      "flyio-token",
      "gcp-api-key",
      "generic-secret",
      "github-fine-grained",
      "github-pat",
      "gitlab-pat",
      "google-oauth-secret",
      "grafana-token",
      "groq-key",
      "huggingface-token",
      "jwt",
      "linear-key",
      "mailchimp-key",
      "mailgun-key",
      "mapbox-token",
      "notion-token",
      "npm-token",
      "openai-key",
      "openai-project-key",
      "openai-service-key",
      "openrouter-key",
      "perplexity-key",
      "pii-brn-kr",
      "pii-codice-fiscale-it",
      "pii-credit-card",
      "pii-dni-nie-es",
      "pii-email",
      "pii-ipv4-public",
      "pii-ipv6",
      "pii-mynumber-jp",
      "pii-nir-fr",
      "pii-phone-cn",
      "pii-phone-de",
      "pii-phone-es",
      "pii-phone-fr",
      "pii-phone-it",
      "pii-phone-jp",
      "pii-phone-kr",
      "pii-phone-us",
      "pii-postal-cn",
      "pii-postal-code",
      "pii-postal-jp",
      "pii-resident-id-cn",
      "pii-rrn-kr",
      "pii-ssn",
      "pii-steuer-id-de",
      "postman-key",
      "private-key",
      "private-key-base64",
      "replicate-token",
      "sendgrid-key",
      "sentry-org-token",
      "sentry-user-token",
      "shopify-token",
      "slack-token",
      "slack-webhook",
      "square-access-token",
      "stripe-restricted-key",
      "stripe-secret-key",
      "supabase-key",
      "telegram-bot-token",
      "twilio-sid",
      "url-basic-auth",
      "vault-token",
      "xai-key",
    ]);
  });

  it("are split as the README says: 52 secret, 24 PII", () => {
    const byCategory: Record<string, number> = {};
    for (const rule of DEFAULT_RULES) {
      byCategory[rule.category] = (byCategory[rule.category] ?? 0) + 1;
    }
    expect(byCategory).toEqual({ secret: 52, pii: 24 });
  });

  it("each declare the fields the loader needs", () => {
    for (const rule of DEFAULT_RULES) {
      expect(typeof rule.id, rule.id).toBe("string");
      expect(typeof rule.description, rule.id).toBe("string");
      expect(["secret", "pii"], rule.id).toContain(rule.category);
      expect(() => new RegExp(rule.regex), rule.id).not.toThrow();
    }
  });
});

// ── compileRule ───────────────────────────────────────────────────────────────

describe("compileRule", () => {
  it("compiles regex source with default g flag", () => {
    const rule = compileRule({
      id: "test",
      description: "Test",
      regex: "\\d{4}",
      category: "pii",
    });
    expect(rule.regex.flags).toBe("g");
    expect("1234".match(rule.regex)).not.toBeNull();
  });

  it("compiles with custom flags", () => {
    const rule = compileRule({
      id: "test",
      description: "Test",
      regex: "\\d{4}",
      flags: "gi",
      category: "pii",
    });
    expect(rule.regex.flags).toBe("gi");
  });

  it("resolves a validator by name", () => {
    const rule = compileRule({
      id: "test",
      description: "Test",
      regex: "\\d{12}",
      category: "pii",
      validate: "mynumber-jp",
    });
    expect(rule.validate).toBeDefined();
    expect(rule.validate?.("123456789018")).toBe(true);
  });

  it("preserves secretGroup and entropyThreshold", () => {
    const rule = compileRule({
      id: "test",
      description: "Test",
      regex: "key=(\\S+)",
      category: "secret",
      secretGroup: 1,
      entropyThreshold: 3.5,
    });
    expect(rule.secretGroup).toBe(1);
    expect(rule.entropyThreshold).toBe(3.5);
  });
});

// ── compileRule: schema validation ───────────────────────────────────────────

describe("compileRule — schema validation", () => {
  const valid = {
    id: "test",
    description: "Test",
    regex: "\\d+",
    category: "pii" as const,
  };

  it("rejects missing id", () => {
    expect(() => compileRule({ ...valid, id: "" } as never)).toThrow('"id"');
  });

  it("rejects missing description", () => {
    expect(() => compileRule({ ...valid, description: "" } as never)).toThrow(
      '"description"',
    );
  });

  it("rejects missing regex", () => {
    expect(() => compileRule({ ...valid, regex: "" } as never)).toThrow(
      '"regex"',
    );
  });

  it("rejects invalid category", () => {
    expect(() => compileRule({ ...valid, category: "other" as never })).toThrow(
      '"category"',
    );
  });

  it("rejects non-integer secretGroup", () => {
    expect(() => compileRule({ ...valid, secretGroup: 1.5 } as never)).toThrow(
      '"secretGroup"',
    );
  });

  it("rejects negative entropyThreshold", () => {
    expect(() =>
      compileRule({ ...valid, entropyThreshold: -1 } as never),
    ).toThrow('"entropyThreshold"');
  });

  it("rejects contextWords with empty string", () => {
    expect(() =>
      compileRule({ ...valid, contextWords: ["ok", ""] } as never),
    ).toThrow('"contextWords"');
  });

  it("rejects non-integer contextWindow", () => {
    expect(() => compileRule({ ...valid, contextWindow: 0 } as never)).toThrow(
      '"contextWindow"',
    );
  });

  it("rejects requireContext without contextWords", () => {
    expect(() =>
      compileRule({ ...valid, requireContext: true } as never),
    ).toThrow("requireContext");
  });

  it("rejects requireContext with empty contextWords array", () => {
    expect(() =>
      compileRule({
        ...valid,
        requireContext: true,
        contextWords: [],
      } as never),
    ).toThrow("requireContext");
  });
});

// ── User config (custom rules) ────────────────────────────────────────────────

describe("user config — custom rules", () => {
  const ENV_KEY = "SENSITIVE_CANARY_CONFIG";
  const envBackup = process.env[ENV_KEY];

  afterEach(() => {
    if (envBackup === undefined) {
      delete process.env[ENV_KEY];
    } else {
      process.env[ENV_KEY] = envBackup;
    }
    vi.resetModules();
  });

  it("adds a custom rule from a user config file", async () => {
    const { mkdtempSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");

    const dir = mkdtempSync(join(tmpdir(), "canary-"));
    writeFileSync(
      join(dir, "config.json"),
      JSON.stringify({
        rules: [
          {
            id: "custom-token",
            description: "Custom Service Token",
            regex: "MYSVC-[A-Za-z0-9]{20}",
            category: "secret",
          },
        ],
      }),
    );

    process.env[ENV_KEY] = join(dir, "config.json");
    vi.resetModules();

    const { RULES, scan } = await import("../rules.ts");
    expect(RULES.some((r) => r.id === "custom-token")).toBe(true);

    const findings = scan("token: MYSVC-abcdefghijklmnopqrst");
    expect(findings.some((f) => f.ruleId === "custom-token")).toBe(true);
  });

  it("overrides a built-in rule by id", async () => {
    const { mkdtempSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");

    const dir = mkdtempSync(join(tmpdir(), "canary-"));
    writeFileSync(
      join(dir, "config.json"),
      JSON.stringify({
        rules: [
          {
            id: "pii-email",
            description: "Replaced Email Rule",
            regex: "NEVERMATCH[a-z]+",
            category: "pii",
          },
        ],
      }),
    );

    process.env[ENV_KEY] = join(dir, "config.json");
    vi.resetModules();

    const { RULES, scan } = await import("../rules.ts");
    const emailRules = RULES.filter((r) => r.id === "pii-email");
    expect(emailRules).toHaveLength(1);
    expect(emailRules[0]?.description).toBe("Replaced Email Rule");

    const findings = scan("contact: ada@analytical-engines.org");
    expect(findings.some((f) => f.ruleId === "pii-email")).toBe(false);
  });

  it("de-duplicates duplicate user rule ids (last definition wins)", async () => {
    const { mkdtempSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");

    const dir = mkdtempSync(join(tmpdir(), "canary-"));
    writeFileSync(
      join(dir, "config.json"),
      JSON.stringify({
        rules: [
          {
            id: "custom-token",
            description: "First Definition",
            regex: "MYSVC-[A-Za-z0-9]{20}",
            category: "secret",
          },
          {
            id: "custom-token",
            description: "Last Definition",
            regex: "MYSVC2-[A-Za-z0-9]{20}",
            category: "secret",
          },
        ],
      }),
    );

    process.env[ENV_KEY] = join(dir, "config.json");
    vi.resetModules();

    const { RULES, scan } = await import("../rules.ts");
    const dupes = RULES.filter((r) => r.id === "custom-token");
    expect(dupes).toHaveLength(1);
    expect(dupes[0]?.description).toBe("Last Definition");

    // Only the last regex is active, and a match produces a single finding.
    // Filtered by rule id: the built-in `env-assignment` reads `token: <value>`
    // as an assignment of its own, which is a finding about the text rather than
    // about which custom regex is loaded.
    expect(
      scan("token: MYSVC-abcdefghijklmnopqrst").filter(
        (f) => f.ruleId === "custom-token",
      ),
    ).toHaveLength(0);
    const findings = scan("token: MYSVC2-abcdefghijklmnopqrst");
    expect(findings.filter((f) => f.ruleId === "custom-token")).toHaveLength(1);
  });

  it("respects a custom contextWindow", async () => {
    const { mkdtempSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");

    const dir = mkdtempSync(join(tmpdir(), "canary-"));
    writeFileSync(
      join(dir, "config.json"),
      JSON.stringify({
        contextWindow: 1,
        rules: [],
      }),
    );

    process.env[ENV_KEY] = join(dir, "config.json");
    vi.resetModules();

    const { getDefaultContextWindow: getWindow } = await import("../rules.ts");
    expect(getWindow()).toBe(1);
  });

  it("skips rules with invalid regex", async () => {
    const { mkdtempSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");

    const dir = mkdtempSync(join(tmpdir(), "canary-"));
    writeFileSync(
      join(dir, "config.json"),
      JSON.stringify({
        rules: [
          {
            id: "bad-regex",
            description: "Bad",
            regex: "[invalid(",
            category: "secret",
          },
          {
            id: "good-regex",
            description: "Good",
            regex: "GOODKEY-\\d+",
            category: "secret",
          },
        ],
      }),
    );

    process.env[ENV_KEY] = join(dir, "config.json");
    vi.resetModules();

    const { RULES } = await import("../rules.ts");
    expect(RULES.some((r) => r.id === "bad-regex")).toBe(false);
    expect(RULES.some((r) => r.id === "good-regex")).toBe(true);
  });

  it("skips null or non-object rule entries without crashing", async () => {
    const { mkdtempSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");

    const dir = mkdtempSync(join(tmpdir(), "canary-"));
    writeFileSync(
      join(dir, "config.json"),
      JSON.stringify({
        rules: [
          null,
          {
            id: "good-rule",
            description: "Good",
            regex: "GOODKEY-\\d+",
            category: "secret",
          },
        ],
      }),
    );

    process.env[ENV_KEY] = join(dir, "config.json");
    vi.resetModules();

    const { RULES } = await import("../rules.ts");
    expect(RULES.some((r) => r.id === "good-rule")).toBe(true);
  });

  it("ignores a non-array rules field without crashing", async () => {
    const { mkdtempSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");

    const dir = mkdtempSync(join(tmpdir(), "canary-"));
    writeFileSync(
      join(dir, "config.json"),
      JSON.stringify({ rules: { id: "not-an-array" } }),
    );

    process.env[ENV_KEY] = join(dir, "config.json");
    vi.resetModules();

    // Built-in defaults still load (spot-check a well-known rule).
    const { RULES } = await import("../rules.ts");
    expect(RULES.some((r) => r.id === "pii-email")).toBe(true);
  });
});

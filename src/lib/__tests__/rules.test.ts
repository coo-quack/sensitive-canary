import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  beginScanBudget,
  compileRule,
  enabledCategoriesFromEnv,
  entropy,
  isNotSecretShaped,
  isRealAwsKey,
  isReservedIpv4,
  isReservedIpv6,
  luhn,
  parseCategories,
  type RuleConfig,
  redact,
  ScanBudgetExceeded,
  scan,
  VALIDATOR_NAMES,
  validateChineseID,
  validateCodiceFiscale,
  validateFrenchNIR,
  validateGermanIdNr,
  validateKoreanBRN,
  validateKoreanRRN,
  validateMyNumber,
  validateSpanishNIF,
} from "../rules.ts";

// Not AWS's documented `…EXAMPLE` key, which the `aws-key`
// validator reads as documentation rather than a credential.
const AWS_KEY = ["AKIA", "3QF7TZ9KLMN2", "PQRS"].join("");

// The shipped rules, read from disk the way rules.ts reads them, so the cases
// generated below walk what is released rather than a list kept in step by hand.
const DEFAULT_RULES: RuleConfig[] = (
  JSON.parse(
    readFileSync(
      join(
        dirname(fileURLToPath(import.meta.url)),
        "..",
        "default-config.json",
      ),
      "utf-8",
    ),
  ) as { rules: RuleConfig[] }
).rules;

// ── luhn ──────────────────────────────────────────────────────────────────────

describe("luhn", () => {
  it("passes a valid Visa number", () => {
    expect(luhn("4532015112830366")).toBe(true);
  });

  it("passes a valid Mastercard number", () => {
    expect(luhn("5500005555555559")).toBe(true);
  });

  it("fails an invalid number", () => {
    expect(luhn("1234567890123456")).toBe(false);
  });

  it("ignores spaces and dashes", () => {
    expect(luhn("4532 0151 1283 0366")).toBe(true);
    expect(luhn("4532-0151-1283-0366")).toBe(true);
  });

  it("fails empty or digit-less input", () => {
    expect(luhn("")).toBe(false);
    expect(luhn("no-digits-here")).toBe(false);
  });
});

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

// ── redact ────────────────────────────────────────────────────────────────────

describe("redact", () => {
  it("masks a short value completely", () => {
    expect(redact("abc")).toBe("****");
    expect(redact("1234567")).toBe("****");
  });

  it("handles empty string", () => {
    expect(redact("")).toBe("****");
  });

  // Whatever this returns is written to stderr, which is where Claude reads it,
  // so it reaches the API the block exists to keep the value from. A quarter of
  // the value, capped at four characters per end.
  it.each([
    [9, 2],
    [16, 4],
    [24, 6],
    [32, 8],
    [64, 8],
  ])("a %i-character value returns at most %i of it", (length, atMost) => {
    const value = "abcdefghijklmnopqrstuvwxyz0123456789"
      .repeat(2)
      .slice(0, length);
    const shown = redact(value);
    expect(shown.replace(/\*/g, "")).toHaveLength(atMost);
  });

  it("never returns more than a quarter of the value", () => {
    for (let length = 1; length <= 200; length++) {
      const value = "a".repeat(length);
      const kept = redact(value).replace(/\*/g, "").length;
      expect(kept / length, `${length} characters`).toBeLessThanOrEqual(0.25);
    }
  });

  // Slicing by code unit cuts a surrogate pair in half, and what reaches the
  // terminal is a lone surrogate: not the character, and not a redaction of it
  // either. Counting by code point also keeps the quarter honest, since one
  // emoji is one character and not two.
  it("does not split a character in half", () => {
    const lone =
      /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
    for (let count = 1; count <= 40; count++) {
      const value = "🔑".repeat(count);
      expect(redact(value), `${count} astral characters`).not.toMatch(lone);
    }
  });

  it("counts an astral character as one", () => {
    expect(redact("🔑".repeat(8))).toBe("🔑****🔑");
  });

  it("shows the ends, so two findings can be told apart", () => {
    expect(redact("AKIAQQQQQQQQQQQQQAAA")).toBe("AK****AA");
    expect(redact("AKIAQQQQQQQQQQQQQZZZ")).toBe("AK****ZZ");
  });
});

// ── scan: secrets ─────────────────────────────────────────────────────────────

describe("scan — secrets", () => {
  it("detects an AWS Access Key ID", () => {
    const findings = scan(`key=${AWS_KEY}`);
    expect(findings.some((f) => f.ruleId === "aws-access-key")).toBe(true);
  });

  it("detects a GCP API key", () => {
    const findings = scan(`key=AIzaSyC${"A".repeat(32)}`);
    expect(findings.some((f) => f.ruleId === "gcp-api-key")).toBe(true);
  });

  it("does not flag a string starting with AIza but too short", () => {
    const findings = scan("AIzaSyC_short");
    expect(findings.some((f) => f.ruleId === "gcp-api-key")).toBe(false);
  });

  it("detects an npm access token", () => {
    const findings = scan(`npm_${"A".repeat(36)}`);
    expect(findings.some((f) => f.ruleId === "npm-token")).toBe(true);
  });

  it("does not flag npm_ with insufficient length", () => {
    const findings = scan("npm_shorttoken");
    expect(findings.some((f) => f.ruleId === "npm-token")).toBe(false);
  });

  it("detects a PEM private key header (RSA)", () => {
    const findings = scan("-----BEGIN RSA PRIVATE KEY-----");
    expect(findings.some((f) => f.ruleId === "private-key")).toBe(true);
  });

  it("detects an OpenSSH private key header via private-key rule", () => {
    const findings = scan("-----BEGIN OPENSSH PRIVATE KEY-----");
    expect(findings.some((f) => f.ruleId === "private-key")).toBe(true);
  });

  it("detects a GitHub PAT", () => {
    const findings = scan(`token=ghp_${"A".repeat(36)}`);
    expect(findings.some((f) => f.ruleId === "github-pat")).toBe(true);
  });

  it("detects a GitHub fine-grained token", () => {
    const findings = scan(`github_pat_${"A".repeat(82)}`);
    expect(findings.some((f) => f.ruleId === "github-fine-grained")).toBe(true);
  });

  it("detects a GitLab PAT", () => {
    const findings = scan(`token=glpat-${"A".repeat(20)}`);
    expect(findings.some((f) => f.ruleId === "gitlab-pat")).toBe(true);
  });

  it("detects a Slack token", () => {
    const findings = scan("xoxb-123456789012-ABCDEFGHIJ");
    expect(findings.some((f) => f.ruleId === "slack-token")).toBe(true);
  });

  it("detects a Slack webhook URL", () => {
    const findings = scan(
      `https://hooks.slack.com/services/TABCDEFGH/BABCDEFGHIJ/${"A".repeat(24)}`,
    );
    expect(findings.some((f) => f.ruleId === "slack-webhook")).toBe(true);
  });

  it("detects a Discord webhook URL", () => {
    const findings = scan(
      `https://discord.com/api/webhooks/123456789012345678/${"A".repeat(68)}`,
    );
    expect(findings.some((f) => f.ruleId === "discord-webhook")).toBe(true);
  });

  it("detects a Telegram bot token", () => {
    const findings = scan(`12345678:AA${"A".repeat(33)}`);
    expect(findings.some((f) => f.ruleId === "telegram-bot-token")).toBe(true);
  });

  it("detects a Twilio Account SID", () => {
    const findings = scan(`AC${"a".repeat(32)}`);
    expect(findings.some((f) => f.ruleId === "twilio-sid")).toBe(true);
  });

  it("detects a SendGrid API key", () => {
    const findings = scan(`SG.${"A".repeat(22)}.${"B".repeat(43)}`);
    expect(findings.some((f) => f.ruleId === "sendgrid-key")).toBe(true);
  });

  it("detects a Mailgun API key", () => {
    const findings = scan(`key-${"a".repeat(32)}`);
    expect(findings.some((f) => f.ruleId === "mailgun-key")).toBe(true);
  });

  it("detects a Mailchimp API key", () => {
    const findings = scan(`${"a".repeat(32)}-us1`);
    expect(findings.some((f) => f.ruleId === "mailchimp-key")).toBe(true);
  });

  it("detects a Stripe secret key", () => {
    const findings = scan(`sk_live_${"A".repeat(24)}`);
    expect(findings.some((f) => f.ruleId === "stripe-secret-key")).toBe(true);
  });

  it("detects a Stripe restricted key", () => {
    const findings = scan(`rk_test_${"A".repeat(24)}`);
    expect(findings.some((f) => f.ruleId === "stripe-restricted-key")).toBe(
      true,
    );
  });

  it("detects an OpenAI legacy API key", () => {
    const findings = scan(`sk-${"A".repeat(48)}`);
    expect(findings.some((f) => f.ruleId === "openai-key")).toBe(true);
  });

  it("does not flag sk-proj-* as openai-key (legacy)", () => {
    const findings = scan("sk-proj-Xk9mP2qR7vL4nW1sYj3cBz8dEf5gHiKoNpQuTxMn");
    expect(findings.some((f) => f.ruleId === "openai-key")).toBe(false);
  });

  it("does not flag sk-ant-* as openai-key (legacy)", () => {
    const findings = scan(`sk-ant-${"A".repeat(95)}`);
    expect(findings.some((f) => f.ruleId === "openai-key")).toBe(false);
  });

  it("detects an OpenAI project API key", () => {
    const findings = scan("sk-proj-Xk9mP2qR7vL4nW1sYj3cBz8dEf5gHiKoNpQuTxMn");
    expect(findings.some((f) => f.ruleId === "openai-project-key")).toBe(true);
  });

  it("detects an Anthropic API key", () => {
    const findings = scan(`sk-ant-${"A".repeat(95)}`);
    expect(findings.some((f) => f.ruleId === "anthropic-key")).toBe(true);
  });

  it("detects a JWT", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const findings = scan(jwt);
    expect(findings.some((f) => f.ruleId === "jwt")).toBe(true);
  });

  it("detects a generic API key assignment with sufficient entropy", () => {
    const findings = scan("api_key=Xk9mP2qR7vL4nW1sYj3cBz8dEf5g");
    expect(findings.some((f) => f.ruleId === "generic-secret")).toBe(true);
  });

  it("does not flag a low-entropy generic API key value", () => {
    const findings = scan("api_key=placeholder");
    expect(findings.some((f) => f.ruleId === "generic-secret")).toBe(false);
  });

  it("detects a database connection string with credentials", () => {
    const findings = scan("postgres://admin:s3cr3tP4ss@db.corp.internal/mydb");
    expect(findings.some((f) => f.ruleId === "connection-string")).toBe(true);
  });

  // `user:password@localhost` is what every database README prints. Reading it
  // as a credential is what made a committed template unreadable.
  it("does not detect the connection string every README prints", () => {
    const findings = scan("postgres://user:password@localhost/mydb");
    expect(findings.some((f) => f.ruleId === "connection-string")).toBe(false);
  });

  it("detects an .env style assignment with sufficient entropy", () => {
    const findings = scan("DATABASE_PASSWORD=Xk9mP2qR7vL4nW1s");
    expect(findings.some((f) => f.ruleId === "env-assignment")).toBe(true);
  });

  it("does not flag a low-entropy .env value", () => {
    const findings = scan("DATABASE_PASSWORD=password");
    expect(findings.some((f) => f.ruleId === "env-assignment")).toBe(false);
  });

  it("returns no findings for clean text", () => {
    expect(scan("hello world, nothing sensitive here")).toHaveLength(0);
  });
});

// ── scan: expanded secrets ───────────────────────────────────────────────────

describe("scan — expanded secrets (AI, cloud, SaaS)", () => {
  it("detects a Replicate token", () => {
    const findings = scan(`r8_${"A".repeat(37)}`);
    expect(findings.some((f) => f.ruleId === "replicate-token")).toBe(true);
  });

  it("detects a Hugging Face token", () => {
    const findings = scan(`hf_${"a".repeat(34)}`);
    expect(findings.some((f) => f.ruleId === "huggingface-token")).toBe(true);
  });

  it("detects a Groq API key", () => {
    const findings = scan(`gsk_${"A".repeat(52)}`);
    expect(findings.some((f) => f.ruleId === "groq-key")).toBe(true);
  });

  it("detects an OpenRouter API key", () => {
    const findings = scan(`sk-or-v1-${"a".repeat(64)}`);
    expect(findings.some((f) => f.ruleId === "openrouter-key")).toBe(true);
  });

  it("detects an xAI (Grok) API key", () => {
    const findings = scan(`xai-${"A".repeat(80)}`);
    expect(findings.some((f) => f.ruleId === "xai-key")).toBe(true);
  });

  it("detects a Perplexity API key", () => {
    const findings = scan(`pplx-${"a".repeat(48)}`);
    expect(findings.some((f) => f.ruleId === "perplexity-key")).toBe(true);
  });

  it("detects a DigitalOcean PAT", () => {
    const findings = scan(`dop_v1_${"a".repeat(64)}`);
    expect(findings.some((f) => f.ruleId === "digitalocean-pat")).toBe(true);
  });

  it("detects a Square access token", () => {
    const findings = scan(`EAAA${"A".repeat(60)}`);
    expect(findings.some((f) => f.ruleId === "square-access-token")).toBe(true);
  });

  it("detects a Sentry user auth token", () => {
    const findings = scan(`sntryu_${"a".repeat(64)}`);
    expect(findings.some((f) => f.ruleId === "sentry-user-token")).toBe(true);
  });

  it("detects an Atlassian API token", () => {
    const findings = scan(`ATATT3${"A".repeat(180)}`);
    expect(findings.some((f) => f.ruleId === "atlassian-token")).toBe(true);
  });

  it("detects a Linear API key", () => {
    const findings = scan(`lin_api_${"a".repeat(40)}`);
    expect(findings.some((f) => f.ruleId === "linear-key")).toBe(true);
  });

  it("detects a Postman API key", () => {
    const findings = scan(`PMAK-${"a".repeat(24)}-${"b".repeat(34)}`);
    expect(findings.some((f) => f.ruleId === "postman-key")).toBe(true);
  });

  it("detects a Supabase PAT", () => {
    const findings = scan(`sbp_${"a".repeat(40)}`);
    expect(findings.some((f) => f.ruleId === "supabase-key")).toBe(true);
  });
});

// ── scan: PII ─────────────────────────────────────────────────────────────────

describe("scan — PII", () => {
  it("detects an email address", () => {
    const findings = scan("contact: ada@analytical-engines.org");
    expect(findings.some((f) => f.ruleId === "pii-email")).toBe(true);
  });

  it("detects a valid credit card number — no separators", () => {
    const findings = scan("card: 4532015112830366");
    expect(findings.some((f) => f.ruleId === "pii-credit-card")).toBe(true);
  });

  it("detects a valid credit card number — space separated", () => {
    const findings = scan("card: 4532 0151 1283 0366");
    expect(findings.some((f) => f.ruleId === "pii-credit-card")).toBe(true);
  });

  it("detects a valid credit card number — hyphen separated", () => {
    const findings = scan("card: 4532-0151-1283-0366");
    expect(findings.some((f) => f.ruleId === "pii-credit-card")).toBe(true);
  });

  it("does not flag an invalid credit card number", () => {
    const findings = scan("card: 4111111111111112");
    expect(findings.some((f) => f.ruleId === "pii-credit-card")).toBe(false);
  });

  it("detects a US SSN", () => {
    const findings = scan("ssn: 123-45-6789");
    expect(findings.some((f) => f.ruleId === "pii-ssn")).toBe(true);
  });

  it("does not flag an SSN with area 000", () => {
    expect(scan("ssn: 000-45-6789").some((f) => f.ruleId === "pii-ssn")).toBe(
      false,
    );
  });

  it("does not flag an SSN with area 666", () => {
    expect(scan("ssn: 666-45-6789").some((f) => f.ruleId === "pii-ssn")).toBe(
      false,
    );
  });

  it("does not flag an SSN with area 9xx", () => {
    expect(scan("ssn: 900-45-6789").some((f) => f.ruleId === "pii-ssn")).toBe(
      false,
    );
  });

  it("does not flag an SSN with group 00", () => {
    expect(scan("ssn: 123-00-6789").some((f) => f.ruleId === "pii-ssn")).toBe(
      false,
    );
  });

  it("does not flag an SSN with serial 0000", () => {
    expect(scan("ssn: 123-45-0000").some((f) => f.ruleId === "pii-ssn")).toBe(
      false,
    );
  });

  it("detects a US phone number", () => {
    const findings = scan("call: (555) 123-4567");
    expect(findings.some((f) => f.ruleId === "pii-phone-us")).toBe(true);
  });

  it("detects a Japanese phone number", () => {
    const findings = scan("tel: 03-1234-5678");
    expect(findings.some((f) => f.ruleId === "pii-phone-jp")).toBe(true);
  });

  it("detects a Japanese postal code with 〒 prefix", () => {
    const findings = scan("address: 〒150-0001");
    expect(findings.some((f) => f.ruleId === "pii-postal-jp")).toBe(true);
  });

  it("does not flag a postal-like number without 〒", () => {
    const findings = scan("zip: 150-0001");
    expect(findings.some((f) => f.ruleId === "pii-postal-jp")).toBe(false);
  });

  // A private address is not personal data. It is non-routable, it identifies
  // nothing outside the network it belongs to, and it appears in nearly every
  // inventory, manifest and ssh config a developer opens — which is where the
  // rule spent its time. Public addresses are still gated on a nearby label.
  it.each([
    "client 192.168.1.100 connected",
    "client 10.0.0.1 connected",
    "visitor 172.16.0.1 seen",
    "visitor 172.31.255.255 seen",
    "192.168.1.50",
    "ip=10.1.2.3",
    "X-Forwarded-For: 10.0.0.5",
    "remote_addr=10.0.0.5",
    "ping 10.0.0.1",
    "curl http://10.0.0.5:8080/health",
    "redis-cli -h 10.0.0.30",
    "ansible_host: 10.0.0.5",
  ])("%s is not PII", (text) => {
    expect(scan(text).filter((f) => f.ruleId.startsWith("pii-ipv4"))).toEqual(
      [],
    );
  });

  // The public rule is untouched by that, in both directions.
  it("a public address with a label is still PII", () => {
    expect(
      scan("the client IP address is 8.8.8.8").some(
        (f) => f.ruleId === "pii-ipv4-public",
      ),
    ).toBe(true);
  });

  it("a public address without a label is not", () => {
    expect(
      scan("server: 8.8.8.8").some((f) => f.ruleId === "pii-ipv4-public"),
    ).toBe(false);
  });
});

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

// ── scan: category filter ─────────────────────────────────────────────────────

describe("scan — category filter", () => {
  const text = `key=${AWS_KEY} card: 4532015112830366`;

  it("scans all categories by default", () => {
    const findings = scan(text);
    expect(findings.some((f) => f.ruleId === "aws-access-key")).toBe(true);
    expect(findings.some((f) => f.ruleId === "pii-credit-card")).toBe(true);
  });

  it("scans only secrets when limited to the secret category", () => {
    const findings = scan(text, new Set(["secret"]));
    expect(findings.some((f) => f.ruleId === "aws-access-key")).toBe(true);
    expect(findings.some((f) => f.ruleId === "pii-credit-card")).toBe(false);
  });

  it("scans only PII when limited to the pii category", () => {
    const findings = scan(text, new Set(["pii"]));
    expect(findings.some((f) => f.ruleId === "aws-access-key")).toBe(false);
    expect(findings.some((f) => f.ruleId === "pii-credit-card")).toBe(true);
  });

  it("returns nothing when no categories are enabled", () => {
    expect(scan(text, new Set())).toEqual([]);
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

// ── National ID checksum validators ───────────────────────────────────────────

describe("validateMyNumber", () => {
  it("passes a valid My Number", () => {
    expect(validateMyNumber("123456789018")).toBe(true);
  });

  it("fails an incorrect check digit", () => {
    expect(validateMyNumber("123456789019")).toBe(false);
  });

  it("fails a wrong length", () => {
    expect(validateMyNumber("12345678901")).toBe(false);
    expect(validateMyNumber("1234567890123")).toBe(false);
  });
});

describe("validateFrenchNIR", () => {
  it("passes a valid NIR", () => {
    expect(validateFrenchNIR("123456789012311")).toBe(true);
  });

  it("fails an incorrect check key", () => {
    expect(validateFrenchNIR("123456789012399")).toBe(false);
  });

  it("fails a wrong length", () => {
    expect(validateFrenchNIR("1234567890123")).toBe(false);
  });

  it("passes a valid NIR with Corsica 2A", () => {
    expect(validateFrenchNIR("188022A12345632")).toBe(true);
  });

  it("passes a valid NIR with Corsica 2B", () => {
    expect(validateFrenchNIR("188022B12345659")).toBe(true);
  });
});

describe("validateCodiceFiscale", () => {
  it("passes a valid Codice Fiscale", () => {
    expect(validateCodiceFiscale("RSSMRA85M01H501Q")).toBe(true);
  });

  it("fails an incorrect control character", () => {
    expect(validateCodiceFiscale("RSSMRA85M01H501Z")).toBe(false);
  });

  it("fails a wrong shape", () => {
    expect(validateCodiceFiscale("RSSMRA85M01H501")).toBe(false);
  });
});

describe("validateGermanIdNr", () => {
  it("passes a valid Steuer-IdNr.", () => {
    expect(validateGermanIdNr("12345678903")).toBe(true);
  });

  it("fails an incorrect check digit", () => {
    expect(validateGermanIdNr("12345678900")).toBe(false);
  });

  it("fails when the first digit is 0", () => {
    expect(validateGermanIdNr("02345678903")).toBe(false);
  });
});

describe("validateSpanishNIF", () => {
  it("passes a valid DNI", () => {
    expect(validateSpanishNIF("12345678Z")).toBe(true);
  });

  it("fails an incorrect DNI control letter", () => {
    expect(validateSpanishNIF("12345678Y")).toBe(false);
  });

  it("passes a valid NIE", () => {
    expect(validateSpanishNIF("X1234567L")).toBe(true);
  });

  it("fails an incorrect NIE control letter", () => {
    expect(validateSpanishNIF("X1234567M")).toBe(false);
  });
});

// ── scan: national ID numbers ─────────────────────────────────────────────────

describe("scan — national ID numbers", () => {
  it("detects a valid My Number", () => {
    const findings = scan("number: 123456789018");
    expect(findings.some((f) => f.ruleId === "pii-mynumber-jp")).toBe(true);
  });

  it("does not flag a My Number with a bad check digit", () => {
    const findings = scan("number: 123456789019");
    expect(findings.some((f) => f.ruleId === "pii-mynumber-jp")).toBe(false);
  });

  it("detects a valid French NIR", () => {
    const findings = scan("secu: 1850175056001 49");
    expect(findings.some((f) => f.ruleId === "pii-nir-fr")).toBe(true);
  });

  it("detects a valid Italian Codice Fiscale", () => {
    const findings = scan("cf: RSSMRA85M01H501Q");
    expect(findings.some((f) => f.ruleId === "pii-codice-fiscale-it")).toBe(
      true,
    );
  });

  it("detects a valid German Steuer-IdNr.", () => {
    const findings = scan("idnr: 12345678903");
    expect(findings.some((f) => f.ruleId === "pii-steuer-id-de")).toBe(true);
  });

  it("detects a valid Spanish DNI", () => {
    const findings = scan("dni: 12345678Z");
    expect(findings.some((f) => f.ruleId === "pii-dni-nie-es")).toBe(true);
  });

  it("detects a valid Spanish NIE", () => {
    const findings = scan("nie: X1234567L");
    expect(findings.some((f) => f.ruleId === "pii-dni-nie-es")).toBe(true);
  });

  it("does not flag a French NIR with a bad check key", () => {
    const findings = scan("secu: 1850175056001 99");
    expect(findings.some((f) => f.ruleId === "pii-nir-fr")).toBe(false);
  });

  it("does not flag a Codice Fiscale with a bad control character", () => {
    const findings = scan("cf: RSSMRA85M01H501Z");
    expect(findings.some((f) => f.ruleId === "pii-codice-fiscale-it")).toBe(
      false,
    );
  });

  it("does not flag a Steuer-IdNr. with a bad check digit", () => {
    const findings = scan("idnr: 12345678900");
    expect(findings.some((f) => f.ruleId === "pii-steuer-id-de")).toBe(false);
  });

  it("does not flag a DNI with a bad control letter", () => {
    const findings = scan("dni: 12345678Y");
    expect(findings.some((f) => f.ruleId === "pii-dni-nie-es")).toBe(false);
  });
});

// ── scan: FIGS phone numbers (context-gated) ──────────────────────────────────

describe("scan — FIGS phone numbers", () => {
  it("detects a French phone number with context", () => {
    const findings = scan("tél: 01 23 45 67 89");
    expect(findings.some((f) => f.ruleId === "pii-phone-fr")).toBe(true);
  });

  it("does not flag a bare French number without context", () => {
    const findings = scan("ref 01 23 45 67 89 done");
    expect(findings.some((f) => f.ruleId === "pii-phone-fr")).toBe(false);
  });

  it("detects an Italian phone number with context", () => {
    const findings = scan("telefono: 0212345678");
    expect(findings.some((f) => f.ruleId === "pii-phone-it")).toBe(true);
  });

  it("does not flag a bare Italian number without context", () => {
    const findings = scan("id 0212345678 end");
    expect(findings.some((f) => f.ruleId === "pii-phone-it")).toBe(false);
  });

  it("detects a German phone number with context", () => {
    const findings = scan("Telefon: 0301234567");
    expect(findings.some((f) => f.ruleId === "pii-phone-de")).toBe(true);
  });

  it("does not flag a bare German number without context", () => {
    const findings = scan("code 0301234567 end");
    expect(findings.some((f) => f.ruleId === "pii-phone-de")).toBe(false);
  });

  it("detects a Spanish phone number with context", () => {
    const findings = scan("teléfono: 612345678");
    expect(findings.some((f) => f.ruleId === "pii-phone-es")).toBe(true);
  });

  it("does not flag a bare Spanish number without context", () => {
    const findings = scan("num 612345678 end");
    expect(findings.some((f) => f.ruleId === "pii-phone-es")).toBe(false);
  });
});

// ── scan: postal code (context-gated) ─────────────────────────────────────────

describe("scan — postal code", () => {
  it("detects a US ZIP with context", () => {
    const findings = scan("ZIP: 90210");
    expect(findings.some((f) => f.ruleId === "pii-postal-code")).toBe(true);
  });

  it("detects a US ZIP+4 with context", () => {
    const findings = scan("postal: 90210-1234");
    expect(findings.some((f) => f.ruleId === "pii-postal-code")).toBe(true);
  });

  it("detects a German PLZ with context", () => {
    const findings = scan("PLZ: 10115");
    expect(findings.some((f) => f.ruleId === "pii-postal-code")).toBe(true);
  });

  it("detects an Italian CAP with context", () => {
    const findings = scan("CAP: 00184");
    expect(findings.some((f) => f.ruleId === "pii-postal-code")).toBe(true);
  });

  it("does not flag a bare 5-digit number", () => {
    const findings = scan("count: 12345 items");
    expect(findings.some((f) => f.ruleId === "pii-postal-code")).toBe(false);
  });

  it("does not flag a ZIP without a context label", () => {
    const findings = scan("order 90210 confirmed");
    expect(findings.some((f) => f.ruleId === "pii-postal-code")).toBe(false);
  });

  it("detects a French postal code with context", () => {
    const findings = scan("postal: 75001");
    expect(findings.some((f) => f.ruleId === "pii-postal-code")).toBe(true);
  });

  it("detects a Spanish postal code with context", () => {
    const findings = scan("postal: 28013");
    expect(findings.some((f) => f.ruleId === "pii-postal-code")).toBe(true);
  });
});

// ── scan: context scoring ─────────────────────────────────────────────────────

describe("scan — context scoring", () => {
  it("assigns score 1.0 to a context-gated match", () => {
    const findings = scan("ZIP: 90210");
    const postal = findings.find((f) => f.ruleId === "pii-postal-code");
    expect(postal?.score).toBe(1.0);
  });

  it("assigns score 1.0 to rules without context requirements", () => {
    const findings = scan("contact: ada@analytical-engines.org");
    const email = findings.find((f) => f.ruleId === "pii-email");
    expect(email?.score).toBe(1.0);
  });
});

// ── scan: adversarial inputs ─────────────────────────────────────────────────

describe("scan — adversarial inputs", () => {
  // A run of digits and dots (a log line full of IPs or versions is this,
  // megabytes over) has a word boundary at every dot, and the local part of
  // the old pii-email pattern — [A-Za-z0-9._%+-]+ — spans those boundaries.
  // Every boundary then cost a greedy consume of the rest of the text plus a
  // character-at-a-time backtrack in search of the "@": O(n²) overall. 200 KB
  // of this kept a hook spinning for half a minute; the multi-MB file a
  // session actually scanned never finished.
  it("stays near-linear on a long digit-and-dot run with no @", () => {
    const input = "1.".repeat(100_000); // 200 KB
    const start = performance.now();
    scan(input);
    // Fixed, this is tens of milliseconds; before the fix it was half a
    // minute. The limit sits far from both so a loaded CI machine does not
    // flake it.
    expect(performance.now() - start).toBeLessThan(10_000);
  }, 30_000);

  it("stays near-linear on a long hyphen-separated digit run with no @", () => {
    const input = "123-".repeat(50_000); // 200 KB
    const start = performance.now();
    scan(input);
    expect(performance.now() - start).toBeLessThan(10_000);
  }, 30_000);

  // The two cases above name the input that was reported. They say nothing
  // about the other sixty-three rules, and the same shape was in one of them:
  // `env-assignment` read `[A-Z_]*` before its alternation and `[A-Z_0-9]*`
  // after, so a long run of capitals with no `=` backtracked from every
  // position. Measured on the rule alone: 59 KB 381ms, 117 KB 1878ms, 234 KB
  // 6871ms, 1 MiB 124574ms — and 1 MiB is what the file cap allows through, so
  // the cap bounded the read and not the work.
  //
  // So this runs every rule in the config against every shape, which is what
  // makes it a property of the rule set rather than a note about two inputs. A
  // rule added with a greedy quantifier either side of a literal fails here
  // before it reaches a release.
  //
  // A shape list is not a proof of completeness, and this one was caught short
  // already: with the first six shapes, `connection-string` was quadratic and
  // none of them reached it — `[^@\s]+` crosses both `:` and `/`, so every
  // `mongodb://` ran to the end of the text looking for an `@`. 188 KB took 2.3s
  // and 1 MiB through the hook took 98s. Adding a rule means asking what input
  // makes its own quantifiers run, and adding that shape here when the list has
  // nothing like it.
  describe("no rule is quadratic", () => {
    // Runs with no match in them, each built so a quantifier that can also
    // match its own separator has somewhere to backtrack.
    const SHAPES = {
      "digits and dots": "1.".repeat(128_000),
      "digits and hyphens": "123-".repeat(64_000),
      "capitals and underscores": "SECRET_".repeat(36_571),
      alphanumeric: "aA0".repeat(85_333),
      hex: "deadbeef".repeat(32_000),
      "base64 alphabet": "aA0+/".repeat(51_200),
      "assignments with no value": "key = ".repeat(42_666),
      "url credentials with no host": "mongodb://a:".repeat(21_333),
      // `url-basic-auth` bounds its two halves at 64 and 256 characters and
      // then wants an `@`. Each run here is as long as those bounds allow and
      // the `@` never comes, so every start position pays the full retreat.
      "https urls that never reach an @":
        `https://${"a".repeat(64)}:${"b".repeat(256)}`.repeat(778),
    };

    // Every rule is linear or better on these. The slowest pair measured is
    // `pii-email` on digits and dots: 56ms warm, a little over 200ms on a cold
    // run of the whole matrix. So the margin is about an order of magnitude, not
    // the three orders I first wrote here. What the budget has to separate is
    // quadratic from linear, and it does that with room: the rule this was
    // written for took seven seconds at a quarter of this size.
    const BUDGET_MS = 2_000;

    // Through `compileRule`, so each rule is timed with the flags it ships with.
    // Built here rather than looked up in the body: `generic-secret` and
    // `pii-nir-fr` declare `"flags": "gi"`, and a bare `new RegExp(regex, "g")`
    // would have timed a pattern the product never runs — `i` changes what a
    // character class matches, so it changes what backtracks.
    const cases = Object.entries(SHAPES).flatMap(([shape, input]) =>
      DEFAULT_RULES.map((rule) => ({
        id: rule.id,
        shape,
        input,
        regex: compileRule(rule).regex,
      })),
    );

    it.each(cases)(
      "$id: $shape",
      ({ id, shape, input, regex }) => {
        const start = performance.now();
        input.match(regex);
        const elapsed = performance.now() - start;
        expect(
          elapsed,
          `${id} took ${elapsed.toFixed(0)}ms on ${(input.length / 1024).toFixed(0)}KB of ${shape}`,
        ).toBeLessThan(BUDGET_MS);
      },
      30_000,
    );
  });
});

// What must not be flagged, alongside what must. A rule quieted to stop a false
// positive can quietly stop detecting, and only the pair says which happened.
//
// Measured before this: of these twenty-one, seventeen were blocked. A tool that
// blocks a quarter of ordinary commands is uninstalled, and then it guards
// nothing.
describe("ordinary work is not a finding", () => {
  const flags = (text: string): string[] => scan(text).map((f) => f.ruleId);

  it.each([
    ["git clone git@github.com:acme/widgets.git", "git over ssh"],
    ["ssh deploy@bastion.analytical-engines.org", "an ssh target"],
    ["scp build.tar ops@files.analytical-engines.org:/srv/", "an scp target"],
    ["rsync -a ops@files.analytical-engines.org:/srv/ .", "an rsync target"],
    ["ping 10.0.0.1", "a private address"],
    ["curl http://10.0.0.5:8080/health", "a private address in a URL"],
    ["redis-cli -h 10.0.0.30", "a private address as a flag value"],
    ["ECONNREFUSED 10.0.0.5:5432", "a private address in an error"],
    ["CIDR 192.168.0.0/24", "a network, not a host"],
    ["the buffer cap is 65536 bytes", "cap is an English word too"],
    ["the request took 1234567890123 nanoseconds", "a long number"],
    ["test card 4242424242424242", "a published test card"],
    ["use 4111111111111111 in the sandbox", "another published test card"],
    ["contact test@example.com for details", "an RFC 2606 domain"],
    ["see user@example.org in the docs", "an RFC 2606 domain"],
    ["POSTGRES_PASSWORD: ${DB_PASSWORD}", "a variable reference"],
    ["password: $VAULT_PASSWORD", "a variable reference"],
    ["function check(token: ShellToken): boolean {", "a type annotation"],
    ["  tokens: ShellToken[]", "a type annotation"],
  ])("%s is not a finding (%s)", (text) => {
    expect(flags(text)).toEqual([]);
  });

  // An ssh public key is base64, and `EAAA` appears in one often enough that the
  // Square rule matched a slice of it.
  it("an ssh public key is not a Square token", () => {
    const key = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEAAAJ1${"a".repeat(60)}`;
    expect(flags(key)).toEqual([]);
  });
});

// Detections the fourth review found had been lost while the false positives
// were being fixed. A corpus of five hundred generated values found a hundred
// and twenty-seven of these; the thirty-two cases chosen by hand had found none
// of them, which is what a hand-picked list is worth.
describe("detections that quieting the rules had removed", () => {
  const R = "Xk9mP2qR7vL4nW1sYj3cBz8d";
  const hits = (text: string): string[] => scan(text).map((f) => f.ruleId);

  // One excluded word within a couple of dozen characters erased every address
  // near it, including three in a row when one line said "test".
  it.each([
    "the remote user is sarah.connor@cyberdyne-systems.com",
    "Email the test results to ada@analytical-engines.org",
    "git blame shows ada@analytical-engines.org",
    "host: db1\nowner: ada@analytical-engines.org",
    "host,email\nsrv,ada@analytical-engines.org",
  ])("%s is still an address", (text) => {
    expect(hits(text)).toContain("pii-email");
  });

  // Anchoring the rule to the start of a line lost the shapes people type.
  it.each([
    `DB_PASSWORD='${R}'`,
    `DB_PASSWORD=${R};`,
    `DB_PASSWORD=${R},`,
    `cd /app && DB_PASSWORD=${R} ./run`,
    `set -e; DB_PASSWORD=${R}`,
    `docker run -e DB_PASSWORD=${R} img`,
    `                    DB_PASSWORD=${R}`,
    `DB_PASS=${R}`,
  ])("%s is still an assignment", (text) => {
    expect(hits(text)).toContain("env-assignment");
  });

  // A boundary that counted `_` and `=` as base64 erased the token after `key_`
  // and in a query string.
  it.each([
    `key_EAAAEaZ7${"b".repeat(56)}`,
    `https://x.io/a?token=EAAAEaZ7${"b".repeat(56)}`,
  ])("%s is still a Square token", (text) => {
    expect(hits(text)).toContain("square-access-token");
  });

  // The Korean numbers are stored without their separators as often as with.
  it("a Korean RRN without separators is still one", () => {
    expect(hits("주민등록번호 9001011234568")).toContain("pii-rrn-kr");
  });

  it("a Korean BRN without separators is still one", () => {
    expect(hits("사업자등록번호 2208162517")).toContain("pii-brn-kr");
  });

  it("a postal code next to the word max is still one", () => {
    expect(hits("zip: 94107 max 3")).toContain("pii-postal-code");
  });

  it("a three-hundred-character password is still a password", () => {
    const url = `postgres://admin:${"a".repeat(300)}@db.corp.internal/app`;
    expect(hits(url)).toContain("connection-string");
  });
});

// Shapes a review found wrong after the last round of rule changes: a keyword
// that is a substring of an ordinary word, a command with flags between it and
// its host, and a token boundary written in a different alphabet from the token.
const ruleIds = (text: string): string[] => scan(text).map((f) => f.ruleId);

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

// A rule shaped `{n,}` then a literal that may never come retries the whole tail
// from every start. `eyJ` recurs every three characters, so a megabyte of it took
// a hundred seconds — past the hook timeout, and a killed hook does not block.
describe("a scan cannot be made to hang", () => {
  const MEGABYTE = 1024 * 1024;

  // Measured against a baseline taken in the same run, not against a clock. The
  // defect this guards was a hundred seconds where a tenth of one was normal —
  // three orders of magnitude — so a generous multiple still catches it, and a
  // machine running the suite alongside other work does not turn it red.
  const timeScan = (text: string): number => {
    const startedAt = Date.now();
    scan(text);
    return Date.now() - startedAt;
  };

  const baseline = (): number =>
    Math.max(timeScan("const x = foo(bar);\n".repeat(MEGABYTE / 20)), 1);

  it.each([
    ["a repeated JWT header", "eyJ".repeat(MEGABYTE / 3)],
    [
      "repeated Square prefixes",
      `${(`-EAAA${"a".repeat(20)}`).repeat(MEGABYTE / 25)}/`,
    ],
    [
      "repeated Mapbox prefixes",
      `pk.eyJ${"a".repeat(12)}`.repeat(MEGABYTE / 18),
    ],
    [
      "repeated Sentry prefixes",
      `sntrys_${"a".repeat(12)}`.repeat(MEGABYTE / 19),
    ],
    ["one long run", "a".repeat(MEGABYTE)],
    ["digits", "1234567890".repeat(MEGABYTE / 10)],
    // `env-assignment` was the rule the first pass at this guard missed: its
    // value capture was open-ended and backtracked, and a megabyte took six
    // minutes.
    ["repeated assignments", `${"TOKEN=".repeat(48000)}${"v".repeat(711999)}<`],
    [
      "assignments and a long value",
      `${"TOKEN=".repeat(87000)}${"v".repeat(524288)}<`,
    ],
  ])("a megabyte of %s costs no more than ordinary text", (_label, text) => {
    expect(timeScan(text)).toBeLessThan(baseline() * 30 + 500);
  });

  // The bound must not cost the detection it exists for.
  it("a JWT with a large payload is still found", () => {
    const segment = (value: object): string =>
      Buffer.from(JSON.stringify(value)).toString("base64url");
    const token = [
      segment({ alg: "HS256", typ: "JWT" }),
      segment({ sub: "1", scope: "a".repeat(3000) }),
      "s".repeat(43),
    ].join(".");
    expect(ruleIds(token)).toContain("jwt");
  });

  // A boundary is what removes the quadratic, so it has to stay meaningful.
  it("a JWT header inside a longer token is not a JWT", () => {
    expect(
      ruleIds(`x${"eyJhbGciOiJIUzI1NiJ9"}.eyJhIjoxfQ.abcdefghij`),
    ).not.toContain("jwt");
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

// A single rule cannot be interrupted from inside the scan loop, so one bad
// pattern from a config file used to hang the hook — and a hook killed by the
// timeout does not block. The interrupt is on the V8 side now, which is why this
// runs the hook rather than calling `scan`: the rules are built at import time.
describe("a single rule cannot hang the scan", () => {
  it("a catastrophic pattern is cut off rather than run to completion", () => {
    const dir = mkdtempSync(join(tmpdir(), "canary-redos-"));
    const config = join(dir, "config.json");
    writeFileSync(
      config,
      JSON.stringify({
        rules: [
          { id: "boom", description: "x", regex: "(a+)+$", category: "secret" },
        ],
      }),
      "utf8",
    );
    const target = join(dir, "target.txt");
    writeFileSync(target, `${"a".repeat(40)}!\n`, "utf8");

    const startedAt = Date.now();
    const result = spawnSync(
      process.execPath,
      [
        "--experimental-strip-types",
        fileURLToPath(new URL("../../pre-tool-use-hook.ts", import.meta.url)),
      ],
      {
        input: JSON.stringify({
          tool_name: "Read",
          tool_input: { file_path: target },
        }),
        env: { ...process.env, SENSITIVE_CANARY_CONFIG: config },
        encoding: "utf8",
        timeout: 60_000,
      },
    );
    rmSync(dir, { recursive: true, force: true });

    // Unbounded, this pattern runs for hours; a killed hook does not block.
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("the check could not complete");
    expect(Date.now() - startedAt).toBeLessThan(40_000);
  }, 90_000);
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

// D.M. 23 dicembre 1976 art. 6: when two people would share the first fifteen
// characters, digits are replaced from the right with 0=L 1=M 2=N 3=P 4=Q 5=R
// 6=S 7=T 8=U 9=V. Every such code belongs to a real person, and the rule
// required digits at exactly the positions that get replaced.
describe("codice fiscale omocodia", () => {
  it.each([
    ["RSSMRA85T10A562S", "no substitution"],
    ["RSSMRA85T10A56NH", "one, from the right"],
    ["RSSMRA85T10ARSNO", "three"],
    ["RSSMRAURTMLARSNL", "all seven"],
  ])("%s is a codice fiscale (%s)", (code) => {
    expect(ruleIds(`CF ${code}`)).toContain("pii-codice-fiscale-it");
  });

  // Widening those positions to letters lets ordinary upper-case text reach the
  // pattern; the check character is what keeps it quiet.
  it.each(["MAXBUFFERSIZELIM", "CONTENTSECURITYPO", "SHELLKEYWORDTOKEN"])(
    "%s is not one",
    (word) => {
      expect(ruleIds(word)).not.toContain("pii-codice-fiscale-it");
    },
  );
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

// The other direction, in the same file, so quieting a rule cannot pass unnoticed.
describe("what must still be a finding", () => {
  it.each([
    [
      "contact alice@analytical-engines.org about the invoice",
      "a real address",
    ],
    [`key=${AWS_KEY}`, "an AWS key"],
    ["POSTGRES_PASSWORD: Sup3rS3cretDbPassw0rd", "a compose password"],
    ['  "client_secret": "Xk9mP2qR7vL4nW1sYj3c"', "a JSON secret"],
    [
      "aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
      "a credentials file",
    ],
    ["export GITHUB_TOKEN=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "a PAT"],
    ["-----BEGIN ENCRYPTED PRIVATE KEY-----", "a private key header"],
    ["card 4532015112830366", "a card that is not a published test number"],
    ["the client IP address is 8.8.8.8", "a public address with a label"],
  ])("%s is a finding (%s)", (text) => {
    expect(scan(text).length).toBeGreaterThan(0);
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
});

// The shipped rules, written out.
//
// This is the largest table in the product and had neither an equality nor a
// case per entry. Measured: deleting `mapbox-token` and `sentry-org-token` whole
// left the suite green — 1,459 cases instead of 1,467, because the only thing
// walking the rules is the timing matrix, and a rule that matches nothing passes
// all eight of its shapes. A rule silently dropped from a release is the worst
// version of that.
// The boundary between a reserved range and a public address. One public case
// (`8.8.8.8`) left the 224 edge free to move: at 200 the whole 200–223 block
// stops being PII.
describe("the reserved IPv4 boundary", () => {
  it.each(["223.255.255.255", "199.0.0.1", "126.0.0.1"])(
    "%s is public",
    (ip) => {
      expect(isReservedIpv4(ip)).toBe(false);
    },
  );

  it.each(["224.0.0.1", "239.255.255.255", "240.0.0.1", "127.0.0.1"])(
    "%s is reserved",
    (ip) => {
      expect(isReservedIpv4(ip)).toBe(true);
    },
  );
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

// One case per format the vendor documents and the rule did not match. Each
// pattern below is what the issuer or the vendor's own detector says, not what
// looked plausible.
// The budget covers the invocation, not one call. A hook scans once per
// environment variable and twice per file, so counting per call left the total
// unbounded — and the runtime kills a hook that runs long, which does not block.
describe("the scan budget spans every call in the invocation", () => {
  afterEach(() => {
    beginScanBudget(null);
  });

  it("a call made after the budget is spent throws rather than returning clean", () => {
    beginScanBudget(0);
    expect(() => scan(`key=${AWS_KEY}`)).toThrow(ScanBudgetExceeded);
  });

  it("repeated calls draw on one budget", () => {
    beginScanBudget(60);
    const started = Date.now();
    expect(() => {
      // Each of these is well inside the budget on its own.
      for (let i = 0; i < 10_000; i++) scan(`line ${i} of ordinary text`);
    }).toThrow(ScanBudgetExceeded);
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it("with no budget begun, a call gets the whole of one", () => {
    beginScanBudget(null);
    expect(scan(`key=${AWS_KEY}`).map((f) => f.ruleId)).toContain(
      "aws-access-key",
    );
  });

  it("a fresh budget lets scanning continue", () => {
    beginScanBudget(0);
    expect(() => scan("anything")).toThrow(ScanBudgetExceeded);
    beginScanBudget();
    expect(scan(`key=${AWS_KEY}`)).not.toHaveLength(0);
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

// ── Korean / Chinese ID validators ────────────────────────────────────────────

describe("validateKoreanRRN", () => {
  it("passes a valid RRN", () => {
    expect(validateKoreanRRN("8001011000008")).toBe(true);
  });

  it("fails an incorrect check digit", () => {
    expect(validateKoreanRRN("8001011000009")).toBe(false);
  });

  it("fails a wrong length", () => {
    expect(validateKoreanRRN("800101100000")).toBe(false);
  });
});

describe("validateKoreanBRN", () => {
  it("passes a valid BRN", () => {
    expect(validateKoreanBRN("1348672612")).toBe(true);
  });

  it("fails an incorrect check digit", () => {
    expect(validateKoreanBRN("1348672610")).toBe(false);
  });

  it("fails a wrong length", () => {
    expect(validateKoreanBRN("134867261")).toBe(false);
  });
});

describe("validateChineseID", () => {
  it("passes a valid Resident Identity Card", () => {
    expect(validateChineseID("110102199001010011")).toBe(true);
  });

  it("fails an incorrect check digit", () => {
    expect(validateChineseID("110102199001010010")).toBe(false);
  });

  it("fails a wrong length", () => {
    expect(validateChineseID("11010219900101001")).toBe(false);
  });
});

// ── IP reserved-range checks ──────────────────────────────────────────────────

describe("isReservedIpv4", () => {
  it("returns false for a public IP", () => {
    expect(isReservedIpv4("8.8.8.8")).toBe(false);
  });

  it("returns true for private ranges", () => {
    expect(isReservedIpv4("192.168.1.1")).toBe(true);
    expect(isReservedIpv4("10.0.0.1")).toBe(true);
    expect(isReservedIpv4("172.16.0.1")).toBe(true);
  });

  it("returns true for TEST-NET addresses", () => {
    expect(isReservedIpv4("192.0.2.1")).toBe(true);
    expect(isReservedIpv4("203.0.113.1")).toBe(true);
  });

  it("returns true for loopback and link-local", () => {
    expect(isReservedIpv4("127.0.0.1")).toBe(true);
    expect(isReservedIpv4("169.254.1.1")).toBe(true);
  });

  it("returns true for partially-numeric octets", () => {
    expect(isReservedIpv4("1a.2.3.4")).toBe(true);
    expect(isReservedIpv4("8.8.8.8x")).toBe(true);
    expect(isReservedIpv4("1.2.3.4 ")).toBe(true);
  });

  it("returns true for other RFC 6890 special-purpose ranges", () => {
    expect(isReservedIpv4("192.0.0.1")).toBe(true); // IETF protocol assignments
    expect(isReservedIpv4("192.88.99.1")).toBe(true); // 6to4 relay anycast
  });
});

describe("isReservedIpv6", () => {
  it("returns false for a public IPv6", () => {
    expect(isReservedIpv6("2001:4860:4860::8888")).toBe(false);
  });

  it("returns true for loopback", () => {
    expect(isReservedIpv6("::1")).toBe(true);
  });

  it("returns true for fully-expanded loopback", () => {
    expect(isReservedIpv6("0:0:0:0:0:0:0:1")).toBe(true);
  });

  it("returns true for fully-expanded unspecified", () => {
    expect(isReservedIpv6("0:0:0:0:0:0:0:0")).toBe(true);
  });

  it("returns true for compressed unspecified", () => {
    expect(isReservedIpv6("::")).toBe(true);
  });

  it("returns true for link-local", () => {
    expect(isReservedIpv6("fe80::1")).toBe(true);
  });

  it("returns true for fully-expanded link-local", () => {
    expect(isReservedIpv6("fe80:0:0:0:0:0:0:1")).toBe(true);
  });

  it("returns true for unique-local", () => {
    expect(isReservedIpv6("fd00::1")).toBe(true);
  });

  it("returns true for multicast", () => {
    expect(isReservedIpv6("ff02::1")).toBe(true);
  });

  it("returns true for documentation addresses", () => {
    expect(isReservedIpv6("2001:db8::1")).toBe(true);
  });

  it("returns true for groups with non-hex trailing characters", () => {
    expect(isReservedIpv6("abcdZ::1")).toBe(true);
    expect(isReservedIpv6("2001:4860:4860::8888g")).toBe(true);
  });

  it("returns true for groups longer than 4 hex digits", () => {
    expect(isReservedIpv6("12345::1")).toBe(true);
  });

  it("returns true when :: compresses zero groups", () => {
    // RFC 4291 §2.2: "::" must compress at least one 16-bit group.
    expect(isReservedIpv6("1:2:3:4:5:6:7::8")).toBe(true);
  });
});

// ── scan: Korean / Chinese IDs ────────────────────────────────────────────────

describe("scan — Korean / Chinese IDs", () => {
  it("detects a valid Korean RRN", () => {
    const findings = scan("rrn: 800101-1000008");
    expect(findings.some((f) => f.ruleId === "pii-rrn-kr")).toBe(true);
  });

  it("does not flag an RRN with a bad check digit", () => {
    const findings = scan("rrn: 800101-1000009");
    expect(findings.some((f) => f.ruleId === "pii-rrn-kr")).toBe(false);
  });

  it("detects a valid Chinese Resident ID", () => {
    const findings = scan("id: 110102199001010011");
    expect(findings.some((f) => f.ruleId === "pii-resident-id-cn")).toBe(true);
  });

  it("does not flag a Chinese ID with a bad check digit", () => {
    const findings = scan("id: 110102199001010010");
    expect(findings.some((f) => f.ruleId === "pii-resident-id-cn")).toBe(false);
  });

  it("detects a valid Korean BRN", () => {
    const findings = scan("brn: 134-86-72612");
    expect(findings.some((f) => f.ruleId === "pii-brn-kr")).toBe(true);
  });

  it("does not flag a BRN with a bad check digit", () => {
    const findings = scan("brn: 134-86-72610");
    expect(findings.some((f) => f.ruleId === "pii-brn-kr")).toBe(false);
  });
});

// ── scan: Korean / Chinese phone numbers ──────────────────────────────────────

describe("scan — Korean / Chinese phones", () => {
  it("detects a Korean phone with context", () => {
    const findings = scan("전화: 010-1234-5678");
    expect(findings.some((f) => f.ruleId === "pii-phone-kr")).toBe(true);
  });

  it("does not flag a bare Korean number without context", () => {
    const findings = scan("ref 010-1234-5678 end");
    expect(findings.some((f) => f.ruleId === "pii-phone-kr")).toBe(false);
  });

  it("detects a Chinese phone with context", () => {
    const findings = scan("电话: 13812345678");
    expect(findings.some((f) => f.ruleId === "pii-phone-cn")).toBe(true);
  });

  it("does not flag a bare Chinese number without context", () => {
    const findings = scan("id 13812345678 end");
    expect(findings.some((f) => f.ruleId === "pii-phone-cn")).toBe(false);
  });
});

// ── scan: Chinese postal code ─────────────────────────────────────────────────

describe("scan — Chinese postal code", () => {
  it("detects a Chinese postal code with context", () => {
    const findings = scan("邮编: 100000");
    expect(findings.some((f) => f.ruleId === "pii-postal-cn")).toBe(true);
  });

  it("does not flag a bare 6-digit number", () => {
    const findings = scan("count 123456 done");
    expect(findings.some((f) => f.ruleId === "pii-postal-cn")).toBe(false);
  });
});

// ── scan: public IP addresses ─────────────────────────────────────────────────

describe("scan — public IPs", () => {
  it("detects a public IPv4 with context", () => {
    const findings = scan("ip: 8.8.8.8");
    expect(findings.some((f) => f.ruleId === "pii-ipv4-public")).toBe(true);
  });

  it("does not flag a public IPv4 without context", () => {
    const findings = scan("ping 8.8.8.8 now");
    expect(findings.some((f) => f.ruleId === "pii-ipv4-public")).toBe(false);
  });

  it("does not flag a private IPv4 as public", () => {
    const findings = scan("ip: 192.168.1.1");
    expect(findings.some((f) => f.ruleId === "pii-ipv4-public")).toBe(false);
  });

  it("does not flag a private IPv4 at all", () => {
    expect(scan("client 192.168.1.1 connected")).toEqual([]);
  });

  it("detects an IPv6 with context", () => {
    const findings = scan("ipv6: 2001:4860:4860::8888");
    expect(findings.some((f) => f.ruleId === "pii-ipv6")).toBe(true);
  });

  it("does not flag a link-local IPv6", () => {
    const findings = scan("ipv6: fe80::1");
    expect(findings.some((f) => f.ruleId === "pii-ipv6")).toBe(false);
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

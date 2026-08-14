import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  compileRule,
  enabledCategoriesFromEnv,
  entropy,
  isReservedIpv4,
  isReservedIpv6,
  luhn,
  parseCategories,
  type RuleConfig,
  redact,
  scan,
  validateChineseID,
  validateCodiceFiscale,
  validateFrenchNIR,
  validateGermanIdNr,
  validateKoreanBRN,
  validateKoreanRRN,
  validateMyNumber,
  validateSpanishNIF,
} from "../rules.ts";

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
    expect(luhn("4111111111111111")).toBe(true);
  });

  it("passes a valid Mastercard number", () => {
    expect(luhn("5500005555555559")).toBe(true);
  });

  it("fails an invalid number", () => {
    expect(luhn("1234567890123456")).toBe(false);
  });

  it("ignores spaces and dashes", () => {
    expect(luhn("4111 1111 1111 1111")).toBe(true);
    expect(luhn("4111-1111-1111-1111")).toBe(true);
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
  it("masks strings of 8 chars or fewer completely", () => {
    expect(redact("abc")).toBe("****");
    expect(redact("12345678")).toBe("****");
  });

  it("shows first 4 and last 4 chars for strings longer than 8 chars", () => {
    expect(redact("123456789")).toBe("1234****6789");
    expect(redact("AKIAIOSFODNN7EXAMPLE")).toBe("AKIA****MPLE");
  });

  it("handles empty string", () => {
    expect(redact("")).toBe("****");
  });
});

// ── scan: secrets ─────────────────────────────────────────────────────────────

describe("scan — secrets", () => {
  it("detects an AWS Access Key ID", () => {
    const findings = scan("key=AKIAIOSFODNN7EXAMPLE");
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
    const findings = scan("postgres://user:password@localhost/mydb");
    expect(findings.some((f) => f.ruleId === "connection-string")).toBe(true);
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
    const findings = scan("contact: user@example.com");
    expect(findings.some((f) => f.ruleId === "pii-email")).toBe(true);
  });

  it("detects a valid credit card number — no separators", () => {
    const findings = scan("card: 4111111111111111");
    expect(findings.some((f) => f.ruleId === "pii-credit-card")).toBe(true);
  });

  it("detects a valid credit card number — space separated", () => {
    const findings = scan("card: 4111 1111 1111 1111");
    expect(findings.some((f) => f.ruleId === "pii-credit-card")).toBe(true);
  });

  it("detects a valid credit card number — hyphen separated", () => {
    const findings = scan("card: 4111-1111-1111-1111");
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

  it("detects a 192.168.x.x private IPv4 address", () => {
    const findings = scan("server: 192.168.1.100");
    expect(findings.some((f) => f.ruleId === "pii-ipv4")).toBe(true);
  });

  it("detects a 10.x.x.x private IPv4 address", () => {
    const findings = scan("server: 10.0.0.1");
    expect(findings.some((f) => f.ruleId === "pii-ipv4")).toBe(true);
  });

  it("detects a 172.16–31.x.x private IPv4 address", () => {
    expect(scan("host: 172.16.0.1").some((f) => f.ruleId === "pii-ipv4")).toBe(
      true,
    );
    expect(
      scan("host: 172.31.255.255").some((f) => f.ruleId === "pii-ipv4"),
    ).toBe(true);
  });

  it("does not flag 172.15.x.x (outside private range)", () => {
    expect(scan("host: 172.15.1.1").some((f) => f.ruleId === "pii-ipv4")).toBe(
      false,
    );
  });

  it("does not flag 172.32.x.x (outside private range)", () => {
    expect(scan("host: 172.32.1.1").some((f) => f.ruleId === "pii-ipv4")).toBe(
      false,
    );
  });

  it("does not flag a public IPv4 address", () => {
    const findings = scan("server: 8.8.8.8");
    expect(findings.some((f) => f.ruleId === "pii-ipv4")).toBe(false);
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
  const text = "key=AKIAIOSFODNN7EXAMPLE card: 4111111111111111";

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
    const findings = scan("contact: user@example.com");
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

describe("the shipped rules", () => {
  it("are exactly these sixty-four", () => {
    expect(DEFAULT_RULES.map((r) => r.id).sort()).toEqual([
      "anthropic-key",
      "atlassian-token",
      "aws-access-key",
      "connection-string",
      "digitalocean-pat",
      "discord-webhook",
      "env-assignment",
      "gcp-api-key",
      "generic-secret",
      "github-fine-grained",
      "github-pat",
      "gitlab-pat",
      "groq-key",
      "huggingface-token",
      "jwt",
      "linear-key",
      "mailchimp-key",
      "mailgun-key",
      "mapbox-token",
      "npm-token",
      "openai-key",
      "openai-project-key",
      "openrouter-key",
      "perplexity-key",
      "pii-brn-kr",
      "pii-codice-fiscale-it",
      "pii-credit-card",
      "pii-dni-nie-es",
      "pii-email",
      "pii-ipv4",
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
      "replicate-token",
      "sendgrid-key",
      "sentry-org-token",
      "sentry-user-token",
      "slack-token",
      "slack-webhook",
      "square-access-token",
      "stripe-restricted-key",
      "stripe-secret-key",
      "supabase-key",
      "telegram-bot-token",
      "twilio-sid",
      "xai-key",
    ]);
  });

  it("are split as the README says: 39 secret, 25 PII", () => {
    const byCategory = DEFAULT_RULES.reduce<Record<string, number>>(
      (acc, r) => ({ ...acc, [r.category]: (acc[r.category] ?? 0) + 1 }),
      {},
    );
    expect(byCategory).toEqual({ secret: 39, pii: 25 });
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
    ["user@example.com", "the plain form"],
    ["Alice.Smith@Example.COM", "mixed case"],
    ["user+tag@example.com", "plus addressing"],
    ["user.name@sub.example.co.uk", "several domain labels"],
    ["a@b.co", "the shortest real shape"],
    ["user_name%foo-bar@example.com", "every character of the local part"],
    ["see<user@example.com>now", "embedded in surrounding text"],
    [`${"a".repeat(64)}@example.com`, "a local part at RFC 5321's limit"],
  ])("%s is detected (%s)", (text) => {
    expect(email(text)).toBe(true);
  });

  // What bounding the local part costs. 65 characters before the `@` with no
  // dot to restart the boundary is not a deliverable address, and it is also a
  // way to write one this rule will not see.
  it("a local part past the limit is not detected", () => {
    expect(email(`${"a".repeat(65)}@example.com`)).toBe(false);
  });

  // A dot restarts the word boundary, so a long address with dots in it is
  // still found — the limit applies to one unbroken run, not to the whole
  // local part.
  it("a long local part broken by dots is still detected", () => {
    const local = Array.from({ length: 10 }, () => "a".repeat(20)).join(".");
    expect(email(`${local}@example.com`)).toBe(true);
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
    expect(conn(`mongodb://user:${"p".repeat(257)}@host`)).toBe(false);
    expect(conn(`mongodb://user:${"p".repeat(256)}@host`)).toBe(true);
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

  it("still flags a private IPv4 via the private-range rule", () => {
    const findings = scan("server: 192.168.1.1");
    expect(findings.some((f) => f.ruleId === "pii-ipv4")).toBe(true);
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

    const findings = scan("contact: user@example.com");
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

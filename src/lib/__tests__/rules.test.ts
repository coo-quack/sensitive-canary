import { afterEach, describe, expect, it } from "vitest";
import {
  enabledCategoriesFromEnv,
  entropy,
  luhn,
  parseCategories,
  redact,
  scan,
  validateCodiceFiscale,
  validateFrenchNIR,
  validateGermanIdNr,
  validateMyNumber,
  validateSpanishNIF,
} from "../rules.ts";

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
    const findings = scan("secu: 1234567890123 11");
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

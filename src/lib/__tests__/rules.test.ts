import { describe, expect, it } from "vitest";
import { entropy, luhn, redact, scan } from "../rules.ts";

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

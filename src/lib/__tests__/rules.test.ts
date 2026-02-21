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
    const findings = scan("key=AKIAIOSFODNN7EXAMPLE", "test");
    expect(findings.some((f) => f.ruleId === "aws-access-key")).toBe(true);
  });

  it("detects a PEM private key header (RSA)", () => {
    const findings = scan("-----BEGIN RSA PRIVATE KEY-----", "test");
    expect(findings.some((f) => f.ruleId === "private-key")).toBe(true);
  });

  it("detects an OpenSSH private key header via private-key rule", () => {
    const findings = scan("-----BEGIN OPENSSH PRIVATE KEY-----", "test");
    expect(findings.some((f) => f.ruleId === "private-key")).toBe(true);
  });

  it("detects a GitHub PAT", () => {
    const findings = scan(`token=ghp_${"A".repeat(36)}`, "test");
    expect(findings.some((f) => f.ruleId === "github-pat")).toBe(true);
  });

  it("detects a GitLab PAT", () => {
    const findings = scan(`token=glpat-${"A".repeat(20)}`, "test");
    expect(findings.some((f) => f.ruleId === "gitlab-pat")).toBe(true);
  });

  it("detects a Slack token", () => {
    const findings = scan("xoxb-123456789012-ABCDEFGHIJ", "test");
    expect(findings.some((f) => f.ruleId === "slack-token")).toBe(true);
  });

  it("detects a Stripe secret key", () => {
    const findings = scan(`sk_live_${"A".repeat(24)}`, "test");
    expect(findings.some((f) => f.ruleId === "stripe-secret-key")).toBe(true);
  });

  it("detects a SendGrid API key", () => {
    const findings = scan(`SG.${"A".repeat(22)}.${"B".repeat(43)}`, "test");
    expect(findings.some((f) => f.ruleId === "sendgrid-key")).toBe(true);
  });

  it("detects a JWT", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const findings = scan(jwt, "test");
    expect(findings.some((f) => f.ruleId === "jwt")).toBe(true);
  });

  it("detects an OpenAI project API key", () => {
    // 40 chars after prefix (meets {40,} minimum), high entropy
    const findings = scan(
      "sk-proj-Xk9mP2qR7vL4nW1sYj3cBz8dEf5gHiKoNpQuTxMn",
      "test",
    );
    expect(findings.some((f) => f.ruleId === "openai-project-key")).toBe(true);
  });

  it("detects a database connection string with credentials", () => {
    const findings = scan("postgres://user:password@localhost/mydb", "test");
    expect(findings.some((f) => f.ruleId === "connection-string")).toBe(true);
  });

  it("detects an .env style assignment with sufficient entropy", () => {
    const findings = scan("DATABASE_PASSWORD=Xk9mP2qR7vL4nW1s", "test");
    expect(findings.some((f) => f.ruleId === "env-assignment")).toBe(true);
  });

  it("does not flag a low-entropy .env value", () => {
    const findings = scan("DATABASE_PASSWORD=password", "test");
    expect(findings.some((f) => f.ruleId === "env-assignment")).toBe(false);
  });

  it("returns no findings for clean text", () => {
    expect(scan("hello world, nothing sensitive here", "test")).toHaveLength(0);
  });
});

// ── scan: PII ─────────────────────────────────────────────────────────────────

describe("scan — PII", () => {
  it("detects an email address", () => {
    const findings = scan("contact: user@example.com", "test");
    expect(findings.some((f) => f.ruleId === "pii-email")).toBe(true);
  });

  it("detects a valid credit card number — no separators", () => {
    const findings = scan("card: 4111111111111111", "test");
    expect(findings.some((f) => f.ruleId === "pii-credit-card")).toBe(true);
  });

  it("detects a valid credit card number — space separated", () => {
    const findings = scan("card: 4111 1111 1111 1111", "test");
    expect(findings.some((f) => f.ruleId === "pii-credit-card")).toBe(true);
  });

  it("detects a valid credit card number — hyphen separated", () => {
    const findings = scan("card: 4111-1111-1111-1111", "test");
    expect(findings.some((f) => f.ruleId === "pii-credit-card")).toBe(true);
  });

  it("does not flag an invalid credit card number", () => {
    const findings = scan("card: 4111111111111112", "test");
    expect(findings.some((f) => f.ruleId === "pii-credit-card")).toBe(false);
  });

  it("detects a US SSN", () => {
    const findings = scan("ssn: 123-45-6789", "test");
    expect(findings.some((f) => f.ruleId === "pii-ssn")).toBe(true);
  });

  it("does not flag an SSN starting with 000", () => {
    expect(
      scan("ssn: 000-45-6789", "test").some((f) => f.ruleId === "pii-ssn"),
    ).toBe(false);
  });

  it("does not flag an SSN starting with 666", () => {
    expect(
      scan("ssn: 666-45-6789", "test").some((f) => f.ruleId === "pii-ssn"),
    ).toBe(false);
  });

  it("does not flag an SSN starting with 9xx", () => {
    expect(
      scan("ssn: 900-45-6789", "test").some((f) => f.ruleId === "pii-ssn"),
    ).toBe(false);
  });

  it("detects a US phone number", () => {
    const findings = scan("call: (555) 123-4567", "test");
    expect(findings.some((f) => f.ruleId === "pii-phone-us")).toBe(true);
  });

  it("detects a Japanese phone number", () => {
    const findings = scan("tel: 03-1234-5678", "test");
    expect(findings.some((f) => f.ruleId === "pii-phone-jp")).toBe(true);
  });

  it("detects a Japanese postal code with 〒 prefix", () => {
    const findings = scan("address: 〒150-0001", "test");
    expect(findings.some((f) => f.ruleId === "pii-postal-jp")).toBe(true);
  });

  it("does not flag a postal-like number without 〒", () => {
    const findings = scan("zip: 150-0001", "test");
    expect(findings.some((f) => f.ruleId === "pii-postal-jp")).toBe(false);
  });

  it("detects a private IPv4 address", () => {
    const findings = scan("server: 192.168.1.100", "test");
    expect(findings.some((f) => f.ruleId === "pii-ipv4")).toBe(true);
  });

  it("does not flag a public IPv4 address", () => {
    const findings = scan("server: 8.8.8.8", "test");
    expect(findings.some((f) => f.ruleId === "pii-ipv4")).toBe(false);
  });
});

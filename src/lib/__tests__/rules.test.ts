import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  beginScanBudget,
  compileRule,
  redact,
  ScanBudgetExceeded,
  scan,
} from "../rules.ts";
import { AWS_KEY, DEFAULT_RULES, ruleIds } from "./rule-fixtures.ts";

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

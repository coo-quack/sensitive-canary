import { describe, expect, it } from "vitest";
import type { Finding } from "../inspector.ts";
import {
  applyAllowTags,
  dedupeFindings,
  findingsToLines,
  parseAllowTags,
  parseMaskTags,
  scanMessages,
} from "../inspector.ts";

// ── parseAllowTags ────────────────────────────────────────────────────────────

describe("parseAllowTags", () => {
  it("returns empty set when no tags are present", () => {
    const tags = parseAllowTags([{ role: "user", content: "hello" }]);
    expect(tags.size).toBe(0);
  });

  it("parses [allow-all]", () => {
    const tags = parseAllowTags([
      { role: "user", content: "[allow-all] send anyway" },
    ]);
    expect(tags.has("all")).toBe(true);
  });

  it("parses [allow-pii]", () => {
    const tags = parseAllowTags([{ role: "user", content: "[allow-pii] ok" }]);
    expect(tags.has("pii")).toBe(true);
  });

  it("parses [allow-secret]", () => {
    const tags = parseAllowTags([
      { role: "user", content: "[allow-secret] here is my key" },
    ]);
    expect(tags.has("secret")).toBe(true);
  });

  it("is case-insensitive", () => {
    const tags = parseAllowTags([{ role: "user", content: "[Allow-Secret]" }]);
    expect(tags.has("secret")).toBe(true);
  });

  it("ignores tags in assistant messages", () => {
    const tags = parseAllowTags([
      { role: "assistant", content: "[allow-all] this is the assistant" },
    ]);
    expect(tags.size).toBe(0);
  });

  it("parses tags from ContentBlock[] content", () => {
    const tags = parseAllowTags([
      {
        role: "user",
        content: [{ type: "text", text: "[allow-secret] check this" }],
      },
    ]);
    expect(tags.has("secret")).toBe(true);
  });
});

// ── parseMaskTags ─────────────────────────────────────────────────────────────

describe("parseMaskTags", () => {
  it("returns empty set when no tags are present", () => {
    const tags = parseMaskTags([{ role: "user", content: "hello" }]);
    expect(tags.size).toBe(0);
  });

  it("parses [mask-all]", () => {
    const tags = parseMaskTags([{ role: "user", content: "[mask-all] send" }]);
    expect(tags.has("all")).toBe(true);
  });

  it("parses [mask-secret]", () => {
    const tags = parseMaskTags([
      { role: "user", content: "[mask-secret] here is my key" },
    ]);
    expect(tags.has("secret")).toBe(true);
  });

  it("parses [mask-pii]", () => {
    const tags = parseMaskTags([{ role: "user", content: "[mask-pii] ok" }]);
    expect(tags.has("pii")).toBe(true);
  });

  it("is case-insensitive", () => {
    const tags = parseMaskTags([{ role: "user", content: "[Mask-Secret]" }]);
    expect(tags.has("secret")).toBe(true);
  });

  it("ignores tags in assistant messages", () => {
    const tags = parseMaskTags([
      { role: "assistant", content: "[mask-all] assistant said this" },
    ]);
    expect(tags.size).toBe(0);
  });

  it("does not pick up [allow-xxx] tags", () => {
    const tags = parseMaskTags([
      { role: "user", content: "[allow-all] send anyway" },
    ]);
    expect(tags.size).toBe(0);
  });
});

// ── applyAllowTags ────────────────────────────────────────────────────────────

describe("applyAllowTags", () => {
  const findings: Finding[] = [
    {
      ruleId: "aws-access-key",
      description: "AWS",
      category: "secret",
      matchRedacted: "AKIA****",
      secretValue: "AKIATEST",
      location: "test",
    },
    {
      ruleId: "pii-email",
      description: "Email",
      category: "pii",
      matchRedacted: "user****",
      secretValue: "user@example.com",
      location: "test",
    },
  ];

  it("returns all findings when allow set is empty", () => {
    expect(applyAllowTags(findings, new Set())).toHaveLength(2);
  });

  it("returns empty array when findings is empty", () => {
    expect(applyAllowTags([], new Set(["all"]))).toHaveLength(0);
  });

  it("[allow-all] removes all findings", () => {
    expect(applyAllowTags(findings, new Set(["all"]))).toHaveLength(0);
  });

  it("[allow-secret] removes only secret findings", () => {
    const result = applyAllowTags(findings, new Set(["secret"]));
    expect(result).toHaveLength(1);
    expect(result[0]?.ruleId).toBe("pii-email");
  });

  it("[allow-pii] removes only PII findings", () => {
    const result = applyAllowTags(findings, new Set(["pii"]));
    expect(result).toHaveLength(1);
    expect(result[0]?.ruleId).toBe("aws-access-key");
  });

  it("an unknown tag has no effect", () => {
    const result = applyAllowTags(findings, new Set(["aws-access-key"]));
    expect(result).toHaveLength(2);
  });
});

// ── dedupeFindings ────────────────────────────────────────────────────────────

describe("dedupeFindings", () => {
  it("removes duplicate findings with the same secretValue", () => {
    const findings: Finding[] = [
      {
        ruleId: "aws-access-key",
        description: "AWS",
        category: "secret",
        matchRedacted: "AKIA****",
        secretValue: "AKIATEST",
        location: "a",
      },
      {
        ruleId: "aws-access-key",
        description: "AWS",
        category: "secret",
        matchRedacted: "AKIA****",
        secretValue: "AKIATEST",
        location: "b",
      },
    ];
    expect(dedupeFindings(findings)).toHaveLength(1);
  });

  it("keeps findings with different secretValues", () => {
    const findings: Finding[] = [
      {
        ruleId: "aws-access-key",
        description: "AWS",
        category: "secret",
        matchRedacted: "AKIA****",
        secretValue: "AKIATEST1",
        location: "a",
      },
      {
        ruleId: "aws-access-key",
        description: "AWS",
        category: "secret",
        matchRedacted: "AKIA****",
        secretValue: "AKIATEST2",
        location: "b",
      },
    ];
    expect(dedupeFindings(findings)).toHaveLength(2);
  });
});

// ── findingsToLines ───────────────────────────────────────────────────────────

describe("findingsToLines", () => {
  it("formats a secret finding", () => {
    const findings: Finding[] = [
      {
        ruleId: "aws-access-key",
        description: "AWS Access Key ID",
        category: "secret",
        matchRedacted: "AKIA****MPLE",
        secretValue: "AKIAIOSFODNN7EXAMPLE",
        location: "test",
      },
    ];
    const lines = findingsToLines(findings);
    expect(lines[0]).toBe(
      "  [Secret] AWS Access Key ID (aws-access-key): AKIA****MPLE",
    );
  });

  it("formats a PII finding", () => {
    const findings: Finding[] = [
      {
        ruleId: "pii-email",
        description: "Email Address",
        category: "pii",
        matchRedacted: "user****",
        secretValue: "user@example.com",
        location: "test",
      },
    ];
    const lines = findingsToLines(findings);
    expect(lines[0]).toBe("  [PII] Email Address (pii-email): user****");
  });
});

// ── scanMessages ──────────────────────────────────────────────────────────────

describe("scanMessages", () => {
  it("detects a secret in a user message", () => {
    const findings = scanMessages([
      { role: "user", content: "my key is AKIAIOSFODNN7EXAMPLE" },
    ]);
    expect(findings.some((f) => f.ruleId === "aws-access-key")).toBe(true);
  });

  it("does not scan assistant messages", () => {
    const findings = scanMessages([
      {
        role: "assistant",
        content: "here is an example key: AKIAIOSFODNN7EXAMPLE",
      },
    ]);
    expect(findings).toHaveLength(0);
  });

  it("respects [allow-all] in the same message", () => {
    const findings = scanMessages([
      {
        role: "user",
        content: "[allow-all] my key is AKIAIOSFODNN7EXAMPLE",
      },
    ]);
    expect(findings).toHaveLength(0);
  });

  it("respects [allow-secret] to bypass a secret", () => {
    const findings = scanMessages([
      {
        role: "user",
        content: "[allow-secret] my key is AKIAIOSFODNN7EXAMPLE",
      },
    ]);
    expect(findings).toHaveLength(0);
  });

  it("deduplicates the same secret appearing multiple times", () => {
    const findings = scanMessages([
      {
        role: "user",
        content: "key1=AKIAIOSFODNN7EXAMPLE key2=AKIAIOSFODNN7EXAMPLE",
      },
    ]);
    const aws = findings.filter((f) => f.ruleId === "aws-access-key");
    expect(aws).toHaveLength(1);
  });

  it("returns empty array for clean messages", () => {
    const findings = scanMessages([
      { role: "user", content: "hello, how are you?" },
    ]);
    expect(findings).toHaveLength(0);
  });

  it("detects a secret in ContentBlock[] content", () => {
    const findings = scanMessages([
      {
        role: "user",
        content: [{ type: "text", text: "my key is AKIAIOSFODNN7EXAMPLE" }],
      },
    ]);
    expect(findings.some((f) => f.ruleId === "aws-access-key")).toBe(true);
  });

  it("scans tool_result content (string) inside a user message", () => {
    const findings = scanMessages([
      {
        role: "user",
        content: [
          {
            type: "tool_result",
            content: "key: AKIAIOSFODNN7EXAMPLE",
          },
        ],
      },
    ]);
    expect(findings.some((f) => f.ruleId === "aws-access-key")).toBe(true);
  });

  it("scans tool_result content (ContentBlock[]) inside a user message", () => {
    const findings = scanMessages([
      {
        role: "user",
        content: [
          {
            type: "tool_result",
            content: [{ type: "text", text: "key: AKIAIOSFODNN7EXAMPLE" }],
          },
        ],
      },
    ]);
    expect(findings.some((f) => f.ruleId === "aws-access-key")).toBe(true);
  });

  it("scans across multiple user messages", () => {
    const findings = scanMessages([
      { role: "user", content: "hello" },
      { role: "assistant", content: "hi there" },
      { role: "user", content: "my key is AKIAIOSFODNN7EXAMPLE" },
    ]);
    expect(findings.some((f) => f.ruleId === "aws-access-key")).toBe(true);
  });

  it("allow tag in one message applies to all messages", () => {
    const findings = scanMessages([
      { role: "user", content: "[allow-secret] first message" },
      { role: "user", content: "my key is AKIAIOSFODNN7EXAMPLE" },
    ]);
    expect(findings).toHaveLength(0);
  });
});

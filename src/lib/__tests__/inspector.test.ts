import { describe, expect, it } from "vitest";
import type { Finding } from "../inspector.ts";
import {
  applyAllowTags,
  dedupeFindings,
  findingsToLines,
  parseAllowTags,
  resolveTagPriority,
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

// ── resolveTagPriority ────────────────────────────────────────────────────────

describe("resolveTagPriority", () => {
  it("returns empty sets when no tags are present", () => {
    const { effectiveAllow, effectiveMask } = resolveTagPriority("hello world");
    expect(effectiveAllow.size).toBe(0);
    expect(effectiveMask.size).toBe(0);
  });

  it("[allow-secret] → effectiveAllow has 'secret'", () => {
    const { effectiveAllow, effectiveMask } = resolveTagPriority(
      "[allow-secret] key=abc",
    );
    expect(effectiveAllow.has("secret")).toBe(true);
    expect(effectiveMask.has("secret")).toBe(false);
  });

  it("[mask-secret] → effectiveMask has 'secret'", () => {
    const { effectiveAllow, effectiveMask } = resolveTagPriority(
      "[mask-secret] key=abc",
    );
    expect(effectiveMask.has("secret")).toBe(true);
    expect(effectiveAllow.has("secret")).toBe(false);
  });

  it("[allow-secret] before [mask-secret] → allow wins for secret", () => {
    const { effectiveAllow, effectiveMask } = resolveTagPriority(
      "[allow-secret] [mask-secret] key=abc",
    );
    expect(effectiveAllow.has("secret")).toBe(true);
    expect(effectiveMask.has("secret")).toBe(false);
  });

  it("[mask-secret] before [allow-secret] → mask wins for secret", () => {
    const { effectiveAllow, effectiveMask } = resolveTagPriority(
      "[mask-secret] [allow-secret] key=abc",
    );
    expect(effectiveMask.has("secret")).toBe(true);
    expect(effectiveAllow.has("secret")).toBe(false);
  });

  it("[allow-all] before [mask-secret] → allow wins for both dimensions", () => {
    const { effectiveAllow, effectiveMask } = resolveTagPriority(
      "[allow-all] [mask-secret] key=abc",
    );
    expect(effectiveAllow.has("secret")).toBe(true);
    expect(effectiveAllow.has("pii")).toBe(true);
    expect(effectiveMask.size).toBe(0);
  });

  it("[mask-all] before [allow-secret] → mask wins for both dimensions", () => {
    const { effectiveAllow, effectiveMask } = resolveTagPriority(
      "[mask-all] [allow-secret] key=abc",
    );
    expect(effectiveMask.has("secret")).toBe(true);
    expect(effectiveMask.has("pii")).toBe(true);
    expect(effectiveMask.has("all")).toBe(true);
    expect(effectiveAllow.size).toBe(0);
  });

  it("[allow-secret] [mask-pii] → allow for secret, mask for pii", () => {
    const { effectiveAllow, effectiveMask } = resolveTagPriority(
      "[allow-secret] [mask-pii] ...",
    );
    expect(effectiveAllow.has("secret")).toBe(true);
    expect(effectiveMask.has("pii")).toBe(true);
    expect(effectiveAllow.has("pii")).toBe(false);
    expect(effectiveMask.has("secret")).toBe(false);
  });

  it("[allow-all] → effectiveAllow has 'all'", () => {
    const { effectiveAllow } = resolveTagPriority("[allow-all] key=abc");
    expect(effectiveAllow.has("all")).toBe(true);
  });

  it("[mask-all] → effectiveMask has 'all'", () => {
    const { effectiveMask } = resolveTagPriority("[mask-all] key=abc");
    expect(effectiveMask.has("all")).toBe(true);
  });

  it("is case-insensitive", () => {
    const { effectiveAllow } = resolveTagPriority("[Allow-Secret] key=abc");
    expect(effectiveAllow.has("secret")).toBe(true);
  });

  it("unknown tag suffix is ignored", () => {
    const { effectiveAllow, effectiveMask } = resolveTagPriority(
      "[allow-unknown] key=abc",
    );
    expect(effectiveAllow.size).toBe(0);
    expect(effectiveMask.size).toBe(0);
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
    },
    {
      ruleId: "pii-email",
      description: "Email",
      category: "pii",
      matchRedacted: "user****",
      secretValue: "user@example.com",
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
      },
      {
        ruleId: "aws-access-key",
        description: "AWS",
        category: "secret",
        matchRedacted: "AKIA****",
        secretValue: "AKIATEST",
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
      },
      {
        ruleId: "aws-access-key",
        description: "AWS",
        category: "secret",
        matchRedacted: "AKIA****",
        secretValue: "AKIATEST2",
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
      },
    ];
    const lines = findingsToLines(findings);
    expect(lines[0]).toBe("  [PII] Email Address (pii-email): user****");
  });
});

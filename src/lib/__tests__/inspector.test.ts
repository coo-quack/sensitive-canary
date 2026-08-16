import { describe, expect, it } from "vitest";
import type { Finding } from "../inspector.ts";

// Not AWS's documented `…EXAMPLE` key, which the `aws-key`
// validator reads as documentation rather than a credential.
const AWS_KEY = ["AKIA", "3QF7TZ9KLMN2", "PQRS"].join("");

import {
  applyAllowTags,
  dedupeFindings,
  findingsToLines,
  MAX_FINDING_LINES,
  resolveTagPriority,
} from "../inspector.ts";

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

  // The last tag replaces the earlier ones whole. Merging per category kept the
  // wider grant of the two, so narrowing from `[allow-all]` to `[allow-secret]`
  // went on allowing PII.
  it("[allow-secret] then [mask-secret] → mask", () => {
    const { effectiveAllow, effectiveMask } = resolveTagPriority(
      "[allow-secret] [mask-secret] key=abc",
    );
    expect(effectiveMask.has("secret")).toBe(true);
    expect(effectiveAllow.has("secret")).toBe(false);
  });

  it("[mask-secret] then [allow-secret] → allow", () => {
    const { effectiveAllow, effectiveMask } = resolveTagPriority(
      "[mask-secret] [allow-secret] key=abc",
    );
    expect(effectiveAllow.has("secret")).toBe(true);
    expect(effectiveMask.has("secret")).toBe(false);
  });

  it("[allow-all] then [allow-secret] narrows, and PII is guarded again", () => {
    const { effectiveAllow, effectiveMask } = resolveTagPriority(
      "[allow-all] [allow-secret] key=abc",
    );
    expect(effectiveAllow.has("secret")).toBe(true);
    expect(effectiveAllow.has("pii")).toBe(false);
    expect(effectiveAllow.has("all")).toBe(false);
    expect(effectiveMask.size).toBe(0);
  });

  it("[allow-secret] then [allow-all] widens", () => {
    const { effectiveAllow } = resolveTagPriority(
      "[allow-secret] [allow-all] key=abc",
    );
    expect(effectiveAllow.has("secret")).toBe(true);
    expect(effectiveAllow.has("pii")).toBe(true);
    expect(effectiveAllow.has("all")).toBe(true);
  });

  it("[mask-all] then [allow-secret] → allow, for secret only", () => {
    const { effectiveAllow, effectiveMask } = resolveTagPriority(
      "[mask-all] [allow-secret] key=abc",
    );
    expect(effectiveAllow.has("secret")).toBe(true);
    expect(effectiveAllow.has("pii")).toBe(false);
    expect(effectiveMask.size).toBe(0);
  });

  // Two tags do not add up: `[allow-all]` is how both categories are asked for.
  it("[allow-secret] then [allow-pii] is not both", () => {
    const { effectiveAllow } = resolveTagPriority(
      "[allow-secret] [allow-pii] ...",
    );
    expect(effectiveAllow.has("pii")).toBe(true);
    expect(effectiveAllow.has("secret")).toBe(false);
  });

  it("a tag mid-sentence still counts", () => {
    const { effectiveAllow } = resolveTagPriority(
      "please read the env file [allow-secret] and summarise it",
    );
    expect(effectiveAllow.has("secret")).toBe(true);
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
      score: 1,
    },
    {
      ruleId: "pii-email",
      description: "Email",
      category: "pii",
      matchRedacted: "user****",
      secretValue: "ada@analytical-engines.org",
      score: 1,
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
        score: 1,
      },
      {
        ruleId: "aws-access-key",
        description: "AWS",
        category: "secret",
        matchRedacted: "AKIA****",
        secretValue: "AKIATEST",
        score: 1,
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
        score: 1,
      },
      {
        ruleId: "aws-access-key",
        description: "AWS",
        category: "secret",
        matchRedacted: "AKIA****",
        secretValue: "AKIATEST2",
        score: 1,
      },
    ];
    expect(dedupeFindings(findings)).toHaveLength(2);
  });

  // One value can be two findings. An address in an assignment matches a PII
  // rule and a secret rule, and collapsing on the value alone reported whichever
  // came first — so which tag lifts the block read as arbitrary, because the
  // message named one category and the other was what held it.
  it("keeps one finding per category for the same value", () => {
    const value = "alice.dupont@realcompany.co.jp";
    const findings: Finding[] = [
      {
        ruleId: "env-assignment",
        description: "assignment",
        category: "secret",
        matchRedacted: "al****jp",
        secretValue: value,
      },
      {
        ruleId: "pii-email",
        description: "Email Address",
        category: "pii",
        matchRedacted: "al****jp",
        secretValue: value,
      },
    ];
    const kept = dedupeFindings(findings);
    expect(kept).toHaveLength(2);
    expect(kept.map((f) => f.category).sort()).toEqual(["pii", "secret"]);
  });

  // And the same category twice is still one, which is what the key is for.
  it("still collapses the same value in the same category", () => {
    const one = (ruleId: string): Finding => ({
      ruleId,
      description: "d",
      category: "secret",
      matchRedacted: "ab****yz",
      secretValue: "the-same-value",
    });
    expect(dedupeFindings([one("a"), one("b")])).toHaveLength(1);
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
        secretValue: `${AWS_KEY}`,
        score: 1,
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
        secretValue: "ada@analytical-engines.org",
        score: 1,
      },
    ];
    const lines = findingsToLines(findings);
    expect(lines[0]).toBe("  [PII] Email Address (pii-email): user****");
  });
});

// The cap on how many findings are printed.
//
// A rule that matches everywhere once produced forty thousand lines of stderr,
// which buries the block it is explaining and is itself a way of hiding one.
// Neither the cap nor the line that says what was left out was fixed by a test,
// so both could move or vanish without anything noticing.
describe("how many findings are printed", () => {
  const finding = (n: number): Finding => ({
    ruleId: `rule-${n}`,
    description: `Rule ${n}`,
    category: "secret",
    matchRedacted: "ab****yz",
    secretValue: `value-${n}`,
  });

  const linesFor = (count: number): string[] =>
    findingsToLines(Array.from({ length: count }, (_, i) => finding(i)));

  it("prints every finding when there are few", () => {
    expect(linesFor(3)).toHaveLength(3);
  });

  // The boundary itself, from both sides: at the cap nothing is elided, one
  // over it the extra line appears.
  it("prints exactly the cap with nothing added", () => {
    const lines = linesFor(MAX_FINDING_LINES);
    expect(lines).toHaveLength(MAX_FINDING_LINES);
    expect(lines.join("\n")).not.toContain("more");
  });

  it("says how many it left out", () => {
    const lines = linesFor(MAX_FINDING_LINES + 1);
    expect(lines).toHaveLength(MAX_FINDING_LINES + 1);
    expect(lines[lines.length - 1]).toBe("  … and 1 more");
  });

  it("counts the ones it left out", () => {
    const lines = linesFor(MAX_FINDING_LINES + 4_000);
    expect(lines).toHaveLength(MAX_FINDING_LINES + 1);
    expect(lines[lines.length - 1]).toBe("  … and 4000 more");
  });
});

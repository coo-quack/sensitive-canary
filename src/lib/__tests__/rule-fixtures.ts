// What the rule tests share: the shipped rules read from disk, a key that is
// not AWS's documented one, and the two ways a scan is asked what it found.
//
// Read from `default-config.json` rather than from a list kept alongside it, so
// that a rule added or removed brings its cases with it instead of leaving a
// table to fall out of step.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { type RuleConfig, scan } from "../rules.ts";

// Not AWS's documented `…EXAMPLE` key, which the `aws-key` validator reads as
// documentation rather than a credential.
export const AWS_KEY = ["AKIA", "3QF7TZ9KLMN2", "PQRS"].join("");

export const DEFAULT_RULES: RuleConfig[] = (
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

export const ruleIds = (text: string): string[] =>
  scan(text).map((f) => f.ruleId);

export const finds = (text: string, ruleId: string): boolean =>
  ruleIds(text).includes(ruleId);

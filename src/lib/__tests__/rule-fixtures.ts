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

// Made-up tokens, joined at run time for the same reason as the key above:
// GitHub's push protection reads a literal in the source as a leaked
// credential and refuses the push.
export const DOCKER_PAT = ["dckr", "pat", "xEFv_Zi-yLNKnOyppRuS6X3wEJB"].join(
  "_",
);
export const STRIPE_DOCS_TEST_KEY = [
  "sk",
  "test",
  "4eC39HqLyjWDarjtT1zdp7dc",
].join("_");

// A run of one character is a placeholder to the rules (see isFillerBody in
// shapes.ts), so an example that needs a long value is built from a cycle of
// distinct characters rather than `"a".repeat(n)`. The cycles have no run longer
// than one, so they are not filler, and they stay in the alphabet the rule asks
// for: `hex` for the rules that take hexadecimal.
const cycle =
  (alphabet: string) =>
  (n: number): string => {
    let out = "";
    for (let i = 0; i < n; i++) out += alphabet[i % alphabet.length];
    return out;
  };
export const mixed = cycle("Xk9mP2qR7vL4nW1sYj3cBz8dEf5gHiKoNpQuTxMnA6bC0eFhJ");
export const hex = cycle("9f3a7c1e5b0d8f2a");

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

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// The six address rules are written by scripts/address-rules.mjs and pasted into
// default-config.json by its --write mode. Editing the config by hand would make
// the two disagree silently, since both are valid regex; this test is the check.
const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const SCRIPT = `${ROOT}scripts/address-rules.mjs`;
const CONFIG = `${ROOT}src/lib/default-config.json`;

const ADDRESS_IDS = [
  "pii-address-cn",
  "pii-address-kr",
  "pii-address-fr",
  "pii-address-it",
  "pii-address-de",
  "pii-address-es",
];

describe("the address rules in the config come from the generator", () => {
  const generated = JSON.parse(
    execFileSync(process.execPath, [SCRIPT], { encoding: "utf8" }),
  ) as Array<{
    id: string;
    description: string;
    regex: string;
    flags: string;
    category: string;
  }>;
  const configured = (
    JSON.parse(readFileSync(CONFIG, "utf8")) as { rules: Array<{ id: string }> }
  ).rules.filter((rule) => ADDRESS_IDS.includes(rule.id)) as typeof generated;

  it("generates exactly the six ids the config holds", () => {
    expect(generated.map((r) => r.id)).toEqual(ADDRESS_IDS);
    expect(configured.map((r) => r.id).sort()).toEqual([...ADDRESS_IDS].sort());
  });

  it.each(ADDRESS_IDS)(
    "%s in the config equals the generator's output",
    (id) => {
      const expected = generated.find((r) => r.id === id);
      const actual = configured.find((r) => r.id === id);
      expect(actual).toEqual(expected);
    },
  );
});

// Coverage the tables themselves guarantee.
//
// Twice now, a table gained an entry and the tests did not: `WRITE_FILE` went
// unexempt because the write-verb cases were a hand-picked few, and `sed -Ei` was
// misread because the valueless-switch set was shared and only the `perl` letters
// had cases. Both files list a handful of examples and looked thorough.
//
// So these cases are generated from the tables. Adding a verb or a switch letter
// without touching this file still produces a case for it, and removing one
// removes its case rather than leaving a stale assertion behind.

import { describe, expect, it } from "vitest";
import {
  isInPlaceFlag,
  VALUELESS_SHORT_SWITCHES,
} from "../lib/bash-commands.ts";
import { isWritingTool, WRITING_TOOL_VERBS } from "../lib/tool-inputs.ts";

const VERBS = [...WRITING_TOOL_VERBS];
const IN_PLACE_COMMANDS = Object.keys(VALUELESS_SHORT_SWITCHES);

describe("every write verb is exempt in every spelling", () => {
  it.each(VERBS)("%s", (verb) => {
    const upper = verb.toUpperCase();
    const camel = verb + "File";
    for (const name of [
      `${verb}_file`,
      `${upper}_FILE`,
      camel,
      `${verb}-file`,
      verb,
    ]) {
      expect(isWritingTool(name), name).toBe(true);
      expect(isWritingTool(`mcp__fs__${name}`), `mcp__fs__${name}`).toBe(true);
    }
  });

  // The verb has to lead. These are the shapes that used to slip through as
  // substring matches, generated per verb so no verb is checked in only one
  // direction.
  it.each(VERBS)("%s does not exempt a name it merely appears in", (verb) => {
    for (const name of [
      `read_and_${verb}_file`,
      `over${verb}_file`,
      `get_${verb}s`,
      `file_${verb}`,
    ]) {
      expect(isWritingTool(name), name).toBe(false);
    }
  });

  it("a server named for a verb does not exempt its read tools", () => {
    for (const verb of VERBS) {
      expect(isWritingTool(`mcp__${verb}__read_file`)).toBe(false);
    }
  });
});

describe("in-place flags, per command and per switch letter", () => {
  it.each(IN_PLACE_COMMANDS)("%s: -i and its long forms", (cmd) => {
    for (const flag of ["-i", "-i.bak", "--in-place", "--in-place=.bak"]) {
      expect(isInPlaceFlag(cmd, flag), `${cmd} ${flag}`).toBe(true);
    }
  });

  // Every letter the table calls valueless must let the reading reach the `i`,
  // in both orders, since a bundle can put it either side.
  it.each(IN_PLACE_COMMANDS)("%s: every valueless letter reaches -i", (cmd) => {
    for (const ch of VALUELESS_SHORT_SWITCHES[cmd] ?? "") {
      expect(isInPlaceFlag(cmd, `-${ch}i`), `${cmd} -${ch}i`).toBe(true);
      expect(isInPlaceFlag(cmd, `-i${ch}`), `${cmd} -i${ch}`).toBe(true);
    }
  });

  // A letter outside the table stops the reading, so the command counts as one
  // that prints and its operands are scanned. `e` is the case that matters: it
  // introduces a script, and a sed script uses `i` to insert.
  it.each(IN_PLACE_COMMANDS)("%s: an unlisted letter stops the read", (cmd) => {
    const valueless = VALUELESS_SHORT_SWITCHES[cmd] ?? "";
    for (const ch of "eEMmIFDCAKrz0123456789") {
      if (valueless.includes(ch)) continue;
      expect(isInPlaceFlag(cmd, `-${ch}i`), `${cmd} -${ch}i`).toBe(false);
    }
  });

  it.each(IN_PLACE_COMMANDS)("%s: a flag with no i is not in-place", (cmd) => {
    for (const flag of ["-p", "-n", "-pe", "--posix", "-", "notaflag"]) {
      expect(isInPlaceFlag(cmd, flag), `${cmd} ${flag}`).toBe(false);
    }
  });

  // The reported false negatives, named so a regression says which one broke.
  it.each([
    ["perl", "-MList::Util"],
    ["perl", "-Mstrict"],
    ["perl", "-Ilib"],
    ["ruby", "-Ilib"],
    ["sed", "-e"],
    ["sed", "-0i"],
  ])("%s %s is not an in-place edit", (cmd, flag) => {
    expect(isInPlaceFlag(cmd, flag)).toBe(false);
  });

  it.each([
    ["sed", "-Ei"],
    ["sed", "-ri"],
    ["sed", "-zi"],
    ["perl", "-pi"],
    ["perl", "-lpi"],
    ["perl", "-Ti"],
    ["ruby", "-pi"],
  ])("%s %s is an in-place edit", (cmd, flag) => {
    expect(isInPlaceFlag(cmd, flag)).toBe(true);
  });
});

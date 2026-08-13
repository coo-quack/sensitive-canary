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
  IN_PLACE_EDIT_COMMANDS,
  isInPlaceFlag,
  VALUELESS_SHORT_SWITCHES,
} from "../lib/bash-commands.ts";
import {
  collectPathFields,
  isWritingTool,
  PATH_FIELD_NAMES,
  WRITING_TOOL_VERBS,
} from "../lib/tool-inputs.ts";

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

// Invariants of the tables themselves.
//
// The generated cases above guarantee that every entry has a case. They cannot
// say whether an entry belongs: they assert what the table says, so a wrong entry
// is asserted as correct. Measured — injecting `e` into `sed`'s valueless
// switches, which would read a sed script's insert command as the in-place flag,
// passed all of them.
//
// These are the properties that hold regardless of what the tables contain, so
// they fail on a wrong entry rather than agreeing with it.
describe("table invariants", () => {
  // `e` introduces a script for all three commands. Reading past it walks into
  // program text, where `i` is sed's insert command.
  it.each(Object.keys(VALUELESS_SHORT_SWITCHES))(
    "%s does not treat -e as valueless",
    (cmd) => {
      expect(VALUELESS_SHORT_SWITCHES[cmd]).not.toContain("e");
    },
  );

  // A digit begins a value for `perl -0777` and is not a switch for the others.
  it.each(Object.keys(VALUELESS_SHORT_SWITCHES))(
    "%s treats no digit as valueless",
    (cmd) => {
      expect(VALUELESS_SHORT_SWITCHES[cmd]).not.toMatch(/[0-9]/);
    },
  );

  // Two tables decide in-place editing together: one says which commands do it,
  // the other how to read their bundles. A command in the first without a line in
  // the second reaches `-i` through an empty set, so a bare `-i` still counts and
  // a bundle never does. Adding `awk` to the first alone passed every other test.
  it("every in-place command has a line of valueless switches", () => {
    expect([...IN_PLACE_EDIT_COMMANDS].sort()).toEqual(
      Object.keys(VALUELESS_SHORT_SWITCHES).sort(),
    );
  });
});

// The two ways a value becomes a path candidate are independent, and a test that
// uses an absolute path exercises only the second. Removing `path` from the name
// list passed every hook-level case, because every fixture path contains a `/`
// and the shape rule collected it anyway.
describe("path fields are found by name, not only by shape", () => {
  it.each([...PATH_FIELD_NAMES])("%s collects a bare filename", (field) => {
    expect(collectPathFields({ [field]: "secrets.txt" })).toContain(
      "secrets.txt",
    );
  });

  it("a name outside the list does not collect a bare filename", () => {
    for (const field of ["target", "document", "uri", "query", "pattern"]) {
      expect(collectPathFields({ [field]: "secrets.txt" })).toEqual([]);
    }
  });
});

// Names the list must contain, written out rather than derived.
//
// The generated cases above walk `PATH_FIELD_NAMES`, so deleting an entry deletes
// its case and nothing fails — measured: removing `path` passed every test in the
// repository. A generated case catches a wrong entry once an invariant pins the
// shape; it can never catch a missing one. So this duplicates the list on
// purpose, and the duplication is the point: two copies that must agree.
describe("path field names that must not be dropped", () => {
  it.each([
    "path",
    "paths",
    "file",
    "files",
    "filepath",
    "filename",
    "absolutepath",
    "notebookpath",
  ])("%s is still a path field name", (name) => {
    expect(PATH_FIELD_NAMES.has(name)).toBe(true);
  });
});

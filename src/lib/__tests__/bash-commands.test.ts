// One case per entry of the command tables, generated from the tables.
//
// The tables were reached only through the hook, and only for the entries
// someone thought to write a case for. Measured on this tree: `zcat`, `tac`,
// `paste`, `fold`, `column`, `look`, `jq`, `yq`, `egrep`, `gawk`, `cksum`,
// `md5sum`, `annotate`, `cat-file`, `doas`, `builtin`, `exec`, `nohup`,
// `stdbuf`, `printf`, `true`, `false` and `:` could each be deleted from its
// table and the whole suite still passed.
//
// So the cases below walk the tables: an entry added brings its own case, an
// entry deleted takes its own away. That last property is why the equality
// assertions at the end are here too — a generated case cannot notice a
// deletion, and only the pair covers both directions.

import { describe, expect, it } from "vitest";
import {
  ARGUMENT_ONLY_COMMANDS,
  COUNT_ONLY_COMMANDS,
  extractCommandRefs,
  FILE_READ_COMMANDS,
  GIT_GLOBAL_FLAGS_WITH_OPERAND,
  GIT_READ_SUBCOMMANDS,
  INLINE_CODE_COMMANDS,
  INLINE_CODE_READS_OPERANDS,
  PATTERN_OR_SCRIPT_FIRST_COMMANDS,
  POSIX_SHELLS,
  WRAPPER_COMMANDS,
  WRITE_TARGET_FLAGS,
} from "../bash-commands.ts";

const paths = (command: string): string[] => extractCommandRefs(command).paths;

const FILE_READ_EXPECTED = [
  "base64",
  "bat",
  "bzcat",
  "bzless",
  "cat",
  "column",
  "comm",
  "cut",
  "diff",
  "expand",
  "fmt",
  "fold",
  "gzcat",
  "head",
  "hexdump",
  "iconv",
  "join",
  "less",
  "look",
  "lz4cat",
  "lzcat",
  "more",
  "nl",
  "od",
  "paste",
  "pr",
  "rev",
  "shuf",
  "sort",
  "strings",
  "tac",
  "tail",
  "unexpand",
  "uniq",
  "view",
  "vimdiff",
  "xxd",
  "xzcat",
  "xzless",
  "zcat",
  "zless",
  "zmore",
  "zstdcat",
];

describe("commands that print the files they are given", () => {
  it.each([...FILE_READ_COMMANDS])("%s names its operand", (cmd) => {
    expect(paths(`${cmd} secrets.txt`)).toContain("secrets.txt");
  });
});

describe("commands that only measure a file", () => {
  it.each([...COUNT_ONLY_COMMANDS])("%s does not name its operand", (cmd) => {
    expect(paths(`${cmd} secrets.txt`)).not.toContain("secrets.txt");
  });

  // Fed over `<` the file is not read either: these print counts and digests,
  // never the bytes.
  it.each([...COUNT_ONLY_COMMANDS])("%s does not name its stdin", (cmd) => {
    expect(paths(`${cmd} < secrets.txt`)).not.toContain("secrets.txt");
  });
});

describe("commands whose first operand is a pattern or a script", () => {
  it.each([...PATTERN_OR_SCRIPT_FIRST_COMMANDS])(
    "%s takes the first operand as the pattern and the second as a file",
    (cmd) => {
      const found = paths(`${cmd} pattern secrets.txt`);
      expect(found).toContain("secrets.txt");
      expect(found).not.toContain("pattern");
    },
  );
});

// A searcher given no file searches where it runs. `rg PATTERN` is the ordinary
// way to search a repository and names nothing, so there is no operand to
// collect and the tree it prints from went unaccounted for.
describe("a search that names no file", () => {
  const searchesCwd = (command: string): boolean =>
    extractCommandRefs(command).searchesWorkingDirectory;

  it.each(["rg", "ag", "ack", "ugrep"])("%s alone searches here", (cmd) => {
    expect(searchesCwd(`${cmd} pattern`)).toBe(true);
  });

  it.each(["rg", "ag", "ack", "ugrep"])(
    "%s with a path named does not",
    (cmd) => {
      expect(searchesCwd(`${cmd} pattern src/`)).toBe(false);
    },
  );

  // `grep` reads stdin unless it is asked to recurse, so the flag is what puts
  // it in this class, one command at a time.
  it.each(["grep -r", "grep -R", "grep --recursive", "grep -rn", "grep -in"])(
    "`%s pattern` is judged on whether it recurses",
    (prefix) => {
      expect(searchesCwd(`${prefix} pattern`)).toBe(prefix !== "grep -in");
    },
  );

  it("a plain grep reads stdin rather than the tree", () => {
    expect(searchesCwd("grep pattern")).toBe(false);
  });

  it("a recursive grep with a path named does not search here", () => {
    expect(searchesCwd("grep -r pattern src/")).toBe(false);
  });

  it("a flag after -- is an operand, not a request to recurse", () => {
    expect(searchesCwd("grep pattern -- -r")).toBe(false);
  });
});

describe("wrappers", () => {
  it.each([...WRAPPER_COMMANDS])(
    "%s is stepped past to reach the command it runs",
    (wrapper) => {
      expect(paths(`${wrapper} cat secrets.txt`)).toContain("secrets.txt");
    },
  );

  // `timeout` and `flock` take an operand of their own before the wrapped
  // command. The case above never writes one, so it says nothing about the form
  // people actually type — and these two are why the search steps forward to the
  // first name it can classify rather than assuming the next token.
  it.each([
    "timeout 5 cat secrets.txt",
    "timeout --preserve-status 5 cat secrets.txt",
    "flock /tmp/lock cat secrets.txt",
  ])("%s reaches the wrapped command", (command) => {
    expect(paths(command)).toContain("secrets.txt");
  });
});

describe("commands that print their arguments rather than open them", () => {
  it.each([...ARGUMENT_ONLY_COMMANDS])(
    "%s stops the search past a wrapper",
    (cmd) => {
      expect(paths(`sudo ${cmd} cat secrets.txt`)).not.toContain("secrets.txt");
    },
  );
});

describe("git subcommands that print file contents", () => {
  it.each([...GIT_READ_SUBCOMMANDS])("git %s names its operand", (sub) => {
    expect(paths(`git ${sub} secrets.txt`)).toContain("secrets.txt");
  });

  // `git log` is the subcommand that is not one of these unless a patch is
  // asked for, and each flag that asks for one is its own way in.
  it.each(["-p", "--patch", "-u", "-U3", "--unified=3", "-c", "-m", "--cc"])(
    "git log %s names its operand",
    (flag) => {
      expect(paths(`git log ${flag} secrets.txt`)).toContain("secrets.txt");
    },
  );

  it("git log without a patch flag names nothing", () => {
    expect(paths("git log secrets.txt")).not.toContain("secrets.txt");
  });
});

describe("redirection into a command", () => {
  it("stdin over < is read", () => {
    expect(paths("cat < secrets.txt")).toContain("secrets.txt");
  });

  // `<<` and `<<<` are not stdin redirections: the first opens a heredoc whose
  // delimiter is a word, the second carries its text inline. Reading any token
  // beginning with `<` as the redirection collected the delimiter as a path.
  it.each(["cat <<EOF", "cat <<-EOF", "grep x <<< secrets.txt"])(
    "%s names no path from the delimiter",
    (command) => {
      expect(paths(command)).toEqual([]);
    },
  );
});

// Three tables in this file had no case generated from them, and deleting an
// entry from any of them passed the whole suite. Two of those deletions are
// missed reads: without `--namespace`, `git --namespace ns show <secret>` reads
// `ns` as the subcommand and never collects the file; without `php`,
// `php -r 'echo file_get_contents("<secret>")'` is not parsed at all.
describe("tables that had no cases", () => {
  it.each([...INLINE_CODE_COMMANDS])(
    "%s carries inline code that is scanned",
    (cmd) => {
      // `-c` is the one flag every one of them spells the same way, apart from
      // the two that read `-e`/`-r` instead; those are covered per command below.
      const flag = cmd === "php" ? "-r" : "-c";
      expect(paths(`${cmd} ${flag} 'x = open("secrets.txt")'`)).toContain(
        "secrets.txt",
      );
    },
  );

  it.each([...INLINE_CODE_READS_OPERANDS])(
    "%s -e also reads the operands after the program",
    (cmd) => {
      expect(paths(`${cmd} -e 'print' secrets.txt`)).toContain("secrets.txt");
    },
  );

  // A shell's `-e` is errexit, not a program. Every entry here has to keep that
  // apart from `-c`, or `sh -e script.sh` gets parsed as inline code.
  it.each([...POSIX_SHELLS])("%s tells -e from -c", (shell) => {
    expect(paths(`${shell} -e script.sh`)).not.toContain("script.sh");
    expect(paths(`${shell} -c 'cat secrets.txt'`)).toContain("secrets.txt");
  });

  it.each([...GIT_GLOBAL_FLAGS_WITH_OPERAND])(
    "git %s <value> does not swallow the subcommand",
    (flag) => {
      expect(paths(`git ${flag} value show secrets.txt`)).toContain(
        "secrets.txt",
      );
    },
  );

  it.each(
    Object.entries(WRITE_TARGET_FLAGS).flatMap(([cmd, flags]) =>
      [...flags].map((flag) => [cmd, flag] as const),
    ),
  )("%s %s names a file written, not read", (cmd, flag) => {
    const found = paths(`${cmd} ${flag} out.txt secrets.txt`);
    expect(found).not.toContain("out.txt");
    expect(found).toContain("secrets.txt");
  });
});

describe("a redirection before the command", () => {
  // The operator is skipped as a non-command token, but its target is an
  // ordinary word: `secrets` was taken for the command name, the real command
  // went unclassified, and none of its operands were collected.
  it.each(["< secrets.txt cat", "<secrets.txt sort", "< secrets.txt grep aws"])(
    "%s names the file",
    (command) => {
      expect(paths(command)).toContain("secrets.txt");
    },
  );

  it("a command that prints no contents still names nothing", () => {
    expect(paths("< secrets.txt wc -l")).not.toContain("secrets.txt");
  });
});

describe("holes an adversarial pass found", () => {
  // A shell bundles its switches: `bash -lc '…'` runs the string `bash -c`
  // would, and only the exact spelling was recognised.
  it.each(["bash -lc", "sh -ec", "zsh -lc", "dash -xc", "ksh -ic"])(
    "%s carries inline code",
    (prefix) => {
      expect(paths(`${prefix} 'cat secrets.txt'`)).toContain("secrets.txt");
    },
  );

  // The letters before the `c` have to be valueless switches, or the `c` belongs
  // to something else.
  it("a shell flag that is not a bundle ending in -c is not inline code", () => {
    expect(paths("bash -e script.sh")).not.toContain("script.sh");
    expect(paths("bash --rcfile script.sh")).not.toContain("script.sh");
  });

  // `eval` runs its arguments as a command line.
  it("eval is stepped past to the command it runs", () => {
    expect(paths("eval cat secrets.txt")).toContain("secrets.txt");
  });

  // `$(<f)` has no command at all: bash reads the file and substitutes it.
  it.each(["echo $(<secrets.txt)", "x=$(< secrets.txt)"])(
    "%s reads the file",
    (command) => {
      expect(paths(command)).toContain("secrets.txt");
    },
  );

  // An awk or sed program can name a file inside itself.
  it("a quoted literal inside an awk program is a path candidate", () => {
    expect(
      paths(`awk 'BEGIN{while((getline l < "secrets.txt")>0) print l}'`),
    ).toContain("secrets.txt");
  });
});

// A substitution standing among the operands is one word to the command. Ending
// the segment there cut the operand list in two, and the file after it was read
// as a command name — a fail-open behind a comment that called it harmless.
// A leading `VAR=value` is not the command. The pattern accepts a lower-case
// name, and every case in the suite used an upper-case one, so narrowing it to
// `[A-Z_]` went unnoticed — `foo=1 cat secrets` then classified `foo=1` as the
// command and collected nothing.
describe("a leading assignment", () => {
  it.each([
    "FOO=1 cat secrets.txt",
    "foo=1 cat secrets.txt",
    "_x=1 cat secrets.txt",
    "a1=1 cat secrets.txt",
    "foo=1 bar=2 cat secrets.txt",
  ])("%s still reaches the command", (command) => {
    expect(paths(command)).toContain("secrets.txt");
  });
});

describe("a substitution among the operands", () => {
  it.each([
    "cat <(echo hi) secrets.txt",
    "cat $(echo hi) secrets.txt",
    "diff <(sort a.txt) secrets.txt",
    "paste <(echo 1) secrets.txt",
    "grep pat <(echo x) secrets.txt",
  ])("%s still names the file after it", (command) => {
    expect(paths(command)).toContain("secrets.txt");
  });

  // The inner command is still walked, by extractSubstitutions.
  it("the command inside the substitution is read too", () => {
    expect(paths("diff <(cat inner.txt) outer.txt")).toEqual(
      expect.arrayContaining(["inner.txt", "outer.txt"]),
    );
  });

  // A subshell is a command line of its own and still ends the segment.
  it("a subshell is still its own segment", () => {
    expect(paths("(cat secrets.txt)")).toContain("secrets.txt");
  });
});

// A `)` inside quotes does not close a substitution. Ending the segment there
// lost the rest of the command, and with it whatever it read.
describe("a substitution containing a quoted bracket", () => {
  it.each([
    'echo $(cat ")" secrets.txt)',
    "echo $(cat ')' secrets.txt)",
    'echo $(grep -e ")" secrets.txt)',
    'echo $(cat "(" secrets.txt)',
  ])("%s still names the file", (command) => {
    expect(paths(command)).toContain("secrets.txt");
  });
});

describe("cd", () => {
  // `cd` into somewhere that is not there does not move the shell, so the read
  // that follows happens where it started. Following it anyway left relative
  // paths resolving against a directory that does not exist, and so unscanned.
  it("a cd into a directory that does not exist does not move the base", () => {
    expect(paths("cd /definitely-not-here && cat secrets.txt")).toContain(
      "secrets.txt",
    );
  });

  // An unexpanded variable names an unknown directory, so the base is unknown
  // too. Guessing it is the same failure in a different place.
  it("a cd through a variable does not move the base", () => {
    expect(paths("cd $TARGET && cat secrets.txt")).toContain("secrets.txt");
  });
});

describe("eval", () => {
  // `eval 'cat secrets'` is a command line in a single word. Stepping past
  // `eval` found that word as the command name, which classifies as nothing.
  it.each([
    "eval cat secrets.txt",
    `eval 'cat secrets.txt'`,
    `eval "cat secrets.txt"`,
    `eval "cd /tmp && cat secrets.txt"`,
  ])("%s names the file", (command) => {
    expect(paths(command)).toContain("secrets.txt");
  });
});

describe("git log -L", () => {
  // `-L` prints the lines themselves, and the file is written inside the range
  // spec after the last `:`, where neither the flag branch nor the operand
  // branch would have looked for it.
  it.each([
    "git log -L1,10:secrets.txt",
    "git log -L 1,10:secrets.txt",
    "git log --line-range=1,10:secrets.txt",
    "git log -L:funcname:secrets.txt",
  ])("%s names the file in the range", (command) => {
    expect(paths(command)).toContain("secrets.txt");
  });

  it("a range with no file names nothing", () => {
    expect(paths("git log -L1,10")).toEqual([]);
  });
});

describe("inline code", () => {
  it("a quoted literal inside perl -e is a path candidate", () => {
    expect(paths(`perl -e 'open(F, "secrets.txt")'`)).toContain("secrets.txt");
  });

  // A shell's `-e` is not an inline-code flag — `bash -e script.sh` sets
  // errexit and runs a file. Treating it as one parsed the filename as a
  // program.
  it.each(["sh", "bash", "zsh", "dash", "ksh"])(
    "%s -e is errexit, not a script to parse",
    (shell) => {
      expect(paths(`${shell} -e script.sh`)).not.toContain("script.sh");
    },
  );

  // `--` ends option parsing for the in-place test too: in `sed -- -i secrets`,
  // `-i` is the script and `secrets` is a file sed prints.
  it("sed -- -i reads its operand rather than editing in place", () => {
    expect(paths("sed -- -i secrets.txt")).toContain("secrets.txt");
  });

  it("sed -i without the -- still edits in place", () => {
    expect(paths("sed -i 's/a/b/' secrets.txt")).not.toContain("secrets.txt");
  });

  it("a shell's -c is still inline code", () => {
    expect(paths(`bash -c 'cat secrets.txt'`)).toContain("secrets.txt");
  });
});

// The tables written out. The generated cases above follow them wherever they
// go, which is what makes an equality necessary rather than redundant: without
// one, deleting an entry deletes its own case and nothing fails.
describe("the tables", () => {
  // Measured: with only the three equalities below, deleting `zcat` from this
  // one still passed all 820 cases. Deleting a read command is the fail-open
  // direction — the command stops being one whose operands are scanned.
  it("commands that print their file operands are exactly these", () => {
    expect([...FILE_READ_COMMANDS].sort()).toEqual(FILE_READ_EXPECTED);
  });

  it("pattern-first commands are exactly these", () => {
    expect([...PATTERN_OR_SCRIPT_FIRST_COMMANDS].sort()).toEqual([
      "ack",
      "ag",
      "awk",
      "egrep",
      "fgrep",
      "gawk",
      "grep",
      "jq",
      "rg",
      "sed",
      "ugrep",
      "yq",
      "zegrep",
      "zfgrep",
      "zgrep",
    ]);
  });

  it("wrappers are exactly these", () => {
    expect([...WRAPPER_COMMANDS].sort()).toEqual([
      "builtin",
      "command",
      "doas",
      "env",
      "eval",
      "exec",
      "flock",
      "ionice",
      "nice",
      "nohup",
      "stdbuf",
      "sudo",
      "time",
      "timeout",
      "xargs",
    ]);
  });

  it("count-only commands are exactly these", () => {
    expect([...COUNT_ONLY_COMMANDS].sort()).toEqual([
      "b2sum",
      "cksum",
      "md5",
      "md5sum",
      "sha1sum",
      "sha224sum",
      "sha256sum",
      "sha384sum",
      "sha512sum",
      "shasum",
      "sum",
      "wc",
    ]);
  });

  it("commands that print their arguments are exactly these", () => {
    expect([...ARGUMENT_ONLY_COMMANDS].sort()).toEqual([
      ":",
      "echo",
      "false",
      "printf",
      "true",
    ]);
  });

  it("git global flags taking a value are exactly these", () => {
    expect([...GIT_GLOBAL_FLAGS_WITH_OPERAND].sort()).toEqual([
      "--config-env",
      "--exec-path",
      "--git-dir",
      "--namespace",
      "--work-tree",
      "-C",
      "-c",
    ]);
  });

  it("commands taking inline code are exactly these", () => {
    expect([...INLINE_CODE_COMMANDS].sort()).toEqual([
      "bash",
      "bun",
      "dash",
      "deno",
      "ksh",
      "node",
      "perl",
      "php",
      "python",
      "python3",
      "ruby",
      "sh",
      "zsh",
    ]);
  });

  it("the write-target flags are exactly these", () => {
    expect(WRITE_TARGET_FLAGS).toEqual({
      sort: new Set(["-o", "--output"]),
      shuf: new Set(["-o", "--output"]),
      iconv: new Set(["-o", "--output"]),
    });
  });

  // The inline-code branch does not mark a pattern as supplied, because there is
  // no command where both would apply. If that stops being true, the branch
  // needs the mark back and this is where it says so.
  // A name in both tables would be read as printing its operands in one place
  // and as printing nothing in another, and the two disagree at the point of use.
  it("no command both prints its operands and only measures them", () => {
    const both = [...FILE_READ_COMMANDS].filter((c) =>
      COUNT_ONLY_COMMANDS.has(c),
    );
    expect(both).toEqual([]);
  });

  it("no command takes inline code and a leading pattern", () => {
    const both = [...INLINE_CODE_COMMANDS].filter((c) =>
      PATTERN_OR_SCRIPT_FIRST_COMMANDS.has(c),
    );
    expect(both).toEqual([]);
  });

  it("the shells are exactly these", () => {
    expect([...POSIX_SHELLS].sort()).toEqual([
      "bash",
      "dash",
      "ksh",
      "sh",
      "zsh",
    ]);
  });

  it("the interpreters whose inline code reads operands are exactly these", () => {
    expect([...INLINE_CODE_READS_OPERANDS].sort()).toEqual(["perl", "ruby"]);
  });

  it("git read subcommands are exactly these", () => {
    expect([...GIT_READ_SUBCOMMANDS].sort()).toEqual([
      "annotate",
      "blame",
      "cat-file",
      "diff",
      "grep",
      "show",
    ]);
  });
});

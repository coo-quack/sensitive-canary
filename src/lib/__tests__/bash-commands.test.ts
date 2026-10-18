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
import { extractCommandRefs } from "../bash-commands.ts";
import {
  ARCHIVE_WRITING_COMMANDS,
  ARGUMENT_ONLY_COMMANDS,
  COPY_COMMANDS,
  COUNT_ONLY_COMMANDS,
  commandName,
  FILE_READ_COMMANDS,
  GIT_GLOBAL_FLAGS_WITH_OPERAND,
  GIT_READ_SUBCOMMANDS,
  INLINE_CODE_COMMANDS,
  INLINE_CODE_READS_OPERANDS,
  PATTERN_OR_SCRIPT_FIRST_COMMANDS,
  POSIX_SHELLS,
  TAR_COMMANDS,
  TARGET_DIRECTORY_COMMANDS,
  WRAPPER_COMMANDS,
  WRITE_TARGET_FLAGS,
} from "../command-tables.ts";

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

// The default reading splits `2>&1` and `&>` at the `&`, so the file after them
// is a segment of its own and goes unread. The joined reading keeps the
// operator whole. Both are scanned, so each case here is a file the default
// alone misses.
describe("redirections that bash joins to their operator", () => {
  it.each([
    "cat 2>&1 .env",
    "cat &>/dev/null .env",
    "cat 2>|/dev/null .env",
    "cat >|/dev/stdout .env",
    "cat 2>\\\n&1 .env",
    "cat >\\\n|/dev/stdout .env",
    "cat &\\\n>/dev/stdout .env",
    // bash closes descriptor 2 at the `-` and reads `.env` as the next word.
    "cat 2>&-.env",
  ])("collects the file in %j", (command) => {
    expect(paths(command)).toContain(".env");
  });

  it("collects the config file after 2>&1 in a head", () => {
    expect(paths("head -n 50 2>&1 secrets.yml")).toContain("secrets.yml");
  });

  // POSIX sh runs `cat .env` here: `&>/dev/stdout` is `&`, then `>/dev/stdout`.
  // The default reading must keep that split, so the joined one cannot
  // replace it.
  it("still collects the command dash runs after &>", () => {
    expect(paths("dash -c 'true &>/dev/stdout cat .env'")).toContain(".env");
  });

  // The target of `>&` is a write, and the operand after it is not. Taking the
  // digit as a descriptor prefix of `>` made out.txt a file to read.
  it("does not collect the write target of 2>&1>out.txt", () => {
    expect(paths("cat plain.txt 2>&1>out.txt")).toEqual(["plain.txt"]);
  });

  it("does not collect the write target of 2>&1 >out.txt", () => {
    expect(paths("cat plain.txt 2>&1 >out.txt")).toEqual(["plain.txt"]);
  });

  it("names no path for echo hi >&2", () => {
    expect(paths("echo hi >&2")).toEqual([]);
  });

  it("does not collect the descriptor 3 of <&3 as a file", () => {
    expect(paths("cat <&3")).toEqual([]);
  });

  // Not a path case. The joined reading sees `cat f` as the command after env,
  // so it is not a dump. The default reading still sees a bare `env` and
  // reports the dump, and the merge keeps that verdict.
  it("keeps the environment dump verdict of env 2>&1 cat f", () => {
    expect(extractCommandRefs("env 2>&1 cat f").dumpsEnvironment).toBe(true);
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

// A copy reads what it copies, and an archive reads what goes into it. The
// destination is neither, and neither is the archive's own name or the directory
// `-C` changes to.
describe("copy and archive commands read their sources", () => {
  it.each([...COPY_COMMANDS])(
    "%s reads its source and not its destination",
    (cmd) => {
      const found = paths(`${cmd} secrets.txt copy.txt`);
      expect(found).toContain("secrets.txt");
      expect(found).not.toContain("copy.txt");
    },
  );

  // Every entry of the table has its own case, so a name deleted from it takes
  // its case with it and the equality below notices.
  it.each([...TARGET_DIRECTORY_COMMANDS])(
    "%s -t DIR reads every operand as a source",
    (cmd) => {
      const found = paths(`${cmd} -t backup secrets.txt other.txt`);
      expect(found).toContain("secrets.txt");
      expect(found).toContain("other.txt");
      expect(found).not.toContain("backup");
    },
  );

  it.each([
    "cp --target-directory=backup secrets.txt",
    "cp -rt backup secrets.txt",
    "cp -tbackup secrets.txt",
    "mv --target-directory backup secrets.txt",
  ])("%s reads every operand as a source", (command) => {
    expect(paths(command)).toContain("secrets.txt");
  });

  it.each([
    "tar -cf out.tar secrets.txt",
    "tar -czf out.tgz secrets.txt",
    "tar -c -f out.tar secrets.txt",
    "tar -f out.tar -c secrets.txt",
    "tar --create --file=out.tar secrets.txt",
    "tar cf out.tar secrets.txt",
  ])("%s reads the file it archives", (command) => {
    const found = paths(command);
    expect(found).toContain("secrets.txt");
    expect(found).not.toContain("out.tar");
    expect(found).not.toContain("out.tgz");
  });

  it.each([...TAR_COMMANDS])(
    "%s creates an archive from its operands",
    (cmd) => {
      const found = paths(`${cmd} -cf out.tar secrets.txt`);
      expect(found).toContain("secrets.txt");
      expect(found).not.toContain("out.tar");
    },
  );

  it("zip reads the files after the archive's name", () => {
    const found = paths("zip -r out.zip secrets.txt");
    expect(found).toContain("secrets.txt");
    expect(found).not.toContain("out.zip");
  });

  it.each([
    "tar -xf out.tar secrets.txt",
    "tar -tf out.tar",
    "tar xf out.tar secrets.txt",
    "bsdtar -xf out.tar secrets.txt",
  ])("%s does not read its operands", (command) => {
    expect(paths(command)).not.toContain("secrets.txt");
  });

  // `-C DIR` makes the names after it relative to DIR, and each `-C` applies to
  // what follows it.
  it.each([
    ["tar -cf o.tar -C sub creds.txt", "sub/creds.txt"],
    ["tar -cf o.tar -C a -C b creds.txt", "a/b/creds.txt"],
    ["tar -cf o.tar --directory=/work creds.txt", "/work/creds.txt"],
    ["tar -C /work -cf o.tar creds.txt", "/work/creds.txt"],
  ])("%s reads %s", (command, expected) => {
    expect(paths(command)).toContain(expected);
  });

  it("the directory of a later -C is relative to the one before it", () => {
    expect(paths("tar -cf o.tar -C /a -C ../b creds.txt")).toContain(
      "/b/creds.txt",
    );
  });

  // The list is a file that names files. Its own name is read as a file, and the
  // names it holds are the list's to read, which the hook does.
  it.each([
    "tar -cf o.tar -T list.txt",
    "tar -cf o.tar --files-from=list.txt",
    "bsdtar -cf o.tar -T list.txt",
    "gtar -cf o.tar --files-from list.txt",
  ])("%s reads the list file and names it for reading", (command) => {
    expect(paths(command)).toContain("list.txt");
    expect(extractCommandRefs(command).lists).toEqual([
      { file: "list.txt", dirs: [""] },
    ]);
  });

  it("a list named after -C is relative to that directory", () => {
    expect(
      extractCommandRefs("tar -cf o.tar -C sub -T list.txt").lists,
    ).toEqual([{ file: "sub/list.txt", dirs: ["sub"] }]);
  });

  it("rsync --files-from names files relative to the current directory and each source", () => {
    expect(
      extractCommandRefs("rsync --files-from=list.txt src/ dst/").lists,
    ).toEqual([{ file: "list.txt", dirs: ["", "src/"] }]);
  });

  it("a list read from standard input names nothing", () => {
    expect(extractCommandRefs("tar -cf o.tar -T -").lists).toEqual([]);
  });
});

// The tables written out. The generated cases above follow them wherever they
// go, which is what makes an equality necessary rather than redundant: without
// one, deleting an entry deletes its own case and nothing fails.
describe("the tables", () => {
  it("copy commands are exactly these", () => {
    expect([...COPY_COMMANDS].sort()).toEqual([
      "cp",
      "install",
      "ln",
      "mv",
      "rsync",
    ]);
  });

  it("commands whose -t names the destination are exactly these", () => {
    expect([...TARGET_DIRECTORY_COMMANDS].sort()).toEqual([
      "cp",
      "install",
      "ln",
      "mv",
    ]);
  });

  it("commands that write an archive from their operands are exactly these", () => {
    expect([...ARCHIVE_WRITING_COMMANDS].sort()).toEqual([
      "bsdtar",
      "gtar",
      "tar",
      "zip",
    ]);
  });

  it("the tar family is exactly these", () => {
    expect([...TAR_COMMANDS].sort()).toEqual(["bsdtar", "gtar", "tar"]);
  });

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

// A comment is not a command. A quote, backquote, substitution, heredoc
// operator or trailing backslash inside one used to fold the lines after it into
// a single word, and even a plain one was read as arguments. The second
// reading, which blanks the comment, is what finds the files those lines name
// and what the command does without its comment.
describe("comments", () => {
  it.each([
    "# Check what's configured\ncat .env",
    '# "x\ncat .env',
    "(( 1 ))# it's\ncat .env",
    "case x in x)# it's\n cat .env;; esac",
    "f()# it's\n{ cat .env; }; f",
    // A backslash ends nothing in a comment; read as a continuation, it joined
    // the next line to the comment.
    "# note \\\ncat .env",
  ])("%j reads the .env it names after the comment", (command) => {
    expect(paths(command)).toContain(".env");
  });

  it("reads the file named after a comment that opens a heredoc", () => {
    expect(paths("# usage: cat <<EOF\ncat secrets.txt")).toContain(
      "secrets.txt",
    );
  });

  it("reads the file after a comment that opens with a word", () => {
    expect(paths("ls # it's here\ncat secrets.txt")).toContain("secrets.txt");
  });

  // The comment's own words are not operands. `.env` in the comment is not
  // read, and the paths are what develop gave, so the second reading added
  // nothing for this command.
  it("does not read a name that appears only in a comment", () => {
    expect(paths("cat notes.md # don't print .env")).toEqual([
      "notes.md",
      "#",
      "dont print .env",
    ]);
    expect(paths("cat notes.md # don't print .env")).not.toContain(".env");
  });

  // A bare printenv dumps the environment, and the comment is not an argument
  // that would name a variable. The variable names come out as develop reads
  // them.
  it("does not name variables from a comment after printenv", () => {
    const refs = extractCommandRefs("printenv # it's HOME");
    expect(refs.envVars).toEqual(["#", "its HOME"]);
    expect(refs.dumpsEnvironment).toBe(true);
  });

  // A comment's words are not arguments, so the command reads as it would
  // without the comment. The first reading's refs stay — the comment's words
  // among them — because merging only adds; what the second reading adds is
  // what the comment had hidden.
  it.each([
    ["env # list", { envVars: [], dumpsEnvironment: true }],
    ["env\t# list", { envVars: [], dumpsEnvironment: true }],
    ["env FOO=1 # set one", { envVars: [], dumpsEnvironment: true }],
    ["env -u HOME # unset one", { envVars: [], dumpsEnvironment: true }],
    ["printenv # all", { envVars: ["#", "all"], dumpsEnvironment: true }],
    ["sudo printenv # as root", { dumpsEnvironment: true }],
    ["timeout 5 env # bounded", { dumpsEnvironment: true }],
    ["env # list\nls", { dumpsEnvironment: true }],
    ["ls # first\nenv # then", { dumpsEnvironment: true }],
    ["env | sort # sorted", { dumpsEnvironment: true }],
  ])("%j dumps the environment", (command, expected) => {
    expect(extractCommandRefs(command)).toMatchObject(expected);
  });

  it.each([
    "rg TODO # find todos",
    "grep -r foo # search",
    "grep -rn foo # numbered",
    "rg TODO # it's here",
  ])("%j searches the working directory", (command) => {
    expect(extractCommandRefs(command).searchesWorkingDirectory).toBe(true);
  });

  // The other direction: blanking the comment of a command that already says
  // what it does finds no dump or search, so the cases above are not passing on
  // every commented command now reading as one. The comment's words stay among
  // the first reading's refs, as `printenv HOME # one` shows.
  it.each([
    ["env FOO=1 ls # run ls", { dumpsEnvironment: false }],
    ["env -i FOO=1 # empty start", { dumpsEnvironment: false }],
    ["env -S 'echo hi' # split", { dumpsEnvironment: false }],
    [
      "printenv HOME # one",
      { envVars: ["HOME", "#", "one"], dumpsEnvironment: false },
    ],
    ["grep -r foo src # named", { searchesWorkingDirectory: false }],
    ["rg TODO docs # named", { searchesWorkingDirectory: false }],
    ["ls # list", { dumpsEnvironment: false, searchesWorkingDirectory: false }],
    ["echo '# env' # quoted", { dumpsEnvironment: false }],
    ["echo env#x", { dumpsEnvironment: false }],
  ])("%j gains no dump or search from its comment", (command, expected) => {
    expect(extractCommandRefs(command)).toMatchObject(expected);
  });

  it("does not read a dump that only a comment names", () => {
    expect(extractCommandRefs("ls # env").dumpsEnvironment).toBe(false);
    expect(extractCommandRefs("ls # printenv").dumpsEnvironment).toBe(false);
  });

  it("does not treat a # inside a substitution's word as a comment", () => {
    expect(paths("echo $(date)#x")).toEqual([]);
  });

  it("does not treat a # inside quotes as a comment", () => {
    expect(paths("echo '# not a comment'; cat x")).toEqual(["x"]);
  });

  it("does not treat a comment-like line inside a heredoc body as a comment", () => {
    expect(paths("cat > s.sh <<'EOF'\n# it's\ncat .env\nEOF")).toEqual([]);
  });
});

// The shell's own listings print the environment as `env` does. Measured with
// a secret exported into a clean environment: every case in the first table
// printed it in bash 5, zsh 5 or both, no case in the second printed it in
// either, and in the third each named variable was printed by at least one
// shell except where the table names none.
describe("shell builtins that list variables", () => {
  it.each([
    "export",
    "export -p",
    "export -n",
    "set",
    "set > vars.txt",
    "set | grep KEY",
    "declare",
    "declare -p",
    "declare -x",
    "declare -px",
    "declare -xp",
    "typeset",
    "typeset -p",
    "typeset -x",
    "local",
    "builtin declare -p",
    "command export -p",
    "if true; then set; fi",
    "ls && export -p",
    "echo $(declare -px)",
    "bash -c 'export -p'",
    "export -p # all of them",
    "export --",
    "typeset -m 'TOK*'",
    "declare -m 'TOK*'",
    "time export -p",
    "time set",
    "command -p export -p",
    "command -- set",
    "builtin -- set",
    "noglob set",
    "nocorrect export -p",
    'v=TOKEN; declare -p "$v"',
    "typeset -p ${!TOK*}",
  ])("%j dumps the environment", (command) => {
    expect(extractCommandRefs(command).dumpsEnvironment).toBe(true);
  });

  it.each([
    "export FOO=bar",
    "export FOO",
    "export PATH=$PATH:/opt/bin",
    "set -o",
    "set -e",
    "set -- a b",
    "set --",
    "set -euo pipefail",
    "declare -f",
    "declare -F",
    "typeset -f",
    "declare -a list",
    "declare FOO=1",
    "command -v set",
    "command -v export",
    "command -V set",
    "time ls",
    "builtin",
    "echo set",
    "echo export -p",
    "ls set",
  ])("%j does not dump the environment", (command) => {
    expect(extractCommandRefs(command).dumpsEnvironment).toBe(false);
  });

  // Given names, the listing prints only those, so only those are scanned. A
  // plain `export NAME` exports it and prints nothing.
  it.each([
    ["declare -p TOKEN", ["TOKEN"]],
    ["declare TOKEN", ["TOKEN"]],
    ["typeset TOKEN", ["TOKEN"]],
    ["typeset -p TOKEN OTHER", ["TOKEN", "OTHER"]],
    ["local TOKEN", ["TOKEN"]],
    ["export -p TOKEN", ["TOKEN"]],
    ["declare -p TOKEN > out.txt", ["TOKEN"]],
    ["declare FOO=1 TOKEN", ["TOKEN"]],
    ["declare -p -- TOKEN", ["TOKEN"]],
    ["export TOKEN", []],
    ["export TOKEN=1", []],
  ])("%j names %j", (command, named) => {
    const refs = extractCommandRefs(command);
    expect(refs.dumpsEnvironment).toBe(false);
    expect(refs.envVars).toEqual(named);
  });
});

// A function body behind the `function` keyword, and a program a shell or
// interpreter reads on stdin: what an echo or printf pipes into it, a
// here-string, or a heredoc. Every dump below prints the environment's values
// in bash 5 or zsh 5, apart from `echo 'env\nls' | bash`, which only zsh's
// echo turns into two lines; reading it as two can only add scanning.
describe("programs a command line hands to a shell", () => {
  it.each([
    "function f { env; }; f",
    "function f() { env; }; f",
    "function f { export -p; }; f",
    "function f {\n  printenv\n}",
    "echo env | bash",
    "echo 'export -p' | sh",
    "echo env |& bash",
    "echo env | sudo bash",
    "echo -n env | zsh",
    "printf '%s\\n' env | sh",
    "printf 'env\\n' | sh",
    "printf '%s' env | sh",
    "printf 'e%sv' n | bash",
    "printf '%s\\n' ls env | sh",
    "printf -- '%s' env | sh",
    "printf '%s%s\\n' e nv ls '' | sh",
    "printf 'e\\156v' | bash",
    "printf '\\x65nv' | bash",
    "echo -e '\\x65nv' | bash",
    "echo -e '\\0145nv' | bash",
    "echo env | source /dev/stdin",
    "echo env | . /dev/stdin",
    "echo 'env\\nls' | zsh",
    "{ echo env; } | bash",
    "(echo env) | bash",
    "echo env | (bash)",
    "echo env | bash -s",
    "bash <<< env",
    "<<< env bash",
    "bash <<< 'set'",
    "bash <<'EOF'\nenv\nEOF",
    "bash <<-EOF\n\tprintenv\n\tEOF",
    "sh <<EOF\nexport -p\nEOF",
    "bash <<EOF\nenv",
    "cat > s.sh <<'A'; bash <<'B'\nls\nA\nenv\nB",
    "cat <<'EOF' | bash\nenv\nEOF",
    "cat <<< env | sh",
    "{ cat <<X; } | bash\nprintenv\nX",
  ])("%j dumps the environment", (command) => {
    expect(extractCommandRefs(command).dumpsEnvironment).toBe(true);
  });

  it.each([
    "function f { ls; }",
    "echo env",
    "echo env || bash",
    "echo env; bash",
    "echo env && sh",
    "echo env | grep x",
    "echo env | tee out.txt",
    "echo hi | bash",
    "echo hi 2> env | bash",
    "bash | echo env",
    "cat x | bash",
    "echo env > s.sh; bash s.sh",
    "bash <<< ls",
    "grep x <<< env",
    "cat <<< env",
    "cat <<'EOF' | grep x\nenv\nEOF",
    "cat > s.sh <<'EOF'\nenv\nEOF",
    "ssh host <<'EOF'\nenv\nEOF",
  ])("%j does not dump the environment", (command) => {
    expect(extractCommandRefs(command).dumpsEnvironment).toBe(false);
  });

  // Inline program text yields every quoted pairing as a candidate, so the
  // file is looked for among them rather than as the only one.
  it.each([
    "echo 'cat secrets' | bash",
    "printf '%s\\n' 'cat secrets' | sh",
    "bash <<< 'cat secrets'",
    "bash <<'EOF'\ncat secrets\nEOF",
    "echo \"print(open('secrets').read())\" | python3",
    "python3 <<'EOF'\nprint(open('secrets').read())\nEOF",
    "node <<< \"require('fs').readFileSync('secrets')\"",
  ])("%j reads secrets", (command) => {
    expect(paths(command)).toContain("secrets");
  });

  it.each([
    "cat > s.sh <<'EOF'\ncat secrets\nEOF",
    "echo 'cat secrets'",
    "echo 'cat secrets' | grep cat",
  ])("%j reads nothing", (command) => {
    expect(paths(command)).toEqual([]);
  });
});

// The program an interpreter runs is read for what it does with the
// environment, wherever the command line hands it over.
describe("interpreters reading the environment", () => {
  it.each([
    "python3 -c 'import os; print(os.environ)'",
    "node -e 'console.log(process.env)'",
    "node -p process.env",
    "node --print 'process.env'",
    "bun -p 'process.env'",
    "ruby -e 'p ENV'",
    "perl -e 'print %ENV'",
    "php -r 'print_r(getenv());'",
    "sudo python3 -c 'import os; print(os.environ)'",
    "echo 'print(__import__(\"os\").environ)' | python3",
    "echo 'p ENV' | ruby",
    "python3 - <<'EOF'\nimport os\nprint(os.environ)\nEOF",
    "node <<< 'console.log(process.env)'",
    "bash -c \"python3 -c 'import os; print(os.environ)'\"",
  ])("%j dumps the environment", (command) => {
    expect(extractCommandRefs(command).dumpsEnvironment).toBe(true);
  });

  it.each([
    ["python3 -c 'import os; print(os.environ[\"TOKEN\"])'", ["TOKEN"]],
    ["node -p process.env.TOKEN", ["TOKEN"]],
    ["echo 'puts ENV[\"TOKEN\"]' | ruby", ["TOKEN"]],
    ["perl -e 'print $ENV{TOKEN}'", ["TOKEN"]],
  ])("%j reads %j", (command, named) => {
    const refs = extractCommandRefs(command);
    expect(refs.dumpsEnvironment).toBe(false);
    expect(refs.envVars).toEqual(named);
  });

  it.each([
    "grep -r process.env src",
    "python3 script.py",
    "bash -c 'echo p ENV'",
    "echo 'print(os.environ)'",
    "echo 'print(os.environ)' > show.py",
    "python3 -c 'print(1)'",
  ])("%j does not dump the environment", (command) => {
    expect(extractCommandRefs(command).dumpsEnvironment).toBe(false);
  });
});

// An interpreter installed under a versioned name, Python's bundled switches,
// and `deno eval` all run the code that follows, as `python3 -c` does. The
// Python, Perl and deno spellings were run against a clean environment and
// printed the value; `deno eval` runs with every permission.
describe("inline code behind other spellings", () => {
  it.each([
    "python3.12 -c \"print(open('secrets').read())\"",
    "/opt/homebrew/bin/python3.14 -c \"print(open('secrets').read())\"",
    "sudo python3.12 -c \"print(open('secrets').read())\"",
    "python3 -Sc \"print(open('secrets').read())\"",
    "python3 -IuSc \"print(open('secrets').read())\"",
    // `-E` takes no code, so the `-c` after it was missed.
    "python3 -E -c \"print(open('secrets').read())\"",
    "ruby3.3 -e \"puts File.read('secrets')\"",
    "deno eval \"console.log(Deno.readTextFileSync('secrets'))\"",
    "deno eval --ext ts \"console.log(Deno.readTextFileSync('secrets'))\"",
    "echo \"print(open('secrets').read())\" | python3.12",
  ])("%j reads secrets", (command) => {
    expect(paths(command)).toContain("secrets");
  });

  it.each([
    "python3.12 -c 'import os; print(os.environ)'",
    "python3 -Ic 'import os; print(os.environ)'",
    "python3 -Ec 'import os; print(os.environ)'",
    "perl5.34 -e 'print %ENV'",
    "node22 -e 'console.log(process.env)'",
    "php8.3 -r 'print_r(getenv());'",
    "deno eval 'console.log(Deno.env.toObject())'",
    "deno eval -p 'Deno.env.toObject()'",
    "echo 'console.log(Deno.env.toObject())' | deno run -A -",
  ])("%j dumps the environment", (command) => {
    expect(extractCommandRefs(command).dumpsEnvironment).toBe(true);
  });

  // `-E` ignores Python's own variables and takes no code; read as Perl's
  // `-e`, it made the script name the program.
  it.each([
    "python3 -E script.py",
    "python3 -m http.server",
    "python3.12 script.py",
    "deno run main.ts",
    'deno run -A eval "cat secrets"',
    // `-W` takes a value, so this `c` is the value and the program is a file.
    "python3 -Wc \"print(open('secrets').read())\"",
    "pythonista -c x",
  ])("%j reads no inline code", (command) => {
    const refs = extractCommandRefs(command);
    expect(refs.paths).toEqual([]);
    expect(refs.dumpsEnvironment).toBe(false);
  });

  // A wrapper or `printenv` named by its path is the same command.
  it("reads past a wrapper named by its path", () => {
    expect(paths("/usr/bin/sudo cat secrets")).toContain("secrets");
    expect(extractCommandRefs("/usr/bin/printenv").dumpsEnvironment).toBe(true);
  });

  it.each([
    ["python3.12", "python"],
    ["/usr/bin/python3.12", "python"],
    ["python3", "python3"],
    ["python3.13t", "python"],
    ["python3.", "python3."],
    ["python3.12-config", "python3.12-config"],
    ["perl5.34", "perl"],
    ["ruby3.3", "ruby"],
    ["php8.3", "php"],
    ["node22", "node"],
    ["pythonista", "pythonista"],
    ["bash5", "bash5"],
    ["/bin/cat", "cat"],
  ])("commandName(%j) is %j", (word, name) => {
    expect(commandName(word)).toBe(name);
  });
});

// An in-place edit writes the files back rather than printing them, but the
// code doing the edit still prints to the terminal: perl run this way printed
// a variable exported into a clean environment from `BEGIN` and `system()`.
describe("inline code of an in-place edit", () => {
  it.each([
    ["perl -pi -e 'BEGIN { print %ENV }' f.txt", true, []],
    ["perl -i -pe 'BEGIN { print $ENV{TOKEN} }' f.txt", false, ["TOKEN"]],
    ["ruby -pi -e 'BEGIN { p ENV }' f.txt", true, []],
    ["perl -pi -e 's/a/b/' f.txt", false, []],
    ["sed -i 's/a/b/' f.txt", false, []],
  ])("%j", (command, dumps, named) => {
    const refs = extractCommandRefs(command);
    expect(refs.dumpsEnvironment).toBe(dumps);
    expect(refs.envVars).toEqual(named);
    expect(refs.paths).toEqual([]);
  });

  it("reads the files the code names, not the files it edits", () => {
    expect(
      paths("perl -pi -e 'BEGIN { open F, \"secrets\"; print <F> }' f.txt"),
    ).toContain("secrets");
    expect(
      paths("perl -pi -e 'BEGIN { open F, \"secrets\"; print <F> }' f.txt"),
    ).not.toContain("f.txt");
  });
});

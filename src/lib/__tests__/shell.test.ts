// The shell syntax layer, tested at its own level.
//
// Every one of these functions was reached only by spawning the hook, which
// meant a fault inside one was caught only when it happened to change a verdict.
// Three faults, measured against the suite as it stood: closing heredocs
// last-opened-first, starting the substitution nesting count at 1, and dropping
// the tab-and-newline guard on quoted literals. Each changes what is scanned and
// each passed all 650 tests.
//
// Two more that looked like survivors were not, and the difference is worth
// keeping straight. Dropping the file-descriptor test already failed a hook-level
// case (`env with stderr redirected is still a dump`), so it needed no help from
// here. Deleting the herestring branch changes no output at all — `<` is in the
// break class of the delimiter reader, so both paths land on the same index — so
// no test can catch it, and the case below asserts the behaviour rather than the
// branch.
//
// So the cases here assert the parse, not the verdict. A wrong parse that a
// later stage happens to paper over still fails.

import { describe, expect, it } from "vitest";
import {
  blankComments,
  extractEnvVarNames,
  extractQuotedLiterals,
  extractSubstitutions,
  findComments,
  isNonCommandToken,
  MAX_QUOTED_LITERAL_LENGTH,
  SHELL_KEYWORD_TOKENS,
  type ShellToken,
  stripHeredocBodies,
  tokenizeCommand,
} from "../shell.ts";

// The words of one segment, dropping the redirection operators, which is what
// most cases below are asking about.
function words(command: string, segment = 0): string[] {
  return (tokenizeCommand(command)[segment] ?? [])
    .filter((t) => !t.redirect)
    .map((t) => t.value);
}

describe("tokenizeCommand", () => {
  it("splits on whitespace and keeps quoted spaces together", () => {
    expect(words('cat "my secrets.txt"')).toEqual(["cat", "my secrets.txt"]);
    expect(words("cat 'my secrets.txt'")).toEqual(["cat", "my secrets.txt"]);
  });

  it("strips the $ from $'…' and $\"…\" and decodes ANSI-C escapes", () => {
    expect(words("cat $'a\\tb'")).toEqual(["cat", "a\tb"]);
    expect(words('cat $"secrets"')).toEqual(["cat", "secrets"]);
  });

  it("keeps a backslash literal inside single quotes", () => {
    expect(words("cat 'a\\tb'")).toEqual(["cat", "a\\tb"]);
  });

  it.each(["cat a | cat b", "cat a; cat b", "cat a && cat b", "cat a\ncat b"])(
    "splits %s into two segments",
    (command) => {
      expect(
        tokenizeCommand(command).map((s) => s.map((t) => t.value)),
      ).toEqual([
        ["cat", "a"],
        ["cat", "b"],
      ]);
    },
  );

  it("ends a segment at a subshell boundary", () => {
    expect(
      tokenizeCommand("(cat a)")
        .filter((s) => s.length > 0)
        .map((s) => s.map((t) => t.value)),
    ).toEqual([["cat", "a"]]);
  });

  // A redirection operator carries its file-descriptor prefix, and only when the
  // digits are written against it. Dropping the digit test took the operand with
  // it whenever no space separated the two, so `cat secrets>out` scanned
  // nothing — and no test noticed, because `cat secrets 2>/dev/null`, the only
  // shape covered, has the space.
  describe("file-descriptor prefixes", () => {
    it("drops digits written against the operator", () => {
      expect(words("cat f 2>err")).toEqual(["cat", "f", "err"]);
    });

    // `2>&1` is one redirection, and `>&` is not read as a single operator here:
    // the `&` ends the segment instead. What matters is that the descriptor does
    // not become an operand of the command, which holds either way, so that is
    // what this asserts. Pinning the split would make reading `>&` properly look
    // like a regression.
    it("does not turn the descriptor of 2>&1 into an operand", () => {
      expect(words("cat f 2>&1")).not.toContain("2");
    });

    it("keeps a word written against the operator", () => {
      expect(words("cat secrets>out")).toEqual(["cat", "secrets", "out"]);
      expect(words("cat secrets>>out")).toEqual(["cat", "secrets", "out"]);
    });

    it("keeps a standalone number before a spaced operator", () => {
      expect(words("sort 1 >out")).toEqual(["sort", "1", "out"]);
    });
  });

  describe("redirection operators", () => {
    it("become tokens of their own, spaced or not", () => {
      const spaced = tokenizeCommand("wc -l < f")[0] ?? [];
      const tight = tokenizeCommand("wc -l <f")[0] ?? [];
      expect(spaced.map((t) => [t.value, t.redirect])).toEqual(
        tight.map((t) => [t.value, t.redirect]),
      );
    });

    // The field that distinguishes a quoted `>` from the operator. Without it,
    // `grep ">" secrets` had `secrets` skipped as an output target.
    it("mark a quoted operator as a word", () => {
      const tokens = tokenizeCommand('grep ">" secrets')[0] ?? [];
      expect(tokens.map((t) => t.value)).toEqual(["grep", ">", "secrets"]);
      expect(tokens.every((t) => !t.redirect)).toBe(true);
    });
  });
});

// The tokens of every segment as `[value, redirect]`, which is what the joined
// reading changes. Quote removal is not what these cases are about.
function shape(
  command: string,
  options?: { joinRedirections: boolean },
): [string, boolean][][] {
  return tokenizeCommand(command, options).map((segment) =>
    segment.map((t): [string, boolean] => [t.value, t.redirect]),
  );
}

describe("tokenizeCommand, default reading", () => {
  // These pin what every caller gets without the option. The cd-following loop
  // in pre-tool-use-hook.ts relies on this shape, so changing it is a
  // regression even where the joined reading would be more correct.
  it("splits 2>&1 at the ampersand", () => {
    expect(shape("cat 2>&1 .env")).toEqual([
      [
        ["cat", false],
        [">", true],
      ],
      [
        ["1", false],
        [".env", false],
      ],
    ]);
  });

  it("splits &> at the ampersand", () => {
    expect(shape("cat &>/dev/null .env")).toEqual([
      [["cat", false]],
      [
        [">", true],
        ["/dev/null", false],
        [".env", false],
      ],
    ]);
  });

  it("splits 2>&1>out.txt, leaving out.txt in a segment led by >", () => {
    expect(shape("cat plain.txt 2>&1>out.txt")).toEqual([
      [
        ["cat", false],
        ["plain.txt", false],
        [">", true],
      ],
      [
        [">", true],
        ["out.txt", false],
      ],
    ]);
  });

  it("keeps echo hi >&2 as an operator and an operand", () => {
    expect(shape("echo hi >&2")).toEqual([
      [
        ["echo", false],
        ["hi", false],
        [">", true],
      ],
      [["2", false]],
    ]);
  });
});

describe("tokenizeCommand, joinRedirections", () => {
  it("reads 2>&1 as one operator and keeps 1 as its target", () => {
    expect(shape("cat 2>&1 .env", { joinRedirections: true })).toEqual([
      [
        ["cat", false],
        [">&", true],
        ["1", false],
        [".env", false],
      ],
    ]);
  });

  it.each([
    ["cat &>/dev/null .env", "&>"],
    ["cat &>>/dev/null .env", "&>>"],
    ["cat &>|/dev/null .env", "&>|"],
  ])("reads the leading & of %s into one operator", (command, op) => {
    const [segment] = shape(command, { joinRedirections: true });
    expect(segment?.[1]).toEqual([op, true]);
    expect(segment?.at(-1)).toEqual([".env", false]);
  });

  it("does not take a digit before &> as a descriptor", () => {
    expect(shape("cat 2&>f", { joinRedirections: true })).toEqual([
      [
        ["cat", false],
        ["2", false],
        ["&>", true],
        ["f", false],
      ],
    ]);
  });

  it.each([
    ["cat 2>|/dev/null .env", ">|"],
    ["cat >|/dev/stdout .env", ">|"],
    ["cat >>|/dev/stdout .env", ">>|"],
    ["cat >&|/dev/stdout .env", ">&|"],
  ])("reads %s with the noclobber | as one operator", (command, op) => {
    const [segment] = shape(command, { joinRedirections: true });
    expect(segment?.[1]).toEqual([op, true]);
    expect(segment?.at(-1)).toEqual([".env", false]);
  });

  it("drops the descriptor written before a joined operator", () => {
    expect(shape("cat f 2>|/dev/null", { joinRedirections: true })).toEqual([
      [
        ["cat", false],
        ["f", false],
        [">|", true],
        ["/dev/null", false],
      ],
    ]);
  });

  it("reads a line continuation between the characters of an operator", () => {
    expect(
      shape("cat 2>\\\n&1 .env", { joinRedirections: true })[0]?.slice(1),
    ).toEqual([
      [">&", true],
      ["1", false],
      [".env", false],
    ]);
    expect(
      shape("cat >\\\n|/dev/stdout .env", { joinRedirections: true })[0]?.slice(
        1,
      ),
    ).toEqual([
      [">|", true],
      ["/dev/stdout", false],
      [".env", false],
    ]);
    expect(
      shape("cat &\\\n>/dev/stdout .env", { joinRedirections: true })[0]?.slice(
        1,
      ),
    ).toEqual([
      ["&>", true],
      ["/dev/stdout", false],
      [".env", false],
    ]);
  });

  it("emits the target of >& as a token of its own in 2>&1>out.txt", () => {
    expect(
      shape("cat plain.txt 2>&1>out.txt", { joinRedirections: true }),
    ).toEqual([
      [
        ["cat", false],
        ["plain.txt", false],
        [">&", true],
        ["1", false],
        [">", true],
        ["out.txt", false],
      ],
    ]);
  });

  it("reads <&3 with 3 as its target", () => {
    expect(shape("cat <&3", { joinRedirections: true })).toEqual([
      [
        ["cat", false],
        ["<&", true],
        ["3", false],
      ],
    ]);
  });

  it("still splits at a bare & that is not a redirection", () => {
    expect(shape("cat a & cat b", { joinRedirections: true })).toEqual([
      [
        ["cat", false],
        ["a", false],
      ],
      [
        ["cat", false],
        ["b", false],
      ],
    ]);
  });
});

describe("stripHeredocBodies", () => {
  it("removes the body and keeps the command line", () => {
    const stripped = stripHeredocBodies("cat > s.sh <<EOF\ncat /secret\nEOF");
    expect(stripped).toBe("cat > s.sh <<EOF");
  });

  it("honours a quoted delimiter and the <<- form", () => {
    expect(stripHeredocBodies("cat <<'EOF'\nx\nEOF")).toBe("cat <<'EOF'");
    expect(stripHeredocBodies("cat <<-EOF\nx\n\tEOF")).toBe("cat <<-EOF");
  });

  // A herestring is not a heredoc: it carries its text on the same line and
  // opens no body. Read as one, the delimiter was never found on a later line,
  // so every command after it was eaten as body — `grep x <<< "y"; cat secrets`
  // left the read unscanned.
  it("does not treat a herestring as opening a body", () => {
    const command = 'grep x <<< "y"\ncat secrets';
    expect(stripHeredocBodies(command)).toBe(command);
  });

  // Two heredocs on one line close in the order they were opened. Taking the
  // last pending delimiter instead of the first swaps the bodies, and whichever
  // text follows the second delimiter is kept as though it were a command.
  it("closes several heredocs in the order they were opened", () => {
    const command = "cmd <<A <<B\nbody a\nA\nbody b\nB\ncat secrets";
    expect(stripHeredocBodies(command)).toBe("cmd <<A <<B\ncat secrets");
  });

  it("leaves a command with no heredoc alone", () => {
    expect(stripHeredocBodies("cat a\ncat b")).toBe("cat a\ncat b");
  });
});

describe("extractSubstitutions", () => {
  it("returns the inner text of each form", () => {
    expect(extractSubstitutions("echo $(cat f)")).toEqual(["cat f"]);
    expect(extractSubstitutions("echo `cat f`")).toEqual(["cat f"]);
    expect(extractSubstitutions("diff <(cat a) >(cat b)")).toEqual([
      "cat a",
      "cat b",
    ]);
  });

  // Parentheses are counted, not matched by a pattern that stops at the first
  // `)`. The inner text here has two of its own, and cutting it short lost the
  // read it contained.
  it("counts nested parentheses to the real end", () => {
    expect(
      extractSubstitutions(`echo $(python3 -c "print(open('.env').read())")`),
    ).toEqual([`python3 -c "print(open('.env').read())"`]);
  });

  it("expands $( ) inside double quotes but not <( )", () => {
    expect(extractSubstitutions('echo "$(cat f)"')).toEqual(["cat f"]);
    expect(extractSubstitutions('echo "<(cat f)"')).toEqual([]);
  });

  it("finds nothing inside single quotes", () => {
    expect(extractSubstitutions("echo '$(cat f)'")).toEqual([]);
  });

  it("runs an unbalanced substitution to the end of the string", () => {
    expect(extractSubstitutions("echo $(cat f")).toEqual(["cat f"]);
  });
});

describe("extractEnvVarNames", () => {
  it("reads the bare and braced forms", () => {
    expect(extractEnvVarNames(`echo $TOKEN $\{OTHER}`).sort()).toEqual([
      "OTHER",
      "TOKEN",
    ]);
  });

  it("reads a name carrying a suffix, and one inside the suffix", () => {
    expect(extractEnvVarNames(`echo $\{A:-$B}`).sort()).toEqual(["A", "B"]);
    expect(extractEnvVarNames(`echo $\{A#$B}`).sort()).toEqual(["A", "B"]);
    expect(extractEnvVarNames(`echo $\{A:-$\{B:-$C}}`).sort()).toEqual([
      "A",
      "B",
      "C",
    ]);
  });

  it("ignores what cannot be a name", () => {
    expect(extractEnvVarNames("echo $1 $$ $? cost: $500")).toEqual([]);
  });
});

describe("isNonCommandToken", () => {
  const word = (value: string): ShellToken => ({ value, redirect: false });

  it.each([
    ["-l", "a flag"],
    ["VAR=1", "an assignment"],
    ["while", "a keyword"],
    ["do", "a keyword"],
  ])("%s is not a command (%s)", (value) => {
    expect(isNonCommandToken(word(value))).toBe(true);
  });

  it("a redirection operator is not a command", () => {
    expect(isNonCommandToken({ value: ">", redirect: true })).toBe(true);
  });

  it.each(["cat", "my-tool", "1file", "_tool"])(
    "%s can name a command",
    (value) => {
      expect(isNonCommandToken(word(value))).toBe(false);
    },
  );
});

// A keyword cannot name a command, and a keyword missing from the set becomes
// one: dropping `else` made `if x; then :; else cat secrets; fi` classify `else`
// as the command and collect nothing. Ten of the seventeen entries had no case
// and the set had no equality.
describe("shell keywords", () => {
  it.each([...SHELL_KEYWORD_TOKENS])("%s cannot name a command", (value) => {
    expect(isNonCommandToken({ value, redirect: false })).toBe(true);
  });

  it("are exactly these", () => {
    expect([...SHELL_KEYWORD_TOKENS].sort()).toEqual([
      "!",
      "case",
      "do",
      "done",
      "elif",
      "else",
      "esac",
      "fi",
      "for",
      "if",
      "in",
      "select",
      "then",
      "until",
      "while",
      "{",
      "}",
    ]);
  });
});

describe("extractQuotedLiterals", () => {
  it("returns literals of both quotes, spaces kept", () => {
    expect(extractQuotedLiterals(`print(open('my secret.txt'))`)).toEqual([
      "my secret.txt",
    ]);
    expect(extractQuotedLiterals(`print(open(".env"))`)).toEqual([".env"]);
  });

  // A literal spanning lines or holding a tab is a message or a pattern, not a
  // path. Nothing else in the suite says so, so dropping the test changed
  // nothing that failed.
  it.each([
    ["'a\\nb'", "a newline"],
    ["'a\\tb'", "a tab"],
    ["'a\\rb'", "a carriage return"],
  ])("skips a literal containing %s (%s)", (literal) => {
    const code = `print(open(${literal.replace(/\\n/g, "\n").replace(/\\t/g, "\t").replace(/\\r/g, "\r")}))`;
    expect(extractQuotedLiterals(code)).toEqual([]);
  });

  // The length cap, at its boundary, read from the source rather than copied as
  // a number: nothing referenced it before, so it could be deleted or set to
  // anything and the suite agreed — and a test that writes 4096 of its own
  // starts failing for the wrong reason the first time someone tunes it.
  it("keeps a literal at the cap and drops the one past it", () => {
    const cap = MAX_QUOTED_LITERAL_LENGTH;
    expect(extractQuotedLiterals(`open('${"a".repeat(cap)}')`)).toEqual([
      "a".repeat(cap),
    ]);
    expect(extractQuotedLiterals(`open('${"a".repeat(cap + 1)}')`)).toEqual([]);
  });

  it("returns nothing for unquoted code", () => {
    expect(extractQuotedLiterals("print(open(path))")).toEqual([]);
  });
});

// A `#` that starts a comment, and the command line once the comment is gone.
// The scanner reads what the shell reads, so the cases split on what it must
// not mistake for a comment: a quote, a substitution, a heredoc body, a shift.
describe("comments", () => {
  // The words of a comment are not commands, and a quote in one does not open a
  // run that reaches the next line.
  it.each([
    ["# Check what's configured\ncat .env", "\ncat .env"],
    ['# "x\ncat .env', "\ncat .env"],
    ["# usage: cat <<EOF\ncat secrets.txt", "\ncat secrets.txt"],
    ["(( 1 ))# it's\ncat .env", "(( 1 ))\ncat .env"],
    ["case x in x)# it's\n cat .env;; esac", "case x in x)\n cat .env;; esac"],
    ["f()# it's\n{ cat .env; }; f", "f()\n{ cat .env; }; f"],
    ["ls # it's here\ncat secrets.txt", "ls \ncat secrets.txt"],
  ])("blanks the comment in %j", (command, blanked) => {
    expect(blankComments(command)).toBe(blanked);
  });

  // A `#` that is part of a word, or sits inside a quote, a substitution's
  // closing mid-word, or a heredoc body, is not a comment and is left alone.
  it.each([
    "echo $(date)#x",
    "echo '# not a comment'; cat x",
    'echo "#not"',
    "echo ${#x}",
    "cat > s.sh <<'EOF'\n# it's\ncat .env\nEOF",
  ])("leaves %j as it is", (command) => {
    expect(blankComments(command)).toBe(command);
  });

  // `1 << 2` in arithmetic is a shift, so the `<<` opens no heredoc and the
  // comment after the expansion is still found.
  it("treats << inside arithmetic as a shift, not a heredoc", () => {
    expect(blankComments("echo $(( 1 << 2 )) # it's\ncat .env")).toBe(
      "echo $(( 1 << 2 )) \ncat .env",
    );
  });

  // Inside a substitution a comment runs to the newline; inside backquotes it
  // ends at the closing backquote, which is kept.
  it("ends a comment inside $(...) at the newline and inside backquotes at the backquote", () => {
    expect(blankComments("echo $(\n# it's\ncat .env\n)")).toBe(
      "echo $(\n\ncat .env\n)",
    );
    expect(blankComments("echo `cat x # it's`; cat .env")).toBe(
      "echo `cat x `; cat .env",
    );
  });

  // The stripping that follows the blanking reads the heredoc the blanked line
  // now holds, so a `<<` that sat in a comment opens nothing.
  // Quoting and expansions before the comment, each of which bash reads to its
  // own close: the `#` inside them is text, and the comment after them is still
  // found. Each pair runs to the same output in bash.
  it.each([
    ["echo $'it\\'s' # it's\ncat .env", "echo $'it\\'s' \ncat .env"],
    ["echo ${x:-'#'} # it's\ncat .env", "echo ${x:-'#'} \ncat .env"],
    ['echo ${x:-"#"} # it\'s\ncat .env', 'echo ${x:-"#"} \ncat .env'],
    ["echo ${x:-a\\}b} # it's\ncat .env", "echo ${x:-a\\}b} \ncat .env"],
    ['echo "a\\"#b" # it\'s\ncat .env', 'echo "a\\"#b" \ncat .env'],
    [
      'echo $(( (1 + 2) * "3" )) # it\'s\ncat .env',
      'echo $(( (1 + 2) * "3" )) \ncat .env',
    ],
    ["echo a\\#b # it's\ncat .env", "echo a\\#b \ncat .env"],
    ["echo a \\\n# it's\ncat .env", "echo a \\\n\ncat .env"],
    [
      "cat <<-EOF\n\t# it's\n\tEOF\n# it's\ncat .env",
      "cat <<-EOF\n\t# it's\n\tEOF\n\ncat .env",
    ],
    [
      "cat << EOF\n# it's\nEOF\n# it's\ncat .env",
      "cat << EOF\n# it's\nEOF\n\ncat .env",
    ],
  ])("finds only the comment in %j", (command, blanked) => {
    expect(blankComments(command)).toBe(blanked);
  });

  it.each([
    "echo $'a # b'",
    "echo ${x#*/}",
    "echo ${x:-$(echo '#')}",
    "echo \"$(echo '#')\"",
    'echo "`echo "#"`"',
    "echo ${x:-\\} # x}",
  ])("leaves the # inside %j", (command) => {
    expect(blankComments(command)).toBe(command);
  });

  it("lets heredoc stripping see the command without its comment", () => {
    expect(
      stripHeredocBodies(blankComments("# usage: cat <<EOF\ncat secrets.txt")),
    ).toBe("\ncat secrets.txt");
  });

  // A comment is found by scanning forward, not by recursing into nesting, so a
  // line nested far past any call-stack depth still returns.
  it("scans a deeply nested line without recursing", () => {
    const deep = `${"$(".repeat(20_000)}# it's`;
    expect(findComments(deep).length).toBe(1);
  });
});

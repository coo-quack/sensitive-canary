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
  extractEnvVarNames,
  extractQuotedLiterals,
  extractSubstitutions,
  isNonCommandToken,
  MAX_QUOTED_LITERAL_LENGTH,
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

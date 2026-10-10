import { describe, expect, it } from "vitest";
import {
  AWS_KEY,
  runBashHook,
  runToolHook,
  TOKEN_VALUE,
  useFixtureDir,
} from "./hook-harness.ts";

const writeFixture = useFixtureDir("shell");

describe("pre-tool-use-hook — shell parsing", () => {
  describe("command substitution", () => {
    it("$(...) substitution should block on file with secret", () => {
      const file = writeFixture("sub1.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`echo $(cat ${file})`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("backtick substitution should block on file with secret", () => {
      const file = writeFixture("sub2.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`echo \`cat ${file}\``);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("process substitution <(...) should block on file with secret", () => {
      const file = writeFixture("sub3.txt", `api=${AWS_KEY}`);
      const result = runBashHook(`diff <(cat ${file}) /dev/null`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("heredoc should not false positive on harmless content", () => {
      const result = runBashHook("cat <<EOF\nhello world\nEOF");
      expect(result.exitCode).toBe(0);
    });

    it("nested $( $(...) ) should block on file with secret", () => {
      const file = writeFixture("sub_nested.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`echo $(echo $(cat ${file}))`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("$(...) inside double quotes should block", () => {
      const file = writeFixture("sub_dq.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`echo "$(cat ${file})"`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("$(...) inside single quotes should allow (no expansion)", () => {
      const file = writeFixture("sub_sq.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`echo '$(cat ${file})'`);
      expect(result.exitCode).toBe(0);
    });
  });

  describe("backward compatibility", () => {
    it("classic cat should still block on secret", () => {
      const file = writeFixture("classic.txt", `password=${AWS_KEY}`);
      const result = runBashHook(`cat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("piped commands should work", () => {
      const file = writeFixture("pipe.txt", `key=${TOKEN_VALUE}`);
      const result = runBashHook(`cat ${file} | grep key`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("multiple arguments should all be scanned", () => {
      const file1 = writeFixture("f1.txt", "clean");
      const file2 = writeFixture("f2.txt", `secret=${AWS_KEY}`);
      const result = runBashHook(`cat ${file1} ${file2}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });
  });

  describe("multi-line and chained commands", () => {
    it("newline-separated commands should block if any reads secret", () => {
      const file = writeFixture("multiline.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`echo hi\ncat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("command1 && command2 should block if any reads secret", () => {
      const file = writeFixture("and.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`ls && cat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("command1; command2 should block if any reads secret", () => {
      const file = writeFixture("semi.txt", `token=${AWS_KEY}`);
      const result = runBashHook(`ls; cat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("newline-separated safe commands should allow", () => {
      const result = runBashHook(`echo one\necho two`);
      expect(result.exitCode).toBe(0);
    });
  });

  // A grouping construct or a shell keyword stands where a command name would.
  // Segments led by one were classified as a command called `(cat` or `then`,
  // and the file they read was never looked at.
  describe("grouped and keyword-led commands", () => {
    it("subshell should block on file with secret", () => {
      const file = writeFixture("subshell.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`(cat ${file})`);
      expect(result.exitCode).toBe(2);
    });

    it("subshell after && should block", () => {
      const file = writeFixture("subshell_and.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`echo hi && (cat ${file})`);
      expect(result.exitCode).toBe(2);
    });

    it("subshell piped onward should block", () => {
      const file = writeFixture("subshell_pipe.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`(cat ${file}) | head`);
      expect(result.exitCode).toBe(2);
    });

    it("brace group should block on file with secret", () => {
      const file = writeFixture("brace_group.txt", `token=${TOKEN_VALUE}`);
      const result = runBashHook(`{ cat ${file}; }`);
      expect(result.exitCode).toBe(2);
    });

    it("command after then should block", () => {
      const file = writeFixture("if_then.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`if true; then cat ${file}; fi`);
      expect(result.exitCode).toBe(2);
    });

    it("command after do should block", () => {
      const file = writeFixture("for_do.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`for f in a; do cat ${file}; done`);
      expect(result.exitCode).toBe(2);
    });

    it("subshell on a clean file should allow", () => {
      const file = writeFixture("subshell_clean.txt", "nothing here");
      const result = runBashHook(`(cat ${file})`);
      expect(result.exitCode).toBe(0);
    });

    // The parens are inside single quotes, so they are text rather than a group.
    it("awk program using $(NF) should allow", () => {
      const file = writeFixture("awk_nf.txt", "one two three");
      const result = runBashHook(`awk '{print $(NF)}' ${file}`);
      expect(result.exitCode).toBe(0);
    });

    // A keyword opening a condition matters as much as one opening a body: the
    // command being tested runs too.
    it("command in a while condition should block", () => {
      const file = writeFixture("while_cond.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`while cat ${file}; do :; done`);
      expect(result.exitCode).toBe(2);
    });

    it("command in an until condition should block", () => {
      const file = writeFixture("until_cond.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`until cat ${file}; do :; done`);
      expect(result.exitCode).toBe(2);
    });

    it("command in an if condition should block", () => {
      const file = writeFixture("if_cond.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`if cat ${file}; then :; fi`);
      expect(result.exitCode).toBe(2);
    });

    it("a quoted subshell is text and should allow", () => {
      const file = writeFixture("quoted_subshell.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`echo '(cat ${file})'`);
      expect(result.exitCode).toBe(0);
    });
  });

  describe("quoted paths and dd", () => {
    it("filename with space should block when secret is read", () => {
      const file = writeFixture("with space.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`cat "${file}"`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("if=<secretFile> without dd (echo) should allow", () => {
      const file = writeFixture("not_dd.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`echo if=${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("wc -l <secretFile> (wc outputs only count) should allow", () => {
      const file = writeFixture("wc_file.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`wc -l ${file}`);
      expect(result.exitCode).toBe(0);
    });
  });

  describe("redirection operators against quoted words", () => {
    it("a quoted > is an operand, not a redirection", () => {
      const file = writeFixture("quoted_gt.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`cat ">" ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("a quoted >> is an operand, not a redirection", () => {
      const file = writeFixture("quoted_gtgt.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`cat ">>" ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("an unquoted > still marks the next token as an output target", () => {
      const file = writeFixture("real_gt.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`cat > ${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("an unquoted >> still marks the next token as an output target", () => {
      const file = writeFixture("real_gtgt.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`cat >> ${file}`);
      expect(result.exitCode).toBe(0);
    });

    // The `<` case the other direction: a printing command fed over stdin does
    // print the file, so the token after the operator is collected rather than
    // skipped. `wc -l <file` above is the non-read half of the same branch.
    it("a printing command fed over < blocks, with no space", () => {
      const file = writeFixture("stdin_nospace.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`cat <${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("a printing command fed over < blocks, with a space", () => {
      const file = writeFixture("stdin_space.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`cat < ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });
  });

  // Run from the fixture directory, so `.env` in the command is the fixture the
  // test wrote, spelled as the command spells it.
  describe("redirections that bash joins to their operator", () => {
    it.each([
      "cat 2>&1 .env",
      "cat &>/dev/null .env",
      "cat 2>|/dev/null .env",
      "cat >|/dev/stdout .env",
      "cat 2>\\\n&1 .env",
      "cat >\\\n|/dev/stdout .env",
      "dash -c 'true &>/dev/stdout cat .env'",
    ])("%j should block on a .env with a secret", (command) => {
      writeFixture(".env", `key=${AWS_KEY}`);
      const result = runBashHook(command, { cwd: writeFixture.path() });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("head 2>&1 on a secrets file should block", () => {
      writeFixture("secrets.yml", `token: ${TOKEN_VALUE}`);
      const result = runBashHook("head -n 50 2>&1 secrets.yml", {
        cwd: writeFixture.path(),
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // A write target is not read, and neither is the descriptor after <&.
    it.each([
      ["cat plain.txt 2>&1>out.txt", "out.txt"],
      ["cat plain.txt 2>&1 >out.txt", "out.txt"],
    ])("%j does not read the write target %s", (command, target) => {
      writeFixture("plain.txt", "clean\n");
      writeFixture(target, `key=${AWS_KEY}`);
      const result = runBashHook(command, { cwd: writeFixture.path() });
      expect(result.exitCode).toBe(0);
    });

    it("echo hi >&2 should allow", () => {
      const result = runBashHook("echo hi >&2");
      expect(result.exitCode).toBe(0);
    });

    it("cat <&3 does not read a file named 3", () => {
      writeFixture("3", `key=${AWS_KEY}`);
      const result = runBashHook("cat <&3", { cwd: writeFixture.path() });
      expect(result.exitCode).toBe(0);
    });

    // The joined reading sees `cat f` after `env`, which is not a dump, but the
    // default reading still sees `env` alone and blocks. Both are scanned, so
    // the verdict is the one the default reading gave before this change.
    it("env 2>&1 cat f stays blocked as an environment dump", () => {
      writeFixture("f", "clean\n");
      const result = runBashHook("env 2>&1 cat f", {
        cwd: writeFixture.path(),
      });
      expect(result.exitCode).toBe(2);
    });
  });

  describe("environment variable expansion", () => {
    it("an expansion with a default should block when the var holds a secret", () => {
      const pathVal = process.env["PATH"] ?? "";
      const result = runBashHook(`echo $\{TOKEN:-fallback}`, {
        env: { PATH: pathVal, TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("an expansion with a default should allow when the var is unset", () => {
      const pathVal = process.env["PATH"] ?? "";
      const result = runBashHook(`echo $\{UNSET_VAR:-safe_default}`, {
        env: { PATH: pathVal },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(0);
    });
  });

  describe("output process substitution", () => {
    it(">(...) should block on file with secret", () => {
      const file = writeFixture("psub_out.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`echo hi >(cat ${file})`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });
  });

  describe("heredoc bodies", () => {
    it("heredoc writing a script that mentions .env should allow", () => {
      const result = runBashHook("cat > deploy.sh <<'EOF'\ncat .env\nEOF");
      expect(result.exitCode).toBe(0);
    });

    it("heredoc body naming a sensitive file should allow (body is text)", () => {
      const file = writeFixture("heredoc_body.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`cat > s.sh <<EOF\ncat ${file}\nEOF`);
      expect(result.exitCode).toBe(0);
    });

    it("<<- heredoc with tab-indented delimiter should allow", () => {
      const result = runBashHook("cat > s.sh <<-EOF\n\tcat .env\n\tEOF");
      expect(result.exitCode).toBe(0);
    });

    // Known limitation: the body is skipped entirely, so a heredoc that feeds
    // commands to a remote shell is no longer caught.
    it("ssh heredoc running cat on a sensitive file is not caught (documented limitation)", () => {
      const file = writeFixture("ssh_heredoc.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`ssh host <<EOF\ncat ${file}\nEOF`);
      expect(result.exitCode).toBe(0);
    });

    it("command after the heredoc still scans", () => {
      const file = writeFixture("after_heredoc.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`cat <<EOF\nhi\nEOF\ncat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // A delimiter cut short never matches its closing line, and every following
    // line is then swallowed as body — hiding the read that comes after it.
    it("command after a hyphenated heredoc delimiter still scans", () => {
      const file = writeFixture("hyphen_delim.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`cat > s.sh <<EOF-1\nhi\nEOF-1\ncat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("command after a partly quoted heredoc delimiter still scans", () => {
      const file = writeFixture("mixed_delim.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`cat > s.sh <<E"O"F\nhi\nEOF\ncat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("hyphenated delimiter still hides its own body", () => {
      const result = runBashHook("cat > deploy.sh <<EOF-1\ncat .env\nEOF-1");
      expect(result.exitCode).toBe(0);
    });
  });

  describe("ANSI-C and locale quoting", () => {
    it("cat $'<path>' should block on file with secret", () => {
      const file = writeFixture("ansi_c.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`cat $'${file}'`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it('cat $"<path>" should block on file with secret', () => {
      const file = writeFixture("locale_q.txt", `key=${TOKEN_VALUE}`);
      const result = runBashHook(`cat $"${file}"`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("cat $'<path with space>' should block", () => {
      const file = writeFixture("ansi space.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`cat $'${file}'`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("$'...' hex escapes should decode", () => {
      const file = writeFixture("hexesc.txt", `key=${AWS_KEY}`);
      // "hexesc" as h e x e \x73 c
      const escaped = file.replace("hexesc", "hexe\\x73c");
      const result = runBashHook(`cat $'${escaped}'`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });
  });
});

// A `#` comment is not a command. Its quotes, `<<` and substitutions must not
// hide the lines after it, and its words must not name files to read.
describe("pre-tool-use-hook — comments", () => {
  // Each names a secret file after a comment that would have hidden it.
  it.each([
    "# Check what's configured\ncat .env",
    '# "x\ncat .env',
    "(( 1 ))# it's\ncat .env",
    "case x in x)# it's\n cat .env;; esac",
    "f()# it's\n{ cat .env; }; f",
  ])("%j should block on a .env with a secret", (command) => {
    writeFixture(".env", `key=${AWS_KEY}`);
    const result = runBashHook(command, { cwd: writeFixture.path() });
    expect(result.exitCode).toBe(2);
    expect(result.blocked).toBe(true);
  });

  it("a << inside a comment does not hide the lines after it", () => {
    writeFixture("secrets.txt", `token: ${TOKEN_VALUE}`);
    const result = runBashHook("# usage: cat <<EOF\ncat secrets.txt", {
      cwd: writeFixture.path(),
    });
    expect(result.exitCode).toBe(2);
    expect(result.blocked).toBe(true);
  });

  it("a comment after a word does not hide the lines after it", () => {
    writeFixture("secrets.txt", `token: ${TOKEN_VALUE}`);
    const result = runBashHook("ls # it's here\ncat secrets.txt", {
      cwd: writeFixture.path(),
    });
    expect(result.exitCode).toBe(2);
    expect(result.blocked).toBe(true);
  });

  it("the MCP command field blocks the same way", () => {
    writeFixture(".env", `key=${AWS_KEY}`);
    const result = runToolHook(
      "mcp__desktop-commander__start_process",
      { command: "# Check what's configured\ncat .env" },
      { cwd: writeFixture.path() },
    );
    expect(result.exitCode).toBe(2);
    expect(result.blocked).toBe(true);
  });

  // The comment names `.env`, but nothing in it is read: allowed, even with a
  // `.env` holding a secret in the directory.
  it("cat notes.md # don't print .env allows a harmless notes.md", () => {
    writeFixture("notes.md", "clean\n");
    writeFixture(".env", `key=${AWS_KEY}`);
    const result = runBashHook("cat notes.md # don't print .env", {
      cwd: writeFixture.path(),
    });
    expect(result.exitCode).toBe(0);
  });

  // The `# it's` is a heredoc body line, so it is text and not a comment.
  it("a heredoc body containing # it's stays text", () => {
    writeFixture(".env", `key=${AWS_KEY}`);
    const result = runBashHook(
      "cat > deploy.sh <<'EOF'\n# it's\ncat .env\nEOF",
      {
        cwd: writeFixture.path(),
      },
    );
    expect(result.exitCode).toBe(0);
  });
});

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runBashHook } from "./hook-harness.ts";

let tmpDir: string;
beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "sensitive-canary-shell-"));
});
afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function writeFixture(name: string, content: string) {
  const p = join(tmpDir, name);
  writeFileSync(p, content, "utf8");
  return p;
}

// Assembled so the full strings never appear in this file's source.
const AWS_KEY = ["AKIA", "IOSFODNN7", "EXAMPLE"].join("");
const TOKEN_VALUE = ["ghp_", "1234567890abcdefghij", "klmnopqrstuvwxyz"].join(
  "",
);

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

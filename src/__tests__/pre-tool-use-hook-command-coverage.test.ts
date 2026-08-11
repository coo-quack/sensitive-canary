import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runBashHook } from "./hook-harness.ts";

let tmpDir: string;
beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "sensitive-canary-commands-"));
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

describe("pre-tool-use-hook — command classification", () => {
  describe("expanded read commands", () => {
    it("sed with pattern should block on file with secret", () => {
      const file = writeFixture("s.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`sed -n '1,5p' ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("sed -i should allow (in-place edit doesn't output)", () => {
      const file = writeFixture("edit.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`sed -i '' 's/a/b/' ${file}`);
      expect(result.exitCode).toBe(0);
    });

    // The reason `sed -i` is exempt holds for the other in-place editors, whose
    // short flags bundle: `-pi` is as common as `-i`.
    it("perl -i -pe should allow", () => {
      const file = writeFixture("perl_i.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`perl -i -pe 's/a/b/' ${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("perl -pi -e should allow", () => {
      const file = writeFixture("perl_pi.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`perl -pi -e 's/a/b/' ${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("ruby -i -pe should allow", () => {
      const file = writeFixture("ruby_i.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`ruby -i -pe 'x' ${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("perl -pe without -i should block", () => {
      const file = writeFixture("perl_pe.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`perl -pe 's/a/b/' ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // Not every `-i` is an in-place edit: grep's is case-insensitive matching,
    // and it still prints the file.
    it("grep -i should block on file with secret", () => {
      const file = writeFixture("grep_i.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`grep -i secret ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("awk should block on file with secret", () => {
      const file = writeFixture("awk.txt", `token=${TOKEN_VALUE}`);
      const result = runBashHook(`awk '{print}' ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("grep should block on file with secret", () => {
      const file = writeFixture("grep.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`grep key ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("grep should allow on clean file", () => {
      const file = writeFixture("clean.txt", "no secrets here");
      const result = runBashHook(`grep key ${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("rg (ripgrep) should block on file with secret", () => {
      const file = writeFixture("rg.txt", `api_key=${AWS_KEY}`);
      const result = runBashHook(`rg key ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("cut should block on file with secret", () => {
      const file = writeFixture("cut.txt", `field=${TOKEN_VALUE}`);
      const result = runBashHook(`cut -d= -f2 ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("sort should block on file with secret", () => {
      const file = writeFixture("sort.txt", `line ${AWS_KEY} end`);
      const result = runBashHook(`sort ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("base64 should block on file with secret", () => {
      const file = writeFixture("b64.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`base64 ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("xxd (hex dump) should block on file with secret", () => {
      const file = writeFixture("hex.txt", `token=${AWS_KEY}`);
      const result = runBashHook(`xxd ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });
  });

  describe("expanded read commands (additional)", () => {
    it("strings <secretFile> should block", () => {
      const file = writeFixture("strings_file.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`strings ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("diff <secretFile> /dev/null should block", () => {
      const file = writeFixture("diff_file.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`diff ${file} /dev/null`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("comm <secretFile> /dev/null should block", () => {
      const file = writeFixture("comm_file.txt", `token=${AWS_KEY}`);
      const result = runBashHook(`comm ${file} /dev/null`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });
  });

  // A flag can stand in for what an operand would otherwise be: the pattern of a
  // pattern-first command, or a file to write rather than read.
  describe("flags that change what the operands mean", () => {
    it("grep --regexp= should block the file it is given", () => {
      const file = writeFixture("long_regexp.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`grep --regexp=aws ${file}`);
      expect(result.exitCode).toBe(2);
    });

    it("sed --expression= should block the file it is given", () => {
      const file = writeFixture("long_expr.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`sed --expression=s/a/b/ ${file}`);
      expect(result.exitCode).toBe(2);
    });

    it("grep -f patterns should block the file it searches", () => {
      const patterns = writeFixture("patterns.txt", "aws");
      const file = writeFixture("grep_f.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`grep -f ${patterns} ${file}`);
      expect(result.exitCode).toBe(2);
    });

    it("sort -o should allow: its value is written, not read", () => {
      const out = writeFixture("sort_out.txt", `key=${AWS_KEY}`);
      const input = writeFixture("sort_in.txt", "clean");
      const result = runBashHook(`sort -o ${out} ${input}`);
      expect(result.exitCode).toBe(0);
    });

    it("shuf -o should allow: its value is written, not read", () => {
      const out = writeFixture("shuf_out.txt", `secret=${TOKEN_VALUE}`);
      const input = writeFixture("shuf_in.txt", "clean");
      const result = runBashHook(`shuf -o ${out} ${input}`);
      expect(result.exitCode).toBe(0);
    });

    // `-o` takes no value here, so its operand is still the file being dumped.
    it("od -o should block on file with secret", () => {
      const file = writeFixture("od_octal.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`od -o ${file}`);
      expect(result.exitCode).toBe(2);
    });

    it("hexdump -o should block on file with secret", () => {
      const file = writeFixture("hexdump_octal.txt", `key=${TOKEN_VALUE}`);
      const result = runBashHook(`hexdump -o ${file}`);
      expect(result.exitCode).toBe(2);
    });
  });

  describe("input redirection", () => {
    it("wc with < redirection should allow: it reports counts, not content", () => {
      const file = writeFixture("wc.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`wc -l < ${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("sha256sum with < redirection should allow", () => {
      const file = writeFixture("sha.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`sha256sum < ${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("grep with < redirection should block on file with secret", () => {
      const file = writeFixture("grep_redir.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`grep key < ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // Searching for a `>` character: the quoted operator is the pattern, and the
    // file after it is still a file.
    it("grep for a quoted > should block on file with secret", () => {
      const file = writeFixture("grep_gt.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`grep ">" ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("tr (non-read-command) with < redirection should block", () => {
      const file = writeFixture("tr.txt", `data=${AWS_KEY}`);
      const result = runBashHook(`tr a b < ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("output redirection > should not scan target file", () => {
      const file = writeFixture("output.txt", `key=${AWS_KEY}`);
      // Redirect to existing file with secret: output redirection is skipped, so no block expected
      const result = runBashHook(`echo hello > ${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("<file form (no space) should block on secret", () => {
      const file = writeFixture("nosp.txt", `key=${TOKEN_VALUE}`);
      const result = runBashHook(`grep pattern <${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("a file-descriptor prefix does not hide the operands", () => {
      const file = writeFixture("fd_prefix.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`cat ${file} 2>/dev/null`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });
  });

  describe("environment variables", () => {
    it("printenv VAR should block when var contains secret", () => {
      const pathVal = process.env["PATH"] ?? "";
      const result = runBashHook("printenv SECRET", {
        env: { PATH: pathVal, SECRET: TOKEN_VALUE },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("env (single token) should block when env contains secret", () => {
      const pathVal = process.env["PATH"] ?? "";
      const result = runBashHook("env", {
        env: { PATH: pathVal, TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("printenv (single token) should block when env contains secret", () => {
      const pathVal = process.env["PATH"] ?? "";
      const result = runBashHook("printenv", {
        env: { PATH: pathVal, SECRET: TOKEN_VALUE },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("env FOO=bar ls (env as launcher) should allow when no secrets", () => {
      const pathVal = process.env["PATH"] ?? "";
      const result = runBashHook("env FOO=1 ls", {
        env: { PATH: pathVal },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(0);
    });
  });

  describe("wrapper commands", () => {
    it("sudo cat <secretFile> should block", () => {
      const file = writeFixture("sudo_cat.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`sudo cat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("env FOO=1 cat <secretFile> should block", () => {
      const file = writeFixture("env_cat.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`env FOO=1 cat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("timeout 5 cat <secretFile> should block", () => {
      const file = writeFixture("timeout_cat.txt", `token=${AWS_KEY}`);
      const result = runBashHook(`timeout 5 cat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("xargs cat (no file argument) should allow", () => {
      const result = runBashHook(`xargs cat`);
      expect(result.exitCode).toBe(0);
    });

    it("sudo ls <secretFile> (ls doesn't output content) should allow", () => {
      const file = writeFixture("sudo_ls.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`sudo ls ${file}`);
      expect(result.exitCode).toBe(0);
    });
  });

  // Peeling a wrapper by counting its flags mistook a flag's value for the
  // command: `sudo -u root cat f` resolved to `root`, and the file went unread.
  describe("wrappers whose flags take a value", () => {
    const blocked = (command: string) => {
      const result = runBashHook(command);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    };

    it("sudo -u root cat should block", () => {
      const file = writeFixture("w_sudo_u.txt", `key=${AWS_KEY}`);
      blocked(`sudo -u root cat ${file}`);
    });

    it("nice -n 10 cat should block", () => {
      const file = writeFixture("w_nice_n.txt", `key=${AWS_KEY}`);
      blocked(`nice -n 10 cat ${file}`);
    });

    it("ionice -c 3 cat should block", () => {
      const file = writeFixture("w_ionice.txt", `key=${TOKEN_VALUE}`);
      blocked(`ionice -c 3 cat ${file}`);
    });

    it("env -u FOO cat should block", () => {
      const file = writeFixture("w_env_u.txt", `key=${AWS_KEY}`);
      blocked(`env -u FOO cat ${file}`);
    });

    it("timeout -s KILL 5 cat should block", () => {
      const file = writeFixture("w_timeout.txt", `key=${TOKEN_VALUE}`);
      blocked(`timeout -s KILL 5 cat ${file}`);
    });

    it("xargs -n 1 cat should block", () => {
      const file = writeFixture("w_xargs.txt", `key=${AWS_KEY}`);
      blocked(`xargs -n 1 cat ${file}`);
    });

    it("flock /tmp/lockfile cat should block", () => {
      const file = writeFixture("w_flock.txt", `key=${AWS_KEY}`);
      blocked(`flock /tmp/canary.lock cat ${file}`);
    });

    it("nested wrappers should block", () => {
      const file = writeFixture("w_nested.txt", `key=${TOKEN_VALUE}`);
      blocked(`sudo -u root timeout -s KILL 5 cat ${file}`);
    });
  });

  // A `VAR=value` prefix is not a command, and skipping assignments only after a
  // wrapper name let `LANG=C cat f` through.
  describe("leading variable assignments", () => {
    it("LANG=C cat should block", () => {
      const file = writeFixture("a_lang.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`LANG=C cat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("NODE_ENV=test grep should block", () => {
      const file = writeFixture("a_node_env.txt", `key=${TOKEN_VALUE}`);
      const result = runBashHook(`NODE_ENV=test grep key ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("assignment before a wrapper should block", () => {
      const file = writeFixture("a_both.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`LANG=C sudo -u root cat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("an assignment on its own should allow", () => {
      const result = runBashHook("LANG=C");
      expect(result.exitCode).toBe(0);
    });
  });

  describe("environment dumps behind a wrapper", () => {
    it("sudo printenv should block when the environment holds a secret", () => {
      const result = runBashHook("sudo printenv", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("sudo -u root printenv should block when the environment holds a secret", () => {
      const result = runBashHook("sudo -u root printenv", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("timeout 5 env should block when the environment holds a secret", () => {
      const result = runBashHook("timeout 5 env", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("env running a command is not a dump", () => {
      const result = runBashHook("env FOO=1 ls", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(0);
    });

    it("env -S split string reading a secret should block", () => {
      const file = writeFixture("env_split.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`env -S "cat ${file}"`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("env -S running a command is not a dump", () => {
      const result = runBashHook(`env -S "echo hi"`, {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(0);
    });

    it("env with only assignments is still a dump", () => {
      const result = runBashHook("env FOO=1 BAR=2", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("env -u FOO unsets one variable and dumps the rest", () => {
      const result = runBashHook("env -u FOO", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("env --unset FOO should also block", () => {
      const result = runBashHook("env --unset FOO", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("env -i starts from an empty environment: not a dump", () => {
      const result = runBashHook("env -i FOO=1", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(0);
    });

    it("env with output redirected is still a dump", () => {
      const result = runBashHook("env > out.txt", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // The file descriptor belongs to the operator: read as a token of its own,
    // `2` passed for env's subcommand and ruled the dump out.
    it("env with stderr redirected is still a dump", () => {
      const result = runBashHook("env 2>err.txt", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("printenv with output redirected is still a dump", () => {
      const result = runBashHook("printenv > out.txt", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("printenv naming one variable is not a dump", () => {
      const result = runBashHook("printenv PATH > out.txt", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(0);
    });
  });

  describe("inline scripts", () => {
    it("python3 -c with file read should block", () => {
      const file = writeFixture("python_script.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`python3 -c "print(open('${file}').read())"`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("python3 -c reading a path with spaces should block", () => {
      const file = writeFixture("python spaced.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`python3 -c "print(open('${file}').read())"`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("sh -c 'cat <secretFile>' should block", () => {
      const file = writeFixture("sh_c.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`sh -c "cat ${file}"`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("bash -c 'cat <secretFile>' should block", () => {
      const file = writeFixture("bash_c.txt", `token=${AWS_KEY}`);
      const result = runBashHook(`bash -c 'cat ${file}'`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("perl -pe with file should block", () => {
      const file = writeFixture("perl_file.txt", `pass=${TOKEN_VALUE}`);
      const result = runBashHook(`perl -pe 's/a/b/' ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("node -e without file reference should allow", () => {
      const result = runBashHook(`node -e "console.log(1)"`);
      expect(result.exitCode).toBe(0);
    });

    it("python3 script.py <secretFile> (script argv is not output) should allow", () => {
      const file = writeFixture("python_argv.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`python3 script.py ${file}`);
      expect(result.exitCode).toBe(0);
    });

    // Same reasoning as python: with a program file the operands are argv, and
    // only a one-liner given inline reads them as input.
    it("perl script.pl <secretFile> should allow", () => {
      const file = writeFixture("perl_argv.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`perl script.pl ${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("ruby script.rb <secretFile> should allow", () => {
      const file = writeFixture("ruby_argv.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`ruby script.rb ${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("ruby -pe with file should block", () => {
      const file = writeFixture("ruby_inline.txt", `pass=${AWS_KEY}`);
      const result = runBashHook(`ruby -pe 'gsub(/a/, "b")' ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("perl -pe with two files should block on either", () => {
      const clean = writeFixture("perl_clean.txt", "nothing here");
      const file = writeFixture("perl_second.txt", `key=${TOKEN_VALUE}`);
      const result = runBashHook(`perl -pe 's/a/b/' ${clean} ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("sh -c 'echo hello world' should allow", () => {
      const result = runBashHook(`sh -c "echo hello world"`);
      expect(result.exitCode).toBe(0);
    });
  });

  describe("git subcommands", () => {
    it("git diff <secretFile> should block", () => {
      const file = writeFixture("git_diff.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`git diff ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("git show <secretFile> should block", () => {
      const file = writeFixture("git_show.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`git show ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("git blame <secretFile> should block", () => {
      const file = writeFixture("git_blame.txt", `token=${AWS_KEY}`);
      const result = runBashHook(`git blame ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("git status should allow", () => {
      const result = runBashHook(`git status`);
      expect(result.exitCode).toBe(0);
    });

    it("git log --oneline -5 should allow", () => {
      const result = runBashHook(`git log --oneline -5`);
      expect(result.exitCode).toBe(0);
    });

    // `git log <file>` prints who changed the file and when, never a line of it.
    it("git log <secretFile> should allow", () => {
      const file = writeFixture("git_log.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`git log ${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("git log --stat <secretFile> should allow", () => {
      const file = writeFixture("git_log_stat.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`git log --stat ${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("git log -p <secretFile> should block", () => {
      const file = writeFixture("git_log_p.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`git log -p ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("git log --patch <secretFile> should block", () => {
      const file = writeFixture("git_log_patch.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`git log --patch ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("git log -U3 <secretFile> should block", () => {
      const file = writeFixture("git_log_u3.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`git log -U3 ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("git add <secretFile> (add doesn't output content) should allow", () => {
      const file = writeFixture("git_add.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`git add ${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("git -C <dir> show <secretFile> should block", () => {
      const file = writeFixture("git_dash_c.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`git -C /tmp show ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("git -c k=v show <secretFile> should block", () => {
      const file = writeFixture("git_dash_c_cfg.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`git -c core.pager=cat show ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("git difftool <secretFile> (hands off to external tool) should allow", () => {
      const file = writeFixture("git_difftool.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`git difftool ${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("git stash pop (prints no file contents) should allow", () => {
      const result = runBashHook(`git stash pop`);
      expect(result.exitCode).toBe(0);
    });
  });

  // Only a known wrapper is peeled: the first real token of any other command
  // is the command, even when a later operand happens to name a read command.
  describe("operands that look like commands", () => {
    it("echo cat <secretFile> should allow (echo prints the words, not the file)", () => {
      const file = writeFixture("echo_cat.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`echo cat ${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("printf cat <secretFile> should allow", () => {
      const file = writeFixture("printf_cat.txt", `key=${TOKEN_VALUE}`);
      const result = runBashHook(`printf cat ${file}`);
      expect(result.exitCode).toBe(0);
    });
  });

  // Held back from the shell-parsing change: each needs a classification this
  // one adds, not a parsing rule.
  describe("classification reached through a substitution or an assignment", () => {
    it("$(...) whose body contains parentheses should block", () => {
      const file = writeFixture("sub_parens.txt", `key=${AWS_KEY}`);
      const result = runBashHook(
        `echo $(python3 -c "print(open('${file}').read())")`,
      );
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("dd if=<secretFile> should block", () => {
      const file = writeFixture("dd_in.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`dd if=${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });
  });
});

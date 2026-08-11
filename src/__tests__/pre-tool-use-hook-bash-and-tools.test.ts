import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runBashHook, runGrepHook, runToolHook } from "./hook-harness.ts";

let tmpDir: string;
beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "sensitive-canary-forms-"));
});
afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function writeFixture(name: string, content: string) {
  const p = join(tmpDir, name);
  writeFileSync(p, content, "utf8");
  return p;
}

// Assemble secrets without showing full strings in file source
const AWS_KEY = ["AKIA", "IOSFODNN7", "EXAMPLE"].join("");
const TOKEN_VALUE = ["ghp_", "1234567890abcdefghij", "klmnopqrstuvwxyz"].join(
  "",
);

describe("pre-tool-use-hook — Bash forms and other tools", () => {
  describe("expanded read commands", () => {
    it("sed with pattern should block on file with secret", () => {
      const file = writeFixture("s.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`sed -n '1,5p' ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("sed -i should allow (in-place edit doesn't output)", () => {
      const file = writeFixture("edit.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`sed -i '' 's/a/b/' ${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("awk should block on file with secret", () => {
      const file = writeFixture("awk.txt", `token=${TOKEN_VALUE}`);
      const result = runBashHook(`awk '{print}' ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("grep should block on file with secret", () => {
      const file = writeFixture("grep.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`grep key ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
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
      expect(result.decision).toBe("block");
    });

    it("cut should block on file with secret", () => {
      const file = writeFixture("cut.txt", `field=${TOKEN_VALUE}`);
      const result = runBashHook(`cut -d= -f2 ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("sort should block on file with secret", () => {
      const file = writeFixture("sort.txt", `line ${AWS_KEY} end`);
      const result = runBashHook(`sort ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("base64 should block on file with secret", () => {
      const file = writeFixture("b64.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`base64 ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("xxd (hex dump) should block on file with secret", () => {
      const file = writeFixture("hex.txt", `token=${AWS_KEY}`);
      const result = runBashHook(`xxd ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
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
      expect(result.decision).toBe("block");
    });

    it("tr (non-read-command) with < redirection should block", () => {
      const file = writeFixture("tr.txt", `data=${AWS_KEY}`);
      const result = runBashHook(`tr a b < ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
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
      expect(result.decision).toBe("block");
    });

    it("a file-descriptor prefix does not hide the operands", () => {
      const file = writeFixture("fd_prefix.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`cat ${file} 2>/dev/null`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });
  });

  describe("command substitution", () => {
    it("$(...) substitution should block on file with secret", () => {
      const file = writeFixture("sub1.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`echo $(cat ${file})`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("backtick substitution should block on file with secret", () => {
      const file = writeFixture("sub2.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`echo \`cat ${file}\``);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("process substitution <(...) should block on file with secret", () => {
      const file = writeFixture("sub3.txt", `api=${AWS_KEY}`);
      const result = runBashHook(`diff <(cat ${file}) /dev/null`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("heredoc should not false positive on harmless content", () => {
      const result = runBashHook("cat <<EOF\nhello world\nEOF");
      expect(result.exitCode).toBe(0);
    });

    // The substitution body carries parentheses of its own, so a scan that stops
    // at the first `)` never sees the read inside it.
    it("$(...) whose body contains parentheses should block", () => {
      const file = writeFixture("sub_parens.txt", `key=${AWS_KEY}`);
      const result = runBashHook(
        `echo $(python3 -c "print(open('${file}').read())")`,
      );
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("nested $( $(...) ) should block on file with secret", () => {
      const file = writeFixture("sub_nested.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`echo $(echo $(cat ${file}))`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("$(...) inside double quotes should block", () => {
      const file = writeFixture("sub_dq.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`echo "$(cat ${file})"`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("$(...) inside single quotes should allow (no expansion)", () => {
      const file = writeFixture("sub_sq.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`echo '$(cat ${file})'`);
      expect(result.exitCode).toBe(0);
    });
  });

  describe("environment variables", () => {
    it("VAR expansion with default should block when var contains secret", () => {
      const pathVal = process.env["PATH"] ?? "";
      const result = runBashHook(`echo $\{TOKEN:-fallback}`, {
        env: { PATH: pathVal, TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("printenv VAR should block when var contains secret", () => {
      const pathVal = process.env["PATH"] ?? "";
      const result = runBashHook("printenv SECRET", {
        env: { PATH: pathVal, SECRET: TOKEN_VALUE },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("env (single token) should block when env contains secret", () => {
      const pathVal = process.env["PATH"] ?? "";
      const result = runBashHook("env", {
        env: { PATH: pathVal, TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("printenv (single token) should block when env contains secret", () => {
      const pathVal = process.env["PATH"] ?? "";
      const result = runBashHook("printenv", {
        env: { PATH: pathVal, SECRET: TOKEN_VALUE },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("env FOO=bar ls (env as launcher) should allow when no secrets", () => {
      const pathVal = process.env["PATH"] ?? "";
      const result = runBashHook("env FOO=1 ls", {
        env: { PATH: pathVal },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(0);
    });

    it("VAR with default should allow when var unset", () => {
      const pathVal = process.env["PATH"] ?? "";
      const result = runBashHook(`echo $\{UNSET_VAR:-safe_default}`, {
        env: { PATH: pathVal },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(0);
    });
  });

  describe("Grep tool", () => {
    it("should block on file with secret", () => {
      const file = writeFixture("grep_tool.txt", `key=${AWS_KEY}`);
      const result = runGrepHook(file);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("should allow on clean file", () => {
      const file = writeFixture("clean_grep.txt", "normal content");
      const result = runGrepHook(file);
      expect(result.exitCode).toBe(0);
    });

    it("should block on .env file", () => {
      const file = writeFixture(".env", `TOKEN=${TOKEN_VALUE}`);
      const result = runGrepHook(file);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("should allow on directory path (known limitation)", () => {
      const result = runGrepHook(tmpDir);
      expect(result.exitCode).toBe(0);
    });

    it("should allow on non-existent path", () => {
      const result = runGrepHook(join(tmpDir, "nonexistent.txt"));
      expect(result.exitCode).toBe(0);
    });
  });

  describe("backward compatibility", () => {
    it("classic cat should still block on secret", () => {
      const file = writeFixture("classic.txt", `password=${AWS_KEY}`);
      const result = runBashHook(`cat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("piped commands should work", () => {
      const file = writeFixture("pipe.txt", `key=${TOKEN_VALUE}`);
      const result = runBashHook(`cat ${file} | grep key`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("multiple arguments should all be scanned", () => {
      const file1 = writeFixture("f1.txt", "clean");
      const file2 = writeFixture("f2.txt", `secret=${AWS_KEY}`);
      const result = runBashHook(`cat ${file1} ${file2}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });
  });

  describe("wrapper commands", () => {
    it("sudo cat <secretFile> should block", () => {
      const file = writeFixture("sudo_cat.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`sudo cat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("env FOO=1 cat <secretFile> should block", () => {
      const file = writeFixture("env_cat.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`env FOO=1 cat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("timeout 5 cat <secretFile> should block", () => {
      const file = writeFixture("timeout_cat.txt", `token=${AWS_KEY}`);
      const result = runBashHook(`timeout 5 cat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
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

  describe("inline scripts", () => {
    it("python3 -c with file read should block", () => {
      const file = writeFixture("python_script.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`python3 -c "print(open('${file}').read())"`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("python3 -c reading a path with spaces should block", () => {
      const file = writeFixture("python spaced.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`python3 -c "print(open('${file}').read())"`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("sh -c 'cat <secretFile>' should block", () => {
      const file = writeFixture("sh_c.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`sh -c "cat ${file}"`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("bash -c 'cat <secretFile>' should block", () => {
      const file = writeFixture("bash_c.txt", `token=${AWS_KEY}`);
      const result = runBashHook(`bash -c 'cat ${file}'`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("perl -pe with file should block", () => {
      const file = writeFixture("perl_file.txt", `pass=${TOKEN_VALUE}`);
      const result = runBashHook(`perl -pe 's/a/b/' ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
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
      expect(result.decision).toBe("block");
    });

    it("perl -pe with two files should block on either", () => {
      const clean = writeFixture("perl_clean.txt", "nothing here");
      const file = writeFixture("perl_second.txt", `key=${TOKEN_VALUE}`);
      const result = runBashHook(`perl -pe 's/a/b/' ${clean} ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("sh -c 'echo hello world' should allow", () => {
      const result = runBashHook(`sh -c "echo hello world"`);
      expect(result.exitCode).toBe(0);
    });
  });

  describe("multi-line and chained commands", () => {
    it("newline-separated commands should block if any reads secret", () => {
      const file = writeFixture("multiline.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`echo hi\ncat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("command1 && command2 should block if any reads secret", () => {
      const file = writeFixture("and.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`ls && cat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("command1; command2 should block if any reads secret", () => {
      const file = writeFixture("semi.txt", `token=${AWS_KEY}`);
      const result = runBashHook(`ls; cat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("newline-separated safe commands should allow", () => {
      const result = runBashHook(`echo one\necho two`);
      expect(result.exitCode).toBe(0);
    });
  });

  describe("git subcommands", () => {
    it("git diff <secretFile> should block", () => {
      const file = writeFixture("git_diff.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`git diff ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("git show <secretFile> should block", () => {
      const file = writeFixture("git_show.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`git show ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("git blame <secretFile> should block", () => {
      const file = writeFixture("git_blame.txt", `token=${AWS_KEY}`);
      const result = runBashHook(`git blame ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("git status should allow", () => {
      const result = runBashHook(`git status`);
      expect(result.exitCode).toBe(0);
    });

    it("git log --oneline -5 should allow", () => {
      const result = runBashHook(`git log --oneline -5`);
      expect(result.exitCode).toBe(0);
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
      expect(result.decision).toBe("block");
    });

    it("git -c k=v show <secretFile> should block", () => {
      const file = writeFixture("git_dash_c_cfg.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`git -c core.pager=cat show ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
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

  describe("quoted paths and dd", () => {
    it("filename with space should block when secret is read", () => {
      const file = writeFixture("with space.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`cat "${file}"`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("dd if=<secretFile> should block", () => {
      const file = writeFixture("dd_file.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`dd if=${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
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

  describe("other tools and MCP", () => {
    it("mcp__filesystem__read_text_file should block on secret", () => {
      const file = writeFixture("mcp_secret.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__filesystem__read_text_file", {
        path: file,
      });
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("mcp tool with nested path should block", () => {
      const file = writeFixture("mcp_nested.txt", `secret=${TOKEN_VALUE}`);
      const result = runToolHook("mcp__example__tool", {
        arguments: { file_path: file },
      });
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("mcp tool with path objects inside an array should block", () => {
      const file = writeFixture("mcp_array.txt", `secret=${TOKEN_VALUE}`);
      const result = runToolHook("mcp__example__tool", {
        paths: [{ path: file }],
      });
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("mcp tool with nonexistent path should allow", () => {
      const result = runToolHook("mcp__example__tool", {
        path: "/api/v1/users",
      });
      expect(result.exitCode).toBe(0);
    });

    it("Write tool should allow (write operations are not checked)", () => {
      const file = writeFixture("write_target.txt", "");
      const result = runToolHook("Write", {
        file_path: file,
        content: "x",
      });
      expect(result.exitCode).toBe(0);
    });

    it("Glob tool should allow (not checked)", () => {
      const file = writeFixture("glob_target.txt", `key=${AWS_KEY}`);
      const result = runToolHook("Glob", {
        pattern: "*.ts",
        path: file,
      });
      expect(result.exitCode).toBe(0);
    });

    it("TodoWrite tool should allow (not checked)", () => {
      const result = runToolHook("TodoWrite", {
        todos: [],
      });
      expect(result.exitCode).toBe(0);
    });
  });

  describe("expanded read commands (additional)", () => {
    it("strings <secretFile> should block", () => {
      const file = writeFixture("strings_file.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`strings ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("diff <secretFile> /dev/null should block", () => {
      const file = writeFixture("diff_file.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`diff ${file} /dev/null`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("comm <secretFile> /dev/null should block", () => {
      const file = writeFixture("comm_file.txt", `token=${AWS_KEY}`);
      const result = runBashHook(`comm ${file} /dev/null`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });
  });

  // Peeling a wrapper by counting its flags mistook a flag's value for the
  // command: `sudo -u root cat f` resolved to `root`, and the file went unread.
  describe("wrappers whose flags take a value", () => {
    const blocked = (command: string) => {
      const result = runBashHook(command);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
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
      expect(result.decision).toBe("block");
    });

    it("NODE_ENV=test grep should block", () => {
      const file = writeFixture("a_node_env.txt", `key=${TOKEN_VALUE}`);
      const result = runBashHook(`NODE_ENV=test grep key ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("assignment before a wrapper should block", () => {
      const file = writeFixture("a_both.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`LANG=C sudo -u root cat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
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
      expect(result.decision).toBe("block");
    });

    it("sudo -u root printenv should block when the environment holds a secret", () => {
      const result = runBashHook("sudo -u root printenv", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("timeout 5 env should block when the environment holds a secret", () => {
      const result = runBashHook("timeout 5 env", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
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
      expect(result.decision).toBe("block");
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
      expect(result.decision).toBe("block");
    });

    it("env -u FOO unsets one variable and dumps the rest", () => {
      const result = runBashHook("env -u FOO", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("env --unset FOO should also block", () => {
      const result = runBashHook("env --unset FOO", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
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
      expect(result.decision).toBe("block");
    });

    // The file descriptor belongs to the operator: read as a token of its own,
    // `2` passed for env's subcommand and ruled the dump out.
    it("env with stderr redirected is still a dump", () => {
      const result = runBashHook("env 2>err.txt", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("printenv with output redirected is still a dump", () => {
      const result = runBashHook("printenv > out.txt", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("printenv naming one variable is not a dump", () => {
      const result = runBashHook("printenv PATH > out.txt", {
        env: { PATH: process.env["PATH"] ?? "", TOKEN: AWS_KEY },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(0);
    });
  });

  describe("write-shaped MCP tools are exempt", () => {
    it("mcp__fs__write_file should allow", () => {
      const file = writeFixture("mcp_write.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__fs__write_file", {
        path: file,
        contents: "x",
      });
      expect(result.exitCode).toBe(0);
    });

    it("mcp__fs__move_file should allow", () => {
      const file = writeFixture("mcp_move.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__fs__move_file", { path: file });
      expect(result.exitCode).toBe(0);
    });

    it("mcp__fs__read_file should still block", () => {
      const file = writeFixture("mcp_read.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__fs__read_file", { path: file });
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    // The write-name heuristic matches the tool component only: a server named
    // "editor" or "readwrite" must not exempt the read tools it offers.
    it("mcp__editor__read_file should block (server name is not the tool name)", () => {
      const file = writeFixture("mcp_editor.txt", `key=${AWS_KEY}`);
      const result = runToolHook("mcp__editor__read_file", { path: file });
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("mcp__readwrite__read_file should block (server name is not the tool name)", () => {
      const file = writeFixture("mcp_readwrite.txt", `key=${TOKEN_VALUE}`);
      const result = runToolHook("mcp__readwrite__read_file", { path: file });
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });
  });

  describe("output process substitution", () => {
    it(">(...) should block on file with secret", () => {
      const file = writeFixture("psub_out.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`echo hi >(cat ${file})`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
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
      expect(result.decision).toBe("block");
    });

    // A delimiter cut short never matches its closing line, and every following
    // line is then swallowed as body — hiding the read that comes after it.
    it("command after a hyphenated heredoc delimiter still scans", () => {
      const file = writeFixture("hyphen_delim.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`cat > s.sh <<EOF-1\nhi\nEOF-1\ncat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("command after a partly quoted heredoc delimiter still scans", () => {
      const file = writeFixture("mixed_delim.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`cat > s.sh <<E"O"F\nhi\nEOF\ncat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
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
      expect(result.decision).toBe("block");
    });

    it('cat $"<path>" should block on file with secret', () => {
      const file = writeFixture("locale_q.txt", `key=${TOKEN_VALUE}`);
      const result = runBashHook(`cat $"${file}"`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("cat $'<path with space>' should block", () => {
      const file = writeFixture("ansi space.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`cat $'${file}'`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });

    it("$'...' hex escapes should decode", () => {
      const file = writeFixture("hexesc.txt", `key=${AWS_KEY}`);
      // "hexesc" as h e x e \x73 c
      const escaped = file.replace("hexesc", "hexe\\x73c");
      const result = runBashHook(`cat $'${escaped}'`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
    });
  });
});

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const HOOK = new URL("../pre-tool-use-hook.ts", import.meta.url).pathname;
const NODE_FLAGS = ["--experimental-strip-types"];

function parseHookOutput(stdout: string) {
  try {
    const parsed = JSON.parse(stdout);
    return { decision: parsed.decision, reason: parsed.reason };
  } catch {
    return { decision: undefined, reason: undefined };
  }
}

function runBashHook(
  command: string,
  opts?: { env?: Record<string, string>; replaceEnv?: boolean },
) {
  const input = JSON.stringify({ tool_name: "Bash", tool_input: { command } });
  const envToUse = opts?.replaceEnv
    ? (opts.env ?? {})
    : { ...process.env, ...opts?.env };
  const result = spawnSync("node", [...NODE_FLAGS, HOOK], {
    input,
    encoding: "utf8",
    env: envToUse,
  });
  const { decision, reason } = parseHookOutput(result.stdout);
  return {
    exitCode: result.status ?? -1,
    stdout: result.stdout,
    stderr: result.stderr,
    decision,
    reason,
  };
}

function runGrepHook(path: string) {
  const input = JSON.stringify({
    tool_name: "Grep",
    tool_input: { pattern: "foo", path },
  });
  const result = spawnSync("node", [...NODE_FLAGS, HOOK], {
    input,
    encoding: "utf8",
    env: { ...process.env },
  });
  const { decision, reason } = parseHookOutput(result.stdout);
  return { exitCode: result.status ?? -1, decision, reason };
}

let tmpDir: string;
beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "sensitive-canary-cov-"));
});
afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function writeFixture(name: string, content: string) {
  const p = join(tmpDir, name);
  writeFileSync(p, content, "utf8");
  return p;
}

function runToolHook(toolName: string, toolInput: Record<string, unknown>) {
  const input = JSON.stringify({ tool_name: toolName, tool_input: toolInput });
  const result = spawnSync("node", [...NODE_FLAGS, HOOK], {
    input,
    encoding: "utf8",
    env: { ...process.env },
  });
  const { decision, reason } = parseHookOutput(result.stdout);
  return { exitCode: result.status ?? -1, decision, reason };
}

// Assemble secrets without showing full strings in file source
const AWS_KEY = ["AKIA", "IOSFODNN7", "EXAMPLE"].join("");
const _EMAIL = ["taro.yamada", "example.com"].join("@");
const TOKEN_VALUE = ["ghp_", "1234567890abcdefghij", "klmnopqrstuvwxyz"].join(
  "",
);

describe("pre-tool-use-hook-coverage", () => {
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
    it("wc with < redirection should block on file with secret", () => {
      const file = writeFixture("wc.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`wc -l < ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.decision).toBe("block");
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
});

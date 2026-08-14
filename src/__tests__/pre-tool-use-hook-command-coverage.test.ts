import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import {
  AWS_KEY,
  runBashHook,
  runToolHook,
  TOKEN_VALUE,
  useFixtureDir,
} from "./hook-harness.ts";

const writeFixture = useFixtureDir("commands");

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

    it("perl -pi.bak -e should allow", () => {
      const file = writeFixture("perl_pi_bak.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`perl -pi.bak -e 's/a/b/' ${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("perl -lpi -e should allow", () => {
      const file = writeFixture("perl_lpi.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`perl -lpi -e 's/a/b/' ${file}`);
      expect(result.exitCode).toBe(0);
    });

    // A flag whose value is attached ends the bundle: the letters after it are
    // the value, not more switches. Reading the whole token for an `i` found one
    // inside `-MList::Util`, `-Mstrict` and `-Ilib`, and took an ordinary
    // `perl -pe` for an in-place edit — a missed read.
    it.each([
      ["-MList::Util", "perl_m_list.txt"],
      ["-Mstrict", "perl_m_strict.txt"],
      ["-Ilib", "perl_i_lib.txt"],
    ])("perl %s -pe should block", (flag, fixture) => {
      const file = writeFixture(fixture, `key=${AWS_KEY}`);
      const result = runBashHook(`perl ${flag} -pe 'print' ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("ruby -Ilib -pe should block", () => {
      const file = writeFixture("ruby_i_lib.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`ruby -Ilib -pe 'print' ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("perl -e with an i in the program should block", () => {
      const file = writeFixture("perl_e_if.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`perl -e 'print if 1' ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("perl -pe without -i should block", () => {
      const file = writeFixture("perl_pe.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`perl -pe 's/a/b/' ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // The five inputs a previous version of the in-place check changed without
    // meaning to. The letters themselves are covered per command in
    // src/lib/__tests__/flag-and-verb-tables.test.ts; these are here because that is
    // where the mistake showed up — as an exit code, on commands people type.
    it.each([
      ["sed -Ei 's/a/b/'", "sed_Ei.txt"],
      ["sed -ri 's/a/b/'", "sed_ri.txt"],
      ["sed -zi 's/a/b/'", "sed_zi.txt"],
      ["sed --in-place=.bak 's/a/b/'", "sed_bak.txt"],
      ["perl -Ti -pe 'x'", "perl_Ti.txt"],
    ])("%s should allow", (prefix, fixture) => {
      const file = writeFixture(fixture, `key=${AWS_KEY}`);
      const result = runBashHook(`${prefix} ${file}`);
      expect(result.exitCode).toBe(0);
    });

    // `-0` is not a sed flag, so the bundle cannot be read past it and the file
    // is scanned. Treating it as in-place is how a scanned file stopped being
    // scanned.
    it("sed -0i should block", () => {
      const file = writeFixture("sed_0i.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`sed -0i 's/a/b/' ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // See IN_PLACE_EDITORS for why `-e` stops the bundle being read.
    it("sed -e with an insert command should block", () => {
      const file = writeFixture("sed_e_insert.txt", `secret=${TOKEN_VALUE}`);
      const result = runBashHook(`sed -e 'i\\hello' ${file}`);
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

    // A short flag can carry its value written against it, and that spelling was
    // not recognised: the flag looked like a plain flag, nothing marked the
    // pattern as supplied, and the file that followed was consumed as the pattern
    // instead of being scanned. Present since before this work, in all three of
    // these forms.
    it.each([
      ["grep -eaws", "attached_grep_e.txt"],
      ["grep -faws", "attached_grep_f.txt"],
      ["sed -e's/a/b/'", "attached_sed_e.txt"],
      ["sed -ei\\hello", "attached_sed_insert.txt"],
      // A one-character attached value. Every other case here uses several, and
      // the test for "is there anything after the flag" is a length comparison:
      // off by one and `grep -e. secrets` stops being scanned while these pass.
      ["grep -e.", "attached_one_char.txt"],
      ["grep -ex", "attached_one_letter.txt"],
      ["grep -fp", "attached_f_one.txt"],
      ["sed -ep", "attached_sed_one.txt"],
    ])("%s should block the file it is given", (prefix, fixture) => {
      const file = writeFixture(fixture, `key=${AWS_KEY}`);
      const result = runBashHook(`${prefix} ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // `--` ends option parsing, so what follows is the pattern and the file
    // after it is a file. Read as a flag, `-aws` marked nothing as supplying the
    // pattern, and the file was consumed in its place — the same hole the
    // attached spelling above had, reached a different way.
    it.each([
      ["grep -- -aws", "dashdash_grep.txt"],
      ["grep -- -e", "dashdash_grep_e.txt"],
      ["sed -- s/a/b/", "dashdash_sed.txt"],
    ])("%s should block the file after the pattern", (prefix, fixture) => {
      const file = writeFixture(fixture, `key=${AWS_KEY}`);
      const result = runBashHook(`${prefix} ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // Without the `--`, the same tokens mean something else: `-aws` is a bundle
    // of flags, the file is the pattern, and grep reads stdin. Nothing is read,
    // so nothing is scanned — the pair is what says the `--` is being read
    // rather than every `-`-shaped token being waved through.
    it("the same command without -- reads stdin, not the file", () => {
      const file = writeFixture("no_dashdash.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`grep -aws ${file}`);
      expect(result.exitCode).toBe(0);
    });

    // The separate-value spelling still consumes the next token, so a pattern
    // that happens to name a secret-bearing file is not scanned as an operand.
    it("grep -e with a separate value does not scan that value", () => {
      const file = writeFixture("sep_value.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`grep -e ${file} /dev/null`);
      expect(result.exitCode).toBe(0);
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

    // A name inside another expansion's suffix is a reference like any other:
    // `${A:-$SECRET}` prints the secret whenever `A` is unset. Matching each
    // expansion whole meant the suffix was skipped over to reach the closing
    // brace, and the name in it went unread.
    it.each([
      `echo $\{A:-$SECRET}`,
      `echo $\{A:-"$SECRET"}`,
      `echo $\{A:-$\{B:-$SECRET}}`,
      `echo $\{A:+$SECRET}`,
      `echo $\{A#$SECRET}`,
    ])("%s should block on the name inside the expansion", (command) => {
      const pathVal = process.env["PATH"] ?? "";
      const result = runBashHook(command, {
        env: { PATH: pathVal, SECRET: TOKEN_VALUE },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    // The outer name is still read, so an expansion naming a clean variable
    // around a secret-free suffix stays allowed.
    it("an expansion naming no secret-bearing variable is allowed", () => {
      const pathVal = process.env["PATH"] ?? "";
      const result = runBashHook(`echo $\{A:-$\{B:-fallback}}`, {
        env: { PATH: pathVal, SECRET: TOKEN_VALUE },
        replaceEnv: true,
      });
      expect(result.exitCode).toBe(0);
    });
  });

  // A token carrying glob metacharacters names whatever the shell expands it to,
  // and the file is in the expansion. Collected and then dropped — no file is
  // named `sec*` — the read went through. `.env*` is the same one character away
  // from `.env`, so the guard this hook is most sure of was a wildcard away from
  // being skipped.
  describe("glob patterns", () => {
    it.each([
      ["cat", "secret_glob.txt"],
      ["head", "secret_glob_head.txt"],
      ["sort", "secret_glob_sort.txt"],
    ])("%s expands a pattern and scans what it matches", (cmd, fixture) => {
      const file = writeFixture(fixture, `key=${AWS_KEY}`);
      const dir = writeFixture.path();
      const stem = file.slice(dir.length + 1, dir.length + 7);
      const result = runBashHook(`${cmd} ${dir}/${stem}*`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("a bare * reaches the files in the directory", () => {
      writeFixture("star_target.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`cat ${writeFixture.path()}/*`);
      expect(result.exitCode).toBe(2);
    });

    // The name guard runs on what the pattern expands to, so `.env*` is blocked
    // for the same reason `.env` is.
    it(".env* is blocked the way .env is", () => {
      writeFixture(".env", "TOKEN=whatever");
      const result = runBashHook(`cat ${writeFixture.path()}/.env*`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("a pattern matching nothing is allowed", () => {
      const result = runBashHook(`cat ${writeFixture.path()}/nomatch*`);
      expect(result.exitCode).toBe(0);
    });

    // `echo` prints its arguments, so its expansion is not a read.
    it("a pattern handed to echo is not a read", () => {
      writeFixture("echo_target.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`echo ${writeFixture.path()}/*`);
      expect(result.exitCode).toBe(0);
    });
  });

  // A tool input is whatever the tool declares. The Bash tool sends a string
  // today; an argv array is the shape an MCP shell server sends, and reading one
  // and not the other left the same command unscanned depending on who sent it.
  it("a command sent as an argv array is read", () => {
    const file = writeFixture("argv.txt", `key=${AWS_KEY}`);
    expect(runToolHook("Bash", { command: ["cat", file] }).exitCode).toBe(2);
  });

  // A redirection may stand before the command. The operator is skipped as a
  // non-command token, but its target is an ordinary word, so `secrets` was
  // taken for the command name and the real command went unclassified — a
  // spelling away from `cat < secrets`, which blocks.
  describe("a redirection before the command", () => {
    it.each(["cat", "sort", "grep aws"])("< file %s is read", (rest) => {
      const file = writeFixture(
        `lead_redirect_${rest.length}.txt`,
        `key=${AWS_KEY}`,
      );
      const result = runBashHook(`< ${file} ${rest}`);
      expect(result.exitCode).toBe(2);
    });

    it("a command that prints no contents is still not a read", () => {
      const file = writeFixture("lead_redirect_wc.txt", `key=${AWS_KEY}`);
      expect(runBashHook(`< ${file} wc -l`).exitCode).toBe(0);
    });
  });

  // Opening a path that is not a regular file can block forever: reading
  // `/dev/zero` never reaches EOF. The hook then hung until Claude Code's
  // PreToolUse timeout killed it, and a killed hook does not block the call —
  // so the hang was a fail-open. The tool-input side has always stat'd first;
  // the Bash side did not.
  describe("targets that are not regular files", () => {
    it("a character device is not read", () => {
      const result = runBashHook("cat /dev/zero");
      expect(result.exitCode).toBe(0);
    });

    it("a fifo is not read", () => {
      const fifo = writeFixture.path("fifo.pipe");
      execFileSync("mkfifo", [fifo]);
      const result = runBashHook(`cat ${fifo}`);
      expect(result.exitCode).toBe(0);
    });

    it("a directory is not read", () => {
      const result = runBashHook(`cat ${writeFixture.path()}`);
      expect(result.exitCode).toBe(0);
    });

    // The name guard runs before the file is opened, so it still applies to a
    // path that names nothing. That is what keeps `cat .env.production` blocked
    // on a machine where the file is absent.
    it("a .env name is still blocked when no such file exists", () => {
      const result = runBashHook(`cat ${writeFixture.path(".env.missing")}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
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

    // Behind a wrapper, the same operand had to survive one more search. The
    // wrapper peel walked past `echo` looking for a name it could classify and
    // found the `cat` in echo's arguments.
    it("sudo echo cat <secretFile> should allow", () => {
      const file = writeFixture("sudo_echo_cat.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`sudo echo cat ${file}`);
      expect(result.exitCode).toBe(0);
    });

    it("timeout 5 echo cat <secretFile> should allow", () => {
      const file = writeFixture("timeout_echo_cat.txt", `key=${TOKEN_VALUE}`);
      const result = runBashHook(`timeout 5 echo cat ${file}`);
      expect(result.exitCode).toBe(0);
    });

    // The stop must not cost the reads it was sitting in front of. A wrapper
    // flag's value is indistinguishable from a command name, so the search has
    // to keep going past it.
    it("sudo -u root cat <secretFile> should still block", () => {
      const file = writeFixture("sudo_u_root_cat.txt", `key=${AWS_KEY}`);
      const result = runBashHook(`sudo -u root cat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
    });

    it("timeout -s KILL 5 cat <secretFile> should still block", () => {
      const file = writeFixture(
        "timeout_kill_cat.txt",
        `secret=${TOKEN_VALUE}`,
      );
      const result = runBashHook(`timeout -s KILL 5 cat ${file}`);
      expect(result.exitCode).toBe(2);
      expect(result.blocked).toBe(true);
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

// Shell syntax, and nothing about what any particular command means.
//
// Splitting a command line into segments and tokens, quote removal, heredoc
// bodies, and the substitutions whose inner text is a command line of its own.
// Everything here answers "what are the pieces of this command line". What a
// piece does with its operands is bash-commands.ts.

// One token of a command line, with quotes removed.
//
// `redirect` records where the token came from, which quote removal otherwise
// destroys: `cat > out` writes a file and `cat ">" secrets` reads one, yet both
// yield a token whose text is `>`. Reading the text alone, the second looked
// like a redirection and the operand after it was skipped as an output target —
// so `grep ">" secrets`, an ordinary way to search for a `>` character, went
// unscanned. Only the source form separates the two.
export interface ShellToken {
  value: string;
  // True for a redirection operator the tokenizer read from the source: `<`,
  // `>`, `<<`, `>>`, `<<<`, each emitted on its own with any file-descriptor
  // prefix dropped. The token after one is a target or a heredoc delimiter
  // rather than an operand.
  redirect: boolean;
}

// Where reading continues after `s[i]`, and the quote state there.
//
// `consumed` marks a position that was quoting syntax rather than content: an
// opening or closing quote, or a backslash and the character it escapes. A
// caller skips those and inspects only the rest.
interface QuoteStep {
  next: number;
  quote: string | null;
  consumed: boolean;
}

// The quoting rule, for the scanners that only need to step over it: a quote
// character opens a run and its twin closes it, and a backslash escapes the next
// character everywhere except inside single quotes, where it is literal.
//
// Three of them spelled that out for themselves — as `quote === '"' && ch ===
// "\\"`, as `ch === "\\" && quote !== "'"`, and as `i += quote === "'" ? 1 : 2`.
// They agreed, which is the point: three spellings of one rule agree until
// someone corrects one of them.
//
// `tokenizeCommand` is not one of the three and keeps its own reading, because
// it does not step over a quoted run — it builds the token's text out of it,
// dropping the quotes, decoding `$'…'` escapes and keeping a backslash literal
// inside single quotes. Returning a position cannot say what the text became.
function stepQuote(s: string, i: number, quote: string | null): QuoteStep {
  const ch = s[i] as string;

  if (ch === "\\" && quote !== "'") {
    return { next: i + 2, quote, consumed: true };
  }
  if (quote !== null) {
    return ch === quote
      ? { next: i + 1, quote: null, consumed: true }
      : { next: i + 1, quote, consumed: false };
  }
  if (ch === "'" || ch === '"') {
    return { next: i + 1, quote: ch, consumed: true };
  }
  return { next: i + 1, quote: null, consumed: false };
}

// Variable names referenced by the command, including expansion forms that carry
// a suffix such as `${TOKEN:-fallback}` or `${TOKEN#prefix}`.
//
// Every `$` that a name follows counts, rather than each expansion being matched
// whole. Matching `${NAME…}` as a unit meant the suffix was consumed by the
// pattern that skipped to the closing brace, and a name inside the suffix went
// with it: `${A:-$TOKEN}` prints `$TOKEN` when `A` is unset, and named only `A`.
// An unclosed `${NAME` now yields its name too, which errs towards scanning.
export function extractEnvVarNames(command: string): string[] {
  const names = new Set<string>();
  for (const match of command.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)/g)) {
    const name = match[1];
    if (name) names.add(name);
  }
  return [...names];
}

// Options for tokenizeCommand. The default reading is the one every caller has
// always had, and it stays byte-for-byte the same.
export interface TokenizeOptions {
  // Read redirection operators the way bash spells them, rather than stopping
  // each at the first character that is not part of its run.
  //
  // The default ends a `<` or `>` run before a following `&` or `|`, so `2>&1`
  // becomes `2>` followed by a separator. That is right for POSIX sh, where
  // `&>` is a background `&` and then `>`: `dash -c 'true &>/dev/stdout cat f'`
  // runs `cat f`. So the default reading must stay, and a caller that wants
  // the bash reading asks for it and scans both.
  //
  // The joined reading takes `>&`, `<&`, `>|`, `&>`, `&>>` and `&>|` as one
  // operator each, skipping line continuations between their characters. After
  // `>&` or `<&` a run of digits or a `-` is the operator's target, emitted as
  // a token of its own so the operand after it is not mistaken for its target.
  joinRedirections?: boolean;
}

// Split a command line into segments (at |, ;, &, &&, || and newlines) and each
// segment into tokens with quotes removed. Redirection operators become tokens of
// their own so that `wc -l <f` and `wc -l < f` tokenize alike. Substitutions are
// left in place; extractSubstitutions handles them against the raw string.
export function tokenizeCommand(
  command: string,
  options: TokenizeOptions = {},
): ShellToken[][] {
  const joined = options.joinRedirections === true;
  const segments: ShellToken[][] = [];
  let tokens: ShellToken[] = [];
  let current = "";
  let hasCurrent = false;
  let i = 0;

  const endToken = (): void => {
    if (hasCurrent) {
      tokens.push({ value: current, redirect: false });
      current = "";
      hasCurrent = false;
    }
  };
  const endSegment = (): void => {
    endToken();
    if (tokens.length > 0) segments.push(tokens);
    tokens = [];
  };

  while (i < command.length) {
    const ch = command[i] as string;

    if (ch === "\\") {
      const next = command[i + 1];
      if (next !== undefined && next !== "\n") {
        current += next;
        hasCurrent = true;
      }
      i += next === undefined ? 1 : 2;
      continue;
    }

    if (
      ch === "'" ||
      ch === '"' ||
      (ch === "$" && (command[i + 1] === "'" || command[i + 1] === '"'))
    ) {
      // $'...' (ANSI-C) and $"..." (locale) are quoting syntax: the `$` is not
      // part of the token. Inside $'...', backslash escapes are decoded.
      let quote = ch;
      let ansiC = false;
      if (ch === "$") {
        quote = command[i + 1] as string;
        ansiC = quote === "'";
        i += 2;
      } else {
        i++;
      }
      hasCurrent = true;
      while (i < command.length && command[i] !== quote) {
        if (command[i] === "\\" && command[i + 1] !== undefined) {
          if (quote === '"' || ansiC) {
            current += ansiC
              ? decodeAnsiCEscape(command, i)
              : (command[i + 1] as string);
            i += ansiC ? ansiCEscapeLength(command, i) : 2;
            continue;
          }
          // plain single quotes keep backslashes literal
        }
        current += command[i];
        i++;
      }
      i++; // closing quote, or end of input for an unbalanced one
      continue;
    }

    // `&>` is a redirection in bash, but only in the joined reading. The
    // default keeps it as a separator, because POSIX sh splits it into `&` and
    // `>`.
    if (joined && ch === "&") {
      const gt = skipLineContinuations(command, i + 1);
      if (command[gt] === ">") {
        // Not a file descriptor prefix: `2&>f` is the word `2`, then `&>f`.
        endToken();
        const operator = readRedirectOperator(command, gt, true, "&");
        tokens.push({ value: operator.op, redirect: true });
        i = operator.next;
        continue;
      }
    }

    if (ch === "|" || ch === ";" || ch === "&" || ch === "\n") {
      endSegment();
      while (i < command.length && /[|;&\n\s]/.test(command[i] as string)) i++;
      continue;
    }

    // A substitution standing among the operands is one word to the command, so
    // it is consumed whole and no token is emitted for it. Ending the segment
    // here instead would cut the operand list in two: `cat <(echo hi) secrets`
    // leaves `secrets` in a segment of its own, where it reads as a command name
    // and its own reading goes unseen.
    //
    // The inner command is still reached: extractSubstitutions walks the raw
    // string for these forms, and the paths are deduplicated.
    if ((ch === "$" || ch === "<" || ch === ">") && command[i + 1] === "(") {
      endToken();
      i = findSubstitutionEnd(command, i + 2, ")") + 1;
      continue;
    }

    // A subshell holds a command line of its own. Without this, `(cat secrets)`
    // tokenized as `(cat` and `secrets)`, naming neither a command this hook
    // classifies nor a path that exists, and the read went unseen.
    if (ch === "(" || ch === ")") {
      endSegment();
      i++;
      continue;
    }

    if (ch === "<" || ch === ">") {
      // A file-descriptor prefix belongs to the operator, not to a token of its
      // own, so `cmd 2>err` tokenizes like `cmd >err`. Left as a token, the `2`
      // would read as an operand of the command — a filename, or a subcommand
      // for whatever later decides what a command does with its operands. It
      // names neither, so it is dropped. Only digits written against the
      // operator count, leaving `sort 1 >out` alone.
      if (hasCurrent && /^\d+$/.test(current)) {
        current = "";
        hasCurrent = false;
      }
      endToken();
      const operator = readRedirectOperator(command, i, joined);
      tokens.push({ value: operator.op, redirect: true });
      if (operator.target !== null) {
        tokens.push({ value: operator.target, redirect: false });
      }
      i = operator.next;
      continue;
    }

    if (ch === " " || ch === "\t" || ch === "\r") {
      endToken();
      i++;
      continue;
    }

    current += ch;
    hasCurrent = true;
    i++;
  }

  endSegment();
  return segments;
}

// Index just past any line continuations (a backslash and a newline) at `i`.
//
// A continuation is removed before the shell reads an operator, so
// `cat 2>\<newline>&1` is `2>&1`. The joined reading looks past them when it
// decides whether an operator goes on, and the default reading does not, which
// is why the two readings disagree on these spellings.
function skipLineContinuations(command: string, i: number): number {
  let j = i;
  while (command[j] === "\\" && command[j + 1] === "\n") j += 2;
  return j;
}

// The redirection operator whose first character is at `start`, and where the
// tokenizer resumes after it. `prefix` is `&` for the `&>` forms.
//
// The default reading takes the run of `<` or `>` and nothing else. The joined
// reading also takes a directly following `&`, and a `|` after a `>`, so that
// `>&` and `>|` are each one operator. `target` is the digits or `-` that
// `>&` and `<&` name, or null.
interface RedirectOperator {
  op: string;
  target: string | null;
  next: number;
}

function readRedirectOperator(
  command: string,
  start: number,
  joined: boolean,
  prefix = "",
): RedirectOperator {
  const ch = command[start] as string;
  let op = prefix + ch;
  let i = start + 1;

  if (!joined) {
    while (i < command.length && command[i] === ch) {
      op += ch;
      i++;
    }
    return { op, target: null, next: i };
  }

  for (;;) {
    const j = skipLineContinuations(command, i);
    if (command[j] !== ch) break;
    op += ch;
    i = j + 1;
  }

  // `>&` and `<&`. The `|` that follows `>&` in `>&|` is taken below, with the
  // `|` of `>|`.
  const amp = skipLineContinuations(command, i);
  const joinedAmp = command[amp] === "&";
  if (joinedAmp) {
    op += "&";
    i = amp + 1;
  }
  if (ch === ">") {
    const bar = skipLineContinuations(command, i);
    if (command[bar] === "|") {
      op += "|";
      i = bar + 1;
    }
  }

  let target: string | null = null;
  if (joinedAmp && !op.endsWith("|")) {
    const at = skipLineContinuations(command, i);
    const digits = /^(?:\d+|-)/.exec(command.slice(at));
    if (digits) {
      target = digits[0];
      i = at + digits[0].length;
    }
  }

  return { op, target, next: i };
}

// Length of the ANSI-C escape starting at `command[i]` (a backslash), so the
// tokenizer can skip the whole sequence: \xHH is 4 chars, anything else is 2.
function ansiCEscapeLength(command: string, i: number): number {
  return command[i + 1] === "x" &&
    /^[0-9A-Fa-f]{2}$/.test(command.slice(i + 2, i + 4))
    ? 4
    : 2;
}

// Decode the ANSI-C escape starting at `command[i]` (a backslash). Covers the
// escapes that appear in paths: \\, \', \", \xHH and the common letter escapes.
function decodeAnsiCEscape(command: string, i: number): string {
  const esc = command[i + 1] as string;
  if (esc === "x" && /^[0-9A-Fa-f]{2}$/.test(command.slice(i + 2, i + 4))) {
    return String.fromCharCode(
      Number.parseInt(command.slice(i + 2, i + 4), 16),
    );
  }
  const simple: Record<string, string> = {
    "\\": "\\",
    "'": "'",
    '"': '"',
    n: "\n",
    t: "\t",
    r: "\r",
    "0": "\0",
  };
  return simple[esc] ?? esc;
}

// One heredoc delimiter introduced by a command line. `allowTabs` marks the
// `<<-` form, whose closing delimiter may be tab-indented.
interface HeredocDelimiter {
  delim: string;
  allowTabs: boolean;
}

// The delimiter word starting at `line[from]`, with quote removal applied the way
// the shell does it: `<<EOF`, `<<'EOF'`, `<<"EOF"` and `<<E"O"F` all end their
// body at the line `EOF`. The word ends at whitespace or a shell metacharacter.
//
// A narrower character class (`[A-Za-z0-9_.]`) cuts the word short, and a
// truncated delimiter never matches the real closing line: stripHeredocBodies
// then swallows the rest of the command, so `cat > f <<EOF-1 … EOF-1` followed
// by `cat .env` hides the read entirely.
function readHeredocDelimiter(
  line: string,
  from: number,
): { delim: string; next: number } {
  let delim = "";
  let i = from;

  while (i < line.length) {
    const ch = line[i] as string;
    if (ch === "'" || ch === '"') {
      i++;
      while (i < line.length && line[i] !== ch) {
        if (ch === '"' && line[i] === "\\" && line[i + 1] !== undefined) {
          delim += line[i + 1];
          i += 2;
          continue;
        }
        delim += line[i];
        i++;
      }
      i++; // closing quote, or end of line for an unbalanced one
      continue;
    }
    if (ch === "\\" && line[i + 1] !== undefined) {
      delim += line[i + 1];
      i += 2;
      continue;
    }
    if (/[\s|&;()<>`]/.test(ch)) break;
    delim += ch;
    i++;
  }

  return { delim, next: i };
}

// Heredoc delimiters introduced by one command line, in order. `<<-` allows a
// tab-indented closing delimiter; `<<<` is a herestring and is not a heredoc.
// Matches outside quotes only, so `echo "a <<EOF b"` is not a heredoc start.
function findHeredocDelimiters(line: string): HeredocDelimiter[] {
  const found: HeredocDelimiter[] = [];
  let quote: string | null = null;
  let i = 0;

  while (i < line.length) {
    const step = stepQuote(line, i, quote);
    quote = step.quote;
    if (step.consumed || quote !== null) {
      i = step.next;
      continue;
    }
    const ch = line[i] as string;
    if (ch === "<" && line[i + 1] === "<") {
      let j = i + 2;
      let allowTabs = false;
      if (line[j] === "-") {
        allowTabs = true;
        j++;
      }
      if (line[j] === "<") {
        i = j; // herestring
        continue;
      }
      while (line[j] === " " || line[j] === "\t") j++;
      const { delim, next } = readHeredocDelimiter(line, j);
      if (delim) found.push({ delim, allowTabs });
      i = next;
      continue;
    }
    i++;
  }

  return found;
}

// Remove heredoc bodies from a command line. A body is text, not commands —
// `cat > deploy.sh <<EOF` followed by a script that mentions `.env` reads
// nothing, and scanning the body as shell blocks exactly that everyday case.
// The trade-off: a heredoc that *feeds* commands to a remote shell
// (`ssh host <<EOF\ncat /secret\nEOF`) is not caught. Written up as a
// known limitation under "② PreToolUse hook" in the README.
export function stripHeredocBodies(command: string): string {
  const lines = command.split("\n");
  const kept: string[] = [];
  const pending: HeredocDelimiter[] = [];

  for (const line of lines) {
    if (pending.length > 0) {
      const first = pending[0] as HeredocDelimiter;
      const cmp = first.allowTabs ? line.replace(/^\t+/, "") : line;
      if (cmp === first.delim) pending.shift();
      continue;
    }
    pending.push(...findHeredocDelimiters(line));
    kept.push(line);
  }

  return kept.join("\n");
}

// A comment in a command line, as the shell reads it. `start` is the `#` and
// `end` is the newline or closing backquote that stops it, or the end of input.
export interface CommentSpan {
  start: number;
  end: number;
}

// What the comment scanner is reading at a given point. `top`, `subshell`,
// `cmdsub` (`$(...)`) and `procsub` (`<(...)`, `>(...)`) are command lines, and
// `backquote` is a command line that ends at its closing backquote. `arithcmd`
// is `((...))` and `arithexp` is `$((...))`, where `#` is not a comment. `param`
// is `${...}`, also free of comments, and `dq` is a double-quoted run.
// `parens` counts the parentheses opened inside an arithmetic frame.
type ScanKind =
  | "top"
  | "subshell"
  | "cmdsub"
  | "procsub"
  | "backquote"
  | "arithcmd"
  | "arithexp"
  | "param"
  | "dq";

interface ScanFrame {
  kind: ScanKind;
  parens: number;
}

// Index just past the single-quoted run whose body starts at `from`. A run that
// never closes runs to the end of the input, as the shell reads it.
function skipSingleQuoted(command: string, from: number): number {
  const close = command.indexOf("'", from);
  return close === -1 ? command.length : close + 1;
}

// Index just past the `$'...'` run whose body starts at `from`. A backslash
// escapes the next character, so `\'` does not close it.
function skipAnsiCQuoted(command: string, from: number): number {
  let i = from;
  while (i < command.length && command[i] !== "'") {
    i += command[i] === "\\" ? 2 : 1;
  }
  return Math.min(i + 1, command.length);
}

// Pushes the substitution or expansion that starts at `i` and returns the index
// past its opener, or null when none starts there. Inside `"..."`, `${...}`,
// `((...))` and backquotes these all open the same way.
function openNested(
  command: string,
  i: number,
  stack: ScanFrame[],
): number | null {
  const ch = command[i];
  const next = command[i + 1];
  if (ch === "$" && next === "(") {
    if (command[i + 2] === "(") {
      stack.push({ kind: "arithexp", parens: 0 });
      return i + 3;
    }
    stack.push({ kind: "cmdsub", parens: 0 });
    return i + 2;
  }
  if (ch === "$" && next === "{") {
    stack.push({ kind: "param", parens: 0 });
    return i + 2;
  }
  if (ch === "`") {
    stack.push({ kind: "backquote", parens: 0 });
    return i + 1;
  }
  return null;
}

// Index just past the body of each heredoc opened on the line just ended. A
// body runs to the line that equals its delimiter, and nothing in it is a
// comment or a quote, so `# it's` inside a heredoc is text.
function skipHeredocBodies(
  command: string,
  from: number,
  pending: HeredocDelimiter[],
): number {
  let i = from;
  while (pending.length > 0 && i < command.length) {
    const eol = command.indexOf("\n", i);
    const end = eol === -1 ? command.length : eol;
    const line = command.slice(i, end);
    const first = pending[0] as HeredocDelimiter;
    const cmp = first.allowTabs ? line.replace(/^\t+/, "") : line;
    if (cmp === first.delim) pending.shift();
    i = end + 1;
  }
  return Math.min(i, command.length);
}

// Every comment in a command line, found the way the shell finds them. A `#`
// starts a comment only where a word starts outside quotes, `${...}` and
// heredoc bodies. A word starts at the beginning of the input, after blanks,
// newlines and the operators `;`, `&`, `|`, `<`, `>`, and after `(`. A `)` also
// starts one when it closes a subshell, a function's `()`, an arithmetic command
// or a case pattern, but not when it closes `$(...)`, `<(...)` or `$((...))`,
// because the word goes on after those: `echo $(date)#x` has no comment.
//
// The scan is one pass with an explicit stack of the constructs it is inside,
// so a deeply nested line cannot overflow the call stack. Where it cannot tell,
// it errs toward a comment: callers only add a reading when a comment is found,
// so a wrong comment can add scanning and cannot hide any.
export function findComments(command: string): CommentSpan[] {
  const spans: CommentSpan[] = [];
  const stack: ScanFrame[] = [{ kind: "top", parens: 0 }];
  const heredocs: HeredocDelimiter[] = [];
  let wordStart = true;
  let i = 0;

  while (i < command.length) {
    const frame = stack[stack.length - 1] as ScanFrame;
    const ch = command[i] as string;
    const next = command[i + 1];

    if (frame.kind === "dq") {
      if (ch === "\\") {
        i += 2;
      } else if (ch === '"') {
        stack.pop();
        i++;
      } else {
        i = openNested(command, i, stack) ?? i + 1;
      }
      continue;
    }

    if (frame.kind === "param") {
      if (ch === "\\") {
        i += 2;
      } else if (ch === "}") {
        stack.pop();
        wordStart = false;
        i++;
      } else if (ch === "'") {
        i = skipSingleQuoted(command, i + 1);
      } else if (ch === '"') {
        stack.push({ kind: "dq", parens: 0 });
        i++;
      } else {
        i = openNested(command, i, stack) ?? i + 1;
      }
      continue;
    }

    if (frame.kind === "arithcmd" || frame.kind === "arithexp") {
      // In arithmetic `<<` is a shift and `#` is not a comment, so neither is
      // taken for a heredoc or a comment here.
      if (ch === "\\") {
        i += 2;
      } else if (ch === "'") {
        i = skipSingleQuoted(command, i + 1);
      } else if (ch === '"') {
        stack.push({ kind: "dq", parens: 0 });
        i++;
      } else if (ch === "(") {
        frame.parens++;
        i++;
      } else if (ch === ")" && frame.parens > 0) {
        frame.parens--;
        i++;
      } else if (ch === ")") {
        // `))` closes the expression. A `((` command is followed by a command,
        // so a word can start after it; a `$((` expansion is part of a word.
        stack.pop();
        wordStart = frame.kind === "arithcmd";
        i += next === ")" ? 2 : 1;
      } else {
        i = openNested(command, i, stack) ?? i + 1;
      }
      continue;
    }

    // The rest are command lines, and a backquote body is one.
    if (ch === "\\") {
      // A backslash-newline joins the lines and does not start a word.
      if (next === "\n") {
        i += 2;
      } else {
        wordStart = false;
        i += 2;
      }
      continue;
    }

    if (ch === "\n") {
      wordStart = true;
      i = skipHeredocBodies(command, i + 1, heredocs);
      continue;
    }

    if (/[ \t\r;&|]/.test(ch)) {
      wordStart = true;
      i++;
      continue;
    }

    if (ch === "#" && wordStart) {
      const inBackquote = frame.kind === "backquote";
      let end = i;
      while (
        end < command.length &&
        command[end] !== "\n" &&
        !(inBackquote && command[end] === "`")
      ) {
        end++;
      }
      spans.push({ start: i, end });
      i = end;
      continue;
    }

    if (ch === "'") {
      i = skipSingleQuoted(command, i + 1);
      wordStart = false;
      continue;
    }

    if (ch === "$" && next === "'") {
      i = skipAnsiCQuoted(command, i + 2);
      wordStart = false;
      continue;
    }

    if (ch === '"') {
      stack.push({ kind: "dq", parens: 0 });
      i++;
      wordStart = false;
      continue;
    }

    if (ch === "`") {
      if (frame.kind === "backquote") {
        stack.pop();
        wordStart = false;
      } else {
        stack.push({ kind: "backquote", parens: 0 });
        wordStart = true;
      }
      i++;
      continue;
    }

    if (ch === "$" && (next === "(" || next === "{")) {
      wordStart = next === "(";
      i = openNested(command, i, stack) ?? i + 2;
      continue;
    }

    if ((ch === "<" || ch === ">") && next === "(") {
      stack.push({ kind: "procsub", parens: 0 });
      wordStart = true;
      i += 2;
      continue;
    }

    if (ch === "<" && next === "<") {
      wordStart = false;
      if (command[i + 2] === "<") {
        i += 3; // a herestring, not a heredoc
        continue;
      }
      let j = i + 2;
      let allowTabs = false;
      if (command[j] === "-") {
        allowTabs = true;
        j++;
      }
      while (command[j] === " " || command[j] === "\t") j++;
      // The delimiter is read from its own line only, so an unclosed quote in
      // it cannot run on into the next line.
      const eol = command.indexOf("\n", j);
      const line = command.slice(0, eol === -1 ? command.length : eol);
      const { delim, next: after } = readHeredocDelimiter(line, j);
      if (delim) heredocs.push({ delim, allowTabs });
      i = after;
      continue;
    }

    if (ch === "<" || ch === ">") {
      wordStart = true;
      i++;
      continue;
    }

    if (ch === "(") {
      if (next === "(") {
        stack.push({ kind: "arithcmd", parens: 0 });
        i += 2;
      } else {
        stack.push({ kind: "subshell", parens: 0 });
        i++;
      }
      wordStart = true;
      continue;
    }

    if (ch === ")") {
      if (
        frame.kind === "subshell" ||
        frame.kind === "cmdsub" ||
        frame.kind === "procsub"
      ) {
        stack.pop();
        wordStart = frame.kind === "subshell";
      } else {
        // A case pattern's `)`, or one with nothing open: a word may follow.
        wordStart = true;
      }
      i++;
      continue;
    }

    wordStart = false;
    i++;
  }

  return spans;
}

// The command line with each comment removed, `#` included, up to but not
// including the newline or closing backquote that ends it. The words of a
// comment are not commands, so removing them is what lets a reading of the line
// proceed past the comment as the shell does.
export function blankComments(command: string): string {
  let out = "";
  let last = 0;
  for (const { start, end } of findComments(command)) {
    out += command.slice(last, start);
    last = end;
  }
  return out + command.slice(last);
}

// Substitution syntaxes whose inner text is a command line in its own right.
// Command substitution and backticks expand inside double quotes; the process
// substitutions do not, so `echo "<(cat f)"` is a literal string.
const SUBSTITUTIONS = [
  { open: "$(", close: ")", expandsInDoubleQuotes: true },
  { open: "<(", close: ")", expandsInDoubleQuotes: false },
  { open: ">(", close: ")", expandsInDoubleQuotes: false },
  { open: "`", close: "`", expandsInDoubleQuotes: true },
];

// Index of the character closing a substitution whose body starts at `from`.
// Parentheses are counted rather than matched with a regex, because a body
// carries parentheses of its own: `$(python3 -c "print(open('.env').read())")`
// was cut short at the first `)` by the old `[^()]*` pattern, and the read it
// contained was never scanned. Quotes and backslashes inside the body are
// respected. An unbalanced substitution runs to the end of the string.
function findSubstitutionEnd(
  command: string,
  from: number,
  close: string,
): number {
  let depth = 0;
  let quote: string | null = null;

  let i = from;
  while (i < command.length) {
    const step = stepQuote(command, i, quote);
    quote = step.quote;
    if (step.consumed || quote !== null) {
      i = step.next;
      continue;
    }
    const ch = command[i] as string;
    const at = i;
    i = step.next;
    if (close === "`") {
      if (ch === "`") return at;
      continue;
    }
    if (ch === "(") depth++;
    else if (ch === ")") {
      if (depth === 0) return at;
      depth--;
    }
  }

  return command.length;
}

// Inner text of every outermost command substitution, process substitution and
// backtick expression. Only the outermost ones: each is a command line in its
// own right, so a nested substitution is reached by the caller feeding what this
// returns back through it.
export function extractSubstitutions(command: string): string[] {
  const found: string[] = [];
  let quote: string | null = null;
  let i = 0;

  // Unlike the scanners above, this one has to look inside double quotes: a
  // command substitution expands there. So it skips only what `stepQuote` calls
  // consumed, and asks the quote state whether an opener counts where it stands.
  while (i < command.length) {
    const step = stepQuote(command, i, quote);
    quote = step.quote;
    if (step.consumed) {
      i = step.next;
      continue;
    }

    const opener = SUBSTITUTIONS.find(
      (s) =>
        command.startsWith(s.open, i) &&
        (quote === null || (quote === '"' && s.expandsInDoubleQuotes)),
    );
    if (opener === undefined) {
      i = step.next;
      continue;
    }

    const bodyStart = i + opener.open.length;
    const end = findSubstitutionEnd(command, bodyStart, opener.close);
    found.push(command.slice(bodyStart, end));
    i = end + 1;
  }

  return found;
}

// Shell keywords and the brace-group delimiters. They stand where a command
// name would, so without this list a segment led by one is classified as a
// command called `{` or `then` and its operands are never looked at:
// `{ cat secrets; }`, `if …; then cat secrets; fi` and
// `while cat secrets; do :; done` each read a file nothing notices. The keywords that open a condition (`if`, `while`,
// `until`) matter as much as the ones that open a body: the command being tested
// runs too.
export const SHELL_KEYWORD_TOKENS = new Set([
  "{",
  "}",
  "!",
  "if",
  "then",
  "else",
  "elif",
  "fi",
  "while",
  "until",
  "for",
  "do",
  "done",
  "case",
  "esac",
  "in",
  "select",
]);

// True for a token that cannot name a command: a redirection operator, a flag, a
// `VAR=value` assignment placed before one, or a shell keyword.
export function isNonCommandToken(token: ShellToken): boolean {
  if (token.redirect) return true;
  const { value } = token;
  if (value.startsWith("-")) return true;
  if (SHELL_KEYWORD_TOKENS.has(value)) return true;
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(value);
}

// Longest quoted literal inside inline code still treated as a path candidate.
// Exported so its test reads the cap instead of copying the number.
export const MAX_QUOTED_LITERAL_LENGTH = 4096;

// Quoted literals inside inline program text — the ".env" in
// `python3 -c "print(open('.env').read())"`. Literals containing line breaks or
// tabs are skipped: those are messages and patterns, not paths. Spaces are kept,
// so a path like `open('my secret.txt')` is still found.
export function extractQuotedLiterals(code: string): string[] {
  const literals: string[] = [];
  for (const match of code.matchAll(/'([^']*)'|"([^"]*)"/g)) {
    const value = match[1] ?? match[2];
    if (
      value &&
      value.length <= MAX_QUOTED_LITERAL_LENGTH &&
      !/[\t\r\n]/.test(value)
    ) {
      literals.push(value);
    }
  }
  return literals;
}

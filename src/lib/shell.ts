// Shell syntax, and nothing about what any particular command means.
//
// Splitting a command line into segments and tokens, quote removal, heredoc
// bodies, and the substitutions whose inner text is a command line of its own.
// Everything here answers "what are the pieces of this command line". What a
// piece does with its operands is bash-commands.ts.

// Longest quoted literal inside inline code still treated as a path candidate.
const MAX_QUOTED_LITERAL_LENGTH = 4096;

// Variable names referenced by the command, including expansion forms that carry
// a suffix such as `${TOKEN:-fallback}` or `${TOKEN#prefix}`.
export function extractEnvVarNames(command: string): string[] {
  const names = new Set<string>();
  const re = /\$\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}|\$([A-Za-z_][A-Za-z0-9_]*)/g;
  for (const match of command.matchAll(re)) {
    const name = match[1] ?? match[2];
    if (name) names.add(name);
  }
  return [...names];
}

// Split a command line into segments (at |, ;, &, &&, || and newlines) and each
// segment into tokens with quotes removed. Redirection operators become tokens of
// their own so that `wc -l <f` and `wc -l < f` tokenize alike. Substitutions are
// left in place; extractSubstitutions handles them against the raw string.
export function tokenizeCommand(command: string): string[][] {
  const segments: string[][] = [];
  let tokens: string[] = [];
  let current = "";
  let hasCurrent = false;
  let i = 0;

  const endToken = (): void => {
    if (hasCurrent) {
      tokens.push(current);
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

    if (ch === "|" || ch === ";" || ch === "&" || ch === "\n") {
      endSegment();
      while (i < command.length && /[|;&\n\s]/.test(command[i] as string)) i++;
      continue;
    }

    // A subshell holds a command line of its own. Without this, `(cat secrets)`
    // tokenized as `(cat` and `secrets)`, naming neither a command this hook
    // classifies nor a path that exists, and the read went unseen. The opening
    // paren of `$(`, `<(` and `>(` lands here too, which only means the inner
    // command is reached twice — extractSubstitutions already recurses into it,
    // and the paths are deduplicated.
    if (ch === "(" || ch === ")") {
      endSegment();
      i++;
      continue;
    }

    if (ch === "<" || ch === ">") {
      // A file-descriptor prefix belongs to the operator, not to a token of its
      // own: `env 2>err` has to tokenize like `env >err`, or the `2` reads as
      // env's subcommand and the environment dump goes unnoticed. The number
      // names neither a file nor a command, so it is dropped. Only digits
      // written against the operator count, leaving `sort 1 >out` alone.
      if (hasCurrent && /^\d+$/.test(current)) {
        current = "";
        hasCurrent = false;
      }
      endToken();
      let op = ch;
      i++;
      while (i < command.length && command[i] === ch) {
        op += ch;
        i++;
      }
      tokens.push(op);
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
// A narrower character class (`[A-Za-z0-9_.]`) used to cut the word short, and the
// truncated delimiter then never matched the real closing line: stripHeredocBodies
// swallowed the rest of the command, so `cat > f <<EOF-1 … EOF-1` followed by
// `cat .env` hid the read entirely.
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
    const ch = line[i] as string;
    if (quote !== null) {
      if (quote === '"' && ch === "\\") i++;
      else if (ch === quote) quote = null;
      i++;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      i++;
      continue;
    }
    if (ch === "\\") {
      i += 2;
      continue;
    }
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
// nothing, and scanning the body as shell blocked exactly that everyday case.
// The trade-off: a heredoc that *feeds* commands to a remote shell
// (`ssh host <<EOF\ncat /secret\nEOF`) is no longer caught. Documented as a
// known limitation in the README.
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

  for (let i = from; i < command.length; i++) {
    const ch = command[i] as string;
    if (ch === "\\" && quote !== "'") {
      i++;
      continue;
    }
    if (quote !== null) {
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (close === "`") {
      if (ch === "`") return i;
      continue;
    }
    if (ch === "(") depth++;
    else if (ch === ")") {
      if (depth === 0) return i;
      depth--;
    }
  }

  return command.length;
}

// Inner text of every outermost command substitution, process substitution and
// backtick expression. Each is a command line in its own right; nested ones are
// reached because extractCommandRefs recurses into what this returns.
export function extractSubstitutions(command: string): string[] {
  const found: string[] = [];
  let quote: string | null = null;
  let i = 0;

  while (i < command.length) {
    const ch = command[i] as string;

    if (ch === "\\") {
      i += quote === "'" ? 1 : 2;
      continue;
    }
    if (quote === "'") {
      if (ch === quote) quote = null;
      i++;
      continue;
    }
    if (quote === '"' && ch === '"') {
      quote = null;
      i++;
      continue;
    }
    if (quote === null && (ch === "'" || ch === '"')) {
      quote = ch;
      i++;
      continue;
    }

    const opener = SUBSTITUTIONS.find(
      (s) =>
        command.startsWith(s.open, i) &&
        (quote === null || s.expandsInDoubleQuotes),
    );
    if (opener === undefined) {
      i++;
      continue;
    }

    const bodyStart = i + opener.open.length;
    const end = findSubstitutionEnd(command, bodyStart, opener.close);
    found.push(command.slice(bodyStart, end));
    i = end + 1;
  }

  return found;
}

// True for a redirection operator token: `<`, `>`, `<<`, `>>`, `<<<`. The
// tokenizer emits each on its own, with any file-descriptor prefix dropped, and
// the token after one is a target or a heredoc delimiter rather than an operand.
export function isRedirectionOperator(token: string): boolean {
  return /^[<>]+$/.test(token);
}

// Shell keywords and the brace-group delimiters. They stand where a command
// name would, so a segment led by one used to be classified as a command called
// `{` or `then` and its operands never looked at: `{ cat secrets; }`,
// `if …; then cat secrets; fi` and `while cat secrets; do :; done` all read a
// file nothing noticed. The keywords that open a condition (`if`, `while`,
// `until`) matter as much as the ones that open a body: the command being tested
// runs too.
const SHELL_KEYWORD_TOKENS = new Set([
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

// True for a token that cannot name a command: a flag, a redirection operator,
// a `VAR=value` assignment placed before one, or a shell keyword.
export function isNonCommandToken(token: string): boolean {
  if (token.startsWith("-") || token.startsWith("<") || token.startsWith(">")) {
    return true;
  }
  if (SHELL_KEYWORD_TOKENS.has(token)) return true;
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(token);
}

// Quoted literals inside inline program text — the ".env" in
// `python3 -c "print(open('.env').read())"`. Literals containing line breaks or
// tabs are skipped: those are messages and patterns, not paths. Spaces are
// kept, so a path like `open('my secret.txt')` is still found.
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

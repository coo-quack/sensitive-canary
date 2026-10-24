// Column-aware detection: the values under a labelled header in a table, and
// the column of a SQL INSERT.
//
// A regex reads one line at a time, so it cannot reach a value in the row under
// a header. These readers read the table instead: a header names a column, and
// the cell at that column in each row under it is a value. Every character is
// read once, and no regex finds the rows, so the pass is linear in the text.

type Delimiter = "|" | "\t" | ",";

// One layer of surrounding quotes or backticks, as a cell or a label may carry.
function unquote(text: string): string {
  if (text.length >= 2) {
    const first = text[0];
    if (
      first === text[text.length - 1] &&
      (first === '"' || first === "'" || first === "`")
    )
      return text.slice(1, -1);
  }
  return text;
}

// A header name or a label, compared in one form: unquoted, lower case, with
// runs of spaces, underscores and hyphens as one space, and no trailing full
// stop or colon. So `date_of_birth`, `Date of Birth` and `D.O.B.` compare alike
// with the labels they are written against.
export function normaliseLabel(raw: string): string {
  return unquote(raw.trim())
    .trim()
    .toLowerCase()
    .replace(/[\s_-]+/g, " ")
    .replace(/[.:：]$/, "")
    .trim();
}

// The value in a cell: trimmed, with one layer of quotes removed.
function cellValue(raw: string): string {
  return unquote(raw.trim()).trim();
}

// A Markdown separator cell is dashes, colons and spaces, with at least one dash.
function isSeparatorCell(cell: string): boolean {
  let dash = false;
  for (const ch of cell) {
    if (ch === "-") dash = true;
    else if (ch !== ":" && ch !== " " && ch !== "\t") return false;
  }
  return dash;
}

// The cells of a Markdown row. The empty cells that leading and trailing pipes
// leave are dropped.
function pipeCells(line: string): string[] {
  const cells = line.split("|");
  if (line.trimStart().startsWith("|")) cells.shift();
  if (line.trimEnd().endsWith("|")) cells.pop();
  return cells;
}

// The end of the line that starts at `pos`: the newline, or the end of the text.
function lineEnd(text: string, pos: number): number {
  const newline = text.indexOf("\n", pos);
  return newline < 0 ? text.length : newline;
}

// One CSV record, starting at `pos`. A record ends at a newline outside double
// quotes, so a quoted cell may span lines; cells split on commas outside
// quotes; and `""` inside quotes is an escaped quote, which the toggle reads as
// two toggles. `next` is the position after the record's newline.
function readCsvRecord(
  text: string,
  pos: number,
): { cells: string[]; next: number; stray: boolean } {
  const cells: string[] = [];
  let current = "";
  let quoted = false;
  let stray = false;
  let i = pos;
  for (; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') {
      // A quote opens a region only when another quote follows somewhere in the
      // text. Otherwise it is a stray character, and the record is marked, so a
      // stray quote cannot run the record on to the end of the text.
      if (quoted) quoted = false;
      else if (text.indexOf('"', i + 1) >= 0) quoted = true;
      else stray = true;
    } else if (ch === "\n" && !quoted) break;
    if (ch === "," && !quoted) {
      cells.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  cells.push(current);
  return { cells, next: Math.min(i + 1, text.length), stray };
}

// The delimiter of a header line and its cells, or undefined when the line has
// none. A line with two or more pipes is a Markdown row, one with a tab is TSV,
// and one with a comma is CSV; the first that fits decides.
function headerRow(
  line: string,
): { delimiter: Delimiter; cells: string[] } | undefined {
  if (line.split("|").length - 1 >= 2)
    return { delimiter: "|", cells: pipeCells(line) };
  if (line.includes("\t")) return { delimiter: "\t", cells: line.split("\t") };
  if (line.includes(","))
    return { delimiter: ",", cells: readCsvRecord(line, 0).cells };
  return undefined;
}

// Reads the rows under a header, from `pos`, with the header's delimiter only.
// A blank line is skipped; any other line that is not a row of that delimiter
// ends the table. Returns where that line starts, so the caller reads it as a
// header candidate of its own, or the end of the text.
function readRows(
  text: string,
  pos: number,
  delimiter: Delimiter,
  indices: number[],
  take: (raw: string) => void,
): number {
  while (pos < text.length) {
    if (delimiter === ",") {
      const record = readCsvRecord(text, pos);
      if (record.cells.length === 1) {
        // No comma outside quotes: a blank line is skipped. A record with a stray
        // quote is a malformed row of this table, so it is skipped too; anything
        // else is not a row, and it ends the table.
        if ((record.cells[0] ?? "").trim() !== "" && !record.stray) return pos;
        pos = record.next;
        continue;
      }
      for (const k of indices) {
        const raw = record.cells[k];
        if (raw !== undefined) take(raw);
      }
      pos = record.next;
      continue;
    }
    const end = lineEnd(text, pos);
    const line = text.slice(pos, end);
    const next = Math.min(end + 1, text.length);
    if (line.trim() === "") {
      pos = next;
      continue;
    }
    if (delimiter === "|") {
      if (!line.includes("|")) return pos;
      const cells = pipeCells(line);
      // The separator row under a Markdown header is not a value.
      if (!cells.every(isSeparatorCell))
        for (const k of indices) {
          const raw = cells[k];
          if (raw !== undefined) take(raw);
        }
    } else {
      if (!line.includes("\t")) return pos;
      const cells = line.split("\t");
      for (const k of indices) {
        const raw = cells[k];
        if (raw !== undefined) take(raw);
      }
    }
    pos = next;
  }
  return pos;
}

// The column list of `INSERT INTO name (columns) VALUES`. The list stops at the
// next parenthesis, which a column name never contains, so every start reads a
// short run and the scan stays linear. The tuples are read by readTuple.
const SQL_INSERT =
  /\binsert\s+into\s+[\w."`[\]]+\s*\(([^()]{0,2000})\)\s*values\s*/gi;

// Where the tuples of one INSERT end: the next INSERT that begins outside
// quotes stops the reading, so an unclosed tuple does not hide the INSERT after
// it. `s` is the next entry of `stops` that is still ahead.
interface StopCursor {
  s: number;
}

// One tuple of values, from the `(` at `start`. Commas outside quotes at the
// tuple's own depth separate its values; parentheses inside a value, such as
// `NOW()`, and quotes inside a value, such as `'Smith (Jr)'`, do not end it.
// Returns undefined when the tuple never closes, or when another INSERT begins
// outside quotes before it does.
function readTuple(
  text: string,
  start: number,
  stops: number[],
  cursor: StopCursor,
): { values: string[]; end: number } | undefined {
  const values: string[] = [];
  let current = "";
  let quoted = false;
  let depth = 0;
  for (let p = start; p < text.length; p++) {
    for (;;) {
      const stop = stops[cursor.s];
      if (stop === undefined || stop >= p) break;
      cursor.s++;
    }
    if (!quoted && stops[cursor.s] === p) return undefined;
    const ch = text[p];
    if (quoted) {
      if (ch === "'") quoted = false;
      current += ch;
      continue;
    }
    if (ch === "'") {
      quoted = true;
      current += ch;
      continue;
    }
    if (ch === "(") {
      depth++;
      if (depth === 1) continue;
    } else if (ch === ")") {
      depth--;
      if (depth === 0) {
        values.push(current);
        return { values, end: p + 1 };
      }
    } else if (ch === "," && depth === 1) {
      values.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  return undefined;
}

function skipSpace(text: string, pos: number): number {
  let p = pos;
  for (;;) {
    const ch = text[p];
    if (ch !== " " && ch !== "\t" && ch !== "\n" && ch !== "\r") return p;
    p++;
  }
}

// The tuples that follow one INSERT's column list, read in order, with each
// value at a column of the list passed to `take`.
function readTuples(
  text: string,
  pos: number,
  stops: number[],
  cursor: StopCursor,
  indices: number[],
  take: (raw: string) => void,
): void {
  for (;;) {
    pos = skipSpace(text, pos);
    if (text[pos] !== "(") return;
    const tuple = readTuple(text, pos, stops, cursor);
    if (tuple === undefined) return;
    for (const k of indices) {
      const raw = tuple.values[k];
      if (raw !== undefined) take(raw);
    }
    pos = skipSpace(text, tuple.end);
    if (text[pos] === ",") pos++;
  }
}

// One column rule's reading of a text: the labels that name its columns, and
// the test a cell has to pass to be a value. The cell is passed to `accept`
// trimmed and unquoted, and the caller decides the rest.
export interface ColumnSpec {
  labels: ReadonlySet<string>;
  accept: (cell: string) => boolean;
}

// The values that every spec reads from the text, one array per spec and in the
// order that spec would read them alone. The text is read once for all of them,
// not once per rule: a rule that walked every line on its own made the column
// pass cost about as much again for each column rule, which is what the scan
// budget and the full-scan timing measure. Only the header parse and the label
// normalisation are shared; each spec keeps its own place in the text, so a
// header that one spec reads as a table does not change what another spec sees.
export function scanColumns(
  text: string,
  specs: readonly ColumnSpec[],
): string[][] {
  const buckets: string[][] = specs.map(() => []);
  const takers = specs.map((spec, s) => {
    const bucket = buckets[s] ?? [];
    return (raw: string): void => {
      const cell = cellValue(raw);
      if (spec.accept(cell)) bucket.push(cell);
    };
  });

  // A table needs a newline: a single line has a header and no rows.
  if (specs.length > 0 && text.includes("\n")) {
    // Where each spec's walk of the lines has got to. Each is at the start of a
    // line, and the lowest one is read next, so every line is parsed once for
    // all of them.
    const at: number[] = specs.map(() => 0);
    let parsedAt = -1;
    let header: { delimiter: Delimiter; names: string[] } | undefined;
    for (;;) {
      let pos = text.length;
      for (const q of at) if (q < pos) pos = q;
      if (pos >= text.length) break;
      const end = lineEnd(text, pos);
      const next = Math.min(end + 1, text.length);
      if (parsedAt !== pos) {
        const parsed = headerRow(text.slice(pos, end));
        header = parsed && {
          delimiter: parsed.delimiter,
          names: parsed.cells.map(normaliseLabel),
        };
        parsedAt = pos;
      }
      specs.forEach((spec, s) => {
        if (at[s] !== pos) return;
        const indices = header
          ? header.names.flatMap((name, k) =>
              spec.labels.has(name) ? [k] : [],
            )
          : [];
        if (!header || indices.length === 0) {
          at[s] = next;
          return;
        }
        at[s] = readRows(
          text,
          next,
          header.delimiter,
          indices,
          takers[s] ?? (() => {}),
        );
      });
    }
  }

  // An INSERT has VALUES; a text without the word has no tuples to read. The
  // INSERTs and their column names are found once, for every spec.
  if (specs.length > 0 && /values/i.test(text)) {
    const inserts = [...text.matchAll(SQL_INSERT)];
    const starts = inserts.map((m) => m.index ?? 0);
    const columnNames = inserts.map((insert) =>
      (insert[1] ?? "").split(",").map((name) => {
        const bare = /^[["'`](.*)[\]"'`]$/su.exec(name.trim());
        return normaliseLabel(bare?.[1] ?? name);
      }),
    );
    specs.forEach((spec, s) => {
      inserts.forEach((insert, n) => {
        const indices = (columnNames[n] ?? []).flatMap((name, k) =>
          spec.labels.has(name) ? [k] : [],
        );
        if (indices.length === 0) return;
        readTuples(
          text,
          (insert.index ?? 0) + insert[0].length,
          starts,
          { s: n + 1 },
          indices,
          takers[s] ?? (() => {}),
        );
      });
    });
  }

  return buckets;
}

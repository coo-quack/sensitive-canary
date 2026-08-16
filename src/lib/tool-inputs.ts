// Which tool calls name a file they are about to read.
//
// A tool's semantics are not knowable from its input, so this reads the tool's
// name and the shape of its input object: the fields that carry a path, and the
// names that say the tool writes rather than reads.

// Tools that never surface the contents of a file they name. Scanning these
// would block writing to a file that already holds a secret, which is not a leak.
export const TOOLS_WITHOUT_FILE_OUTPUT = new Set([
  "Write",
  "Edit",
  "MultiEdit",
  "NotebookEdit",
  "TodoWrite",
  "Glob",
  "WebFetch",
  "WebSearch",
  "ExitPlanMode",
  "AskUserQuestion",
]);

// A tool whose name says it writes is treated like the built-in Write and Edit:
// naming a file it does not read is not a leak. Matched on the tool name because
// an MCP tool's semantics are not otherwise knowable from its input. For MCP
// tools (`mcp__<server>__<tool>`) only the tool component is matched — a server
// named "editor" or "readwrite" must not exempt every read tool it offers.
// The verb has to be the first word of the name, not a substring of it anywhere.
// As a substring test this would exempt reads: "update" sits inside
// `get_updates`, and "write" inside `read_and_write_file` — a tool that returns
// contents read as one that only writes. Word boundaries are the `_`/`-` in snake and
// kebab names and, in camelCase, a capital that follows a lowercase letter — so
// `write_file`, `createPage` and `WRITE_FILE` all match while `overwrite_file`
// and `readwrite` do not.
//
// Erring this way costs a false block on a noun-first write tool (`file_write`),
// which is the direction to fail in. The built-in write tools are named
// explicitly in TOOLS_WITHOUT_FILE_OUTPUT, so `TodoWrite` and `MultiEdit` do not
// depend on this at all.
//
// What the exemption assumes is that the tool returns no file contents, which is
// not quite what its name says. `update` and `copy` are where the two come
// apart: a tool called `update_file` or `copy_file` opens a file to do its work,
// and one that returned the result would go unscanned. They stay, because the
// alternative costs more — scanning them blocks writing to a file that already
// holds a secret, which is not a leak — and the gap that leaves is written up
// under Known Limitations in the README.
// Exported so the tests can generate a case per verb rather than list the ones
// someone remembered: a verb added here without a test is what let `WRITE_FILE`
// go unexempt for a release.
export const WRITING_TOOL_VERBS = new Set([
  "write",
  "create",
  "edit",
  "update",
  "append",
  "delete",
  "remove",
  "move",
  "rename",
  "mkdir",
  "copy",
]);

// The first word of a tool name. Splitting on every capital broke the all-caps
// spelling: `WRITE_FILE` came apart into single letters and its first word was
// `W`, so a write tool was scanned as a read. A capital only starts a new word
// when it follows a lowercase letter or a digit, which is what camelCase means;
// a run of capitals is one word.
function firstWord(name: string): string | undefined {
  const [first] = name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean);
  return first;
}

export function isWritingTool(tool: string): boolean {
  const name = tool.startsWith("mcp__")
    ? (tool.split("__").pop() ?? tool)
    : tool;
  const first = firstWord(name);
  return first !== undefined && WRITING_TOOL_VERBS.has(first.toLowerCase());
}

// Input field names that commonly carry a filesystem path, compared with
// separators and case removed. Listing the spellings instead meant the same
// field was missed under a different one: `file_path` and `filePath` were both
// here, but `filepath` was not, and neither was `filename` or `source_path`.
// Normalising is a rule where a list of spellings is a list of the ones someone
// happened to think of.
// A field name with the punctuation taken out, so `file_path`, `file-path`,
// `filePath`, `file.path` and `file path` are one name. Both collectors here
// share it: they had a regex each, and the one used for command fields dropped
// only `-` and `_`, so a field called `command.line` was walked past.
export function normalizeFieldName(key: string): string {
  return key.replace(/[^A-Za-z0-9]/g, "").toLowerCase();
}

export const PATH_FIELD_NAMES = new Set([
  "filepath",
  "filename",
  "filenames",
  "path",
  "paths",
  "file",
  "files",
  "absolutepath",
  "notebookpath",
  "sourcepath",
]);

// `file_path`, `filePath`, `FILE_PATH` and `filepath` are one name here.
function isPathFieldName(key: string): boolean {
  return PATH_FIELD_NAMES.has(normalizeFieldName(key));
}

// A value that names a path whatever its field is called. The list above can
// only hold names someone thought of, so a tool carrying its path under `target`
// or `document` went unscanned; this is the second way in.
//
// It is deliberately not "any string". Collecting every string would read a
// search pattern as a path: `grep` for the literal `.env` arrives as
// `{ pattern: ".env" }`, `.env` exists, and the name guard would then block a
// search for that text as though it were a read of the file. A separator is the
// cheapest test that tells a path from a word, and the cost of using it is that
// a bare filename under an unlisted field name is still missed.
function looksLikePath(value: string): boolean {
  return value.includes("/");
}

// Whether a value is worth statting: either its field name says path, or the
// value is shaped like one.
function isPathCandidate(key: string, value: string): boolean {
  return isPathFieldName(key) || looksLikePath(value);
}

// Depth to which a tool's input object is searched for path-bearing fields. Two
// levels left `{ a: { b: { c: { path } } } }` unscanned, which is not a shape a
// tool has to be perverse to use; four costs nothing on inputs this size, and
// the bound is here at all so a deeply nested input cannot make the hook walk
// an arbitrary tree before a tool call.
const MAX_PATH_FIELD_DEPTH = 4;

// Input field names that carry something to run rather than something to read.
// Compared with separators and case removed, the way path field names are.
export const COMMAND_FIELD_NAMES = new Set([
  "command",
  "commands",
  "cmd",
  "script",
  "code",
  "shellcommand",
  "commandline",
]);

// How far into a nested input a command field is looked for. The same depth the
// path fields use, and for the same reason: a tool wraps its arguments.
const MAX_COMMAND_FIELD_DEPTH = 4;

export function collectPathFields(
  input: Record<string, unknown>,
  depth = 0,
): string[] {
  if (depth > MAX_PATH_FIELD_DEPTH) return [];
  const found: string[] = [];

  for (const [key, value] of Object.entries(input)) {
    if (typeof value === "string") {
      if (isPathCandidate(key, value)) found.push(value);
    } else if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === "string") {
          // An element inherits the array's field name: `{ paths: ["…"] }`.
          if (isPathCandidate(key, item)) found.push(item);
        } else if (Array.isArray(item)) {
          // An array inside an array: `{ paths: [["…"]] }`. The element is not a
          // string and was not an object either, so it fell through and the path
          // in it was never looked at. Re-entered under the same key, so the
          // name rule still applies to what is inside.
          found.push(...collectPathFields({ [key]: item }, depth + 1));
        } else if (
          // Paths also arrive as objects inside an array, e.g.
          // `{ paths: [{ path: "…" }] }` — recurse into those elements too.
          item !== null &&
          typeof item === "object"
        ) {
          found.push(
            ...collectPathFields(item as Record<string, unknown>, depth + 1),
          );
        }
      }
    } else if (value !== null && typeof value === "object") {
      found.push(
        ...collectPathFields(value as Record<string, unknown>, depth + 1),
      );
    }
  }

  return found;
}

// Every command an input carries, whatever shape it arrives in.
//
// Reading only top-level strings left two shapes through, and both reach the
// `.env` name guard by a name with no slash in it, which the path rules do not
// collect: an argv array (`{"command":["cat",".env"]}`) and a command nested
// under another key (`{"args":{"command":"cat .env"}}`). Depth-limited the way
// path fields are, for the same reason.
//
// Beside `collectPathFields` rather than in the hook: the two walk the same tree
// to the same depth and differ only in which field names count, and that
// question — along with `normalizeFieldName` and both name sets — belongs in one
// module rather than split across two.
export function collectCommandFields(
  input: Record<string, unknown>,
  depth = 0,
): string[] {
  if (depth > MAX_COMMAND_FIELD_DEPTH) return [];
  const found: string[] = [];
  for (const [key, value] of Object.entries(input)) {
    const named = COMMAND_FIELD_NAMES.has(normalizeFieldName(key));
    if (named && typeof value === "string") {
      found.push(value);
    } else if (named && Array.isArray(value)) {
      // An argv array is one command line with the spaces taken out.
      const argv = value.filter((v): v is string => typeof v === "string");
      if (argv.length > 0) found.push(argv.join(" "));
    } else if (value !== null && typeof value === "object") {
      found.push(
        ...collectCommandFields(value as Record<string, unknown>, depth + 1),
      );
    }
  }
  return found;
}

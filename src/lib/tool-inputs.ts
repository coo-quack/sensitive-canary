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
// As a substring test this exempted reads: "update" sits inside `get_updates`,
// and "write" inside `read_and_write_file` — a tool that returns contents was
// treated as one that only writes. Word boundaries are the `_`/`-` in snake and
// kebab names and the capital in camelCase, so `write_file` and `createPage`
// still match while `overwrite_file` and `readwrite` no longer do.
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
const WRITING_TOOL_VERBS = new Set([
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

export function isWritingTool(tool: string): boolean {
  const name = tool.startsWith("mcp__")
    ? (tool.split("__").pop() ?? tool)
    : tool;
  const [first] = name.split(/[^A-Za-z0-9]+|(?=[A-Z])/).filter(Boolean);
  return first !== undefined && WRITING_TOOL_VERBS.has(first.toLowerCase());
}

// Input field names that commonly carry a filesystem path, compared with
// separators and case removed. Listing the spellings instead meant the same
// field was missed under a different one: `file_path` and `filePath` were both
// here, but `filepath` was not, and neither was `filename` or `source_path`.
// Normalising is a rule where a list of spellings is a list of the ones someone
// happened to think of.
const PATH_FIELD_NAMES = new Set([
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
  return PATH_FIELD_NAMES.has(key.replace(/[^A-Za-z0-9]/g, "").toLowerCase());
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
        } else if (
          // Paths also arrive as objects inside an array, e.g.
          // `{ paths: [{ path: "…" }] }` — recurse into those elements too.
          item !== null &&
          typeof item === "object" &&
          !Array.isArray(item)
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

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

// Input field names that commonly carry a filesystem path.
const PATH_FIELD_NAMES = new Set([
  "file_path",
  "filePath",
  "path",
  "paths",
  "file",
  "absolute_path",
  "notebook_path",
]);

// Depth to which a tool's input object is searched for path-bearing fields.
const MAX_PATH_FIELD_DEPTH = 2;

export function collectPathFields(
  input: Record<string, unknown>,
  depth = 0,
): string[] {
  if (depth > MAX_PATH_FIELD_DEPTH) return [];
  const found: string[] = [];

  for (const [key, value] of Object.entries(input)) {
    if (typeof value === "string") {
      if (PATH_FIELD_NAMES.has(key)) found.push(value);
    } else if (Array.isArray(value)) {
      if (PATH_FIELD_NAMES.has(key)) {
        found.push(...value.filter((v): v is string => typeof v === "string"));
      }
      // Paths also arrive as objects inside an array, e.g.
      // `{ paths: [{ path: "…" }] }` — recurse into those elements too.
      for (const item of value) {
        if (item !== null && typeof item === "object" && !Array.isArray(item)) {
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

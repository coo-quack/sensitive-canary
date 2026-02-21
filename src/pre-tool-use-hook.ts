#!/usr/bin/env node

/**
 * Claude Code PreToolUse hook.
 *
 * For Read tool calls and file-reading Bash commands (cat, head, tail, …):
 *   - Block if the file is a .env file
 *   - Block if the file contents contain secrets or PII
 *
 * For Bash tool calls in general:
 *   - Block if the command string itself contains secrets or PII
 *     (e.g. `echo AKIAIOSFODNN7EXAMPLE`)
 *   - Block if a referenced env var ($TOKEN) contains secrets or PII
 *
 * Allow tags: if the user's most recent prompt includes an [allow-xxx] tag,
 * the corresponding block is bypassed.  The hook reads allow tags from the
 * session transcript supplied via transcript_path.
 *
 * Exit codes:
 *   0 - allow
 *   2 - block
 */

import fs from "node:fs";
import path from "node:path";
import {
  applyAllowTags,
  dedupeFindings,
  findingsToLines,
  type Message,
  parseAllowTags,
  randomBird,
} from "./lib/inspector.ts";
import { type Finding, scan } from "./lib/rules.ts";

interface HookInput {
  transcript_path?: string;
  tool_name?: string;
  tool_input?: {
    file_path?: string;
    command?: string;
  };
}

// ── Transcript ────────────────────────────────────────────────────────────────

// Load allow tags from the Claude Code session transcript.
// Transcript format (JSONL): { "type": "user"|"assistant", "message": { role, content }, … }
// Only the most recent user message is consulted — older messages would make allow tags
// persist unintentionally across turns.
function loadAllowTagsFromTranscript(transcriptPath: string): Set<string> {
  let raw: string;
  try {
    raw = fs.readFileSync(transcriptPath, "utf8");
  } catch {
    return new Set();
  }

  // Collect all user messages, then take only the last one
  let lastUserMessage: Message | null = null;
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed) as Record<string, unknown>;
      // biome-ignore lint/complexity/useLiteralKeys: bracket notation required by noPropertyAccessFromIndexSignature
      const msg = parsed["message"] as Record<string, unknown> | undefined;
      if (
        msg &&
        // biome-ignore lint/complexity/useLiteralKeys: bracket notation required by noPropertyAccessFromIndexSignature
        typeof msg["role"] === "string" &&
        // biome-ignore lint/complexity/useLiteralKeys: bracket notation required by noPropertyAccessFromIndexSignature
        msg["role"] === "user" &&
        // biome-ignore lint/complexity/useLiteralKeys: bracket notation required by noPropertyAccessFromIndexSignature
        msg["content"] !== undefined
      ) {
        lastUserMessage = msg as unknown as Message;
      }
    } catch {
      // skip malformed lines
    }
  }

  if (!lastUserMessage) return new Set();
  return parseAllowTags([lastUserMessage]);
}

// ── Bash helpers ──────────────────────────────────────────────────────────────

// Bash commands that read file contents
const FILE_READ_COMMANDS = new Set([
  "cat",
  "head",
  "tail",
  "less",
  "more",
  "bat",
  "nl",
]);

/**
 * Extract environment variable names referenced in a shell command string.
 * Matches $VAR and ${VAR} but ignores special variables like $?, $!, $$, $0.
 */
function extractEnvVarNames(command: string): string[] {
  const names = new Set<string>();
  const re = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g;
  let match: RegExpExecArray | null;
  // biome-ignore lint/suspicious/noAssignInExpressions: idiomatic regex loop
  while ((match = re.exec(command)) !== null) {
    names.add((match[1] ?? match[2]) as string);
  }
  return [...names];
}

/**
 * Extract file paths targeted by file-reading commands in a shell command string.
 * Handles compound commands split by |, ;, &&, ||.
 */
function extractFilePathsFromCommand(command: string): string[] {
  const paths: string[] = [];
  // Split compound commands into segments
  const segments = command.split(/\s*(?:[|;&]|&&|\|\|)\s*/);

  for (const seg of segments) {
    const tokens = seg.trim().split(/\s+/).filter(Boolean);
    if (tokens.length < 2) continue;

    const cmd = path.basename(tokens[0] ?? "");
    if (!FILE_READ_COMMANDS.has(cmd)) continue;

    let skipNext = false;
    for (let i = 1; i < tokens.length; i++) {
      if (skipNext) {
        skipNext = false;
        continue;
      }
      const tok = tokens[i];
      if (!tok) continue;
      // Skip flags
      if (tok.startsWith("-")) continue;
      // Skip redirect operators and their target
      if (tok === ">" || tok === ">>" || tok === "<") {
        skipNext = true;
        continue;
      }
      paths.push(tok);
    }
  }

  return [...new Set(paths)];
}

// ── .env pattern ──────────────────────────────────────────────────────────────

// .env and .env.* (e.g. .env.local, .env.production) are blocked unconditionally.
// Files that merely end in .env (e.g. production.env) are handled by content scanning.
function isBlockedEnvFile(filePath: string): boolean {
  if (!filePath) return false;
  const base = path.basename(filePath);
  return base === ".env" || base.startsWith(".env.");
}

// ── Output helpers ────────────────────────────────────────────────────────────

// Build the allow-tag hint lines shown to Claude.
// showAllTags: when true, always show [allow-secret] and [allow-pii] hints
// regardless of findings content (used for .env name blocks).
function buildAllowHints(
  exampleContext: string,
  findings: Finding[],
  showAllTags = false,
): string[] {
  const hasSecret =
    showAllTags || findings.some((f) => f.category === "secret");
  const hasPii = showAllTags || findings.some((f) => f.category === "pii");

  const lines: string[] = [];
  if (hasSecret) lines.push("  [allow-secret]  — allow secrets");
  if (hasPii) lines.push("  [allow-pii]     — allow PII");
  lines.push("  [allow-all]     — bypass all sensitive-canary checks");
  lines.push("");

  const example = hasSecret
    ? "allow-secret"
    : hasPii
      ? "allow-pii"
      : "allow-all";
  lines.push(`Example: "[${example}] ${exampleContext}"`);

  return lines;
}

function block(
  source: string,
  detectionLines: string[],
  allowHints: string[],
): never {
  // Human-readable message for the terminal
  const terminalMessage = [
    "",
    `${randomBird()} sensitive-canary: blocked — ${source}`,
    "",
    ...detectionLines,
    "",
  ].join("\n");

  // Write directly to /dev/tty so the user always sees the message
  try {
    const fd = fs.openSync("/dev/tty", "w");
    fs.writeSync(fd, terminalMessage);
    fs.closeSync(fd);
  } catch {
    process.stderr.write(terminalMessage);
  }

  // Structured reason for Claude — explain the block and how to allow it
  const reasonLines = [
    `sensitive-canary blocked: ${source}`,
    "",
    ...detectionLines,
    "",
    "To allow this, the user must add an allow tag to their next prompt:",
    ...allowHints,
    "",
    "Please tell the user about this block and suggest the appropriate tag.",
  ];

  process.stdout.write(
    `${JSON.stringify({
      decision: "block",
      reason: reasonLines.join("\n"),
    })}\n`,
  );
  process.exit(2);
}

// ── Core scan logic ───────────────────────────────────────────────────────────

function scanFile(filePath: string, allowTags: Set<string>): void {
  // 1. .env / .env.* — blocked unconditionally by name.
  //    Any allow tag ([allow-secret], [allow-pii], [allow-all]) bypasses this.
  if (isBlockedEnvFile(filePath)) {
    if (allowTags.size > 0) return;
    block(
      filePath,
      [
        "⚠️  Blocked: .env and .env.* files contain secrets and must not be read into the conversation.",
      ],
      buildAllowHints(`please read ${filePath}`, [], true),
    );
  }

  // 2. Read and scan contents for secrets/PII.
  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf8");
  } catch {
    return; // file unreadable — let the tool handle the error
  }

  const findings = applyAllowTags(
    dedupeFindings(scan(content, filePath)),
    allowTags,
  );
  if (findings.length === 0) return;

  block(
    filePath,
    [
      "⚠️  Blocked: file contains sensitive data",
      "",
      ...findingsToLines(findings),
    ],
    buildAllowHints(`please read ${filePath}`, findings),
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk: string) => (raw += chunk));
process.stdin.on("end", () => {
  let data: HookInput;
  try {
    data = JSON.parse(raw) as HookInput;
  } catch {
    process.exit(0);
  }

  const tool = data.tool_name ?? "";
  const input = data.tool_input ?? {};

  // Load allow tags from the session transcript (empty set if unavailable)
  const allowTags = data.transcript_path
    ? loadAllowTagsFromTranscript(data.transcript_path)
    : new Set<string>();

  // ── Read tool ──────────────────────────────────────────────────────────────
  if (tool === "Read") {
    scanFile(input.file_path ?? "", allowTags);
    process.exit(0);
  }

  // ── Bash tool ──────────────────────────────────────────────────────────────
  if (tool === "Bash") {
    const command = input.command ?? "";

    // 1. Expand env vars referenced in the command and scan their values
    for (const varName of extractEnvVarNames(command)) {
      const value = process.env[varName];
      if (!value) continue;
      const findings = applyAllowTags(
        dedupeFindings(scan(value, `$${varName}`)),
        allowTags,
      );
      if (findings.length === 0) continue;
      block(
        `bash command: ${command.slice(0, 80)}`,
        [
          `⚠️  Blocked: environment variable $${varName} contains sensitive data`,
          "",
          ...findingsToLines(findings),
        ],
        buildAllowHints("please run the command", findings),
      );
    }

    // 2. Scan the command string itself (catches inline literals like `echo AKIA…`)
    const cmdFindings = applyAllowTags(
      dedupeFindings(scan(command, "(bash command)")),
      allowTags,
    );
    if (cmdFindings.length > 0) {
      block(
        `bash command: ${command.slice(0, 80)}`,
        [
          "⚠️  Blocked: bash command contains sensitive data",
          "",
          ...findingsToLines(cmdFindings),
        ],
        buildAllowHints("please run the command", cmdFindings),
      );
    }

    // 3. For file-reading commands, scan each referenced file
    for (const fp of extractFilePathsFromCommand(command)) {
      scanFile(fp, allowTags);
    }

    process.exit(0);
  }

  // All other tools — allow
  process.exit(0);
});

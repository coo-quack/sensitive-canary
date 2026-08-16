import { readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import {
  entropy,
  isNotSecretShaped,
  isPlaceholder,
  keyDescribesRatherThanHolds,
} from "./shapes.ts";
import { getValidator } from "./validators.ts";

export type Category = "secret" | "pii";

export interface Finding {
  ruleId: string;
  description: string;
  category: Category;
  matchRedacted: string;
  secretValue: string;
  score?: number;
}

interface Rule {
  id: string;
  description: string;
  regex: RegExp;
  secretGroup?: number;
  entropyThreshold?: number;
  validate?: (str: string) => boolean;
  category: Category;
  contextWords?: string[];
  requireContext?: boolean;
  // Words that, found near a match, say it is not what the rule is looking for —
  // the mirror of contextWords. The postal-code rule uses it: `65536 bytes` and
  // `max 3` are five-digit numbers beside a word that says they are not places.
  excludeContext?: string[];
  contextWindow?: number;
}

// JSON representation of a rule, as written in config files. The `regex` is a
// source string (not a RegExp literal), compiled at load time. `validate` is a
// name into the VALIDATORS registry.
export interface RuleConfig {
  id: string;
  description: string;
  regex: string;
  flags?: string;
  secretGroup?: number;
  entropyThreshold?: number;
  validate?: string;
  category: Category;
  contextWords?: string[];
  requireContext?: boolean;
  // See Rule.excludeContext.
  excludeContext?: string[];
  contextWindow?: number;
}

// Top-level config file: a context window override plus a list of rules.
// User config files use the same shape and can override built-in rules by id.
export interface CanaryConfig {
  contextWindow?: number;
  rules: RuleConfig[];
}

const ALL_CATEGORIES: ReadonlySet<Category> = new Set(["secret", "pii"]);

// Parse the SENSITIVE_CANARY_CATEGORIES env var: a comma-separated list of
// "secret", "pii", or "all" (e.g. "secret" or "secret,pii"). Unset, empty, or
// containing no valid token means all categories are enabled.
export function parseCategories(value: string | undefined): Set<Category> {
  const categories = new Set<Category>();
  for (const token of (value ?? "").split(",")) {
    const normalized = token.trim().toLowerCase();
    if (normalized === "all") return new Set(ALL_CATEGORIES);
    if (normalized === "secret" || normalized === "pii")
      categories.add(normalized);
  }
  return categories.size > 0 ? categories : new Set(ALL_CATEGORIES);
}

// Rule categories enabled for this process, from SENSITIVE_CANARY_CATEGORIES
// ("secret", "pii", "secret,pii", or "all"; default: all).
export function enabledCategoriesFromEnv(): Set<Category> {
  const { SENSITIVE_CANARY_CATEGORIES } = process.env;
  return parseCategories(SENSITIVE_CANARY_CATEGORIES);
}

// ── Context enhancement ──────────────────────────────────────────────────────

// Set from the default config during module initialisation (see buildRules).
let effectiveContextWindow = 3;

export function getDefaultContextWindow(): number {
  return effectiveContextWindow;
}

// Words as they were written, with only the punctuation around them removed.
// Splitting on punctuation made `extract-zip` supply "zip" and
// `golang.org/x/mobile` supply "mobile", so a version number beside either read
// as a postal code or a telephone number — which is to say lockfiles and
// `go.sum` could not be read.
function contextTokens(text: string): Set<string> {
  const out = new Set<string>();
  for (const raw of text.split(/\s+/)) {
    const word = raw
      .replace(/^[\p{P}\p{S}]+/gu, "")
      .replace(/[\p{P}\p{S}]+$/gu, "")
      .toLowerCase();
    if (word) out.add(word);
  }
  return out;
}

function hasNearbyContextWord(
  text: string,
  matchStart: number,
  matchEnd: number,
  contextWords: string[],
  windowTokens: number,
): boolean {
  if (contextWords.length === 0) return true;
  const charWindow = windowTokens * 8;
  const before = text.slice(Math.max(0, matchStart - charWindow), matchStart);
  const after = text.slice(matchEnd, matchEnd + charWindow);
  const window = `${before} ${after}`;
  const nearby = contextTokens(window);
  const lowered = window.toLowerCase();
  return contextWords.some((raw) => {
    const word = raw.toLowerCase();
    // A label in a language that does not put spaces around its words is
    // written against the number, so it is looked for as written.
    // biome-ignore lint/suspicious/noControlCharactersInRegex: the ASCII range is the test
    if (!/^[\x00-\x7f]+$/.test(word)) return lowered.includes(word);
    return nearby.has(word);
  });
}

// ── Config loading ───────────────────────────────────────────────────────────

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_CONFIG_PATH = join(MODULE_DIR, "default-config.json");
const { SENSITIVE_CANARY_CONFIG: userConfigPath } = process.env;
const USER_CONFIG_PATH =
  userConfigPath ??
  join(homedir(), ".config", "sensitive-canary", "config.json");

function readJsonFile(filePath: string): unknown {
  return JSON.parse(readFileSync(filePath, "utf-8"));
}

// Validate a raw JSON object against the RuleConfig schema. Throws with a
// descriptive message when a required field is missing, a type is wrong, or a
// cross-field constraint is violated.
function validateRuleConfig(rc: unknown): asserts rc is RuleConfig {
  if (typeof rc !== "object" || rc === null) {
    throw new Error("rule must be an object");
  }
  const {
    id,
    description,
    regex: source,
    category,
    flags,
    secretGroup,
    entropyThreshold,
    validate: validateName,
    contextWords,
    excludeContext,
    requireContext,
    contextWindow,
  } = rc as Record<string, unknown>;

  if (typeof id !== "string" || id.length === 0) {
    throw new Error('missing or empty "id" field');
  }
  if (typeof description !== "string" || description.length === 0) {
    throw new Error('missing or empty "description" field');
  }
  if (typeof source !== "string" || source.length === 0) {
    throw new Error('missing or empty "regex" field');
  }
  if (category !== "secret" && category !== "pii") {
    throw new Error(
      `invalid "category" ${JSON.stringify(category)} (must be "secret" or "pii")`,
    );
  }
  if (flags != null && typeof flags !== "string") {
    throw new Error('"flags" must be a string');
  }
  if (
    secretGroup != null &&
    (typeof secretGroup !== "number" ||
      !Number.isInteger(secretGroup) ||
      secretGroup < 0)
  ) {
    throw new Error('"secretGroup" must be a non-negative integer');
  }
  if (
    entropyThreshold != null &&
    (typeof entropyThreshold !== "number" || entropyThreshold < 0)
  ) {
    throw new Error('"entropyThreshold" must be a non-negative number');
  }
  if (validateName != null && typeof validateName !== "string") {
    throw new Error('"validate" must be a string');
  }
  if (excludeContext != null) {
    if (
      !Array.isArray(excludeContext) ||
      excludeContext.some((w) => typeof w !== "string" || w.length === 0)
    ) {
      throw new Error('"excludeContext" must be an array of non-empty strings');
    }
  }
  if (contextWords != null) {
    if (
      !Array.isArray(contextWords) ||
      contextWords.some((w) => typeof w !== "string" || w.length === 0)
    ) {
      throw new Error('"contextWords" must be an array of non-empty strings');
    }
  }
  if (requireContext != null && typeof requireContext !== "boolean") {
    throw new Error('"requireContext" must be a boolean');
  }
  if (
    contextWindow != null &&
    (typeof contextWindow !== "number" ||
      !Number.isInteger(contextWindow) ||
      contextWindow < 1)
  ) {
    throw new Error('"contextWindow" must be a positive integer');
  }

  // Cross-field: requireContext is meaningless without contextWords
  if (
    requireContext === true &&
    (!Array.isArray(contextWords) || contextWords.length === 0)
  ) {
    throw new Error(
      '"requireContext" is true but "contextWords" is empty — context gating would be disabled and the rule would always fire',
    );
  }
}

// Compile a single RuleConfig (JSON) into a Rule (with compiled RegExp and
// resolved validator function). Throws on invalid regex or missing required
// fields so the caller (buildRules) can catch and warn per-rule.
export function compileRule(rc: RuleConfig): Rule {
  validateRuleConfig(rc);
  const { regex: source, flags, validate: validateName, ...rest } = rc;
  // matchAll requires the global flag; ensure it is always present.
  const flagStr = flags ?? "g";
  const withG = flagStr.includes("g") ? flagStr : `${flagStr}g`;
  const rule: Rule = {
    ...rest,
    regex: new RegExp(source, withG),
  };
  if (validateName) {
    const fn = getValidator(validateName);
    if (fn) {
      rule.validate = fn;
    } else {
      process.stderr.write(
        `sensitive-canary: unknown validator "${validateName}" in rule "${rc.id}" — validation disabled\n`,
      );
    }
  }
  return rule;
}

// Load and compile the built-in default rules from default-config.json.
function loadDefaultConfig(): CanaryConfig {
  return readJsonFile(DEFAULT_CONFIG_PATH) as CanaryConfig;
}

// Load user config if it exists. Returns null when the file is absent (the
// common case). JSON parse errors and permission issues are reported on stderr
// so that a broken config file is not silently ignored.
function loadUserConfig(): CanaryConfig | null {
  try {
    // A FIFO or a device here would block the read until something wrote to
    // it, and a hook that never returns is killed by the timeout, which does
    // not block. The transcript reader and the file scanner both pay this stat
    // already; this path was the one that did not.
    if (!statSync(USER_CONFIG_PATH).isFile()) {
      process.stderr.write(
        `sensitive-canary: user config "${USER_CONFIG_PATH}" is not a regular file, ignoring\n`,
      );
      return null;
    }
    return readJsonFile(USER_CONFIG_PATH) as CanaryConfig;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") {
      process.stderr.write(
        `sensitive-canary: could not read user config "${USER_CONFIG_PATH}": ${e instanceof Error ? e.message : String(e)}\n`,
      );
    }
    return null;
  }
}

// Build the final rule list: default rules first, then user rules. A user rule
// with the same id as a built-in rule replaces it; new ids are appended.
// Invalid user rules (bad regex, etc.) are skipped with a warning so that one
// bad entry does not break the entire hook.
function buildRules(): Rule[] {
  const defaultConfig = loadDefaultConfig();
  effectiveContextWindow = defaultConfig.contextWindow ?? 3;

  const defaultRules: Rule[] = [];
  for (const rc of defaultConfig.rules) {
    try {
      defaultRules.push(compileRule(rc));
    } catch (e) {
      process.stderr.write(
        `sensitive-canary: failed to compile built-in rule "${(rc as { id?: unknown })?.id ?? "(unknown)"}": ${e instanceof Error ? e.message : String(e)}\n`,
      );
    }
  }

  const userConfig = loadUserConfig();
  if (userConfig) {
    if (
      typeof userConfig.contextWindow === "number" &&
      Number.isInteger(userConfig.contextWindow) &&
      userConfig.contextWindow >= 1
    ) {
      effectiveContextWindow = userConfig.contextWindow;
    } else if (userConfig.contextWindow != null) {
      process.stderr.write(
        `sensitive-canary: invalid contextWindow in user config, ignoring\n`,
      );
    }
    if (userConfig.rules != null && !Array.isArray(userConfig.rules)) {
      process.stderr.write(
        `sensitive-canary: "rules" in user config must be an array, ignoring\n`,
      );
    }
    if (Array.isArray(userConfig.rules) && userConfig.rules.length) {
      const userRules: Rule[] = [];
      for (const rc of userConfig.rules) {
        try {
          userRules.push(compileRule(rc));
        } catch (e) {
          process.stderr.write(
            `sensitive-canary: skipping user rule "${(rc as { id?: unknown })?.id ?? "(unknown)"}": ${e instanceof Error ? e.message : String(e)}\n`,
          );
        }
      }
      // De-duplicate by id (last definition wins) so duplicate ids in the
      // user config don't produce duplicate rules and duplicate findings.
      const byId = new Map<string, Rule>();
      for (const rule of userRules) {
        if (byId.has(rule.id)) {
          process.stderr.write(
            `sensitive-canary: duplicate user rule id "${rule.id}" — using the last definition\n`,
          );
        }
        byId.set(rule.id, rule);
      }
      return defaultRules
        .filter((r) => !byId.has(r.id))
        .concat(Array.from(byId.values()));
    }
  }

  return defaultRules;
}

export const RULES: Rule[] = buildRules();

// Enough of a value to say which one was found, and no more.
//
// The block reason is written to stderr, which is where Claude reads it, so
// whatever is shown here reaches the API that the block exists to keep it from.
// Four characters at each end returned eight of a nine-character password.
// A quarter of the value, capped at four per end.
export function redact(str: string): string {
  // Code points, not code units. Slicing by unit cuts a surrogate pair in half
  // and writes a lone surrogate to the terminal, which is neither the character
  // nor a redaction of it.
  const characters = [...str];
  const shown = Math.min(4, Math.floor(characters.length / 8));
  if (shown === 0) return "****";
  const head = characters.slice(0, shown).join("");
  const tail = characters.slice(-shown).join("");
  return `${head}****${tail}`;
}

// Longer than any honest scan and far shorter than the hook timeout. A rule
// that backtracks badly takes minutes on a megabyte, and a hook killed by the
// timeout does not block, so the damage is silent. The patterns that did that
// are bounded; this catches the next one of that shape rather than letting it
// repeat. The check sits between rules because a single `matchAll` cannot be
// interrupted.
export const SCAN_BUDGET_MS = 10_000;

export class ScanBudgetExceeded extends Error {
  constructor(ruleId: string, elapsed: number) {
    super(
      `the scan passed ${SCAN_BUDGET_MS}ms (${elapsed}ms at rule "${ruleId}")`,
    );
    this.name = "ScanBudgetExceeded";
  }
}

// The budget belongs to the hook invocation, not to one `scan()` call. A single
// call is a small part of the work: `scanEnvironment` scans once per variable,
// a file is scanned at both ends, and `Object.keys(process.env)` sets the
// multiplier. Per call, each stays inside the budget while the total runs past
// the hook timeout — and a hook killed by the timeout does not block.
//
// Set once by each hook entry point. Left unset, every call gets the full
// budget, which is what the test suite needs.
let deadline: number | null = null;

// `null` clears it, which is the state a process starts in.
export function beginScanBudget(totalMs: number | null = SCAN_BUDGET_MS): void {
  deadline = totalMs === null ? null : Date.now() + totalMs;
}

// What is left of the budget, or the whole of it when none was begun.
function remainingBudget(): number {
  return deadline === null ? SCAN_BUDGET_MS : deadline - Date.now();
}

// The between-rule check below cannot interrupt a single `matchAll`, and one
// rule from a user config is enough to hang the hook — which is then killed by
// the timeout, and a killed hook does not block. A V8-side timeout does
// interrupt a running match. Measured at 0.06ms per call, against a scan that
// costs hundreds of times that.
const SCAN_SLOT = "__sensitiveCanaryScan";
const HARD_LIMIT_SLACK_MS = 2_000;

// `limitMs` bounds this call so it cannot overshoot what the invocation has
// left. Without it a single call could run the full hard limit past a deadline
// that was already spent.
function runInterruptibly<T>(work: () => T, limitMs: number): T {
  const slots = globalThis as unknown as Record<string, unknown>;
  slots[SCAN_SLOT] = work;
  try {
    return vm.runInThisContext(`globalThis.${SCAN_SLOT}()`, {
      timeout: limitMs,
      displayErrors: false,
    }) as T;
  } catch (error) {
    if (error instanceof Error && error.message.includes("timed out"))
      throw new ScanBudgetExceeded("a single rule", limitMs);
    throw error;
  } finally {
    delete slots[SCAN_SLOT];
  }
}

export function scan(
  text: string,
  categories: ReadonlySet<Category> = ALL_CATEGORIES,
): Finding[] {
  const remaining = remainingBudget();
  if (remaining <= 0)
    throw new ScanBudgetExceeded("this call's total", SCAN_BUDGET_MS);
  return runInterruptibly(
    () => scanUninterrupted(text, categories, remaining),
    remaining + HARD_LIMIT_SLACK_MS,
  );
}

function scanUninterrupted(
  text: string,
  categories: ReadonlySet<Category>,
  budgetMs: number,
): Finding[] {
  const findings: Finding[] = [];
  const startedAt = Date.now();

  for (const rule of RULES) {
    if (!categories.has(rule.category)) continue;
    const elapsed = Date.now() - startedAt;
    // Thrown rather than returned: a partial result is indistinguishable from a
    // clean one, and the hooks stop the call on an error they cannot explain.
    if (elapsed > budgetMs) throw new ScanBudgetExceeded(rule.id, elapsed);
    for (const match of text.matchAll(rule.regex)) {
      const secretValue =
        rule.secretGroup != null ? match[rule.secretGroup] : match[0];

      if (!secretValue) continue;
      // Both the captured value and the whole match: a rule with a
      // `secretGroup` captures only part of what it matched, and the
      // connection-string rule stops at the `@`, so the host — the one thing
      // that separates `user:password@localhost` from `user:password@` in front
      // of real infrastructure — is outside the capture.
      const matchStart = match.index ?? 0;
      const matchEnd = matchStart + match[0].length;
      const following = text.slice(matchEnd, matchEnd + 64);
      // The shape test applies only where the rule captured a free-form value.
      // A rule that matches a fixed prefix has already said what the thing is —
      // a Slack webhook is a URL and a secret, and asking whether it looks like
      // a URL is asking the wrong question.
      const capturesAValue = rule.secretGroup != null;
      if (
        rule.category === "secret" &&
        (isPlaceholder(secretValue, following) ||
          (capturesAValue &&
            (isNotSecretShaped(secretValue) ||
              isPlaceholder(match[0], following) ||
              isNotSecretShaped(match[0]) ||
              keyDescribesRatherThanHolds(match[0]))))
      )
        continue;
      if (
        rule.entropyThreshold != null &&
        entropy(secretValue) < rule.entropyThreshold
      )
        continue;
      if (rule.validate != null && !rule.validate(secretValue)) continue;

      const hasContext =
        !rule.contextWords || rule.contextWords.length === 0
          ? true
          : hasNearbyContextWord(
              text,
              matchStart,
              matchEnd,
              rule.contextWords,
              rule.contextWindow ?? effectiveContextWindow,
            );

      // Rules that require context (e.g. bare postal codes) are dropped when
      // no context label is nearby, to avoid flagging every 5-digit number.
      if (rule.requireContext && !hasContext) continue;

      // And the other way: a word nearby that says this is not what the rule is
      // for. `git clone git@github.com:…` and `ssh deploy@host` are addresses by
      // shape, and the command in front of them is what says they are not
      // anyone's mail.
      if (
        rule.excludeContext &&
        rule.excludeContext.length > 0 &&
        hasNearbyContextWord(
          text,
          matchStart,
          matchEnd,
          rule.excludeContext,
          rule.contextWindow ?? effectiveContextWindow,
        )
      ) {
        continue;
      }

      findings.push({
        ruleId: rule.id,
        description: rule.description,
        category: rule.category,
        matchRedacted: redact(secretValue),
        secretValue,
        score: hasContext ? 1.0 : 0.4,
      });
    }
  }

  return findings;
}

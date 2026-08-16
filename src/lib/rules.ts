import { readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

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

// Luhn algorithm checksum validation. Returns true if the number (digits only) passes.
// Card numbers every payment gateway publishes as test data. They pass Luhn by
// design, and a developer pasting one into a prompt or a fixture is not leaking
// anything — but the block reads the same as a real one, and that is the kind of
// block that gets the tool turned off.
const TEST_CARD_NUMBERS = new Set([
  "4242424242424242",
  "4111111111111111",
  "4012888888881881",
  "4000056655665556",
  "5555555555554444",
  "5105105105105100",
  "5200828282828210",
  "378282246310005",
  "371449635398431",
  "6011111111111117",
  "6011000990139424",
  "3056930009020004",
  "3566002020360505",
]);

// A card number that is not published test data and passes the checksum. This
// is what the `luhn` validator resolves to: `luhn` alone answers a narrower
// question, and having one function answer both meant it returned false for
// numbers that do pass the checksum.
export function isRealCardNumber(str: string): boolean {
  if (TEST_CARD_NUMBERS.has(str.replace(/\D/g, ""))) return false;
  return luhn(str);
}

// AWS writes every key in its documentation with `EXAMPLE` where the random
// part would end — `AKIAIOSFODNN7EXAMPLE`, `ASIAIOSFODNN7EXAMPLE`,
// `AKIAI44QH8DHBEXAMPLE`. Those appear in setup guides, in READMEs that copy
// them, and in this project's own documentation, and a block on one reads
// exactly like a block on a live key.
//
// The suffix is the test rather than a list of bodies. The bodies differ
// between guides, so a list would exempt the three anyone thought to write down
// and block the fourth; the convention is what AWS keeps to. What it costs is a
// real key whose last seven characters spell the word, one in thirty-six to the
// seventh, and the rule's own character class keeps that to uppercase keys.
export function isRealAwsKey(str: string): boolean {
  return !/EXAMPLE$/.test(str);
}

export function luhn(str: string): boolean {
  const digits = str.replace(/\D/g, "");
  if (digits.length === 0) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = parseInt(digits[i] ?? "", 10);
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

// ── National ID checksum validators ──────────────────────────────────────────

// Japanese Individual Number (My Number): 12 digits, weighted checksum over the
// first 11 digits with weights 6,5,4,3,2,7,6,5,4,3,2. The 12th digit is
// 11 - (sum mod 11); when the remainder is 0 or 1, the check digit is 0.
// Spec: 地方公共団体情報システム機構 (J-LIS).
export function validateMyNumber(input: string): boolean {
  // Twelve of the same digit satisfies the weighted sum by arithmetic, not by
  // being anyone's number. Padding, zeroed records and hex dumps are full of
  // them.
  if (/^(\d)\1*$/.test(input.replace(/[-\s]/g, ""))) return false;
  const digits = input.replace(/\D/g, "");
  if (digits.length !== 12) return false;
  const weights = [6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
  let sum = 0;
  for (let i = 0; i < 11; i++) {
    sum += parseInt(digits[i] ?? "", 10) * (weights[i] ?? 0);
  }
  const remainder = sum % 11;
  const checkDigit = remainder <= 1 ? 0 : 11 - remainder;
  return checkDigit === parseInt(digits[11] ?? "", 10);
}

// French NIR (Numéro de sécurité sociale / INSEE): 15 digits, 2-digit check key
// computed as 97 - (N mod 97) over the leading 13 digits. Corsica departements
// use 2A/2B, substituted to 19/18 before the mod. The 13-digit value can exceed
// Number.MAX_SAFE_INTEGER, so BigInt is used. Spec: INSEE / décret n°82-103.
export function validateFrenchNIR(input: string): boolean {
  const cleaned = input.replace(/\s/g, "");
  let nir13: string;
  let keyStr: string;

  const standard = cleaned.match(/^([12]\d{12})(\d{2})$/);
  const corseA = cleaned.match(/^([12]\d{4}2A\d{6})(\d{2})$/i);
  const corseB = cleaned.match(/^([12]\d{4}2B\d{6})(\d{2})$/i);

  if (standard) {
    nir13 = standard[1] ?? "";
    keyStr = standard[2] ?? "";
  } else if (corseA) {
    nir13 = (corseA[1] ?? "").replace(/2A/i, "19");
    keyStr = corseA[2] ?? "";
  } else if (corseB) {
    nir13 = (corseB[1] ?? "").replace(/2B/i, "18");
    keyStr = corseB[2] ?? "";
  } else {
    return false;
  }

  const num = BigInt(nir13);
  const computedKey = 97 - Number(num % 97n);
  return computedKey === parseInt(keyStr, 10);
}

// Italian Codice Fiscale: 16 alphanumeric chars. The last char is a control
// character computed by summing odd/even position values (different maps) mod 26.
// Spec: Agenzia delle Entrate, DM 12 giugno 2007.
const CF_ODD_VALUES: Record<string, number> = {
  "0": 1,
  "1": 0,
  "2": 5,
  "3": 7,
  "4": 9,
  "5": 13,
  "6": 15,
  "7": 17,
  "8": 19,
  "9": 21,
  A: 1,
  B: 0,
  C: 5,
  D: 7,
  E: 9,
  F: 13,
  G: 15,
  H: 17,
  I: 19,
  J: 21,
  K: 2,
  L: 4,
  M: 18,
  N: 20,
  O: 11,
  P: 3,
  Q: 6,
  R: 8,
  S: 12,
  T: 14,
  U: 16,
  V: 10,
  W: 22,
  X: 25,
  Y: 24,
  Z: 23,
};

export function validateCodiceFiscale(input: string): boolean {
  const cf = input.toUpperCase().replace(/\s/g, "");
  // Omocodia: when two people would share the first fifteen characters, the
  // Agenzia delle Entrate substitutes letters for digits from the right,
  // 0=L 1=M 2=N 3=P 4=Q 5=R 6=S 7=T 8=U 9=V, over the seven numeric
  // positions. Requiring digits there rejected every substituted code — all
  // of them issued to real people. The check character below needs no change:
  // it is defined over the substituted fifteen, and the odd/even tables
  // already carry letters.
  if (
    !/^[A-Z]{6}[0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{3}[A-Z]$/.test(
      cf,
    )
  )
    return false;

  let sum = 0;
  for (let i = 0; i < 15; i++) {
    const ch = cf[i] ?? "";
    if (i % 2 === 0) {
      sum += CF_ODD_VALUES[ch] ?? -1;
    } else if (/[0-9]/.test(ch)) {
      sum += parseInt(ch, 10);
    } else {
      sum += ch.charCodeAt(0) - 65;
    }
  }
  const expected = String.fromCharCode(65 + (sum % 26));
  return expected === cf[15];
}

// German Steuer-Identifikationsnummer (IdNr.): 11 digits, first digit non-zero.
// The procedure is ISO/IEC 7064 MOD 11,10, though the tax administration's own
// specification states it as code rather than by that name.
//
// Deliberately not enforced: the digit-composition rule. Since 2016 it reads
// "exactly one digit occurs twice or three times in positions 1-10", replacing
// an older "exactly twice". Adding the older form as a tightening would reject
// valid current numbers.
// Spec: ELSTER, Prüfung der Steuer- und Steueridentifikationsnummer, §2.2.
export function validateGermanIdNr(input: string): boolean {
  const cleaned = input.replace(/\s/g, "");
  if (!/^[1-9]\d{10}$/.test(cleaned)) return false;

  let produkt = 10;
  for (let i = 0; i < 10; i++) {
    let summe = (parseInt(cleaned[i] ?? "", 10) + produkt) % 10;
    if (summe === 0) summe = 10;
    produkt = (summe * 2) % 11;
  }
  let check = 11 - produkt;
  if (check === 10) check = 0;
  return check === parseInt(cleaned[10] ?? "", 10);
}

// Spanish DNI (8 digits + letter) and NIE (X/Y/Z + 7 digits + letter). The
// control letter is selected from TRWAGMYFPDXBNJZSQVHLCKE by the number mod 23.
// NIE leading letters map X→0, Y→1, Z→2 before the mod.
// The X/Y/Z mapping and the mod-23 alphabet are what every implementation uses,
// but they were not confirmed against a Spanish government source here — the
// Interior page that documents them was unreachable. The governing decree is
// Real Decreto 255/2025, which repealed RD 1553/2005 on 2025-04-02, and it
// specifies neither digit count nor separator; the Agencia Tributaria describes
// the number as "ocho dígitos ... más una letra de control", with no separator.
// Hyphens are stripped above so both the official and the common form are read.
const NIF_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE";

export function validateSpanishNIF(input: string): boolean {
  const cleaned = input.toUpperCase().replace(/[\s-]/g, "");

  const dni = cleaned.match(/^(\d{8})([A-Z])$/);
  if (dni) {
    return NIF_LETTERS[parseInt(dni[1] ?? "", 10) % 23] === dni[2];
  }

  const nie = cleaned.match(/^([XYZ])(\d{7})([A-Z])$/);
  if (nie) {
    const prefix = nie[1] === "X" ? "0" : nie[1] === "Y" ? "1" : "2";
    const num = parseInt(prefix + (nie[2] ?? ""), 10);
    return NIF_LETTERS[num % 23] === nie[3];
  }

  return false;
}

// Korean Resident Registration Number (RRN, 주민등록번호): 13 digits.
// Checksum is (11 - (weighted sum mod 11)) mod 10 with weights
// 2,3,4,5,6,7,8,9,2,3,4,5 over the first 12 digits.
// Numbers newly issued or changed on or after 2020-10-05 randomize digits 8-13,
// and the check digit is the 13th — so it is inside the randomized block and the
// weighted sum above holds only by chance, roughly one time in ten. Treat a pass
// as evidence, never as a requirement. 주민등록법 시행규칙 제2조 (행정안전부령
// 제204호) now reads "생년월일ㆍ성별 등을 표시할 수 있는 13자리의 숫자", with the
// 지역 (region) term of the older text removed. No rule ever specified the check
// digit, so no rule announces its end either.
// Spec: 주민등록법 시행규칙 제2조; 주민등록 사무편람 (Ministry of the Interior and Safety).
export function validateKoreanRRN(input: string): boolean {
  const s = input.replace(/[-\s]/g, "");
  if (!/^\d{13}$/.test(s)) return false;
  const weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
  let sum = 0;
  for (let i = 0; i < 12; i++) {
    sum += parseInt(s[i] ?? "", 10) * (weights[i] ?? 0);
  }
  const check = (11 - (sum % 11)) % 10;
  return check === parseInt(s[12] ?? "", 10);
}

// Korean Business Registration Number (사업자등록번호): 10 digits. Uses the
// NTS (Hometax) standard algorithm: weights 1,3,7,1,3,7,1,3,5 over digits 1-9,
// plus floor(digit9 × 5 / 10), and the check digit is (10 - (sum mod 10)) mod 10.
export function validateKoreanBRN(input: string): boolean {
  const s = input.replace(/[-\s]/g, "");
  if (!/^\d{10}$/.test(s)) return false;
  const weights = [1, 3, 7, 1, 3, 7, 1, 3, 5];
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    sum += parseInt(s[i] ?? "", 10) * (weights[i] ?? 0);
  }
  sum += Math.floor((parseInt(s[8] ?? "", 10) * 5) / 10);
  return (10 - (sum % 10)) % 10 === parseInt(s[9] ?? "", 10);
}

// Chinese Resident Identity Card (居民身份证): 18 chars (17 digits + check).
// ISO 7064 MOD 11-2 per GB 11643-1999. Weights
// 7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2; remainder maps to "10X98765432".
export function validateChineseID(input: string): boolean {
  const s = input.toUpperCase().replace(/[-\s]/g, "");
  if (!/^\d{17}[\dX]$/.test(s)) return false;
  const weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
  const code = "10X98765432";
  let sum = 0;
  for (let i = 0; i < 17; i++) {
    sum += parseInt(s[i] ?? "", 10) * (weights[i] ?? 0);
  }
  return code[sum % 11] === s[17];
}

// IPv4 reserved / non-public ranges. Returns true for addresses that should
// NOT be flagged as PII (loopback, private, link-local, TEST-NET, multicast,
// reserved, CGN, benchmarking). Used by pii-ipv4-public to keep only public IPs.
export function isReservedIpv4(ip: string): boolean {
  const octets = ip.split(".");
  // Require exactly 4 octets of 1–3 digits each, so partial parses
  // (e.g. "1a" → 1 via parseInt) are treated as malformed, not public.
  if (octets.length !== 4 || octets.some((o) => !/^\d{1,3}$/.test(o))) {
    return true;
  }
  const parts = octets.map((o) => parseInt(o, 10));
  if (parts.some((p) => p > 255)) {
    return true;
  }
  const a = parts[0] ?? 0;
  const b = parts[1] ?? 0;
  const c = parts[2] ?? 0;
  if (a === 0 || a === 10) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGN 100.64.0.0/10
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 0 && c === 0) return true; // IETF protocol assignments
  if (a === 192 && b === 0 && c === 2) return true; // TEST-NET-1
  if (a === 192 && b === 88 && c === 99) return true; // 6to4 relay anycast (deprecated)
  if (a === 192 && b === 168) return true; // private
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmark
  if (a === 198 && b === 51 && c === 100) return true; // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true; // TEST-NET-3
  if (a >= 224) return true; // multicast + reserved
  return false;
}

// IPv6 reserved / non-public ranges. Returns true for addresses that should
// NOT be flagged as PII (loopback, unspecified, link-local, unique-local,
// multicast, documentation). Properly handles both compressed (::) and
// fully-expanded (0:0:0:0:0:0:0:1) forms. Used by pii-ipv6.
// Each group must be 1–4 hex digits; anything else is malformed.
const isHexGroup = (g: string): boolean => /^[0-9a-f]{1,4}$/.test(g);
export function isReservedIpv6(ip: string): boolean {
  const lower = ip.toLowerCase();

  // Multiple :: is invalid — treat as reserved.
  const halves = lower.split("::");
  if (halves.length > 2) return true;

  // Split and expand :: notation into zero groups.
  let groups: number[];
  if (halves.length === 1) {
    const raw = lower.split(":");
    if (raw.some((g) => !isHexGroup(g))) return true;
    groups = raw.map((g) => Number.parseInt(g, 16));
  } else {
    const leftRaw = halves[0] ? halves[0].split(":") : [];
    const rightRaw = halves[1] ? halves[1].split(":") : [];
    if (
      leftRaw.some((g) => !isHexGroup(g)) ||
      rightRaw.some((g) => !isHexGroup(g))
    ) {
      return true;
    }
    // Too many groups to fit in 128 bits — malformed. A "::" that compresses
    // zero groups (left + right === 8) is also invalid per RFC 4291 §2.2.
    if (leftRaw.length + rightRaw.length >= 8) return true;
    const left = leftRaw.map((g) => Number.parseInt(g, 16));
    const right = rightRaw.map((g) => Number.parseInt(g, 16));
    const zeros = Array(8 - left.length - right.length).fill(0);
    groups = [...left, ...zeros, ...right];
  }

  if (groups.length !== 8) return true; // malformed — treat as reserved

  // Unspecified (::)
  if (groups.every((g) => g === 0)) return true;
  // Loopback (::1)
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) return true;
  // Link-local fe80::/10
  if ((groups[0] ?? 0) >= 0xfe80 && (groups[0] ?? 0) <= 0xfebf) return true;
  // Unique-local fc00::/7
  if (((groups[0] ?? 0) & 0xfe00) === 0xfc00) return true;
  // Multicast ff00::/8
  if (((groups[0] ?? 0) & 0xff00) === 0xff00) return true;
  // Documentation 2001:db8::/32
  if ((groups[0] ?? 0) === 0x2001 && (groups[1] ?? 0) === 0x0db8) return true;

  return false;
}

// A value written to be replaced. Half of a realistic `.env.example` was being
// blocked on its contents, which is the block most likely to get the tool turned
// off — the file is meant to be committed and read.
//
// Only secret rules consult this. "todo@company.com" is a real address, and
// AWS's own documented key ends in EXAMPLE and is still a key, so `example` is
// deliberately absent from the list.
// A value whose shape says it is not a credential, whatever its name suggests.
// `TOKEN_ENDPOINT`, `secret_name`, `VAULT_TOKEN_PATH` and `TOKEN_HEADER_NAME`
// all assign something that points at a secret rather than being one, and
// blocking them made Terraform, Kubernetes manifests and OAuth configuration
// unreadable — fourteen of the twenty-six wrong blocks in a survey of six
// hundred real files.
export function isNotSecretShaped(value: string): boolean {
  const v = value.trim();
  // A URL or a URN. Credentials embedded in one are the connection-string
  // rule's business, and a URL carrying a token in its query is left alone
  // here so the `?` case still reaches the other rules.
  if (
    /^[a-z][a-z0-9+.-]*:\/\//i.test(v) &&
    !v.includes("?") &&
    !v.includes("@")
  )
    return true;
  if (/^urn:/i.test(v)) return true;
  // A filesystem path.
  if (/^[~.]?\/[^\s]*$/.test(v)) return true;
  // The name of a variable rather than its value.
  if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(v)) return true;
  // An HTTP header name.
  if (/^[A-Z][A-Za-z0-9]*(?:-[A-Z][A-Za-z0-9]*)+$/.test(v)) return true;
  // A number.
  if (/^\d+$/.test(v)) return true;
  // A dotted lower-case identifier, as a storage key or a setting name.
  if (/^[a-z][a-z0-9]*(?:\.[a-z0-9]+)+$/.test(v)) return true;
  // A reference to a value in code rather than the value: `process.env.API_KEY`,
  // `user.password_digest`, `self.api_key`, `response.data.accessToken`. Of the
  // distinct values `env-assignment` matched across thirty thousand real files,
  // two in five were one of these.
  if (
    /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(v) &&
    v.split(".").every(readsAsWords)
  )
    return true;
  return false;
}

// Whether a name is built out of words rather than out of random characters.
//
// Dotted credentials exist — a JWT, and the dotted forms several vendors issue —
// so the shape alone cannot stand for "this is code". What separates them is
// that a name is words: `connectionString` and `password_digest` run several
// letters between one boundary and the next, where a random segment changes
// case or slips in a digit every character or two.
//
// Measured over 147,643 dotted identifiers taken from the source on this
// machine, 0.06% fall below the threshold below, and the ones that do are JWTs.
const MIN_MEAN_WORD_LENGTH = 2.5;

// Short segments are words by default: `env`, `data`, `id`. The statistic needs
// something to average over before it says anything.
const SHORTEST_MEASURABLE_SEGMENT = 8;

function readsAsWords(segment: string): boolean {
  if (segment.length < SHORTEST_MEASURABLE_SEGMENT) return true;
  // A leading capital belongs to the lowercase run after it, so `toLowerCase`
  // is three words and not five runs of one case.
  const words = segment.match(/[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+/g);
  if (words === null || words.length === 0) return false;
  return segment.length / words.length >= MIN_MEAN_WORD_LENGTH;
}

// A key that says where a secret lives, or what it is called, rather than what
// it is. The rule fires on the keyword anywhere in the name, so
// `SECRET_MANAGER_PROJECT` reads as a secret because of its first word, when its
// last one says it holds a project.
const DESCRIBES_A_SECRET =
  /\b[A-Za-z0-9_]*_(?:PROJECT|NAME|PATH|FILE|DIR|URL|URI|ENDPOINT|HOST|PORT|ID|TYPE|HEADER|PREFIX|SUFFIX|FIELD|COLUMN|TABLE|ENV|REGION|BUCKET|ARN|VERSION|TTL|TIMEOUT|LENGTH|COUNT|ENABLED|ALGORITHM|ISSUER|AUDIENCE|SCOPE|PROVIDER|BACKEND|SOURCE)\b[ \t]*[:=]/i;

export function keyDescribesRatherThanHolds(matchText: string): boolean {
  return DESCRIBES_A_SECRET.test(matchText);
}

// A word that only ever appears in a value nobody typed.
const PLACEHOLDER_MARKERS =
  /^(?:changeme|change|me|replace|insert|set|with|real|this|your|my|here|todo|tbd|fixme|dummy|placeholder|insecure|sample|example|test|fake|redacted|value|x{3,})$/i;

// A word that can make up the rest of such a value, but never marks one alone.
const PLACEHOLDER_FILLER =
  /^(?:api|key|keys|token|tokens|secret|secrets|password|passwd|pwd|pass|base|url|uri|host|hostname|name|user|username|id|access|refresh|client|auth|sk|pk|in|production|development|staging|local|dev|the|a|of|for|and|[0-9]+)$/i;

export function isPlaceholder(value: string, following = ""): boolean {
  const v = value.trim();
  if (!v) return false;
  // Filler on its own: `xxxxxxxxxxxx`.
  if (/^[Xx]+$/.test(v)) return true;
  // A slot rather than a value: `<your-token>`, `${TOKEN}`, `{{ token }}`.
  if (/^[<{[]/.test(v) && /[>}\]]$/.test(v)) return true;
  // A shell or template reference, which holds nothing at all.
  if (/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(v)) return true;
  // An unexpanded reference anywhere inside a connection string: no character
  // of the credentials has been substituted yet.
  if (
    /:\/\/[^@\s]*(?:\$\{[A-Za-z_][^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\})[^@\s]*@/.test(
      v,
    )
  )
    return true;
  // A user and a password that are the same word, and that word names the
  // service: `postgres:postgres@`, `root:root@`, `guest:guest@` are what a
  // compose file and a quickstart ship with.
  const samePair = v.match(/:\/\/([A-Za-z]{3,12}):([A-Za-z]{3,12})@/);
  if (
    samePair &&
    samePair[1]?.toLowerCase() === samePair[2]?.toLowerCase() &&
    /^(?:postgres|postgresql|mysql|mariadb|mongo|mongodb|redis|root|guest|admin|user|test|rabbitmq)$/i.test(
      samePair[1] ?? "",
    )
  )
    return true;
  // The default the django template generates, which ships in every new project.
  if (/^django-insecure-/i.test(v)) return true;
  // A connection string where the user, the password and the host are all the
  // words for them. Each of the three matters: `root:secret@` is a password
  // people set, and `user:password@prod.corp.internal` names real infrastructure.
  // The rule that finds these stops at the `@`, so the host arrives as the text
  // that follows rather than as part of the value.
  // The scheme is bounded: an unbounded `\w+` in front of a literal that
  // usually is not there makes the match quadratic in the length of the value,
  // and a value is as long as whoever wrote the text wants. A scheme is a word.
  const GENERIC_CREDENTIALS =
    /\w{1,32}:\/\/(?:your[_-]?)?(?:user|username)(?:name)?:(?:your[_-]?)?(?:password|passwd|pwd)@/i;
  const GENERIC_HOST =
    /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|host|hostname|db|database|example\.(?:com|org|net))\b/i;
  // Matched once. Asking three times ran the same backtracking three times.
  const credentials = GENERIC_CREDENTIALS.exec(v);
  if (credentials !== null) {
    const afterAt = v.slice(credentials.index + credentials[0].length);
    if (GENERIC_HOST.test(afterAt || following)) return true;
  }
  // Otherwise every part of the value has to be one of these words, and at
  // least one has to be a marker. Testing whether the value *contains* a marker
  // was a way through: `changeme_` in front of a live key disabled the rule.
  const parts = v.split(/[-_.\s]+/).filter(Boolean);
  if (parts.length === 0) return false;
  if (!parts.some((part) => PLACEHOLDER_MARKERS.test(part))) return false;
  return parts.every(
    (part) => PLACEHOLDER_MARKERS.test(part) || PLACEHOLDER_FILLER.test(part),
  );
}

// Shannon entropy (bits per character; ≈0–8 for byte-sized alphabets)
export function entropy(str: string): number {
  if (str.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const ch of str) freq[ch] = (freq[ch] ?? 0) + 1;
  let h = 0;
  const n = str.length;
  for (const count of Object.values(freq)) {
    const p = count / n;
    h -= p * Math.log2(p);
  }
  return h;
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

// ── Validator registry ───────────────────────────────────────────────────────
// Validators are code (checksum algorithms), not data. They live here and are
// referenced by name from the JSON config. User-defined rules can use any of
// these validators or omit `validate` entirely.

// A Japanese telephone number: ten digits, or eleven for a mobile. The pattern
// alone also matched `01-02-2024`, which is a date, and `0000 0000 0000`, which
// is an identifier. Freephone prefixes are excluded — 0120 and 0800 belong to a
// business and are printed to be dialled.
export function validateJapanesePhone(input: string): boolean {
  const digits = input.replace(/\D/g, "");
  if (!/^0\d{8,10}$/.test(digits)) return false;
  if (digits.length !== 10 && digits.length !== 11) return false;
  if (/^0(?:120|800)/.test(digits)) return false;
  return true;
}

const VALIDATORS: Readonly<Record<string, (str: string) => boolean>> = {
  luhn: isRealCardNumber,
  "aws-key": isRealAwsKey,
  "mynumber-jp": validateMyNumber,
  "phone-jp": validateJapanesePhone,
  "nir-fr": validateFrenchNIR,
  "codice-fiscale-it": validateCodiceFiscale,
  "steuer-id-de": validateGermanIdNr,
  "dni-nie-es": validateSpanishNIF,
  "rrn-kr": validateKoreanRRN,
  "brn-kr": validateKoreanBRN,
  "resident-id-cn": validateChineseID,
  "public-ipv4": (ip: string) => !isReservedIpv4(ip),
  "public-ipv6": (ip: string) => !isReservedIpv6(ip),
};

// The names a config file may put in `validate`. Exported so the documents can
// be held to the same list: `phone-jp` was added to the registry and named in
// neither document, so a user writing a rule could not know it existed.
export const VALIDATOR_NAMES: readonly string[] = Object.keys(VALIDATORS);

export function getValidator(
  name: string,
): ((str: string) => boolean) | undefined {
  return VALIDATORS[name];
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
    const fn = VALIDATORS[validateName];
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

// Longer than any honest scan and far shorter than the hook timeout. One rule
// that backtracks badly used to take minutes on a megabyte, and a hook killed by
// the timeout does not block — so the damage was silent. Bounding the patterns
// fixed the two that did it; this is here so the next one of that shape is
// caught rather than repeating the same failure. The check sits between rules
// because a single `matchAll` cannot be interrupted.
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

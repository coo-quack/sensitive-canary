export type Category = "secret" | "pii";

export interface Finding {
  ruleId: string;
  description: string;
  category: Category;
  matchRedacted: string;
  secretValue: string;
  score: number;
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
  contextWindow?: number;
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
export function luhn(str: string): boolean {
  const digits = str.replace(/\D/g, "");
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
// 11 - (sum mod 11); a remainder of 0 or 1 is an invalid number.
// Spec: 地方公共団体情報システム機構 (JIPTEC).
export function validateMyNumber(input: string): boolean {
  const digits = input.replace(/\D/g, "");
  if (digits.length !== 12) return false;
  const weights = [6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
  let sum = 0;
  for (let i = 0; i < 11; i++) {
    sum += parseInt(digits[i] ?? "", 10) * (weights[i] ?? 0);
  }
  const remainder = sum % 11;
  if (remainder <= 1) return false;
  return 11 - remainder === parseInt(digits[11] ?? "", 10);
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
  if (!/^[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]$/.test(cf)) return false;

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
// Uses ISO/IEC 7064 MOD 11,10. Spec: Bundeszentralamt für Steuern.
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
// Spec: Ministerio del Interior, Orden INT/2058/2008.
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

// Shannon entropy (bits per character, 0–8 scale)
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

const DEFAULT_CONTEXT_WINDOW = 10;

// Split on whitespace and Unicode punctuation. A cheap tokenizer with no NLP
// dependency, sufficient for matching context labels (phone, ZIP, etc.) in
// Latin-script text. Japanese PII rules rely on prefixes (〒) or required
// separators rather than context words, so this tokenizer not needing to
// handle Japanese word segmentation is acceptable.
function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[\s\p{P}]+/u)
    .filter(Boolean);
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
  const nearby = new Set(tokenize(`${before} ${after}`));
  return contextWords.some((word) => nearby.has(word.toLowerCase()));
}

// Patterns sourced from gitleaks and TruffleHog detector definitions.
// Each rule:
//   regex        — must have /g flag
//   secretGroup  — capture group containing the secret (default: 0 = full match)
//   entropyThreshold — skip match if entropy(secretValue) is below threshold

// ── Secrets ───────────────────────────────────────────────────────────────────

const SECRET_RULES: Rule[] = [
  // Cloud
  {
    id: "aws-access-key",
    description: "AWS Access Key ID",
    regex:
      /\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g,
    category: "secret",
  },
  {
    id: "gcp-api-key",
    description: "Google Cloud API Key",
    regex: /AIza[0-9A-Za-z_-]{35}/g,
    category: "secret",
  },
  {
    id: "private-key",
    description: "PEM Private Key",
    // Covers RSA, EC, DSA, PGP, and OpenSSH private keys
    regex: /-----BEGIN (RSA |EC |DSA |PGP |OPENSSH )?PRIVATE KEY/g,
    category: "secret",
  },

  // Source control
  {
    id: "github-pat",
    description: "GitHub Personal Access Token",
    regex: /gh[pousr]_[A-Za-z0-9]{36,255}/g,
    category: "secret",
  },
  {
    id: "github-fine-grained",
    description: "GitHub Fine-Grained Token",
    regex: /github_pat_[A-Za-z0-9_]{82}/g,
    category: "secret",
  },
  {
    id: "gitlab-pat",
    description: "GitLab Personal Access Token",
    regex: /glpat-[A-Za-z0-9_=-]{20,22}/g,
    category: "secret",
  },

  // Package registries
  {
    id: "npm-token",
    description: "npm Access Token",
    regex: /npm_[A-Za-z0-9]{36}/g,
    category: "secret",
  },

  // Communication
  {
    id: "slack-token",
    description: "Slack Token",
    regex: /xox[baprs]-[0-9a-zA-Z-]{10,72}/g,
    category: "secret",
  },
  {
    id: "slack-webhook",
    description: "Slack Webhook URL",
    regex:
      /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]{8,10}\/B[A-Za-z0-9_]{8,12}\/[A-Za-z0-9_]{23,24}/g,
    category: "secret",
  },
  {
    id: "discord-webhook",
    description: "Discord Webhook URL",
    regex:
      /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[A-Za-z0-9_-]{68}/g,
    category: "secret",
  },
  {
    id: "telegram-bot-token",
    description: "Telegram Bot Token",
    regex: /[0-9]{8,10}:AA[0-9A-Za-z_-]{33}/g,
    category: "secret",
  },
  {
    id: "twilio-sid",
    description: "Twilio Account SID",
    regex: /AC[0-9a-f]{32}/g,
    category: "secret",
  },

  // Email services
  {
    id: "sendgrid-key",
    description: "SendGrid API Key",
    regex: /SG\.[A-Za-z0-9_-]{20,24}\.[A-Za-z0-9_-]{39,50}/g,
    category: "secret",
  },
  {
    id: "mailgun-key",
    description: "Mailgun API Key",
    regex: /key-[0-9a-zA-Z]{32}/g,
    category: "secret",
  },
  {
    id: "mailchimp-key",
    description: "Mailchimp API Key",
    regex: /[0-9a-f]{32}-us[0-9]{1,2}/g,
    category: "secret",
  },

  // Payment
  {
    id: "stripe-secret-key",
    description: "Stripe Secret Key",
    regex: /sk_(live|test)_[0-9a-zA-Z]{24}/g,
    category: "secret",
  },
  {
    id: "stripe-restricted-key",
    description: "Stripe Restricted Key",
    regex: /rk_(live|test)_[0-9a-zA-Z]{24}/g,
    category: "secret",
  },

  // AI services
  {
    id: "openai-key",
    description: "OpenAI API Key (legacy)",
    regex: /sk-(?!proj-|ant-)[A-Za-z0-9]{48}/g,
    category: "secret",
  },
  {
    id: "openai-project-key",
    description: "OpenAI Project API Key",
    regex: /sk-proj-[A-Za-z0-9_-]{40,}/g,
    entropyThreshold: 3.5,
    category: "secret",
  },
  {
    id: "anthropic-key",
    description: "Anthropic API Key",
    regex: /sk-ant-[A-Za-z0-9_-]{95}/g,
    category: "secret",
  },

  // Auth tokens
  {
    id: "jwt",
    description: "JSON Web Token (JWT)",
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    category: "secret",
  },

  // Generic / env-based
  {
    id: "generic-secret",
    description: "Generic API Key / Secret",
    regex:
      /(api[_-]?key|secret[_-]?key|access[_-]?token|api[_-]?secret)\s*[:=]\s*['"]?([A-Za-z0-9\-_.]{20,})/gi,
    secretGroup: 2,
    entropyThreshold: 3.5,
    category: "secret",
  },
  {
    id: "env-assignment",
    description: ".env style secret assignment",
    regex:
      /\b[A-Z_]*(SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|PRIVATE_KEY)[A-Z_0-9]*\s*=\s*(\S{8,})/g,
    secretGroup: 2,
    entropyThreshold: 3.0,
    category: "secret",
  },
  {
    id: "connection-string",
    description: "Database Connection String with credentials",
    regex: /(mongodb|mysql|postgres|postgresql|redis):\/\/[^:\s]+:[^@\s]+@/g,
    category: "secret",
  },
];

// ── PII ───────────────────────────────────────────────────────────────────────

const PII_RULES: Rule[] = [
  {
    id: "pii-email",
    description: "Email Address",
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    category: "pii",
  },
  {
    id: "pii-credit-card",
    description: "Credit Card Number",
    // Visa (16d) | Mastercard (16d) | Amex (15d) | Discover (16d)
    // Optional spaces or dashes between digit groups
    regex:
      /\b(?:4[0-9]{3}(?:[\s-]?[0-9]{4}){3}|5[1-5][0-9]{2}(?:[\s-]?[0-9]{4}){3}|3[47][0-9]{2}[\s-]?[0-9]{6}[\s-]?[0-9]{5}|6(?:011|5[0-9]{2})[0-9](?:[\s-]?[0-9]{4}){3})\b/g,
    validate: luhn,
    category: "pii",
  },
  {
    id: "pii-ssn",
    description: "US Social Security Number",
    regex: /\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b/g,
    category: "pii",
  },
  {
    id: "pii-phone-us",
    description: "US Phone Number",
    regex: /\b(\+1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g,
    category: "pii",
  },
  {
    id: "pii-phone-jp",
    description: "Japanese Phone Number",
    regex: /\b0\d{1,4}[\s-]\d{1,4}[\s-]\d{4}\b/g,
    category: "pii",
  },
  {
    id: "pii-postal-jp",
    description: "Japanese Postal Code",
    // Require 〒 prefix to avoid false positives (e.g. phone number fragments)
    regex: /〒\d{3}[\s-]\d{4}/g,
    category: "pii",
  },
  {
    id: "pii-ipv4",
    description: "IPv4 Address (private range)",
    // Only flag RFC-1918 private addresses to reduce noise
    regex:
      /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
    category: "pii",
  },

  // ── National ID numbers (checksum-validated) ────────────────────────────────
  {
    id: "pii-mynumber-jp",
    description: "Japanese Individual Number (My Number)",
    regex: /\b\d{12}\b/g,
    validate: validateMyNumber,
    category: "pii",
  },
  {
    id: "pii-nir-fr",
    description: "French NIR / Social Security Number",
    regex:
      /\b[12]\d{2}(?:0[1-9]|1[0-9]|2[0-9]|[3-9]\d)(?:\d{5}|2[AB]\d{3})\d{3}\s?\d{2}\b/gi,
    validate: validateFrenchNIR,
    category: "pii",
  },
  {
    id: "pii-codice-fiscale-it",
    description: "Italian Codice Fiscale",
    regex: /\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b/g,
    validate: validateCodiceFiscale,
    category: "pii",
  },
  {
    id: "pii-steuer-id-de",
    description: "German Steuer-Identifikationsnummer",
    regex: /\b[1-9]\d{10}\b/g,
    validate: validateGermanIdNr,
    category: "pii",
  },
  {
    id: "pii-dni-nie-es",
    description: "Spanish DNI / NIE",
    regex: /\b(?:\d{8}[A-Z]|[XYZ]\d{7}[A-Z])\b/g,
    validate: validateSpanishNIF,
    category: "pii",
  },

  // ── Phone numbers (FIGS) ─────────────────────────────────────────────────────
  // Variable-length Italian and German numbers are noisy on bare digits, so
  // these require a nearby phone-related context word.
  {
    id: "pii-phone-fr",
    description: "French Phone Number",
    regex: /\b0[1-9](?:[\s.-]?\d{2}){4}\b/g,
    category: "pii",
    requireContext: true,
    contextWords: [
      "tél",
      "tel",
      "téléphone",
      "telephone",
      "phone",
      "mobile",
      "portable",
      "contact",
      "appel",
      "fax",
    ],
  },
  {
    id: "pii-phone-it",
    description: "Italian Phone Number",
    regex: /\b(?:0\d{8,9}|3\d{8,9})\b/g,
    category: "pii",
    requireContext: true,
    contextWords: [
      "telefono",
      "tel",
      "cellulare",
      "mobile",
      "phone",
      "contatto",
      "chiamata",
      "fax",
    ],
  },
  {
    id: "pii-phone-de",
    description: "German Phone Number",
    regex: /\b0[1-9]\d{6,11}\b/g,
    category: "pii",
    requireContext: true,
    contextWords: [
      "telefon",
      "tel",
      "handy",
      "mobil",
      "phone",
      "anruf",
      "nummer",
      "fax",
    ],
  },
  {
    id: "pii-phone-es",
    description: "Spanish Phone Number",
    regex: /\b[67]\d{8}\b/g,
    category: "pii",
    requireContext: true,
    contextWords: [
      "teléfono",
      "telefono",
      "tel",
      "móvil",
      "movil",
      "phone",
      "contacto",
      "llamada",
      "fax",
    ],
  },

  // ── Postal codes (5/9-digit, context-gated) ─────────────────────────────────
  // Bare 5/9-digit numbers are too generic to flag without a nearby label.
  // Japanese postal codes keep their own rule (〒 prefix required).
  {
    id: "pii-postal-code",
    description: "Postal Code (US ZIP / EU)",
    regex: /\b\d{5}(?:-\d{4})?\b/g,
    category: "pii",
    requireContext: true,
    contextWords: [
      "zip",
      "postal",
      "postale",
      "postcode",
      "plz",
      "postleitzahl",
      "cap",
      "código",
      "codigo",
    ],
  },
];

export const RULES: Rule[] = [...SECRET_RULES, ...PII_RULES];

// Show first 4 + **** + last 4 chars; fully mask strings of 8 chars or fewer
export function redact(str: string): string {
  if (str.length <= 8) return "****";
  return `${str.slice(0, 4)}****${str.slice(-4)}`;
}

export function scan(
  text: string,
  categories: ReadonlySet<Category> = ALL_CATEGORIES,
): Finding[] {
  const findings: Finding[] = [];

  for (const rule of RULES) {
    if (!categories.has(rule.category)) continue;
    for (const match of text.matchAll(rule.regex)) {
      const secretValue =
        rule.secretGroup != null ? match[rule.secretGroup] : match[0];

      if (!secretValue) continue;
      if (
        rule.entropyThreshold != null &&
        entropy(secretValue) < rule.entropyThreshold
      )
        continue;
      if (rule.validate != null && !rule.validate(match[0])) continue;

      const matchStart = match.index ?? 0;
      const matchEnd = matchStart + match[0].length;
      const hasContext =
        !rule.contextWords || rule.contextWords.length === 0
          ? true
          : hasNearbyContextWord(
              text,
              matchStart,
              matchEnd,
              rule.contextWords,
              rule.contextWindow ?? DEFAULT_CONTEXT_WINDOW,
            );

      // Rules that require context (e.g. bare postal codes) are dropped when
      // no context label is nearby, to avoid flagging every 5-digit number.
      if (rule.requireContext && !hasContext) continue;

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

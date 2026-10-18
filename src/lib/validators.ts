// The checksum algorithms and range checks a rule may name in its `validate`
// field.
//
// These are code where the rules are data: a rule says `"validate": "luhn"` and
// the registry at the foot of this file resolves the name. Each answers one
// question about one value — does this pass the checksum, is this address
// reserved — and none of them knows what a rule is.

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
  // Stripe's published test cards that the list above did not carry. The
  // Mastercard 2-series number is one of them, so a test that expects it to be
  // found is wrong, not this list.
  "4000000000000002",
  "2223003122003222",
  "36227206271667",
  "6200000000000005",
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

// A value written after `password` or `--password` that is a password and not
// a word about one. `password is required` and `the password was reset` are
// prose, and the rules that read a password off a label would otherwise block
// them. A password has a letter, and a digit or a symbol beside it; the length
// bounds keep single characters and pasted paragraphs out.
//
// The leading characters are the ones a value is written as a reference in,
// not as a value: `$VAR`, `%VAR%`, `<token>`, `{{ token }}`, `-` as a flag,
// `/path`, `~/file`. A value of only asterisks is a mask that a tool printed.
const ASCII_SYMBOL = /[!-/:-@[-`{-~]/;
export function isPasswordLike(input: string): boolean {
  // The rules that take a quoted value hand over the quotes with it. They are
  // not part of the password, and the checks below read the value alone.
  const str = input.replace(/^(["'])(.*)\1$/s, "$2");
  if (str.length < 6 || str.length > 128) return false;
  if (/\s/.test(str)) return false;
  if (/^[$%<{\-/~]/.test(str)) return false;
  if (/^\*+$/.test(str)) return false;
  if (!/[A-Za-z]/.test(str)) return false;
  return /[0-9]/.test(str) || ASCII_SYMBOL.test(str);
}

// An HTTP Basic credential: the base64 of `user:password`. The value has to
// decode to printable UTF-8 with a colon that has a user before it and a
// password after it. The round trip rejects base64 that a lenient decoder
// would accept anyway (wrong padding, stray characters), so a value only
// counts when it is exactly what the header would carry.
export function isBasicCredentials(str: string): boolean {
  if (str.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(str)) return false;
  const bytes = Buffer.from(str, "base64");
  if (bytes.toString("base64") !== str) return false;
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return false;
  }
  if (/\p{Cc}/u.test(text)) return false;
  const colon = text.indexOf(":");
  if (colon <= 0 || colon === text.length - 1) return false;
  // The credentials every tutorial, test fixture and default install uses.
  // A pair made only of these is a documented example, not a credential, and
  // both halves have to be on the list: `admin:Xk9mP2qR7v` is still one.
  const user = text.slice(0, colon).toLowerCase();
  const password = text.slice(colon + 1).toLowerCase();
  return !(
    DOCUMENTED_BASIC_WORDS.has(user) && DOCUMENTED_BASIC_WORDS.has(password)
  );
}

const DOCUMENTED_BASIC_WORDS: ReadonlySet<string> = new Set([
  "user",
  "username",
  "admin",
  "root",
  "test",
  "foo",
  "bar",
  "guest",
  "demo",
  "pass",
  "password",
  "passwd",
  "secret",
  "changeme",
]);

// Lengths for the countries whose IBANs have a fixed length, from the SWIFT
// IBAN registry. A country not listed here is only held to the general range
// and the check digits, so a new country is not refused on a table that is
// out of date.
const IBAN_LENGTHS: Readonly<Record<string, number>> = {
  AT: 20,
  BE: 16,
  CH: 21,
  DE: 22,
  DK: 18,
  ES: 24,
  FI: 18,
  FR: 27,
  GB: 22,
  IE: 22,
  IT: 27,
  LU: 20,
  NL: 18,
  NO: 15,
  PL: 28,
  PT: 25,
  SE: 24,
};

// ISO 13616 mod-97 check: move the first four characters to the end, turn each
// letter into two digits (A=10 … Z=35), and the number must leave a remainder
// of 1. The remainder is kept as it goes so the number never leaves safe
// integer range.
export function isIban(str: string): boolean {
  const iban = str.replace(/ /g, "");
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]+$/.test(iban)) return false;
  const expected = IBAN_LENGTHS[iban.slice(0, 2)];
  if (expected !== undefined) {
    if (iban.length !== expected) return false;
  } else if (iban.length < 15 || iban.length > 34) {
    return false;
  }
  let remainder = 0;
  for (const ch of iban.slice(4) + iban.slice(0, 4)) {
    const code = ch.charCodeAt(0);
    if (code >= 65) {
      remainder = (remainder * 100 + (code - 55)) % 97;
    } else {
      remainder = (remainder * 10 + (code - 48)) % 97;
    }
  }
  return remainder === 1;
}

// An international telephone number, judged by its digits alone. Nine digits is
// the shortest a subscriber number with a country code runs, and fifteen is the
// E.164 limit. A run of one digit repeated is a placeholder, not a number.
export function isIntlPhone(str: string): boolean {
  const digits = str.replace(/\D/g, "");
  if (digits.length < 9 || digits.length > 15) return false;
  return !/^(\d)\1*$/.test(digits);
}

// The UK National Insurance number format: two letters the HMRC does not issue
// in the first and second position, the prefixes it reserves, and a suffix of
// A to D (the regex enforces the suffix). Spaces are the printed form and are
// dropped before the check.
const NINO_FORBIDDEN_FIRST = "DFIQUV";
const NINO_FORBIDDEN_SECOND = "DFIOQUV";
const NINO_FORBIDDEN_PREFIXES: ReadonlySet<string> = new Set([
  "BG",
  "GB",
  "KN",
  "NK",
  "NT",
  "TN",
  "ZZ",
]);
export function isNinoUk(str: string): boolean {
  const nino = str.replace(/ /g, "");
  if (!/^[A-Z]{2}[0-9]{6}[A-D]$/.test(nino)) return false;
  if (NINO_FORBIDDEN_FIRST.includes(nino.charAt(0))) return false;
  if (NINO_FORBIDDEN_SECOND.includes(nino.charAt(1))) return false;
  return !NINO_FORBIDDEN_PREFIXES.has(nino.slice(0, 2));
}

// A US number judged by its last ten digits, so the country code before it does
// not matter. The numbers these checks refuse are the ones documentation and
// fixtures use: area code 555 is not allocated, the 555 exchange with lines
// 0100–0199 is reserved for fiction, 555-1212 is the directory-assistance
// number, and the toll-free area codes are businesses that print their number
// to be dialled.
const US_TOLL_FREE_AREAS: ReadonlySet<string> = new Set([
  "800",
  "888",
  "877",
  "866",
  "855",
  "844",
  "833",
]);
export function isUsPhone(str: string): boolean {
  const digits = str.replace(/\D/g, "");
  if (digits.length < 10) return false;
  const last10 = digits.slice(-10);
  const area = last10.slice(0, 3);
  const exchange = last10.slice(3, 6);
  const line = last10.slice(6);
  if (area === "555") return false;
  if (exchange === "555" && (line === "1212" || /^01[0-9]{2}$/.test(line)))
    return false;
  return !US_TOLL_FREE_AREAS.has(area);
}

// Local parts that name a function rather than a person. The list is the one a
// mailbox policy would name; a local part is compared whole, so `john.support`
// and `support2` are still a person's address and still found.
const ROLE_MAILBOX_LOCAL_PARTS: ReadonlySet<string> = new Set([
  "noreply",
  "no-reply",
  "donotreply",
  "do-not-reply",
  "support",
  "sales",
  "info",
  "help",
  "contact",
  "press",
  "abuse",
  "postmaster",
  "webmaster",
  "hostmaster",
]);

// Takes a whole address, as the email rule matches it, and reports whether its
// local part is a person's. The `%40` form is the `@` in a URL query, and it is
// split on as well so `support%40x.com` is read the same way.
export function isPersonalMailbox(address: string): boolean {
  const local = address.split(/@|%40/i, 1)[0] ?? "";
  return !ROLE_MAILBOX_LOCAL_PARTS.has(local.toLowerCase());
}

// AWS secret access keys are base64 over a mixed alphabet. A 40-character run
// that is all lower case, or all hex, is a git commit id or a digest that happens
// to sit beside an access key ID, and the rule that reads a secret beside a key
// ID cannot tell those apart by their position alone.
export function hasAwsSecretShape(str: string): boolean {
  return /[A-Z]/.test(str) && /[a-z]/.test(str) && /[0-9]/.test(str);
}

// The first year of each era, so that 昭和63 is 1925 + 63.
const ERA_BASE_YEARS: Readonly<Record<string, number>> = {
  明治: 1867,
  大正: 1911,
  昭和: 1925,
  平成: 1988,
  令和: 2018,
};

// The one-letter prefixes of the S63.7.21 form, for the same eras.
const ERA_LETTERS: Readonly<Record<string, string>> = {
  M: "明治",
  T: "大正",
  S: "昭和",
  H: "平成",
  R: "令和",
};

const MONTH_ABBREVIATIONS = [
  "jan",
  "feb",
  "mar",
  "apr",
  "may",
  "jun",
  "jul",
  "aug",
  "sep",
  "oct",
  "nov",
  "dec",
];

const MONTH_NAME =
  "(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)";

const monthNumber = (name: string): number =>
  MONTH_ABBREVIATIONS.indexOf(name.slice(0, 3).toLowerCase()) + 1;

// "YYYY-M-D" when the day exists in that month and the year is from 1900 to
// this year. Date.UTC rolls an impossible day into the next month, so the
// fields are read back and compared.
function calendarKey(
  year: number,
  month: number,
  day: number,
): string | undefined {
  if (year < 1900 || year > new Date().getFullYear()) return undefined;
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  )
    return undefined;
  return `${year}-${month}-${day}`;
}

function calendarKeys(...dates: [number, number, number][]): string[] {
  return dates.flatMap(([y, m, d]) => {
    const key = calendarKey(y, m, d);
    return key === undefined ? [] : [key];
  });
}

// The kanji digits, read one at a time. 十 is handled by kanjiNumber.
const KANJI_DIGITS: Readonly<Record<string, number>> = {
  〇: 0,
  一: 1,
  二: 2,
  三: 3,
  四: 4,
  五: 5,
  六: 6,
  七: 7,
  八: 8,
  九: 9,
};

// A number written in kanji or in ASCII digits. Without 十 the digits are read
// one at a time, so 一九八八 is 1988. With 十 the number is positional and runs
// from 1 to 99: 十 is 10, 五十 is 50 and 二十一 is 21. Any other shape, such as
// 十十, gives undefined.
function kanjiNumber(str: string): number | undefined {
  if (!str.includes("十")) {
    if (str.length === 0) return undefined;
    let value = 0;
    for (const ch of str) {
      const digit = /^[0-9]$/.test(ch) ? Number(ch) : KANJI_DIGITS[ch];
      if (digit === undefined) return undefined;
      value = value * 10 + digit;
    }
    return value;
  }
  const m = /^([一二三四五六七八九]?)十([一二三四五六七八九]?)$/.exec(str);
  if (!m) return undefined;
  const tens = m[1] ? (KANJI_DIGITS[m[1]] ?? 0) : 1;
  const ones = m[2] ? (KANJI_DIGITS[m[2]] ?? 0) : 0;
  return tens * 10 + ones;
}

// A year, month or day group as a date form captured it. A group that is not a
// number gives NaN, which calendarKey refuses.
function dateNumber(text: string | undefined): number {
  if (text === undefined) return Number.NaN;
  if (/^[0-9]+$/.test(text)) return Number(text);
  return kanjiNumber(text) ?? Number.NaN;
}

// 元 is the first year of an era. An era year of 0 is not a year.
function eraCalendarKeys(
  era: string,
  eraYear: string,
  month: number,
  day: number,
): string[] {
  const base = ERA_BASE_YEARS[era];
  const year = eraYear === "元" ? 1 : dateNumber(eraYear);
  if (base === undefined || !(year >= 1)) return [];
  return calendarKeys([base + year, month, day]);
}

function birthDateKeys(str: string): string[] {
  const iso = /^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})$/.exec(str);
  if (iso)
    return calendarKeys([Number(iso[1]), Number(iso[2]), Number(iso[3])]);

  const kanjiWestern =
    /^([0-9〇一二三四五六七八九]{4})年\s?([0-9〇一二三四五六七八九十]{1,3})月\s?([0-9〇一二三四五六七八九十]{1,3})日$/.exec(
      str,
    );
  if (kanjiWestern)
    return calendarKeys([
      dateNumber(kanjiWestern[1]),
      dateNumber(kanjiWestern[2]),
      dateNumber(kanjiWestern[3]),
    ]);

  const numericEnd = /^(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})$/.exec(str);
  if (numericEnd) {
    const a = Number(numericEnd[1]);
    const b = Number(numericEnd[2]);
    const y = Number(numericEnd[3]);
    return calendarKeys([y, b, a], [y, a, b]);
  }

  const dayMonth = new RegExp(
    `^(\\d{1,2})(?:st|nd|rd|th)?\\s+${MONTH_NAME}\\.?,?\\s+(\\d{4})$`,
    "i",
  ).exec(str);
  if (dayMonth)
    return calendarKeys([
      Number(dayMonth[3]),
      monthNumber(dayMonth[2] ?? ""),
      Number(dayMonth[1]),
    ]);

  const monthDay = new RegExp(
    `^${MONTH_NAME}\\.?\\s+(\\d{1,2})(?:st|nd|rd|th)?,?\\s+(\\d{4})$`,
    "i",
  ).exec(str);
  if (monthDay)
    return calendarKeys([
      Number(monthDay[3]),
      monthNumber(monthDay[1] ?? ""),
      Number(monthDay[2]),
    ]);

  const kanjiEra =
    /^(明治|大正|昭和|平成|令和)\s?(元|[0-9〇一二三四五六七八九十]{1,4})年\s?([0-9〇一二三四五六七八九十]{1,3})月\s?([0-9〇一二三四五六七八九十]{1,3})日$/.exec(
      str,
    );
  if (kanjiEra)
    return eraCalendarKeys(
      kanjiEra[1] ?? "",
      kanjiEra[2] ?? "",
      dateNumber(kanjiEra[3]),
      dateNumber(kanjiEra[4]),
    );

  const letterEra = /^([MTSHR])(\d{1,2})\.(\d{1,2})\.(\d{1,2})$/i.exec(str);
  if (letterEra) {
    const era = ERA_LETTERS[(letterEra[1] ?? "").toUpperCase()];
    if (era === undefined) return [];
    return eraCalendarKeys(
      era,
      letterEra[2] ?? "",
      Number(letterEra[3]),
      Number(letterEra[4]),
    );
  }

  return [];
}

// 1970-01-01 and 1900-01-01 are what form defaults and "unknown" placeholders
// write: a record that says DOB 01/01/1970 has no date of birth, and its subject
// was not born that day.
const BIRTH_DATE_PLACEHOLDERS: ReadonlySet<string> = new Set([
  "1970-1-1",
  "1900-1-1",
]);

export function isBirthDate(str: string): boolean {
  return birthDateKeys(str.trim()).some(
    (key) => !BIRTH_DATE_PLACEHOLDERS.has(key),
  );
}

const VALIDATORS: Readonly<Record<string, (str: string) => boolean>> = {
  "password-like": isPasswordLike,
  "basic-credentials": isBasicCredentials,
  iban: isIban,
  "phone-intl": isIntlPhone,
  "nino-uk": isNinoUk,
  "phone-us": isUsPhone,
  "personal-mailbox": isPersonalMailbox,
  "aws-secret-shape": hasAwsSecretShape,
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
  "birth-date": isBirthDate,
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

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

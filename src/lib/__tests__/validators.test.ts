import { describe, expect, it } from "vitest";
import {
  hasAwsSecretShape,
  isBasicCredentials,
  isIban,
  isIntlPhone,
  isNinoUk,
  isPasswordLike,
  isPersonalMailbox,
  isRealCardNumber,
  isReservedIpv4,
  isReservedIpv6,
  isUsPhone,
  luhn,
  validateChineseID,
  validateCodiceFiscale,
  validateFrenchNIR,
  validateGermanIdNr,
  validateKoreanBRN,
  validateKoreanRRN,
  validateMyNumber,
  validateSpanishNIF,
} from "../validators.ts";
import { mixed, ruleIds } from "./rule-fixtures.ts";

// The checksum validators, and the reserved-range checks. Each answers a
// question about one value and nothing else, so each is tested directly rather
// than through a scan.

// ── luhn ──────────────────────────────────────────────────────────────────────

describe("luhn", () => {
  it("passes a valid Visa number", () => {
    expect(luhn("4532015112830366")).toBe(true);
  });

  it("passes a valid Mastercard number", () => {
    expect(luhn("5500005555555559")).toBe(true);
  });

  it("fails an invalid number", () => {
    expect(luhn("1234567890123456")).toBe(false);
  });

  it("ignores spaces and dashes", () => {
    expect(luhn("4532 0151 1283 0366")).toBe(true);
    expect(luhn("4532-0151-1283-0366")).toBe(true);
  });

  it("fails empty or digit-less input", () => {
    expect(luhn("")).toBe(false);
    expect(luhn("no-digits-here")).toBe(false);
  });
});

// ── National ID checksum validators ───────────────────────────────────────────

describe("validateMyNumber", () => {
  it("passes a valid My Number", () => {
    expect(validateMyNumber("123456789018")).toBe(true);
  });

  it("fails an incorrect check digit", () => {
    expect(validateMyNumber("123456789019")).toBe(false);
  });

  it("fails a wrong length", () => {
    expect(validateMyNumber("12345678901")).toBe(false);
    expect(validateMyNumber("1234567890123")).toBe(false);
  });
});

describe("validateFrenchNIR", () => {
  it("passes a valid NIR", () => {
    expect(validateFrenchNIR("123456789012311")).toBe(true);
  });

  it("fails an incorrect check key", () => {
    expect(validateFrenchNIR("123456789012399")).toBe(false);
  });

  it("fails a wrong length", () => {
    expect(validateFrenchNIR("1234567890123")).toBe(false);
  });

  it("passes a valid NIR with Corsica 2A", () => {
    expect(validateFrenchNIR("188022A12345632")).toBe(true);
  });

  it("passes a valid NIR with Corsica 2B", () => {
    expect(validateFrenchNIR("188022B12345659")).toBe(true);
  });
});

describe("validateCodiceFiscale", () => {
  it("passes a valid Codice Fiscale", () => {
    expect(validateCodiceFiscale("RSSMRA85M01H501Q")).toBe(true);
  });

  it("fails an incorrect control character", () => {
    expect(validateCodiceFiscale("RSSMRA85M01H501Z")).toBe(false);
  });

  it("fails a wrong shape", () => {
    expect(validateCodiceFiscale("RSSMRA85M01H501")).toBe(false);
  });
});

describe("validateGermanIdNr", () => {
  it("passes a valid Steuer-IdNr.", () => {
    expect(validateGermanIdNr("12345678903")).toBe(true);
  });

  it("fails an incorrect check digit", () => {
    expect(validateGermanIdNr("12345678900")).toBe(false);
  });

  it("fails when the first digit is 0", () => {
    expect(validateGermanIdNr("02345678903")).toBe(false);
  });
});

describe("validateSpanishNIF", () => {
  it("passes a valid DNI", () => {
    expect(validateSpanishNIF("12345678Z")).toBe(true);
  });

  it("fails an incorrect DNI control letter", () => {
    expect(validateSpanishNIF("12345678Y")).toBe(false);
  });

  it("passes a valid NIE", () => {
    expect(validateSpanishNIF("X1234567L")).toBe(true);
  });

  it("fails an incorrect NIE control letter", () => {
    expect(validateSpanishNIF("X1234567M")).toBe(false);
  });
});

// D.M. 23 dicembre 1976 art. 6: when two people would share the first fifteen
// characters, digits are replaced from the right with 0=L 1=M 2=N 3=P 4=Q 5=R
// 6=S 7=T 8=U 9=V. Every such code belongs to a real person, and the rule
// required digits at exactly the positions that get replaced.
describe("codice fiscale omocodia", () => {
  it.each([
    ["RSSMRA85T10A562S", "no substitution"],
    ["RSSMRA85T10A56NH", "one, from the right"],
    ["RSSMRA85T10ARSNO", "three"],
    ["RSSMRAURTMLARSNL", "all seven"],
  ])("%s is a codice fiscale (%s)", (code) => {
    expect(ruleIds(`CF ${code}`)).toContain("pii-codice-fiscale-it");
  });

  // Widening those positions to letters lets ordinary upper-case text reach the
  // pattern; the check character is what keeps it quiet.
  it.each(["MAXBUFFERSIZELIM", "CONTENTSECURITYPO", "SHELLKEYWORDTOKEN"])(
    "%s is not one",
    (word) => {
      expect(ruleIds(word)).not.toContain("pii-codice-fiscale-it");
    },
  );
});

// The shipped rules, written out.
//
// This is the largest table in the product and had neither an equality nor a
// case per entry. Measured: deleting `mapbox-token` and `sentry-org-token` whole
// left the suite green — 1,459 cases instead of 1,467, because the only thing
// walking the rules is the timing matrix, and a rule that matches nothing passes
// all eight of its shapes. A rule silently dropped from a release is the worst
// version of that.
// The boundary between a reserved range and a public address. One public case
// (`8.8.8.8`) left the 224 edge free to move: at 200 the whole 200–223 block
// stops being PII.
describe("the reserved IPv4 boundary", () => {
  it.each(["223.255.255.255", "199.0.0.1", "126.0.0.1"])(
    "%s is public",
    (ip) => {
      expect(isReservedIpv4(ip)).toBe(false);
    },
  );

  it.each(["224.0.0.1", "239.255.255.255", "240.0.0.1", "127.0.0.1"])(
    "%s is reserved",
    (ip) => {
      expect(isReservedIpv4(ip)).toBe(true);
    },
  );
});

// ── Korean / Chinese ID validators ────────────────────────────────────────────

describe("validateKoreanRRN", () => {
  it("passes a valid RRN", () => {
    expect(validateKoreanRRN("8001011000008")).toBe(true);
  });

  it("fails an incorrect check digit", () => {
    expect(validateKoreanRRN("8001011000009")).toBe(false);
  });

  it("fails a wrong length", () => {
    expect(validateKoreanRRN("800101100000")).toBe(false);
  });
});

describe("validateKoreanBRN", () => {
  it("passes a valid BRN", () => {
    expect(validateKoreanBRN("1348672612")).toBe(true);
  });

  it("fails an incorrect check digit", () => {
    expect(validateKoreanBRN("1348672610")).toBe(false);
  });

  it("fails a wrong length", () => {
    expect(validateKoreanBRN("134867261")).toBe(false);
  });
});

describe("validateChineseID", () => {
  it("passes a valid Resident Identity Card", () => {
    expect(validateChineseID("110102199001010011")).toBe(true);
  });

  it("fails an incorrect check digit", () => {
    expect(validateChineseID("110102199001010010")).toBe(false);
  });

  it("fails a wrong length", () => {
    expect(validateChineseID("11010219900101001")).toBe(false);
  });
});

// ── IP reserved-range checks ──────────────────────────────────────────────────

describe("isReservedIpv4", () => {
  it("returns false for a public IP", () => {
    expect(isReservedIpv4("8.8.8.8")).toBe(false);
  });

  it("returns true for private ranges", () => {
    expect(isReservedIpv4("192.168.1.1")).toBe(true);
    expect(isReservedIpv4("10.0.0.1")).toBe(true);
    expect(isReservedIpv4("172.16.0.1")).toBe(true);
  });

  it("returns true for TEST-NET addresses", () => {
    expect(isReservedIpv4("192.0.2.1")).toBe(true);
    expect(isReservedIpv4("203.0.113.1")).toBe(true);
  });

  it("returns true for loopback and link-local", () => {
    expect(isReservedIpv4("127.0.0.1")).toBe(true);
    expect(isReservedIpv4("169.254.1.1")).toBe(true);
  });

  it("returns true for partially-numeric octets", () => {
    expect(isReservedIpv4("1a.2.3.4")).toBe(true);
    expect(isReservedIpv4("8.8.8.8x")).toBe(true);
    expect(isReservedIpv4("1.2.3.4 ")).toBe(true);
  });

  it("returns true for other RFC 6890 special-purpose ranges", () => {
    expect(isReservedIpv4("192.0.0.1")).toBe(true); // IETF protocol assignments
    expect(isReservedIpv4("192.88.99.1")).toBe(true); // 6to4 relay anycast
  });
});

describe("isReservedIpv6", () => {
  it("returns false for a public IPv6", () => {
    expect(isReservedIpv6("2001:4860:4860::8888")).toBe(false);
  });

  it("returns true for loopback", () => {
    expect(isReservedIpv6("::1")).toBe(true);
  });

  it("returns true for fully-expanded loopback", () => {
    expect(isReservedIpv6("0:0:0:0:0:0:0:1")).toBe(true);
  });

  it("returns true for fully-expanded unspecified", () => {
    expect(isReservedIpv6("0:0:0:0:0:0:0:0")).toBe(true);
  });

  it("returns true for compressed unspecified", () => {
    expect(isReservedIpv6("::")).toBe(true);
  });

  it("returns true for link-local", () => {
    expect(isReservedIpv6("fe80::1")).toBe(true);
  });

  it("returns true for fully-expanded link-local", () => {
    expect(isReservedIpv6("fe80:0:0:0:0:0:0:1")).toBe(true);
  });

  it("returns true for unique-local", () => {
    expect(isReservedIpv6("fd00::1")).toBe(true);
  });

  it("returns true for multicast", () => {
    expect(isReservedIpv6("ff02::1")).toBe(true);
  });

  it("returns true for documentation addresses", () => {
    expect(isReservedIpv6("2001:db8::1")).toBe(true);
  });

  it("returns true for groups with non-hex trailing characters", () => {
    expect(isReservedIpv6("abcdZ::1")).toBe(true);
    expect(isReservedIpv6("2001:4860:4860::8888g")).toBe(true);
  });

  it("returns true for groups longer than 4 hex digits", () => {
    expect(isReservedIpv6("12345::1")).toBe(true);
  });

  it("returns true when :: compresses zero groups", () => {
    // RFC 4291 §2.2: "::" must compress at least one 16-bit group.
    expect(isReservedIpv6("1:2:3:4:5:6:7::8")).toBe(true);
  });
});

// ── password-like ─────────────────────────────────────────────────────────────

// Each condition is tested on its own: a value that fails only that condition
// is refused, and the other conditions are satisfied by it.
describe("isPasswordLike", () => {
  it.each(["hunter2!x", "V1m*23zdFGB", "S4Kv&DEu0GBmb", "Salt_lVi9UMB45"])(
    "%s is a password",
    (value) => {
      expect(isPasswordLike(value)).toBe(true);
    },
  );

  // The length bounds: six is the shortest and 128 the longest.
  it("the length is six to 128", () => {
    expect(isPasswordLike("abc1!")).toBe(false);
    expect(isPasswordLike("abc12!")).toBe(true);
    expect(isPasswordLike(`a1${"b".repeat(126)}`)).toBe(true);
    expect(isPasswordLike(`a1${"b".repeat(127)}`)).toBe(false);
  });

  it("no whitespace", () => {
    expect(isPasswordLike("hunter 2!x")).toBe(false);
    expect(isPasswordLike("hunter\t2!x")).toBe(false);
  });

  // A letter, and a digit or a symbol beside it. Each half is refused alone.
  it("needs a letter", () => {
    expect(isPasswordLike("123456!!")).toBe(false);
  });

  it("needs a digit or a symbol", () => {
    expect(isPasswordLike("abcdefgh")).toBe(false);
    expect(isPasswordLike("ABCDEFGH")).toBe(false);
  });

  // A reference, a slot, a flag, a path, or a tool's mask, not a value.
  it.each([
    ["$HOME1x", "a shell variable"],
    ["%VAR%ab1", "a Windows variable"],
    ["<token>1a", "a slot"],
    ["{token}1a", "a brace"],
    ["-password1", "a flag"],
    ["/etc/key1a", "a path"],
    ["~/key1abc", "a home path"],
  ])("%s is not a password (%s)", (value) => {
    expect(isPasswordLike(value)).toBe(false);
  });

  it("a value of only asterisks is a mask", () => {
    expect(isPasswordLike("********")).toBe(false);
  });

  it("asterisks with a letter and a digit are not a mask", () => {
    expect(isPasswordLike("**a1xy")).toBe(true);
  });
});

// ── basic-credentials ─────────────────────────────────────────────────────────

describe("isBasicCredentials", () => {
  it("decodes to user:password", () => {
    // svc_billing:6MzX9nEW+T+LLc=
    expect(isBasicCredentials("c3ZjX2JpbGxpbmc6Nk16WDluRVcrVCtMTGM=")).toBe(
      true,
    );
  });

  // Each refusal on its own: a colon is required, the user and the password are
  // both non-empty, and the bytes are printable UTF-8.
  it.each([
    ["dXNlcg==", "no colon: user"],
    ["OnBhc3M=", "an empty user"],
    ["dXNlcjo=", "an empty password"],
    ["/w==", "bytes that are not UTF-8"],
    ["dQE6cA==", "a control character, u 0x01 : p"],
  ])("%s is refused (%s)", (value) => {
    expect(isBasicCredentials(value)).toBe(false);
  });

  // Base64 must be a whole number of four-character groups with the right
  // padding; a lenient decoder would read the unpadded form anyway.
  it("the length must be a multiple of four", () => {
    expect(isBasicCredentials("c3ZjX2JpbGxpbmc6Nk16WDluRVcrVCtMTGM")).toBe(
      false,
    );
  });

  it("characters outside the base64 alphabet are refused", () => {
    expect(isBasicCredentials("c3Zj X2Jp")).toBe(false);
    expect(isBasicCredentials("c3ZjX2!p")).toBe(false);
  });
});

// ── iban ──────────────────────────────────────────────────────────────────────

describe("isIban", () => {
  it.each([
    ["DE89370400440532013000", "German"],
    ["DE89 3704 0044 0532 0130 00", "German, with spaces"],
    ["GB82WEST12345698765432", "British"],
    ["AE92070331234567890123456", "a country not in the table, length 25"],
    ["IL170108000000012612345", "a country not in the table, length 23"],
  ])("%s is an IBAN (%s)", (value) => {
    expect(isIban(value)).toBe(true);
  });

  // The check digits are the two after the country code. Changing either one
  // leaves the remainder at something other than one.
  it("a changed check digit is refused", () => {
    expect(isIban("DE88370400440532013000")).toBe(false);
    expect(isIban("DE99370400440532013000")).toBe(false);
  });

  // The table: Germany is 22 characters. One under and one over are both
  // refused even when the check digits would pass.
  it("a country with a fixed length must have that length", () => {
    expect(isIban("DE8937040044053201300")).toBe(false);
    expect(isIban("DE893704004405320130001")).toBe(false);
  });

  // A country not in the table is held only to the general range of fifteen to
  // thirty-four characters.
  it("a country not in the table is held to fifteen to thirty-four", () => {
    // Fourteen characters is under the range, whatever the check digits say.
    expect(isIban(`IL00${"1".repeat(10)}`)).toBe(false);
    // Thirty-five is over it.
    expect(isIban(`IL00${"1".repeat(31)}`)).toBe(false);
  });

  it("lower case and punctuation are refused", () => {
    expect(isIban("de89370400440532013000")).toBe(false);
    expect(isIban("DE89-3704-0044-0532-0130-00")).toBe(false);
  });
});

// ── phone-intl ────────────────────────────────────────────────────────────────

describe("isIntlPhone", () => {
  it("nine to fifteen digits, not all the same", () => {
    expect(isIntlPhone("+4 12345678")).toBe(true); // nine
    expect(isIntlPhone("+49 1234567890123")).toBe(true); // fifteen
    expect(isIntlPhone("+4 1234567")).toBe(false); // eight
    expect(isIntlPhone("+49 12345678901234")).toBe(false); // sixteen
  });

  it("every digit the same is a placeholder", () => {
    expect(isIntlPhone("+11 111 111 111")).toBe(false);
    expect(isIntlPhone("+00 0000 0000")).toBe(false);
  });

  it("only the digits count", () => {
    expect(isIntlPhone("+49 (151) 852-80948")).toBe(true);
  });
});

// ── nino-uk ───────────────────────────────────────────────────────────────────

describe("isNinoUk", () => {
  it.each(["RE 62 91 56 A", "CS 45 74 46 B", "AB 12 34 56 C"])(
    "%s is a National Insurance number",
    (value) => {
      expect(isNinoUk(value)).toBe(true);
    },
  );

  it.each([
    ["DA 12 34 56 A", "first letter D"],
    ["FA 12 34 56 A", "first letter F"],
    ["IA 12 34 56 A", "first letter I"],
    ["QA 12 34 56 A", "first letter Q"],
    ["UA 12 34 56 A", "first letter U"],
    ["VA 12 34 56 A", "first letter V"],
    ["RD 12 34 56 A", "second letter D"],
    ["RF 12 34 56 A", "second letter F"],
    ["RI 12 34 56 A", "second letter I"],
    ["RO 12 34 56 A", "second letter O"],
    ["RQ 12 34 56 A", "second letter Q"],
    ["RU 12 34 56 A", "second letter U"],
    ["RV 12 34 56 A", "second letter V"],
    ["BG 12 34 56 A", "prefix BG"],
    ["GB 12 34 56 A", "prefix GB"],
    ["KN 12 34 56 A", "prefix KN"],
    ["NK 12 34 56 A", "prefix NK"],
    ["NT 12 34 56 A", "prefix NT"],
    ["TN 12 34 56 A", "prefix TN"],
    ["ZZ 12 34 56 A", "prefix ZZ"],
  ])("%s is refused (%s)", (value) => {
    expect(isNinoUk(value)).toBe(false);
  });

  // The prefix is refused whole: a pair that merely starts with a reserved
  // letter is not one of the reserved pairs.
  it("a prefix that starts with a reserved letter is not refused for it", () => {
    expect(isNinoUk("BA 12 34 56 A")).toBe(true);
    expect(isNinoUk("GA 12 34 56 A")).toBe(true);
  });

  it("the digit count is six", () => {
    expect(isNinoUk("RE 62 91 5 A")).toBe(false);
    expect(isNinoUk("RE 62 91 567 A")).toBe(false);
  });
});

// ── phone-us ──────────────────────────────────────────────────────────────────

describe("isUsPhone", () => {
  it.each(["(415) 867-5309", "(212) 555-0300", "+1 212 555 0300"])(
    "%s is a phone number",
    (value) => {
      expect(isUsPhone(value)).toBe(true);
    },
  );

  it.each([
    ["(555) 867-5309", "area code 555"],
    ["(212) 555-0100", "fiction range, first line"],
    ["(212) 555-0199", "fiction range, last line"],
    ["(212) 555-1212", "directory assistance"],
    ["1-800-555-1212", "toll-free 800"],
    ["(888) 123-4567", "toll-free 888"],
    ["(877) 123-4567", "toll-free 877"],
    ["(866) 123-4567", "toll-free 866"],
    ["(855) 123-4567", "toll-free 855"],
    ["(844) 123-4567", "toll-free 844"],
  ])("%s is refused (%s)", (value) => {
    expect(isUsPhone(value)).toBe(false);
  });

  // The fiction range is 0100 to 0199 and the exchange has to be 555. Outside
  // either bound the number is an ordinary one.
  it("the fiction range is 0100 to 0199 in the 555 exchange only", () => {
    expect(isUsPhone("(212) 555-0200")).toBe(true);
    expect(isUsPhone("(212) 556-0150")).toBe(true);
  });
});

// ── personal-mailbox ──────────────────────────────────────────────────────────

describe("isPersonalMailbox", () => {
  it.each([
    ["support@acmecorp.io", false],
    ["Support@acmecorp.io", false],
    ["NO-REPLY@acmecorp.io", false],
    ["support%40acmecorp.io", false],
    ["john.support@acmecorp.io", true],
    ["support2@acmecorp.io", true],
    ["ada@analytical-engines.org", true],
  ])("%s is personal: %s", (address, personal) => {
    expect(isPersonalMailbox(address)).toBe(personal);
  });
});

// ── aws-secret-shape ──────────────────────────────────────────────────────────

describe("hasAwsSecretShape", () => {
  it("needs an upper case letter, a lower case letter and a digit", () => {
    expect(hasAwsSecretShape("wJ4rXUt0nFEM9K7MDENG2bPxRfiCYqZ8nMLVAa3D")).toBe(
      true,
    );
    expect(hasAwsSecretShape("wj4rxut0nfem9k7mdeng2bpxrficyqz8nmlvaa3d")).toBe(
      false,
    );
    expect(hasAwsSecretShape("WJ4RXUT0NFEM9K7MDENG2BPXRFICYQZ8NMLVAA3D")).toBe(
      false,
    );
    expect(hasAwsSecretShape("wJrXUtnFEMIKMDENGbPxRfiCYqZnMLVAaD")).toBe(false);
  });

  // A git commit id is lower case hex: it has digits and lower case letters,
  // and no upper case letter, so it is refused.
  it("a lower case hex digest is refused", () => {
    expect(hasAwsSecretShape("0123456789abcdef0123456789abcdef01234567")).toBe(
      false,
    );
  });

  it("a random mixed value is accepted", () => {
    expect(hasAwsSecretShape(mixed(40))).toBe(true);
  });
});

// ── the card numbers Stripe publishes ─────────────────────────────────────────

describe("isRealCardNumber and the published test cards", () => {
  it.each([
    "4242424242424242",
    "4000000000000002",
    "2223003122003222",
    "36227206271667",
    "6200000000000005",
  ])("%s is test data, not a real card", (number) => {
    expect(isRealCardNumber(number)).toBe(false);
  });

  it("a Luhn-valid number outside the list is a real card", () => {
    expect(isRealCardNumber("2221000000000009")).toBe(true);
  });

  // The list is compared on digits, so the spacing a card is printed with does
  // not get a published test card past it as a real one.
  it("the list is compared on digits, not as printed", () => {
    expect(isRealCardNumber("4000 0000 0000 0002")).toBe(false);
  });
});

// A quoted value reaches the check with its quotes. The check reads the value
// inside them, so a quoted `$VAR` is still a reference and a quoted password is
// still a password.
describe("isPasswordLike with its quotes", () => {
  it.each(['"Summer2024!"', "'Summer2024!'"])("%s is a password", (value) => {
    expect(isPasswordLike(value)).toBe(true);
  });

  it.each([
    ['"$MYSQL_ROOT_PASSWORD"', "a quoted shell reference"],
    ['"*****"', "a quoted mask"],
  ])("%s is not a password (%s)", (value) => {
    expect(isPasswordLike(value)).toBe(false);
  });
});

// The credentials every tutorial uses. Both halves have to be on the list.
describe("isBasicCredentials and the documented pairs", () => {
  it.each([
    ["dXNlcjpwYXNz", "user:pass"],
    ["YWRtaW46cGFzc3dvcmQ=", "admin:password"],
    ["cm9vdDp0ZXN0", "root:test"],
  ])("%s is a documented example (%s)", (value) => {
    expect(isBasicCredentials(value)).toBe(false);
  });

  it.each([
    [
      "YWRtaW46WGs5bVAycVI3dg==",
      "admin:Xk9mP2qR7v, the password is not listed",
    ],
    ["cm9vdDpYazltUDJxUjd2", "root:Xk9mP2qR7v, the same"],
  ])("%s is a credential (%s)", (value) => {
    expect(isBasicCredentials(value)).toBe(true);
  });
});

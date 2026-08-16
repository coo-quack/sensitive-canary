import { describe, expect, it } from "vitest";
import {
  isReservedIpv4,
  isReservedIpv6,
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
import { ruleIds } from "./rule-fixtures.ts";

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

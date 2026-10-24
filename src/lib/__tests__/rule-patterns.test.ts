import { describe, expect, it } from "vitest";
import { scan } from "../rules.ts";
import {
  AWS_KEY,
  DEFAULT_RULES,
  DOCKER_PAT,
  hex,
  mixed,
  ruleIds,
} from "./rule-fixtures.ts";

// What the shipped patterns match, at the edges of what they claim to. Every
// rule has one example and the suite runs it; an example sits in the middle of
// its range, so the cases here are the ones an example cannot reach — a length
// one over the guess, a range's last prefix, a grouping nobody thought of.

describe("numbers that are not people", () => {
  it.each([
    ["000000000000", "twelve zeros"],
    ["checksum 000000000000 ok", "twelve zeros in a sentence"],
    ["111111111111", "twelve ones"],
  ])("%s is not a My Number (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-mynumber-jp");
  });

  it("a real My Number still is one", () => {
    expect(ruleIds("My Number: 123456789018")).toContain("pii-mynumber-jp");
  });

  it.each([
    ["01-02-2024", "a date"],
    ["09-15-2025", "another date"],
    ["build 0000 0000 0000", "a zero-padded id"],
    ["0120-123-4567", "a freephone number, which belongs to a business"],
  ])("%s is not a Japanese telephone number (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-phone-jp");
  });

  it.each(["090-1234-5678", "03-1234-5678", "080 1234 5678"])(
    "%s still is one",
    (line) => {
      expect(ruleIds(line)).toContain("pii-phone-jp");
    },
  );
});

// A label is what says a date or a number belongs to a person. Each table below
// is a label with the values it must reach, and the near misses it must not.
describe("a date of birth after a label", () => {
  it.each([
    ["DOB: 1990-05-06", "ISO after DOB"],
    ["D.O.B. 05/04/1991", "dotted label, day first"],
    ["dob 18.07.1961", "lower case, dot form"],
    ["Date of birth (form B): 03/01/1990", "a label with words after it"],
    ["date of birth: 2 Apr 1978", "English day and abbreviated month"],
    ["DOB on file: 15 Apr 1968", "words between the label and the date"],
    ["Birthdate: March 27, 1973", "month name first"],
    ['"dob": "1986-12-20"', "JSON key"],
    ["DOB 24 Oct 1983", "no punctuation after the label"],
    ["生年月日 1988年7月21日", "生年月日 with a western year"],
    ["生年月日：昭和63年7月21日", "生年月日 with a Showa year"],
    ["誕生日は平成元年1月1日", "誕生日 with 元 as the first year"],
    ["生年月日 1988/07/21", "生年月日 with a slash date"],
    ["DOB S63.7.21", "one-letter era form"],
    ["DOB: 1990-05-06T00:00:00", "a timestamp after the date does not hide it"],
    ["生年月日 一九八八年七月二十一日", "a western year written in kanji"],
    ["生年月日：昭和五十年十二月三日", "kanji numerals in an era date"],
    ["date_of_birth: 2 Apr 1978", "snake_case label"],
    ["birth-date: 1984-09-30", "kebab-case label"],
    ['"date_of_birth": "1994-02-17"', "JSON key in snake_case"],
    ["dateOfBirth: 1990-05-06", "camelCase label"],
    ["birthDate: 1990-05-06", "camelCase label"],
  ])("%s is found (%s)", (line) => {
    expect(ruleIds(line)).toContain("pii-date-of-birth");
  });

  it.each([
    ["2024-01-15 release notes", "a date with no label"],
    ["version 1.2.3", "a version"],
    ["DOB 01/01/1970 is a placeholder", "the epoch default"],
    ["DOB: 1900-01-01", "the 1900 default"],
    ["(id, full_name, dob) VALUES", "a column name with no date"],
    ["lack DOB.", "dob inside a word"],
    ["subdob: 1990-05-06", "a letter before dob, so it is inside a word"],
    ["adobe reader 2024-01-01", "dob inside a longer word"],
    ["dob = new Date(1990, 0, 1)", "a constructor, not a date literal"],
    ["DOB: 1990-05-061", "one digit too many"],
    ["DOB 32/13/1990", "no such day or month"],
    ["DOB 30/02/1990", "no such day"],
    ["DOB 2099-01-01", "a future date"],
    ["birthday party on 2026-11-02", "birthday is not a label"],
    ["order date 2024-03-01", "date is not a label"],
    ["DOB 90/05/06", "a two-digit year is not covered"],
    [
      "誕生日おめでとう！2024年1月1日",
      "a ! ends the label's reach before the date",
    ],
    [
      "誕生日会は2026年11月14日（土）13時から",
      "誕生日会 is a party, and the date is the party's",
    ],
  ])("%s is not found (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-date-of-birth");
  });
});

describe("a member, customer or account number after a label", () => {
  it.each([
    ["会員番号：ABC-12345678", "会員番号 with a full-width colon"],
    ["顧客番号 0001234567", "顧客番号 with digits"],
    ["お客様番号は 0001234567 です", "お客様番号 with は before the value"],
    ["customer ID 12345", "five characters is the minimum"],
    ["customer_id: 100042", "snake case"],
    ["customerId = 100042", "camel case with an equals sign"],
    ["member ID POL-WCYAPQ2N4FY", "a value with letters and digits"],
    ["membership number: MBR-2GZ5R6DH", "membership number"],
    ["My account number is AC-924089.", "a full stop after the value"],
    ['"customer_id": "C-0001234"', "JSON key and value"],
    ["Member No. 12345678", "No. label"],
    ["account no: 1234567890", "account no"],
    ['{member_id: "0000000070172001"}', "a brace before the label"],
    ["user.customer_id = 100042", "a dot before the label"],
    [
      "member id: 5a2493c33c95a1281836eb6a",
      "a value of twenty-four characters",
    ],
    ["会員番号MBR-3PW8D6YT", "a Japanese label with no boundary after it"],
    ["会員番号：１２３４５６７８", "full-width digits"],
    ["口座番号 1234567", "口座番号 is a label"],
  ])("%s is found (%s)", (line) => {
    expect(ruleIds(line)).toContain("pii-customer-number");
  });

  it.each([
    ["order number 12345678", "order number is not a label the rule knows"],
    ["customerIdx 12345", "an English label needs a boundary after it"],
    [
      "customer id: ABCDEFGHIJKLMNOPQRSTUVW12",
      "a run of twenty-five characters is not a value",
    ],
    [
      "customer id: a1b2c3d4e5f6g7h8i9j0k1l2m",
      "a run of twenty-five characters is not a value",
    ],
    ["customer_id = 1000", "four characters is below the minimum of five"],
    ["customer_id IN (10001, 10002)", "a SQL list, not a value"],
    ["customer_id: integer", "a type, with no digits"],
    ["customerId: ${id}", "an interpolation"],
    [
      "account ID 123456789012",
      "account ID is an infrastructure term and is not covered",
    ],
    ["account_number_length = 10", "a variable name, not a value"],
    ["customer count 12345", "count is not a label"],
    ["accountNumber.length", "a property access"],
    ["member of the team since 2024", "member is a word, not a label"],
    ["version 1.2.3", "a version"],
    ["customer id: abcdef", "no digit in the value"],
    ["customer id: A1", "too short"],
    [
      'organization_membership_id: "2c159c8f5eecbb28c233367b"',
      "a membership record's key, not a member's number: the label is the tail of a longer key",
    ],
    ['cap_member_id: "CAP990000092"', "the label is the tail of a longer key"],
    [
      "billing_customer_id: 100042",
      "the label is the tail of a longer key; a foreign key is not a member's number",
    ],
  ])("%s is not found (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-customer-number");
  });
});

// The six localized date-of-birth rules. Each has its own label list, its own
// month names and the numeric forms, so each table below is one language: the
// labels it must reach and the near misses it must not. A value is checked
// where the capture is what matters.
const capturedBy = (line: string, ruleId: string): string | undefined =>
  scan(line).find((f) => f.ruleId === ruleId)?.secretValue;

describe("a date of birth after a German label", () => {
  it.each([
    ["Geburtsdatum: 12.03.1985", "dot form"],
    ["Geb.-Datum 12. März 1985", "abbreviated label, written month"],
    ["geb. am 1. Maerz 1985", "unaccented month"],
    ["geb. 12.03.1985", "short label, date at once"],
    ["geboren am 3. Mrz. 1985", "DIN abbreviation of März"],
    ["GEBURTSDATUM 1985-03-12", "upper case, ISO"],
    ["geburts_datum = '1985-03-12'", "snake_case"],
    ['"geburtsdatum": "1985/03/12"', "JSON key"],
    ["Geb.Dat.: 12.3.1985", "no padding"],
    ["user_geburtsdatum: 1985-03-12", "underscore before the label"],
    ["Geb.: 15.10.1983", "abbreviation with a colon"],
  ])("%s is found (%s)", (line) => {
    expect(ruleIds(line)).toContain("pii-date-of-birth-de");
  });

  it("the captured value is the date", () => {
    expect(capturedBy("Geburtsdatum: 12.03.1985", "pii-date-of-birth-de")).toBe(
      "12.03.1985",
    );
    expect(capturedBy("Geb.-Datum 12. März 1985", "pii-date-of-birth-de")).toBe(
      "12. März 1985",
    );
  });

  it.each([
    [
      "Anna Vogt, geb. Schmidt, Mitglied seit 2020-01-01",
      "geb. is a maiden name here, and the date is not at once",
    ],
    ["Geburtstag am 12.03.2026", "an event"],
    ["Geburtstagsfeier 12.03.2026", "a party"],
    ["kundeGeburtsdatum: 1985-03-12", "a letter before the label"],
    ["Geburtsdatum: 12 March 1985", "English month, not this rule's language"],
    ["Geburtsdatum 01.01.1970", "the epoch default"],
    ["Geburtsdatum: 1900-01-01", "the 1900 default"],
    ["Geburtsdatum 12.03.2099", "a future date"],
    ["Geburtsdatum 31.02.1985", "no such day"],
    ["Geburtsdatum v1.2.3", "a version"],
    ["Geburtsdatum 12.03.85", "a two-digit year is not covered"],
    [
      "Geburtsdaten vom 12.03.2024 geprüft",
      "plural runs into the letter boundary",
    ],
  ])("%s is not found (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-date-of-birth-de");
  });
});

describe("a date of birth after a French label", () => {
  it.each([
    ["Date de naissance : 12/03/1985", "slash form, space before the colon"],
    ["né(e) le 1er mars 1985", "ordinal day"],
    ["Née le 12 janv. 1985", "feminine, abbreviated month"],
    ["né le 12 décembre 1985", "accented month"],
    ["NÉ LE 12/03/1985", "upper case"],
    ["date_de_naissance: 1985-03-12", "snake_case"],
    ['dateDeNaissance = "12.03.1985"', "camelCase"],
    ["DDN: 1985-03-12", "abbreviation"],
    ['"date de naissance": "12-03-1985"', "JSON key"],
    ["né le 1er août 1985", "accented August"],
    ["date_naissance: 1964-09-05", "snake_case without de"],
  ])("%s is found (%s)", (line) => {
    expect(ruleIds(line)).toContain("pii-date-of-birth-fr");
  });

  it("the captured value is the date, the day with its ordinal included", () => {
    expect(capturedBy("né(e) le 1er mars 1985", "pii-date-of-birth-fr")).toBe(
      "1er mars 1985",
    );
  });

  it.each([
    ["ne le fais pas avant le 12/03/2024", "unaccented ne le is the negation"],
    ["naissance du projet le 12/03/2024", "naissance alone names any birth"],
    ["date de naissance : 01/01/1970", "the epoch default"],
    ["DDN 1900-01-01", "the 1900 default"],
    ["date de naissance 12/03/2099", "a future date"],
    ["date de naissance 30/02/1985", "no such day"],
    ["anniversaire le 12/03/2026", "an event"],
    ["date de naissance: March 12, 1985", "English month"],
    ["maddn: 1985-03-12", "a letter before ddn, so it is inside a word"],
    ["date de naissance 12/03/85", "a two-digit year"],
    ["release notes 2024-01-15", "a date with no label"],
  ])("%s is not found (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-date-of-birth-fr");
  });
});

describe("a date of birth after an Italian label", () => {
  it.each([
    ["Data di nascita: 12/03/1985", "slash form"],
    ["nato a Roma il 12 marzo 1985", "place, then il and a written month"],
    ["nata il 1º marzo 1985", "feminine, ordinal day"],
    ["nato/a il 12.03.1985", "nato/a, dot form"],
    ["nata a Sesto San Giovanni il 1985-03-12", "a place with several words"],
    ["dataDiNascita: 1985-03-12", "camelCase"],
    ["data_nascita = '12/03/1985'", "snake_case"],
    ["DATA DI NASCITA 12 SETT. 1985", "upper case, abbreviated month"],
    ["nato il 31 dic 1985", "abbreviated month"],
    ["D.N.: 12 luglio 1961", "D.N. abbreviation with a written month"],
    ["DN: 15.10.1983", "DN abbreviation"],
  ])("%s is found (%s)", (line) => {
    expect(ruleIds(line)).toContain("pii-date-of-birth-it");
  });

  it("the captured value is the date, the ordinal sign included", () => {
    expect(
      capturedBy("nato a Roma il 12 marzo 1985", "pii-date-of-birth-it"),
    ).toBe("12 marzo 1985");
    expect(capturedBy("nata il 1º marzo 1985", "pii-date-of-birth-it")).toBe(
      "1º marzo 1985",
    );
  });

  it.each([
    ["la NATO il 12 marzo 2024 ha deciso", "the alliance after its article"],
    ["alla NATO il 12 marzo 2024", "the alliance after its article"],
    ["nato nel 1985", "a year is not a date"],
    ["nascita del progetto il 12/03/2024", "nascita alone"],
    ["data di nascita 01/01/1970", "the epoch default"],
    ["data di nascita: 1900-01-01", "the 1900 default"],
    ["data di nascita 12/03/2099", "a future date"],
    ["data di nascita 31/04/1985", "no such day"],
    ["compleanno il 12/03/2026", "an event"],
    ["data di nascita 12 March 1985", "English month"],
    ["nato a Milano il giorno dopo", "no date"],
    ["data di nascita 12/03/85", "a two-digit year"],
  ])("%s is not found (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-date-of-birth-it");
  });
});

describe("a date of birth after a Spanish label", () => {
  it.each([
    ["Fecha de nacimiento: 12 de marzo de 1985", "written form with de"],
    ["nacido en Madrid el 12/03/1985", "place, then el and a slash date"],
    ["nacida el 1 de enero de 1985", "feminine, written form"],
    ["nacido/a el 12-03-1985", "nacido/a, dash form"],
    [
      "F. Nac.: 12-mar-1985",
      "abbreviated label and day-month-year with dashes",
    ],
    ["fechaNacimiento = '1985-03-12'", "camelCase"],
    ["fecha_de_nacimiento: 1985/03/12", "snake_case"],
    ["FECHA NAC. 12/03/1985", "upper case abbreviation"],
    ["fecha de nacimiento 12 sept 1985", "abbreviated month"],
    ["fec. nac. 31 dic. 1985", "abbreviated label and month"],
    ["F.N.: 15.10.1983", "F.N. abbreviation with a dotted date"],
    ["nací el 3 de marzo de 1992", "first person, written form"],
  ])("%s is found (%s)", (line) => {
    expect(ruleIds(line)).toContain("pii-date-of-birth-es");
  });

  it("the captured value is the date", () => {
    expect(
      capturedBy(
        "Fecha de nacimiento: 12 de marzo de 1985",
        "pii-date-of-birth-es",
      ),
    ).toBe("12 de marzo de 1985");
    expect(capturedBy("F. Nac.: 12-mar-1985", "pii-date-of-birth-es")).toBe(
      "12-mar-1985",
    );
  });

  it.each([
    ["compré en Fnac. 12/03/2024", "the retailer is not f. nac."],
    ["nacido en 1985", "a year alone"],
    ["nacimiento del proyecto el 12/03/2024", "nacimiento alone"],
    ["fecha de nacimiento 01/01/1970", "the epoch default"],
    ["fecha de nacimiento: 1900-01-01", "the 1900 default"],
    ["fecha de nacimiento 12/03/2099", "a future date"],
    ["fecha de nacimiento 30/02/1985", "no such day"],
    ["cumpleaños el 12/03/2026", "an event"],
    ["fecha de nacimiento March 12, 1985", "English month"],
    ["fecha de nacimiento 12/03/85", "a two-digit year"],
    ["fecha de pago 12/03/2024", "another date label"],
  ])("%s is not found (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-date-of-birth-es");
  });
});

describe("a date of birth after a Chinese label", () => {
  it.each([
    ["出生日期：1985年3月12日", "full-width colon"],
    ["出生年月日 1985-03-12", "出生年月日 with a dash date"],
    ["出生于1985年3月12号", "出生于 with 号 as the day counter"],
    ["出生年月：1985/3/12", "出生年月 with a slash date"],
    ["出生日期 1985.03.12", "dot form"],
    [
      "出生日期（公历）1985年03月12日",
      "a parenthesis between the label and the date",
    ],
    ['"出生日期": "1985-03-12"', "JSON key"],
    ["出生日期为1985年3月12日", "为 between the label and the date"],
  ])("%s is found (%s)", (line) => {
    expect(ruleIds(line)).toContain("pii-date-of-birth-zh");
  });

  it("the captured value is the date, 号 included", () => {
    expect(capturedBy("出生于1985年3月12号", "pii-date-of-birth-zh")).toBe(
      "1985年3月12号",
    );
  });

  it.each([
    ["生日快乐！2026年3月12日", "生日 is not a label, and ！ ends the reach"],
    [
      "发生于2024年3月1日",
      "happened on: 生于 is inside 发生于 and is not a label",
    ],
    ["出生人口在2024年3月1日公布", "出生 alone is not a label"],
    ["出生日期 1970-01-01", "the epoch default"],
    ["出生日期：1900年1月1日", "the 1900 default"],
    ["出生日期 2099-01-01", "a future date"],
    ["出生日期 1985年2月30日", "no such day"],
    ["出生年月 1985年3月", "month only, not covered"],
    ["出生日期 85-03-12", "a two-digit year"],
    ["出生日期。2024年3月1日", "。 ends the reach"],
    ["出生日期 v1.2.3", "a version"],
  ])("%s is not found (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-date-of-birth-zh");
  });
});

describe("a date of birth after a Korean label", () => {
  it.each([
    ["생년월일은 1985년 3월 12일", "written form, after a particle"],
    ["생년월일: 1985. 3. 12.", "official numeric form"],
    ["출생일자 1985.03.12", "dot form"],
    ["생년월일 1985년3월12일", "written form without spaces"],
    ["출생연월일：1985-03-12", "a full-width colon after the label"],
    ["출생일 1985/03/12", "slash form"],
    ['"생년월일": "1985-03-12"', "JSON key"],
    ["생년월일이 1985. 03. 12.", "zero-padded official form"],
  ])("%s is found (%s)", (line) => {
    expect(ruleIds(line)).toContain("pii-date-of-birth-ko");
  });

  it("the captured value is the date, the final dot included", () => {
    expect(capturedBy("생년월일: 1985. 3. 12.", "pii-date-of-birth-ko")).toBe(
      "1985. 3. 12.",
    );
  });

  it.each([
    ["생일 파티 2026. 3. 12.", "생일 is not a label"],
    ["생년월일 1970. 1. 1.", "the epoch default"],
    ["생년월일 1900년 1월 1일", "the 1900 default"],
    ["생년월일 2099-01-01", "a future date"],
    ["생년월일 1985. 13. 12.", "no such month"],
    ["생년월일 85. 3. 12.", "a two-digit year"],
    ["발행일 2024. 3. 12.", "another date label"],
    ["생년월일! 2024년 3월 12일", "! ends the reach"],
    ["생년월일 v1.2.3", "a version"],
    ["출생률 2024. 3. 12.", "출생 alone is not a label"],
  ])("%s is not found (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-date-of-birth-ko");
  });
});

describe("a member, customer or account number after a German label", () => {
  it.each([
    ["Kundennummer: 1234567", "plain"],
    ["Kd.-Nr. KD-4471-8820", "abbreviation with a hyphen, and a dashed value"],
    [
      "Meine Mitgliedsnummer lautet M-20419",
      "lautet between the label and the value",
    ],
    ["Kto.-Nr.: 123456789", "Kontonummer abbreviated"],
    ["Kunden-Nr 10023456", "hyphen before the abbreviation"],
    ['kundennummer = "C-0001234"', "assignment in quotes"],
    ["Mitgl.-Nr. 20419", "Mitgliedsnummer abbreviated"],
    ["Kontonummer 000123456789", "bank account number"],
    ["Kunden-ID 10023456", "customer ID"],
    ["Ihre Kundennummer ist 12345", "ist between the label and the value"],
    ["kundenNr: 1234567", "camelCase"],
  ])("%s is found (%s)", (line) => {
    expect(ruleIds(line)).toContain("pii-customer-number-de");
  });

  it("the captured value is the number, the dashes included", () => {
    expect(capturedBy("Kd.-Nr. KD-4471-8820", "pii-customer-number-de")).toBe(
      "KD-4471-8820",
    );
  });

  it.each([
    ["Konto-ID 123456789", "account ID, the infrastructure sense"],
    ["billing_kundennummer: 1234567", "the tail of a longer key"],
    ["Kundennummern ab 10000", "plural runs into the letter boundary"],
    ["Kundennummer: 1000", "four characters"],
    ["Kundennummer: ABCDEF", "no digits"],
    ["Bestellnummer 12345678", "order number"],
    ["Rechnungsnummer 2024-0012", "invoice number"],
    ["Kundennummer v1.2.3", "a version"],
    ["Kundennummer: integer", "a word, not a number"],
    ["kundennummer_length = 10", "a longer key after the label"],
    ["Kundennummer: ABCDEFGHIJKLMNOPQRSTUVW12", "twenty-five characters"],
    ["Kundennummer: 00000000", "an all-zero placeholder"],
    ["Kontonummer: 0000000000000000", "an all-zero placeholder"],
  ])("%s is not found (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-customer-number-de");
  });
});

describe("a member, customer or account number after a French label", () => {
  it.each([
    ["N° client : 4471882", "abbreviated label with a degree sign"],
    ["numéro d'adhérent 20419-A", "adhérent with a dash in the value"],
    ["Numéro de compte: 00123456789", "bank account"],
    ["code client ABC-12345", "invoice vocabulary"],
    ["numero client 1002345", "unaccented"],
    ["N° d’adhérent 20419", "typographic apostrophe"],
    ["identifiant client : CL-0001234", "identifiant client"],
    ["Nº de membre 123456", "membre with the masculine ordinal sign"],
    ['numeroClient = "1002345"', "camelCase"],
    ["Mon numéro de client est 4471882", "est between the label and the value"],
    ['"numero_client": "C-0001234"', "snake_case key"],
  ])("%s is found (%s)", (line) => {
    expect(ruleIds(line)).toContain("pii-customer-number-fr");
  });

  it("the captured value is the number, the dash included", () => {
    expect(
      capturedBy("numéro d'adhérent 20419-A", "pii-customer-number-fr"),
    ).toBe("20419-A");
  });

  it.each([
    ["ID de compte 123456789012", "account ID, the infrastructure sense"],
    [
      "there is no client 12345",
      "no client without a degree sign or dot is English",
    ],
    ["organization_numero_client: 1002345", "the tail of a longer key"],
    ["numéro de commande 12345678", "order number"],
    ["numéro de facture 2024-0012", "invoice number"],
    ["numéro client: 1000", "four characters"],
    ["numéro client: abcdef", "no digits"],
    ["Numéro de compte : 0000000000000000", "an all-zero placeholder"],
    ["Nº de membre : 00000000", "an all-zero placeholder"],
    ["numéro de client v1.2.3", "a version"],
    ["référence client 12345678", "a reference names contracts and orders too"],
    ["numéro de clients 12345", "plural"],
  ])("%s is not found (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-customer-number-fr");
  });
});

describe("a member, customer or account number after an Italian label", () => {
  it.each([
    ["Numero cliente: 123456789", "plain"],
    ["n. socio 20419", "socio, abbreviated"],
    ["Cliente N. 12345678", "label with the number after it"],
    ["numero di conto 000123456", "bank account"],
    ["codice cliente CL-0001234", "invoice vocabulary"],
    ["n° tessera 20419", "membership card"],
    ["Il mio numero cliente è 123456789", "è between the label and the value"],
    ['numeroCliente = "123456789"', "camelCase"],
    ['"numero_cliente": "C-0001234"', "snake_case key"],
    ["cod. cliente 1002345", "abbreviated codice"],
  ])("%s is found (%s)", (line) => {
    expect(ruleIds(line)).toContain("pii-customer-number-it");
  });

  it.each([
    ["ID account 123456789", "account ID, the infrastructure sense"],
    ["id conto 123456789", "account ID, the infrastructure sense"],
    ["numero ordine 12345678", "order number"],
    ["numero fattura 2024-0012", "invoice number"],
    ["org_numero_cliente: 1002345", "the tail of a longer key"],
    ["numero cliente: 1000", "four characters"],
    ["numero cliente: abcdef", "no digits"],
    ["Numero socio: 00000000", "an all-zero placeholder"],
    ["Numero di conto: 0000000000000000", "an all-zero placeholder"],
    ["numero cliente v1.2.3", "a version"],
    ["numero clienti 12345", "plural"],
    ["numero di telefono 0612345678", "another number"],
  ])("%s is not found (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-customer-number-it");
  });
});

describe("a member, customer or account number after a Spanish label", () => {
  it.each([
    ["Número de cliente: 4471882", "accented"],
    ["n.º de socio/a 20419", "socio/a with the ordinal sign"],
    ["núm. cliente ES-00123", "abbreviated, with a dash in the value"],
    ["Nro. de cliente 1002345", "nro abbreviation"],
    ["número de cuenta 00123456789", "bank account"],
    ["código de cliente CL-0001234", "invoice vocabulary"],
    ["nº socio 20419", "abbreviated socio"],
    ["numero cliente 1002345", "unaccented"],
    ["Mi número de cliente es 4471882", "es between the label and the value"],
    ['numeroCliente = "4471882"', "camelCase"],
    ['"numero_de_cliente": "C-0001234"', "snake_case key with de"],
  ])("%s is found (%s)", (line) => {
    expect(ruleIds(line)).toContain("pii-customer-number-es");
  });

  it("the captured value is the number, the dash included", () => {
    expect(capturedBy("núm. cliente ES-00123", "pii-customer-number-es")).toBe(
      "ES-00123",
    );
  });

  it.each([
    ["ID de cuenta 123456789012", "account ID, the infrastructure sense"],
    ["no de cliente 12345", "no without a dot is the negation"],
    ["número de pedido 12345678", "order number"],
    ["número de factura 2024-0012", "invoice number"],
    ["org_numero_cliente: 1002345", "the tail of a longer key"],
    ["número de cliente: 1000", "four characters"],
    ["número de cliente: abcdef", "no digits"],
    ["Número de socio: 00000000", "an all-zero placeholder"],
    ["Número de cuenta: 0000000000000000", "an all-zero placeholder"],
    ["número de cliente v1.2.3", "a version"],
    ["número de clientes 12345", "plural"],
    [
      "código de cuenta 0049-1500-05-1234567890",
      "an accounting chart code, dropped",
    ],
  ])("%s is not found (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-customer-number-es");
  });
});

describe("a member, customer or account number after a Chinese label", () => {
  it.each([
    ["客户编号：10023456", "full-width colon"],
    ["客户编号：00012300", "zeros with other digits are still a number"],
    ["会员卡号 6222-0012-3456", "member card number with dashes"],
    ["会员号是 A12345", "是 between the label and the value"],
    ["客户号码：C-0001234", "客户号码"],
    ["客户号 10023456", "客户号"],
    ["会员编号MBR-20419", "no boundary after a Chinese label"],
    ["银行账号：6222001234567890", "bank account"],
    ["账户号码 000123456", "account number"],
    ["客户ID：10023456", "customer ID"],
    ['"会员编号": "１２３４５６７８"', "full-width digits"],
  ])("%s is found (%s)", (line) => {
    expect(ruleIds(line)).toContain("pii-customer-number-zh");
  });

  it("the captured value is the number, the dashes included", () => {
    expect(
      capturedBy("会员卡号 6222-0012-3456", "pii-customer-number-zh"),
    ).toBe("6222-0012-3456");
  });

  it.each([
    ["账号：alice_01", "a login account, and no two digits in a run"],
    ["账户ID 123456789", "account ID, the infrastructure sense"],
    ["用户ID 123456789", "user ID is infrastructure"],
    ["订单编号 2024031200123", "order number"],
    ["客户编号：1000", "four characters"],
    ["客户编号：ABCDEF", "no digits"],
    ["会员编号 v1.2.3", "a version"],
    ["客户数 12345", "a count"],
    ["产品编号 P-0001234", "product number"],
    ["客户编号: ABCDEFGHIJKLMNOPQRSTUVW12", "twenty-five characters"],
    ["会员号：00000000", "an all-zero placeholder"],
    ["银行账号：0000000000000000", "an all-zero placeholder"],
  ])("%s is not found (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-customer-number-zh");
  });
});

describe("a member, customer or account number after a Korean label", () => {
  it.each([
    ["고객번호: 0123456789", "plain"],
    ["회원 번호는 MBR-20419", "space in the compound, a particle after it"],
    ["계좌번호 110-123-456789", "bank account with dashes"],
    ["회원번호가 20419", "가 after the label"],
    ["고객 ID: C-0001234", "customer ID with a space"],
    ["회원ID MBR-20419", "member ID without a space"],
    ["계좌 번호: 1002345678", "bank account with a space"],
    ['"회원번호": "12345678"', "JSON key"],
    ["고객번호 １２３４５６７８", "full-width digits"],
  ])("%s is found (%s)", (line) => {
    expect(ruleIds(line)).toContain("pii-customer-number-ko");
  });

  it("the captured value is the number, the dashes included", () => {
    expect(capturedBy("회원 번호는 MBR-20419", "pii-customer-number-ko")).toBe(
      "MBR-20419",
    );
  });

  it.each([
    ["계정 ID 123456789", "login-account sense"],
    ["아이디: alice01", "a login ID"],
    ["주문번호 2024031200123", "order number"],
    ["고객번호: 1000", "four characters"],
    ["고객번호: ABCDEF", "no digits"],
    ["회원번호 v1.2.3", "a version"],
    ["고객수 12345", "a count"],
    ["사업자번호 123-45-67890", "business registration number, another rule's"],
    ["고객번호: ABCDEFGHIJKLMNOPQRSTUVW12", "twenty-five characters"],
    ["회원번호: 00000000", "an all-zero placeholder"],
    ["계좌번호: 0000000000000000", "an all-zero placeholder"],
    ["송장번호 INV-20240312", "invoice number"],
  ])("%s is not found (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-customer-number-ko");
  });
});

describe("a Japanese postal address", () => {
  it.each([
    ["東京都渋谷区神宮前5-28-11", "prefecture, ward and block with hyphens"],
    [
      "愛知県名古屋市中村区名駅4丁目3番2号グランドハイツ経堂210号室",
      "the match stops after 号, before the building",
    ],
    ["京都府京都市左京区北白川1丁目6番11号", "丁目, 番 and 号"],
    ["〒174-7567 東京都渋谷区神宮前5-28-11", "with a postal code in front"],
    ["千葉県市川市八幡2-3-4", "a city whose name contains 市"],
    ["東京都町田市原町田１−２−３", "full-width digits and minus"],
    ["北海道札幌市中央区北一条西2丁目", "a 丁目 block in Hokkaido"],
    ["大阪府大阪市北区梅田一丁目一番一号", "kanji numerals"],
    ["埼玉県さいたま市浦和区高砂3-15-1", "a city written in hiragana"],
    ["茨城県つくば市天王台1-1-1", "a city written in hiragana"],
    ["東京都千代田区霞が関1-3-1", "a town name with が"],
    ["神奈川県横浜市西区みなとみらい2-2-1", "a town name written in katakana"],
    ["福岡県糟屋郡粕屋町仲原2500-1", "a county and a town"],
    ["鹿児島県鹿児島市山下町11-1", "a prefecture whose name begins with 鹿"],
    ["愛媛県松山市一番町4-4-2", "a town name made of a kanji numeral and 番"],
  ])("%s is found (%s)", (line) => {
    expect(ruleIds(line)).toContain("pii-address-jp");
  });

  it.each([
    ["東京都", "a prefecture alone"],
    ["東京都千代田区", "a municipality alone, no block number"],
    ["神奈川県横浜市", "a city alone"],
    ["東京都渋谷区で2-3件", "a count, not a block"],
    ["東京都渋谷区で2-3の案件", "a count, not a block"],
    [
      "大阪府の人口は2024年",
      "a prefecture in a sentence with no municipality after it",
    ],
    ["東京都 2025年10月18日", "a date after a space"],
    ["北海道は1-2月が寒い", "a month, not a block"],
    ["東京都千代田区1", "a bare number without 丁目, 番, 号 or a hyphen"],
    ["東京都渋谷区神宮前5-", "a dangling hyphen"],
  ])("%s is not found (%s)", (line) => {
    expect(ruleIds(line)).not.toContain("pii-address-jp");
  });

  // The issue leaves this open: the rule reads a company's footer the way it
  // reads a person's address, and nothing in the text tells them apart. This
  // records the current behaviour, not a decision about it.
  it("a company's footer address is found, as a person's would be", () => {
    expect(
      ruleIds("株式会社ホライズン技研 本社：東京都港区虎ノ門一丁目2番3号"),
    ).toContain("pii-address-jp");
  });

  // 二番 reads as a block number, so the match stops before 町. The match is
  // shorter than the address, and it still blocks.
  it("東京都千代田区二番町5 is found as 東京都千代田区二番", () => {
    const found = scan("東京都千代田区二番町5").find(
      (f) => f.ruleId === "pii-address-jp",
    );
    expect(found?.secretValue).toBe("東京都千代田区二番");
  });
});

// A label in a table header reaches the cells under it, which a regex cannot
// do. The header is CSV, TSV, a Markdown table or a SQL INSERT column list, and
// the rows read are the ones directly under the header.
describe("a value under a labelled column", () => {
  const count = (text: string, ruleId: string): number =>
    scan(text).filter((f) => f.ruleId === ruleId).length;
  const values = (text: string, ruleId: string): string[] =>
    scan(text)
      .filter((f) => f.ruleId === ruleId)
      .map((f) => f.secretValue);

  it.each([
    [
      "name,dob,region\nLena Vogt,18.07.1961,DE-BW\nMarco Bellini,27/03/1973,IT-MI",
      "CSV, two rows",
      "pii-date-of-birth",
      2,
    ],
    [
      "name,date of birth\nAmara Okafor,1994-02-17\nYuto Hayashi,2001-11-20",
      "CSV, a label of three words",
      "pii-date-of-birth",
      2,
    ],
    [
      "| 氏名 | 生年月日 |\n|---|---|\n| 中村 れい | 1996年12月8日 |",
      "Markdown table, kanji date",
      "pii-date-of-birth",
      1,
    ],
    [
      "INSERT INTO users (id, display_name, birth_date) VALUES (1042, 'Sara Lindqvist', '1984-09-30');",
      "SQL INSERT column list",
      "pii-date-of-birth",
      1,
    ],
    [
      "INSERT INTO members (membership_number, name) VALUES ('MBR-5TR2N8WC', 'Oskar Lind'), ('MBR-7QW1X9ZK', 'Ana Ruiz');",
      "SQL INSERT, two tuples",
      "pii-customer-number",
      2,
    ],
    [
      "name,membership number,joined\nHana Sato,MBR-2GZ5R6DH,2021-04-11",
      "CSV, membership number",
      "pii-customer-number",
      1,
    ],
    [
      "| 氏名 | 顧客番号 |\n|---|---|\n| 渡辺 悠真 | C-0009921 |",
      "Markdown table, 顧客番号",
      "pii-customer-number",
      1,
    ],
    [
      "customer_number,name,tier\nC-0007710,Erika Lund,gold",
      "CSV, snake_case header",
      "pii-customer-number",
      1,
    ],
    ["id\tdob\n7\t1990-05-06", "TSV", "pii-date-of-birth", 1],
    [
      "Name,Geburtsdatum,Ort\nAnna Vogt,12.03.1985,Berlin",
      "CSV with a German header",
      "pii-date-of-birth-de",
      1,
    ],
    [
      "| 이름 | 생년월일 |\n|---|---|\n| 김서연 | 1985. 3. 12. |",
      "Markdown table with a Korean header and the official form",
      "pii-date-of-birth-ko",
      1,
    ],
    [
      "nombre,fecha de nacimiento\nLucía Ortega,12 de marzo de 1985",
      "CSV with a Spanish header and the written form",
      "pii-date-of-birth-es",
      1,
    ],
    [
      "INSERT INTO clientes (nombre, numero_client) VALUES ('Claire Petit', '4471882'), ('Léa Roux', '1002345')",
      "SQL INSERT with a French column name, two tuples",
      "pii-customer-number-fr",
      2,
    ],
    [
      "INSERT INTO cuentas (codigo_cliente, nombre) VALUES ('CUS-77130', 'Lucas Herrera')",
      "SQL INSERT with an unaccented Spanish column name",
      "pii-customer-number-es",
      1,
    ],
    [
      "姓名\t会员编号\n李华\tMBR-20419",
      "TSV with a Chinese header",
      "pii-customer-number-zh",
      1,
    ],
    [
      "Name,Kd.-Nr.\nAnna Vogt,KD-4471-8820",
      "CSV with a German abbreviated header, its dot and hyphen normalised",
      "pii-customer-number-de",
      1,
    ],
    [
      '"Name","DOB"\n"Lee, Ann","1990-05-06"',
      "quoted CSV with a comma in a cell",
      "pii-date-of-birth",
      1,
    ],
    [
      "dob,version\n2024-01-15,1.2.3",
      "a dob column is trusted: its values are read as dates",
      "pii-date-of-birth",
      1,
    ],
    [
      "D.O.B.,region\n1990-05-06,DE",
      "the trailing full stop is stripped from the header",
      "pii-date-of-birth",
      1,
    ],
    [
      "name,dob\nA|B|C,1\nTaro,1990-05-06",
      "a pipe inside a CSV cell does not end the table",
      "pii-date-of-birth",
      1,
    ],
    [
      "name,dob\nTaro\tYamada,1\nHanako,1990-05-06",
      "a tab inside a CSV cell does not end the table",
      "pii-date-of-birth",
      1,
    ],
    [
      "name,dob\n\nTaro,1990-05-06",
      "a blank line does not end the table",
      "pii-date-of-birth",
      1,
    ],
    [
      'name,dob\n"Taro\nYamada",1990-05-06',
      "a quoted CSV cell may span a newline",
      "pii-date-of-birth",
      1,
    ],
    [
      'name,dob\n"Taro ""T"" Yamada",1990-05-06',
      "an escaped quote inside a quoted cell",
      "pii-date-of-birth",
      1,
    ],
    [
      "INSERT INTO t (name, dob) VALUES ('Smith (Jr)', '1990-05-06');",
      "parentheses inside a quoted value",
      "pii-date-of-birth",
      1,
    ],
    [
      "INSERT INTO t (name, dob) VALUES ('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', '1990-05-06');",
      "a value longer than 4000 characters",
      "pii-date-of-birth",
      1,
    ],
    [
      "INSERT INTO users (id, display_name, birth_date) VALUES (1, 'Lee, Ann', '1990-05-06')",
      "a comma inside a quoted value",
      "pii-date-of-birth",
      1,
    ],
    [
      'name,dob\n"open\nTaro,1990-05-06\nHanako,1991-01-02',
      "a stray quote does not swallow the rest of the table",
      "pii-date-of-birth",
      2,
    ],
    [
      'name,dob\n"a""b",1990-05-06',
      "an escaped quote is still a quoted cell",
      "pii-date-of-birth",
      1,
    ],
  ])("%s (%s)", (text, _reason, ruleId, expected) => {
    expect(count(text, ruleId)).toBe(expected);
  });

  it("the values are the cells, and the header's own text is not one", () => {
    expect(
      values(
        "name,dob,region\nLena Vogt,18.07.1961,DE-BW\nMarco Bellini,27/03/1973,IT-MI",
        "pii-date-of-birth",
      ),
    ).toEqual(["18.07.1961", "27/03/1973"]);
  });

  it.each([
    ["name,dob,region\nLena Vogt,,DE-BW", "an empty cell"],
    ["version,released\n1.2.3,2024-01-15", "no header is a label"],
    ["name,dob\n", "a header with no rows"],
    ["| 氏名 | 生年月日 |\n|---|---|", "a separator row and no data"],
    ["dob\nhello", "one column with no comma is not a row"],
    ["INSERT INTO users (id, dob) VALUES (1, NULL)", "NULL is not a date"],
    [
      "name,dob,region\nLena Vogt,01/01/1970,DE-BW",
      "the validator refuses the 1970 placeholder",
    ],
    ["customer_id,name\n1000,Erika", "a value of four characters is too short"],
    ["member,count\nalice,12345", "member alone is not a label"],
    [
      "dob\n\n1990-05-06",
      "a blank line ends the table, so the date is on its own line",
    ],
  ])("%s is not found (%s)", (text) => {
    expect(
      scan(text).filter(
        (f) =>
          f.ruleId.startsWith("pii-date") ||
          f.ruleId.startsWith("pii-customer"),
      ),
    ).toEqual([]);
  });

  // A value that the label regex and the column pass both reach is reported
  // once. A date with no separator on its own line is not a row, so it is not
  // read from a column either.
  it("a value found by the label and by its column is reported once", () => {
    expect(count("dob: 1990-05-06", "pii-date-of-birth")).toBe(1);
    expect(
      count(
        "INSERT INTO users (id, dob) VALUES ('x', '1990-05-06')",
        "pii-date-of-birth",
      ),
    ).toBe(1);
  });

  it("a header with no delimiter is not a row, so its value is not read", () => {
    expect(count("dob\n1990-05-06", "pii-date-of-birth")).toBe(0);
  });
});

// Formats confirmed against each vendor's own documentation, after a survey
// found the rules here were written to shapes those vendors do not issue.
describe("credential formats", () => {
  // Every branch of the card rule, in both directions. Luhn gates all of them,
  // so each number below is Luhn-valid and none is published test data.
  it.each([
    ["36123456789013", "Diners, 14 digits"],
    ["6011000991300009", "Discover 6011"],
    ["6450000000000002", "Discover 644-658"],
    ["3530111333300000", "JCB 3528-3589"],
    ["2221000000000009", "Mastercard 2-series"],
    ["6221260000000000", "UnionPay 62"],
    ["8171990000000008", "UnionPay 81"],
  ])("%s is a card (%s)", (number) => {
    expect(ruleIds(`card ${number}`)).toContain("pii-credit-card");
  });

  // Discover's published range stops at 658. Treating "65" as a two-digit
  // prefix claims 659, which belongs to nobody here.
  it("659 is not a Discover range", () => {
    expect(ruleIds("card 6591111111111116")).not.toContain("pii-credit-card");
  });

  // Token rotation introduced xoxe-; xapp- is app-level; xwfp- is a workflow
  // token. The character class held only b, a, p, r and s.
  it.each(["xoxb", "xoxp", "xoxe", "xapp", "xwfp"])(
    "a Slack %s- token is found",
    (prefix) => {
      expect(ruleIds(`${prefix}-1-${mixed(40)}`)).toContain("slack-token");
    },
  );

  it.each([
    "glpat",
    "glrt",
    "gldt",
    "gloas",
    "glcbt",
    "glptt",
    "glimt",
    "glagent",
  ])("a GitLab %s- token is found", (prefix) => {
    expect(ruleIds(`${prefix}-${mixed(20)}`)).toContain("gitlab-pat");
  });

  // A restricted key has a rule of its own; widening the secret-key rule to
  // cover `rk_` too left that rule unable to fire.
  it("a restricted key is the restricted-key rule, not the secret-key one", () => {
    expect(ruleIds(`rk_live_${mixed(24)}`)).toEqual(["stripe-restricted-key"]);
  });

  it.each([
    [`sk_live_${mixed(24)}`, "a secret key"],
    [`sk_org_${mixed(24)}`, "an organization key"],
    [`whsec_${mixed(32)}`, "a webhook signing secret"],
  ])("%s is a Stripe secret (%s)", (token) => {
    expect(ruleIds(token)).toContain("stripe-secret-key");
  });

  // Mapbox documents the token as header.payload.signature where the header is
  // the literal pk, sk or tk — two dots, not three. Requiring three matched
  // nothing Mapbox issues.
  it.each(["pk", "sk", "tk"])("a Mapbox %s. token is found", (prefix) => {
    expect(ruleIds(`${prefix}.eyJ1IjoiYWJjIn0.${mixed(22)}`)).toContain(
      "mapbox-token",
    );
  });

  // sentry-cli splits the token on underscores and requires exactly three
  // parts. The rule was written for dots.
  it("a Sentry org token is underscore-separated", () => {
    expect(ruleIds(`sntrys_eyJpYXQiOjEuMH0=_${mixed(43)}`)).toContain(
      "sentry-org-token",
    );
  });
});

// A word anywhere within forty characters suppressed the address. The suppression
// belongs to the operand position: `ssh user@host` is a host, `rsync failed,
// notify alice@corp.io` is an address. The host:path forms of scp and rsync are
// already handled by the trailing colon.
describe("an address near a remote-shell command", () => {
  it.each([
    "rsync failed, notify alice@acmecorp.io",
    "# sftp creds, ask carol@acmecorp.io",
    "See ssh(1). Maintainer: bob@acmecorp.io",
    "the ssh key belongs to dave@acmecorp.io",
    "scp is slow; email erin@acmecorp.io",
  ])("%s is an address", (text) => {
    expect(ruleIds(text)).toContain("pii-email");
  });

  // An address is never an argument on the way to another address: without that,
  // the first host swallows the second one's exemption.
  it("only the host is exempt, not what follows it", () => {
    expect(
      ruleIds("ssh deploy@bastion.acmecorp.io admin@acmecorp.io"),
    ).toContain("pii-email");
  });

  it.each([
    "ssh deploy@bastion.acmecorp.io",
    "ssh -i ~/.ssh/id_ed25519 deploy@bastion.acmecorp.io",
    "ssh -o StrictHostKeyChecking=no deploy@bastion.acmecorp.io",
    "scp build.tar ops@files.acmecorp.io:/srv/",
    "rsync -a ops@files.acmecorp.io:/srv/ .",
    "sftp ops@files.acmecorp.io",
  ])("%s is a host", (text) => {
    expect(ruleIds(text)).not.toContain("pii-email");
  });
});

describe("keywords and boundaries are read as words, not substrings", () => {
  const flags = (t: string): string[] => scan(t).map((f) => f.ruleId);
  const V = "Xk9mP2qR7vL4nW1s";

  it.each([`COMPASS=${V}`, `BYPASS=${V}`, `PASSENGER_NAME=${V}`])(
    "%s is not a password",
    (text) => {
      expect(flags(text)).not.toContain("env-assignment");
    },
  );

  it.each([`DB_PASS=${V}`, `DB_PASSWORD=${V}`, `MYSQL_PASSWD=${V}`])(
    "%s is",
    (text) => {
      expect(flags(text)).toContain("env-assignment");
    },
  );

  // The lookbehind used to allow exactly one space.
  it.each([
    "ssh deploy@prod.acme-corp.net",
    "ssh  deploy@prod.acme-corp.net",
    "ssh -p 22 deploy@prod.acme-corp.net",
    "scp -r build ops@files.acme-corp.net:/srv/",
    "rsync -avz ops@files.acme-corp.net:/srv/ .",
  ])("%s is a host, not a person", (text) => {
    expect(flags(text)).not.toContain("pii-email");
  });

  it("an address further from the command is still a person", () => {
    const text = `ssh into the box, then write to ${mixed(45)} ada@analytical-engines.org`;
    expect(flags(text)).toContain("pii-email");
  });

  // Square's own contract puts the maximum at 1024, so a token longer than the
  // sixty seen in the wild is a token, not a false positive. Pinning the length
  // at exactly sixty let every longer one through.
  it.each([64, 128, 512])("a %i-character Square token is one", (length) => {
    expect(flags(`EAAA${mixed(length - 4)}`)).toContain("square-access-token");
  });

  // The boundary still has work to do: a longer standard-base64 blob that opens
  // with these four characters is not a token.
  it("a standard-base64 blob beginning EAAA is not one", () => {
    expect(flags(`data:${`EAAA${mixed(60)}`}/x+y=`)).not.toContain(
      "square-access-token",
    );
  });

  it.each([`key_EAAA${mixed(60)}`, `https://x.io/a?token=EAAA${mixed(60)}`])(
    "%s is one",
    (text) => {
      expect(flags(text)).toContain("square-access-token");
    },
  );
});

// Every rule needs a value it must catch, or the id list proves only that a name
// is present. Four of the nine added in this release had their patterns made
// unmatchable and the suite stayed green, because nothing here asked them to
// find anything.
describe("every rule catches something", () => {
  const EXAMPLES: Record<string, string> = {
    "aws-access-key": `${AWS_KEY}`,
    "gcp-api-key": `AIzaSyC${mixed(32)}`,
    "github-pat": `ghp_${mixed(36)}`,
    "github-fine-grained": `github_pat_${mixed(82)}`,
    "gitlab-pat": `glpat-${mixed(20)}`,
    "npm-token": `npm_${mixed(36)}`,
    "openai-key": `sk-${mixed(48)}`,
    "openai-project-key": "sk-proj-Xk9mP2qR7vL4nW1sYj3cBz8dEf5gHiKoNpQuTxMn",
    "openai-service-key": `sk-svcacct-${mixed(40)}`,
    "anthropic-key": `sk-ant-${mixed(95)}`,
    "replicate-token": `r8_${mixed(37)}`,
    "huggingface-token": `hf_${mixed(34)}`,
    "groq-key": `gsk_${mixed(52)}`,
    "openrouter-key": `sk-or-v1-${hex(64)}`,
    "xai-key": `xai-${mixed(80)}`,
    "perplexity-key": `pplx-${mixed(48)}`,
    "digitalocean-pat": `dop_v1_${hex(64)}`,
    "supabase-key": `sbp_${hex(40)}`,
    "slack-token": "xoxb-123456789012-ABCDEFGHIJ",
    "slack-webhook": `https://hooks.slack.com/services/TABCDEFGH/BABCDEFGHIJ/${mixed(24)}`,
    "discord-webhook": `https://discord.com/api/webhooks/123456789012345678/${mixed(68)}`,
    "telegram-bot-token": `12345678:AA${mixed(33)}`,
    "twilio-sid": `AC${hex(32)}`,
    "stripe-secret-key": `sk_live_${mixed(24)}`,
    "stripe-restricted-key": `rk_test_${mixed(24)}`,
    "square-access-token": `EAAA${mixed(60)}`,
    "sendgrid-key": `SG.${mixed(22)}.${mixed(43)}`,
    "mailgun-key": `key-${mixed(32)}`,
    "mailchimp-key": `${hex(32)}-us1`,
    jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "private-key": "-----BEGIN RSA PRIVATE KEY-----",
    "connection-string": "postgres://admin:hunter2xyz@db.internal/app",
    "mapbox-token": `pk.eyJ${mixed(20)}.${mixed(20)}.${mixed(20)}`,
    "sentry-user-token": `sntryu_${hex(64)}`,
    "sentry-org-token": `sntrys_eyJpYXQiOjEuMH0=_${mixed(43)}`,
    "atlassian-token": `ATATT3${mixed(180)}`,
    "linear-key": `lin_api_${mixed(40)}`,
    "postman-key": `PMAK-${hex(24)}-${hex(34)}`,
    "azure-storage-key": `AccountKey=${mixed(86)}==`,
    "private-key-base64": `LS0tLS1CRUdJTi${"QUJDRA".repeat(9)}`,
    "url-basic-auth":
      "https://admin:s3cr3tP4ssw0rdX9@internal.corp.example.com",
    "azure-sas-key": `SharedAccessKey=${mixed(43)}=`,
    "google-oauth-secret": "GOCSPX-aBcD1234eFgH5678iJkL",
    "flyio-token": `FlyV1 fm2_${mixed(50)}`,
    "databricks-token": `dapi${"0123456789abcdef".repeat(2)}`,
    "vault-token": `hvs.${mixed(30)}`,
    "shopify-token": `shpat_${"0123456789abcdef".repeat(2)}`,
    "doppler-token": `dp.pt.${mixed(44)}`,
    "grafana-token": `glsa_${mixed(40)}`,
    "notion-token": `ntn_${mixed(44)}`,
    "generic-secret": "api_key = Xk9mP2qR7vL4nW1sYj3cBz8d",
    "env-assignment": "DB_PASSWORD=Xk9mP2qR7vL4nW1sYj3cBz8d",
    "pii-email": "contact alice@analytical-engines.org",
    "pii-credit-card": "card 4532015112830366",
    "pii-ipv4-public": "the client IP address is 8.8.8.8",
    "pii-ipv6": "ipv6: 2001:4860:4860::8888",
    "pii-ssn": "SSN 123-45-6789",
    "pii-mynumber-jp": "My Number: 123456789018",
    "pii-nir-fr": "NIR 188022B12345659",
    "pii-codice-fiscale-it": "codice fiscale RSSMRA85M01H501Q",
    "pii-steuer-id-de": "Steuer-IdNr. 12345678903",
    "pii-dni-nie-es": "DNI 12345678Z",
    "pii-rrn-kr": "주민등록번호 900101-1234568",
    "pii-brn-kr": "사업자등록번호 220-81-62517",
    "pii-resident-id-cn": "身份证 11010519491231002X",
    "pii-phone-us": "call 415-867-5309",
    "pii-phone-jp": "03-1234-5678",
    "pii-phone-fr": "tél: 01 23 45 67 89",
    "pii-phone-it": "telefono: 0212345678",
    "pii-phone-de": "Telefon: 0301234567",
    "pii-phone-es": "teléfono: 612345678",
    "pii-phone-kr": "phone 010-1234-5678",
    "pii-phone-cn": "电话 13800138000",
    "pii-postal-jp": "〒100-0001",
    "pii-postal-code": "ZIP 94107",
    "pii-postal-cn": "postal code 100000",
    "aws-secret-near-key-id": `AKIA32M9QY4UEBOPC69U\nrIXf+Y0WDSn5Ctrn2zsvegYvJGWJWRXzhwOLfPg6`,
    "docker-hub-pat": `docker login -u chatalab -p ${DOCKER_PAT}`,
    "http-basic-auth":
      "Authorization: Basic c3ZjX2JpbGxpbmc6Nk16WDluRVcrVCtMTGM=",
    "http-bearer-token":
      "Authorization: Bearer sk-live-OqDqQa5ZD5sRIkeC8wLtO9BS",
    "password-cli-flag":
      "mysql -h 10.2.0.14 -u report -p'V1m*23zdFGB' analytics",
    "password-netrc":
      "machine git.example-corp.net\n  login deploy\n  password V9N7z2!pjcRs",
    "password-prose": "my password is CKj3Jg%V8Yr if you want",
    "password-json-key":
      '"db.user": "malvarez", "db.pass": "i!kyBV7DyKVcqNoixmQ"',
    "redis-auth": "127.0.0.1:6379> AUTH hMDvD-xED3A",
    "pii-iban": "DE89 3704 0044 0532 0130 00",
    "pii-phone-intl": "+49 151 85280948",
    "pii-nino-uk": "NI: RE 62 91 56 A",
    "pii-date-of-birth": "DOB: 1990-05-06",
    "pii-customer-number": "会員番号：ABC-12345678",
    "pii-address-jp": "東京都渋谷区神宮前5-28-11",
    "pii-date-of-birth-zh": "出生日期：1985年3月12日",
    "pii-date-of-birth-ko": "생년월일: 1985. 3. 12.",
    "pii-date-of-birth-fr": "Date de naissance : 12/03/1985",
    "pii-date-of-birth-it": "Data di nascita: 12 marzo 1985",
    "pii-date-of-birth-de": "Geburtsdatum: 12.03.1985",
    "pii-date-of-birth-es": "Fecha de nacimiento: 12 de marzo de 1985",
    "pii-customer-number-zh": "客户编号：10023456",
    "pii-customer-number-ko": "고객번호: 0123456789",
    "pii-customer-number-fr": "N° client : 4471882",
    "pii-customer-number-it": "Numero cliente: 123456789",
    "pii-customer-number-de": "Kundennummer: 1234567",
    "pii-customer-number-es": "Número de cliente: 4471882",
  };

  it("has an example for every shipped rule", () => {
    const missing = DEFAULT_RULES.map((r) => r.id).filter(
      (id) => !(id in EXAMPLES),
    );
    expect(missing).toEqual([]);
  });

  it.each(DEFAULT_RULES.map((r) => r.id))("%s finds its example", (id) => {
    const example = EXAMPLES[id];
    if (example === undefined) throw new Error(`no example for ${id}`);
    expect(scan(example).map((f) => f.ruleId)).toContain(id);
  });

  // A credential longer than the pattern guessed must not become invisible.
  //
  // This is the defect the Square rule had, generalised: an exact length with a
  // negative lookahead behind it has no shorter match to fall back to, so one
  // character over the guess stopped the token matching at all. Every vendor
  // length in this file is a guess about someone else's format, so the check is
  // run over every rule rather than the ones anyone suspected — the example is
  // padded with more of the characters it already ends in.
  // The rules a longer value legitimately does not belong to. Each is exact
  // because the format is, not because a length was guessed: a checksum fixes
  // the digits, or the credential is a fixed-width field. Anything not listed
  // has to survive the padding, so a new rule with a guessed upper bound fails
  // here rather than going quiet in a release.
  const LONGER_IS_A_DIFFERENT_THING: Record<string, string> = {
    "aws-access-key": "twenty characters exactly; a longer run is not a key",
    "databricks-token": "dapi and thirty-two hex; longer is a digest",
    "shopify-token": "a prefix and thirty-two hex; longer is a digest",
    "twilio-sid": "thirty-four characters; longer is a certificate digest",
    "pii-email": "padding the end writes a different domain",
    "pii-credit-card": "the checksum fixes the digits",
    "pii-ssn": "nine digits; a longer run is not one",
    "pii-mynumber-jp": "twelve digits with a check digit",
    "pii-nir-fr": "fifteen digits with a two-digit key",
    "pii-codice-fiscale-it": "sixteen characters, checksummed",
    "pii-steuer-id-de": "eleven digits with a check digit",
    "pii-dni-nie-es": "eight digits and a checksum letter",
    "pii-rrn-kr": "thirteen digits with a check digit",
    "pii-brn-kr": "ten digits with a check digit",
    "pii-resident-id-cn": "eighteen characters with a check digit",
    "pii-phone-us": "a dialling plan fixes the length",
    "pii-phone-jp": "ten or eleven digits",
    "pii-phone-fr": "ten digits",
    "pii-phone-it": "a dialling plan fixes the length",
    "pii-phone-de": "a dialling plan fixes the length",
    "pii-phone-es": "nine digits",
    "pii-postal-code": "five digits",
    "pii-postal-cn": "six digits",
    "pii-ipv4-public": "four octets",
    "aws-secret-near-key-id":
      "the secret is exactly forty characters, and the rule takes exactly forty",
    "http-basic-auth":
      "a base64 credential is whole four-character groups, so a longer one is not a credential",
    "pii-iban": "the country length and the check digits fix the value",
    "pii-phone-intl":
      "a dialling plan fixes the number of digits, and the rule's range is nine to fifteen",
    "pii-nino-uk": "two letters, six digits and a suffix",
    "pii-customer-number":
      "a run longer than twenty-four characters is a hash or a token, not a number anyone types",
    "pii-date-of-birth":
      "a date has a fixed number of digits; one more is not a date",
    "pii-customer-number-zh":
      "a run longer than twenty-four characters is a hash or a token, not a number anyone types",
    "pii-customer-number-ko":
      "a run longer than twenty-four characters is a hash or a token, not a number anyone types",
    "pii-customer-number-fr":
      "a run longer than twenty-four characters is a hash or a token, not a number anyone types",
    "pii-customer-number-it":
      "a run longer than twenty-four characters is a hash or a token, not a number anyone types",
    "pii-customer-number-de":
      "a run longer than twenty-four characters is a hash or a token, not a number anyone types",
    "pii-customer-number-es":
      "a run longer than twenty-four characters is a hash or a token, not a number anyone types",
  };

  // The list above is a list, so it is held to the rules that exist: an id left
  // in it after its rule is renamed or dropped would silently stop anything
  // being checked.
  it("exempts only rules that are shipped", () => {
    const ids = new Set(DEFAULT_RULES.map((r) => r.id));
    const stale = Object.keys(LONGER_IS_A_DIFFERENT_THING).filter(
      (id) => !ids.has(id),
    );
    expect(stale).toEqual([]);
  });

  const alphabetFor = (example: string): string => {
    const tail = example.slice(-12);
    if (/^[0-9]+$/.test(tail)) return "0123456789";
    if (/^[a-f0-9]+$/i.test(tail)) return "abcdef0123456789";
    if (/^[a-z0-9]+$/.test(tail)) return "abcdefghijklmnopqrstuvwxyz0123456789";
    return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  };

  const padded = (example: string, extra: number): string => {
    const alphabet = alphabetFor(example);
    let out = example;
    for (let i = 0; i < extra; i++) out += alphabet[i % alphabet.length];
    return out;
  };

  it.each(
    DEFAULT_RULES.map((r) => r.id).filter(
      (id) => !(id in LONGER_IS_A_DIFFERENT_THING),
    ),
  )("%s still finds a value that runs longer", (id) => {
    const example = EXAMPLES[id];
    if (example === undefined) throw new Error(`no example for ${id}`);
    for (const extra of [1, 8, 64]) {
      expect(
        scan(padded(example, extra)).map((f) => f.ruleId),
        `${id} with ${extra} more characters`,
      ).toContain(id);
    }
  });
});

// Every rule has an example, and the test above enforces that. What no example
// does is sit on a boundary: each is one value from the middle of the range, so
// a range written one digit short, a length guessed too tight, or a grouping
// nobody thought of all pass the suite. Every bug in this block was found that
// way and none of them by the examples.
describe("rule boundaries", () => {
  // A Luhn-valid PAN of a given length, built digit by digit so the check digit
  // is right and no card-shaped literal is written down.
  const pan = (prefix: string, length: number): string => {
    const body = prefix.split("");
    while (body.length < length - 1) body.push(String((body.length * 7) % 10));
    let sum = 0;
    let double = true;
    for (let i = body.length - 1; i >= 0; i--) {
      let d = Number(body[i]);
      if (double) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
      double = !double;
    }
    return body.join("") + String((10 - (sum % 10)) % 10);
  };

  const grouped = (digits: string, sizes: number[]): string => {
    const groups: string[] = [];
    let at = 0;
    for (const n of sizes) {
      groups.push(digits.slice(at, at + n));
      at += n;
    }
    return groups.join(" ");
  };

  const found = (text: string, id: string): boolean =>
    scan(text).some((f) => f.ruleId === id);

  // `5[0-8][0-9]` covered 6500–6589 and stopped: a range ending at 6589 belongs
  // to no issuing scheme, and the last hundred prefixes went unmatched.
  it.each(["6500", "6589", "6590", "6599"])(
    "a Discover PAN beginning %s is matched",
    (prefix) => {
      expect(found(pan(prefix, 16), "pii-credit-card")).toBe(true);
    },
  );

  // Every alternative assumed groups of four. A card is copied the way it is
  // printed, and neither of these is printed in fours.
  it("an Amex PAN written 4-6-5 is matched", () => {
    expect(found(grouped(pan("3782", 15), [4, 6, 5]), "pii-credit-card")).toBe(
      true,
    );
  });

  it("a Diners PAN written 4-6-4 is matched", () => {
    expect(found(grouped(pan("3600", 14), [4, 6, 4]), "pii-credit-card")).toBe(
      true,
    );
  });

  // An exact length with a negative lookahead behind it does not degrade: one
  // character over and there is no shorter match to fall back to, so the token
  // stops matching altogether rather than matching partly.
  const filler = (n: number): string =>
    "A1b2C3d4E5f6G7h8I9j0".repeat(60).slice(0, n);

  it.each([
    ["sq0csp-", 43],
    ["sq0csp-", 44],
    ["sq0csp-", 64],
    ["sq0atp-", 22],
    ["sq0atp-", 61],
  ])("a Square token %s with %i characters is matched", (prefix, n) => {
    expect(found(prefix + filler(n), "square-access-token")).toBe(true);
  });

  it.each([60, 200])("a Square EAAA token of %i characters is matched", (n) => {
    expect(found(`EAAA${filler(n)}`, "square-access-token")).toBe(true);
  });

  // No boundary at all, which is its own kind of missing boundary: the pattern
  // matched inside a longer run of hex and accepted upper case, so a certificate
  // fingerprint was a Twilio SID.
  it("a Twilio SID inside a longer hex string is not a SID", () => {
    const hex = `AC${"0123456789ABCDEF".repeat(2)}`;
    expect(found(`SHA256:${hex}AA`, "twilio-sid")).toBe(false);
  });

  it("a Twilio SID on its own is one", () => {
    expect(found(`AC${"0123456789abcdef".repeat(2)}`, "twilio-sid")).toBe(true);
  });
});

// ── the two rules whose patterns were rewritten for speed ────────────────────

// Both were changed by bounding a quantifier, which is a change to what they
// match as much as to how long they take. The performance cases above would
// pass just as well if the patterns had stopped matching anything at all.
describe("pii-email after bounding the local part", () => {
  const email = (text: string): boolean =>
    scan(text).some((f) => f.ruleId === "pii-email");

  it.each([
    ["ada@analytical-engines.org", "the plain form"],
    ["Alice.Smith@Example.COM", "mixed case"],
    ["user+tag@analytical-engines.org", "plus addressing"],
    ["user.name@sub.analytical-engines.co.uk", "several domain labels"],
    ["a@b.co", "the shortest real shape"],
    [
      "user_name%foo-bar@analytical-engines.org",
      "every character of the local part",
    ],
    ["see<ada@analytical-engines.org>now", "embedded in surrounding text"],
    [`${mixed(64)}@analytical-engines.org`, "a local part at RFC 5321's limit"],
  ])("%s is detected (%s)", (text) => {
    expect(email(text)).toBe(true);
  });

  // What bounding the local part costs. 65 characters before the `@` with no
  // dot to restart the boundary is not a deliverable address, and it is also a
  // way to write one this rule will not see.
  it("a local part past the limit is not detected", () => {
    expect(email(`${mixed(65)}@analytical-engines.org`)).toBe(false);
  });

  // A dot restarts the word boundary, so a long address with dots in it is
  // still found — the limit applies to one unbroken run, not to the whole
  // local part.
  it("a long local part broken by dots is still detected", () => {
    const local = Array.from({ length: 10 }, () => mixed(20)).join(".");
    expect(email(`${local}@analytical-engines.org`)).toBe(true);
  });

  // Domains without a dot were never matched, before this change or after it.
  it.each(["user@localhost", "user@example", "user@[192.168.0.1]"])(
    "%s is not detected, as before",
    (text) => {
      expect(email(text)).toBe(false);
    },
  );
});

// `openssl genpkey -aes256` writes this header, and it was not one of the forms
// the rule listed.
describe("encrypted private key headers", () => {
  it.each([
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
  ])("%s is detected", (header) => {
    expect(scan(header).some((f) => f.ruleId === "private-key")).toBe(true);
  });

  it("a header that is not a private key is not detected", () => {
    expect(
      scan("-----BEGIN CERTIFICATE-----").some(
        (f) => f.ruleId === "private-key",
      ),
    ).toBe(false);
  });
});

// A survey of how five vendors actually format their credentials found five
// shapes the rules did not see. Each is held here in both directions: the value
// that must be found, and the near neighbour that must stay quiet. Widening a
// pattern until it matches is easy, and a pattern that matches everything
// protects nothing.
describe("the credential shapes the rules used to miss", () => {
  const hits = (text: string, ruleId: string): boolean =>
    scan(text).some((f) => f.ruleId === ruleId);

  describe("telegram-bot-token counts the hash loosely", () => {
    // The pattern asked for exactly 33 characters after `AA`. Not at least 33 —
    // exactly, so a 32-character token and a 35-character one were both
    // invisible, and the length that did work was the one nobody writes down.
    it.each([
      ["32", "110201543:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"],
      ["35", "8012345678:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawXyz"],
      ["a six-digit bot id", "123456:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"],
    ])("%s characters after AA is a token", (_label, token) => {
      expect(hits(token, "telegram-bot-token")).toBe(true);
    });

    it.each([
      ["a bot id with no hash", "1234567890:AA"],
      [
        "too few digits before the colon",
        "12345:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw",
      ],
    ])("%s is not", (_label, text) => {
      expect(hits(text, "telegram-bot-token")).toBe(false);
    });
  });

  it("connection-string reads the SRV scheme MongoDB Atlas hands out", () => {
    expect(
      hits(
        "mongodb+srv://svc:Xk2p9QmR7t@cluster0.abcd.mongodb.net/db",
        "connection-string",
      ),
    ).toBe(true);
  });

  describe("aws-access-key knows the prefixes it was missing", () => {
    it.each(["ABIA", "ACCA", "APKA", "ASCA", "AKIA"])("%s", (prefix) => {
      expect(hits(`${prefix}3QF7TZ9KLMN2PQRS`, "aws-access-key")).toBe(true);
    });

    it("a four-letter run that is not a prefix is not a key", () => {
      expect(hits("AZZA3QF7TZ9KLMN2PQRS", "aws-access-key")).toBe(false);
    });

    // AWS writes `EXAMPLE` where the random part would end, in every setup
    // guide it publishes. A block on one of those reads exactly like a block on
    // a live key, and this project's own documentation is full of them.
    it.each([
      ["the documented access key", ["AKIA", "IOSFODNN7", "EXAMPLE"].join("")],
      ["the documented session key", ["ASIA", "IOSFODNN7", "EXAMPLE"].join("")],
      ["another from the docs", ["AKIA", "I44QH8DHB", "EXAMPLE"].join("")],
    ])("%s is documentation, not a credential", (_label, key) => {
      expect(hits(key, "aws-access-key")).toBe(false);
    });
  });

  describe("private-key-base64 at each base64 alignment", () => {
    const pem = [
      "-----BEGIN RSA PRIVATE KEY-----",
      "MIIEowIBAAKCAQEAwK3vJ9m5Q8xY2nB4dF6hL0pR7sT1uV3wX5yZ8aC2eG4iK6mO",
      "-----END RSA PRIVATE KEY-----",
      "",
    ].join("\n");

    // Three bytes encode to four characters, so where the header sits relative
    // to that boundary decides what it looks like once encoded. Matching one
    // alignment would find one key in three.
    it.each([0, 1, 2])("%i bytes ahead of the header", (offset) => {
      const encoded = Buffer.from(mixed(offset) + pem, "utf8").toString(
        "base64",
      );
      expect(hits(`client-key-data: ${encoded}`, "private-key-base64")).toBe(
        true,
      );
    });

    it("the plaintext header is still the plaintext rule's to find", () => {
      expect(hits(pem, "private-key")).toBe(true);
      expect(hits(pem, "private-key-base64")).toBe(false);
    });
  });

  describe("url-basic-auth", () => {
    it.each([
      [
        "a private registry",
        "https://deploy:Xk2p9QmR7tLw@registry.internal.example.com/v2/",
      ],
      [
        "a git remote",
        "git clone https://svcacct:ghp_A1b2C3d4E5f6G7h8@github.com/org/repo.git",
      ],
    ])("%s is a finding", (_label, text) => {
      expect(hits(text, "url-basic-auth")).toBe(true);
    });

    // The rule captures no group, so the shape tests that need one do not run
    // over it. `isPlaceholder` does — it is applied to every secret rule — and
    // it is the whole of what keeps these quiet. Each was measured: without it
    // all four are findings.
    it.each([
      [
        "a generic pair against localhost",
        "https://user:password@localhost:8080",
      ],
      [
        "a reference the shell never expanded",
        "https://x-access-token:${GH_TOKEN}@github.com/org/repo.git",
      ],
      [
        "an environment variable",
        "https://admin:$REGISTRY_PASSWORD@registry.example.com",
      ],
      [
        "the words a document tells you to replace",
        "https://USERNAME:PASSWORD@example.com/path",
      ],
    ])("%s is not", (_label, text) => {
      expect(scan(text)).toEqual([]);
    });
  });
});

describe("credential formats the vendors document", () => {
  const hits = (text: string, ruleId: string): boolean =>
    scan(text).some((f) => f.ruleId === ruleId);
  const b64 = (n: number): string =>
    "aB3d5f7h9jK2m4n6p8r0stUvwx1y3z5A7c9e1g3iQwErTyUiOpAsDfGhJkLzXcVbNm"
      .repeat(4)
      .slice(0, n);
  const hex = (n: number): string =>
    "a3d5f7b9c2e4a6d8f0b1c3e5a7d9f0b2".repeat(4).slice(0, n);
  // Assembled rather than written out. GitHub's push protection reads these
  // three as live tokens and refuses the push, which is the shapes being right.
  const glft = ["gl", "ft-"].join("");
  const grRunner = ["GR", "1348941"].join("");
  const sqOauth = ["sq", "0atp-"].join("");
  const sqSecret = ["sq", "0csp-"].join("");

  it.each([
    ["linear-key", "mixed case", `lin_api_${b64(40)}`],
    ["notion-token", "the legacy secret_ token", `secret_${b64(43)}`],
    ["digitalocean-pat", "an OAuth access token", `doo_v1_${hex(64)}`],
    ["digitalocean-pat", "an OAuth refresh token", `dor_v1_${hex(64)}`],
    ["gitlab-pat", "a feed token", `${glft}${b64(20)}`],
    ["gitlab-pat", "a runner registration token", `${grRunner}${b64(20)}`],
    ["flyio-token", "a token with no auth scheme in front", `fm2_${b64(120)}`],
    ["flyio-token", "an fo1_ token", `fo1_${b64(43)}`],
    ["flyio-token", "underscore inside the body", `fm2_aB3d5f7h_${b64(60)}`],
    ["square-access-token", "an OAuth token", `${sqOauth}${b64(24)}`],
    ["square-access-token", "a client secret", `${sqSecret}${b64(43)}`],
    ["huggingface-token", "an organization token", `api_org_${b64(34)}`],
    ["twilio-sid", "an uppercase Account SID", `AC${hex(32).toUpperCase()}`],
    ["twilio-sid", "an API Key SID", `SK${hex(32)}`],
    [
      "postman-key",
      "uppercase hex",
      `PMAK-${hex(24).toUpperCase()}-${hex(34).toUpperCase()}`,
    ],
    [
      "replicate-token",
      "a hyphen in the body",
      "r8_aB3d5f7h9jK2m4n6-8r0stUvwx1y3z5A7c9e1",
    ],
    ["azure-sas-key", "an IoT DPS 64-byte key", `SharedAccessKey=${b64(86)}==`],
    ["azure-sas-key", "a 16-byte key", `SharedAccessKey=${b64(22)}==`],
  ])("%s finds %s", (ruleId, _label, value) => {
    expect(hits(value, ruleId)).toBe(true);
  });

  it.each([
    [
      "digitalocean-pat",
      "dox_v1_ is not a DigitalOcean prefix",
      `dox_v1_${hex(64)}`,
    ],
    ["twilio-sid", "AB is not a Twilio prefix", `AB${hex(32)}`],
    ["replicate-token", "r9_ is not a Replicate prefix", `r9_${b64(37)}`],
  ])("%s does not find %s", (ruleId, _label, value) => {
    expect(hits(value, ruleId)).toBe(false);
  });

  // The whole key, not a prefix of it. `{95}` matched 102 of the 108 characters
  // and left the tail outside the match.
  it("anthropic-key matches the key to its end", () => {
    const key = `sk-ant-api03-${b64(93).replace(/[+/]/g, "x")}AA`;
    const finding = scan(key).find((f) => f.ruleId === "anthropic-key");
    expect(finding?.secretValue).toHaveLength(key.length);
  });
});

// ISO/IEC 7812 allows 10–19 digits and the brands use most of that range. The
// pattern encoded one length per brand, so a 19-digit UnionPay or JCB card —
// and every Maestro card — went unmatched.
describe("card numbers at every length their brand issues", () => {
  const luhnCheck = (body: string): string => {
    let sum = 0;
    let double = true;
    for (let i = body.length - 1; i >= 0; i--) {
      let d = Number(body[i]);
      if (double) d = d * 2 > 9 ? d * 2 - 9 : d * 2;
      double = !double;
      sum += d;
    }
    return String((10 - (sum % 10)) % 10);
  };
  const pan = (prefix: string, total: number): string => {
    let body = prefix;
    let n = 7;
    while (body.length < total - 1) {
      n = (n * 7 + 3) % 10;
      body += String(n);
    }
    return body + luhnCheck(body);
  };
  const found = (value: string): boolean =>
    scan(`card ${value}`).some((f) => f.ruleId === "pii-credit-card");

  it.each([
    ["visa", "4539", [13, 16, 19]],
    ["amex", "3782", [15]],
    ["discover", "6011", [16, 17, 18, 19]],
    ["jcb", "3528", [16, 17, 18, 19]],
    ["diners", "3056", [14, 16, 17, 18, 19]],
    ["unionpay", "6212", [16, 17, 18, 19]],
    ["maestro", "6759", [12, 13, 14, 15, 16, 17, 18, 19]],
  ] as [string, string, number[]][])("%s", (_brand, prefix, lengths) => {
    for (const total of lengths) {
      expect(found(pan(prefix, total)), `${total} digits`).toBe(true);
    }
  });

  it("a nineteen-digit run that fails Luhn is not a card", () => {
    expect(found("6212272727272727270")).toBe(false);
  });

  it("a thirteen-digit millisecond timestamp is not a card", () => {
    expect(found("1755300000000")).toBe(false);
  });

  it("groups separated by spaces and by hyphens are both found", () => {
    const digits = pan("4539", 19);
    const spaced = digits.replace(/(.{4})/g, "$1 ").trim();
    const hyphenated = digits.replace(/(.{4})/g, "$1-").replace(/-$/, "");
    expect(found(spaced)).toBe(true);
    expect(found(hyphenated)).toBe(true);
  });
});

describe("connection-string after bounding the credentials", () => {
  const conn = (text: string): boolean =>
    scan(text).some((f) => f.ruleId === "connection-string");

  it.each([
    "mongodb://user:pass@host/db",
    "postgres://u:p@h:5432/d",
    "postgresql://u:p@h/d",
    "mysql://root:secret@localhost",
    "redis://default:abc123@127.0.0.1:6379",
    "see mongodb://user:pass@host in the log",
  ])("%s is detected", (text) => {
    expect(conn(text)).toBe(true);
  });

  it.each([
    ["mongodb://host/db", "no credentials"],
    ["https://user:pass@host", "a scheme the rule does not cover"],
    ["mongodb://user@host", "no password"],
  ])("%s is not detected (%s)", (text) => {
    expect(conn(text)).toBe(false);
  });

  // What the bound costs: a userinfo field longer than 256 characters. A
  // password that long is not what a connection string carries, and the
  // alternative is the quantifier running to the end of the file.
  it("credentials longer than the bound are not detected", () => {
    expect(conn(`mongodb://user:${mixed(1025)}@host`)).toBe(false);
    expect(conn(`mongodb://user:${mixed(1024)}@host`)).toBe(true);
  });
});

describe("env-assignment after bounding the name", () => {
  const assigned = (text: string): boolean =>
    scan(text).some((f) => f.ruleId === "env-assignment");

  it.each([
    "API_KEY=abcdefgh12345",
    "SECRET=abcdefgh12345",
    "MY_SECRET_TOKEN = supersecretvalue",
    "DB_PASSWORD=hunter2xyz",
    "PRIVATE_KEY=Xk9mP2qR7vL4nW1s",
    "AWS_SECRET_ACCESS_KEY_2=abcdefghijkl",
  ])("%s is detected", (text) => {
    expect(assigned(text)).toBe(true);
  });

  it.each([
    ["NOTASECRET=short", "a value under eight characters"],
    ["SECRET=", "no value at all"],
  ])("%s is not detected (%s)", (text) => {
    expect(assigned(text)).toBe(false);
  });

  // The bound is on the run of capitals either side of the keyword. A name
  // longer than that is not an environment variable anyone writes, and saying
  // so here is what stops the bound being loosened to "fix" a case nobody has.
  it("a name with more than 64 capitals before the keyword is not detected", () => {
    expect(assigned(`${mixed(65)}SECRET=abcdefgh12345`)).toBe(false);
    expect(assigned(`${mixed(64)}SECRET=abcdefgh12345`)).toBe(true);
  });
});

// ── the address shapes a document prints ──────────────────────────────────────

const ruleHit = (text: string, id: string): boolean =>
  scan(text).some((f) => f.ruleId === id);

// A sentence ends in a full stop, and the address before it is still an
// address. The rule used to refuse any domain that a dot followed, so the stop
// hid it. A dot that is followed by a label is still a longer domain, and the
// whole domain is taken either way.
describe("an address followed by a full stop", () => {
  it.each([
    ["contact dmitri.ferreira@fernhill.co.", "dmitri.ferreira@fernhill.co"],
    ["write to ada@analytical-engines.org.", "ada@analytical-engines.org"],
    ["the mailbox is a@b.co.uk.", "a@b.co.uk"],
    ["see (ada@analytical-engines.org).", "ada@analytical-engines.org"],
  ])("%s is found as %s", (text, address) => {
    const found = scan(text).find((f) => f.ruleId === "pii-email");
    expect(found?.secretValue).toBe(address);
  });

  // The whole domain, not the first label: a rule that stopped at `co` would
  // leave `.uk` outside the match and report a different address.
  it("a multi-label domain is taken whole", () => {
    const found = scan("a@b.co.uk").find((f) => f.ruleId === "pii-email");
    expect(found?.secretValue).toBe("a@b.co.uk");
  });

  // A dot followed by a letter run is part of the name, not a stop.
  it("a domain followed by a dot and a word is not cut at the dot", () => {
    const found = scan("a@b.co.uk.example").find(
      (f) => f.ruleId === "pii-email",
    );
    expect(found).toBeUndefined();
  });
});

// The `@` in a URL query is written `%40`. The local part is the same kind of
// text as before the `@`, so the same rule finds it.
describe("an address with its @ percent-encoded", () => {
  it.each([
    [
      "GET /api/users?email=tomas.reyes%40quillfield.com&expand=orders",
      "tomas.reyes%40quillfield.com",
    ],
    ["?to=ada%40analytical-engines.org", "ada%40analytical-engines.org"],
    ["mailto:ada%40analytical-engines.org", "ada%40analytical-engines.org"],
  ])("%s is found", (text, value) => {
    const found = scan(text).find((f) => f.ruleId === "pii-email");
    expect(found?.secretValue).toBe(value);
  });

  // The negative lookahead for `git@` names the `@` form of an address that is
  // a repository, not a person. Its `%40` form is the same thing.
  it("git%40 is still a repository address, not a person", () => {
    expect(ruleHit("clone git%40github.com:org/repo.git", "pii-email")).toBe(
      false,
    );
  });
});

// The local parts a mailbox policy names as functions. A role address reaches a
// shared inbox, and a block on it stops a developer quoting their team's
// published contact. Compared whole and case-insensitively.
describe("a role address is not a person's", () => {
  it.each([
    "noreply@acmecorp.io",
    "no-reply@acmecorp.io",
    "donotreply@acmecorp.io",
    "do-not-reply@acmecorp.io",
    "support@acmecorp.io",
    "sales@acmecorp.io",
    "info@acmecorp.io",
    "help@acmecorp.io",
    "contact@acmecorp.io",
    "press@acmecorp.io",
    "abuse@acmecorp.io",
    "postmaster@acmecorp.io",
    "webmaster@acmecorp.io",
    "hostmaster@acmecorp.io",
    "Support@acmecorp.io",
    "NOREPLY@acmecorp.io",
    "No-Reply@acmecorp.io",
  ])("%s is not found", (address) => {
    expect(ruleHit(`write to ${address}`, "pii-email")).toBe(false);
  });

  // The near misses: a name that contains a role word, or a role word with a
  // digit or a different suffix, is a person or a team's own mailbox, and it
  // stays a finding.
  it.each([
    "john.support@acmecorp.io",
    "support2@acmecorp.io",
    "supportteam@acmecorp.io",
    "info.jane@acmecorp.io",
    "sales-team@acmecorp.io",
    "x.noreply@acmecorp.io",
  ])("%s is still found", (address) => {
    expect(ruleHit(`write to ${address}`, "pii-email")).toBe(true);
  });

  it("a role address in a URL query is also not a person's", () => {
    expect(ruleHit("?to=support%40acmecorp.io", "pii-email")).toBe(false);
  });
});

// ── passwords on a command line, in a netrc file, in a sentence, in JSON ────

describe("a password passed on the command line", () => {
  it.each([
    [
      "mysql -h 10.2.0.14 -u report -p'V1m*23zdFGB' analytics",
      "mysql -p with single quotes",
    ],
    [
      'mysql -h 10.2.0.14 -u report -p"V1m*23zdFGB" analytics',
      "mysql -p with double quotes",
    ],
    [
      "pg_dump --host db1 --username app --password 'S4Kv&DEu0GBmb' prod",
      "--password with a space and a quoted value",
    ],
    [
      'sync.exe --password "jQMhIKJNlyJl@u#Ulf" --user fwagner',
      "--password with double quotes",
    ],
    ["tool --password=S4Kv&DEu0GBmb", "--password= with no quotes"],
    ["tool --passwd hunter2!x", "--passwd, unquoted"],
    ["tool --pass=Xk9mP2qR7v", "--pass="],
    ["(mysql -p'V1m*23zdFGB')", "inside parentheses"],
    ['"cmd": "mysql -p\'V1m*23zdFGB\' db"', "inside a JSON string"],
  ])("%s is found (%s)", (text) => {
    expect(ruleHit(text, "password-cli-flag")).toBe(true);
  });

  it.each([
    ["pg_dump --password prod", "a word that is not a password"],
    ["tool --password-stdin", "a flag that names the source, not the value"],
    ["tool --password=abc1!", "five characters, one under the minimum"],
    ["ssh -p 22 host", "-p with a port, not a password"],
    ["mysql -p analytics", "-p without quotes is not the mysql form"],
    ["tool --password", "a flag with no value"],
    ["tool --password 'my pass1'", "a value with a space in it"],
  ])("%s is not found (%s)", (text) => {
    expect(ruleHit(text, "password-cli-flag")).toBe(false);
  });

  // A value that ends in a full stop or a closing parenthesis is a sentence
  // around it. The stop is not part of the password.
  it("the value stops before a trailing full stop", () => {
    const found = scan("run tool --password Xk9mP2qR7v.").find(
      (f) => f.ruleId === "password-cli-flag",
    );
    expect(found?.secretValue).toBe("Xk9mP2qR7v");
  });
});

describe("a password line in a .netrc file or a vault listing", () => {
  it.each([
    [
      "machine git.example-corp.net\n  login deploy\n  password V9N7z2!pjcRs",
      "an indented netrc line",
    ],
    ["password V9N7z2!pjcRs", "at the start of the text"],
    [
      "username       meilin.zhou\npassword       Salt_lVi9UMB45",
      "a vault key listing",
    ],
    ["\tpasswd\tSalt_lVi9UMB45", "a tab-indented passwd line"],
  ])("%s is found (%s)", (text) => {
    expect(ruleHit(text, "password-netrc")).toBe(true);
  });

  it.each([
    ["the password V9N7z2!pjcRs is old", "the word is in the middle of a line"],
    ["password required", "a value with no digit or symbol"],
    ["password_hint V9N7z2!pjcRs", "a name that is not the word"],
  ])("%s is not found (%s)", (text) => {
    expect(ruleHit(text, "password-netrc")).toBe(false);
  });
});

describe("a password written in a sentence", () => {
  it.each([
    ["my password is CKj3Jg%V8Yr if you want", "password is"],
    [
      "Temporary password is Kessler?dlbRswI01j24 -- change it",
      "password is, capitalised",
    ],
    ["pw: hunter2!x", "pw:"],
    ['password = "Xk9mP2qR7v"', "password = with quotes"],
    ["PASSWORD: Xk9mP2qR7v!", "upper case keyword"],
    ["パスワードは Xk9mP2qR7v です", "Japanese, は and です"],
    ["パスワード：Xk9mP2qR7v", "Japanese, full-width colon"],
    ["パスワード: Xk9mP2qR7v", "Japanese, colon"],
    ["パスワードは Xk9mP2qR7v で届きます", "Japanese, stops before で"],
  ])("%s is found (%s)", (text) => {
    expect(ruleHit(text, "password-prose")).toBe(true);
  });

  it.each([
    ["password is required", "required has no digit or symbol"],
    ["password is incorrect.", "incorrect has no digit or symbol"],
    ["the password was reset", "reset has no digit or symbol"],
    ["passwords are stored elsewhere", "a longer word"],
    ["password: 123456", "digits only"],
    ["password = None", "None has no digit or symbol"],
    ["パスワードは設定済みです", "Japanese with no Latin letters"],
    ["パスワードを忘れました", "no separator after the word"],
  ])("%s is not found (%s)", (text) => {
    expect(ruleHit(text, "password-prose")).toBe(false);
  });

  // The value is the password and not the code around it: an identifier path
  // like `os.environ[` is refused by the value class, so the rule does not read
  // a read from the environment as a password.
  it("code that reads the password is not one", () => {
    expect(
      ruleHit('password = os.environ["DB_PASSWORD"]', "password-prose"),
    ).toBe(false);
  });
});

describe("a password under a key that ends in pass, passwd, password or pwd", () => {
  it.each([
    ['"db.user": "malvarez", "db.pass": "i!kyBV7DyKVcqNoixmQ"', "db.pass"],
    ['{"user_password": "Xk9mP2qR7vL4"}', "user_password"],
    ['{"userPassword": "Xk9mP2qR7vL4"}', "camel case"],
    ['{"PASSWORD": "Xk9mP2qR7vL4"}', "upper case"],
    ['{"dbPass": "Xk9mP2qR7vL4"}', "camel case pass"],
    ['{"passwd": "Xk9mP2qR7vL4"}', "passwd"],
    ['{"pwd": "Xk9mP2qR7vL4"}', "pwd"],
  ])("%s is found (%s)", (text) => {
    expect(ruleHit(text, "password-json-key")).toBe(true);
  });

  // `bypass` ends in the letters `pass` but the word is `by`: the key is judged
  // by where its last word starts, and a boundary has to come before it.
  it.each([
    ['{"bypass": "Xk9mP2qR7vL4"}', "bypass ends in pass but is one word"],
    ['{"password_hint": "Xk9mP2qR7vL4"}', "the key ends in hint"],
    ['{"passwordless": "Xk9mP2qR7vL4"}', "the key ends in less"],
    ['{"db.pass": "12345"}', "a value with no letter"],
  ])("%s is not found (%s)", (text) => {
    expect(ruleHit(text, "password-json-key")).toBe(false);
  });
});

describe("the Redis AUTH command and redis-cli -a", () => {
  it.each([
    ["127.0.0.1:6379> AUTH hMDvD-xED3A", "a MONITOR prompt"],
    ['"AUTH" "Ember%0eWzV6g4lU59"', "a quoted MONITOR line"],
    ["AUTH hMDvD-xED3A", "at the start of the text"],
    ["redis-cli -h 10.0.0.5 -a hMDvD-xED3A ping", "redis-cli -a"],
    ['AUTH "hMDvD-xED3A"', "a quoted value"],
  ])("%s is found (%s)", (text) => {
    expect(ruleHit(text, "redis-auth")).toBe(true);
  });

  it.each([
    ["auth hMDvD-xED3A", "lower case is not the command"],
    ["AUTH required", "a word that is not a password"],
    ["redis-cli -h 10.0.0.5 ping", "no -a"],
    ["AUTHORIZED hMDvD-xED3A", "a longer word"],
  ])("%s is not found (%s)", (text) => {
    expect(ruleHit(text, "redis-auth")).toBe(false);
  });
});

// ── the Authorization header ──────────────────────────────────────────────────

describe("an HTTP Basic credential", () => {
  it.each([
    ["Authorization: Basic c3ZjX2JpbGxpbmc6Nk16WDluRVcrVCtMTGM=", "the header"],
    ["authorization: basic c3ZjX2JpbGxpbmc6Nk16WDluRVcrVCtMTGM=", "lower case"],
    ['"Authorization": "Basic c3ZjX2JpbGxpbmc6Nk16WDluRVcrVCtMTGM="', "JSON"],
  ])("%s is found (%s)", (text) => {
    expect(ruleHit(text, "http-basic-auth")).toBe(true);
  });

  // Each is base64 that is well formed and decodes, and is still not a
  // `user:password` pair: no colon, an empty user, an empty password, a bad
  // length, bytes that are not UTF-8, and a control character.
  it.each([
    ["Authorization: Basic dXNlcg==", "decodes to a user name with no colon"],
    ["Authorization: Basic OnBhc3M=", "an empty user name"],
    ["Authorization: Basic dXNlcjo=", "an empty password"],
    [
      "Authorization: Basic c3ZjX2JpbGxpbmc6Nk16WDluRVcrVCtMTGM",
      "missing padding",
    ],
    ["Authorization: Basic /w==", "bytes that are not UTF-8"],
    ["Authorization: Basic dQE6cA==", "a control character"],
  ])("%s is not found (%s)", (text) => {
    expect(ruleHit(text, "http-basic-auth")).toBe(false);
  });
});

describe("an HTTP Bearer token", () => {
  it.each([
    ["Authorization: Bearer sk-live-OqDqQa5ZD5sRIkeC8wLtO9BS", "the header"],
    ["authorization: bearer sk-live-OqDqQa5ZD5sRIkeC8wLtO9BS", "lower case"],
    ['"Authorization": "Bearer sk-live-OqDqQa5ZD5sRIkeC8wLtO9BS"', "JSON"],
    [`Authorization: Bearer ${mixed(20)}`, "the minimum length of twenty"],
  ])("%s is found (%s)", (text) => {
    expect(ruleHit(text, "http-bearer-token")).toBe(true);
  });

  it.each([
    ["Authorization: Bearer $TOKEN", "a shell reference"],
    ["Authorization: Bearer <token>", "a slot"],
    ["Authorization: Bearer ${API_KEY}", "a template reference"],
    ["Authorization: Bearer abcdefghijklmnopqrs", "nineteen characters"],
    ["Authorization: Bearer abababababababababababab", "no entropy"],
    [
      "Authorization: Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "a run of one character",
    ],
  ])("%s is not found (%s)", (text) => {
    expect(ruleHit(text, "http-bearer-token")).toBe(false);
  });
});

// ── the AWS secret access key, written beside its key ID ─────────────────────

describe("an AWS secret access key beside its Access Key ID", () => {
  const SECRET = "wJ4rXUt0nFEM9K7MDENG2bPxRfiCYqZ8nMLVAa3D";
  const KEY_ID = "AKIA32M9QY4UEBOPC69U";

  it.each([
    [`${KEY_ID}\nrIXf+Y0WDSn5Ctrn2zsvegYvJGWJWRXzhwOLfPg6`, "on the next line"],
    [
      `svc-report-1,${KEY_ID},/yvGmsLPhuxamXfuIt4mxDZncVBbdM4d4bs6SuZc`,
      "a CSV row",
    ],
    [`access key ${KEY_ID} secret ${SECRET}`, "on the same line"],
    [`アクセスキーは ${KEY_ID}、シークレットは ${SECRET}`, "Japanese labels"],
    [`${KEY_ID}, ${SECRET}`, "a comma and a space"],
  ])("%s is found (%s)", (text) => {
    expect(ruleHit(text, "aws-secret-near-key-id")).toBe(true);
  });

  // Only the forty characters are the value: the key ID and the label beside
  // it are not part of the finding.
  it("the finding is the forty characters and nothing else", () => {
    const found = scan(`${KEY_ID},${SECRET}`).find(
      (f) => f.ruleId === "aws-secret-near-key-id",
    );
    expect(found?.secretValue).toBe(SECRET);
  });

  // The gap between the key ID and the secret is bounded at eighty characters.
  // Eighty is the limit, and eighty-one on the same line is not a secret beside
  // the key.
  it("a gap of eighty characters on the same line is found, eighty-one is not", () => {
    expect(
      ruleHit(`${KEY_ID}${" ".repeat(80)}${SECRET}`, "aws-secret-near-key-id"),
    ).toBe(true);
    expect(
      ruleHit(`${KEY_ID}${" ".repeat(81)}${SECRET}`, "aws-secret-near-key-id"),
    ).toBe(false);
  });

  it("the same bound applies to the next line", () => {
    expect(
      ruleHit(
        `${KEY_ID}\n${" ".repeat(80)}${SECRET}`,
        "aws-secret-near-key-id",
      ),
    ).toBe(true);
    expect(
      ruleHit(
        `${KEY_ID}\n${" ".repeat(81)}${SECRET}`,
        "aws-secret-near-key-id",
      ),
    ).toBe(false);
  });

  // The secret is exactly forty characters: a forty-first base64 character on
  // the end is part of a longer run, not a secret.
  it("a run of forty-one base64 characters is not a secret", () => {
    expect(ruleHit(`${KEY_ID},${SECRET}Q`, "aws-secret-near-key-id")).toBe(
      false,
    );
  });

  it.each([
    [
      `${KEY_ID},${"0123456789abcdef".repeat(2)}abcdef01`,
      "a git commit id, lower case hex",
    ],
    [
      `${KEY_ID},${"wJ4rXUt0nFEM9K7MDENG2bPxRfiCYqZ8nMLVAa3"}`,
      "thirty-nine characters",
    ],
    [
      `${KEY_ID},${"wJ4rXUt0nFEM9K7MDENG2bPxRfiCYqZ8nMLVA"}`,
      "a secret without a digit in it",
    ],
    [
      `${KEY_ID},${"WJ4RXUT0NFEM9K7MDENG2BPXRFICYQZ8NMLVAA3"}`,
      "a secret without a lower case letter",
    ],
    [
      `${KEY_ID}${" ".repeat(3)}${"x".repeat(40)}`,
      "forty characters of one letter",
    ],
  ])("%s is not found (%s)", (text) => {
    expect(ruleHit(text, "aws-secret-near-key-id")).toBe(false);
  });

  // AWS's documentation key ends with EXAMPLE, and its secret is documentation
  // too. The rule reads the key ID's tail, as the key rule does.
  it("a documented Access Key ID that ends in EXAMPLE is not a finding", () => {
    expect(
      ruleHit(`AKIA${"IOSFODNN7"}EXAMPLE\n${SECRET}`, "aws-secret-near-key-id"),
    ).toBe(false);
  });

  it("a key ID without a secret beside it is not a finding", () => {
    expect(ruleHit(`${KEY_ID} is the key`, "aws-secret-near-key-id")).toBe(
      false,
    );
  });
});

// ── Docker Hub personal access token ──────────────────────────────────────────

describe("a Docker Hub personal access token", () => {
  it.each([
    [`docker login -u chatalab -p ${DOCKER_PAT}`, "a docker login"],
    [
      `dckr_pat_${mixed(27)}`,
      "exactly twenty-seven characters after the prefix",
    ],
    [`dckr_pat_${mixed(40)}`, "a longer token"],
    [`"token": "dckr_pat_${mixed(27)}_x"`, "in JSON, with an underscore"],
  ])("%s is found (%s)", (text) => {
    expect(ruleHit(text, "docker-hub-pat")).toBe(true);
  });

  it.each([
    [`dckr_pat_${mixed(26)}`, "one character under the length"],
    ["dckr_pat_", "the prefix alone"],
    [`mydckr_pat_${mixed(27)}`, "the prefix is not at a word boundary"],
  ])("%s is not found (%s)", (text) => {
    expect(ruleHit(text, "docker-hub-pat")).toBe(false);
  });
});

// ── Telegram bot token in a URL ──────────────────────────────────────────────

describe("a Telegram bot token written after bot in a URL", () => {
  const TOKEN = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";

  it.each([
    [`https://api.telegram.org/bot${TOKEN}/getMe`, "a getMe URL"],
    [`https://api.telegram.org/bot${TOKEN}`, "a URL ending at the token"],
    [TOKEN, "the token on its own"],
  ])("%s is found (%s)", (text) => {
    expect(ruleHit(text, "telegram-bot-token")).toBe(true);
  });

  // The `:AA` requirement is the shape Telegram issues, and it still holds
  // after bot: a number written after bot without it is not a token.
  it.each([
    [
      "https://api.telegram.org/bot123456789:BBHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/getMe",
      "not AA",
    ],
    ["robot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", "robot is not bot"],
  ])("%s is not found (%s)", (text) => {
    expect(ruleHit(text, "telegram-bot-token")).toBe(false);
  });
});

// ── connection strings with no user name ─────────────────────────────────────

describe("a connection string with an empty user name", () => {
  it.each([
    [
      "redis://:4yBnLzQgJuCkCCJsJ7@cache-03.northgate-data.io:6379/0",
      "redis with no user",
    ],
    ["mongodb://:Xk2p9QmR7t@cluster0.example.net/db", "mongodb with no user"],
    ["postgres://:Xk2p9QmR7t@db.internal/app", "postgres with no user"],
  ])("%s is found (%s)", (text) => {
    expect(ruleHit(text, "connection-string")).toBe(true);
  });

  it.each([
    ["redis://:@cache-03.northgate-data.io:6379/0", "no user and no password"],
    ["redis://cache-03.northgate-data.io:6379/0", "no credentials at all"],
  ])("%s is not found (%s)", (text) => {
    expect(ruleHit(text, "connection-string")).toBe(false);
  });
});

// ── an AWS account ID in an ARN is not a My Number ───────────────────────────

describe("a twelve-digit AWS account ID in an ARN", () => {
  it.each([
    ["arn:aws:iam::835997400938:role/ci-deployer", "an IAM role"],
    ["arn:aws:sns:us-east-1:835997400938:topic", "an SNS topic"],
    ["arn:aws-cn:s3:cn-north-1:835997400938:bucket", "a partition with a dash"],
  ])("%s is not a My Number (%s)", (text) => {
    expect(ruleHit(text, "pii-mynumber-jp")).toBe(false);
  });

  // The same digits outside an ARN are still a number, so the exemption is for
  // the account's place in an ARN and not for the digits.
  it("the same twelve digits outside an ARN are still found", () => {
    expect(ruleHit("account 835997400938 is ours", "pii-mynumber-jp")).toBe(
      true,
    );
  });
});

// ── IBAN, international phone numbers, UK National Insurance numbers ──────────

describe("an IBAN", () => {
  it.each([
    ["DE89 3704 0044 0532 0130 00", "German, grouped in fours"],
    ["GB82WEST12345698765432", "British, unspaced"],
    ["DE89370400440532013000", "German, unspaced"],
    ["IBAN: GB82 WEST 1234 5698 7654 32.", "after a label, before a full stop"],
    ["(DE89 3704 0044 0532 0130 00)", "inside parentheses"],
    ['{"iban": "DE89370400440532013000"}', "inside JSON"],
    ["IL17 0108 0000 0001 2612 345", "a country not in the length table"],
  ])("%s is found (%s)", (text) => {
    expect(ruleHit(text, "pii-iban")).toBe(true);
  });

  // The check digits are 89 for the German number. Changing the first of them
  // to 88 leaves the mod-97 remainder at other than one.
  it.each([
    ["DE88 3704 0044 0532 0130 00", "one check digit changed"],
    ["DE89 3704 0044 0532 0130 0", "one character short for Germany"],
    ["DE89 3704 0044 0532 0130 001", "one character long for Germany"],
    ["AA12 3456 7890 1234 5678", "a country with no check that passes"],
    ["XX82WEST12345698765432", "a two-letter prefix that is not a country"],
  ])("%s is not found (%s)", (text) => {
    expect(ruleHit(text, "pii-iban")).toBe(false);
  });
});

describe("an international phone number", () => {
  it.each([
    ["+49 151 85280948", "German"],
    ["+33 6 22 81 96 59", "French"],
    ["+55 11 98206-4442", "Brazilian, hyphen"],
    ["+91 90848 57208", "Indian"],
    ["+61 477 715 965", "Australian"],
    ["+81 90-9384-1967", "Japanese, hyphens"],
    ["+44 7801 997035", "British"],
    ["+52 55 4268 5070", "Mexican"],
    ["+4915112345678", "unspaced"],
    ["call +49 151 85280948 now", "inside a sentence"],
    ["(+49 151 85280948)", "inside parentheses"],
    ['"phone": "+49.151.85280948"', "dotted, inside JSON"],
  ])("%s is found (%s)", (text) => {
    expect(ruleHit(text, "pii-phone-intl")).toBe(true);
  });

  it.each([
    ["+0000", "a time zone"],
    ["+2026-10-09", "a date: eight digits, one under the minimum"],
    ["+12.5%", "a number with a leading one, which is the US rule's"],
    ["version +3.2.1", "a version: three digits"],
    ["a+44 7801 997035", "a letter directly before the plus"],
    ["1+44 7801 997035", "a digit directly before the plus"],
    ["diff: + 123", "a plus with a space after it"],
    ["+11 111 111 111", "every digit the same, which is a placeholder"],
  ])("%s is not found (%s)", (text) => {
    expect(ruleHit(text, "pii-phone-intl")).toBe(false);
  });

  // The digit count is nine to fifteen. Eight is under the bottom edge and
  // sixteen is over the top one.
  it.each([
    ["+4 1234567", false, "eight digits, counted with the country code"],
    ["+4 12345678", true, "nine digits"],
    ["+49 123456789012", true, "fourteen digits"],
    ["+49 1234567890123", true, "fifteen digits"],
    ["+49 12345678901234", false, "sixteen digits"],
  ])("the boundary %s is found: %s (%s)", (text, expected, label) => {
    expect(ruleHit(text, "pii-phone-intl"), label).toBe(expected);
  });
});

describe("a UK National Insurance number", () => {
  it.each([
    ["NI: RE 62 91 56 A", "RE, suffix A"],
    ["CS 45 74 46 B", "CS, suffix B"],
    ["AB 12 34 56 C", "AB, suffix C"],
    ["(CE 12 34 56 D)", "suffix D inside parentheses"],
  ])("%s is found (%s)", (text) => {
    expect(ruleHit(text, "pii-nino-uk")).toBe(true);
  });

  // The first letter cannot be D, F, I, Q, U or V; the second cannot be D, F,
  // I, O, Q, U or V; the prefix cannot be one of the reserved pairs; and the
  // suffix is A to D.
  it.each([
    ["DA 12 34 56 A", "first letter D"],
    ["FA 12 34 56 A", "first letter F"],
    ["IA 12 34 56 A", "first letter I"],
    ["QA 12 34 56 A", "first letter Q"],
    ["UA 12 34 56 A", "first letter U"],
    ["VA 12 34 56 A", "first letter V"],
    ["RD 12 34 56 A", "second letter D"],
    ["RO 12 34 56 A", "second letter O"],
    ["BG 12 34 56 A", "prefix BG"],
    ["GB 12 34 56 A", "prefix GB"],
    ["KN 12 34 56 A", "prefix KN"],
    ["NK 12 34 56 A", "prefix NK"],
    ["NT 12 34 56 A", "prefix NT"],
    ["TN 12 34 56 A", "prefix TN"],
    ["ZZ 12 34 56 A", "prefix ZZ"],
    ["RE 62 91 56 E", "suffix E"],
    ["RE 62 91 56", "no suffix"],
  ])("%s is not found (%s)", (text) => {
    expect(ruleHit(text, "pii-nino-uk")).toBe(false);
  });

  // The rule covers the spaced form only: without the spaces the same letters
  // and digits are too common in identifiers to read as a number.
  it("the unspaced form is not found", () => {
    expect(ruleHit("RE629156A", "pii-nino-uk")).toBe(false);
  });
});

describe("a US phone number judged by its area code and exchange", () => {
  it.each([
    ["call (415) 867-5309", "a real-looking area code"],
    ["(212) 555-0300", "a 555 exchange on a line outside 0100 to 0199"],
    ["(415) 867-5309", "ordinary"],
  ])("%s is found (%s)", (text) => {
    expect(ruleHit(text, "pii-phone-us")).toBe(true);
  });

  it.each([
    ["(555) 867-5309", "area code 555 is not allocated"],
    ["(212) 555-0100", "555 exchange, line 0100"],
    ["(212) 555-0199", "555 exchange, line 0199, the top of the range"],
    ["(212) 555-1212", "directory assistance"],
    ["1-800-555-1212", "a toll-free area code"],
    ["(800) 123-4567", "toll-free 800"],
    ["(888) 123-4567", "toll-free 888"],
    ["(833) 123-4567", "toll-free 833"],
  ])("%s is not found (%s)", (text) => {
    expect(ruleHit(text, "pii-phone-us")).toBe(false);
  });

  it("line 0200 is outside the fiction range", () => {
    expect(ruleHit("(212) 555-0200", "pii-phone-us")).toBe(true);
  });
});

// The test card numbers Stripe publishes. A developer pasting one of them is
// not leaking anything, and each one passes Luhn, so the list is what keeps
// them quiet.
describe("published test card numbers", () => {
  it.each([
    "4242424242424242",
    "4000000000000002",
    "4000056655665556",
    "5555555555554444",
    "2223003122003222",
    "5200828282828210",
    "5105105105105100",
    "378282246310005",
    "371449635398431",
    "6011111111111117",
    "36227206271667",
    "6200000000000005",
    "4111111111111111",
    "4012888888881881",
  ])("%s is not found as a card", (number) => {
    expect(ruleHit(`card ${number}`, "pii-credit-card")).toBe(false);
  });

  // A card that passes Luhn and is not on the list is still a card, so the
  // list is not a way to get any number past the rule.
  it("a Luhn-valid number that is not published test data is found", () => {
    expect(ruleHit("card 2221000000000009", "pii-credit-card")).toBe(true);
  });
});

// Source code names a password without holding one. A call, an attribute read
// or a bare identifier after `password =` or `password:` is the code, and the
// rules that read a label off a value must not block it. Quoted values and the
// `is` and Japanese forms keep being found: their value is written out.
describe("code that names a password is not a password", () => {
  it.each([
    ["password = hash_password(raw)", "a call"],
    ['password = getpass("Enter password: ")', "a call with a prompt"],
    ['password=os.environ.get("DB_PASSWORD")', "an attribute call"],
    ["pwd = os.getcwd()", "pwd assigned from a call"],
    ["password: z.string().min(8),", "a schema call"],
    ["pw = self.pw_hash(salt+raw)", "a method call"],
    ["password = new_password", "a bare identifier"],
    ["password: form.password2", "a dotted identifier"],
    ["password: string | null;", "a type annotation"],
    ["if password == confirm_password:", "a comparison"],
  ])("%s is not a password (%s)", (text) => {
    expect(ruleHit(text, "password-prose")).toBe(false);
  });

  it.each([
    ['password = "Summer2024!"', "quoted, after ="],
    ['password = "hunter2"', "quoted identifier-shaped value"],
    ['password = "Summer(2024)"', "quoted, with parentheses in it"],
    ["my password is Summer2024", "is form, identifier-shaped"],
    ["password: hunter2!x", "a symbol makes it a value, not an identifier"],
    ["パスワードは Abc123!x です", "Japanese form"],
  ])("%s is a password (%s)", (text) => {
    expect(ruleHit(text, "password-prose")).toBe(true);
  });

  // The cost of the identifier check, written out: an unquoted identifier after
  // a colon or an equals sign is refused, so `password: hunter2` is not found.
  // A value with a symbol or in quotes is the way to write one that is.
  it("an unquoted identifier after a colon is not found", () => {
    expect(ruleHit("password: hunter2", "password-prose")).toBe(false);
  });

  it.each([
    ['--password=os.environ.get("DB_PASSWORD")', "a call on the value"],
    ["--password getpass()", "a call with no argument"],
  ])("%s is not a password on a command line (%s)", (text) => {
    expect(ruleHit(text, "password-cli-flag")).toBe(false);
  });

  // The shapes of code and of prose that a value can take after the word: a
  // Ruby symbol or instance variable, a method chain that starts with a word,
  // a GraphQL type, and a value written in backticks in a comment.
  it.each([
    ["password: :ContentChecker::MAX_LENGTH", "a Ruby symbol"],
    ["password = @user_data", "a Ruby instance variable"],
    ["passwd = same_pair.group(2).lower()", "a method call on a name"],
    ["password = 4.times.map", "a method chain that starts with a number"],
    ["password: String!", "a GraphQL non-null type"],
    ["the `password is required` check", "a backticked phrase, not a value"],
  ])("%s is not a password (%s)", (text) => {
    expect(ruleHit(text, "password-prose")).toBe(false);
  });

  // A password with a digit and a bang is still a password. A type name is
  // letters only, so the GraphQL refusal does not reach it.
  it("a password with a digit before its bang is found", () => {
    expect(ruleHit("password: Summer2024!", "password-prose")).toBe(true);
  });

  it("a netrc password line that is a call is not a password", () => {
    expect(
      ruleHit('  password os.environ.get("DB_PASSWORD")', "password-netrc"),
    ).toBe(false);
  });
});

// The HTTP Basic documentation examples: the pairs every tutorial uses. Both
// halves on the list makes the pair an example. A real pair with one half off
// the list is still a credential.
describe("an HTTP Basic example that tutorials use", () => {
  it.each([
    ["Authorization: Basic dXNlcjpwYXNz", "user:pass"],
    ["Authorization: Basic YWRtaW46cGFzc3dvcmQ=", "admin:password"],
  ])("%s is not found (%s)", (text) => {
    expect(ruleHit(text, "http-basic-auth")).toBe(false);
  });

  it.each([
    [
      "Authorization: Basic YWRtaW46WGs5bVAycVI3dg==",
      "admin:Xk9mP2qR7v, a real password",
    ],
    [
      "Authorization: Basic cm9vdDpYazltUDJxUjd2",
      "root:Xk9mP2qR7v, a real password",
    ],
  ])("%s is found (%s)", (text) => {
    expect(ruleHit(text, "http-basic-auth")).toBe(true);
  });
});

// The body of a regex's first capturing group: the text between its own
// parentheses, with escapes and character classes skipped over.
function firstCaptureBody(source: string): string {
  const open: { capturing: boolean; start: number }[] = [];
  let inClass = false;
  for (let i = 0; i < source.length; i++) {
    const ch = source[i];
    if (ch === "\\") i++;
    else if (inClass) {
      if (ch === "]") inClass = false;
    } else if (ch === "[") inClass = true;
    else if (ch === "(")
      open.push({ capturing: source[i + 1] !== "?", start: i + 1 });
    else if (ch === ")") {
      const group = open.pop();
      if (group?.capturing) return source.slice(group.start, i);
    }
  }
  throw new Error("no capturing group in the regex");
}

// pii-date-of-birth writes its date alternation twice: in the rule's regex, as
// the first capturing group, and in its cellRegex, which judges a labelled cell.
// The two are the same pattern, and this keeps them from drifting apart.
describe("the date-of-birth cell pattern is the rule's capture group", () => {
  const rule = DEFAULT_RULES.find((r) => r.id === "pii-date-of-birth");

  it("the rule has a cell pattern to compare", () => {
    expect(rule?.cellRegex).toBeTruthy();
  });

  it("the cell pattern is exactly the body of the regex's first capturing group", () => {
    expect(rule).toBeDefined();
    expect(rule?.cellRegex).toBe(firstCaptureBody(rule?.regex ?? ""));
  });
});

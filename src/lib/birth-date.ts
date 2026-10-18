// Date of birth, as the birth-date validator reads it: the calendar dates a
// captured text can mean, with the era, kanji and placeholder rules. Lives
// apart from validators.ts so that the date forms have one place to change.

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

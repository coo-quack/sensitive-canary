import { describe, expect, it } from "vitest";
import { scan } from "../rules.ts";
import { ruleIds } from "./rule-fixtures.ts";

// Each table is the street types, units and road suffixes that docs/rules.md lists
// for one rule, and each row is one value a real address writes with that word. A
// word dropped from a rule's list, or a first-character gate that stops admitting
// it, fails the row for that word. Every value is fictional.

const valueAt = (line: string, ruleId: string): string | undefined =>
  scan(line).find((f) => f.ruleId === ruleId)?.secretValue;

describe("every French street type is read", () => {
  const TYPES = [
    "rue",
    "avenue",
    "av.",
    "boulevard",
    "bd",
    "bd.",
    "bvd",
    "chemin",
    "ch.",
    "place",
    "pl.",
    "allée",
    "allee",
    "impasse",
    "imp.",
    "quai",
    "cours",
    "passage",
    "chaussée",
    "faubourg",
    "sentier",
    "promenade",
    "esplanade",
    "lotissement",
    "hameau",
    "résidence",
    "parvis",
    "rond-point",
    "cité",
    "route",
    "rte",
  ];
  it.each(TYPES)("%s", (type) => {
    expect(ruleIds(`12 ${type} de la Paix, 75002 Paris`)).toContain(
      "pii-address-fr",
    );
  });
  it.each(TYPES)("%s in capitals", (type) => {
    expect(
      ruleIds(`12 ${type.toUpperCase()} DE LA PAIX, 75002 PARIS`),
    ).toContain("pii-address-fr");
  });
});

describe("every Italian street type is read", () => {
  const TYPES = [
    "Via",
    "Viale",
    "V.le",
    "Piazza",
    "P.zza",
    "P.za",
    "Piazzale",
    "P.le",
    "Piazzetta",
    "Corso",
    "C.so",
    "Largo",
    "Vicolo",
    "Strada",
    "Borgo",
    "Contrada",
    "C.da",
    "Lungomare",
    "Lungarno",
    "Lungotevere",
    "Galleria",
    "Salita",
    "Calata",
    "Traversa",
    "Vico",
    "Località",
    "Loc.",
    "Frazione",
    "Fraz.",
    "Circonvallazione",
  ];
  it.each(TYPES)("%s", (type) => {
    expect(ruleIds(`${type} Roma 12, 00100 Roma`)).toContain("pii-address-it");
  });
  it.each(TYPES)("%s in capitals", (type) => {
    expect(ruleIds(`${type.toUpperCase()} ROMA 12, 00100 ROMA`)).toContain(
      "pii-address-it",
    );
  });
  it("lower-case via, which is also English prose, is read only with a capitalised name", () => {
    expect(ruleIds("via Roma 12, 00100 Roma")).toContain("pii-address-it");
  });
});

describe("every German street form is read", () => {
  // Compounds: the suffix is the end of one word.
  const COMPOUNDS = [
    "straße",
    "strasse",
    "str.",
    "weg",
    "platz",
    "allee",
    "gasse",
    "ring",
    "damm",
    "ufer",
    "steig",
    "stieg",
    "chaussee",
    "promenade",
    "markt",
    "hof",
    "pfad",
    "wall",
    "graben",
    "berg",
    "winkel",
    "anger",
    "kamp",
    "redder",
    "twiete",
    "zeile",
  ];
  it.each(COMPOUNDS)("a compound ending in %s", (suffix) => {
    expect(ruleIds(`Ahorn${suffix} 12, 10115 Berlin`)).toContain(
      "pii-address-de",
    );
  });

  // A name and a separate type word.
  const TYPE_WORDS = [
    "Straße",
    "Strasse",
    "Str.",
    "Weg",
    "Platz",
    "Allee",
    "Gasse",
    "Ring",
    "Damm",
    "Ufer",
    "Chaussee",
    "Markt",
    "Promenade",
    "Steig",
    "Stieg",
    "Wall",
    "Graben",
    "Zeile",
  ];
  it.each(TYPE_WORDS)("a name and the type word %s", (type) => {
    expect(ruleIds(`Berliner ${type} 5, 10115 Berlin`)).toContain(
      "pii-address-de",
    );
  });

  // A type word with a genitive.
  it.each([
    "Straße des 17. Juni 135",
    "Platz der Republik 1",
    "Weg zum Sportplatz 3",
    "Ring am Park 2",
    "Straße an der Mauer 4",
    "Platz unter den Linden 5",
    "Straße zur Ahornallee 6",
  ])("a genitive: %s", (street) => {
    expect(ruleIds(`${street}, 10115 Berlin`)).toContain("pii-address-de");
  });

  // A preposition or an adjective and a name.
  it.each([
    "Am Markt 3",
    "An der Alster 4",
    "An den Linden 5",
    "Auf dem Hügel 6",
    "Auf der Heide 7",
    "Im Hof 8",
    "In der Aue 9",
    "Unter den Linden 10",
    "Zum Bach 11",
    "Zur Brücke 12",
    "Hinter dem Haus 13",
    "Bei der Kirche 14",
    "Vor dem Tor 15",
    "Alter Markt 16",
    "Alte Post 17",
    "Neuer Wall 18",
    "Neue Mühle 19",
    "Große Bleichen 20",
    "Grosse Gasse 21",
    "Kleine Gasse 22",
    "Obere Straße 23",
    "Untere Straße 24",
    "Lange Reihe 25",
    "Breite Straße 26",
    "Hohe Brücke 27",
  ])("a preposition or adjective: %s", (street) => {
    expect(ruleIds(`${street}, 10115 Berlin`)).toContain("pii-address-de");
  });
});

describe("every Spanish street type is read", () => {
  const TYPES = [
    "calle",
    "c/",
    "avenida",
    "avda.",
    "avda",
    "av.",
    "plaza",
    "pza.",
    "pza",
    "plza.",
    "pl.",
    "paseo",
    "pº",
    "p.º",
    "p°",
    "carretera",
    "ctra.",
    "ctra",
    "camino",
    "cno.",
    "ronda",
    "rda.",
    "travesía",
    "travesia",
    "trav.",
    "glorieta",
    "gta.",
    "urbanización",
    "urbanizacion",
    "urb.",
    "polígono",
    "poligono",
    "pol.",
    "rambla",
    "bulevar",
    "vía",
    "pasaje",
    "cuesta",
    "plazuela",
    "callejón",
    "callejon",
    "paraje",
  ];
  it.each(TYPES)("%s", (type) => {
    expect(ruleIds(`${type} Mayor 3, 28013 Madrid`)).toContain(
      "pii-address-es",
    );
  });
  it.each(TYPES)("%s in capitals", (type) => {
    expect(ruleIds(`${type.toUpperCase()} MAYOR 3, 28013 MADRID`)).toContain(
      "pii-address-es",
    );
  });
});

describe("every Chinese unit and road suffix is read", () => {
  it.each([
    ["北京市海淀区中关村路1号", "路"],
    ["北京市海淀区中关村大街1号", "街"],
    ["北京市海淀区天府道1号", "道"],
    ["北京市东城区史家胡同24号", "胡同"],
    ["上海市黄浦区西康巷5号", "巷"],
    ["上海市虹口区西康南弄34号", "弄"],
    ["成都市武侯区天府大道北段1700号", "段"],
  ])("a road ending in %s: %s", (line) => {
    expect(ruleIds(line)).toContain("pii-address-cn");
  });

  it.each([
    ["北京市海淀区中关村大街1号", "市 and 区"],
    ["江苏省扬州市宝应县泰山路102号", "县"],
    ["内蒙古自治区鄂托克旗敖勒召其镇团结路1号", "旗 and 镇"],
    ["内蒙古自治区锡林郭勒盟正蓝旗中心街1号", "盟 and 旗"],
    ["浙江省杭州市余杭区良渚镇古墩路1号", "镇"],
    ["河南省南阳市唐河县昝岗乡中州路42号", "乡"],
    ["北京市朝阳区三里屯街道工体北路8号", "街道"],
  ])("a unit: %s (%s)", (line) => {
    expect(ruleIds(line)).toContain("pii-address-cn");
  });
});

describe("every Korean sido, unit, road and lot form is read", () => {
  it.each([
    "서울특별시",
    "서울시",
    "서울",
    "부산광역시",
    "부산시",
    "대구광역시",
    "대구시",
    "인천광역시",
    "인천시",
    "광주광역시",
    "광주시",
    "대전광역시",
    "대전시",
    "울산광역시",
    "울산시",
    "세종특별자치시",
    "세종시",
    "경기도",
    "경기",
    "강원특별자치도",
    "강원도",
    "충청북도",
    "충북",
    "충청남도",
    "충남",
    "전라북도",
    "전북특별자치도",
    "전북",
    "전라남도",
    "전남",
    "경상북도",
    "경북",
    "경상남도",
    "경남",
    "제주특별자치도",
    "제주도",
  ])("the sido %s", (sido) => {
    expect(ruleIds(`${sido} 강남구 테헤란로 123`)).toContain("pii-address-kr");
  });

  it.each([
    ["경기도 성남시 분당구 판교역로 166", "시 and 구"],
    ["경기도 가평군 청평면 대성리 산 123", "군 and 면, with a lot"],
    ["서울특별시 강남구 테헤란로 123", "구 and 로"],
    ["서울특별시 금천구 시흥길 70", "길"],
    ["서울특별시 강남구 강남대로 12번길 3", "번길"],
    ["서울특별시 강남구 강남대로 1안길 2", "안길"],
    ["서울특별시 강남구 강남대로 45길 6", "NN길"],
    ["서울특별시 강남구 강남대로 45", "대로"],
    ["서울특별시 강남구 역삼동 123", "동"],
    ["경기도 가평군 청평면 대성리 123", "리"],
  ])("%s (%s)", (line) => {
    expect(ruleIds(line)).toContain("pii-address-kr");
  });
});

describe("the year guard", () => {
  it.each([
    "2024 rue de la Paix, 75002 Paris",
    "1999 rue de la Paix, 75002 Paris",
  ])("a year is not a French house number: %s", (line) => {
    expect(ruleIds(line)).not.toContain("pii-address-fr");
  });
  it.each(["Hauptstraße 2024, 10115 Berlin", "Hauptstraße 1999, 10115 Berlin"])(
    "a year is not a German house number: %s",
    (line) => {
      expect(ruleIds(line)).not.toContain("pii-address-de");
    },
  );
  it("a three-digit or a two-digit number that starts like a year is a house number", () => {
    expect(ruleIds("202 rue de la Paix, 75002 Paris")).toContain(
      "pii-address-fr",
    );
    expect(ruleIds("Hauptstraße 202, 10115 Berlin")).toContain(
      "pii-address-de",
    );
  });
});

describe("the town ends at the last capitalised word", () => {
  it("a lower-case word after the town ends it", () => {
    expect(
      valueAt("5 rue de Rivoli, 75001 Paris pour le concert", "pii-address-fr"),
    ).toBe("5 rue de Rivoli, 75001 Paris");
  });
  it.each([
    ["12 rue de la Paix, 75002 Paris Cedex 08", "pii-address-fr"],
    ["Berliner Straße 5, 60311 Frankfurt am Main", "pii-address-de"],
    ["Corso Italia 7, 42100 Reggio d'Emilia", "pii-address-it"],
    ["Calle Mayor 3, 28013 Monte de Pozuelo", "pii-address-es"],
  ])("a town joined by a particle or Cedex is taken whole: %s", (line, id) => {
    expect(valueAt(line, id)).toBe(line);
  });
});

describe("a currency or a unit is not a town", () => {
  it.each([
    ["Am Ende 3, 10000 Euro Berlin", "pii-address-de"],
    ["Am Ende 3, 10000 EUR Berlin", "pii-address-de"],
    ["Calle Mayor 3, 10000 Pesos Mexico", "pii-address-es"],
    ["Via Roma 12, 10000 Euros Milano", "pii-address-it"],
    ["Hauptstraße 12, 10000 Franken Bern", "pii-address-de"],
    ["Hauptstraße 12, 10000 Dollars New", "pii-address-de"],
    ["12 rue de la Paix, 75002 Euros Paris", "pii-address-fr"],
  ])("%s is not found", (line, id) => {
    expect(ruleIds(line)).not.toContain(id);
  });
});

describe("the Chinese value starts at the place name", () => {
  it.each([
    ["我在北京市海淀区中关村大街1号工作", "北京市海淀区中关村大街1号"],
    [
      "我住在上海市虹口区西康南路125弄34号201室",
      "上海市虹口区西康南路125弄34号201室",
    ],
    ["位于海淀区中关村大街1号", "海淀区中关村大街1号"],
    ["请寄到广东省深圳市南山区科苑路15号", "广东省深圳市南山区科苑路15号"],
  ])("%s is found as %s", (line, value) => {
    expect(valueAt(line, "pii-address-cn")).toBe(value);
  });
});

describe("a courtyard or wing needs no number in German", () => {
  it.each([
    "Hauptstraße 12, Hinterhaus, 10115 Berlin",
    "Hauptstraße 12, Vorderhaus, 10115 Berlin",
    "Hauptstraße 12, Seitenflügel, 10115 Berlin",
    "Hauptstraße 12, Gartenhaus, 10115 Berlin",
    "Hauptstraße 12, Hinterhaus 2, 10115 Berlin",
  ])("%s", (line) => {
    expect(ruleIds(line)).toContain("pii-address-de");
  });
});

// Generates the six European and Asian postal-address rules in
// src/lib/default-config.json. Each regex is built from named pieces (street
// types, units, gaps) so that a list of words is written once and every
// first-character gate is derived from it.
//
//   node scripts/address-rules.mjs            print the six rule objects as JSON
//   node scripts/address-rules.mjs --write    replace the six entries in default-config.json
//
// The six entries must be the last entries of the config's `rules` array; --write
// refuses to run otherwise. src/lib/__tests__/address-rules.test.ts fails when the
// config and this script disagree, so edit the script and run --write, never the JSON.
//
// Plain Node ESM with no dependencies; the file is not in the published package.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
const cap = (w) => w[0].toUpperCase() + w.slice(1);
const variants = (words) => [...new Set(words.flatMap((w) => [w, cap(w), w.toUpperCase()]))];
// The variants as a trie on the first character: each letter is tried once,
// not once per word (a flat list of 40 words costs 40 tries at every capital).
const trie = (words) => {
  const groups = new Map();
  let empty = false;
  for (const w of new Set(words)) {
    if (w === "") { empty = true; continue; }
    const c = [...w][0];
    if (!groups.has(c)) groups.set(c, []);
    groups.get(c).push(w.slice(c.length));
  }
  const alts = [...groups].map(([c, tails]) => esc(c) + (tails.length === 1 ? esc(tails[0]) : `(?:${trie(tails)})`));
  if (empty) alts.push("");
  return alts.join("|");
};
const cases = (words) => {
  const v = variants(words);
  const firsts = [...new Set(v.map((w) => w[0]))].map(esc).join("");
  return `(?=[${firsts}])(?:${trie(v)})`;
};

// Atomic run: a lookahead captures the greedy run and a backreference consumes it,
// so the engine never backs off into it. Each run here has one possible end (the
// next character is a unit suffix, a road suffix, a digit or a space), so the
// matches are the same and the retreat is gone.
let groupSeq = 0;
const atomic = (run) => {
  const name = `a${groupSeq++}`;
  return `(?=(?<${name}>${run}))\\k<${name}>`;
};

// ── shared pieces ────────────────────────────────────────────────────────────
const TOWN = "\\p{Lu}(?:[\\p{L}'’.-]+|(?=[ \\t]\\p{Lu}))(?:[ \\t][\\p{L}'’.()-]+){0,3}";
// Latin letters only. `\\p{L}` in a lookbehind costs ~4 ms per 200k characters; the explicit
// ranges cost ~0.6 ms. The address rules read Latin letters for the European countries.
const START = "(?<![A-Za-zÀ-ÖØ-öø-ɏ\\d/.-])";
const NOT_YEAR = "(?!(?:19|20)\\d{2}(?!\\d))";
const HOUSE_NO =
  "(?!(?:19|20)\\d{2}(?!\\d))\\d{1,4}(?:\\s?[a-zA-Z](?![\\p{L}\\d])|\\s?(?:bis|ter|BIS|TER)(?![\\p{L}]))?(?:\\s?[-–/]\\s?\\d{1,4}(?:[a-zA-Z](?![\\p{L}\\d]))?)?(?!\\d)";
const postal = (range) => `(?<![\\d-])(?:${range})(?!\\d)\\s{1,2}`;
// A name is words separated by single spaces, each word a run of non-separator
// characters. The run stops at the first comma, digit or space, so the number
// that follows is found without walking the name a character at a time.
// Each call makes fresh atomic groups, since a group name may appear once in a pattern.
const nameWords = (excluded = "\\s,;|\\d") =>
  `${atomic(`\\p{L}[^${excluded}]{0,20}`)}(?:\\s${atomic(`\\p{L}[^${excluded}]{0,20}`)}){0,4}`;

// ── France ───────────────────────────────────────────────────────────────────
const FR_TYPES = cases([
  "rue", "avenue", "av.", "boulevard", "bd", "bd.", "bvd", "chemin", "ch.",
  "place", "pl.", "allée", "allee", "impasse", "imp.", "quai", "cours",
  "passage", "chaussée", "faubourg", "sentier", "promenade", "esplanade",
  "lotissement", "hameau", "résidence", "parvis", "rond-point", "cité",
]);
// The street name is a run of words that are capitalised, digits (`8 Mai 1945`) or
// a particle (`de`, `la`, `d'`). Any other lower-case word (`coûte`, `settings`)
// ends the name, so a sentence after a number is not read as a street.
const FR_START_NAME = "(?=\\s(?:\\p{Lu}|d[eu]\\s|des\\s|d['’]|l[ae]s?\\s|l['’]|aux?\\s))";
const FR_ROUTE_NAME = "(?=\\s(?:de\\s|du\\s|des\\s|d['’]|nationale|départementale|[ND]\\s?\\d))";
const FR_WORD =
  "(?:\\p{Lu}[\\p{L}'’.-]{0,30}|[0-9]{1,4}(?!\\d)|de|du|des|d['’]\\p{L}{1,30}|la|le|les|l['’]\\p{L}{1,30}|et|sur|sous|en|au|aux|à|lès|lez|nationale|départementale)";
// What may stand between the street name and the postal code: separators, and the
// tokens a French address writes there (bâtiment, appartement, escalier, étage,
// lot, boîte postale, CEDEX). Each token needs its number, so `Apt` alone is not one.
const FR_TOKEN =
  "(?:(?:[Bb]ât\\.?|[Bb]âtiment|[Aa]pt\\.?|[Aa]ppt\\.?|[Aa]ppartement|[Ee]sc\\.?|[Ee]scalier|[Éé]tage|[Ee]t\\.|[ÉéEe]t\\.|[Ll]ot|BP|CS|[Bb]oîte|[Bb]te\\.?|[Rr]ésidence)\\s?[0-9A-Za-z]{1,6}(?![\\p{L}])|(?:CEDEX|[Cc]edex)(?:\\s?[0-9]{1,2})?(?![\\p{L}]))";
const FR_GAP = `(?:[\\s,;/()\\n–-]|${FR_TOKEN}|(?:CP|C\\.P\\.|Code postal)\\s?:\\s?){0,10}?`;
const FR_HEAD = `(?:${FR_TYPES}(?![\\p{L}])${FR_START_NAME}|${cases(["route", "rte"])}${FR_ROUTE_NAME})`;
const FR_POSTAL = "(?:0[1-9]|[1-8]\\d|9[0-8])\\d{3}";
export const fr =
  `${START}${NOT_YEAR}(\\d{1,4})(?:\\s?(?:bis|ter|quater|BIS|TER|[a-zA-Z](?![\\p{L}\\d])))?,?\\s{1,2}` +
  `${FR_HEAD}(?:\\s${FR_WORD}){1,8}${FR_GAP}` +
  `${postal(FR_POSTAL)}${TOWN}`;

// ── Italy ────────────────────────────────────────────────────────────────────
const IT_TYPES_NOT_VIA = cases([
  "viale", "v.le", "piazza", "p.zza", "p.za", "piazzale", "p.le", "piazzetta",
  "corso", "c.so", "largo", "vicolo", "strada", "borgo", "contrada", "c.da",
  "lungomare", "lungarno", "lungotevere", "galleria", "salita", "calata",
  "traversa", "vico", "località", "loc.", "frazione", "fraz.",
  "circonvallazione",
]);
const IT_NAME =
  "(?:\\d{1,2}[º°]?\\s(?=\\p{Lu}))?(?=\\p{Lu}|de[il]\\s|dell[ae]\\s|degli\\s|di\\s|d['’]|dell['’])" + nameWords();
const IT_NO = "(?:n\\.|N\\.|n[°º]|N[°º]|num\\.)?\\s{0,2}";
const IT_POSTAL = "(?:[0-8]\\d|9[0-8])\\d{3}";
// Between the civic number and the CAP: separators, and an internal number, a
// staircase, a floor or a palazzo, each with its number. A free word (`times`,
// `hops`) ends the gap, so `via Jenkins 12 times, 10000 Builds` is not an address.
const IT_TOKEN = `(?:(?:${variants(["interno", "int.", "scala", "sc.", "piano", "p.", "palazzo", "blocco"]).map(esc).join("|")})\\s?[0-9A-Za-z]{1,4}(?![\\p{L}])|/[A-Za-z](?![\\p{L}\\d]))`;
// A form writes its label before the code: `CAP: 40123`.
const IT_GAP = `(?:[\\s,;/\\n–-]|${IT_TOKEN}|CAP\\s?:\\s?){0,12}?`;
export const it =
  `${START}(?:` +
  `(?:Via|VIA|${IT_TYPES_NOT_VIA})(?![\\p{L}])\\s{1,2}${IT_NAME},?\\s{0,2}${IT_NO}` +
  `|via\\s(?=\\p{Lu}\\p{Ll})${nameWords()}\\s${IT_NO}` +
  `)${HOUSE_NO}${IT_GAP}${postal(IT_POSTAL)}${TOWN}(?:\\s\\(?[A-Z]{2}\\)?(?![\\p{L}]))?`;

// ── Germany ──────────────────────────────────────────────────────────────────
const DE_SUFFIX_END =
  "(?:[sS]tra(?:ß|ss)e|[wW]eg|[pP]latz|[aA]llee|[gG]asse|[rR]ing|[dD]amm|[uU]fer|[sS]teig|[sS]tieg|[cC]haussee|[pP]romenade|[mM]arkt|[hH]of|[pP]fad|[wW]all|[gG]raben|[bB]erg|[wW]inkel|[aA]nger|[kK]amp|[rR]edder|[tT]wiete|[zZ]eile)";
const DE_TYPE_WORD =
  "(?:Straße|Strasse|Str\\.|Weg|Platz|Allee|Gasse|Ring|Damm|Ufer|Chaussee|Markt|Promenade|Steig|Stieg|Wall|Graben|Zeile)";
const DE_CAP_WORD = "\\p{Lu}[\\p{L}-]{1,30}";
// A preposition with a time word (`Am Montag 12, 10000 Anrufe Berlin`) is not a street.
const DE_TIME_WORD =
  "(?!(?:Montag|Dienstag|Mittwoch|Donnerstag|Freitag|Samstag|Sonntag|Wochenende|Abend|Morgen|Mittag|Nachmittag|Jahr|Januar|Februar|März|April|Mai|Juni|Juli|August|September|Oktober|November|Dezember)(?![\\p{L}-]))";
const DE_GAP_TOKEN =
  "(?:\\d{1,2}\\.?\\s?(?:OG|UG|EG|Stock|Etage)|(?:Hinterhaus|Vorderhaus|Hof|Haus|Aufgang|Whg\\.?|Wohnung|Eingang)\\s?[0-9A-Za-z]{1,4})(?![\\p{L}])";
// A form writes its label before the code: `PLZ: 24937`.
const DE_GAP = `(?:[\\s,;|/\\n–-]|${DE_GAP_TOKEN}|(?:PLZ|Postleitzahl)\\s?:\\s?){0,12}?`;
const DE_PIECES = {
  // a compound: the whole word is one run, and the suffix ends it after a letter
  compound: `${atomic(DE_CAP_WORD)}(?=\\s{1,2}\\d)(?<=[\\p{L}-]${DE_SUFFIX_END})`,
  strDot: `${atomic(DE_CAP_WORD)}(?<=[\\p{L}-][sS]tr)\\.(?=\\s{1,2}\\d)`,
  // one or two capitalised words and a separate type
  twoWords: `(?:${atomic(DE_CAP_WORD)}\\s){1,2}${DE_TYPE_WORD}`,
  genitive: `${DE_TYPE_WORD}\\s(?:des|der|am|zum|zur|an\\sder|unter\\sden)\\s(?:\\d{1,2}\\.\\s)?\\p{Lu}[\\p{L}-]{2,30}`,
  prep: `(?:Am|An\\sder|An\\sden|Auf\\sdem|Auf\\sder|Im|In\\sder|Unter\\sden|Zum|Zur|Hinter\\sdem|Bei\\sder|Vor\\sdem|Alter?|Alte|Neue[rs]?|Große[rn]?|Grosse[rn]?|Kleine[rn]?|Obere[rn]?|Untere[rn]?|Lange[rn]?|Breite[rn]?|Hohe[rn]?)\\s${DE_TIME_WORD}\\p{Lu}[\\p{L}-]{2,30}`,
};
const DE_STREET = `(?:${Object.values(DE_PIECES).join("|")})`;
const DE_DELIM = "[ \\t]{0,3}(?:[,;|–—\\n]|-\\s|[ \\t]{2,})";
const DE_POSTAL = "(?:D-)?(?:0[1-9]|[1-9]\\d)\\d{3}";
export const de =
  `(?=[A-ZÄÖÜẞ])${START}${DE_STREET}(?![\\p{L}])\\s{1,2}${HOUSE_NO}${DE_DELIM}${DE_GAP}${postal(DE_POSTAL)}${TOWN}`;

// ── Spain ────────────────────────────────────────────────────────────────────
const ES_TYPES = cases([
  "calle", "c/", "avenida", "avda.", "avda", "av.", "plaza", "pza.", "pza",
  "plza.", "pl.", "paseo", "pº", "p.º", "p°", "carretera", "ctra.", "ctra",
  "camino", "cno.", "ronda", "rda.", "travesía", "travesia", "trav.",
  "glorieta", "gta.", "urbanización", "urbanizacion", "urb.", "polígono",
  "poligono", "pol.", "rambla", "bulevar", "vía", "pasaje", "cuesta",
  "plazuela", "callejón", "callejon", "paraje",
]);
const ES_NAME =
  "(?:\\d{1,2}\\s(?=\\p{Lu}|de\\s))?(?=\\p{Lu}|de\\s|del\\s|l[ao]s?\\s|el\\s|d['’])" +
  `${atomic("\\p{L}[^\\s,;|\\d/]{0,20}")}(?:\\s${atomic("\\p{L}[^\\s,;|\\d/]{0,20}")}){0,4}`;
const ES_NO = "(?:n[º°]\\.?|N[º°]\\.?|n\\.[º°]|N\\.[º°]|n[úu]m\\.?|N[úu]m\\.?|número|Número|[kK]m\\.?)?\\s{0,2}";
const ES_POSTAL = "(?:0[1-9]|[1-4]\\d|5[0-2])\\d{3}";
// Between the number and the postal code: separators, and the floor, door and
// staircase forms a Spanish address writes (`3.º izda.`, `2º B`, `puerta B`, `bajo`).
const ES_KW = variants(["piso", "planta", "puerta", "bajo", "izda.", "izq.", "izquierda", "dcha.", "dch.", "derecha", "escalera", "esc.", "portal", "ático", "entresuelo", "letra"]).map(esc).join("|");
const ES_TOKEN =
  `(?:\\d{1,2}\\.?\\s?[ºª°]\\.?(?:\\s?[A-Za-z](?![\\p{L}]))?|(?:${ES_KW})(?![\\p{L}])(?:\\s?[0-9A-Za-zºª]{1,4}(?![\\p{L}]))?)`;
const ES_GAP = `(?:[\\s,;/\\n–-]|${ES_TOKEN}|(?:CP|C\\.P\\.|Código postal|Cód\\. postal)\\s?:\\s?){0,12}?`;
export const es =
  `${START}${ES_TYPES}(?![\\p{L}])\\s{0,2}${ES_NAME},?\\s{0,2}${ES_NO}` +
  `(?:${HOUSE_NO}|s/n|S/N)${ES_GAP}${postal(ES_POSTAL)}${TOWN}`;

// ── China ────────────────────────────────────────────────────────────────────
// An address starts at a province-level name, or at a city or district unit
// (市, 区, 县, 旗, 盟) that is not in the middle of a run of Han characters. A
// unit is tried at every character, so the unit start is gated on what comes
// before it: a non-Han character, or a place particle (在, 到, 于, 为, 至, 往,
// 从). Gated, the unit start costs ~4 ms on 200k Han characters; ungated it cost
// ~40 ms (`海区` repeated, each start walks a unit pair and a road).
const HAN = "\\p{sc=Han}";
const CN_PROV_FIRST = "[北天上重河山辽吉黑江浙安福湖广海四贵云陕甘青台内西宁新香澳]";
const CN_PROV =
  "(?:北京|天津|上海|重庆|河(?:北|南)|山(?:西|东)|辽宁|吉林|黑龙江|江(?:苏|西)|浙江|安徽|福建|湖(?:北|南)|广(?:东|西)|海南|四川|贵州|云南|陕西|甘肃|青海|台湾|内蒙古|西藏|宁夏|新疆|香港|澳门)(?:省|市|(?:壮族|回族|维吾尔)?自治区|特别行政区)?";
// A unit is a run of characters that are not a unit suffix, then the suffix
// (市, 区, 县, 旗, 盟, or a 镇, 乡 or 街道 under the province), so each run has one
// possible end and the atomic form never backs off into it. The list is at most
// two units: a city and a district (`北京市海淀区`), or a district and a street
// (`北京市朝阳区三里屯街道`); from a unit start, at most three.
const cnUnit = () => atomic(`(?:(?![市区县旗盟镇乡]|街道)${HAN}){1,7}`) +
  "(?:市|(?<![小社校景])(?<!(?<!工业)园)区|县|旗|盟|镇|乡|街道)";
const cnRoad = () => atomic(`(?:(?![路街道巷弄]|胡同)${HAN}){1,6}`) + "(?:路|街|道|胡同|巷|弄)(?:[东南西北中]{0,2}[一二三四五六七八九十0-9]{0,2}段)?";
// A space is allowed before the number (`南京路 35号`) and before 号 (`35 号`).
const CN_NUM =
  "\\s?(?:[0-9０-９]{1,5}弄)?[0-9０-９]{1,5}(?:[-－][0-9０-９]{1,4})?\\s?号(?![线码])" +
  "(?:[0-9０-９]{1,4}(?:号楼|栋|幢|座))?(?:[0-9０-９]{1,3}单元)?(?:[0-9０-９]{1,5}(?:室|户))?";
const CN_START_UNIT = `(?:(?<!${HAN})|(?<=[在到于为至往从]))`;
export const cn =
  `(?:(?=${CN_PROV_FIRST})${CN_PROV}(?:${cnUnit()}){0,2}|${CN_START_UNIT}${cnUnit()}(?:${cnUnit()}){0,2})` +
  `${cnRoad()}${CN_NUM}`;

// ── Korea ────────────────────────────────────────────────────────────────────
// A Korean address starts at a word: the gate stops a run of syllables from being
// tried at every position, which is what made `구` repeated cost 11 ms.
const KR_START = "(?<![가-힣])";
const KR_SIDO =
  "(?:서울(?:특별시|시)?|부산(?:광역시|시)?|대구(?:광역시|시)?|인천(?:광역시|시)?|광주(?:광역시|시)?|대전(?:광역시|시)?|울산(?:광역시|시)?|세종(?:특별자치시|시)?|경기도?|강원(?:특별자치도|도)?|충청북도|충북|충청남도|충남|전라북도|전북(?:특별자치도)?|전라남도|전남|경상북도|경북|경상남도|경남|제주(?:특별자치도|도)?)";
const HANGUL = "[가-힣]";
const KR_UNIT = `(?:${atomic(`${HANGUL}{2,9}`)}(?<=[시군구])\\s)`;
const KR_EUPMYEON = `(?:${atomic(`${HANGUL}{2,9}`)}(?<=[읍면])\\s)?`;
const KR_ADMIN =
  `(?:${KR_SIDO}\\s${KR_UNIT}{0,3}|(?:${atomic(`${HANGUL}{2,9}`)}(?<=시)\\s)?${atomic(`${HANGUL}{2,9}`)}(?<=[구군])\\s)`;
// The number ends the address unless a counter word follows it (a counter is a
// whole word: `주소` is not `주`), and a particle may be attached (`대학로 99에`).
const KR_NOT_COUNTER =
  "(?:(?![0-9가-힣])|(?=(?:에서|에|의|는|은|도|을|를|과|와|로|부터|까지|가|이)(?![가-힣])))" +
  "(?!\\s?(?:번(?!지)|호선|명|개|년|월|일|시간|분|초|원|층|호|회|대|차|배|개월|주)(?![가-힣]))";
const KR_ROAD =
  `${atomic(`${HANGUL}{2,11}`)}(?<=로|길)(?:\\s?[0-9]{1,3}(?:번|안)?길)?\\s?[0-9]{1,4}(?:-[0-9]{1,3})?${KR_NOT_COUNTER}`;
const KR_LOT =
  `${atomic(`${HANGUL}{2,9}`)}(?<=[동리가])\\s?(?:산\\s?)?[0-9]{1,4}(?:-[0-9]{1,4})?(?:번지)?${KR_NOT_COUNTER}`;
export const kr = `${KR_START}${KR_ADMIN}${KR_EUPMYEON}(?:${KR_ROAD}|${KR_LOT})`;

export const RULES = [
  { id: "pii-address-cn", description: "Chinese postal address: a province, city or district, a road and a number with 号 in sequence", regex: cn, flags: "gu", category: "pii" },
  { id: "pii-address-kr", description: "Korean postal address: a 시/도 or 구/군, then a road name (로/길) and a building number, or a 동/리 and a lot number", regex: kr, flags: "gu", category: "pii" },
  { id: "pii-address-fr", description: "French postal address: a number, a street type and name, then a postal code and a town", regex: fr, flags: "gu", category: "pii" },
  { id: "pii-address-it", description: "Italian postal address: a street type and name, a civic number, then a CAP and a town", regex: it, flags: "gu", category: "pii" },
  { id: "pii-address-de", description: "German postal address: a street and house number, then a postal code and a town", regex: de, flags: "gu", category: "pii" },
  { id: "pii-address-es", description: "Spanish postal address: a street type and name, a number, then a postal code and a town", regex: es, flags: "gu", category: "pii" },
];

const CONFIG = resolve(dirname(fileURLToPath(import.meta.url)), "../src/lib/default-config.json");

// The block layout the config uses: four spaces for the object, six for its fields.
const block = (r) =>
  ["    {", `      "id": ${JSON.stringify(r.id)},`, `      "description": ${JSON.stringify(r.description)},`,
   `      "regex": ${JSON.stringify(r.regex)},`, `      "flags": ${JSON.stringify(r.flags)},`,
   `      "category": ${JSON.stringify(r.category)}`, "    }"].join("\n");

function write() {
  const text = readFileSync(CONFIG, "utf8");
  const rules = JSON.parse(text).rules;
  const ids = RULES.map((r) => r.id);
  if (JSON.stringify(rules.slice(-ids.length).map((r) => r.id)) !== JSON.stringify(ids)) {
    throw new Error("the six address rules must be the last entries of default-config.json");
  }
  const first = text.indexOf(`    {\n      "id": "${ids[0]}"`);
  const end = text.indexOf("\n  ]\n}", first);
  writeFileSync(CONFIG, text.slice(0, first) + RULES.map(block).join(",\n") + text.slice(end));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.includes("--write")) {
    write();
  } else {
    console.log(JSON.stringify(RULES, null, 2));
  }
}

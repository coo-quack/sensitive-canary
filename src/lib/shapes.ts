// Whether a value that matched a rule is a credential after all.
//
// A rule finds a shape. These decide what the shape is standing for: a name
// that points at a secret, a slot waiting to be filled, a reference to a value
// in code. Each one waves a match through, so each is a way past every rule it
// runs over, and each is written to be narrower than the shape it answers for.

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
export const MIN_MEAN_WORD_LENGTH = 2.5;

// Short segments are words by default: `env`, `data`, `id`. The statistic needs
// something to average over before it says anything.
export const SHORTEST_MEASURABLE_SEGMENT = 8;

export function readsAsWords(segment: string): boolean {
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

// A value written to be replaced. Half of a realistic `.env.example` was being
// blocked on its contents, which is the block most likely to get the tool turned
// off — the file is meant to be committed and read.
//
// Only secret rules consult this. "todo@company.com" is a real address, and
// AWS's own documented key ends in EXAMPLE and is still a key, so `example` is
// deliberately absent from the marker list where it would matter.

// A word that only ever appears in a value nobody typed.
const PLACEHOLDER_MARKERS =
  /^(?:changeme|change|me|replace|insert|set|with|real|this|your|my|here|todo|tbd|fixme|dummy|placeholder|insecure|sample|example|test|fake|redacted|value|x{3,})$/i;

// A word that can make up the rest of such a value, but never marks one alone.
const PLACEHOLDER_FILLER =
  /^(?:api|key|keys|token|tokens|secret|secrets|password|passwd|pwd|pass|base|url|uri|host|hostname|name|user|username|id|access|refresh|client|auth|sk|pk|in|production|development|staging|local|dev|the|a|of|for|and|[0-9]+)$/i;

// The scheme is bounded: an unbounded `\w+` in front of a literal that usually
// is not there makes the match quadratic in the length of the value, and a
// value is as long as whoever wrote the text wants. A scheme is a word.
const GENERIC_CREDENTIALS =
  /\w{1,32}:\/\/(?:your[_-]?)?(?:user|username)(?:name)?:(?:your[_-]?)?(?:password|passwd|pwd)@/i;

const GENERIC_HOST =
  /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|host|hostname|db|database|example\.(?:com|org|net))\b/i;

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
  //
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

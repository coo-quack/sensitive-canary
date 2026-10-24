# Detection Rules

Sensitive Canary scans text against the following rules. Patterns are sourced from [gitleaks](https://github.com/gitleaks/gitleaks) and [TruffleHog](https://github.com/trufflesecurity/trufflehog) detector definitions.

## Secrets

### Cloud

| Rule ID | Description |
|---------|-------------|
| `aws-access-key` | AWS Access Key ID (`AKIA`, `ASIA`, `AGPA`, `AIDA`, `AROA`, … + 16 uppercase alphanumeric chars) |
| `aws-secret-near-key-id` | AWS Secret Access Key on the same line as its Access Key ID, or on the next one, within 80 characters. Forty base64 characters that mix upper case, lower case and digits. A key ID ending in `EXAMPLE` is documentation and is not matched |
| `gcp-api-key` | Google Cloud API Key (`AIza` + 35 alphanumeric/dash/underscore chars) |
| `digitalocean-pat` | DigitalOcean Personal Access Token (`dop_v1_` prefix) |
| `supabase-key` | Supabase Personal Access Token (`sbp_` prefix) |

### Source Control

| Rule ID | Description |
|---------|-------------|
| `github-pat` | GitHub Personal Access Token (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` prefix) |
| `github-fine-grained` | GitHub Fine-Grained Token (`github_pat_` prefix) |
| `gitlab-pat` | GitLab Personal Access Token (`glpat-` prefix) |

### Package Registries

| Rule ID | Description |
|---------|-------------|
| `npm-token` | npm Access Token (`npm_` prefix + 36 alphanumeric chars) |

### AI Services

| Rule ID | Description |
|---------|-------------|
| `openai-key` | OpenAI API Key — legacy format (`sk-` + 48 chars) |
| `openai-project-key` | OpenAI Project API Key (`sk-proj-` prefix, entropy-filtered) |
| `anthropic-key` | Anthropic API Key (`sk-ant-` prefix) |
| `replicate-token` | Replicate API Token (`r8_` prefix) |
| `huggingface-token` | Hugging Face Access Token (`hf_` prefix) |
| `groq-key` | Groq API Key (`gsk_` prefix) |
| `openrouter-key` | OpenRouter API Key (`sk-or-v1-` prefix) |
| `xai-key` | xAI (Grok) API Key (`xai-` prefix) |
| `perplexity-key` | Perplexity API Key (`pplx-` prefix) |

### Communication

| Rule ID | Description |
|---------|-------------|
| `slack-token` | Slack Token (`xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` prefix) |
| `slack-webhook` | Slack Incoming Webhook URL |
| `discord-webhook` | Discord Webhook URL |
| `telegram-bot-token` | Telegram Bot Token |
| `twilio-sid` | Twilio Account SID |

### Payment

| Rule ID | Description |
|---------|-------------|
| `stripe-secret-key` | Stripe Secret Key (`sk_live_` / `sk_test_` prefix) |
| `stripe-restricted-key` | Stripe Restricted Key (`rk_live_` / `rk_test_` prefix) |
| `square-access-token` | Square Access Token (`EAAA` prefix) |

### Email Services

| Rule ID | Description |
|---------|-------------|
| `sendgrid-key` | SendGrid API Key (`SG.` prefix) |
| `mailgun-key` | Mailgun API Key (`key-` prefix) |
| `mailchimp-key` | Mailchimp API Key (32-char hex + `-usN` suffix) |

### Auth

| Rule ID | Description |
|---------|-------------|
| `jwt` | JSON Web Token (three Base64URL segments separated by `.`) |
| `private-key` | PEM Private Key header (`-----BEGIN … PRIVATE KEY-----`) |
| `private-key-base64` | PEM private key that has been base64-encoded — how one appears in a kubeconfig, a Kubernetes Secret or a Terraform state, where the `-----BEGIN` header never shows in the text |
| `url-basic-auth` | Credentials in the userinfo field of an http(s) URL — a git remote, a `.netrc`, a private registry, a `curl` invocation. RFC 3986 deprecates the form for this reason |
| `connection-string` | Database connection string with embedded credentials; each half of the credentials is bounded at 1024 characters, and the user name may be empty (`redis://:password@host`) — see the note below the tables |

### SaaS / Developer Tools

| Rule ID | Description |
|---------|-------------|
| `mapbox-token` | Mapbox Token (`pk.` / `sk.` JWT prefix) |
| `sentry-user-token` | Sentry User Auth Token (`sntryu_` prefix) |
| `sentry-org-token` | Sentry Organization Auth Token (`sntrys_` JWT prefix) |
| `atlassian-token` | Atlassian (Jira/Confluence) API Token (`ATATT3` prefix) |
| `linear-key` | Linear API Key (`lin_api_` prefix) |
| `postman-key` | Postman API Key (`PMAK-` prefix) |
| `docker-hub-pat` | Docker Hub Personal Access Token (`dckr_pat_` prefix, then 27 or more letters, digits, `_` or `-`) |

### Platforms and Infrastructure

| Rule ID | Description |
|---------|-------------|
| `openai-service-key` | OpenAI Service Account / Admin Key (`sk-svcacct-`, `sk-admin-`, `sk-proj-` prefix) |
| `azure-storage-key` | Azure Storage Account Key (`AccountKey=` + 88-char base64) |
| `azure-sas-key` | Azure Shared Access Key for Service Bus, Event Hubs and IoT Hub (`SharedAccessKey=` + 22–86-char base64 with optional `=` padding). Separate from the storage account key, which is 88 characters |
| `google-oauth-secret` | Google OAuth Client Secret (`GOCSPX-` prefix) |
| `flyio-token` | Fly.io API Token (`FlyV1 fm2_` prefix) |
| `databricks-token` | Databricks Personal Access Token (`dapi` + 32 hex) |
| `vault-token` | HashiCorp Vault Token (`hvs.` / `hvb.` prefix) |
| `shopify-token` | Shopify Access Token (`shpat_`, `shpss_`, `shpca_`, `shppa_` prefix) |
| `doppler-token` | Doppler Token (`dp.pt.`, `dp.st.`, … prefix) |
| `grafana-token` | Grafana Cloud / Service Account Token (`glc_`, `glsa_` prefix) |
| `notion-token` | Notion Integration Token (`ntn_` prefix) |

### Generic / Env-based

| Rule ID | Description | Entropy threshold |
|---------|-------------|-------------------|
| `generic-secret` | `api_key`, `secret_key`, `access_token`, `api_secret` assignments | 3.5 |
| `env-assignment` | Assignments whose name carries `SECRET`, `PASSWORD`, `PASSWD`, `PASS`, `TOKEN`, `API_KEY`, `ACCESS_KEY` or `PRIVATE_KEY`, written with `=` anywhere or with `:` at the start of a line. `PASS` must stand on its own — `COMPASS` and `BYPASS` are not passwords. The value must be a value: eight characters or more, no brackets or separators in it, and not a `$VAR` reference | 3.0 |

The entropy threshold filters out low-entropy values that are unlikely to be real secrets — `API_KEY=aaaaaaaa` scores 0 and is dropped. It is a weak filter, not a classifier: `placeholder` scores 3.096 and clears the 3.0 threshold, so entropy alone would report `API_KEY=placeholder`. What drops that one is the placeholder test, not the threshold. Entropy is the Shannon entropy of the value.

### Passwords and Authorization headers

These rules read a value off the word beside it, not off its shape, so each one
runs the `password-like` check on the value before it reports a match. A
Basic header is checked by `basic-credentials` instead.

| Rule ID | Description | Notes |
|---------|-------------|-------|
| `password-cli-flag` | `--password`, `--passwd` or `--pass` followed by `=` or a space; `mysql -p'…'` and `-p"…"` | The value may be quoted. `--password-stdin` and `--password prod` are not matched, since `prod` is not a password |
| `password-netrc` | A line that begins `password` or `passwd`, indentation allowed | Matches a `.netrc` file and a `vault kv get` listing |
| `password-prose` | `password`, `passwd`, `passcode`, `pwd` or `pw` followed by `is`, `was`, `:` or `=`; `パスワードは`, `パスワード：` | The value stops at a space, a comma, a full stop or `で`. After `:` or `=`, an unquoted name is code and is not matched: an identifier or dotted name (`new_password`, `form.password2`), a call (`hash_password(raw)`), a Ruby symbol, a GraphQL type (`String!`). `password: hunter2` is therefore not matched; quote it, or add a symbol |
| `password-json-key` | A JSON string whose key ends in `pass`, `passwd`, `password` or `pwd` | The last word of the key has to start at a `.`, `_`, `-` or a capital letter, so `bypass` is not one. `dbpassword` in lower case is not matched |
| `redis-auth` | `AUTH` in capitals at the start of a line or after a space or `>`, `"AUTH"` in a MONITOR line, and `redis-cli … -a` | |
| `http-basic-auth` | `Authorization: Basic …` | The value must decode to printable UTF-8 with a non-empty user name before the colon and a non-empty password after it. A pair made only of `user`, `username`, `admin`, `root`, `test`, `foo`, `bar`, `guest`, `demo`, `pass`, `password`, `passwd`, `secret` or `changeme` is a documented example and is not matched |
| `http-bearer-token` | `Authorization: Bearer …` | Twenty or more characters from `[A-Za-z0-9._~+/-]` with entropy of at least 3.5. `$TOKEN`, `<token>` and `${API_KEY}` are not matched |

`password-like` accepts a value of six to 128 characters with no whitespace, at
least one letter, and a digit or a symbol. It refuses a value that starts with
`$`, `%`, `<`, `{`, `-`, `/` or `~`, and a value made only of asterisks, which
is a mask a tool printed. A quoted value is checked without its quotes.

### Why `private-key-base64` carries three prefixes

Base64 encodes three bytes at a time, so what `-----BEGIN ` looks like once
encoded depends on where it sits relative to that boundary. A key encoded whole
— `client-key-data` in a kubeconfig, `tls.key` in a Kubernetes Secret, a
`base64 -w0 < key.pem` — starts at offset 0 and produces `LS0tLS1CRUdJTi`. A key
that begins one or two bytes into what was encoded produces `0tLS0tQkVHSU4g` or
`tLS0tLUJFR0lOI` instead, and the rule lists all three: matching only the first
would find one PEM in three. Offsets beyond two repeat the cycle.

The plaintext `private-key` rule is unaffected either way — it reads the header
itself.

## PII

| Rule ID | Description | Notes |
|---------|-------------|-------|
| `pii-email` | Email Address | Local part up to 64 characters per unbroken run (RFC 5321's limit); domain matched as dot-separated labels, so a domain with no dot (`user@localhost`) is not one. Both bounds are there to keep the pattern from backtracking — see the note below the table. A `%40` in place of the `@` is found too. A role address such as `support@` or `noreply@` is not, and a full stop after the domain does not end the match |
| `pii-credit-card` | Credit Card Number | Visa, Mastercard, Amex, Discover; validated with Luhn algorithm |
| `pii-ssn` | US Social Security Number | Excludes invalid area (000, 666, 9xx), group (00), and serial (0000) numbers |
| `pii-mynumber-jp` | Japanese Individual Number (My Number) | 12 digits, validated with weighted checksum (mod 11) |
| `pii-nir-fr` | French NIR / Social Security Number | 15 digits, validated with check key (mod 97); Corsica 2A/2B supported |
| `pii-codice-fiscale-it` | Italian Codice Fiscale | 16 alphanumeric chars, validated with control character (mod 26) |
| `pii-steuer-id-de` | German Steuer-Identifikationsnummer | 11 digits, validated with MOD 11,10 (ISO/IEC 7064) |
| `pii-dni-nie-es` | Spanish DNI / NIE | 8 digits + letter (DNI) or X/Y/Z + 7 digits + letter (NIE); validated with mod 23 |
| `pii-iban` | IBAN | Country length from the SWIFT registry for the common countries, and the mod-97 check digits. Spaces in groups of four are allowed |
| `pii-nino-uk` | UK National Insurance Number | The spaced form `AB 12 34 56 C` only. The first and second letters and the reserved prefixes are excluded |
| `pii-phone-us` | US Phone Number | With or without country code. Numbers in the 555 exchange, the fiction range 0100 to 0199 and toll-free area codes are not matched |
| `pii-phone-jp` | Japanese Phone Number | Area code + subscriber number format |
| `pii-phone-intl` | International Phone Number | `+` and a country code, then digits with spaces, hyphens, dots or brackets between them. Nine to fifteen digits, not all the same |
| `pii-phone-fr` | French Phone Number | Context-gated (requires nearby phone label) |
| `pii-phone-it` | Italian Phone Number | Context-gated |
| `pii-phone-de` | German Phone Number | Context-gated |
| `pii-phone-es` | Spanish Phone Number | Context-gated |
| `pii-postal-jp` | Japanese Postal Code | Requires `〒` prefix to avoid false positives |
| `pii-postal-code` | Postal Code (US ZIP / EU / KR) | Context-gated (requires nearby postal label) |
| `pii-rrn-kr` | Korean Resident Registration Number | 13 digits, validated with weighted checksum (mod 11); context-gated, since thirteen digits that satisfy the checksum turn up in timestamps |
| `pii-brn-kr` | Korean Business Registration Number | 10 digits, validated with NTS standard checksum; context-gated, for the same reason |
| `pii-resident-id-cn` | Chinese Resident Identity Card | 18 chars (17 digits + check), validated with GB 11643 MOD 11-2 |
| `pii-phone-kr` | Korean Phone Number | Context-gated |
| `pii-phone-cn` | Chinese Phone Number | Context-gated |
| `pii-postal-cn` | Chinese Postal Code (6-digit) | Context-gated |
| `pii-ipv4-public` | Public IPv4 Address | Context-gated; reserved/private ranges excluded |
| `pii-ipv6` | IPv6 Address | Context-gated; loopback, link-local, ULA, multicast excluded |
| `pii-date-of-birth` | Date of Birth after a label | Labels: `DOB`, `D.O.B.`, `date of birth`, `birthdate`, `生年月日` and `誕生日`. The words of an English label may be joined by spaces, underscores or hyphens (`date_of_birth`, `birth-date`), or run together in camelCase (`dateOfBirth`, `birthDate`). `誕生日会` (a birthday party) is not a label, so the date after it is not matched. Up to 24 characters that are not digits may separate the label from the date; after `生年月日` or `誕生日` it is up to 8, and none of them may be `!`, `！` or `。`. Date forms: ISO (`1990-05-06`), slash and dot, English month names (`2 Apr 1978`, `March 27, 1973`), 年月日 with a western or an era year (`1988年7月21日`, `昭和63年7月21日`, `平成元年1月1日`), and `S63.7.21`. A numeric form is read day first or month first, whichever is a real date. Only calendar dates from 1900 to this year are found, and `1970-01-01` and `1900-01-01` are not, since form defaults write them. Kanji numerals are read in the era and 年月日 forms (`昭和五十年十二月三日`, `一九八八年七月二十一日`). A cell under a header named as one of these labels is read too, in CSV, TSV, a Markdown table or a SQL `INSERT` column list |
| `pii-customer-number` | Member, Customer or Account Number after a label | Labels: `customer ID`, `customer number`, `customer no.`, `customer #`, the same forms for `member` and `membership` (`member ID`, `membership number`), `account number`, `account no.` and `account #` (not `account ID`), and `会員番号`, `顧客番号`, `お客様番号`, each with `番号`, `No.` or `ID`. The label has to stand alone: a label that is the tail of a longer snake_case key, such as `organization_membership_id` or `billing_customer_id`, is not matched, because the underscore before the label belongs to the key. The cost is that a number under a composite key such as `billing_customer_id` is not found. The value is five to twenty-four letters, digits or hyphens, with at least two digits, starting and ending with a letter or digit; a longer run is not a value. `口座番号` is a label, and so are the `ID`, `No.` and `番号` forms of the Japanese labels. A Japanese label needs no boundary after it, so `会員番号MBR-3PW8D6YT` is found, and the value may use full-width digits (`会員番号：１２３４５６７８`). An English label still needs one, so `customerIdx 12345` is not found. A cell under a header named as one of these labels is read too, in CSV, TSV, a Markdown table or a SQL `INSERT` column list |
| `pii-address-jp` | Japanese Postal Address | Starts at one of the 47 prefectures and needs a municipality suffix (市, 区, 郡, 町 or 村) within ten characters after it. The block number is `N丁目`, `N番`, `N番地`, `N号` or `N-N-N`, repeated as needed, in ASCII, full-width or kanji numerals, and may be followed by a final number and 号. A prefecture alone, a municipality alone, and a number followed by a counter such as 件 or 年 are not matched |
| `pii-date-of-birth-zh` | Date of Birth after a Chinese label | Labels: `出生日期`, `出生年月日`, `出生年月` and `出生于`. `生日` is not a label, since it names the birthday (`生日快乐`) as often as the birth date, and `生于` and `出生` alone are not labels (`发生于` contains `生于`, and `出生人口` is a population). No boundary is needed after the label, as in the Japanese rule. Up to 8 characters that are not digits may separate the label from the date, and `！`, `!` and `。` end the label's reach. Date forms: `1985年3月12日`, `1985年3月12号` (号 is the spoken day counter), `1985-03-12`, `1985/3/12`, `1985.03.12`, and the day-first or month-first numeric forms that are real dates. Chinese numerals in a Chinese date (`一九八五年`) and month-only dates (`出生年月 1985年3月`) are not read. Dates are checked as `pii-date-of-birth` checks them: 1900 to this year, and not `1970-01-01` or `1900-01-01`. A cell under a header named `出生日期`, `出生年月日` or `出生年月` is read too; `出生于` heads no column. |
| `pii-date-of-birth-ko` | Date of Birth after a Korean label | Labels: `생년월일`, `출생일`, `출생일자`, `출생연월일` and `출생년월일`. `생일` is not a label, since it names the birthday event as often as the birth date, and `출생` alone is not one (`출생률`). No boundary is needed after the label, and the gap may hold the particles `은`, `는`, `이` and `가` and a full-width colon `：`; `!`, `！` and `。` end the label's reach. Date forms: `1985년 3월 12일` (spaces optional), the official `1985. 3. 12.` with a space after each dot and a final dot, `1985.03.12`, `1985-03-12`, `1985/03/12`, and the day-first or month-first numeric forms that are real dates. Dates are checked as `pii-date-of-birth` checks them, so `1970. 1. 1.` and `1900-01-01` are not found. A cell under a header named `생년월일`, `출생일`, `출생일자`, `출생연월일` or `출생년월일` is read too. |
| `pii-date-of-birth-fr` | Date of Birth after a French label | Labels: `date de naissance` (also `date naissance`, joined by `_` or `-`, or run together as in `dateDeNaissance`), `DDN`, and `né le`, `née le` and `né(e) le` before the date. `ne le` without the accent is not a label, since it is the negation (`ne le fais pas`), and `naissance` alone is not one, since it names any birth (`naissance du projet`). `DDN` must stand alone, so `maddn` is not matched. Up to 24 characters that are not digits may separate `date de naissance` or `DDN` from the date, and up to 8 may follow `né le`. Date forms: `12/03/1985`, `1985-03-12`, `12.03.1985`, and a day with `1er` or no suffix before a French month name, with or without an accent, abbreviated or not (`1er mars 1985`, `12 janv. 1985`, `1er août 1985`). English month names are not read by this rule, so `date de naissance: March 12, 1985` is not found. Month-first forms such as `mars 12, 1985` are not read, since French writes the day first. A cell under a header named `date de naissance`, `date naissance`, `DDN`, `né le`, `née le` or `né(e) le` is read too. |
| `pii-date-of-birth-it` | Date of Birth after an Italian label | Labels: `data di nascita` (also `data nascita`, `dataDiNascita` and `data_nascita`), the abbreviations `D.N.` and `DN`, and `nato/a il`, `nato il` and `nata il`, with an optional place in the `nato/a a PLACE il DATE` structure. The place is up to 24 characters without a digit or a comma. `nato` alone is not a label: under the case-insensitive match it is the same word as `NATO`, so `la NATO il` and `alla NATO il` are refused by a lookbehind. Residual: `NATO il 12 marzo 2024` at the start of a sentence still matches, since the validator accepts the year. `nascita` alone is not a label (`nascita del progetto`), and `compleanno` names an event. Date forms: `12/03/1985`, `1985-03-12`, `12.03.1985`, and a day with an optional `º` or `°` before an Italian month name, with or without an accent, abbreviated or not (`1º marzo 1985`, `12 marzo 1985`, `12 sett. 1985`, `31 dic 1985`). English month names are not read by this rule. Month-first forms such as `marzo 12, 1985` are not read, since Italian writes the day first. A cell under a header named `data di nascita`, `data nascita`, `nato il`, `nata il` or `nato/a il` is read too; `D.N.` and `DN` head no column, since a `dn` column is an LDAP distinguished name. |
| `pii-date-of-birth-de` | Date of Birth after a German label | Labels: `Geburtsdatum` (also `Geburts_datum`, `geburts-datum` and `GEBURTSDATUM`), `Geb.-Datum`, `Geb. Datum`, `Geb.Dat.`, `geboren am` and `geb.`, with or without a colon after it. `geb.` alone is taken only when the date follows it within two spaces, since `geb. Schmidt` gives a maiden name, and a date later in the sentence belongs to someone else. `Geburtstag` is not a label, since it names the birthday event as often (`Geburtstag am 12.03.2026`). Up to 24 characters that are not digits may separate `Geburtsdatum` from the date. Date forms: `12.03.1985`, `12.3.1985`, `1985-03-12`, `1985/03/12`, and a day with an optional dot before a German month name, with or without an accent or `ae` for `ä`, abbreviated or not (`12. März 1985`, `1. Maerz 1985`, `3. Mrz. 1985`, `1 Dez 1985`). English month names are not read by this rule, so `Geburtsdatum: 12 March 1985` is not found. Month-first forms such as `März 12, 1985` are not read, since German writes the day first. A cell under a header named `Geburtsdatum`, `Geb.-Datum`, `Geb. Datum`, `Geb.Dat.`, `geb.` or `geboren am` is read too. |
| `pii-date-of-birth-es` | Date of Birth after a Spanish label | Labels: `fecha de nacimiento` (also `fecha nacimiento`, `fechaNacimiento` and `fecha_de_nacimiento`), `fecha nac.`, `fec. nac.`, `F. Nac.` and `F.N.` (the dot after `F` is required, so `Fnac.`, the retailer, is not a label), and `nacido/a el`, `nacida el`, `nací el` (first person) and `nacido en PLACE el`, where the place is up to 24 characters without a digit or a comma. `nacimiento` alone is not a label, and `cumpleaños` names an event. Date forms: `12/03/1985`, `1985-03-12`, `12-03-1985`, `1985/03/12`, and the written form `12 de marzo de 1985`, with `12 marzo 1985`, `12-mar-1985` and `31 dic. 1985` also read. An ordinal sign after the day (`1º`) is accepted. The Spanish `1.º` is not. English month names are not read by this rule. Month-first forms such as `marzo 12, 1985` are not read, since Spanish writes the day first. A cell under a header named `fecha de nacimiento`, `fecha nacimiento`, `fecha nac.`, `fec. nac.`, `F. Nac.`, `F. Nacimiento`, `nacido el`, `nacida el` or `nacido/a el` is read too; `F.N.` heads no column. |
| `pii-customer-number-zh` | Member, Customer or Account Number after a Chinese label | Labels: `客户编号`, `客户号码`, `客户号`, `客户ID`, `会员编号`, `会员号码`, `会员号`, `会员卡号`, `会员ID`, `银行账号` and `账户号码`. `账号` is not a label, since it names a login account as often as a bank account, and `账户ID` and `用户ID` are infrastructure IDs. No boundary is needed after the label, as with the Japanese label (`会员编号MBR-20419` is found). Up to six characters may separate the label from the value: whitespace, the colons `：` and `:`, `=`, `#`, `是`, `为`, quotes and brackets. The value is the English rule's: five to twenty-four letters, digits or hyphens, with at least two digits, starting and ending with a letter or digit, and not all zeros. Full-width digits are accepted. A cell under a header named `客户编号`, `客户号码`, `客户号`, `客户ID`, `会员编号`, `会员号码`, `会员号`, `会员卡号`, `会员ID`, `银行账号` or `账户号码` is read too. |
| `pii-customer-number-ko` | Member, Customer or Account Number after a Korean label | Labels: `고객번호`, `고객 번호`, `고객ID`, `고객 ID`, `회원번호`, `회원 번호`, `회원ID`, `회원 ID`, `계좌번호` and `계좌 번호`. `계정 ID` and `계정번호` name a login account, and `아이디` is a login ID, so none is a label. No boundary is needed after the label, and the gap may hold the particles `은`, `는`, `이` and `가`. The value is the English rule's: five to twenty-four letters, digits or hyphens, with at least two digits. The value is the English rule's, except that a value of nothing but zeros is refused, since a form writes `00000000` in place of a number. A cell under a header named `고객번호`, `고객 번호`, `고객ID`, `고객 ID`, `회원번호`, `회원 번호`, `회원ID`, `회원 ID`, `계좌번호` or `계좌 번호` is read too. |
| `pii-customer-number-fr` | Member, Customer or Account Number after a French label | Labels: `numéro de client` (also `numero client`, `numéro client`, `numeroClient` and `numero_client`), `N° client` (also `Nº client` and `N° de client`), `code client`, `identifiant client`, `id client`, `numéro de compte` and `n° de compte`, and `numéro d'adhérent`, `N° d’adhérent` (the typographic apostrophe too), `N° adhérent` and `numéro de membre`. `ID de compte` names an account ID, `référence client` names contracts and orders as well, and `no client` without a degree sign or a dot is English, so none is a label. A label must stand alone: `organization_numero_client` is not matched, since the underscore before the label belongs to a key. The value is the English rule's, except that a value of nothing but zeros is refused, since a form writes `00000000` in place of a number. A cell under a header named `numéro de client`, `N° client`, `N° de client`, `Nº client`, `code client`, `identifiant client`, `id client`, `numéro de compte`, `N° de compte`, `numéro d'adhérent`, `N° d’adhérent`, `N° adhérent`, `numéro adhérent`, `numéro de membre` or `N° de membre` is read too, and so is each unaccented spelling of these. |
| `pii-customer-number-it` | Member, Customer or Account Number after an Italian label | Labels: `numero cliente`, `codice cliente`, `cod. cliente`, `id cliente`, `Cliente N.`, `numero socio`, `n. socio`, `numero tessera`, `n. tessera`, `numero di conto` and `numero conto`. `ID account` and `id conto` are account IDs, so neither is a label. A label must stand alone: `org_numero_cliente` is not matched. `è` may stand between the label and the value (`Il mio numero cliente è 123456789`). The value is the English rule's, except that a value of nothing but zeros is refused, since a form writes `00000000` in place of a number. A cell under a header named `numero cliente`, `n. cliente`, `n° cliente`, `num. cliente`, `codice cliente`, `cod. cliente`, `id cliente`, `numero socio`, `n. socio`, `numero tessera`, `n. tessera`, `numero di conto`, `numero conto` or `n. conto` is read too. |
| `pii-customer-number-de` | Member, Customer or Account Number after a German label | Labels: `Kundennummer` (also `Kunden-Nr.`, `Kundennr.`, `Kunden-ID` and `KundenNr`), `Kd.-Nr.`, `Kd-Nr.`, `KdNr`, `Mitgliedsnummer` and `Mitglieds-Nr.`, `Mitgl.-Nr.`, `Kontonummer` and `Kto.-Nr.`. `Konto-ID` names an account ID, and `Debitorennummer` is a ledger key, so neither is a label. A label must stand alone: `billing_kundennummer` is not matched, and neither is the plural `Kundennummern`. `ist` and `lautet` may stand between the label and the value. The value is the English rule's, except that a value of nothing but zeros is refused, since a form writes `00000000` in place of a number. A cell under a header named `Kundennummer`, `Kunden-Nr.`, `Kundennr.`, `Kunden-ID`, `Kd.-Nr.`, `Kd-Nr.`, `KdNr`, `Mitgliedsnummer`, `Mitglieds-Nr.`, `Mitgliedsnr.`, `Mitgl.-Nr.`, `Mitglieds-ID`, `Kontonummer`, `Konto-Nr.` or `Kto.-Nr.` is read too. |
| `pii-customer-number-es` | Member, Customer or Account Number after a Spanish label | Labels: `número de cliente` (also `numero cliente`, `numeroCliente`, `numero_de_cliente`, `Nro. de cliente`, `núm. de cliente`, `nº de cliente` and `n.º de cliente`), `código de cliente`, `id de cliente`, `número de socio` (also `número de socio/a` and `nº de socio`), `número de cuenta` and `número de miembro`. `ID de cuenta` names an account ID, and `código de cuenta` is an accounting chart code, so neither is a label. `no de cliente` without a dot is the negation, so it is not one either. A label must stand alone: `org_numero_cliente` is not matched. `es` may stand between the label and the value. The value is the English rule's, except that a value of nothing but zeros is refused, since a form writes `00000000` in place of a number. A cell under a header named `número de cliente`, `número cliente`, `núm. de cliente`, `nº de cliente`, `n.º de cliente`, `nro. de cliente`, `código de cliente`, `código cliente`, `id de cliente`, `id cliente`, `número de socio`, `número de socio/a`, `nº de socio`, `número de cuenta`, `nº de cuenta` or `número de miembro` is read too, and so is each unaccented spelling of these. |
| `pii-address-cn` | Chinese Postal Address | Starts at a province-level name (`北京`, `广东省`, `内蒙古自治区`), or at a city or district unit (ending in 市, 区, 县, 旗 or 盟) that is not in the middle of Han text: it must follow a non-Han character, or one of 在, 到, 于, 为, 至, 往 and 从. Then up to two more units, a road ending in 路, 街, 道, 胡同, 巷 or 弄 (with an optional 段 section), and a number with 号, with a space allowed before the number and 弄 before it, and 号楼/栋/幢/座, 单元 and 室/户 after it. A road alone (`中关村大街1号`), a district alone, a metro line (`3号线`), a date (`3月12号`), a building with no road (`1号楼`) and a count are not matched. 小区, 社区, 校区, 景区 and 园区 (other than 工业园区) are not districts. A village (`泰山东村102栋`), `第N号` and 甲/乙 suffixes are not matched |
| `pii-address-kr` | Korean Postal Address | Starts at a word, with one of the 17 시/도 (full or short: `서울특별시`, `서울시`, `서울`, `경기`, `전북`) and up to three 시/군/구 units, or with a 구 or 군 (optionally after a 시), each unit followed by a space. Then either a road name ending in 대로, 로 or 길, an optional branch (`45길`, `23번길`) and a building number (`123`, `123-4`), or a 동, 리 or 가 with a lot number (`123-4`, `산 123`, with or without 번지). A number followed by a counter (`123명`, `2024년`, `2번 출구`, `2호선`, `2차`) is not a building number; a particle may follow it (`대학로 99에`). `서울로 갑니다` (로 as a particle) and a road with no unit before it (`테헤란로 123`) are not matched. Units written with no space (`서울특별시강남구테헤란로123`) are missed |
| `pii-address-fr` | French Postal Address | A house number (with `bis`, `ter`, `quater` or a letter), a street type (`rue`, `avenue`/`av.`, `boulevard`/`bd`, `chemin`, `place`, `allée`, `impasse`, `quai`, `cours`, `route de …` and others, in any case), a name starting with a capital or an article, then within 60 characters (newlines allowed) a postal code in the 01000–98999 range and a capitalised town. A street without a number, a town alone, a postal code alone, a street with no postal code, and `12 rue X coûte 12000 euros` are not matched; English `404 route not found, 10000 Requests` is not matched either |
| `pii-address-it` | Italian Postal Address | A street type (`Via`, `Viale`/`V.le`, `Piazza`/`P.zza`, `Corso`/`C.so`, `Largo`, `Vicolo`, `Strada` and others), a name starting with a capital, an article or `di`, a civic number after it (`Via Roma 12`, `Via Roma, 12`, `n. 12`, `16/A`, `12 bis`), then within 60 characters a five-digit CAP (first two digits 00 to 98) and a capitalised town, with an optional province code. Lower-case `via` needs a capitalised name that is not an acronym and no comma before the number, because `via` is also English prose (`via SSH, 12 hosts, 10000 Users` is not matched). A year is not a civic number (`Corso di laurea 2024, 10000 Studenti`). `via Jenkins 12 times, 10000 Builds` is matched, which is a known limit of the lower-case form |
| `pii-address-de` | German Postal Address | A street as a compound (`Hauptstraße`, `Hauptstr.`, `Lindenweg`, `Marktplatz`, `Kaiser-Wilhelm-Straße`), as a name with a separate type (`Berliner Straße`, `Schönhauser Allee`), with a genitive (`Straße des 17. Juni`), or with a preposition or adjective (`Am Markt`, `Unter den Linden`, `Neuer Wall`); a house number (`12`, `12a`, `12-14`); a comma, semicolon, dash, pipe, newline or two spaces; then within 60 characters a postal code (`D-` allowed) and a capitalised town. The delimiter is required because German capitalises every noun: `Musterweg 3 kostet 12000 Euro` is not matched, and neither is `Hauptstraße 12 10115 Berlin` with a single space. A type word alone (`Ring 2`, `Weg 1`) is not a street. `Lindenstr. 5a in 80331 München` is missed, since a preposition is not a delimiter: `Bahnhofstraße 5 in 10000 Euro` is a sentence |
| `pii-address-es` | Spanish Postal Address | A street type (`Calle`, `C/`, `Avenida`/`Avda.`/`Av.`, `Plaza`/`Pza.`, `Paseo`/`Pº`, `Carretera`/`Ctra.`, `Camino`, `Ronda`, `Travesía`, `Glorieta`, `Urbanización`, `Polígono`, `Rambla` and others), a name starting with a capital or an article, a number (`10`, `nº 10`, `10 bis`, `km 5`, `s/n`), then within 60 characters (floors and doors such as `3.º izda.` included) a postal code in the 01000–52999 range and a capitalised town. An address whose postal code is not followed by a town, such as a Latin American `C.P. 02180` at the end, is not matched |

### Why three patterns carry length bounds

`pii-email`, `env-assignment` and `connection-string` each bound a repeated character class, and the bounds are not cosmetic. Each put an unbounded quantifier on a class that also matches the separator around it, so on a long run with no match in it — a log full of IP addresses, a file of capitals with no `=`, a line of `mongodb://` with no `@` — every position started a greedy consume of the rest of the text and then backtracked a character at a time. That is quadratic: measured on `env-assignment` alone, 59 KB took 381 ms, 234 KB took 6.9 s and 1 MiB took 125 s; `connection-string` took 2.3 s on 188 KB and 98 s on 1 MiB through the hook.

This matters more than a slow scan. A hook that does not return is killed by Claude Code's PreToolUse timeout, and **a killed hook does not block the tool call** — so a slow pattern is a way through, not an inconvenience. `src/lib/__tests__/rules.test.ts` runs every rule in this file against a list of adversarial shapes and fails any that takes more than two seconds. That list is not a proof: `connection-string` was quadratic and every shape then in the list walked past it, so one written for its own syntax had to be added before it failed. Adding a rule means asking what input makes its own quantifiers run, and adding that shape there if the list has nothing like it.

A rule that needs an unbounded repeat should say why in its `description`, and should come with a case in that file.

What the bounds cost, stated rather than implied:

- **`pii-email`**: an address with 65 or more `[A-Za-z0-9_]` characters in an unbroken run before the `@`. Every other character the local part allows — `.`, `%`, `+`, `-` — is a non-word character, so the word boundary restarts at it and a long address containing one is still found (measured: 65 letters is missed, 65 with a `%` in the middle is not); 64 is RFC 5321's limit for the whole local part, so no deliverable address is lost. The exemption for an address after `ssh`, `scp`, `rsync` or `sftp` is bounded too: it covers at most two arguments between the command and the address, each up to 64 characters, with runs of up to 16 spaces or tabs between them. An address after a longer argument, or after 17 or more spaces, is a finding (measured: 16 spaces exempt, 17 found; 64 characters exempt, 65 found).
- **`env-assignment`**: a name with 65 or more capitals in a run on either side of the keyword — `AAA…SECRET=` and `SECRET…AAA=` alike. `_` is a word character, so `A×65_SECRET=` is lost too, since the boundary does not restart at the underscore.
- **`connection-string`**: a user or a password longer than 1024 characters.

None of these is a spelling anyone writes. All of them are a way to write one this tool will not see, which is the honest way to hold both facts.

The address rules bound the same way. The distance between a house number and its postal code is at most 60 characters, each word of a name is at most 21 characters and a name has at most five words, a Chinese unit name is at most seven characters and a road name at most six, and a Korean unit name at most nine syllables. Each bound is longer than any name or distance in a real address, and without it a rule would walk the rest of a long line from every start position.

### National ID Validation

National ID numbers (JP My Number, FR NIR, IT Codice Fiscale, DE Steuer-IdNr., ES DNI/NIE) are matched by pattern **and** validated against their official checksum algorithm. A digit sequence that looks right but fails the checksum is not flagged. The algorithms follow each issuing authority's published spec:

- **My Number**: 地方公共団体情報システム機構 (J-LIS)
- **NIR**: INSEE / décret n°82-103 (97 − N mod 97)
- **Codice Fiscale**: Agenzia delle Entrate, DM 12 giugno 2007 (mod 26)
- **Steuer-IdNr.**: Bundeszentralamt für Steuern (ISO/IEC 7064 MOD 11,10)
- **DNI/NIE**: Ministerio del Interior, Orden INT/2058/2008 (mod 23)
- **Korean RRN**: 주민등록 사무편람, Ministry of the Interior and Safety (weighted mod 11)
- **Chinese Resident ID**: GB 11643-1999 (ISO 7064 MOD 11-2)
- **Korean BRN**: NTS (Hometax) standard algorithm

### Context Gating

Phone numbers (IT, DE, FR, ES, KR, CN) and bare postal codes (5/9-digit and Chinese 6-digit) produce too many false positives on digit-only patterns. These rules carry a list of nearby context words (`phone`, `tel`, `ZIP`, `PLZ`, `CAP`, `postal`, … in each relevant language) and only fire when one of those words appears within a small window of the match. Only words that **directly indicate the PII type** are included; generic words such as `contact`, `host`, `server`, or `code` are excluded because they cause false positives. If no decisive context word is nearby, the match is dropped.

National ID numbers rely on their checksums instead and do not require context. Japanese postal codes keep their `〒` prefix requirement, which is a stricter form of the same idea.

Public IPv4 and IPv6 addresses are also context-gated, and additionally exclude reserved ranges (private, loopback, link-local, TEST-NET, multicast, documentation, etc.), so an address like `8.8.8.8` fires only when a label such as `ip`, `ipv4` or `ipv6` is nearby. RFC 1918 private addresses are not matched by any rule: they are non-routable and identify nothing outside their own network, and treating them as personal data blocked ordinary infrastructure work.

### Labelled attributes

`pii-date-of-birth`, `pii-customer-number`, their twelve per-language counterparts (`pii-date-of-birth-de` and so on) key on a label, and the address rules (`pii-address-jp`, `pii-address-cn`, `pii-address-kr`, `pii-address-fr`, `pii-address-it`, `pii-address-de` and `pii-address-es`) key on place names and the shape of the address, not on the value alone. Each language has its own rule, so that a label list can be read and measured on its own. The labels taken are the ones whose meaning is a person's attribute alone. A word that names an event or an infrastructure account as often as a person's attribute (`Geburtstag`, `生日`, `생일`, `账号`, `Konto-ID`, `ID de compte`) is left out, and the row for each rule says which. The new rules do not read two-digit years, month-only dates, eight-digit dates with no separator (`19850312`), the Spanish `1.º`, the French `1ᵉʳ`, Chinese numerals in a Chinese date, or a label on a line above its value outside a table. A member number is read only as one unbroken run, so `4471 0932` with a space in it is not found, and a member number of nothing but zeros is not read. A bare date or a bare number is in every log, lockfile and fixture, so a rule that matched `1990-05-06` wherever it appeared would block most of what a developer pastes. The label is what says the value belongs to a person: `DOB: 1990-05-06` is a date of birth, and `1990-05-06` in a changelog is not. The address rules have no label, so the parts in sequence are what say the text is an address: a prefecture, a municipality and a block number for `pii-address-jp`, and for the six others the structure described under [Address rules](#address-rules).

A company's address matches the same way a person's does, because the text of a footer does not say whose address it is. Issue #336 leaves that open. Until it is settled, the rule finds a company's office address in a document as it finds a person's, and the six address rules do the same: `Siège : 1 cours Lafayette, 69003 Lyon` and `公司地址：深圳市福田区深南大道6008号` are found.

A table is the other place a label is found. A header such as `dob` or `customer id` over a column names every value under it, so the cell needs no label of its own. The header is the context, and the rule's validator still applies. This is set with `columnLabels` and `cellRegex` (see [Rule fields](#rule-fields)): the built-in date-of-birth and member-number rules name their columns in the same way.

### Address rules

The four European address rules require the postal code. A street name and a house number alone (`Hauptstraße 12`, `Via Roma 12`) are in every map tile, shop listing and fixture, and a five-digit number with a capitalised word after it (`10000 Users`) is in every log. It is the sequence of street, number, postal code and town within a short distance that says the text is an address. The French and Italian rules accept a single space before the postal code. The German rule needs a comma, a dash, a newline or two spaces, because in German every noun is capitalised and `Musterweg 3 kostet 12000 Euro` would otherwise read as an address.

The Chinese and Korean rules do not require a postal code, since those texts rarely write one beside an address. A Chinese address is read from a province-level name, or from a 市, 区 or 县 unit, through a road to a number with 号. A Korean one is read from a 시/도 or 구/군 unit, each followed by a space, through a road suffix (로 or 길) or a lot suffix (동, 리 or 가) to a number. What each rule refuses is in the table above.

Two properties of these rules are not obvious from their patterns, and a change that simplifies either one makes a rule slower or wider.

The first is the start. A pattern is tried at every character, so a rule whose first step is a long alternation of street types or units pays for it at every character of a long text. The European rules start with a lookbehind on Latin letters, digits and `/.-`, written as explicit ranges, because `\p{L}` in a lookbehind costs several times as much over the same text. The Chinese unit start is gated on the character before it (a non-Han character, or 在, 到, 于, 为, 至, 往 or 从), because a unit would otherwise be tried inside every run of Han characters. The Korean rule starts at a word boundary, `(?<![가-힣])`, so that a run of syllables is not read from each of its characters.

The second is the atomic run. A pattern such as `(?=(?<a0>\p{Lu}[\p{L}-]{1,30}))\k<a0>` takes the whole run once and never gives characters back, which is what a backtracking `[\p{L}-]{1,30}` followed by a suffix would do at every length. It matches the same text, since each run here ends at a character that cannot continue it (a unit suffix, a road suffix, a digit or a space). Group names must be unique within one pattern.

Two lookbehinds are unusual and are kept on purpose. `(?<=[시군구])\s` after a run of syllables checks the last syllable of the unit, not the run, so `구로구` and `시흥시` are read whole. `(?<!(?<!工业)园)区` refuses 园区 unless it follows 工业, so 苏州工业园区 is a district and the other 园区 names are not.

### Credit Card Validation

Credit card numbers are matched by pattern **and** validated using the [Luhn algorithm](https://en.wikipedia.org/wiki/Luhn_algorithm). This means valid-looking but invalid card numbers (e.g. `4111111111111112`) are not flagged.

## Allow Tags

All blocks can be bypassed by including an allow tag in your prompt. Allow tags are read only from the **current** user message — they do not carry over between turns.

| Tag | Bypasses |
|-----|----------|
| `[allow-secret]` | All findings with `category: secret` |
| `[allow-pii]` | All findings with `category: pii` |
| `[allow-all]` | All findings regardless of category |

Tags are **case-insensitive**: `[ALLOW-SECRET]` and `[Allow-Secret]` work the same as `[allow-secret]`.

The name-based block on `.env`/`.env.*` files is a secret guard, so `[allow-secret]` and `[allow-all]` lift it and `[allow-pii]` does not.

### Mask Tags

`[mask-secret]`, `[mask-pii]`, and `[mask-all]` are recognised but **not supported**. Claude Code hooks cannot rewrite prompt content before it is sent to the API.

If you include a mask tag in your prompt, sensitive-canary shows an explanation and lists the findings the prompt would be blocked for, up to fifty as a block lists them. It suggests the allow tag for each category among them, so a prompt with a secret and PII is told about both `[allow-secret]` and `[allow-pii]`, not only the one that matches the mask tag. The prompt is not sent until you resend with an allow tag or redact the values manually.

| Mask tag | Allow tag for the same category |
|----------|---------------------------------|
| `[mask-secret]` | `[allow-secret]` |
| `[mask-pii]` | `[allow-pii]` |
| `[mask-all]` | `[allow-all]` |

### Tag Priority

When more than one tag appears, **the last one wins**. It replaces the earlier
ones entirely rather than combining with them, so changing your mind mid-message
works the way it reads.

| Example | secret | pii |
|---------|--------|-----|
| `[allow-all] … [allow-secret]` | allow | blocked |
| `[allow-secret] … [allow-all]` | allow | allow |
| `[allow-secret] … [mask-secret]` | mask (unsupported) | blocked |
| `[mask-secret] … [allow-secret]` | allow | blocked |
| `[allow-secret] … [allow-pii]` | blocked | allow |

The last line is the one to watch: two tags do not add up. Narrowing from
`[allow-all]` to `[allow-secret]` really does put PII back under guard, which is
the point — but so does writing `[allow-secret] [allow-pii]` and expecting both.
**`[allow-all]` is how you ask for both.**

A tag counts wherever it appears in the message, including mid-sentence. What
does not count is a tag inside a fenced code block, inside one of the elements
Claude Code writes around command output, or in a message the runtime wrote
rather than you — a compaction summary or a skill body. Those are quoting, not
asking.

## Category Filtering

Set the `SENSITIVE_CANARY_CATEGORIES` environment variable (e.g. in the `env` block of Claude Code `settings.json`) to limit which rule categories are active:

| Value | Effect |
|-------|--------|
| `secret` | Scan for secrets only — PII rules are disabled |
| `pii` | Scan for PII only — secret rules and the name-based `.env`/`.env.*` block are disabled |
| `secret,pii` / `all` | Scan everything (default) |

Values are comma-separated and case-insensitive. Unset, empty, or containing no valid token means all categories are enabled. This persistent filter is applied before allow tags.

## .env File Blocking

`.env` and `.env.*` files (e.g. `.env.local`, `.env.production`) are blocked **by filename** when Claude attempts to read them, regardless of content. This name-based block is a secret guard: it only applies while the `secret` category is enabled via `SENSITIVE_CANARY_CATEGORIES`.

Files that end in `.env` but don't start with a dot (e.g. `production.env`) are handled by content scanning rather than name-based blocking.

The name is compared without regard to case, so `.ENV` and `.Env.local` are blocked too. A symbolic link is judged by its own name and by the name of the file it points to, so a link named `notes.txt` that points to `.env` is blocked when it is read. The template names are exempt in any case, and a link to one is exempt by that name.

Commands that copy, move, link or archive a file (`cp`, `mv`, `ln`, `install`, `rsync`, `tar -c` (and `bsdtar`, `gtar`) and `zip`) read their sources, so `cp .env backup.txt` is blocked on the name of `.env`. The same holds for a directory named as a source: `cp -r . backup` and `tar -czf b.tgz .` are blocked when a `.env` sits directly in it, as a read of that directory is. `tar -T FILE` and `rsync --files-from=FILE` read the names in FILE as sources, and `tar -C DIR` makes the names after it relative to DIR. `tar -x` reads none of its operands.

`[allow-secret]` and `[allow-all]` lift the name-based block; `[allow-pii]` does not, since the block is a secret-category finding. Lifting the name block is not a pass: the contents are still scanned, and a tag only removes findings of the category it names. A file exempted by `[allow-secret]` is still blocked for an email address in it.

## Bash Command Scanning

When Claude uses the `Bash` tool, sensitive-canary checks three things:

1. **Environment variables** — any `$VAR` or `${VAR}` references in the command are looked up in the current environment; if their values contain secrets or PII, the command is blocked.
2. **Command string** — the raw command is scanned, which catches a secret written inline (`echo ghp_…`, `curl -H "Authorization: Bearer …"`).
3. **File-reading commands** — the target files are read and scanned before the command runs. The set is the one in `src/lib/bash-commands.ts`: around forty commands that print their operands (`cat`, `head`, `xxd`, `zcat`, `iconv`, `comm`, …), a second class whose first argument is a pattern and whose rest are files (`grep`, `sed`, `awk`, `jq`, `zgrep`, …), the git subcommands that print contents, `dd if=`, and inline program text. Copying, moving, linking and archiving commands (`cp`, `mv`, `ln`, `install`, `rsync`, `tar -c`, `bsdtar`, `gtar`, `zip`) read their sources, which are every operand but the destination, and the files named in a `tar -T` or `rsync --files-from` list. Compound commands using `|`, `;`, `&&`, `||` are split and each segment is checked independently. README's "How it works" has the full picture.

### Ways a rule goes quiet without saying so

A rule that matches nothing looks the same as a rule that finds nothing. These
are the settings that produce one, and none of them warns:

- **`secretGroup: 0`** is not the same as omitting the field. A rule that names a
  capture group is treated as capturing a free-form value, which brings in the
  placeholder and shape tests that the built-in assignment rules rely on — so a
  value that is all digits, or a path, or a URL, is skipped. Omit the field when
  the whole match is the secret.
- **`entropyThreshold` above 8.** Shannon entropy is at most 8 bits per
  character, so anything higher rejects every match. `1e999` parses as
  `Infinity` and is accepted.
- **`secretGroup` pointing at a group the pattern does not have.** The capture is
  `undefined` and the match is dropped.
- **`flags` containing `y`.** A sticky pattern only matches at position 0, so the
  rule finds a secret at the very start of a file and nothing anywhere else.
- **A large `contextWindow`.** It widens `excludeContext` as well as
  `contextWords`, so a single `buffer` anywhere in a large file can suppress
  every postal-code match in it.

- **A value that is filler or a documented example.** A run of one character
  after a short prefix (`ghp_xxxxxxxx…`, `AC000…`) is a placeholder, and so is
  one of the three values vendors print in their own documentation: AWS's
  secret access key, Stripe's test secret key and the jwt.io token. The
  documented values are matched whole, so a real value that begins with one is
  still a finding.

After writing or overriding a rule, check it against a file you expect it to
catch. An override that fails to compile leaves the built-in in place and says so
on stderr; one that compiles and matches nothing replaces the built-in silently.

## Custom Rules

All built-in rules are defined in `src/lib/default-config.json` as JSON data. You can add your own rules or override built-in ones without modifying the plugin source.

### Config file

Create `~/.config/sensitive-canary/config.json`, or set the `SENSITIVE_CANARY_CONFIG` environment variable to a custom path (e.g. in the `env` block of your Claude Code `settings.json`).

### Rule fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique identifier. Matching a built-in id overrides it. |
| `description` | string | yes | Human-readable label shown in block messages. |
| `regex` | string | yes | Regex source (not a `/literal/`). |
| `category` | `"secret"` \| `"pii"` | yes | Which category the rule belongs to. |
| `flags` | string | no | Regex flags. `g` is added if you leave it out, since the scan needs every match; `y` makes a rule match only at the start of the text, which is almost never what a detection rule wants |
| `secretGroup` | number | no | Capture group containing the secret. Omit it for the full match — writing `0` is not the same as omitting it, see [Ways a rule goes quiet without saying so](#ways-a-rule-goes-quiet-without-saying-so) |
| `entropyThreshold` | number | no | Skip matches below this Shannon entropy (bits/char). |
| `requireContext` | boolean | no | Only fire when a context word is nearby. |
| `contextWords` | string[] | no | Words that satisfy `requireContext`. |
| `contextWindow` | number | no | Per-rule override for context scan width (tokens). |
| `excludeContext` | string[] | no | Words that suppress a match when one is near it — the inverse of `contextWords`. The postal-code rule uses `buffer`, `bytes`, `byte`, `memory` and `cache`, so `65536 bytes` is a size rather than a place |
| `validate` | string | no | Name of a built-in checksum validator. |
| `columnLabels` | string[] | no | Header names of a column, compared after trimming, unquoting, lower-casing, and with spaces, underscores and hyphens treated alike. A cell under a matching header is a value. Needs `cellRegex` |
| `cellRegex` | string | no | The value in a column, matched against the whole trimmed, unquoted cell with the rule's flags minus `g` and `y`. Anchored in code, so it describes the cell. The rule's `validate` applies to the cell too. Needs `columnLabels` |

A header is recognised in four shapes: a CSV line (a comma, with quotes respected), a TSV line (a tab), a Markdown table (at least two pipes, with the separator row skipped), and the column list of a SQL `INSERT INTO name (…) VALUES`, read against the tuples after it. A line is tried as a Markdown row first, then as TSV, then as CSV, and the header's delimiter then fixes the table: a line without that delimiter ends it. A CSV record may span lines when a cell is quoted. A quote with no later quote in the text is a character, and a record that holds one is skipped, so a stray quote does not run to the end of the text. A cell may contain a `|` or a tab, so neither ends a table. A blank line is skipped rather than ending the table. In a SQL tuple, a comma, a `)` or an `INSERT` inside single quotes is part of the value. A line with no delimiter is not a row, so a single `dob` line over a date is not read. The same rule is a known limit: a line of prose between two rows ends the table, and the rows after it are read only by the per-line regex, which needs a label beside the value.

### Available validators

| Name | Algorithm |
|------|-----------|
| `luhn` | Luhn checksum, and not a card number the payment gateways publish as test data |
| `aws-key` | Not a key ending in `EXAMPLE`, which is how AWS writes every key in its documentation |
| `phone-jp` | Ten or eleven digits beginning with 0, excluding the 0120 and 0800 freephone prefixes, which belong to a business |
| `mynumber-jp` | Japanese Individual Number (My Number) |
| `nir-fr` | French NIR / Social Security Number |
| `codice-fiscale-it` | Italian Codice Fiscale |
| `steuer-id-de` | German Steuer-Identifikationsnummer |
| `dni-nie-es` | Spanish DNI / NIE |
| `rrn-kr` | Korean Resident Registration Number |
| `brn-kr` | Korean Business Registration Number |
| `resident-id-cn` | Chinese Resident Identity Card |
| `public-ipv4` | Rejects reserved IPv4 ranges |
| `public-ipv6` | Rejects reserved IPv6 ranges |
| `password-like` | Six to 128 characters, no whitespace, a letter, and a digit or a symbol; not a `$VAR`, `%VAR%`, slot, flag, path, or an all-asterisk mask |
| `basic-credentials` | Base64 that decodes to printable UTF-8 `user:password`, with a non-empty user name and password |
| `iban` | ISO 13616 mod-97 check; the length for the countries in the registry table, and fifteen to thirty-four characters for the rest |
| `phone-intl` | Nine to fifteen digits, not all the same digit |
| `nino-uk` | The first letter is not D, F, I, Q, U or V; the second is not D, F, I, O, Q, U or V; the prefix is not BG, GB, KN, NK, NT, TN or ZZ |
| `phone-us` | Not area code 555; not the 555 exchange with line 0100 to 0199 or 1212; not a toll-free area code (800, 888, 877, 866, 855, 844, 833) |
| `personal-mailbox` | The local part is not a role name (`noreply`, `no-reply`, `donotreply`, `do-not-reply`, `support`, `sales`, `info`, `help`, `contact`, `press`, `abuse`, `postmaster`, `webmaster`, `hostmaster`), compared whole and case-insensitively |
| `aws-secret-shape` | Contains an upper case letter, a lower case letter and a digit |
| `birth-date` | A calendar date between 1900 and this year, in the forms the date-of-birth rule reads (ISO, slash, dot, English, 年月日, era years, `S63.7.21`), German, French, Italian and Spanish month names with and without accents (`12. März 1985`, `1er mars 1985`, `12 de marzo de 1985`), Korean `1985년 3월 12일` and `1985. 3. 12.`, and Chinese `号` as the day counter; not `1970-01-01` or `1900-01-01` |

### Global context window

Set `contextWindow` at the top level to override the default (3 tokens ≈ 24 characters):

```json
{
  "contextWindow": 5,
  "rules": []
}
```

### Examples

Add a custom secret pattern:

```json
{
  "rules": [
    {
      "id": "custom-api-key",
      "description": "My Service API Key",
      "regex": "MYSVC-[A-Za-z0-9]{32}",
      "category": "secret",
      "entropyThreshold": 3.5
    }
  ]
}
```

Add a context-gated PII rule:

```json
{
  "rules": [
    {
      "id": "employee-id",
      "description": "Employee ID",
      "regex": "EMP\\d{6}",
      "category": "pii",
      "requireContext": true,
      "contextWords": ["employee", "staff", "社員"]
    }
  ]
}
```

Override a built-in rule (same `id` replaces the original):

```json
{
  "rules": [
    {
      "id": "pii-email",
      "description": "Internal Email Only",
      "regex": "[A-Za-z0-9]+@internal\\.corp\\.(com|org)",
      "category": "pii"
    }
  ]
}
```

Invalid rules (bad regex, wrong types, missing required fields) are skipped with a warning on stderr. The rest of the config loads normally. Each rule is validated against a strict schema before compilation:

- **Required**: `id`, `description`, `regex` (non-empty strings), `category` (`"secret"` or `"pii"`)
- **Type-checked**: `flags` (string), `secretGroup` (non-negative integer), `entropyThreshold` (non-negative number), `validate` (string), `contextWords` (array of non-empty strings), `requireContext` (boolean), `contextWindow` (positive integer)
- **Cross-field**: `requireContext: true` without `contextWords` is rejected (empty `contextWords` would disable context gating, making the rule fire on every match)

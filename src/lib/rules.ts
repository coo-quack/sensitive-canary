export interface Finding {
  ruleId: string;
  description: string;
  category: "secret" | "pii";
  matchRedacted: string;
  secretValue: string;
}

interface Rule {
  id: string;
  description: string;
  regex: RegExp;
  secretGroup?: number;
  entropyThreshold?: number;
  validate?: (str: string) => boolean;
  category: "secret" | "pii";
}

// Luhn algorithm checksum validation. Returns true if the number (digits only) passes.
export function luhn(str: string): boolean {
  const digits = str.replace(/\D/g, "");
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

// Shannon entropy (bits per character, 0–8 scale)
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

// Patterns sourced from gitleaks and TruffleHog detector definitions.
// Each rule:
//   regex        — must have /g flag
//   secretGroup  — capture group containing the secret (default: 0 = full match)
//   entropyThreshold — skip match if entropy(secretValue) is below threshold

// ── Secrets ───────────────────────────────────────────────────────────────────

const SECRET_RULES: Rule[] = [
  // Cloud
  {
    id: "aws-access-key",
    description: "AWS Access Key ID",
    regex:
      /\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g,
    category: "secret",
  },
  {
    id: "gcp-api-key",
    description: "Google Cloud API Key",
    regex: /AIza[0-9A-Za-z_-]{35}/g,
    category: "secret",
  },
  {
    id: "private-key",
    description: "PEM Private Key",
    // Covers RSA, EC, DSA, PGP, and OpenSSH private keys
    regex: /-----BEGIN (RSA |EC |DSA |PGP |OPENSSH )?PRIVATE KEY/g,
    category: "secret",
  },

  // Source control
  {
    id: "github-pat",
    description: "GitHub Personal Access Token",
    regex: /gh[pousr]_[A-Za-z0-9]{36,255}/g,
    category: "secret",
  },
  {
    id: "github-fine-grained",
    description: "GitHub Fine-Grained Token",
    regex: /github_pat_[A-Za-z0-9_]{82}/g,
    category: "secret",
  },
  {
    id: "gitlab-pat",
    description: "GitLab Personal Access Token",
    regex: /glpat-[A-Za-z0-9_=-]{20,22}/g,
    category: "secret",
  },

  // Package registries
  {
    id: "npm-token",
    description: "npm Access Token",
    regex: /npm_[A-Za-z0-9]{36}/g,
    category: "secret",
  },

  // Communication
  {
    id: "slack-token",
    description: "Slack Token",
    regex: /xox[baprs]-[0-9a-zA-Z-]{10,72}/g,
    category: "secret",
  },
  {
    id: "slack-webhook",
    description: "Slack Webhook URL",
    regex:
      /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]{8,10}\/B[A-Za-z0-9_]{8,12}\/[A-Za-z0-9_]{23,24}/g,
    category: "secret",
  },
  {
    id: "discord-webhook",
    description: "Discord Webhook URL",
    regex:
      /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[A-Za-z0-9_-]{68}/g,
    category: "secret",
  },
  {
    id: "telegram-bot-token",
    description: "Telegram Bot Token",
    regex: /[0-9]{8,10}:AA[0-9A-Za-z_-]{33}/g,
    category: "secret",
  },
  {
    id: "twilio-sid",
    description: "Twilio Account SID",
    regex: /AC[0-9a-f]{32}/g,
    category: "secret",
  },

  // Email services
  {
    id: "sendgrid-key",
    description: "SendGrid API Key",
    regex: /SG\.[A-Za-z0-9_-]{20,24}\.[A-Za-z0-9_-]{39,50}/g,
    category: "secret",
  },
  {
    id: "mailgun-key",
    description: "Mailgun API Key",
    regex: /key-[0-9a-zA-Z]{32}/g,
    category: "secret",
  },
  {
    id: "mailchimp-key",
    description: "Mailchimp API Key",
    regex: /[0-9a-f]{32}-us[0-9]{1,2}/g,
    category: "secret",
  },

  // Payment
  {
    id: "stripe-secret-key",
    description: "Stripe Secret Key",
    regex: /sk_(live|test)_[0-9a-zA-Z]{24}/g,
    category: "secret",
  },
  {
    id: "stripe-restricted-key",
    description: "Stripe Restricted Key",
    regex: /rk_(live|test)_[0-9a-zA-Z]{24}/g,
    category: "secret",
  },

  // AI services
  {
    id: "openai-key",
    description: "OpenAI API Key (legacy)",
    regex: /sk-(?!proj-|ant-)[A-Za-z0-9]{48}/g,
    category: "secret",
  },
  {
    id: "openai-project-key",
    description: "OpenAI Project API Key",
    regex: /sk-proj-[A-Za-z0-9_-]{40,}/g,
    entropyThreshold: 3.5,
    category: "secret",
  },
  {
    id: "anthropic-key",
    description: "Anthropic API Key",
    regex: /sk-ant-[A-Za-z0-9_-]{95}/g,
    category: "secret",
  },

  // Auth tokens
  {
    id: "jwt",
    description: "JSON Web Token (JWT)",
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    category: "secret",
  },

  // Generic / env-based
  {
    id: "generic-secret",
    description: "Generic API Key / Secret",
    regex:
      /(api[_-]?key|secret[_-]?key|access[_-]?token|api[_-]?secret)\s*[:=]\s*['"]?([A-Za-z0-9\-_.]{20,})/gi,
    secretGroup: 2,
    entropyThreshold: 3.5,
    category: "secret",
  },
  {
    id: "env-assignment",
    description: ".env style secret assignment",
    regex:
      /\b[A-Z_]*(SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|PRIVATE_KEY)[A-Z_0-9]*\s*=\s*(\S{8,})/g,
    secretGroup: 2,
    entropyThreshold: 3.0,
    category: "secret",
  },
  {
    id: "connection-string",
    description: "Database Connection String with credentials",
    regex: /(mongodb|mysql|postgres|postgresql|redis):\/\/[^:\s]+:[^@\s]+@/g,
    category: "secret",
  },
];

// ── PII ───────────────────────────────────────────────────────────────────────

const PII_RULES: Rule[] = [
  {
    id: "pii-email",
    description: "Email Address",
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    category: "pii",
  },
  {
    id: "pii-credit-card",
    description: "Credit Card Number",
    // Visa (16d) | Mastercard (16d) | Amex (15d) | Discover (16d)
    // Optional spaces or dashes between digit groups
    regex:
      /\b(?:4[0-9]{3}(?:[\s-]?[0-9]{4}){3}|5[1-5][0-9]{2}(?:[\s-]?[0-9]{4}){3}|3[47][0-9]{2}[\s-]?[0-9]{6}[\s-]?[0-9]{5}|6(?:011|5[0-9]{2})[0-9](?:[\s-]?[0-9]{4}){3})\b/g,
    validate: luhn,
    category: "pii",
  },
  {
    id: "pii-ssn",
    description: "US Social Security Number",
    regex: /\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b/g,
    category: "pii",
  },
  {
    id: "pii-phone-us",
    description: "US Phone Number",
    regex: /\b(\+1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g,
    category: "pii",
  },
  {
    id: "pii-phone-jp",
    description: "Japanese Phone Number",
    regex: /\b0\d{1,4}[\s-]\d{1,4}[\s-]\d{4}\b/g,
    category: "pii",
  },
  {
    id: "pii-postal-jp",
    description: "Japanese Postal Code",
    // Require 〒 prefix to avoid false positives (e.g. phone number fragments)
    regex: /〒\d{3}[\s-]\d{4}/g,
    category: "pii",
  },
  {
    id: "pii-ipv4",
    description: "IPv4 Address (private range)",
    // Only flag RFC-1918 private addresses to reduce noise
    regex:
      /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
    category: "pii",
  },
];

export const RULES: Rule[] = [...SECRET_RULES, ...PII_RULES];

// Show first 4 + **** + last 4 chars; fully mask strings of 8 chars or fewer
export function redact(str: string): string {
  if (str.length <= 8) return "****";
  return `${str.slice(0, 4)}****${str.slice(-4)}`;
}

export function scan(text: string): Finding[] {
  const findings: Finding[] = [];

  for (const rule of RULES) {
    for (const match of text.matchAll(rule.regex)) {
      const secretValue =
        rule.secretGroup != null ? match[rule.secretGroup] : match[0];

      if (!secretValue) continue;
      if (
        rule.entropyThreshold != null &&
        entropy(secretValue) < rule.entropyThreshold
      )
        continue;
      if (rule.validate != null && !rule.validate(match[0])) continue;

      findings.push({
        ruleId: rule.id,
        description: rule.description,
        category: rule.category,
        matchRedacted: redact(secretValue),
        secretValue,
      });
    }
  }

  return findings;
}

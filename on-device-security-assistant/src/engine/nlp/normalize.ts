import { BRANDS } from '../domain/brands';

/**
 * Undoes common filter-evasion tricks before rules run:
 *   hidden characters, look-alike letters from other alphabets, spaced-out letters, leetspeak.
 * URLs are never rewritten so domain analysis still sees the real address.
 */
export type ObfuscationKind = 'hidden-chars' | 'mixed-script' | 'spaced-letters' | 'leet';

export interface ObfuscationFinding {
  kind: ObfuscationKind;
  weight: number;
  reason: string;
  evidence: string;
}

export interface NormalizedText {
  text: string;
  findings: ObfuscationFinding[];
}

const KIND_INFO: Record<ObfuscationKind, { weight: number; reason: string }> = {
  'hidden-chars': { weight: 15, reason: 'Contains invisible characters, a trick used to dodge scam filters' },
  'mixed-script': { weight: 25, reason: 'Mixes look-alike letters from other alphabets into words to disguise them' },
  'spaced-letters': { weight: 25, reason: 'Spreads letters apart to hide keywords from filters' },
  leet: { weight: 25, reason: 'Swaps letters for digits or symbols to disguise words' },
};

const ZERO_WIDTH_RE = /[\u200B-\u200D\u2060\uFEFF\u00AD]/g;
const URL_SPLIT = /(https?:\/\/\S+|www\.\S+)/gi;
const SPACED_RE = /\b(?:[A-Za-z][ \t.\-_*]){2,}[A-Za-z]\b/g;
const LEET_TOKEN_RE = /[A-Za-z0-9@$]{3,}/g;

/** Cyrillic and Greek letters that look like Latin ones. */
const CONFUSABLES: Record<string, string> = {
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c', '\u0445': 'x',
  '\u0443': 'y', '\u0456': 'i', '\u0455': 's', '\u0458': 'j', '\u04BB': 'h', '\u0501': 'd',
  '\u03BF': 'o', '\u03B1': 'a', '\u03BD': 'v',
  '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041A': 'K', '\u041C': 'M', '\u041D': 'H',
  '\u041E': 'O', '\u0420': 'P', '\u0421': 'C', '\u0422': 'T', '\u0425': 'X',
};

const LEET: Record<string, string> = { '0': 'o', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', $: 's' };

/** Words scammers disguise. Leet/spaced text is only rewritten when it decodes to one of these. */
const VOCAB = new Set<string>([
  'otp', 'pin', 'cvv', 'kyc', 'upi', 'verify', 'verification', 'account', 'block', 'blocked',
  'suspend', 'suspended', 'password', 'urgent', 'urgently', 'immediately', 'bank', 'prize',
  'refund', 'click', 'login', 'update', 'confirm', 'expire', 'expired', 'expires', 'lottery',
  'winner', 'claim', 'reward', 'cashback', 'aadhaar', 'netbanking', 'card', 'debit', 'credit',
  'unlock', 'security', 'alert', ...BRANDS.map((b) => b.name),
]);

function decodeLeet(token: string): string | null {
  if (!/[013457@$]/.test(token) || /\d{3}/.test(token) || !/[A-Za-z]/.test(token)) return null;
  const base = Array.from(token.toLowerCase(), (c) => LEET[c] ?? c).join('');
  for (const one of ['i', 'l']) {
    const candidate = base.replace(/1/g, one);
    if (VOCAB.has(candidate)) return candidate;
  }
  return null;
}

type Found = Record<ObfuscationKind, string[]>;

function deobfuscateSegment(segment: string, found: Found): string {
  // 1. Latin letters mixed with Cyrillic/Greek look-alikes inside one word.
  let out = segment
    .split(/(\s+)/)
    .map((token) => {
      if (!/[A-Za-z]/.test(token) || !/[\u0370-\u03FF\u0400-\u04FF]/.test(token)) return token;
      found['mixed-script'].push(token);
      return Array.from(token, (ch) => CONFUSABLES[ch] ?? ch).join('');
    })
    .join('');

  // 2. "o t p", "u.r.g.e.n.t": collapse when the result is a long word or scam vocabulary.
  out = out.replace(SPACED_RE, (match) => {
    const collapsed = match.replace(/[ \t.\-_*]/g, '');
    if (collapsed.length >= 5 || VOCAB.has(collapsed.toLowerCase())) {
      found['spaced-letters'].push(match);
      return collapsed;
    }
    return match;
  });

  // 3. Leetspeak, only when it decodes to scam vocabulary (so "4G" or "3rd" are never touched).
  out = out.replace(LEET_TOKEN_RE, (token) => {
    const decoded = decodeLeet(token);
    if (decoded === null) return token;
    found.leet.push(token);
    return decoded;
  });

  return out;
}

export function normalizeText(input: string): NormalizedText {
  const found: Found = { 'hidden-chars': [], 'mixed-script': [], 'spaced-letters': [], leet: [] };

  let text = input.normalize('NFKC'); // also folds full-width letters (ＯＴＰ -> OTP)

  const hidden = text.match(ZERO_WIDTH_RE);
  if (hidden && hidden.length >= 2) found['hidden-chars'].push(`${hidden.length} invisible characters`);
  text = text.replace(ZERO_WIDTH_RE, '');

  // split() with a capture group keeps URLs at odd indexes; only rewrite the text between them.
  text = text
    .split(URL_SPLIT)
    .map((part, i) => (i % 2 === 1 ? part : deobfuscateSegment(part, found)))
    .join('');

  const findings = (Object.keys(found) as ObfuscationKind[])
    .filter((kind) => found[kind].length > 0)
    .map((kind) => ({ kind, ...KIND_INFO[kind], evidence: found[kind].slice(0, 3).join(', ') }));

  return { text, findings };
}
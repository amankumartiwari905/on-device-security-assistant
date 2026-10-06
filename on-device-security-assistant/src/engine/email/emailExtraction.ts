/**
 * Finds candidate email addresses in raw page text / HTML / href values.
 * It does not judge them; emailAnalyzer.ts does that.
 */
export type EmailSource = 'text' | 'mailto' | 'obfuscated';

export interface EmailCandidate {
  address: string;
  obfuscated: boolean;
  source: EmailSource;
  occurrences: number;
  /** Name shown in front of the address: "PayPal Support" <alerts@example.com> */
  displayName?: string;
}

const MAX_SOURCE_CHARS = 200_000;
const MAX_CANDIDATES = 100;

const EMAIL_CANDIDATE = /[^\s<>()\[\]{}"',;]+@[^\s<>()\[\]{}"',;]+/g;
const OBFUSCATED_EMAIL = /\b([a-z0-9.!#$%&'*+/=?^_`{|}~-]+)\s*(?:\[at\]|\(at\)|\{at\})\s*([a-z0-9.-]+(?:(?:\s*\[dot\]\s*|\s*\(dot\)\s*|\s*\{dot\}\s*)[a-z0-9-]+)+)/gi;
const OBFUSCATED_BRACKET_AT = /\b([a-z0-9._%+-]+)\s*(?:\[@\]|\(@\))\s*([a-z0-9-]+(?:\.[a-z0-9-]+)+)/gi;
const OBFUSCATED_WORDS = /\b([a-z0-9._%+-]+)\s+at\s+([a-z0-9-]+(?:\s+dot\s+[a-z0-9-]+)+)\b/gi;
const MAILTO = /mailto:([^?\s"'<>]*)(?:\?([^\s"'<>]*))?/gi;
const DISPLAY_NAME = /(?:"([^"\n]{1,80})"|\b([A-Za-z][A-Za-z0-9 .,'&_-]{0,60}?))\s*<\s*([^<>\s,;]+@[^<>\s,;]+?)\s*>/g;
const HEADER_PREFIX = /^(?:from|to|cc|bcc|reply-to|sender)\s*:\s*/i;
const ZERO_WIDTH = /[\u200B-\u200D\u2060\uFEFF]/g;

function cleanCandidate(value: string): string {
  return value.replace(/^[.,:;]+|[.,:;!?]+$/g, '');
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** Decodes numeric/named entities for printable ASCII only (&#64; -> @, &commat; -> @). */
function decodeEntities(value: string): string {
  const toChar = (match: string, code: number): string => (code >= 32 && code <= 126 ? String.fromCharCode(code) : match);
  return value
    .replace(/&#(\d{1,3});/g, (match, n: string) => toChar(match, Number(n)))
    .replace(/&#x([0-9a-f]{1,2});/gi, (match, h: string) => toChar(match, parseInt(h, 16)))
    .replace(/&commat;/gi, '@')
    .replace(/&period;/gi, '.');
}

function normalizeSource(source: string): string {
  // NFKC also folds full-width characters (＠ -> @).
  return decodeEntities(source.slice(0, MAX_SOURCE_CHARS).normalize('NFKC')).replace(ZERO_WIDTH, '');
}

function parseMailto(target: string, query?: string): string[] {
  const values = [safeDecode(target)];
  if (query) {
    for (const [key, value] of new URLSearchParams(query)) {
      if (/^(?:to|cc|bcc)$/i.test(key)) values.push(value);
    }
  }
  return values.flatMap((v) => v.split(/[,;]/)).map((v) => v.trim()).filter(Boolean);
}

export function extractEmailCandidates(sources: readonly string[]): EmailCandidate[] {
  const found = new Map<string, EmailCandidate>();
  const displayNames = new Map<string, string>();

  const add = (rawAddress: string, source: EmailSource): void => {
    const address = cleanCandidate(rawAddress);
    if (!address) return;

    const key = address.toLowerCase();
    const existing = found.get(key);
    if (existing) {
      existing.occurrences += 1;
      if (existing.obfuscated && source !== 'obfuscated') {
        existing.obfuscated = false; // seen written plainly at least once
        existing.source = source;
      }
      return;
    }
    if (found.size >= MAX_CANDIDATES) return;
    found.set(key, { address, obfuscated: source === 'obfuscated', source, occurrences: 1 });
  };

  for (const source of sources) {
    let text = normalizeSource(source);

    // mailto: first, otherwise "mailto:a@b.com?subject=x" is misread as one malformed address.
    text = text.replace(MAILTO, (_match: string, target: string, query: string | undefined) => {
      for (const address of parseMailto(target, query)) add(address, 'mailto');
      return ' ';
    });

    if (text.includes('<') && text.includes('@')) {
      for (const m of text.matchAll(DISPLAY_NAME)) {
        const name = (m[1] ?? m[2] ?? '').replace(HEADER_PREFIX, '').trim();
        const address = cleanCandidate(m[3]).toLowerCase();
        if (name && address && !displayNames.has(address)) displayNames.set(address, name);
      }
    }

    for (const m of text.matchAll(OBFUSCATED_EMAIL)) {
      const domain = m[2].replace(/\s*(?:\[dot\]|\(dot\)|\{dot\})\s*/gi, '.');
      add(`${m[1]}@${domain}`, 'obfuscated');
    }
    for (const m of text.matchAll(OBFUSCATED_BRACKET_AT)) add(`${m[1]}@${m[2]}`, 'obfuscated');
    for (const m of text.matchAll(OBFUSCATED_WORDS)) add(`${m[1]}@${m[2].replace(/\s+dot\s+/gi, '.')}`, 'obfuscated');
    for (const m of text.matchAll(EMAIL_CANDIDATE)) add(m[0], 'text');
  }

  return [...found.values()].map((candidate) => ({
    ...candidate,
    displayName: displayNames.get(candidate.address.toLowerCase()),
  }));
}
import { BRANDS } from '../domain/brands';
import { getRegistrableDomain, parseUrl } from '../url/urlFeatures';

const URL_RE = /(?:https?:\/\/|www\.)[^\s<>"')]+/gi;
const PHONE_RE = /(?:\+?91[\s-]?)?\b[6-9]\d{9}\b|\b1800[\s-]?\d{3}[\s-]?\d{3,4}\b|\+\d{1,3}[\s-]?\d{6,12}\b/g;
const CALL_VERB_RE = /\b(?:call|contact|whatsapp|dial|ring|helpline|customer care)\b/i;

export function extractUrls(text: string): string[] {
  return (text.match(URL_RE) ?? [])
    .slice(0, 10)
    .map((u) => u.replace(/[.,;:!?]+$/, ''))
    .map((u) => (/^https?:/i.test(u) ? u : `http://${u}`));
}

export function hostOf(url: string): string {
  return parseUrl(url)?.hostname ?? 'unknown';
}

function mentionsBrand(haystackLower: string, name: string): boolean {
  if (new RegExp(`\\b${name}\\b`).test(haystackLower)) return true;
  return name.length >= 7 && haystackLower.replace(/\s+/g, '').includes(name);
}

/** The message names a known brand but none of its links go to that brand. */
export function findBrandLinkMismatch(text: string, urls: string[]): { brand: string; url: string; host: string } | null {
  const parsed = urls.map((u) => ({ url: u, parsed: parseUrl(u) })).filter((x) => x.parsed !== null);
  if (parsed.length === 0) return null;

  const lower = text.toLowerCase();
  const domains = parsed.map((x) => getRegistrableDomain(x.parsed!.hostname));

  for (const brand of BRANDS) {
    if (!mentionsBrand(lower, brand.name)) continue;
    if (domains.some((d) => brand.domains.includes(d))) continue; // links to the genuine site
    return { brand: brand.name, url: parsed[0].url, host: parsed[0].parsed!.hostname };
  }
  return null;
}

/** A phone number the message tells you to call/contact (vishing). */
export function findCallbackNumber(text: string): string | null {
  for (const m of text.matchAll(PHONE_RE)) {
    const index = m.index ?? 0;
    if (CALL_VERB_RE.test(text.slice(Math.max(0, index - 40), index))) return m[0];
  }
  return null;
}
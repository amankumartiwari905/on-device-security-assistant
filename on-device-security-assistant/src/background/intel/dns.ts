import { fetchJson } from './http';
import { isRecord } from './util';

/** DNS-over-HTTPS with failover: the second provider is only used if the first fails. */
const DOH_ENDPOINTS = ['https://dns.google/resolve', 'https://cloudflare-dns.com/dns-query'] as const;
const TYPE_A = 1;
const TYPE_CNAME = 5;
const TYPE_MX = 15;
const TYPE_TXT = 16;

export type DmarcPolicy = 'none' | 'quarantine' | 'reject';

export interface DnsAnswer {
  type: number;
  value: string;
}

export interface DnsResult {
  nxdomain: boolean;
  answers: DnsAnswer[];
}

export interface DnsFacts {
  /** The domain does not exist at all. null = unknown. */
  nxdomain: boolean | null;
  hasMx: boolean | null;
  mxHosts: string[];
  /** RFC 7505 "null MX": the domain says it never accepts email. */
  nullMx: boolean;
  /** Has an address (A) or alias (CNAME) record. null = unknown. */
  resolves: boolean | null;
  hasSpf: boolean | null;
  /** The "all" mechanism of the SPF record, e.g. "-all", "~all", "+all". */
  spfAll: string | null;
  hasDmarc: boolean | null;
  dmarcPolicy: DmarcPolicy | null;
  errors: string[];
}

export function parseDnsResponse(data: unknown): DnsResult {
  if (!isRecord(data) || typeof data.Status !== 'number') throw new Error('DNS provider returned an invalid response.');
  // 0 = ok, 3 = NXDOMAIN (a valid answer: the name does not exist). Anything else triggers failover.
  if (data.Status !== 0 && data.Status !== 3) throw new Error(`DNS lookup returned status ${data.Status}.`);

  const answers = (Array.isArray(data.Answer) ? data.Answer : [])
    .filter(isRecord)
    .filter((a) => typeof a.type === 'number' && typeof a.data === 'string')
    .map((a) => ({ type: a.type as number, value: (a.data as string).trim() }));
  return { nxdomain: data.Status === 3, answers };
}

export function parseMx(answers: readonly DnsAnswer[]): { hosts: string[]; nullMx: boolean } {
  const records = answers.filter((a) => a.type === TYPE_MX);
  const hosts = records
    .map((a) => a.value.split(/\s+/).slice(1).join(' ').replace(/\.$/, '').toLowerCase())
    .filter(Boolean);
  return { hosts: [...new Set(hosts)].slice(0, 5), nullMx: records.length > 0 && hosts.length === 0 };
}

/** TXT data arrives quoted and may be split into several quoted chunks. */
export function unquoteTxt(value: string): string {
  return value.replace(/"\s+"/g, '').replace(/^"|"$/g, '');
}

export function txtRecords(answers: readonly DnsAnswer[]): string[] {
  return answers.filter((a) => a.type === TYPE_TXT).map((a) => unquoteTxt(a.value));
}

export function parseSpf(records: readonly string[]): { present: boolean; all: string | null } {
  const spf = records.find((r) => r.toLowerCase().startsWith('v=spf1'));
  if (!spf) return { present: false, all: null };
  const match = spf.toLowerCase().match(/(?:^|\s)([+\-~?]?)all(?:\s|$)/);
  return { present: true, all: match ? `${match[1] || '+'}all` : null };
}

export function parseDmarc(records: readonly string[]): { present: boolean; policy: DmarcPolicy | null } {
  const record = records.find((r) => /^v=dmarc1\b/i.test(r));
  if (!record) return { present: false, policy: null };

  const tags = new Map<string, string>();
  for (const part of record.split(';')) {
    const [name, ...rest] = part.split('=');
    if (name && rest.length > 0) tags.set(name.trim().toLowerCase(), rest.join('=').trim().toLowerCase());
  }
  const p = tags.get('p');
  return { present: true, policy: p === 'none' || p === 'quarantine' || p === 'reject' ? p : null };
}

async function dohQuery(name: string, type: 'A' | 'MX' | 'TXT'): Promise<DnsResult> {
  let lastError: unknown;
  for (const endpoint of DOH_ENDPOINTS) {
    try {
      const data = await fetchJson(`${endpoint}?name=${encodeURIComponent(name)}&type=${type}`, { accept: 'application/dns-json' });
      return parseDnsResponse(data);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError instanceof Error ? lastError : new Error('DNS lookup failed.');
}

/** Looks up everything we score from. Never throws; failures are reported in `errors`. */
export async function lookupDomainDns(domain: string, registrable: string = domain): Promise<DnsFacts> {
  const facts: DnsFacts = {
    nxdomain: null,
    hasMx: null,
    mxHosts: [],
    nullMx: false,
    resolves: null,
    hasSpf: null,
    spfAll: null,
    hasDmarc: null,
    dmarcPolicy: null,
    errors: [],
  };

  const [mx, txt, dmarc, address] = await Promise.allSettled([
    dohQuery(domain, 'MX'),
    dohQuery(domain, 'TXT'),
    dohQuery(`_dmarc.${domain}`, 'TXT'),
    dohQuery(domain, 'A'),
  ]);

  if (mx.status === 'fulfilled') {
    const parsed = parseMx(mx.value.answers);
    facts.hasMx = parsed.hosts.length > 0;
    facts.mxHosts = parsed.hosts;
    facts.nullMx = parsed.nullMx;
    facts.nxdomain = mx.value.nxdomain;
  } else {
    facts.errors.push('DNS/MX lookup failed.');
  }

  if (txt.status === 'fulfilled') {
    const spf = parseSpf(txtRecords(txt.value.answers));
    facts.hasSpf = spf.present;
    facts.spfAll = spf.all;
  } else {
    facts.errors.push('SPF lookup failed.');
  }

  if (dmarc.status === 'fulfilled') {
    const parsed = parseDmarc(txtRecords(dmarc.value.answers));
    facts.hasDmarc = parsed.present;
    facts.dmarcPolicy = parsed.policy;
  } else {
    facts.errors.push('DMARC lookup failed.');
  }

  if (address.status === 'fulfilled') {
    facts.resolves = address.value.answers.some((a) => a.type === TYPE_A || a.type === TYPE_CNAME);
    if (facts.nxdomain === null) facts.nxdomain = address.value.nxdomain;
  } else {
    facts.errors.push('Address lookup failed.');
  }

  // A subdomain inherits the DMARC policy of its organizational domain.
  if (facts.hasDmarc === false && registrable !== domain) {
    try {
      const parent = parseDmarc(txtRecords((await dohQuery(`_dmarc.${registrable}`, 'TXT')).answers));
      if (parent.present) {
        facts.hasDmarc = true;
        facts.dmarcPolicy = parent.policy;
      }
    } catch {
      facts.errors.push('Parent DMARC lookup failed.');
    }
  }

  return facts;
}
import { analyzeSenderIdentity } from './senderIdentity';
import { combineWeights, findBrand } from './emailSignals';
import type { EmailSignal } from './emailSignals';
import { getRegistrableDomain } from '../url/urlFeatures';

export type AuthMethod = 'spf' | 'dkim' | 'dmarc';
export type AuthResult = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror';

export interface HeaderAuthClaim {
  method: AuthMethod;
  result: AuthResult;
  authservId: string;
  identityDomain: string | null;
  source: 'Authentication-Results' | 'Received-SPF';
}

export type AuthAlignment = 'aligned' | 'not-aligned' | 'unknown';

export interface EmailHeaderAssessment {
  from: string | null;
  senderDisplayName: string | null;
  senderDomain: string | null;
  claimedBrand: string | null;
  returnPath: string | null;
  replyTo: string | null;
  claims: HeaderAuthClaim[];
  alignment: Record<AuthMethod, AuthAlignment>;
  dmarcStatus: 'reported-pass' | 'reported-fail' | 'reported-inconclusive' | 'missing';
  riskScore: number;
  signals: EmailSignal[];
  warnings: string[];
}

export const MAX_HEADER_SIZE = 50_000;
export const MAX_EML_SIZE = 1_000_000;

export function extractHeaderBlock(rawMessage: string): string {
  const separator = /\r?\n\r?\n/.exec(rawMessage);
  const headerBlock = separator ? rawMessage.slice(0, separator.index) : rawMessage;
  if (headerBlock.length > MAX_HEADER_SIZE) {
    throw new Error(`Email headers must be ${MAX_HEADER_SIZE.toLocaleString()} characters or fewer.`);
  }
  return headerBlock.replace(/^\uFEFF/, '');
}

function parseHeaders(headerBlock: string): Map<string, string[]> {
  const unfolded: string[] = [];
  for (const line of headerBlock.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n')) {
    if (/^[ \t]/.test(line) && unfolded.length > 0) {
      unfolded[unfolded.length - 1] += ` ${line.trim()}`;
    } else {
      unfolded.push(line);
    }
  }

  const headers = new Map<string, string[]>();
  for (const line of unfolded) {
    const separator = line.indexOf(':');
    if (separator <= 0) continue;
    const name = line.slice(0, separator).trim().toLowerCase();
    if (!/^[a-z0-9-]+$/.test(name)) continue;
    const value = line.slice(separator + 1).trim();
    const values = headers.get(name) ?? [];
    values.push(value);
    headers.set(name, values);
  }
  if (headers.size === 0) throw new Error('No valid email headers were found.');
  return headers;
}

function firstAddress(value: string | undefined): string | null {
  if (!value) return null;
  const bracketed = value.match(/<\s*([^<>\s,;]+@[^<>\s,;]+)\s*>/);
  const bare = bracketed ? null : value.match(/(?:^|[\s,;])([^<>\s,;]+@[^<>\s,;]+)(?=$|[\s,;])/);
  return (bracketed?.[1] ?? bare?.[1] ?? null)?.replace(/[.,;:]+$/, '') ?? null;
}

function identityDomain(value: string): string | null {
  const match = value.match(/(?:smtp\.mailfrom|envelope-from|header\.d|header\.i|header\.from)\s*=\s*([^\s;]+)/i);
  const raw = match?.[1]?.replace(/^@/, '').replace(/[>,]+$/, '').toLowerCase();
  if (!raw) return null;
  const domain = raw.includes('@') ? raw.slice(raw.lastIndexOf('@') + 1) : raw;
  try {
    return new URL(`http://${domain}`).hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    return null;
  }
}

function parseAuthenticationResults(value: string): HeaderAuthClaim[] {
  const [authservId = 'unknown', ...clauses] = value.split(';');
  const normalizedAuthservId = authservId.trim().slice(0, 160) || 'unknown';
  const claims: HeaderAuthClaim[] = [];
  const methodPattern = /^\s*(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b(.*)$/i;

  for (const clause of clauses) {
    const match = methodPattern.exec(clause);
    if (!match) continue;
    const method = match[1].toLowerCase() as AuthMethod;
    claims.push({
      method,
      result: match[2].toLowerCase() as AuthResult,
      authservId: normalizedAuthservId,
      identityDomain: identityDomain(match[3]),
      source: 'Authentication-Results',
    });
  }
  return claims;
}

function parseReceivedSpf(value: string): HeaderAuthClaim | null {
  const match = /^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b(.*)$/i.exec(value);
  if (!match) return null;
  const authservId = /^\s*\(([^:;)]+)/.exec(match[2])?.[1]?.trim() || 'unknown';
  return {
    method: 'spf',
    result: match[1].toLowerCase() as AuthResult,
    authservId: authservId.slice(0, 160),
    identityDomain: identityDomain(match[2]),
    source: 'Received-SPF',
  };
}

function authenticationSignals(claims: readonly HeaderAuthClaim[]): EmailSignal[] {
  const failed = claims.filter((claim) => ['fail', 'softfail', 'permerror'].includes(claim.result));
  const signals: EmailSignal[] = [];
  for (const method of ['spf', 'dkim', 'dmarc'] as const) {
    const claimsForMethod = failed.filter((claim) => claim.method === method);
    if (claimsForMethod.length === 0) continue;
    const label = method.toUpperCase();
    signals.push({
      id: `header-${method}-failure`,
      weight: method === 'dmarc' ? 65 : 55,
      reason: `Supplied headers report ${label} ${claimsForMethod[0].result}; this result is not independently authenticated`,
    });
  }
  return signals;
}

function addressDomain(value: string | null): string | null {
  if (!value) return null;
  const rawDomain = value.slice(value.lastIndexOf('@') + 1).replace(/\.$/, '').toLowerCase();
  try {
    return getRegistrableDomain(new URL(`http://${rawDomain}`).hostname);
  } catch {
    return null;
  }
}

function claimedAlignment(
  method: AuthMethod,
  claims: readonly HeaderAuthClaim[],
  fromDomain: string | null,
): AuthAlignment {
  const passingClaims = claims.filter((claim) => claim.method === method && claim.result === 'pass');
  if (!passingClaims.length || !fromDomain) return 'unknown';
  const domains = passingClaims.map((claim) => claim.identityDomain).filter((domain): domain is string => Boolean(domain));
  if (!domains.length) return 'unknown';
  return domains.some((domain) => {
    try {
      return getRegistrableDomain(new URL(`http://${domain}`).hostname) === fromDomain;
    } catch {
      return false;
    }
  }) ? 'aligned' : 'not-aligned';
}

export function analyzeEmailHeaders(rawMessage: string): EmailHeaderAssessment {
  const headerBlock = extractHeaderBlock(rawMessage);
  const headers = parseHeaders(headerBlock);
  const fromValue = headers.get('from')?.[0];
  const returnPathValue = headers.get('return-path')?.[0];
  const replyToValue = headers.get('reply-to')?.[0];
  const from = firstAddress(fromValue);
  const returnPath = firstAddress(returnPathValue);
  const replyTo = firstAddress(replyToValue);
  const claims = (headers.get('authentication-results') ?? []).flatMap(parseAuthenticationResults);
  if (claims.length === 0) {
    const receivedSpf = (headers.get('received-spf') ?? [])
      .map(parseReceivedSpf)
      .filter((claim): claim is HeaderAuthClaim => claim !== null);
    claims.push(...receivedSpf);
  }

  const identity = analyzeSenderIdentity({
    from: fromValue ?? '',
    ...(returnPath ? { returnPath } : {}),
    ...(replyTo ? { replyTo } : {}),
  });
  const fromDomain = addressDomain(from);
  const sender = identity.sender;
  const alignment: Record<AuthMethod, AuthAlignment> = {
    spf: claimedAlignment('spf', claims, fromDomain),
    dkim: claimedAlignment('dkim', claims, fromDomain),
    dmarc: claimedAlignment('dmarc', claims, fromDomain),
  };
  const signals = [...identity.signals, ...authenticationSignals(claims)];
  const dmarcClaims = claims.filter((claim) => claim.method === 'dmarc');
  const dmarcStatus: EmailHeaderAssessment['dmarcStatus'] = dmarcClaims.some((claim) => claim.result === 'fail')
    ? 'reported-fail'
    : dmarcClaims.some((claim) => claim.result === 'pass')
      ? 'reported-pass'
      : dmarcClaims.length > 0
        ? 'reported-inconclusive'
        : 'missing';

  const warnings = [
    'Authentication-Results and Received-SPF values are claims from the supplied headers; they can be forged.',
    'Trust results only when these are the original headers from your receiving mail provider.',
    'This check does not independently validate DKIM signatures or prove control of the mailbox.',
    'Alignment uses relaxed registrable-domain comparison; the supplied headers do not establish the domain policy mode.',
  ];
  if (headers.has('dkim-signature') && !claims.some((claim) => claim.method === 'dkim')) {
    warnings.push('A DKIM-Signature header is present, but its signature was not independently verified.');
  }
  if (claims.length === 0) warnings.push('No SPF, DKIM, or DMARC authentication results were found in the supplied headers.');

  return {
    from,
    senderDisplayName: sender?.displayName ?? null,
    senderDomain: sender?.domain ?? null,
    claimedBrand: sender?.displayName ? findBrand(sender.displayName)?.name ?? null : null,
    returnPath,
    replyTo,
    claims,
    alignment,
    dmarcStatus,
    riskScore: combineWeights(signals),
    signals,
    warnings,
  };
}

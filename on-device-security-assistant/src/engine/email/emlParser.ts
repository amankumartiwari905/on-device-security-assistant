import { analyzeEmailHeaders, MAX_EML_SIZE } from './headerVerifier';
import type { EmailHeaderAssessment } from './headerVerifier';

export interface ParsedHeader {
  name: string;
  values: string[];
}

export interface EmailLink {
  url: string;
  displayedText?: string;
  mismatch?: boolean;
  source: 'body' | 'href' | 'image' | 'form';
}

export interface EmailForm {
  action: string;
  method: string;
}

export interface EmailAttachment {
  filename: string;
  extension: string;
  mimeType: string;
  size: number;
  sha256: string;
}

export interface ReceivedRoute {
  header: string;
  ipAddresses: string[];
}

export interface ParsedEmail {
  headers: ParsedHeader[];
  receivedRoute: ReceivedRoute[];
  headerAssessment: EmailHeaderAssessment;
  plainText: string;
  html: string;
  images: string[];
  links: EmailLink[];
  forms: EmailForm[];
  hiddenText: string[];
  attachments: EmailAttachment[];
}

export const MAX_EMAIL_PARTS = 200;
const MAX_MIME_DEPTH = 10;
const RELEVANT_HEADERS = [
  'from',
  'to',
  'cc',
  'reply-to',
  'return-path',
  'subject',
  'date',
  'message-id',
  'received',
  'authentication-results',
  'dkim-signature',
] as const;

interface MimePart {
  headers: Map<string, string[]>;
  body: string;
}

interface MimeState {
  plainText: string[];
  html: string[];
  attachments: EmailAttachment[];
  partCount: number;
}

function splitHeaderBody(raw: string): [string, string] {
  const separator = /\r?\n\r?\n/.exec(raw);
  return separator
    ? [raw.slice(0, separator.index), raw.slice(separator.index + separator[0].length)]
    : [raw, ''];
}

function parseHeaders(raw: string): Map<string, string[]> {
  const unfolded: string[] = [];
  for (const line of raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n')) {
    if (/^[ \t]/.test(line) && unfolded.length > 0) unfolded[unfolded.length - 1] += ` ${line.trim()}`;
    else unfolded.push(line);
  }
  const headers = new Map<string, string[]>();
  for (const line of unfolded) {
    const separator = line.indexOf(':');
    if (separator <= 0) continue;
    const name = line.slice(0, separator).trim().toLowerCase();
    if (!/^[a-z0-9-]+$/.test(name)) continue;
    const values = headers.get(name) ?? [];
    values.push(line.slice(separator + 1).trim());
    headers.set(name, values);
  }
  return headers;
}

function parseMimePart(raw: string): MimePart {
  const [rawHeaders, body] = splitHeaderBody(raw);
  return { headers: parseHeaders(rawHeaders), body };
}

function parameter(value: string, name: string): string | undefined {
  const match = new RegExp(`(?:^|;)\\s*${name}\\s*=\\s*(?:"((?:[^"\\\\]|\\\\.)*)"|([^;\\s]*))`, 'i').exec(value);
  return (match?.[1] ?? match?.[2])?.replace(/\\(.)/g, '$1');
}

function bytesFromBinary(binary: string): Uint8Array {
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function decodePartBytes(body: string, encoding: string): Uint8Array {
  if (encoding.trim().toLowerCase() === 'base64') {
    const compact = body.replace(/\s/g, '');
    try {
      return bytesFromBinary(atob(compact));
    } catch {
      throw new Error('An email part contains invalid base64 data.');
    }
  }
  if (encoding.trim().toLowerCase() === 'quoted-printable') {
    const binary = body
      .replace(/=(?:\r\n|\n|\r)/g, '')
      .replace(/=([0-9a-f]{2})/gi, (_match, hex: string) => String.fromCharCode(parseInt(hex, 16)));
    return bytesFromBinary(binary);
  }
  return new TextEncoder().encode(body);
}

function decodeText(bytes: Uint8Array, contentType: string): string {
  const charset = parameter(contentType, 'charset');
  try {
    return new TextDecoder(charset || 'utf-8').decode(bytes);
  } catch {
    return new TextDecoder('utf-8').decode(bytes);
  }
}

function cleanFilename(raw: string | undefined, contentType: string): string {
  const value = raw ?? parameter(contentType, 'name') ?? 'attachment';
  return value
    .replace(/^\s*["']|["']\s*$/g, '')
    .replace(/[\r\n\\/]/g, '_')
    .slice(0, 255) || 'attachment';
}

async function sha256(bytes: Uint8Array): Promise<string> {
  if (!globalThis.crypto?.subtle) throw new Error('SHA-256 hashing is unavailable in this browser context.');
  const input = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(input).set(bytes);
  const digest = await crypto.subtle.digest('SHA-256', input);
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, '0')).join('');
}

function splitMultipart(body: string, boundary: string): string[] {
  if (!boundary || boundary.length > 200) throw new Error('The email contains an invalid MIME boundary.');
  const escaped = boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const marker = new RegExp(`^--${escaped}(--)?[ \\t]*$`, 'gm');
  const parts: string[] = [];
  let start = -1;
  for (const match of body.matchAll(marker)) {
    const index = match.index ?? 0;
    if (start >= 0) {
      const part = body.slice(start, index).replace(/(?:\r\n|\n|\r)$/, '');
      if (part.trim()) parts.push(part);
    }
    if (match[1] === '--') break;
    start = index + match[0].length;
    if (body.slice(start, start + 2) === '\r\n') start += 2;
    else if (/[\r\n]/.test(body[start] ?? '')) start += 1;
  }
  return parts;
}

async function inspectMimePart(raw: string, state: MimeState, depth: number): Promise<void> {
  state.partCount += 1;
  if (state.partCount > MAX_EMAIL_PARTS) throw new Error(`Email contains more than ${MAX_EMAIL_PARTS} MIME parts.`);
  if (depth > MAX_MIME_DEPTH) throw new Error(`Email MIME nesting exceeds ${MAX_MIME_DEPTH} levels.`);

  const part = parseMimePart(raw);
  const contentType = part.headers.get('content-type')?.[0] ?? 'text/plain';
  const mimeType = contentType.split(';', 1)[0].trim().toLowerCase() || 'application/octet-stream';
  const disposition = part.headers.get('content-disposition')?.[0] ?? '';
  const transferEncoding = part.headers.get('content-transfer-encoding')?.[0] ?? '';
  const filename = cleanFilename(parameter(disposition, 'filename'), contentType);
  const isAttachment = /^attachment\b/i.test(disposition) || Boolean(parameter(disposition, 'filename')) ||
    Boolean(parameter(contentType, 'name'));

  if (mimeType.startsWith('multipart/')) {
    const boundary = parameter(contentType, 'boundary');
    if (!boundary) throw new Error('A multipart email section is missing its MIME boundary.');
    const children = splitMultipart(part.body, boundary);
    for (const child of children) await inspectMimePart(child, state, depth + 1);
    return;
  }

  const bytes = decodePartBytes(part.body, transferEncoding);
  if (isAttachment || (!mimeType.startsWith('text/') && mimeType !== 'message/rfc822')) {
    const extension = filename.includes('.') ? filename.split('.').pop()!.toLowerCase() : '';
    state.attachments.push({
      filename,
      extension,
      mimeType,
      size: bytes.byteLength,
      sha256: await sha256(bytes),
    });
    return;
  }

  const text = decodeText(bytes, contentType);
  if (mimeType === 'text/html') state.html.push(text);
  else if (mimeType === 'text/plain') state.plainText.push(text);
}

function normalizedUrl(value: string): string | null {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed.href : null;
  } catch {
    return null;
  }
}

function extractHtml(html: string): Pick<ParsedEmail, 'images' | 'links' | 'forms' | 'hiddenText'> {
  const document = new DOMParser().parseFromString(html, 'text/html');
  const images: string[] = [];
  const links: EmailLink[] = [];
  const forms: EmailForm[] = [];
  const hiddenText: string[] = [];

  for (const image of document.querySelectorAll('img[src]')) {
    const src = image.getAttribute('src')?.trim();
    if (src) images.push(src);
    const url = src ? normalizedUrl(src) : null;
    if (url) links.push({ url, source: 'image' });
  }

  for (const anchor of document.querySelectorAll('a[href]')) {
    const href = anchor.getAttribute('href')?.trim() ?? '';
    const url = normalizedUrl(href);
    if (!url) continue;
    const displayedText = anchor.textContent?.trim().slice(0, 500);
    const displayedUrl = displayedText ? normalizedUrl(displayedText) : null;
    links.push({
      url,
      displayedText: displayedText || undefined,
      mismatch: Boolean(displayedUrl && displayedUrl !== url),
      source: 'href',
    });
  }

  for (const form of document.querySelectorAll('form')) {
    forms.push({
      action: form.getAttribute('action')?.trim() ?? '',
      method: (form.getAttribute('method') || 'get').toLowerCase(),
    });
    const action = normalizedUrl(form.getAttribute('action')?.trim() ?? '');
    if (action) links.push({ url: action, source: 'form' });
  }

  for (const element of document.querySelectorAll('[hidden], [aria-hidden="true"], [style]')) {
    const style = element.getAttribute('style') ?? '';
    if (element.hasAttribute('hidden') || element.getAttribute('aria-hidden') === 'true' ||
        /(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)/i.test(style)) {
      const text = element.textContent?.trim();
      if (text) hiddenText.push(text.slice(0, 1_000));
    }
  }
  for (const input of document.querySelectorAll('input[type="hidden"]')) {
    const name = input.getAttribute('name')?.trim();
    const value = input.getAttribute('value')?.trim();
    if (name || value) hiddenText.push(`${name || '(unnamed)'}=${value ?? ''}`.slice(0, 1_000));
  }

  return {
    images: [...new Set(images)].slice(0, 100),
    links,
    forms,
    hiddenText: [...new Set(hiddenText)].slice(0, 100),
  };
}

function bodyUrls(text: string): EmailLink[] {
  const links: EmailLink[] = [];
  for (const match of text.matchAll(/https?:\/\/[^\s<>"']+/gi)) {
    const url = normalizedUrl(match[0].replace(/[),.;!?]+$/, ''));
    if (url) links.push({ url, source: 'body' });
  }
  return links;
}

function extractReceivedRoute(headers: Map<string, string[]>): ReceivedRoute[] {
  return (headers.get('received') ?? []).map((header) => {
    const ips = new Set<string>();
    for (const match of header.matchAll(/(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/g)) {
      const parts = match[0].split('.').map(Number);
      if (parts.every((part) => part >= 0 && part <= 255)) ips.add(match[0]);
    }
    for (const match of header.matchAll(/\[(?:IPv6:)?([0-9a-f:]{3,})\]/gi)) {
      try {
        const hostname = new URL(`http://[${match[1]}]/`).hostname;
        if (hostname.includes(':')) ips.add(hostname.slice(1, -1));
      } catch {
        // Ignore bracketed values that are not valid IPv6 addresses.
      }
    }
    return { header, ipAddresses: [...ips] };
  });
}

export async function parseEml(rawMessage: string): Promise<ParsedEmail> {
  if (rawMessage.length > MAX_EML_SIZE || new TextEncoder().encode(rawMessage).byteLength > MAX_EML_SIZE) {
    throw new Error(`Email must be ${MAX_EML_SIZE.toLocaleString()} bytes or fewer.`);
  }
  const normalizedMessage = rawMessage.replace(/^\uFEFF/, '');
  const [rawHeaders] = splitHeaderBody(normalizedMessage);
  const topHeaders = parseHeaders(rawHeaders);
  if (topHeaders.size === 0) throw new Error('No valid email headers were found.');

  const state: MimeState = { plainText: [], html: [], attachments: [], partCount: 0 };
  if (normalizedMessage.includes('\n\n') || normalizedMessage.includes('\r\n\r\n')) {
    await inspectMimePart(normalizedMessage, state, 0);
  }

  const selectedHeaders = RELEVANT_HEADERS.flatMap((name) => {
    const values = topHeaders.get(name);
    return values ? [{ name, values }] : [];
  });
  const headerAssessment = analyzeEmailHeaders(rawHeaders);
  const plainText = state.plainText.join('\n');
  const html = state.html.join('\n');
  const htmlDetails = html ? extractHtml(html) : { images: [], links: [], forms: [], hiddenText: [] };
  const links = [...bodyUrls(plainText), ...bodyUrls(html), ...htmlDetails.links];
  const uniqueLinks = [...new Map(links.map((link) => [`${link.url}\n${link.source}`, link])).values()].slice(0, 200);

  return {
    headers: selectedHeaders,
    receivedRoute: extractReceivedRoute(topHeaders),
    headerAssessment,
    plainText,
    html,
    images: htmlDetails.images,
    links: uniqueLinks,
    forms: htmlDetails.forms,
    hiddenText: htmlDetails.hiddenText,
    attachments: state.attachments.slice(0, 100),
  };
}

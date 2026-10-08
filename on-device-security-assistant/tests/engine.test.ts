import { describe, expect, it } from 'vitest';
import { scanText, scanUrl } from '../src/engine';
import { getRegistrableDomain } from '../src/engine/url/urlFeatures';
import { DEFAULT_DETECTION_RULES } from '../src/engine/url/rules';
import { formatDetectionRules, parseDetectionRuleText } from '../src/storage/detectionRules';

describe('URL scanning', () => {
  it('treats a normal site as safe', () => {
    expect(scanUrl('https://www.google.com').level).toBe('safe');
  });

  it('flags a brand-imitating phishing URL as dangerous', () => {
    const v = scanUrl('https://paypal-secure-login.xyz/verify');
    expect(v.level).toBe('dangerous');
    expect(v.reasons.length).toBeGreaterThan(0);
  });

  it('scores the PayPal lookalike example as high risk with clear evidence', () => {
    const verdict = scanUrl('https://secure-paypal-login-example.com/verify');
    expect(verdict.level).toBe('dangerous');
    expect(verdict.score).toBe(87);
    expect(verdict.reasons).toContain('Domain resembles PayPal but is not paypal.com');
    expect(verdict.signals.some((signal) => signal.id === 'sensitive-path')).toBe(true);
    expect(verdict.signals.some((signal) => signal.id === 'brand-credential-lure')).toBe(true);
  });

  it('detects nonstandard ports and sensitive URL parameters', () => {
    const signals = scanUrl('https://example.com:8443/login?email=user%40example.com&password=secret').signals;
    expect(signals.some((signal) => signal.id === 'unusual-port')).toBe(true);
    expect(signals.some((signal) => signal.id === 'sensitive-query')).toBe(true);
  });

  it('applies locally supplied detection rules without changing the scanner', () => {
    const rules = {
      ...DEFAULT_DETECTION_RULES,
      brands: [...DEFAULT_DETECTION_RULES.brands, { name: 'contoso', domains: ['contoso.com'] }],
      suspiciousTlds: [...DEFAULT_DETECTION_RULES.suspiciousTlds, 'test'],
      suspiciousKeywords: [...DEFAULT_DETECTION_RULES.suspiciousKeywords, 'review'],
    };
    expect(scanUrl('https://example.test/review').signals.some((signal) => signal.id === 'suspicious-tld')).toBe(false);
    expect(scanUrl('https://example.test/review', rules).signals.some((signal) => signal.id === 'suspicious-tld')).toBe(true);
    expect(scanUrl('https://example.test/review').signals.some((signal) => signal.id === 'keyword')).toBe(false);
    expect(scanUrl('https://example.test/review', rules).signals.some((signal) => signal.id === 'keyword')).toBe(true);
    expect(scanUrl('https://contoso-login-example.com').signals.some((signal) => signal.id === 'brand-in-domain')).toBe(false);
    expect(scanUrl('https://example.test/review', rules).signals.some((signal) => signal.id === 'brand-in-domain')).toBe(false);
    expect(scanUrl('https://contoso-login-example.com', rules).signals.some((signal) => signal.id === 'brand-in-domain')).toBe(true);
  });

  it('parses editable detection-rule text and rejects malformed entries', () => {
    expect(parseDetectionRuleText(formatDetectionRules(DEFAULT_DETECTION_RULES))).toEqual(DEFAULT_DETECTION_RULES);
    const parsed = parseDetectionRuleText({
      brands: 'contoso=contoso.com, contoso.net',
      suspiciousTlds: '.test',
      urlShorteners: 'short.example',
      suspiciousKeywords: 'review',
    });
    expect(parsed.brands).toEqual([{ name: 'contoso', domains: ['contoso.com', 'contoso.net'] }]);
    expect(parsed.suspiciousTlds).toEqual(['test']);
    expect(() => parseDetectionRuleText({
      brands: 'bad rule', suspiciousTlds: '', urlShorteners: '', suspiciousKeywords: '',
    })).toThrow(/Invalid brand rule/);
  });

  it('flags raw-IP login pages', () => {
    expect(scanUrl('http://192.168.1.1/login').level).not.toBe('safe');
  });

  it('detects digit-for-letter swaps', () => {
    expect(scanUrl('https://paypa1.com').signals.some((s) => s.id === 'homoglyph')).toBe(true);
  });

  it('detects common brand spoofs offline', () => {
    for (const domain of [
      'paypa1.com',
      'paypai.com',
      'pay-pal-security.com',
      'g00gle.com',
      'micros0ft.com',
      'payapl.com',
      'paypall.com',
      'paypl.com',
    ]) {
      expect(scanUrl(`https://${domain}`).signals.some((signal) =>
        ['homoglyph', 'typosquat', 'brand-in-domain'].includes(signal.id),
      ), domain).toBe(true);
    }
    expect(scanUrl('https://paypal.com').signals.some((signal) =>
      ['homoglyph', 'typosquat', 'brand-in-domain', 'brand-wrong-domain'].includes(signal.id),
    )).toBe(false);
  });

  it('detects capital-I lookalikes and Unicode homoglyphs', () => {
    expect(scanUrl('https://paypaI.com').signals.some((s) => s.id === 'homoglyph')).toBe(true);
    expect(scanUrl(`https://${String.fromCodePoint(0x440, 0x430)}ypal.com`).signals.some((s) => s.id === 'homoglyph')).toBe(true);
    expect(scanUrl('https://ρaypal.com').signals.some((s) => s.id === 'homoglyph')).toBe(true);
  });

  it('flags mixed confusable scripts without treating a single-script IDN as mixed', () => {
    expect(scanUrl('https://раypal.com').signals.some((signal) => signal.id === 'mixed-script')).toBe(true);
    expect(scanUrl('https://παράδειγμα.com').signals.some((signal) => signal.id === 'mixed-script')).toBe(false);
    expect(scanUrl('https://xn--bcher-kva.de').signals.some((signal) => signal.id === 'punycode')).toBe(true);
  });

  it('detects malformed and obfuscated encodings', () => {
    expect(scanUrl('https://example.com/%ZZ').signals.some((s) => s.id === 'malformed-encoding')).toBe(true);
    expect(scanUrl('https://example.com/%0d%0a%00').signals.some((s) => s.id === 'suspicious-characters')).toBe(true);
  });

  it('detects external redirect destinations embedded in query parameters', () => {
    const verdict = scanUrl('https://example.com/redirect?next=https%3A%2F%2Fevil.example%2Flogin');
    expect(verdict.signals.some((s) => s.id === 'external-redirect')).toBe(true);
    expect(scanUrl('https://example.com/out/https%3A%2F%2Fevil.example%2Flogin').signals.some((s) => s.id === 'external-redirect')).toBe(true);
  });

  it('does not treat a Gmail compose body as a redirect destination', () => {
    const composeUrl = new URL('https://mail.google.com/mail/u/0/');
    composeUrl.searchParams.set('view', 'cm');
    composeUrl.searchParams.set('fs', '1');
    composeUrl.searchParams.set('to', 'person@example.com');
    composeUrl.searchParams.set('body', 'Please review https://example.org/login');

    expect(scanUrl(composeUrl.href).signals.some((signal) => signal.id === 'external-redirect')).toBe(false);
  });

  it('still detects an external URL in an explicit redirect parameter', () => {
    const url = 'https://mail.google.com/mail/u/0/?url=https%3A%2F%2Fevil.example%2Flogin';
    expect(scanUrl(url).signals.some((signal) => signal.id === 'external-redirect')).toBe(true);
  });

  it('flags malformed URLs, excessive length and suspicious TLDs', () => {
    expect(scanUrl('not a valid URL').signals.some((s) => s.id === 'invalid-url')).toBe(true);
    expect(scanUrl(`https://example.com/${'a'.repeat(220)}`).signals.some((s) => s.id === 'long-url')).toBe(true);
    expect(scanUrl('https://a.b.c.d.e.example.com').signals.some((s) => s.id === 'many-subdomains')).toBe(true);
    expect(scanUrl('https://example.xyz').signals.some((s) => s.id === 'suspicious-tld')).toBe(true);
  });

  it('treats HTTP as a weak signal on its own', () => {
    const verdict = scanUrl('http://example.com');
    expect(verdict.signals).toEqual([{ id: 'no-https', weight: 10, reason: 'Connection is not encrypted (HTTP)' }]);
    expect(verdict.level).toBe('safe');
  });

  it('uses public suffixes when identifying brand lookalikes', () => {
    expect(getRegistrableDomain('login.paypal.com.tr')).toBe('paypal.com.tr');
    expect(scanUrl('https://paypal.com.tr').signals.some((s) => s.id === 'brand-wrong-domain')).toBe(true);
  });

  it('does not treat a hosted subdomain as the official brand domain', () => {
    expect(getRegistrableDomain('paypal.github.io')).toBe('paypal.github.io');
    expect(scanUrl('https://paypal.github.io').signals.some((s) => s.id === 'brand-wrong-domain')).toBe(true);
  });
});

describe('Text scanning', () => {
  it('flags a classic OTP/account scam', () => {
    const v = scanText('URGENT: Your account will be suspended. Verify your PIN and OTP at http://bit.ly/x');
    expect(v.score).toBeGreaterThanOrEqual(50);
  });

  it('ignores ordinary conversation', () => {
    expect(scanText('Hey, are we still meeting for lunch tomorrow?').level).toBe('safe');
  });
});
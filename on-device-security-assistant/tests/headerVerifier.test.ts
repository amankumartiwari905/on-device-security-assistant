import { describe, expect, it } from 'vitest';
import {
  analyzeEmailHeaders,
  extractHeaderBlock,
  MAX_HEADER_SIZE,
} from '../src/engine/email/headerVerifier';

describe('email header verification', () => {
  it('parses folded headers and reports SPF, DKIM, and DMARC claims without asserting trust', () => {
    const result = analyzeEmailHeaders([
      'From: "Example Support" <help@example.com>',
      'Return-Path: <bounce@example.com>',
      'Reply-To: help@example.com',
      'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=example.com;',
      ' dkim=pass header.d=example.com; dmarc=pass header.from=example.com',
      '',
      'Message body must not be analyzed as headers.',
    ].join('\r\n'));

    expect(result.from).toBe('help@example.com');
    expect(result.returnPath).toBe('bounce@example.com');
    expect(result.replyTo).toBe('help@example.com');
    expect(result.claims.map(({ method, result: claim }) => `${method}:${claim}`)).toEqual([
      'spf:pass',
      'dkim:pass',
      'dmarc:pass',
    ]);
    expect(result.claims.map((claim) => claim.identityDomain)).toEqual([
      'example.com',
      'example.com',
      'example.com',
    ]);
    expect(result.dmarcStatus).toBe('reported-pass');
    expect(result.warnings[0]).toContain('can be forged');
    expect(result.signals).toEqual([]);
  });

  it('keeps authentication failures as unverified warnings, scoring only sender mismatches', () => {
    const result = analyzeEmailHeaders([
      'From: alerts@bank.example',
      'Return-Path: <bounce@unrelated.example>',
      'Authentication-Results: mx.receiver.example; spf=fail smtp.mailfrom=unrelated.example;',
      ' dkim=fail header.d=unrelated.example; dmarc=fail header.from=bank.example',
    ].join('\n'));

    expect(result.dmarcStatus).toBe('reported-fail');
    expect(result.signals.map((signal) => signal.id)).toEqual(expect.arrayContaining([
      'return-path-mismatch',
    ]));
    expect(result.signals.map((signal) => signal.id)).not.toEqual(expect.arrayContaining([
      'header-spf-failure',
      'header-dkim-failure',
      'header-dmarc-failure',
    ]));
    expect(result.riskScore).toBe(15);
    expect(result.warnings.some((warning) => warning.includes('SPF fail, DKIM fail, DMARC fail'))).toBe(true);
  });

  it('records Received-SPF failures as claims and warnings, not scored evidence', () => {
    const result = analyzeEmailHeaders([
      'From: sender@example.com',
      'Received-SPF: softfail (mx.receiver.example: domain of sender@other.example does not designate permitted sender)',
    ].join('\n'));

    expect(result.claims).toMatchObject([
      { method: 'spf', result: 'softfail', source: 'Received-SPF', authservId: 'mx.receiver.example' },
    ]);
    expect(result.dmarcStatus).toBe('missing');
    expect(result.signals.map((signal) => signal.id)).not.toContain('header-spf-failure');
    expect(result.warnings.some((warning) => warning.includes('SPF softfail'))).toBe(true);
  });

  it('ignores body text after the header separator and warns when results are missing', () => {
    const headerBlock = extractHeaderBlock([
      'From: sender@example.com',
      '',
      'Authentication-Results: forged; dmarc=pass',
    ].join('\r\n'));
    const result = analyzeEmailHeaders(headerBlock);

    expect(result.claims).toHaveLength(0);
    expect(result.dmarcStatus).toBe('missing');
    expect(result.warnings).toContain('No SPF, DKIM, or DMARC authentication results were found in the supplied headers.');
  });

  it('rejects oversized header blocks and input without recognizable headers', () => {
    expect(() => extractHeaderBlock(`X-Test: ${'x'.repeat(MAX_HEADER_SIZE)}`)).toThrow('headers must be');
    expect(() => analyzeEmailHeaders('just some text')).toThrow('No valid email headers');
  });
});

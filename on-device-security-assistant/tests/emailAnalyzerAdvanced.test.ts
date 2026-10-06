import { describe, expect, it } from 'vitest';
import { analyzePageEmails, summarizeEmailAssessments } from '../src/engine/email/emailAnalyzer';
import { analyzeSenderIdentity } from '../src/engine/email/senderIdentity';

const idsOf = (signals: { id: string }[]): string[] => signals.map((s) => s.id);
const first = (source: string, page = 'example.com') => analyzePageEmails([source], page)[0];

describe('extraction', () => {
  it('parses mailto links including cc parameters', () => {
    const results = analyzePageEmails(
      ['<a href="mailto:Sales@Example.com?subject=Hi&cc=team@example.com">Email us</a>'],
      'www.example.com',
    );
    expect(results.map((r) => r.address.toLowerCase())).toEqual(['sales@example.com', 'team@example.com']);
    expect(results.every((r) => r.status === 'matches-site' && r.source === 'mailto')).toBe(true);
  });

  it('keeps flagging [at]/[dot] disguises with the original explanation', () => {
    const results = analyzePageEmails(['Write to john [at] example [dot] com today'], 'example.com');
    expect(results).toHaveLength(1);
    expect(results[0].address).toBe('john@example.com');
    expect(results[0].status).toBe('suspicious');
    expect(results[0].source).toBe('obfuscated');
    expect(results[0].explanation).toBe('This address is disguised with \u201Cat\u201D or \u201Cdot\u201D text.');
  });

  it('decodes HTML entities and bracketed @ signs', () => {
    expect(analyzePageEmails(['mail ann&#64;example.com'], 'example.com')[0].address).toBe('ann@example.com');
    expect(analyzePageEmails(['mail bob[@]example.com'], 'example.com')[0].source).toBe('obfuscated');
  });

  it('counts repeated addresses once, case-insensitively', () => {
    const results = analyzePageEmails(['a@b.co a@b.co', 'A@B.CO'], '');
    expect(results).toHaveLength(1);
    expect(results[0].occurrences).toBe(3);
  });

  it('reports malformed addresses with the original explanation', () => {
    const result = first('contact foo@bar');
    expect(result.status).toBe('suspicious');
    expect(result.explanation).toBe('This address does not have a valid email format.');
  });
});

describe('benign addresses stay quiet', () => {
  it('recognises an address on the same site', () => {
    const result = first('Reach support@example.com', 'www.example.com');
    expect(result.status).toBe('matches-site');
    expect(result.category).toBe('same-site');
    expect(result.riskScore).toBeLessThan(30);
  });

  it('treats a personal free-mail address as external, not suspicious', () => {
    const result = first('jane.doe@gmail.com');
    expect(result.status).toBe('external');
    expect(result.category).toBe('free-provider');
  });
});

describe('domain checks', () => {
  it('flags disposable email services', () => {
    const result = first('x@mailinator.com');
    expect(result.status).toBe('suspicious');
    expect(result.category).toBe('disposable');
    expect(idsOf(result.signals)).toContain('disposable-domain');
  });

  it('flags misspellings of popular providers', () => {
    expect(idsOf(first('john@gmial.com').signals)).toContain('freemail-typo');
  });

  it('flags internationalized domains without calling them malformed', () => {
    const ids = idsOf(first('info@b\u00FCcher.de').signals);
    expect(ids).toContain('idn-domain');
    expect(ids).not.toContain('invalid-format');
  });

  it('flags a domain that is a near-copy of the current site', () => {
    expect(idsOf(first('help@examplee.com', 'www.example.com').signals)).toContain('resembles-this-site');
  });

  it('flags a domain that borrows the current site name', () => {
    expect(idsOf(first('billing@example-secure.com', 'www.example.com').signals)).toContain('contains-this-site-name');
  });
});

describe('local-part and display-name checks', () => {
  it('flags official-sounding brand addresses on a free mailbox', () => {
    const result = first('Contact paypal.support@gmail.com for help');
    expect(result.status).toBe('suspicious');
    expect(idsOf(result.signals)).toEqual(expect.arrayContaining(['brand-in-local-part', 'authority-on-freemail']));
  });

  it('does not treat a brand-like first name as impersonation', () => {
    expect(idsOf(first('chase.miller@gmail.com').signals)).not.toContain('brand-in-local-part');
  });

  it('flags a display name that impersonates a brand', () => {
    const result = first('"PayPal Support" <alerts@random-mail.xyz>');
    expect(result.displayName).toBe('PayPal Support');
    expect(result.status).toBe('suspicious');
    expect(idsOf(result.signals)).toContain('display-name-impersonation');
  });

  it('flags a display name that shows a different address', () => {
    const results = analyzePageEmails(['"support@paypal.com" <x@evil-mail.net>'], 'example.com');
    const spoof = results.find((r) => r.address === 'x@evil-mail.net');
    expect(idsOf(spoof?.signals ?? [])).toContain('display-name-email-mismatch');
  });
});

describe('summary', () => {
  it('counts statuses and finds the riskiest address', () => {
    const summary = summarizeEmailAssessments(
      analyzePageEmails(['sales@example.com', 'x@mailinator.com', 'jane@gmail.com'], 'example.com'),
    );
    expect(summary).toMatchObject({ total: 3, suspicious: 1, matchesSite: 1, external: 1, disposable: 1 });
    expect(summary.worst?.address).toBe('x@mailinator.com');
  });
});

describe('sender identity', () => {
  it('flags replies that go to a free mailbox while the sender is a business', () => {
    const result = analyzeSenderIdentity({
      from: 'Acme Billing <billing@acme-corp.com>',
      replyTo: 'acme.billing.dept@gmail.com',
    });
    expect(idsOf(result.signals)).toContain('reply-to-freemail');
    expect(result.riskScore).toBeGreaterThanOrEqual(30);
  });

  it('flags a reply-to on a different domain', () => {
    const result = analyzeSenderIdentity({ from: 'news@shop.example.com', replyTo: 'owner@other-site.net' });
    expect(idsOf(result.signals)).toContain('reply-to-mismatch');
  });

  it('accepts a consistent reply-to', () => {
    const result = analyzeSenderIdentity({ from: 'news@shop.example.com', replyTo: 'help@example.com' });
    expect(idsOf(result.signals)).not.toContain('reply-to-mismatch');
    expect(result.riskScore).toBeLessThan(30);
  });

  it('flags shortened links and links that never touch the sender domain', () => {
    const result = analyzeSenderIdentity({ from: 'news@example.com', linkUrls: ['https://bit.ly/abc'] });
    expect(idsOf(result.signals)).toEqual(expect.arrayContaining(['shortened-links', 'links-off-sender-domain']));
  });
});
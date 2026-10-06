import { describe, expect, it } from 'vitest';
import { analyzePageEmails } from '../src/engine/email/emailAnalyzer';

describe('page email analysis', () => {
  it('extracts and deduplicates visible email addresses', () => {
    const results = analyzePageEmails(
      ['Contact help@example.com or billing@example.com. help@example.com'],
      'www.example.com',
    );
    expect(results.map((item) => item.address)).toEqual(['help@example.com', 'billing@example.com']);
    expect(results.every((item) => item.status === 'matches-site')).toBe(true);
  });

  it('marks malformed and disguised addresses as suspicious', () => {
    const results = analyzePageEmails(
      ['Bad address: person@@example.com. Hidden: help [at] example [dot] com'],
      'example.com',
    );
    expect(results.find((item) => item.address === 'person@@example.com')?.status).toBe('suspicious');
    expect(results.find((item) => item.address === 'help@example.com')?.explanation).toContain('disguised');
  });

  it('flags known brand lookalikes and labels other domains unverified', () => {
    const results = analyzePageEmails(
      ['security@paypa1.com support@outside.test'],
      'example.com',
    );
    expect(results.find((item) => item.address === 'security@paypa1.com')?.status).toBe('suspicious');
    expect(results.find((item) => item.address === 'support@outside.test')?.status).toBe('external');
  });
});
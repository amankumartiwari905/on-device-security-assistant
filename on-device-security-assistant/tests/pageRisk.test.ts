import { describe, expect, it } from 'vitest';
import { scanUrl } from '../src/engine';
import { includePageLinkClues } from '../src/ui/popup/pageRisk';

describe('popup page clues', () => {
  it('includes a PayPal look-alike link among the three strongest page clues', () => {
    const page = scanUrl('http://127.0.0.1:5000/demo.html');
    const link = scanUrl('https://paypa1.com/login');

    const verdict = includePageLinkClues(page, [{
      url: 'https://paypa1.com/login',
      text: 'paypa1.com/login',
      verdict: link,
    }]);

    expect(verdict.signals).toHaveLength(3);
    expect(verdict.signals.some((signal) => signal.id === 'homoglyph')).toBe(true);
    expect(verdict.signals.find((signal) => signal.id === 'homoglyph')?.evidence).toBe('https://paypa1.com/login');
    expect(verdict.reasons).toContain('Domain uses visually similar characters to imitate paypal');
  });
});

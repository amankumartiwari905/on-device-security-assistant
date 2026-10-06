import { describe, expect, it } from 'vitest';
import { scanText } from '../src/engine';
import { normalizeText } from '../src/engine/nlp/normalize';
import { DEFAULT_DETECTION_RULES } from '../src/engine/url/rules';

const idsOf = (text: string): string[] => scanText(text).signals.map((s) => s.id);

describe('negation and protective context', () => {
  it('treats a genuine OTP message as safe', () => {
    const result = scanText('Your OTP is 482913. Do not share this OTP with anyone.');
    expect(result.level).toBe('safe');
    expect(result.signals.map((s) => s.id)).not.toContain('otp-share');
  });

  it('treats a bank awareness notice as safe', () => {
    const result = scanText('Dear customer, never share your OTP, PIN or CVV with anyone. SBI will never ask for these details.');
    expect(result.level).toBe('safe');
  });

  it('is not fooled by a negation in a different sentence', () => {
    expect(idsOf('Do not ignore this. Share your OTP now.')).toContain('otp-share');
  });
});

describe('deobfuscation', () => {
  it('decodes leetspeak that spells scam vocabulary', () => {
    const ids = idsOf('Y0ur acc0unt will be bl0cked. Share y0ur 0TP n0w');
    expect(ids).toContain('obfuscation-leet');
    expect(ids).toContain('account-threat');
    expect(ids).toContain('otp-share');
  });

  it('collapses spaced-out letters', () => {
    const ids = idsOf('Your account is blocked. Share the o t p now');
    expect(ids).toContain('obfuscation-spaced-letters');
    expect(ids).toContain('otp-share');
  });

  it('maps look-alike Cyrillic letters inside Latin words', () => {
    const ids = idsOf('Verify y\u043Eur \u041E\u0422P immediately');
    expect(ids).toContain('obfuscation-mixed-script');
    expect(ids).toContain('credential-request');
  });

  it('removes invisible characters', () => {
    const ids = idsOf('Ver\u200Bify your O\u200BT\u200BP');
    expect(ids).toContain('obfuscation-hidden-chars');
    expect(ids).toContain('credential-request');
  });

  it('never rewrites URLs or ordinary tokens like 4G and 3rd', () => {
    const { text, findings } = normalizeText('Get 4G on the 3rd floor: http://paypa1.com/login');
    expect(findings).toEqual([]);
    expect(text).toContain('http://paypa1.com/login');
    expect(text).toContain('4G');
  });
});

describe('language coverage', () => {
  it('catches Hinglish scams', () => {
    const ids = idsOf('Aapka khata band ho jayega. Turant OTP bhejein.');
    expect(ids).toEqual(expect.arrayContaining(['urgency-hinglish', 'account-threat-hinglish', 'otp-hinglish']));
  });

  it('catches Hindi (Devanagari) scams', () => {
    const ids = idsOf('\u0924\u0941\u0930\u0902\u0924 \u0916\u093E\u0924\u093E \u092C\u0902\u0926 \u0939\u094B\u0917\u093E');
    expect(ids).toEqual(expect.arrayContaining(['urgency-hindi', 'account-threat-hindi']));
  });

  it('does not flag a Hindi "do not share OTP" notice', () => {
    // OTP \u0915\u093F\u0938\u0940 \u0915\u094B \u0928 \u092C\u0924\u093E\u090F\u0902 = "do not tell anyone the OTP"
    const ids = idsOf('\u0913\u091F\u0940\u092A\u0940 \u0915\u093F\u0938\u0940 \u0915\u094B \u0928 \u092C\u0924\u093E\u090F\u0902');
    expect(ids).not.toContain('otp-hindi');
  });
});

describe('links, callbacks and fusion', () => {
  it('applies custom detection rules to links inside text', () => {
    const rules = { ...DEFAULT_DETECTION_RULES, suspiciousTlds: ['com'] };
    const result = scanText('Check this link: http://example.com/login', rules);
    expect(result.signals.map((signal) => signal.id)).toContain('risky-link');
  });

  it('flags a brand mentioned with a link to an unrelated site', () => {
    const ids = idsOf('Your SBI account will be blocked. Update now: http://secure-update.example.xyz/kyc');
    expect(ids).toContain('brand-link-mismatch');
  });

  it('does not flag a brand that links to its own site', () => {
    const ids = idsOf('Your account will be blocked. Update now: https://www.paypal.com/signin');
    expect(ids).not.toContain('brand-link-mismatch');
  });

  it('flags pressure combined with a number to call', () => {
    const ids = idsOf('URGENT: your account will be suspended. Call 1800 123 4567 immediately');
    expect(ids).toContain('pressure-plus-callback');
  });

  it('rewards messages that combine several tactics', () => {
    const result = scanText(
      'Dear customer, your SBI KYC is pending. Update immediately or your account will be blocked. Share OTP to verify: http://sbi-kyc-update.top/login',
    );
    expect(result.signals.map((s) => s.id)).toContain('multi-tactic');
    expect(result.level).toBe('dangerous');
  });

  it('attaches the matched excerpt as evidence', () => {
    const signal = scanText('Please share your OTP right now').signals.find((s) => s.id === 'otp-share');
    expect(signal?.evidence?.toLowerCase()).toContain('otp');
  });
});

describe('newer scam types', () => {
  it('flags tech-support scams', () => {
    expect(idsOf('Your computer is infected with a virus. Call our support helpline now')).toContain('tech-support');
  });

  it('flags secrecy demands but not protective advice', () => {
    expect(idsOf('Do not tell anyone about this transfer')).toContain('secrecy-demand');
    expect(idsOf('Do not share your OTP with anyone')).not.toContain('secrecy-demand');
  });

  it('flags digital-arrest threats', () => {
    expect(idsOf('Cyber crime branch has registered a case against your Aadhaar. Digital arrest warrant issued.')).toContain('digital-arrest');
  });

  it('keeps ordinary conversation safe', () => {
    expect(scanText('Hey, are we still meeting for lunch tomorrow?').level).toBe('safe');
  });
});
import { describe, expect, it } from 'vitest';
import { scanText, scanUrl } from '../src/engine';

describe('hackathon demo cases', () => {
  it('blocks a look-alike brand hidden inside a hyphenated phishing domain', () => {
    expect(scanUrl('https://paypa1-secure-login.xyz/verify').level).toBe('dangerous');
  });

  it('flags a brand imitation with phishing keywords', () => {
    expect(scanUrl('https://g00gle-account-verify.xyz/').level).toBe('dangerous');
  });

  it('flags the SBI KYC scam SMS as dangerous', () => {
    const v = scanText(
      'Dear customer, your SBI KYC is pending. Update immediately or your account will be blocked. Share OTP to verify: http://sbi-kyc-update.top/login',
    );
    expect(v.level).toBe('dangerous');
  });

  it('flags a UPI PIN request', () => {
    const v = scanText('To receive your cashback enter your UPI PIN here.');
    expect(v.signals.some((s) => s.id === 'upi-pin')).toBe(true);
  });
});
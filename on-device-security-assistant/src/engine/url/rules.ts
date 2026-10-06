import { BRANDS } from '../domain/brands';

export interface DetectionRules {
  brands: { name: string; domains: string[] }[];
  suspiciousTlds: string[];
  urlShorteners: string[];
  suspiciousKeywords: string[];
}

export const DEFAULT_DETECTION_RULES: DetectionRules = {
  brands: BRANDS.map((brand) => ({ ...brand, domains: [...brand.domains] })),
  suspiciousTlds: [
    'zip', 'mov', 'top', 'xyz', 'click', 'link', 'work', 'support', 'country',
    'gq', 'tk', 'ml', 'cf', 'ga', 'rest', 'cam', 'icu', 'monster', 'buzz',
  ],
  urlShorteners: [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy',
  ],
  suspiciousKeywords: [
    'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
    'banking', 'password', 'wallet', 'suspend', 'unlock', 'billing', 'invoice', 'kyc',
    'payment', 'checkout', 'refund', 'payout',
  ],
};
/** Static reference data for email analysis. Extend these lists as you find gaps. */

export interface EmailBrand {
  /** Lowercase brand token, e.g. "paypal". */
  name: string;
  /** Official registrable domains that may legitimately use the brand. */
  domains: readonly string[];
  /** Multi-word spellings that can appear in a display name ("state bank of india"). */
  aliases?: readonly string[];
}

export const EMAIL_BRANDS: readonly EmailBrand[] = [
  { name: 'paypal', domains: ['paypal.com'] },
  { name: 'amazon', domains: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazonpay.in'] },
  { name: 'apple', domains: ['apple.com', 'icloud.com'] },
  { name: 'microsoft', domains: ['microsoft.com', 'outlook.com', 'live.com', 'office.com', 'microsoftonline.com'] },
  { name: 'google', domains: ['google.com'] },
  { name: 'netflix', domains: ['netflix.com'] },
  { name: 'facebook', domains: ['facebook.com', 'facebookmail.com', 'fb.com'] },
  { name: 'instagram', domains: ['instagram.com'] },
  { name: 'whatsapp', domains: ['whatsapp.com'] },
  { name: 'linkedin', domains: ['linkedin.com'] },
  { name: 'dropbox', domains: ['dropbox.com'] },
  { name: 'binance', domains: ['binance.com'] },
  { name: 'coinbase', domains: ['coinbase.com'] },
  { name: 'fedex', domains: ['fedex.com'] },
  { name: 'dhl', domains: ['dhl.com'] },
  { name: 'usps', domains: ['usps.com'] },
  { name: 'chase', domains: ['chase.com'] },
  { name: 'wellsfargo', domains: ['wellsfargo.com'], aliases: ['wells fargo'] },
  { name: 'bankofamerica', domains: ['bankofamerica.com'], aliases: ['bank of america'] },
  { name: 'sbi', domains: ['sbi.co.in', 'onlinesbi.sbi', 'sbicard.com'], aliases: ['state bank of india'] },
  { name: 'hdfcbank', domains: ['hdfcbank.com', 'hdfcbank.net'], aliases: ['hdfc bank'] },
  { name: 'icicibank', domains: ['icicibank.com'], aliases: ['icici bank'] },
  { name: 'axisbank', domains: ['axisbank.com'], aliases: ['axis bank'] },
  { name: 'kotak', domains: ['kotak.com'] },
  { name: 'paytm', domains: ['paytm.com', 'paytmbank.com'] },
  { name: 'phonepe', domains: ['phonepe.com'] },
  { name: 'flipkart', domains: ['flipkart.com'] },
  { name: 'irctc', domains: ['irctc.co.in'] },
  { name: 'uidai', domains: ['uidai.gov.in'], aliases: ['aadhaar'] },
  { name: 'incometax', domains: ['incometax.gov.in'], aliases: ['income tax'] },
  { name: 'jio', domains: ['jio.com'] },
  { name: 'airtel', domains: ['airtel.in', 'airtel.com'] },
];

export const FREE_EMAIL_PROVIDERS: ReadonlySet<string> = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.in', 'yahoo.co.uk', 'yahoo.in', 'ymail.com',
  'outlook.com', 'hotmail.com', 'hotmail.co.uk', 'live.com', 'msn.com', 'icloud.com', 'me.com', 'aol.com',
  'proton.me', 'protonmail.com', 'pm.me', 'zoho.com', 'zohomail.com', 'gmx.com', 'gmx.net', 'mail.com',
  'email.com', 'rediffmail.com', 'yandex.com', 'yandex.ru', 'tutanota.com', 'fastmail.com', 'hey.com',
]);

/** Providers people misspell on purpose (gmial.com, outlok.com). */
export const FREEMAIL_TYPO_TARGETS: readonly string[] = [
  'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com', 'protonmail.com', 'rediffmail.com', 'yandex.com',
];

export const DISPOSABLE_EMAIL_DOMAINS: ReadonlySet<string> = new Set([
  'mailinator.com', 'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org', 'sharklasers.com',
  '10minutemail.com', '10minutemail.net', 'tempmail.com', 'temp-mail.org', 'temp-mail.io', 'yopmail.com',
  'trashmail.com', 'trashmail.net', 'getnada.com', 'nada.email', 'throwawaymail.com', 'maildrop.cc',
  'dispostable.com', 'fakeinbox.com', 'mohmal.com', 'emailondeck.com', 'mintemail.com', 'spamgourmet.com',
  'mailnesia.com', 'tempail.com', 'burnermail.io', 'moakt.com', 'mytemp.email', 'inboxkitten.com', 'discard.email',
]);

export const SUSPICIOUS_EMAIL_TLDS: ReadonlySet<string> = new Set([
  'zip', 'mov', 'top', 'xyz', 'click', 'link', 'work', 'support', 'country', 'gq', 'tk', 'ml', 'cf', 'ga',
  'rest', 'cam', 'icu', 'monster', 'buzz', 'loan', 'download', 'review',
]);

/** Words that make an address sound official. Harmless on a company domain, suspicious on a free mailbox. */
export const AUTHORITY_LOCAL_PARTS: ReadonlySet<string> = new Set([
  'support', 'security', 'billing', 'helpdesk', 'helpline', 'verify', 'verification', 'refund', 'kyc',
  'customercare', 'service', 'alert', 'alerts', 'admin', 'accounts', 'account', 'payments', 'payment',
  'fraud', 'recovery', 'compliance', 'noreply', 'official',
]);
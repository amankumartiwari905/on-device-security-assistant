/**
 * Scam-language rules. Each rule belongs to a manipulation "tactic" so the analyzer can
 * reward messages that combine several tactics (urgency + fear + credential theft...).
 *
 * negatable: the rule describes asking for something (OTP, PIN...) that legitimate security
 *            notices mention in a protective sense ("never share your OTP"). Those are skipped.
 */
export type Tactic = 'urgency' | 'fear' | 'authority' | 'reward' | 'credential' | 'payment' | 'remote' | 'lure';
export type Language = 'en' | 'hinglish' | 'hi';

export interface TextRule {
  id: string;
  tactic: Tactic;
  weight: number;
  reason: string;
  pattern: RegExp; // no /g flag here; the analyzer builds a global copy
  lang?: Language; // defaults to 'en'
  negatable?: boolean;
}

export const TEXT_RULES: TextRule[] = [
  // ------------------------------------------------------------------ English: core
  {
    id: 'urgency', tactic: 'urgency', weight: 20,
    reason: 'Creates artificial urgency to rush you',
    pattern: /\b(urgent(ly)?|immediately|act now|final notice|last warning|within \d+ (hours?|minutes?)|expires? (today|soon))\b/i,
  },
  {
    id: 'account-threat', tactic: 'fear', weight: 25,
    reason: 'Threatens to suspend, block or close an account or card',
    pattern: /(account|card|sim|number|wallet).{0,40}(suspend|block|lock|deactivat|clos(e|ed|ure))/i,
  },
  {
    id: 'credential-request', tactic: 'credential', weight: 35, negatable: true,
    reason: 'Asks you to provide a password, PIN, OTP, card or ID details',
    pattern: /(verify|confirm|update|enter|provide).{0,30}(password|pin|otp|cvv|card number|aadhaar|pan\b|ssn|bank details)/i,
  },
  {
    id: 'otp-share', tactic: 'credential', weight: 35, negatable: true,
    reason: 'Asks you to share a one-time code or PIN (real companies never do)',
    pattern: /(share|send|tell|give|read out).{0,20}(otp|pin|cvv|verification code)/i,
  },
  {
    id: 'upi-pin', tactic: 'credential', weight: 35, negatable: true,
    reason: 'Asks for your UPI PIN (you never need a PIN to receive money)',
    pattern: /(enter|share|give).{0,15}upi pin|upi pin.{0,30}(receive|refund|cashback|credit)/i,
  },
  {
    id: 'prize', tactic: 'reward', weight: 25,
    reason: 'Promises a prize, reward or lottery win',
    pattern: /(you(\u0027ve| have)? won|lottery|lucky draw|prize|claim your|congratulations)/i,
  },
  {
    id: 'kyc', tactic: 'fear', weight: 30,
    reason: 'Claims your KYC is expiring or pending (a very common bank scam)',
    pattern: /(\bkyc\b.{0,40}(update|expire|pending|verify|suspend))|((update|pending|expire|verify).{0,20}\bkyc\b)/i,
  },
  {
    id: 'pay-to-receive', tactic: 'payment', weight: 30,
    reason: 'Asks you to pay a fee or tax to receive money or a parcel',
    pattern: /(pay|send|transfer).{0,30}(fee|charges|tax|deposit).{0,40}(release|claim|receive|unlock)/i,
  },
  {
    id: 'gift-crypto', tactic: 'payment', weight: 30,
    reason: 'Asks for payment in gift cards or cryptocurrency',
    pattern: /(gift ?cards?|bitcoin|usdt|crypto(currency)?).{0,40}(pay|send|buy|transfer)/i,
  },
  {
    id: 'remote-access', tactic: 'remote', weight: 35,
    reason: 'Asks you to install remote-access software',
    pattern: /(anydesk|teamviewer|quicksupport|remote access)/i,
  },
  {
    id: 'authority-threat', tactic: 'authority', weight: 25,
    reason: 'Impersonates an authority or courier and threatens penalties',
    pattern: /(irs|income tax|customs|police|cbi|fedex|dhl|courier).{0,50}(fine|penalty|arrest|parcel|held|legal action)/i,
  },
  {
    id: 'job-scam', tactic: 'reward', weight: 25,
    reason: 'Offers easy money for work-from-home or part-time tasks',
    pattern: /(work from home|part[- ]?time job|earn).{0,50}\d[\d,]*\s*(per day|daily|per hour|a day|\/day)/i,
  },
  {
    id: 'bill-disconnect', tactic: 'fear', weight: 25,
    reason: 'Threatens to disconnect a utility service unless you act now',
    pattern: /(electricity|power|gas|water|bill).{0,40}(disconnect|cut off|discontinu)/i,
  },
  {
    id: 'refund-lure', tactic: 'lure', weight: 20,
    reason: 'Dangles a refund or cashback behind a link',
    pattern: /(refund|cashback).{0,40}(click|link|claim|process)/i,
  },

  // ------------------------------------------------------------------ English: more scam types
  {
    id: 'digital-arrest', tactic: 'authority', weight: 35,
    reason: 'Claims a police or cybercrime case against you ("digital arrest" scam)',
    pattern: /(digital arrest|cyber ?crime (branch|police)|narcotics|money laundering).{0,60}(case|arrest|warrant|parcel|aadhaar)/i,
  },
  {
    id: 'tech-support', tactic: 'fear', weight: 30,
    reason: 'Claims a virus or hack and asks you to call a support number',
    pattern: /(virus|malware|infected|hacked|security alert).{0,50}(call|contact|support|helpline|toll[- ]?free)/i,
  },
  {
    id: 'investment-scam', tactic: 'reward', weight: 30,
    reason: 'Promises guaranteed returns or doubled money',
    pattern: /(guaranteed|assured|risk[- ]?free).{0,30}(returns?|profits?|income)|(double|triple|10x).{0,20}(your )?(money|investment)|\b(crypto|forex|stock)s? (signals?|tips?)\b/i,
  },
  {
    id: 'loan-fee', tactic: 'payment', weight: 30,
    reason: 'Offers an instant loan but asks for an upfront fee or skips checks',
    pattern: /(instant|pre[- ]?approved|guaranteed).{0,20}loan.{0,40}(no (documents?|cibil|credit check)|processing fee|advance fee)/i,
  },
  {
    id: 'collect-request', tactic: 'payment', weight: 30,
    reason: 'Asks you to approve a UPI collect/payment request to "receive" money',
    pattern: /(collect request|payment request).{0,40}(approve|accept)|(approve|accept).{0,20}(collect request|payment request)/i,
  },
  {
    id: 'secrecy-demand', tactic: 'fear', weight: 25,
    reason: 'Tells you to keep the matter secret from family, bank or police',
    pattern: /(?:do not|don'?t|dont).{0,15}(?:tell|inform|discuss).{0,20}(?:anyone|anybody|family|bank|police)|keep (?:this|it) (?:confidential|secret|private)/i,
  },
  {
    id: 'delivery-fee', tactic: 'lure', weight: 20,
    reason: 'Claims a parcel problem (address, customs fee) to get you to click',
    pattern: /(parcel|package|delivery|courier).{0,50}(address (is )?(incomplete|invalid)|undeliverable|unable to deliver|reschedule|redeliver|customs fee|held at)/i,
  },
  {
    id: 'chat-invite', tactic: 'lure', weight: 20,
    reason: 'Invites you into a WhatsApp or Telegram group (common in investment scams)',
    pattern: /(join|add).{0,30}(whatsapp|telegram).{0,20}(group|channel)|\b(wa\.me|t\.me)\//i,
  },

  // ------------------------------------------------------------------ Hinglish (Hindi in Latin letters)
  {
    id: 'urgency-hinglish', tactic: 'urgency', weight: 20, lang: 'hinglish',
    reason: 'Creates artificial urgency to rush you (Hinglish)',
    pattern: /\b(turant|jaldi|abhi (karein|karo|kare)|aaj hi|der mat)\b/i,
  },
  {
    id: 'account-threat-hinglish', tactic: 'fear', weight: 25, lang: 'hinglish',
    reason: 'Threatens that your account will be closed or blocked (Hinglish)',
    pattern: /(khata|khaata).{0,30}\b(band|block|suspend)\b|\b(band|block)\b.{0,10}\bho (jayega|jaega|jayegi|jaye)\b/i,
  },
  {
    id: 'otp-hinglish', tactic: 'credential', weight: 35, lang: 'hinglish', negatable: true,
    reason: 'Asks you to hand over your OTP, PIN or CVV (Hinglish)',
    pattern: /\b(?:otp|pin|cvv).{0,20}\b(?:batao|batayein|bataye|bhejo|bhejein|dijiye)\b|\b(?:batao|batayein|bhejo|bhejein|dijiye)\b.{0,15}\b(?:otp|pin|cvv)\b/i,
  },
  {
    id: 'prize-hinglish', tactic: 'reward', weight: 25, lang: 'hinglish',
    reason: 'Promises a prize or lottery win (Hinglish)',
    pattern: /\b(inaam|inam|lottery lagi|jeet(a|e|ey)? hai|jeet liya)\b/i,
  },

  // ------------------------------------------------------------------ Hindi (Devanagari, written as \u escapes)
  {
    id: 'urgency-hindi', tactic: 'urgency', weight: 20, lang: 'hi',
    reason: 'Creates artificial urgency to rush you (Hindi)',
    pattern: /\u0924\u0941\u0930\u0902\u0924/,
  },
  {
    id: 'account-threat-hindi', tactic: 'fear', weight: 25, lang: 'hi',
    reason: 'Threatens that your account will be closed (Hindi)',
    pattern: /\u0916\u093E\u0924\u093E.{0,30}\u092C\u0902\u0926/,
  },
  {
    id: 'kyc-hindi', tactic: 'fear', weight: 30, lang: 'hi',
    reason: 'Mentions KYC (a very common bank scam topic) in Hindi',
    pattern: /\u0915\u0947\u0935\u093E\u0908\u0938\u0940/,
  },
  {
    id: 'otp-hindi', tactic: 'credential', weight: 35, lang: 'hi', negatable: true,
    reason: 'Asks you to hand over your OTP (Hindi)',
    pattern: /\u0913\u091F\u0940\u092A\u0940.{0,25}(?:\u0938\u093E\u091D\u093E|\u092C\u0924\u093E\u090F\u0902|\u092C\u0924\u093E\u0907\u090F|\u092D\u0947\u091C\u0947\u0902)/,
  },
  {
    id: 'prize-hindi', tactic: 'reward', weight: 25, lang: 'hi',
    reason: 'Promises a prize or lottery win (Hindi)',
    pattern: /\u0907\u0928\u093E\u092E|\u0932\u0949\u091F\u0930\u0940/,
  },
];
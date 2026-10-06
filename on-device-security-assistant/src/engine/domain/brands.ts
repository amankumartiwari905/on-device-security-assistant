export interface Brand {
  name: string; // first label of the official domain, e.g. "paypal"
  domains: string[]; // official registrable domains
}

export const BRANDS: Brand[] = [
  // Global
  { name: 'google', domains: ['google.com', 'google.co.in', 'googleusercontent.com', 'gstatic.com'] },
  { name: 'microsoft', domains: ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'microsoftonline.com'] },
  { name: 'apple', domains: ['apple.com', 'icloud.com'] },
  { name: 'amazon', domains: ['amazon.com', 'amazon.in', 'amazon.co.uk'] },
  { name: 'paypal', domains: ['paypal.com'] },
  { name: 'facebook', domains: ['facebook.com', 'fb.com'] },
  { name: 'instagram', domains: ['instagram.com'] },
  { name: 'whatsapp', domains: ['whatsapp.com', 'whatsapp.net'] },
  { name: 'telegram', domains: ['telegram.org', 't.me'] },
  { name: 'netflix', domains: ['netflix.com'] },
  { name: 'spotify', domains: ['spotify.com'] },
  { name: 'linkedin', domains: ['linkedin.com'] },
  { name: 'github', domains: ['github.com', 'github.io'] },
  { name: 'dropbox', domains: ['dropbox.com'] },
  { name: 'adobe', domains: ['adobe.com'] },
  { name: 'zoom', domains: ['zoom.us'] },
  { name: 'binance', domains: ['binance.com'] },
  { name: 'coinbase', domains: ['coinbase.com'] },
  { name: 'fedex', domains: ['fedex.com'] },
  { name: 'dhl', domains: ['dhl.com'] },
  { name: 'chase', domains: ['chase.com'] },
  { name: 'wellsfargo', domains: ['wellsfargo.com'] },
  { name: 'bankofamerica', domains: ['bankofamerica.com'] },
  // India
  { name: 'sbi', domains: ['sbi.co.in', 'onlinesbi.sbi'] },
  { name: 'hdfcbank', domains: ['hdfcbank.com'] },
  { name: 'icicibank', domains: ['icicibank.com'] },
  { name: 'axisbank', domains: ['axisbank.com'] },
  { name: 'kotak', domains: ['kotak.com'] },
  { name: 'pnbindia', domains: ['pnbindia.in'] },
  { name: 'bankofbaroda', domains: ['bankofbaroda.in', 'bankofbaroda.com'] },
  { name: 'paytm', domains: ['paytm.com'] },
  { name: 'phonepe', domains: ['phonepe.com'] },
  { name: 'flipkart', domains: ['flipkart.com'] },
  { name: 'swiggy', domains: ['swiggy.com'] },
  { name: 'zomato', domains: ['zomato.com'] },
  { name: 'jio', domains: ['jio.com'] },
  { name: 'airtel', domains: ['airtel.in'] },
  { name: 'irctc', domains: ['irctc.co.in'] },
  { name: 'uidai', domains: ['uidai.gov.in'] },
  { name: 'incometax', domains: ['incometax.gov.in'] },
];

export const OFFICIAL_DOMAINS = new Set(BRANDS.flatMap((b) => b.domains));
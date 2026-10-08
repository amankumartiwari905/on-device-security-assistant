# AI Guard

Phishing and scam protection (Chrome MV3). Detection runs locally. When enabled, email reputation checks send up to five valid addresses per page to EmailRep.io; Google DNS receives the domain only. Raw email headers and message bodies are analyzed locally and never sent to those providers. Optional message explanation is sent to a local Ollama instance on `localhost`.

## Develop
    npm install
    npm run demo       # offline demo at http://127.0.0.1:5000/
    npm run build     # typecheck + build popup/warning/options/background + content script
    npm test          # unit tests for the security engine

Load `dist/` via chrome://extensions > Developer mode > Load unpacked. After changes: rebuild, then reload the extension.

## Layout
- `src/engine`      pure TypeScript detection (url, domain, nlp, scoring, ml hook)
- `src/background`  navigation blocking, badge, allow-once, Ollama threat router
- `src/content`     in-page link marking and scam-text banner
- `src/ui`          React popup, warning screen, options
- `ml/`             Python training work; no ONNX model is currently bundled

## Optional local Ollama message analysis

The popup runs the local rules scan first. Qwen is triggered automatically when
the local risk score is elevated (30/100 or higher), or on any score when the
user selects **Why is this suspicious?**. The worker sends Qwen the pasted text
along with structured local evidence (risk score, risk level, reasons, and
detector indicators). Mode-specific system prompts require a concise,
evidence-based JSON explanation. Qwen does not change the local verdict or score.
If Ollama is not running or returns an invalid response, the popup clearly
reports that only the local scan is available. Requests go to
`http://localhost:11434/api/chat`.

1. Install Ollama and download the model: `ollama pull qwen3.5:4b`.
2. Start Ollama locally, then rebuild and reload the extension.
3. If Ollama rejects the extension request due to CORS, add this extension's
   `chrome-extension://<extension-id>` origin to Ollama's `OLLAMA_ORIGINS` and
   restart Ollama. Find the extension ID at `chrome://extensions`.

The extension grants access only to the Ollama API on localhost/127.0.0.1 port
11434. Page navigation checks remain local and do not call Ollama. ONNX inference
is not enabled yet: the existing ML module is a placeholder and there is no
bundled model or ONNX Runtime dependency.

## Verify an email message

The popup's **Analyze an email** tool accepts pasted raw email or an `.eml` file
(maximum 1 MB; header block maximum 50 KB). It extracts sender/recipient and
authentication headers, plain text and HTML bodies, HTTP(S) links, image
references, forms, hidden HTML text, and attachment metadata. Attachment
content is decoded only to compute its byte size and SHA-256 hash; it is never
opened or executed. HTML is parsed inertly and is never rendered as active
content.

The report compares visible link text with each target URL, and displays SPF,
DKIM, DMARC and registrable-domain alignment claims when the supplied headers
contain them. These results are not independently verified: headers can be
forged, and the extension does not validate DKIM signatures or prove mailbox
ownership. Return-Path differences are weak signals, not an automatic malicious
verdict. Parsing, extraction, and local risk checks do not upload the message.

Authentication results are reported as claims from the supplied headers, not
independently verified facts. A forged header can claim SPF/DKIM/DMARC passed;
use the original message headers from the receiving mail provider. This
extension does not independently validate DKIM cryptographic signatures or
prove mailbox ownership. A domain's SPF/DMARC DNS records are configuration
evidence only and cannot authenticate a particular message.

## Online email reputation checks

Online email reputation checks are enabled by default and can be disabled in
extension settings. When scanning a page, the content script submits at most five
valid distinct addresses to the extension service worker. EmailRep.io receives
the full address and provides reputation signals, first/last-seen information,
and an estimated domain age when available. Google DNS receives the domain for
MX, SPF, and DMARC records. These DNS records describe domain configuration;
they do not authenticate the specific message. DKIM results are read from
supplied headers only; the signature is not independently cryptographically
verified. Lookups are cached in
service-worker memory for 30 minutes; addresses are not persisted by the
reputation checker. Provider errors are reported as unavailable/partial data,
not as proof that an email is safe or malicious. Recently registered domains
and reputation matches are evidence signals, not a definitive sender identity
check. Reload the extension after building to grant the new host permissions.

## Optional URL reputation providers

URL lookups are separate from page navigation and are **disabled by default**.
After parsing an email, choose **Check links online** to manually check up to
five unique HTTP(S) links. The full URL is sent to each configured provider, so
do not query private links containing access tokens, invitation codes, or
personal data. A positive result is a provider report; a no-match or lookup
failure is not proof that a URL is safe. Provider keys are stored in
`chrome.storage.local` in the browser profile. They are not encrypted by the
extension; use a personal browser profile, not a shared or managed one.

To configure providers, open **Settings**, enable **Allow manual URL lookups**,
enter one or more API keys, and save. Only providers with a non-empty key are
queried. Lookups happen only after the explicit popup action:

1. **Google Safe Browsing** — create/select a Google Cloud project, enable the
   [Safe Browsing API](https://console.cloud.google.com/marketplace/product/google/safebrowsing.googleapis.com),
   and create an API key in [Google Cloud Credentials](https://console.cloud.google.com/apis/credentials).
   Paste the key into the Google Safe Browsing field. The extension queries
   Safe Browsing v5 and sends the full link to Google.
2. **VirusTotal** — sign in/register at
   [VirusTotal](https://www.virustotal.com/gui/my-apikey), copy the personal API
   key, and paste it into Settings. The extension requests an existing URL
   report; it does not submit unknown URLs for a new scan. Usage limits and
   acceptable-use terms depend on the account.
3. **URLhaus** — register at [abuse.ch](https://auth.abuse.ch/) and create an
   Auth-Key, then paste it into the URLhaus field. The extension submits the
   URL to URLhaus's lookup endpoint.
4. **PhishTank** — register an application at
   [PhishTank API](https://phishtank.org/api_register.php), then paste the
   application key into Settings. The extension submits the URL to its check
   endpoint. PhishTank's API is rate limited; availability and response
   behavior can vary for browser clients.

Provider APIs, quotas, and access requirements can change. The extension makes
the requests directly from its service worker; no AI Guard backend receives
the URLs or keys. Remove the keys from Settings to stop those provider queries.
Reload the extension after building so Chrome applies the added host
permissions.

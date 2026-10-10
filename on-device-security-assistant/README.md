# AI Guard

Phishing and scam protection (Chrome MV3). URL, message, and email checks run on-device by default. The bundled ONNX phishing model analyzes message and email text; URL checks use local TypeScript rules. Online reputation checks are off by default; if enabled, email reputation checks can send up to five valid addresses per page to EmailRep.io and Google DNS receives the domain. Raw email headers and message bodies are analyzed locally and never sent to those providers. Optional message explanation is sent to a local Ollama instance on `localhost`.

## Develop
    npm install
    npm run demo       # offline demo at http://127.0.0.1:5000/
    npm run build     # typecheck + build popup/warning/options/background + content script
    npm test          # unit tests for the security engine
    npm run test:model # run the bundled ONNX model on sample messages

Load `dist/` via chrome://extensions > Developer mode > Load unpacked. After changes: rebuild, then reload the extension.

## Layout
- `src/engine`      TypeScript detection (URL, domain, text, scoring) and ONNX ML inference
- `src/background`  navigation blocking, badge, allow-once, Ollama threat router
- `src/content`     in-page link marking and scam-text banner
- `src/ui`          React popup, warning screen, options
- `ml/`             Python model export and training work
- `public/models/`  browser-bundled ONNX phishing model

## On-device phishing model and optional Ollama explanation

Message and email checks run the local TypeScript detection rules and the
bundled ONNX model. The ONNX model contains the project's trained TF-IDF
vectorizer and calibrated SVM; the browser performs inference locally and does
not call FastAPI. Email inference uses the subject, extracted plain and hidden
body text, and extracted links. Model probability adds evidence to (and cannot
suppress) the local rules result. If model inference is unavailable, the
TypeScript rules remain available and the UI reports the model status.

To regenerate `public/models/phishing-text.onnx` from the committed model
artifacts, use Python 3.13 or earlier, install `ml/requirements.txt`, then run:

    python ml/export_phishing_model.py

The export validates ONNX probabilities against the sklearn model before
writing the browser asset. To validate the browser model artifact directly,
run `npm run test:model`. The browser build includes the model, bundled ONNX
Runtime Web loader, and WASM asset in `dist/`; no separate inference service is
required.

Qwen is triggered automatically when the combined risk score is elevated
(30/100 or higher), or on any score when the user selects **Why is this
suspicious?**. The worker sends Qwen the pasted text along with structured
assessment evidence (risk score, risk level, reasons, and detector indicators).
Qwen's explanation does not change the verdict or score. Requests go to the
local Ollama API at `http://localhost:11434/api/chat`.

The standalone FastAPI service remains available for API development. It is
not part of the extension's inference path. Use Python 3.13 or earlier; its
pinned scikit-learn version (1.6.1) matches the committed serialized model
artifacts:

1. From `backend/`, install dependencies from `requirements.txt`.
2. Start the service bound to loopback: `uvicorn main:app --host 127.0.0.1 --port 8000`.
3. Keep the supplied model files under `backend/models/`; restart the service
   after any model changes.

New installations use **Off** privacy mode and keep automatic online email
checks disabled. The on-device rules and ONNX model run in every mode.
**Domains** mode may send extracted website domains to registration/DNS
services. **Full** mode also allows local Ollama explanations and configured
EmailRep lookups. **Off** mode makes no enrichment or Ollama requests.
Automatic email reputation checks additionally require enabling their separate
setting, and send addresses only in **Full** mode.

To enable Ollama explanations:

1. Install Ollama and download the model: `ollama pull qwen3.5:4b`.
2. Start Ollama locally, then rebuild and reload the extension.
3. If Ollama rejects the extension request due to CORS, add this extension's
   `chrome-extension://<extension-id>` origin to Ollama's `OLLAMA_ORIGINS` and
   restart Ollama. Find the extension ID at `chrome://extensions`.

The extension needs local API access only for Ollama on port 11434. The
FastAPI service under `backend/` remains a standalone reference/development
service; the extension does not call it. Page navigation checks and message
and email ML inference run locally.

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
ownership. Reported authentication failures contribute capped, low-confidence
risk indicators so they can inform the score without being treated as verified
facts. A reported DMARC failure receives a stronger caution weight than an SPF
softfail, so their combination is not presented as negligible risk. Only trust
authentication results taken from the original headers at your receiving mail
provider.
Return-Path differences are weak signals, not an automatic malicious verdict.
The parser enforces the 1 MB limit in bytes even when called outside the popup.
Parsing, extraction, and local risk checks do not upload the message.

Authentication results are reported as claims from the supplied headers, not
independently verified facts. A forged header can claim SPF/DKIM/DMARC passed;
use the original message headers from the receiving mail provider. This
extension does not independently validate DKIM cryptographic signatures or
prove mailbox ownership. A domain's SPF/DMARC DNS records are configuration
evidence only and cannot authenticate a particular message.

## Online email reputation checks

Online email reputation checks are disabled by default and can be enabled in
extension settings. They run only in **Full** privacy mode. When enabled and
scanning a page, the content script submits at most five
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

## Local URL checks

Page-link checks run locally. They examine URL structure (including IP hosts,
nonstandard ports, HTTP, and known shorteners), punycode and mixed Latin,
Cyrillic, or Greek characters, and domains resembling known brands. These are
risk indicators, not proof that a site is malicious or safe.

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

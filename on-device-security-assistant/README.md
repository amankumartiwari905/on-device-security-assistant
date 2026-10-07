# AI Guard

On-device phishing and scam protection (Chrome MV3). Rules-based analysis runs in the extension. Optional message analysis is sent to a local Ollama instance on `localhost`; no message is sent to a remote service.

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

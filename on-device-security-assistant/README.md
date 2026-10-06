# AI Guard

On-device phishing and scam protection (Chrome MV3). All analysis runs locally; nothing is sent to a server.

## Develop
    npm install
    npm run demo       # offline demo at http://127.0.0.1:5000/
    npm run build     # typecheck + build popup/warning/options/background + content script
    npm test          # unit tests for the security engine

Load `dist/` via chrome://extensions > Developer mode > Load unpacked. After changes: rebuild, then reload the extension.

## Layout
- `src/engine`      pure TypeScript detection (url, domain, nlp, scoring, ml hook)
- `src/background`  navigation blocking, badge, allow-once
- `src/content`     in-page link marking and scam-text banner
- `src/ui`          React popup, warning screen, options
- `ml/`             Phase 2 Python training -> ONNX
import { useEffect, useState } from 'react';
import type { ChangeEvent } from 'react';
import { combineSignals, scanUrl } from '../../engine';
import type { Verdict } from '../../engine';
import { getSettings, saveSettings } from '../../storage/settings';
import { getDetectionRules } from '../../storage/detectionRules';
import { clearHistory, getHistory } from '../../storage/history';
import type { HistoryItem } from '../../storage/history';
import type { AnalyzeMessageResponse, ThreatExplanation } from '../../shared/messages';
import { MAX_EML_SIZE } from '../../engine/email/headerVerifier';
import { parseEml } from '../../engine/email/emlParser';
import type { ParsedEmail } from '../../engine/email/emlParser';
import type { CheckUrlReputationResponse } from '../../shared/messages';
import type { UrlReputationProvider, UrlReputationReport } from '../../shared/urlReputation';
import { VerdictCard } from '../components/VerdictCard';

function timeAgo(ms: number): string {
  const mins = Math.max(0, Math.round((Date.now() - ms) / 60000));
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  return hours < 24 ? `${hours}h ago` : `${Math.round(hours / 24)}d ago`;
}

export function Popup() {
  const [enabled, setEnabled] = useState(true);
  const [onlineUrlChecks, setOnlineUrlChecks] = useState(false);
  const [tabUrl, setTabUrl] = useState('');
  const [pageVerdict, setPageVerdict] = useState<Verdict | null>(null);
  const [text, setText] = useState('');
  const [textVerdict, setTextVerdict] = useState<Verdict | null>(null);
  const [textExplanation, setTextExplanation] = useState<ThreatExplanation | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [analyzingMessage, setAnalyzingMessage] = useState(false);
  const [analysisStatus, setAnalysisStatus] = useState<string | null>(null);
  const [emailSource, setEmailSource] = useState('');
  const [emailAnalysis, setEmailAnalysis] = useState<ParsedEmail | null>(null);
  const [emailError, setEmailError] = useState<string | null>(null);
  const [urlReports, setUrlReports] = useState<Record<string, UrlReputationReport> | null>(null);
  const [urlError, setUrlError] = useState<string | null>(null);
  const [checkingUrls, setCheckingUrls] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      const [settingsResult, rulesResult, historyResult, tabsResult] = await Promise.allSettled([
        Promise.resolve().then(getSettings),
        Promise.resolve().then(getDetectionRules),
        Promise.resolve().then(getHistory),
        Promise.resolve().then(() => chrome.tabs.query({ active: true, currentWindow: true })),
      ]);
      if (cancelled) return;

      const errors: string[] = [];
      if (settingsResult.status === 'fulfilled') {
        setEnabled(settingsResult.value.enabled);
        setOnlineUrlChecks(settingsResult.value.onlineUrlChecks);
      }
      else errors.push('settings');

      const rules = rulesResult.status === 'fulfilled' ? rulesResult.value : undefined;
      if (!rules) errors.push('detection rules');

      if (historyResult.status === 'fulfilled') setHistory(historyResult.value);
      else errors.push('history');

      if (tabsResult.status === 'fulfilled') {
        const tab = tabsResult.value[0];
        if (tab?.url && /^https?:/i.test(tab.url)) {
          setTabUrl(tab.url);
          setPageVerdict(scanUrl(tab.url, rules));
        }
      } else {
        errors.push('active tab');
      }

      setLoadError(errors.length ? `Could not load ${errors.join(', ')}. Reload the extension and try again.` : null);
      setLoading(false);
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  const toggle = async () => {
    const next = !enabled;
    setEnabled(next);
    await saveSettings({ enabled: next });
  };

  const clear = async () => {
    await clearHistory();
    setHistory([]);
  };

  const analyzeMessage = async (intent: 'automatic' | 'explain') => {
    setAnalyzingMessage(true);
    setAnalysisStatus(intent === 'explain' ? 'Running local checks and asking Qwen for an explanation...' : 'Running local checks...');
    if (intent === 'automatic') setTextVerdict(null);
    setTextExplanation(null);
    try {
      const response: AnalyzeMessageResponse = await chrome.runtime.sendMessage({
        type: 'ANALYZE_MESSAGE',
        text,
        intent,
      });
      if ('error' in response) {
        setAnalysisStatus(response.error);
      } else {
        setTextVerdict(response.verdict);
        setTextExplanation(response.explanation);
        setAnalysisStatus(response.ollama.message);
      }
    } catch (error) {
      console.error('[AI Guard] could not request message analysis', error);
      setAnalysisStatus('Could not reach the AI Guard service worker. Reload the extension and try again.');
    } finally {
      setAnalyzingMessage(false);
    }
  };

  const analyzeEmail = async (rawEmail: string) => {
    try {
      setEmailAnalysis(await parseEml(rawEmail));
      setUrlReports(null);
      setUrlError(null);
      setEmailError(null);
    } catch (error) {
      setEmailAnalysis(null);
      setEmailError(error instanceof Error ? error.message : 'Could not analyze this email.');
    }
  };

  const loadEmailFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const input = event.currentTarget;
    const file = input.files?.[0];
    if (!file) return;
    setEmailAnalysis(null);
    setEmailError(null);
    if (file.size > MAX_EML_SIZE) {
      setEmailError(`Choose an .eml file no larger than ${MAX_EML_SIZE.toLocaleString()} bytes.`);
      input.value = '';
      return;
    }
    try {
      const rawEmail = await file.text();
      setEmailSource(rawEmail);
      await analyzeEmail(rawEmail);
    } catch (error) {
      setEmailError(error instanceof Error ? error.message : 'Could not read this .eml file.');
    } finally {
      input.value = '';
    }
  };

  const checkEmailLinks = async () => {
    const urls = [...new Set(emailAnalysis?.links.map((link) => link.url) ?? [])].slice(0, 5);
    if (!urls.length) return;
    setCheckingUrls(true);
    setUrlReports(null);
    setUrlError(null);
    try {
      const response: CheckUrlReputationResponse = await chrome.runtime.sendMessage({
        type: 'CHECK_URL_REPUTATION',
        urls,
      });
      if ('error' in response) setUrlError(response.error);
      else setUrlReports(response.results);
    } catch (error) {
      console.error('[AI Guard] could not request URL reputation lookup', error);
      setUrlError('Could not reach the AI Guard service worker. Reload the extension and try again.');
    } finally {
      setCheckingUrls(false);
    }
  };

  return (
    <div className="popup">
      <div className="row popup-header">
        <h1>AI Guard</h1>
        <div className="popup-header-actions">
          <button className="secondary popup-settings" onClick={() => chrome.runtime.openOptionsPage()}>
            Settings
          </button>
          <label className="popup-toggle">
            <input type="checkbox" checked={enabled} onChange={toggle} /> {enabled ? 'On' : 'Off'}
          </label>
        </div>
      </div>
      <p className="muted popup-status">
        {history.length} site{history.length === 1 ? '' : 's'} blocked
      </p>
      {loadError && <p className="muted" role="status">{loadError}</p>}

      <h2 className="popup-heading">This website</h2>
      {loading ? (
        <p className="muted">Checking this tab...</p>
      ) : pageVerdict ? (
        <>
          <div className="muted popup-url" title={tabUrl}>{tabUrl}</div>
          <VerdictCard verdict={pageVerdict} />
        </>
      ) : (
        <p className="muted">Open a website to see its risk.</p>
      )}

      <details className="popup-section">
        <summary>Check a message</summary>
        <div className="popup-section-content">
          <textarea
            value={text}
            placeholder="Paste a text, email, or chat message..."
            disabled={analyzingMessage}
            onChange={(e) => {
              setText(e.target.value);
              setTextVerdict(null);
              setTextExplanation(null);
              setAnalysisStatus(null);
            }}
          />
          <p className="muted popup-counter">{text.length.toLocaleString()} / 20,000</p>
          <button onClick={() => void analyzeMessage('automatic')} disabled={!text.trim() || analyzingMessage || text.length > 20_000}>
            {analyzingMessage ? 'Checking...' : 'Check message'}
          </button>
          {text.length > 20_000 && <p className="muted" role="alert">Message is too long. Limit: 20,000 characters.</p>}
          {analysisStatus && <p className="muted" role="status">{analysisStatus}</p>}
          {textVerdict && (
            <>
              <VerdictCard verdict={textVerdict} />
              <button
                className="secondary"
                onClick={() => void analyzeMessage('explain')}
                disabled={analyzingMessage || text.length > 20_000}
              >
                {analyzingMessage ? 'Explaining...' : 'Explain result'}
              </button>
              {textExplanation && (
                <section className="card" aria-label="AI explanation">
                  <p>{textExplanation.summary}</p>
                  {textExplanation.reasons.length > 0 && (
                    <ul>
                      {textExplanation.reasons.map((reason, index) => <li key={`${index}-${reason}`}>{reason}</li>)}
                    </ul>
                  )}
                  <p><strong>What to do:</strong> {textExplanation.recommendation}</p>
                </section>
              )}
            </>
          )}
        </div>
      </details>

      <details className="popup-section">
        <summary>Check an email</summary>
        <div className="popup-section-content">
          <p className="muted">Paste an email or choose an .eml file. Analysis stays on your device.</p>
          <textarea
            value={emailSource}
            maxLength={MAX_EML_SIZE}
            placeholder={'From: sender@example.com\nSubject: Example\n\nEmail text'}
            onChange={(event) => {
              setEmailSource(event.target.value);
              setEmailAnalysis(null);
              setEmailError(null);
              setUrlReports(null);
              setUrlError(null);
            }}
          />
          <p className="muted popup-counter">{emailSource.length.toLocaleString()} / {MAX_EML_SIZE.toLocaleString()}</p>
          <div className="actions header-actions">
            <button onClick={() => void analyzeEmail(emailSource)} disabled={!emailSource.trim()}>
              Check email
            </button>
            <label className="file-picker">
              <span>Choose .eml file</span>
              <input type="file" accept=".eml,message/rfc822" onChange={(event) => void loadEmailFile(event)} />
            </label>
          </div>
          {emailSource.length >= MAX_EML_SIZE && <p className="muted" role="alert">Email text is at the size limit.</p>}
          {emailError && <p className="muted" role="alert">{emailError}</p>}
          {emailAnalysis && (
            <>
              <EmailAnalysisResult email={emailAnalysis} />
              <button className="secondary" onClick={() => void checkEmailLinks()}
                disabled={!onlineUrlChecks || checkingUrls || emailAnalysis.links.length === 0}>
                {checkingUrls ? 'Checking links...' : `Check links online (${Math.min(emailAnalysis.links.length, 5)})`}
              </button>
              {!onlineUrlChecks && <p className="muted">Turn on online link checks in Settings to use this.</p>}
              {urlError && <p className="muted" role="alert">{urlError}</p>}
              {urlReports && <UrlReputationResults reports={urlReports} />}
            </>
          )}
        </div>
      </details>

      <details className="popup-section">
        <summary>Blocked sites ({history.length})</summary>
        <div className="popup-section-content">
          {history.length > 0 ? (
            <>
              <button className="secondary" onClick={clear} style={{ padding: '3px 8px', fontSize: 12 }}>
                Clear history
              </button>
              <ul className="history">
                {history.slice(0, 5).map((h) => (
                  <li key={`${h.time}-${h.hostname}`}>
                    <span>{h.hostname}</span>
                    <span className="muted">{h.score} · {timeAgo(h.time)}</span>
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <p className="muted">No sites blocked yet.</p>
          )}
        </div>
      </details>
    </div>
  );
}

function EmailAnalysisResult({ email }: { email: ParsedEmail }) {
  const assessment = email.headerAssessment;
  const statusLabel = {
    'reported-pass': 'DMARC pass reported',
    'reported-fail': 'DMARC fail reported',
    'reported-inconclusive': 'DMARC result inconclusive',
    missing: 'No DMARC result found',
  }[assessment.dmarcStatus];
  return (
    <section className="card" aria-label="Parsed email report">
      <div className="row">
        <strong>{statusLabel}</strong>
        <strong>{assessment.riskScore}/100 risk</strong>
      </div>
      <p className="muted email-sender">
        Sender: {assessment.from ?? 'not found'}
        {assessment.signals.length > 0 && ` · ${assessment.signals.length} warning${assessment.signals.length === 1 ? '' : 's'}`}
      </p>
      <details className="email-report-details">
        <summary>See email details</summary>
      <details>
        <summary>Headers ({email.headers.length})</summary>
        <ul className="header-claims">
          {email.headers.map(({ name, values }) => (
            <li key={name}><strong>{name}:</strong> {values.join(' | ')}</li>
          ))}
        </ul>
      </details>
      <div className="row" style={{ marginTop: 10 }}>
        <strong>{statusLabel}</strong>
        <strong>{assessment.riskScore}/100 estimate</strong>
      </div>
      <p className="muted">Authentication results are unverified header claims; this is not a probability.</p>
      <div className="header-claims">
        {(['spf', 'dkim', 'dmarc'] as const).map((method) => {
          const claims = assessment.claims.filter((claim) => claim.method === method);
          const reported = claims.length ? claims.map((claim) => claim.result.toUpperCase()).join(', ') : 'not reported';
          return <p key={method} style={{ margin: '4px 0' }}>
            <strong>{method.toUpperCase()}:</strong> {reported}
            {claims.some((claim) => claim.result === 'pass') && ` · alignment ${assessment.alignment[method]}`}
          </p>;
        })}
      </div>
      <p className="muted">
        Display name: {assessment.senderDisplayName ?? 'not found'} · From: {assessment.from ?? 'not found'} ·
        Domain: {assessment.senderDomain ?? 'not found'}
        {assessment.claimedBrand && ` · Claimed brand: ${assessment.claimedBrand}`}
      </p>
      <p className="muted">Reply-To: {assessment.replyTo ?? 'not found'} · Return-Path: {assessment.returnPath ?? 'not found'}</p>
      <details>
        <summary>Received route ({email.receivedRoute.length} hops)</summary>
        {email.receivedRoute.length ? <ol className="header-claims">
          {email.receivedRoute.map((hop, index) => (
            <li key={`${index}-${hop.header}`}>
              {hop.ipAddresses.length ? `IP address${hop.ipAddresses.length === 1 ? '' : 'es'}: ${hop.ipAddresses.join(', ')}` : 'No IP literal extracted'}
              <div>{hop.header}</div>
            </li>
          ))}
        </ol> : <p className="muted">No Received headers found.</p>}
        <p className="muted">Header order and IP location are not proof of the sender's origin; these values are not geolocated.</p>
      </details>
      {assessment.claims.length > 0 ? (
        <ul className="header-claims">
          {assessment.claims.map((claim, index) => (
            <li key={`${claim.source}-${claim.authservId}-${claim.method}-${index}`}>
              {claim.method.toUpperCase()} {claim.result.toUpperCase()} reported by {claim.authservId}
              {claim.identityDomain ? ` (${claim.identityDomain})` : ''}
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted">No SPF/DKIM/DMARC results were found in the supplied headers.</p>
      )}
      {assessment.signals.length > 0 && (
        <ul className="header-claims">
          {assessment.signals.map((signal) => <li key={signal.id}>{signal.reason}</li>)}
        </ul>
      )}
      <ul className="header-warnings">
        {assessment.warnings.map((warning) => <li key={warning}>{warning}</li>)}
      </ul>
      <EmailDetail label={`Plain text body (${email.plainText.length.toLocaleString()} characters)`} value={email.plainText} />
      <EmailDetail label={`HTML body (${email.html.length.toLocaleString()} characters; inert text only)`} value={email.html} />
      <details>
        <summary>Links ({email.links.length})</summary>
        {email.links.length ? <ul className="header-claims">
          {email.links.map((link, index) => {
            const verdict = scanUrl(link.url);
            return (
              <li key={`${link.url}-${link.source}-${index}`}>
                {link.mismatch && <strong>Displayed link differs from target · </strong>}
                {link.displayedText && `Shown: ${link.displayedText} · `}
                <div>{link.source}: {link.url}</div>
                <div>Local URL risk: {verdict.score}/100
                  {verdict.signals.length > 0 && ` · ${verdict.signals.map((signal) => signal.reason).join('; ')}`}
                </div>
              </li>
            );
          })}
        </ul> : <p className="muted">No web links found.</p>}
      </details>
      <details>
        <summary>Images ({email.images.length}) and forms ({email.forms.length})</summary>
        {email.images.length > 0 && <ul className="header-claims">{email.images.map((image, index) =>
          <li key={`${image}-${index}`}>Image source: {image}</li>)}</ul>}
        {email.forms.length > 0 && <ul className="header-claims">{email.forms.map((form, index) =>
          <li key={`${form.action}-${index}`}>Form {form.method.toUpperCase()} → {form.action || '(no action)'}</li>)}</ul>}
        {!email.images.length && !email.forms.length && <p className="muted">No image references or forms found.</p>}
      </details>
      <details>
        <summary>Hidden text ({email.hiddenText.length})</summary>
        {email.hiddenText.length ? <ul className="header-claims">
          {email.hiddenText.map((text, index) => <li key={`${index}-${text}`}>{text}</li>)}
        </ul> : <p className="muted">No hidden HTML text found.</p>}
      </details>
      <details>
        <summary>Attachments ({email.attachments.length})</summary>
        {email.attachments.length ? <ul className="header-claims">
          {email.attachments.map((attachment, index) => (
            <li key={`${attachment.sha256}-${index}`}>
              {attachment.filename} · {attachment.extension || '(no extension)'} · {attachment.mimeType} · {attachment.size.toLocaleString()} bytes · SHA-256 {attachment.sha256}
            </li>
          ))}
        </ul> : <p className="muted">No attachments found.</p>}
        <p className="muted">Attachments were decoded for metadata and hashing only; they were not opened or executed.</p>
      </details>
      </details>
    </section>
  );
}

function EmailDetail({ label, value }: { label: string; value: string }) {
  return (
    <details>
      <summary>{label}</summary>
      {value ? <pre className="email-body">{value}</pre> : <p className="muted">No content found.</p>}
    </details>
  );
}

function UrlReputationResults({ reports }: { reports: Record<string, UrlReputationReport> }) {
  const providerNames: Record<UrlReputationProvider, string> = {
    googleSafeBrowsing: 'Google Safe Browsing',
    virusTotal: 'VirusTotal',
    urlhaus: 'URLhaus',
    phishTank: 'PhishTank',
  };
  return (
    <section className="card" aria-label="URL reputation report">
      <strong>Online URL reputation</strong>
      {Object.entries(reports).map(([url, report]) => {
        const local = scanUrl(url);
        const providerSignals = report.providers
          .filter(({ status }) => status === 'listed')
          .map(({ provider, detail }) => ({
            id: `url-reputation-${provider}`,
            weight: 55,
            reason: `${providerNames[provider]} reported this URL: ${detail}`,
          }));
        const combined = combineSignals([...local.signals, ...providerSignals]);
        return (
          <div key={url} className="url-report">
            <p className="muted">{url}</p>
            <p><strong>Local URL risk: {local.score}/100</strong> · <strong>with provider matches: {combined.score}/100</strong></p>
            <ul className="header-claims">
              {report.providers.map(({ provider, status, detail }) => (
                <li key={provider}><strong>{providerNames[provider]}:</strong> {status} — {detail}</li>
              ))}
            </ul>
          </div>
        );
      })}
      <p className="muted">A provider hit adds a risk signal; a no-match adds no safety points. Scores are heuristic, and “not listed” or unavailable does not mean safe.</p>
    </section>
  );
}
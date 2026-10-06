import { useEffect, useState } from 'react';
import { scanText, scanUrl } from '../../engine';
import type { Verdict } from '../../engine';
import { getSettings, saveSettings } from '../../storage/settings';
import { getDetectionRules } from '../../storage/detectionRules';
import { clearHistory, getHistory } from '../../storage/history';
import type { HistoryItem } from '../../storage/history';
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
  const [tabUrl, setTabUrl] = useState('');
  const [pageVerdict, setPageVerdict] = useState<Verdict | null>(null);
  const [text, setText] = useState('');
  const [textVerdict, setTextVerdict] = useState<Verdict | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

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
      if (settingsResult.status === 'fulfilled') setEnabled(settingsResult.value.enabled);
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

  return (
    <div className="popup">
      <div className="row">
        <h1>AI Guard</h1>
        <label style={{ margin: 0 }}>
          <input type="checkbox" checked={enabled} onChange={toggle} /> On
        </label>
      </div>
      <p className="muted" style={{ margin: '0 0 6px' }}>
        {history.length} threat{history.length === 1 ? '' : 's'} blocked. 100% on-device.
      </p>
      {loadError && <p className="muted" role="status">{loadError}</p>}

      <h2>This page</h2>
      {loading ? (
        <p className="muted">Checking this tab...</p>
      ) : pageVerdict ? (
        <>
          <div className="muted">{tabUrl}</div>
          <VerdictCard verdict={pageVerdict} />
        </>
      ) : (
        <p className="muted">Open a website to see its risk.</p>
      )}

      <h2>Check a message</h2>
      <textarea
        value={text}
        placeholder="Paste an SMS, email or chat message..."
        onChange={(e) => setText(e.target.value)}
      />
      <div className="actions">
        <button onClick={async () => setTextVerdict(scanText(text, await getDetectionRules()))} disabled={!text.trim()}>
          Analyze
        </button>
        <button className="secondary" onClick={() => chrome.runtime.openOptionsPage()}>
          Settings
        </button>
      </div>
      {textVerdict && <VerdictCard verdict={textVerdict} />}

      <div className="row">
        <h2>Recently blocked</h2>
        {history.length > 0 && (
          <button className="secondary" onClick={clear} style={{ padding: '3px 8px', fontSize: 12 }}>
            Clear
          </button>
        )}
      </div>
      {history.length > 0 ? (
        <ul className="history">
          {history.slice(0, 5).map((h) => (
            <li key={`${h.time}-${h.hostname}`}>
              <span>{h.hostname}</span>
              <span className="muted">
                {h.score} - {timeAgo(h.time)}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted">Nothing blocked yet.</p>
      )}
    </div>
  );
}
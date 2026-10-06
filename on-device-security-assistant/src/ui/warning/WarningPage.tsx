import type { Message } from '../../shared/messages';
import type { Signal } from '../../engine';

export function WarningPage() {
  const params = new URLSearchParams(location.search);
  const rawTarget = params.get('url') ?? '';
  const target = /^https?:\/\//i.test(rawTarget) ? rawTarget : '';
  const score = Number(params.get('score') ?? 0);

  let signals: Signal[] = [];
  try {
    const parsed: unknown = JSON.parse(params.get('signals') ?? '[]');
    if (Array.isArray(parsed)) {
      signals = parsed.filter((signal): signal is Signal =>
        typeof signal === 'object'
        && signal !== null
        && 'id' in signal
        && typeof signal.id === 'string'
        && 'reason' in signal
        && typeof signal.reason === 'string'
        && 'weight' in signal
        && typeof signal.weight === 'number'
        && (!('evidence' in signal) || typeof signal.evidence === 'string'),
      );
    }
  } catch {
    /* ignore malformed signals */
  }

  const goBack = () => {
    if (history.length > 1) history.back();
    else window.close();
  };

  const proceed = async () => {
    if (!target) return;
    const msg: Message = { type: 'ALLOW_ONCE', url: target };
    const response = await chrome.runtime.sendMessage(msg);
    if (!response?.ok) return;
    location.href = target;
  };

  return (
    <div className="page">
      <div className="danger-screen">
        <h1>Dangerous site blocked</h1>
        <p>AI Guard stopped this page before it loaded (risk {score}/100).</p>
        <p className="muted">{target || 'Unknown address'}</p>

        <h2>Detected indicators ({signals.length})</h2>
        <ul className="signals">
          {signals.map((s) => (
            <li key={s.id}>
              <code className="signal-id">{s.id}</code>
              <div className="row">
                <span>{s.reason}</span>
                <span className="muted signal-weight" title="Signal weight (0-100)">
                  {s.weight}/100
                </span>
              </div>
              {s.evidence && <div className="signal-evidence">&ldquo;{s.evidence}&rdquo;</div>}
              <div className="bar">
                <div style={{ width: `${s.weight}%`, background: '#dc2626' }} />
              </div>
            </li>
          ))}
        </ul>
        <p className="muted scoring-note">
          Signal weights describe individual clues; the overall risk score combines them.
        </p>
        <p className="muted">Analyzed entirely on your device. Nothing was sent to a server.</p>

        <div className="actions">
          <button onClick={goBack}>Take me to safety</button>
          <button className="secondary" onClick={proceed} disabled={!target}>
            Proceed anyway (unsafe)
          </button>
        </div>
      </div>
    </div>
  );
}
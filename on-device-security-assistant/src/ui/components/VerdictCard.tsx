import type { Verdict } from '../../engine';

const COLORS = { safe: '#16a34a', suspicious: '#d97706', dangerous: '#dc2626' } as const;
const LABELS = { safe: 'Looks safe', suspicious: 'Suspicious', dangerous: 'Dangerous' } as const;

export function VerdictCard({ verdict }: { verdict: Verdict & { durationMs?: number } }) {
  const color = COLORS[verdict.level];
  return (
    <div className="card" style={{ borderColor: color }}>
      <div className="row">
        <strong style={{ color }}>{LABELS[verdict.level]}</strong>
        <strong className="verdict-score" style={{ color }}>{verdict.score}<span>/100</span></strong>
      </div>
      <div
        className="verdict-meter"
        role="meter"
        aria-label="Risk score"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={verdict.score}
      >
        <div style={{ width: `${verdict.score}%`, background: color }} />
      </div>
      <div className="risk-scale" aria-label="Risk score scale">
        <span>Lower 0–29</span>
        <span>Elevated 30–59</span>
        <span>High 60–100</span>
      </div>
      <p className="muted scoring-note">
        Rule-based estimate from detected signals; it is not a probability or a guarantee.
      </p>
      {verdict.signals.length > 0 ? (
        <>
          <div className="muted signal-summary">
            Detected indicators ({verdict.signals.length})
          </div>
          <ul className="signals">
            {verdict.signals.map((s) => (
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
                  <div style={{ width: `${s.weight}%`, background: color }} />
                </div>
              </li>
            ))}
          </ul>
          <p className="muted scoring-note">
            Signal weights describe individual clues; the overall risk score combines them.
          </p>
        </>
      ) : (
        <p className="muted">No threat signals found.</p>
      )}
      {verdict.durationMs !== undefined && (
        <p className="muted" style={{ margin: '8px 0 0' }}>
          Analyzed on-device in {verdict.durationMs} ms
        </p>
      )}
    </div>
  );
}
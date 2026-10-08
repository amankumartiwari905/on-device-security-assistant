import type { Verdict } from '../../engine';

const COLORS = { safe: '#16a34a', suspicious: '#d97706', dangerous: '#dc2626' } as const;
const LABELS = { safe: 'Looks safe', suspicious: 'Suspicious', dangerous: 'Dangerous' } as const;
const ADVICE = {
  safe: 'No obvious warning signs found.',
  suspicious: 'Check the sender and links before you respond.',
  dangerous: 'Avoid links and never share passwords or payment details.',
} as const;

export function VerdictCard({ verdict }: { verdict: Verdict & { durationMs?: number } }) {
  const color = COLORS[verdict.level];
  return (
    <div className="card verdict-card" style={{ borderColor: color }}>
      <div className="row verdict-title">
        <strong style={{ color }}>{LABELS[verdict.level]}</strong>
        <strong className="verdict-score" style={{ color }}>{verdict.score}<span>/100 risk</span></strong>
      </div>
      <p className="verdict-advice">{ADVICE[verdict.level]}</p>
      <div className="verdict-meter" role="meter" aria-label="Risk score" aria-valuemin={0} aria-valuemax={100} aria-valuenow={verdict.score}>
        <div style={{ width: `${verdict.score}%`, background: color }} />
      </div>
      <details className="verdict-details">
        <summary>{verdict.signals.length ? `Why? ${verdict.signals.length} clue${verdict.signals.length === 1 ? '' : 's'}` : 'About this result'}</summary>
        {verdict.signals.length > 0 ? (
          <ul className="signals">
            {verdict.signals.map((s) => (
              <li key={s.id}>
                <div className="row">
                  <span>{s.reason}</span>
                  <span className="muted signal-weight" title="Signal weight">{s.weight}</span>
                </div>
                {s.evidence && <div className="signal-evidence">&ldquo;{s.evidence}&rdquo;</div>}
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">No warning signs were detected.</p>
        )}
        <p className="muted scoring-note">This is an estimate from on-device checks, not a guarantee.</p>
        {verdict.durationMs !== undefined && (
          <p className="muted scoring-note">Checked on your device in {verdict.durationMs} ms.</p>
        )}
      </details>
    </div>
  );
}
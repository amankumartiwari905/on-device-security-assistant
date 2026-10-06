import { useEffect, useState } from 'react';
import { DEFAULT_SETTINGS, getSettings, saveSettings } from '../../storage/settings';
import type { Sensitivity, Settings } from '../../storage/settings';
import {
  formatDetectionRules,
  getDetectionRules,
  parseDetectionRuleText,
  saveDetectionRules,
} from '../../storage/detectionRules';
import type { DetectionRuleText } from '../../storage/detectionRules';
import { DEFAULT_DETECTION_RULES } from '../../engine/url/rules';

export function Options() {
  const [s, setS] = useState<Settings>(DEFAULT_SETTINGS);
  const [allowText, setAllowText] = useState('');
  const [ruleText, setRuleText] = useState<DetectionRuleText>(formatDetectionRules(DEFAULT_DETECTION_RULES));
  const [saved, setSaved] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([getSettings(), getDetectionRules()]).then(([cur, rules]) => {
      setS(cur);
      setAllowText(cur.allowlist.join('\n'));
      setRuleText(formatDetectionRules(rules));
    });
  }, []);

  const update = (patch: Partial<Settings>) => {
    setS((prev) => ({ ...prev, ...patch }));
    setSaved(false);
    setSaveError(null);
  };

  const save = async () => {
    const allowlist = allowText.split('\n').map((l) => l.trim().toLowerCase()).filter(Boolean);
    try {
      const detectionRules = parseDetectionRuleText(ruleText);
      await Promise.all([
        saveSettings({ ...s, allowlist }),
        saveDetectionRules(detectionRules),
      ]);
      setSaved(true);
      setSaveError(null);
    } catch (error) {
      setSaved(false);
      setSaveError(error instanceof Error ? error.message : 'Could not save settings.');
    }
  };

  return (
    <div className="page">
      <h1>AI Guard settings</h1>

      <label>
        <input type="checkbox" checked={s.enabled} onChange={(e) => update({ enabled: e.target.checked })} /> Protection enabled
      </label>

      <label>
        <input
          type="checkbox"
          checked={s.scanPageText}
          onChange={(e) => update({ scanPageText: e.target.checked })}
        />{' '}
        Scan page text for scam language
      </label>

      <label>
        Blocking sensitivity{' '}
        <select value={s.sensitivity} onChange={(e) => update({ sensitivity: e.target.value as Sensitivity })}>
          <option value="low">Low (fewer warnings)</option>
          <option value="medium">Medium</option>
          <option value="high">High (more warnings)</option>
        </select>
      </label>

      <h2>Trusted sites (one hostname per line)</h2>
      <textarea
        value={allowText}
        placeholder="example.com"
        onChange={(e) => {
          setAllowText(e.target.value);
          setSaved(false);
        }}
      />

      <h2>URL detection rules</h2>
      <p className="muted">These rule lists are saved locally and used for URL, page, and link scans.</p>
      <label>
        Brands (brand=domain[, domain], one brand per line)
        <textarea value={ruleText.brands} onChange={(e) => {
          setRuleText((prev) => ({ ...prev, brands: e.target.value }));
          setSaved(false);
          setSaveError(null);
        }} />
      </label>
      <label>
        Suspicious TLDs (one per line)
        <textarea value={ruleText.suspiciousTlds} onChange={(e) => {
          setRuleText((prev) => ({ ...prev, suspiciousTlds: e.target.value }));
          setSaved(false);
          setSaveError(null);
        }} />
      </label>
      <label>
        URL shortener hostnames (one per line)
        <textarea value={ruleText.urlShorteners} onChange={(e) => {
          setRuleText((prev) => ({ ...prev, urlShorteners: e.target.value }));
          setSaved(false);
          setSaveError(null);
        }} />
      </label>
      <label>
        Suspicious URL keywords (one per line)
        <textarea value={ruleText.suspiciousKeywords} onChange={(e) => {
          setRuleText((prev) => ({ ...prev, suspiciousKeywords: e.target.value }));
          setSaved(false);
          setSaveError(null);
        }} />
      </label>

      <div className="actions">
        <button onClick={save}>Save</button>
        {saved && <span className="muted">Saved</span>}
      </div>
      {saveError && <p className="muted" role="alert">{saveError}</p>}
    </div>
  );
}
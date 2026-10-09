import { useEffect, useState } from 'react';
import { DEFAULT_SETTINGS, getSettings, saveSettings } from '../../storage/settings';
import type { Sensitivity, Settings } from '../../storage/settings';
import { DEFAULT_INTEL_SETTINGS, getIntelSettings, saveIntelSettings } from '../../background/intel/intelSettings';
import type { IntelMode } from '../../background/intel/intelSettings';
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
  const [intelMode, setIntelMode] = useState<IntelMode>(DEFAULT_INTEL_SETTINGS.mode);
  const [allowText, setAllowText] = useState('');
  const [ruleText, setRuleText] = useState<DetectionRuleText>(formatDetectionRules(DEFAULT_DETECTION_RULES));
  const [saved, setSaved] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([getSettings(), getIntelSettings(), getDetectionRules()]).then(([cur, intel, rules]) => {
      setS(cur);
      setIntelMode(intel.mode);
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
        saveIntelSettings({ mode: intelMode }),
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

      <h2>Online enrichment privacy</h2>
      <label>
        Privacy mode{' '}
        <select
          value={intelMode}
          onChange={(e) => {
            setIntelMode(e.target.value as IntelMode);
            setSaved(false);
            setSaveError(null);
          }}
        >
          <option value="off">Off — local checks only</option>
          <option value="domains">Domains — send domain names only</option>
          <option value="full">Full — allow configured online and local-model checks</option>
        </select>
      </label>
      <p className="muted">
        Off is the default and makes no enrichment requests. Domains may send website domains to registration and DNS
        services. Full enables the optional local phishing and explanation services; automatic EmailRep checks still
        require the separate setting below.
      </p>

      <label>
        <input
          type="checkbox"
          checked={s.scanPageText}
          onChange={(e) => update({ scanPageText: e.target.checked })}
        />{' '}
        Scan page text for scam language
      </label>

      <label>
        <input
          type="checkbox"
          checked={s.onlineEmailChecks}
          onChange={(e) => update({ onlineEmailChecks: e.target.checked })}
        />{' '}
        Check email addresses online automatically
      </label>
      <p className="muted">
        When enabled in Full privacy mode, up to 5 valid addresses found on each page are sent to EmailRep.io for
        reputation checks. Google DNS receives the email domain to inspect MX, SPF, and DMARC records. This is
        disabled by default; leave it off to keep email checks local-only.
      </p>

      <h2>Online URL reputation providers</h2>
      <label>
        <input
          type="checkbox"
          checked={s.onlineUrlChecks}
          onChange={(e) => update({ onlineUrlChecks: e.target.checked })}
        />{' '}
        Allow manual URL lookups
      </label>
      <p className="muted">
        Lookups run only when you choose “Check links online” for a parsed email. Up to five full URLs are sent to
        every provider with a configured key. Keys are stored in this browser profile’s extension storage (not
        encrypted) and are sent only to their named provider. Do not use shared or managed browsers for personal keys.
        Unconfigured providers are skipped; provider errors and no-match results are not proof that a URL is safe.
      </p>
      <label>
        Google Safe Browsing API key
        <input type="password" autoComplete="off" value={s.googleSafeBrowsingKey}
          onChange={(e) => update({ googleSafeBrowsingKey: e.target.value })} />
      </label>
      <label>
        VirusTotal API key
        <input type="password" autoComplete="off" value={s.virusTotalKey}
          onChange={(e) => update({ virusTotalKey: e.target.value })} />
      </label>
      <label>
        URLhaus Auth-Key
        <input type="password" autoComplete="off" value={s.urlhausAuthKey}
          onChange={(e) => update({ urlhausAuthKey: e.target.value })} />
      </label>
      <label>
        PhishTank application key
        <input type="password" autoComplete="off" value={s.phishTankAppKey}
          onChange={(e) => update({ phishTankAppKey: e.target.value })} />
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
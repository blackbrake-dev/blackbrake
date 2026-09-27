// Which problems can be fixed, and how: blackbrake itself, locally (clean-up of secret copies, safe
// settings changes), and/or the user's own AI agent with a prompt. Built from the audit's
// precautions (they carry an id) and from the scan's results. Pure: data in, a list out.
import { t } from '../i18n.mjs';
import { CLASSES } from '../secrets/context.mjs';
import { canFixSettings } from './settings.mjs';

// Precautions with nothing to fix (information only).
const NOT_FIXABLE = new Set(['episodes']);

// From the audit: each precaution becomes a fix. Secrets' keys let the clean-up find their copies.
export function fixesFromAudit(advice, data) {
  const real = data.secrets.filter((s) => s.classification === CLASSES.real);

  return advice.filter((a) => a.id && !NOT_FIXABLE.has(a.id)).map((a) => {
    const fix = { id: a.id, level: a.level, title: a.title, why: a.why, steps: a.steps, auto: null };

    if (a.id === 'rotate' || a.id === 'local-copies') {
      const keys = (a.id === 'rotate' ? real.filter((s) => s.inTranscripts !== false || (s.stores ?? []).length) : real.filter((s) => !s.inTranscripts && !s.inConfig)).map((s) => s.key);

      if (keys.length) fix.auto = { kind: 'scrub', source: 'claude', keys };
    }

    if (canFixSettings(a.id, a.where)) fix.auto = { kind: 'settings', ids: [a.id] };

    return fix;
  });
}

// From the scan: one fix per AI tool with secrets that look real.
export function fixesFromScan(results) {
  return results.filter((r) => r.findings.some((f) => f.classification === CLASSES.real)).map((r) => {
    const real = r.findings.filter((f) => f.classification === CLASSES.real);

    return {
      id: `scan:${r.id}`,
      level: 'critical',
      title: t('Secrets in {name}\'s files', { name: r.name }),
      why: t('{n} look real in its history, sessions or settings: whoever reads those files has them.', { n: real.length }),
      steps: [
        ...real.slice(0, 8).map((f) => `${f.ruleId} ${f.shape}: ${f.files.slice(0, 3).join(', ')}${f.fileCount > 3 ? ' …' : ''}`),
        t('Rotate each key at its provider, then remove the old copies from these files.'),
        t('Where a key sits in a settings file, replace it with a reference to an environment variable.'),
      ],
      auto: { kind: 'scrub', source: r.id, keys: real.map((f) => f.key).filter(Boolean) },
    };
  });
}

// Lays out a report from what the person typed and the aggregates they ticked (guard-design#6x §5.3,
// §5.4). The builder writes the headings; a typed field cannot add one. What it returns has passed
// the validator, so there is no way to get text out of here that the validator would refuse.
import { randomBytes } from 'node:crypto';
import { assertKind, HEADINGS, TITLES, validateReport } from './validate.mjs';

// The closed list for the security report's "Affected part" (design §5.3).
export const AFFECTED_PARTS = Object.freeze(['guard or hook', 'watcher', 'login item', 'reports', 'site', 'other']);

const VERSION = /^\d{1,3}\.\d{1,3}\.\d{1,3}$/;

// Normalized like the file will be: LF, no trailing spaces, no blank lines at the ends.
function tidy(text) {
  return String(text ?? '').replace(/\r\n/g, '\n').split('\n').map((l) => l.replace(/[ \t]+$/, '')).join('\n').replace(/^\n+|\n+$/g, '');
}

function utc(now) {
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new TypeError('now must be a valid Date');

  return now.toISOString();
}

// `fields` are typed text by heading; `sections` are the automatic lines by heading (arrays of
// "- key: value"). Returns { ok, text } or { ok: false, problems } (line numbers are in the built
// text; never the content).
export function buildReport({ kind, version, now, rules, identity, fields = {}, sections = {} }) {
  assertKind(kind);

  if (!VERSION.test(String(version))) throw new TypeError('version must look like 0.3.0');
  const date = utc(now).slice(0, 10);
  const bodies = new Map();
  const problems = [];

  for (const [source, isField] of [[fields, true], [sections, false]]) {
    for (const [name, value] of Object.entries(source)) {
      if (!HEADINGS[kind].includes(name)) throw new TypeError('unknown report section');

      if (bodies.has(name)) throw new TypeError('section given twice');
      const body = isField ? tidy(value) : (Array.isArray(value) ? value : []).map((l) => tidy(l)).join('\n');

      if (isField && body.split('\n').some((l) => l.startsWith('#'))) problems.push({ rule: 'V5', code: 'heading-in-field', line: 0, field: name });

      if (body !== '') bodies.set(name, body);
    }
  }

  if (problems.length) return { ok: false, problems };
  const blocks = HEADINGS[kind].filter((name) => bodies.has(name)).map((name) => `## ${name}\n${bodies.get(name)}`);
  const text = [`# ${TITLES[kind]}`, `Version: ${version}, Date: ${date}`, '', ...blocks.flatMap((b, i) => (i ? ['', b] : [b]))].join('\n') + '\n';
  const checked = validateReport(text, { kind, rules, identity });

  return checked.ok ? { ok: true, text: checked.text, problems: [] } : { ok: false, problems: checked.problems };
}

// Generated name (design V8): <kind>-<UTC date>T<UTC time>Z-<8 hex>.md. `random` is injectable for tests.
export function reportFileName(kind, now, random = () => randomBytes(4)) {
  assertKind(kind);
  const stamp = utc(now).replace(/[-:]/g, '').slice(0, 15);
  const hex = Buffer.from(random()).toString('hex');

  if (hex.length !== 8) throw new TypeError('random part must be 4 bytes');

  return `${kind}-${stamp}Z-${hex}.md`;
}

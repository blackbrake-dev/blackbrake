// The automatic data a report can carry, and only as aggregates (guard-design#6x §5.3). Every key is
// checked against a closed shape (and, where the caller has one, a closed list), every count is an
// integer, and a key that fails is counted, never shown: a rejected key may be exactly what should
// not leave the machine. Nothing here is added unless its box was ticked.
import { CLASSES } from '../secrets/context.mjs';
import { AUTO_SECTIONS } from './validate.mjs';

export const SAFE_KEY = /^[a-z0-9][a-z0-9-]{1,60}$/;
const MAX_COUNT = 999999;

// `- <label> <key>: <n>` lines, sorted by key. `allowed` (a Set) narrows the keys further.
export function countLines(label, input, { allowed } = {}) {
  if (!input || typeof input !== 'object') return { lines: [], rejected: 0 };
  const kept = [];
  let rejected = 0;

  for (const [key, value] of Object.entries(input)) {
    if (SAFE_KEY.test(key) && (!allowed || allowed.has(key)) && Number.isSafeInteger(value) && value >= 0) kept.push([key, Math.min(value, MAX_COUNT)]);
    else rejected++;
  }

  kept.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

  return { lines: kept.map(([k, n]) => `- ${label} ${k}: ${n}`), rejected };
}

const OS = new Set(['win32', 'darwin', 'linux']);
const ARCH = new Set(['x64', 'arm64', 'ia32', 'arm']);

// "About my setup": closed values only. An unknown os or arch becomes "other" (it is still a fact
// about the platform, not free text); anything else that does not fit is dropped and counted.
export function setupLines(info) {
  const lines = [];
  let rejected = 0;
  const has = (k) => info && info[k] !== undefined;
  const add = (key, value) => lines.push(`- ${key}: ${value}`);
  const flag = (k, key, yes, no) => {
    if (!has(k)) return;

    if (typeof info[k] === 'boolean') add(key, info[k] ? yes : no);
    else rejected++;
  };
  const list = (k, key) => {
    if (!has(k)) return;

    if (!Array.isArray(info[k])) { rejected++; return; }
    const good = info[k].filter((v) => typeof v === 'string' && SAFE_KEY.test(v));
    rejected += info[k].length - good.length;
    add(key, good.length ? good.join(', ') : 'none');
  };

  if (has('version')) {
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(String(info.version))) add('blackbrake_version', info.version);
    else rejected++;
  }

  if (has('os')) add('os', OS.has(info.os) ? info.os : 'other');

  if (has('arch')) add('arch', ARCH.has(info.arch) ? info.arch : 'other');

  if (has('nodeMajor')) {
    if (Number.isInteger(info.nodeMajor) && info.nodeMajor >= 10 && info.nodeMajor <= 99) add('node_major', info.nodeMajor);
    else rejected++;
  }

  if (has('lang')) {
    if (info.lang === 'en' || info.lang === 'es') add('lang', info.lang);
    else rejected++;
  }

  list('harnessesDetected', 'harnesses_detected');
  list('harnessesProtected', 'harnesses_protected');

  if (has('mode')) {
    if (info.mode === 'observe' || info.mode === 'protect') add('mode', info.mode);
    else rejected++;
  }

  flag('watcher', 'watcher', 'on', 'off');
  flag('window', 'window', 'on', 'off');
  flag('paused', 'paused', 'yes', 'no');

  return { lines, rejected };
}

const PROBLEM_KEYS = ['error', 'tamper', 'integrity'];

function problemLines(input) {
  const lines = [];
  let rejected = 0;

  for (const key of PROBLEM_KEYS) {
    const value = input?.[key];

    if (value === undefined) continue;

    if (Number.isSafeInteger(value) && value >= 0) lines.push(`- ${key}: ${Math.min(value, MAX_COUNT)}`);
    else rejected++;
  }

  return { lines, rejected };
}

// data: { setup, kinds, actions, byRule, byClass, problems } (counts already taken from the log and
// the last scan). selected: which boxes are ticked ({ setup, activity, secrets, problems }).
// Returns { sections: { <heading>: [lines] }, rejected }; a ticked box with no data says "none".
export function aggregateReport(data, { selected = {}, ruleIds, kindIds } = {}) {
  const sections = {};
  let rejected = 0;
  const put = (box, parts) => {
    if (!selected[box]) return;
    const lines = parts.flatMap((p) => p.lines);
    rejected += parts.reduce((sum, p) => sum + p.rejected, 0);
    sections[AUTO_SECTIONS[box]] = lines.length ? lines : ['- none'];
  };

  put('setup', [setupLines(data?.setup)]);
  put('activity', [countLines('kind', data?.kinds, { allowed: kindIds }), countLines('action', data?.actions)]);
  put('secrets', [countLines('rule', data?.byRule, { allowed: ruleIds }), countLines('class', data?.byClass, { allowed: new Set(Object.values(CLASSES)) })]);
  put('problems', [problemLines(data?.problems)]);

  return { sections, rejected };
}

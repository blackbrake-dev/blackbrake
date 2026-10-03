// Interface language. Data and --json stay in English (stable for scripts); only what a person
// reads is translated. The English text is the key: a missing translation shows English, never a
// blank. Dynamic phrases ("runs 3 hook commands") are matched by pattern.
import { ES, ES_PATTERNS } from './i18n-es.mjs';
import { isFunction } from './kinds.mjs';

export const LANGS = ['en', 'es'];

let lang = 'en';

const pick = (v) => {
  const s = String(v ?? '').toLowerCase();

  return s.startsWith('es') ? 'es' : s.startsWith('en') ? 'en' : null;
};

// Order: explicit choice (flag, BLACKBRAKE_LANG, saved setting), then the system locale.
export function detectLang({ env = process.env, saved = null } = {}) {
  let system = null;

  try { system = Intl.DateTimeFormat().resolvedOptions().locale; } catch { /* no Intl data */ }

  return pick(env.BLACKBRAKE_LANG) ?? pick(saved) ?? pick(env.LC_ALL) ?? pick(env.LC_MESSAGES) ?? pick(system) ?? pick(env.LANG) ?? 'en';
}

export const setLang = (l) => { lang = LANGS.includes(l) ? l : 'en'; };

export const getLang = () => lang;

const fill = (tpl, vars) => tpl.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));

export function t(text, vars = {}) {
  if (lang !== 'es') return fill(text, vars);

  if (text in ES) return fill(ES[text], vars);

  // A pattern's replacement may be a function that gets the captured parts and t() itself, so a
  // variable part that is also known text ("stored in prompt history") is translated too.
  for (const [re, out] of ES_PATTERNS) {
    if (re.test(text)) return fill(isFunction(out) ? text.replace(re, (...g) => out(g.slice(1, -2), t)) : text.replace(re, out), vars);
  }

  return fill(text, vars);
}

export const num = (n) => Number(n).toLocaleString(lang === 'es' ? 'es-ES' : 'en-US');

// Fixed decimals in the interface language (0.69 / 0,69).
export const dec = (n, digits) => Number(n).toLocaleString(lang === 'es' ? 'es-ES' : 'en-US', { minimumFractionDigits: digits, maximumFractionDigits: digits });

export const plural = (n, one, many = `${one}s`) => `${num(n)} ${t(n === 1 ? one : many)}`;

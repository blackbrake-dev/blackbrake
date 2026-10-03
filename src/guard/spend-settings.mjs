// The spend brakes the user can adjust (state.json settings.spend). Every value is checked against
// a short list or a range; anything missing, unknown or out of range falls back to the 0.3.0
// default, so a damaged file never switches a brake off. Loosening a brake (later or never) lowers
// protection: the CLI asks a person at a terminal for it, as for "mode observe".
import { getSetting, guardHome, setSetting } from './state.mjs';

export const PERCENTILES = [50, 75, 90, 95, 99];

export const SPEND_DEFAULTS = Object.freeze({
  cost: Object.freeze({ on: true, percentile: 90, fixed: null }),
  tokens: Object.freeze({ on: true, percentile: 90 }),
  loop: Object.freeze({ on: true, repeats: 3, minutes: 2 }),
  quota: Object.freeze({ on: true, fiveHour: 95, weekly: 98 }),
});

const isFlag = (v) => v === true || v === false;

const between = (lo, hi, { integer = true } = {}) => (v) => Number.isFinite(v) && (!integer || Number.isInteger(v)) && v >= lo && v <= hi;

// For each brake, the fields it has and what each accepts. `fixed` also accepts null (no amount).
const FIELDS = {
  cost: { on: isFlag, percentile: (v) => PERCENTILES.includes(v), fixed: (v) => v === null || between(0.5, 1000, { integer: false })(v) },
  tokens: { on: isFlag, percentile: (v) => PERCENTILES.includes(v) },
  loop: { on: isFlag, repeats: between(2, 10), minutes: between(1, 30) },
  quota: { on: isFlag, fiveHour: between(50, 100), weekly: between(50, 100) },
};

export const BRAKES = Object.keys(FIELDS);

export function normalizeSpendSettings(saved) {
  const out = {};

  for (const brake of BRAKES) {
    const given = saved && Object.hasOwn(saved, brake) ? saved[brake] : null;
    out[brake] = {};

    for (const [field, valid] of Object.entries(FIELDS[brake])) {
      const value = given && Object.hasOwn(given, field) ? given[field] : undefined;
      out[brake][field] = valid(value) ? value : SPEND_DEFAULTS[brake][field];
    }
  }

  return out;
}

export const getSpendSettings = (home = guardHome()) => normalizeSpendSettings(getSetting('spend', null, home));

export const setSpendSettings = (settings, home = guardHome()) => setSetting('spend', normalizeSpendSettings(settings), home);

// ["cost.percentile", "95"], ["loop", "off"], ["cost.fixed", "off"] → { path, value }, or null.
export function parseBrakeChange(words) {
  if (!Array.isArray(words) || words.length !== 2) return null;
  const [key, raw] = words.map((w) => String(w).trim().toLowerCase());
  const [brake, rawField] = key.split('.');
  const field = rawField ?? 'on';

  if (!Object.hasOwn(FIELDS, brake)) return null;
  const fields = FIELDS[brake];
  const name = Object.keys(fields).find((f) => f.toLowerCase() === field);

  if (!name) return null;
  let value;

  if (raw === 'on' || raw === 'off') value = name === 'on' ? raw === 'on' : name === 'fixed' && raw === 'off' ? null : undefined;
  else if (/^\d+(\.\d+)?$/.test(raw)) value = Number(raw);

  if (value === undefined || !fields[name](value)) return null;

  return { path: [brake, name], value };
}

export function applyBrakeChange(settings, change) {
  const next = normalizeSpendSettings(settings);
  next[change.path[0]] = { ...next[change.path[0]], [change.path[1]]: change.value };

  return normalizeSpendSettings(next);
}

// True when `next` makes any brake fire later than `prev`, or never. Comparisons that do not have
// an order (a percentile against a fixed amount) count as loosening.
export function loosens(prev, next) {
  const a = normalizeSpendSettings(prev);
  const b = normalizeSpendSettings(next);

  for (const brake of BRAKES) if (a[brake].on && !b[brake].on) return true;

  if (b.cost.on) {
    if ((a.cost.fixed === null) !== (b.cost.fixed === null)) return true;

    if (b.cost.fixed !== null && b.cost.fixed > a.cost.fixed) return true;

    if (b.cost.fixed === null && b.cost.percentile > a.cost.percentile) return true;
  }

  if (b.tokens.on && b.tokens.percentile > a.tokens.percentile) return true;

  if (b.loop.on && (b.loop.repeats > a.loop.repeats || b.loop.minutes < a.loop.minutes)) return true;

  return b.quota.on && (b.quota.fiveHour > a.quota.fiveHour || b.quota.weekly > a.quota.weekly);
}

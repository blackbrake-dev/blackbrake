// API list prices in USD per million tokens, from Anthropic's pricing page
// (https://docs.anthropic.com/en/docs/about-claude/pricing), checked on the date below.
// Cache writes are multiples of the input price: 1.25x for the 5-minute cache, 2x for the 1-hour
// cache. Cache reads are listed per model (0.1x, or 0.025x on Fable/Mythos 5.1).
// Models 4.6 and later have no long-context surcharge. For subscription plans this is a common
// unit of effort, not a bill.
export const PRICES_DATE = '2026-09-26';

const TABLE = [
  [/fable-5-1|mythos-5-1/i, { in: 10, cr: 0.25, out: 50 }],
  [/fable-5|mythos-5/i, { in: 10, cr: 1, out: 50 }],
  [/opus-4-1|opus-4-2025|opus-4-0|claude-opus-4$/i, { in: 15, cr: 1.5, out: 75 }],
  [/opus/i, { in: 5, cr: 0.5, out: 25 }], // Opus 4.5 and later
  [/sonnet-5/i, { in: 2, cr: 0.2, out: 10 }],
  [/sonnet/i, { in: 3, cr: 0.3, out: 15 }],
  [/haiku-3/i, { in: 0.8, cr: 0.08, out: 4 }],
  [/haiku/i, { in: 1, cr: 0.1, out: 5 }],
];

// Fast mode (research preview): premium price across the whole request.
const FAST = [[/opus-5(?!-\d)|opus-4-8/i, { in: 10, cr: 1, out: 50 }]];

const FALLBACK = { in: 3, cr: 0.3, out: 15 };

export function priceFor(model = '', { fast = false } = {}) {
  const hit = (fast && FAST.find(([re]) => re.test(model))) || TABLE.find(([re]) => re.test(model));
  const p = hit ? hit[1] : FALLBACK;

  return { ...p, cw: p.in * 1.25, cw1h: p.in * 2, known: Boolean(hit) };
}

// Transcript lines are untrusted (F6.12 D2): a forged line with negative, fractional, non-finite,
// string or absurd token counts could lower an episode's cost below the alert threshold or poison
// the p90. A token field is either absent (undefined = 0) or an integer 0..1e9; a record with
// any other value is invalid as a whole and is worth nothing (callers discard it).
const MAX_TOKENS = 1e9;

const USAGE_FIELDS = ['input_tokens', 'output_tokens', 'cache_creation_input_tokens', 'cache_read_input_tokens'];

const SPLIT_FIELDS = ['ephemeral_1h_input_tokens', 'ephemeral_5m_input_tokens'];

const isRecord = (value) => value !== null && !Array.isArray(value) && Object.prototype.toString.call(value) === '[object Object]';

const validCount = (value) => value === undefined || (Number.isInteger(value) && value >= 0 && value <= MAX_TOKENS);

export function validUsage(u) {
  if (!isRecord(u) || !USAGE_FIELDS.every((field) => validCount(u[field]))) return false;
  const split = u.cache_creation;

  return split === undefined || split === null || (isRecord(split) && SPLIT_FIELDS.every((field) => validCount(split[field])));
}

export function usageCost(u, model) {
  if (!validUsage(u)) return 0;
  const p = priceFor(model, { fast: u.speed === 'fast' });
  const total = u.cache_creation_input_tokens || 0;
  const split = u.cache_creation;
  const oneHour = split ? Math.min(total, split.ephemeral_1h_input_tokens || 0) : 0;

  return ((u.input_tokens || 0) * p.in + (u.output_tokens || 0) * p.out
    + (total - oneHour) * p.cw + oneHour * p.cw1h + (u.cache_read_input_tokens || 0) * p.cr) / 1e6;
}

// Size of a usage record: streaming snapshots of one response only grow, so the largest is final.
export const usageSize = (u) => (validUsage(u)
  ? (u.input_tokens || 0) + (u.output_tokens || 0) + (u.cache_creation_input_tokens || 0) + (u.cache_read_input_tokens || 0)
  : 0);

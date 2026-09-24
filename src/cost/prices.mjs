// API list prices in USD per million tokens, from Anthropic's pricing page
// (https://docs.anthropic.com/en/docs/about-claude/pricing), checked on the date below.
// cw = 5-minute cache write. For subscription plans this is a common unit of effort, not a bill.
export const PRICES_DATE = '2026-09-23';

const TABLE = [
  [/fable-5-1|mythos-5-1/i, { in: 10, cw: 12.5, cr: 0.25, out: 50 }],
  [/fable-5|mythos-5/i, { in: 10, cw: 12.5, cr: 1, out: 50 }],
  [/opus-4-1|opus-4-2025|opus-4-0|claude-opus-4$/i, { in: 15, cw: 18.75, cr: 1.5, out: 75 }],
  [/opus/i, { in: 5, cw: 6.25, cr: 0.5, out: 25 }], // Opus 4.5 and later
  [/sonnet-5/i, { in: 2, cw: 2.5, cr: 0.2, out: 10 }],
  [/sonnet/i, { in: 3, cw: 3.75, cr: 0.3, out: 15 }],
  [/haiku-3/i, { in: 0.8, cw: 1, cr: 0.08, out: 4 }],
  [/haiku/i, { in: 1, cw: 1.25, cr: 0.1, out: 5 }],
];

export function priceFor(model = '') {
  const hit = TABLE.find(([re]) => re.test(model));
  return hit ? { ...hit[1], known: true } : { in: 3, cw: 3.75, cr: 0.3, out: 15, known: false };
}

export function usageCost(u, model) {
  const p = priceFor(model);
  return ((u.input_tokens || 0) * p.in + (u.output_tokens || 0) * p.out
    + (u.cache_creation_input_tokens || 0) * p.cw + (u.cache_read_input_tokens || 0) * p.cr) / 1e6;
}

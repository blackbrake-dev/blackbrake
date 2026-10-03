// Local, descriptive spend brakes. Costs are list-price equivalents, never savings claims.
import { t } from '../i18n.mjs';
import { PERCENTILES, SPEND_DEFAULTS } from './spend-settings.mjs';

export const MIN_BASELINE_EPISODES = 30;

const finite = (value) => Number.isFinite(value) && value >= 0;

const quantile = (values, p) => {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);

  return sorted[Math.max(0, Math.ceil(p * sorted.length) - 1)];
};

export function baselineFromEpisodes(episodes, harness, minimum = MIN_BASELINE_EPISODES) {
  const costs = episodes.filter((episode) => !episode.harness || episode.harness === harness).map((episode) => episode.cost).filter(finite);

  return {
    harness,
    n: costs.length,
    p50: quantile(costs, 0.5),
    p90: quantile(costs, 0.9),
    q: Object.fromEntries(PERCENTILES.map((p) => [p, quantile(costs, p / 100)])),
    ready: costs.length >= minimum,
  };
}

// The value at the chosen percentile; a baseline saved before 0.3.0 only has p50 and p90, and uses
// its p90 for anything else.
export function thresholdFor(baseline, percentile = 90) {
  const value = baseline?.q?.[percentile];

  if (finite(value)) return value;

  return percentile === 50 && finite(baseline?.p50) ? baseline.p50 : baseline?.p90 ?? 0;
}

export function applyEpisodeEvent(previous = {}, update) {
  const state = { completed: [...(previous.completed ?? [])], open: previous.open ? { ...previous.open } : null };

  if (update.event === 'UserPromptSubmit' && update.realPrompt) {
    if (state.open) state.completed.push({ ...state.open, end: update.at });
    state.open = { start: update.at, cost: 0, responses: 0, label: null, costAlerted: false };
  } else if (update.event === 'AssistantUsage' && state.open) {
    state.open.cost += finite(update.costDelta) ? update.costDelta : 0;

    if (update.response) state.open.responses++;
  }

  return state;
}

export function labelEpisode(previous, label) {
  if (!['valid', 'invalid', 'unrated'].includes(label) || !previous.open) return previous;

  return { ...previous, open: { ...previous.open, label } };
}

export function spendAlert({ baseline, episode, mode = 'observe', canAsk = false, settings = SPEND_DEFAULTS }) {
  const brake = settings?.cost ?? SPEND_DEFAULTS.cost;

  if (!brake.on || !episode || episode.costAlerted || !finite(episode.cost)) return null;
  const fixed = brake.fixed !== null && finite(brake.fixed);

  if (!fixed && !baseline?.ready) return null;
  const limit = fixed ? brake.fixed : thresholdFor(baseline, brake.percentile);

  if (episode.cost <= limit) return null;

  episode.costAlerted = true;

  const base = fixed
    ? t('blackbrake: this episode is at API≈${cost} across {responses} responses; above the limit you set, API≈${limit} (list prices).', { cost: episode.cost.toFixed(2), responses: episode.responses ?? 0, limit: limit.toFixed(2) })
    : brake.percentile === 90
      ? t('blackbrake: this episode is at API≈${cost} across {responses} responses; above your local p90 API≈${p90} for this agent (median API≈${median}; {episodes} episodes, list prices).', {
        cost: episode.cost.toFixed(2), responses: episode.responses ?? 0, p90: limit.toFixed(2), median: baseline.p50.toFixed(2), episodes: baseline.n,
      })
      : t('blackbrake: this episode is at API≈${cost} across {responses} responses; above your local p{pct} API≈${limit} for this agent (median API≈${median}; {episodes} episodes, list prices).', {
        cost: episode.cost.toFixed(2), responses: episode.responses ?? 0, pct: brake.percentile, limit: limit.toFixed(2), median: baseline.p50.toFixed(2), episodes: baseline.n,
      });

  const message = `${base} ${t(mode === 'protect' && canAsk ? 'Continue?' : 'Warning: review whether to continue.')}`;

  return { action: mode === 'protect' && canAsk ? 'ask' : 'warn', message };
}

// The token brake (Codex, Devin): over the chosen percentile of this agent's own episodes.
export const overTokenLimit = (baseline, tokens, settings = SPEND_DEFAULTS) => Boolean(settings?.tokens?.on && baseline?.ready && tokens > thresholdFor(baseline, settings.tokens.percentile));

export const spendTextTokens = (text) => Math.ceil(String(text).length / 4);

export const withinTokenBudget = (text, observedTokens) => spendTextTokens(text) < Number(observedTokens ?? 0) * 0.01;

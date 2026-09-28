// Local, descriptive spend brakes. Costs are list-price equivalents, never savings claims.

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
    ready: costs.length >= minimum,
  };
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

export function spendAlert({ baseline, episode, mode = 'observe', canAsk = false }) {
  if (!baseline?.ready || !episode || episode.costAlerted || !finite(episode.cost) || episode.cost <= baseline.p90) return null;
  episode.costAlerted = true;
  const message = `blackbrake: this episode is at API≈$${episode.cost.toFixed(2)} across ${episode.responses ?? 0} responses; above your local p90 API≈$${baseline.p90.toFixed(2)} for this agent (median API≈$${baseline.p50.toFixed(2)}; ${baseline.n} episodes, list prices).${mode === 'protect' && canAsk ? ' Continue?' : ' Warning: review whether to continue.'}`;

  return { action: mode === 'protect' && canAsk ? 'ask' : 'warn', message };
}

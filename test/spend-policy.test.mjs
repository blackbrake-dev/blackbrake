import assert from 'node:assert/strict';
import test from 'node:test';
import { baselineFromEpisodes, spendAlert } from '../src/guard/spend.mjs';

const episodes = (n) => Array.from({ length: n }, (_, i) => ({ cost: i + 1, responses: i % 4 + 1 }));

test('baseline-from-existing-history-without-declarations', () => {
  const baseline = baselineFromEpisodes(episodes(30), 'claude');

  assert.equal(baseline.n, 30);
  assert.equal(baseline.p50, 15);
  assert.equal(baseline.p90, 27);
  assert.equal(baseline.ready, true);
});

test('alert-uses-overall-personal-p90', () => {
  const baseline = baselineFromEpisodes(episodes(30), 'claude');
  const decision = spendAlert({ baseline, episode: { cost: 28, responses: 180 }, mode: 'observe' });

  assert.equal(decision.action, 'warn');
  assert.match(decision.message, /28\.00/);
  assert.match(decision.message, /180/);
  assert.match(decision.message, /27\.00/);
  assert.match(decision.message, /15\.00/);
});

test('insufficient-history-no-alert', () => {
  const baseline = baselineFromEpisodes(episodes(29), 'claude');

  assert.equal(baseline.ready, false);
  assert.equal(spendAlert({ baseline, episode: { cost: 100, responses: 1 }, mode: 'protect' }), null);
});

test('length-buckets-are-status-only', () => {
  const baseline = baselineFromEpisodes(episodes(30), 'claude');

  assert.equal(spendAlert({ baseline, episode: { cost: 28, responses: 1 }, mode: 'observe' }).action, 'warn');
  assert.equal(spendAlert({ baseline, episode: { cost: 28, responses: 180 }, mode: 'observe' }).action, 'warn');
});

test('baseline-alerts-once-on-upward-crossing', () => {
  const baseline = baselineFromEpisodes(episodes(30), 'claude');
  const episode = { cost: 28, responses: 3 };
  const first = spendAlert({ baseline, episode, mode: 'protect', canAsk: true });

  assert.equal(first.action, 'ask');
  assert.equal(episode.costAlerted, true);
  assert.equal(spendAlert({ baseline, episode, mode: 'protect', canAsk: true }), null);
});

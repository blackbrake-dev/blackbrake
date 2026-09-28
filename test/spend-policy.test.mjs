import assert from 'node:assert/strict';
import test from 'node:test';
import { createLoopDetector } from '../src/guard/loops.mjs';
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

test('loop-hash-is-canonical-and-private', () => {
  const detector = createLoopDetector({ secret: Buffer.alloc(32, 7) });
  const first = detector.record('Read', { path: 'café', options: { b: 2, a: 1 } }, 0);
  const second = detector.record('Read', { options: { a: 1, b: 2 }, path: 'café' }, 1);
  const different = detector.record('Read', { options: { a: '1', b: 2 }, path: 'café' }, 2);
  const snapshot = JSON.stringify(detector.snapshot());

  assert.equal(first.fingerprint, second.fingerprint);
  assert.notEqual(first.fingerprint, different.fingerprint);
  assert.equal(snapshot.includes('café'), false);
  assert.equal(snapshot.includes('options'), false);
});

test('loop-triggers-third-in-eight-within-120s', () => {
  const detector = createLoopDetector({ secret: Buffer.alloc(32, 8) });

  assert.equal(detector.record('Bash', { command: 'fixture' }, 0).alert, false);
  assert.equal(detector.record('Bash', { command: 'fixture' }, 60_000).alert, false);
  assert.equal(detector.record('Bash', { command: 'fixture' }, 120_000).alert, true);
  assert.equal(detector.record('Bash', { command: 'fixture' }, 120_001).alert, false);

  const expired = createLoopDetector({ secret: Buffer.alloc(32, 9) });
  expired.record('Read', { path: 'fixture' }, 0);
  expired.record('Read', { path: 'fixture' }, 1);
  assert.equal(expired.record('Read', { path: 'fixture' }, 120_001).alert, false);
});

test('loop-never-silently-denies', () => {
  const baseline = { ready: true, p50: 1, p90: 2, n: 30 };
  const noAsk = spendAlert({ baseline, episode: { cost: 3 }, mode: 'protect', canAsk: false });

  assert.equal(noAsk.action, 'warn');
  assert.notEqual(noAsk.action, 'deny');
});

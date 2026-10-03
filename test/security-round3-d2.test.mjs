// D2 (F6.12 round 2): a forged transcript line with invalid token counts must not lower the
// episode cost (silencing the spend alert) nor poison the local p90. Pure in-memory tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { usageCost, usageSize, validUsage } from '../src/cost/prices.mjs';
import { createCostAnalyzer, createUsageLedger } from '../src/cost/analyzer.mjs';
import { accountTranscriptRecords } from '../src/cost/live.mjs';

const MODEL = 'claude-sonnet-4-5';

const SECRET = 'd2-test-secret';

const assistant = (id, usage, model = MODEL) => ({ type: 'assistant', message: { id, role: 'assistant', model, usage } });

const good = { input_tokens: 1000, output_tokens: 200_000, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 };

const goodCost = usageCost(good, MODEL);

const forged = [
  ['negative tokens', { input_tokens: 0, output_tokens: -200_000 }],
  ['negative cache read', { cache_read_input_tokens: -1e9 }],
  ['string tokens', { output_tokens: '-200000' }],
  ['float tokens', { output_tokens: -1.5e5 + 0.5 }],
  ['positive float', { output_tokens: 10.5 }],
  ['NaN', { output_tokens: Number.NaN }],
  ['Infinity', { output_tokens: Number.POSITIVE_INFINITY }],
  ['-Infinity', { input_tokens: Number.NEGATIVE_INFINITY }],
  ['above 1e9', { output_tokens: 1e12 }],
  ['negative 1h cache split', { cache_creation_input_tokens: 0, cache_creation: { ephemeral_1h_input_tokens: -1e9 } }],
  ['string 1h cache split', { cache_creation_input_tokens: 10, cache_creation: { ephemeral_1h_input_tokens: '5' } }],
  ['cache split not an object', { cache_creation_input_tokens: 10, cache_creation: 'x' }],
  ['boolean tokens', { output_tokens: true }],
  ['null tokens', { output_tokens: null }],
  ['null cache split tokens', { cache_creation: { ephemeral_5m_input_tokens: null } }],
];

test('D2: validUsage accepts only finite integers 0..1e9 per token field', () => {
  assert.equal(validUsage(good), true);
  assert.equal(validUsage({}), true, 'absent fields count as zero');
  assert.equal(validUsage({ output_tokens: 1e9 }), true);
  assert.equal(validUsage({ cache_creation_input_tokens: 10, cache_creation: { ephemeral_1h_input_tokens: 4, ephemeral_5m_input_tokens: 6 } }), true);
  assert.equal(validUsage(null), false);
  assert.equal(validUsage('usage'), false);
  assert.equal(validUsage([]), false);

  for (const [name, usage] of forged) assert.equal(validUsage(usage), false, name);
});

test('D2: usageCost and usageSize never return negative or non-finite values', () => {
  for (const [name, usage] of forged) {
    const cost = usageCost(usage, MODEL);
    const size = usageSize(usage);

    assert.ok(Number.isFinite(cost) && cost >= 0, `${name}: cost ${cost}`);
    assert.ok(Number.isFinite(size) && size >= 0, `${name}: size ${size}`);
    assert.equal(cost, 0, `${name}: an invalid record costs nothing`);
    assert.equal(size, 0, `${name}: an invalid record has no size`);
  }
});

test('D2: reviewer case — negative tokens cannot pull the live episode cost below the threshold', () => {
  for (const [name, usage] of forged) {
    const result = accountTranscriptRecords([assistant('msg_real', good), assistant('msg_forged', usage)], {}, SECRET);

    assert.equal(result.costDelta, goodCost, `${name}: cost`);
    assert.equal(result.tokensDelta, usageSize(good), `${name}: tokens`);
    assert.equal(result.responseDelta, 1, `${name}: the forged record is discarded, not counted`);
  }
});

test('D2: a forged later snapshot of the same response cannot reduce its cost (delta >= 0)', () => {
  // Bigger size, but cheaper: switched to a cheaper model with input tokens instead of output.
  const cheaper = { input_tokens: 300_000, output_tokens: 0 };
  const ledger = createUsageLedger();
  const first = ledger.account({}, { id: 'r1', model: MODEL, usage: good });
  const second = ledger.account({}, { id: 'r1', model: 'claude-haiku-4-5', usage: cheaper });

  assert.equal(first.delta, goodCost);
  assert.ok(second.delta >= 0, `delta ${second.delta}`);
  assert.ok(second.sizeDelta >= 0);

  const forgedSnapshot = ledger.account({}, { id: 'r1', model: MODEL, usage: { output_tokens: -1e9 } });

  assert.equal(forgedSnapshot.delta, 0);
  assert.equal(forgedSnapshot.sizeDelta, 0);
});

test('D2: poisoned persisted ledger entries are not trusted', () => {
  const result = accountTranscriptRecords([assistant('msg_real', good)], {
    responses: [
      { key: 'k', size: -5, cost: Number.NaN }, { key: 'j', size: 'x', cost: -1 },
      { key: 'fraction', size: 0.5, cost: 1 }, { key: 'huge', size: 4e9 + 1, cost: 1 },
    ],
  }, SECRET);

  assert.equal(result.costDelta, goodCost);
  assert.equal(result.responses.length, 1);

  for (const entry of result.responses) {
    assert.ok(Number.isFinite(entry.size) && entry.size >= 0);
    assert.ok(Number.isFinite(entry.cost) && entry.cost >= 0);
  }
});

test('D2: forged records do not lower historical episode costs (p90 baseline)', () => {
  const analyzer = createCostAnalyzer();

  analyzer.onFile({ session: 's1', project: 'p', isSubagent: false });
  analyzer.onRecord({ timestamp: '2026-10-01T00:00:00Z', message: { role: 'user', content: 'do the thing' } });
  analyzer.onRecord(assistant('a1', good));

  for (const [i, [, usage]] of forged.entries()) analyzer.onRecord(assistant(`f${i}`, usage));

  analyzer.onFile({ session: 's1', project: 'p', isSubagent: true });
  analyzer.onRecord({ timestamp: '2026-10-01T00:00:01Z', ...assistant('sub-forged', { output_tokens: -1e9 }) });

  const result = analyzer.finish();

  assert.equal(result.episodes, 1);
  assert.equal(result.episodeCosts[0].cost, goodCost);
  assert.equal(result.episodeCosts[0].responses, 1);
  assert.equal(result.total, goodCost);
});

test('D2: invalid usage cannot change historical tools, dates or unknown models', () => {
  const analyzer = createCostAnalyzer();

  analyzer.onFile({ session: 's1', project: 'p', isSubagent: false });
  analyzer.onRecord({ timestamp: '2026-10-01T00:00:00Z', message: { role: 'user', content: 'work' } });
  analyzer.onRecord({ timestamp: '2026-10-01T00:00:01Z', ...assistant('valid', good) });
  const invalid = assistant('forged', { output_tokens: -1 }, 'forged-model');

  invalid.message.content = [{ type: 'tool_use', id: 'fake-tool' }];
  analyzer.onRecord({ timestamp: '2030-01-01T00:00:00Z', ...invalid });
  const result = analyzer.finish();

  assert.deepEqual(result.unknownModels, []);
  assert.equal(result.worst[0].tools, 0);
  assert.equal(result.worst[0].hours, 1 / 3600);
});

test('D2: valid cache splits keep the one-hour premium and persisted maximum cost', () => {
  const usage = { cache_creation_input_tokens: 100, cache_creation: { ephemeral_1h_input_tokens: 40, ephemeral_5m_input_tokens: 60 } };

  assert.equal(usageSize(usage), 100);
  assert.equal(usageCost(usage, MODEL), (40 * 6 + 60 * 3.75) / 1e6);
  const first = accountTranscriptRecords([assistant('persisted', good)], {}, SECRET);
  const restored = accountTranscriptRecords([assistant('persisted', { input_tokens: 300_000 }, 'claude-haiku-4-5')], first, SECRET);
  const replay = accountTranscriptRecords([assistant('persisted', good)], restored, SECRET);

  assert.equal(restored.costDelta, 0);
  assert.equal(restored.responses[0].cost, goodCost);
  assert.equal(replay.costDelta, 0);
  assert.equal(replay.responseDelta, 0);
});

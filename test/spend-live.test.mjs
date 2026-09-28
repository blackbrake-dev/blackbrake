import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createUsageLedger, isUserPromptMessage } from '../src/cost/analyzer.mjs';
import { summarizeHistory, tailTranscript } from '../src/cost/live.mjs';
import { usageCost } from '../src/cost/prices.mjs';
import { applyEpisodeEvent, baselineFromEpisodes, labelEpisode } from '../src/guard/spend.mjs';

const assistant = (id, output = 100) => ({
  id,
  role: 'assistant',
  model: 'claude-sonnet-5',
  content: [{ type: 'text', text: 'fixture output' }],
  usage: { input_tokens: 1000, output_tokens: output, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 },
});

test('harness-injected-prompts-do-not-split-episodes', () => {
  assert.equal(isUserPromptMessage({ role: 'user', content: 'implement the change' }), true);
  assert.equal(isUserPromptMessage({ role: 'user', content: '[Subagent hand-back] done' }), false);
  assert.equal(isUserPromptMessage({ role: 'user', content: 'Base directory for this skill: C:/tmp' }), false);
  assert.equal(isUserPromptMessage({ role: 'user', content: [{ type: 'tool_result', content: 'done' }] }), false);
});

test('live-cost-counts-each-response-once', () => {
  const ledger = createUsageLedger();
  const first = assistant('response-1', 100);
  const duplicate = { ...first, content: [{ type: 'text', text: 'another streamed block' }] };
  const final = assistant('response-1', 600);

  assert.deepEqual(ledger.account({ requestId: 'request-1' }, first), {
    first: true,
    delta: usageCost(first.usage, first.model),
    size: 1100,
  });
  assert.deepEqual(ledger.account({ requestId: 'request-1' }, duplicate), { first: false, delta: 0, size: 1100 });
  const corrected = ledger.account({ requestId: 'request-1' }, final);

  assert.equal(corrected.first, false);
  assert.equal(corrected.size, 1600);
  assert.equal(corrected.delta, usageCost(final.usage, final.model) - usageCost(first.usage, first.model));
});

test('episode-ends-at-next-user-prompt', () => {
  let state = {};

  state = applyEpisodeEvent(state, { event: 'UserPromptSubmit', realPrompt: true, at: 1 });
  state = applyEpisodeEvent(state, { event: 'Stop', at: 2 });
  state = applyEpisodeEvent(state, { event: 'SessionEnd', at: 3 });
  assert.equal(state.completed.length, 0);
  state = applyEpisodeEvent(state, { event: 'UserPromptSubmit', realPrompt: true, at: 4 });
  assert.equal(state.completed.length, 1);
  assert.equal(state.completed[0].end, 4);
  assert.equal(state.open.start, 4);
});

test('declaration-is-optional-label', () => {
  let state = applyEpisodeEvent({}, { event: 'UserPromptSubmit', realPrompt: true, at: 1 });

  state = applyEpisodeEvent(state, { event: 'AssistantUsage', costDelta: 1, at: 2 });
  const baseline = baselineFromEpisodes(Array.from({ length: 30 }, (_, i) => ({ cost: i + 1 })), 'claude');
  const before = { ...baseline };
  state = labelEpisode(state, 'valid');
  assert.equal(state.open.label, 'valid');
  assert.equal(state.completed.length, 0);
  assert.deepEqual(baseline, before);
});

test('tail-keeps-partial-line-and-survives-truncate', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-tail-'));
  const file = path.join(root, 'session.jsonl');

  fs.writeFileSync(file, '{"a":"caf');
  const first = tailTranscript(file, { roots: [root] });
  assert.deepEqual(first.records, []);
  assert.equal(first.state.offset, 0);
  fs.appendFileSync(file, 'é"}\n{"b":2}\npartial');
  const second = tailTranscript(file, { roots: [root], state: first.state });
  assert.deepEqual(second.records, [{ a: 'café' }, { b: 2 }]);
  assert.equal(second.state.offset, Buffer.byteLength('{"a":"café"}\n{"b":2}\n'));
  fs.writeFileSync(file, '{"c":3}\n');
  const third = tailTranscript(file, { roots: [root], state: second.state });
  assert.deepEqual(third.records, [{ c: 3 }]);
});

test('tail-rejects-untrusted-transcript-path', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-root-'));
  const outside = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-outside-')), 'session.jsonl');

  fs.writeFileSync(outside, '{}\n');
  assert.throws(() => tailTranscript('relative.jsonl', { roots: [root] }), /Untrusted/);
  assert.throws(() => tailTranscript(outside, { roots: [root] }), /Untrusted/);
});

test('baseline-from-existing-history-without-declarations', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-history-'));
  const file = path.join(root, 'session.jsonl');
  const rows = [];

  for (let i = 0; i < 30; i++) {
    rows.push({ timestamp: new Date(i * 1000).toISOString(), message: { role: 'user', content: `fixture ${i}` } });
    rows.push({ requestId: `req-${i}`, timestamp: new Date(i * 1000 + 1).toISOString(), message: assistant(`answer-${i}`, i + 1) });
    rows.push({ requestId: `req-${i}`, timestamp: new Date(i * 1000 + 2).toISOString(), message: assistant(`answer-${i}`, i + 1) });
  }
  fs.writeFileSync(file, `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`);
  const summary = await summarizeHistory({ root, harness: 'claude' });

  assert.equal(summary.episodes, 30);
  assert.equal(summary.baseline.ready, true);
  assert.equal(summary.baseline.n, 30);
  assert.equal(Object.hasOwn(summary, 'prompts'), false);
});

test('live-cost-prices-one-hour-cache-at-2x', () => {
  const hour = usageCost({ input_tokens: 0, output_tokens: 0, cache_creation_input_tokens: 1000, cache_read_input_tokens: 1000 }, 'claude-sonnet-5');
  const plain = usageCost({ input_tokens: 2000, output_tokens: 0, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 }, 'claude-sonnet-5');

  assert.ok(hour > 0);
  assert.notEqual(hour, plain);
});

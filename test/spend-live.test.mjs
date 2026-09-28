import assert from 'node:assert/strict';
import test from 'node:test';
import { createUsageLedger, isUserPromptMessage } from '../src/cost/analyzer.mjs';
import { usageCost } from '../src/cost/prices.mjs';

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

// Spend brakes the user can adjust: validated values, defaults when anything is off, and which
// changes loosen a brake (those lower protection and need a person at a terminal).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { applyBrakeChange, getSpendSettings, loosens, parseBrakeChange, SPEND_DEFAULTS } from '../src/guard/spend-settings.mjs';
import { baselineFromEpisodes, spendAlert, thresholdFor } from '../src/guard/spend.mjs';
import { createLoopDetector } from '../src/guard/loops.mjs';
import { setSetting } from '../src/guard/state.mjs';
import { applyBrakes, runBrakes } from '../src/cli/features/brakes.mjs';
import { createPainter } from '../src/ui/term.mjs';
import { decide } from '../src/guard/policy.mjs';
import { loadRules } from '../src/secrets/engine.mjs';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bb-brakes-'));

test('with nothing saved the brakes are the 0.3.0 defaults', () => {
  assert.deepEqual(getSpendSettings(tmp()), SPEND_DEFAULTS);
  assert.equal(SPEND_DEFAULTS.cost.percentile, 90);
  assert.equal(SPEND_DEFAULTS.loop.repeats, 3);
  assert.equal(SPEND_DEFAULTS.loop.minutes, 2);
  assert.equal(SPEND_DEFAULTS.quota.fiveHour, 95);
  assert.equal(SPEND_DEFAULTS.quota.weekly, 98);
});

test('saved values outside their range, of the wrong type or unknown fall back to the default', () => {
  const home = tmp();
  setSetting('spend', { cost: { on: 'no', percentile: 42, fixed: -3 }, loop: { repeats: 1, minutes: 999 }, quota: { fiveHour: 120, weekly: '50' }, extra: { on: false } }, home);
  assert.deepEqual(getSpendSettings(home), SPEND_DEFAULTS);
  setSetting('spend', 'not an object', home);
  assert.deepEqual(getSpendSettings(home), SPEND_DEFAULTS);
});

test('valid saved values are kept', () => {
  const home = tmp();
  setSetting('spend', { cost: { on: true, percentile: 95, fixed: 12.5 }, tokens: { on: false, percentile: 75 }, loop: { on: true, repeats: 5, minutes: 10 }, quota: { on: true, fiveHour: 80, weekly: 90 } }, home);
  const s = getSpendSettings(home);
  assert.equal(s.cost.percentile, 95);
  assert.equal(s.cost.fixed, 12.5);
  assert.equal(s.tokens.on, false);
  assert.equal(s.loop.repeats, 5);
  assert.equal(s.quota.fiveHour, 80);
});

test('changes are parsed from plain words, and anything else is refused', () => {
  assert.deepEqual(parseBrakeChange(['cost.percentile', '95']), { path: ['cost', 'percentile'], value: 95 });
  assert.deepEqual(parseBrakeChange(['loop', 'off']), { path: ['loop', 'on'], value: false });
  assert.deepEqual(parseBrakeChange(['loop', 'on']), { path: ['loop', 'on'], value: true });
  assert.deepEqual(parseBrakeChange(['cost.fixed', 'off']), { path: ['cost', 'fixed'], value: null });
  assert.deepEqual(parseBrakeChange(['cost.fixed', '7.5']), { path: ['cost', 'fixed'], value: 7.5 });
  assert.equal(parseBrakeChange(['cost.percentile', '42']), null, 'not an offered percentile');
  assert.equal(parseBrakeChange(['loop.repeats', '1']), null, 'below the range');
  assert.equal(parseBrakeChange(['quota.fiveHour', '101']), null);
  assert.equal(parseBrakeChange(['__proto__.on', 'off']), null);
  assert.equal(parseBrakeChange(['cost.on', 'maybe']), null);
  assert.equal(parseBrakeChange(['cost']), null);
});

test('loosening is anything that makes a brake fire later or never', () => {
  const d = SPEND_DEFAULTS;
  const change = (words) => applyBrakeChange(d, parseBrakeChange(words));
  assert.equal(loosens(d, change(['cost', 'off'])), true);
  assert.equal(loosens(d, change(['cost.percentile', '95'])), true);
  assert.equal(loosens(d, change(['cost.percentile', '75'])), false, 'a lower percentile fires sooner');
  assert.equal(loosens(d, change(['cost.fixed', '5'])), true, 'switching to a fixed amount cannot be compared: treated as loosening');
  assert.equal(loosens(change(['cost.fixed', '5']), applyBrakeChange(change(['cost.fixed', '5']), parseBrakeChange(['cost.fixed', '3']))), false, 'a lower amount fires sooner');
  assert.equal(loosens(d, change(['loop.repeats', '5'])), true);
  assert.equal(loosens(d, change(['loop.repeats', '2'])), false);
  assert.equal(loosens(d, change(['loop.minutes', '1'])), true, 'a shorter window catches fewer loops');
  assert.equal(loosens(d, change(['loop.minutes', '10'])), false);
  assert.equal(loosens(d, change(['quota.weekly', '99'])), true);
  assert.equal(loosens(d, change(['quota.fiveHour', '80'])), false);
  assert.equal(loosens(change(['tokens', 'off']), d), false, 'turning a brake back on tightens');
});

test('the cost brake uses the chosen percentile, a fixed amount, or nothing when off', () => {
  const costs = Array.from({ length: 100 }, (_, i) => ({ cost: i + 1 }));
  const baseline = baselineFromEpisodes(costs, 'claude');
  assert.equal(thresholdFor(baseline, 90), 90);
  assert.equal(thresholdFor(baseline, 99), 99);
  assert.equal(thresholdFor({ ...baseline, q: undefined }, 95), baseline.p90, 'an old baseline without percentiles uses its p90');
  const episode = () => ({ cost: 92, responses: 4 });
  assert.ok(spendAlert({ baseline, episode: episode(), settings: SPEND_DEFAULTS }), 'above p90');
  assert.equal(spendAlert({ baseline, episode: episode(), settings: { ...SPEND_DEFAULTS, cost: { on: true, percentile: 95, fixed: null } } }), null, 'below p95');
  assert.equal(spendAlert({ baseline, episode: episode(), settings: { ...SPEND_DEFAULTS, cost: { on: false, percentile: 90, fixed: null } } }), null, 'off');
  const fixed = { ...SPEND_DEFAULTS, cost: { on: true, percentile: 90, fixed: 50 } };
  assert.ok(spendAlert({ baseline: null, episode: episode(), settings: fixed }), 'a fixed amount needs no history');
});

test('the loop brake counts the chosen repeats in the chosen minutes', () => {
  const d = createLoopDetector({ secret: 'k', threshold: 5, windowMs: 10 * 60e3 });
  const at = 1e12;

  for (let i = 0; i < 4; i++) assert.equal(d.record('Bash', { command: 'ls' }, at + i * 60e3).alert, false);
  assert.equal(d.record('Bash', { command: 'ls' }, at + 4 * 60e3).alert, true, 'five calls in five minutes');
});

// ---------- the `blackbrake brakes` command ----------

const memoryDeps = (initial = SPEND_DEFAULTS, paused = false) => {
  let saved = structuredClone(initial);

  return { get: () => structuredClone(saved), set: (s) => { saved = structuredClone(s); }, paused: () => paused, peek: () => saved };
};

const noTerminal = { input: { isTTY: false }, output: { isTTY: false, write() {} }, env: {} };

const quiet = () => {};

test('tightening a brake is saved without asking', async () => {
  const deps = memoryDeps();
  assert.equal(await runBrakes(createPainter(0), ['cost.percentile', '75'], { io: noTerminal, deps, print: quiet }), 0);
  assert.equal(deps.peek().cost.percentile, 75);
});

test('loosening a brake without a person at a terminal changes nothing', async () => {
  const deps = memoryDeps();
  assert.equal(await runBrakes(createPainter(0), ['cost', 'off'], { io: noTerminal, deps, print: quiet }), 1);
  assert.equal(deps.peek().cost.on, true);
  assert.equal(await runBrakes(createPainter(0), ['loop.repeats', '10'], { io: noTerminal, deps, print: quiet }), 1);
  assert.equal(deps.peek().loop.repeats, 3);
});

test('an AI agent with a terminal cannot loosen a brake', async () => {
  const deps = memoryDeps();
  const agentTty = { input: { isTTY: true }, output: { isTTY: true, write() {} }, env: { CLAUDECODE: '1' } };
  assert.equal(await applyBrakes(createPainter(0), parseBrakeChange(['quota', 'off']), { io: agentTty, deps, print: quiet }), 1);
  assert.equal(deps.peek().quota.on, true);
});

test('while paused nothing changes, and unknown words are refused', async () => {
  const paused = memoryDeps(SPEND_DEFAULTS, true);
  assert.equal(await runBrakes(createPainter(0), ['cost.percentile', '75'], { io: noTerminal, deps: paused, print: quiet }), 1);
  assert.equal(paused.peek().cost.percentile, 90);
  assert.equal(await runBrakes(createPainter(0), ['speed', '9'], { io: noTerminal, deps: memoryDeps(), print: quiet }), 2);
});

test('reset goes back to the defaults; from looser values that tightens, so it needs no confirmation', async () => {
  const deps = memoryDeps({ ...SPEND_DEFAULTS, loop: { on: true, repeats: 10, minutes: 1 } });
  assert.equal(await runBrakes(createPainter(0), ['reset'], { io: noTerminal, deps, print: quiet }), 0);
  assert.deepEqual(deps.peek(), structuredClone(SPEND_DEFAULTS));
});

// ---------- an agent cannot loosen the brakes through guard ----------

test('an agent is denied changing the spend brakes, by command or by writing the settings', () => {
  const home = os.homedir();
  const ctx = { mode: 'observe', rules: loadRules(), home };

  for (const input of [
    { tool_name: 'Bash', tool_input: { command: 'blackbrake brakes cost off' } },
    { tool_name: 'Bash', tool_input: { command: 'npx blackbrake brakes loop.repeats 10' } },
    { tool_name: 'Bash', tool_input: { command: 'blackbrake brakes reset' } },
    { tool_name: 'Write', tool_input: { file_path: path.join(home, '.blackbrake', 'state.json'), content: '{"settings":{"spend":{"cost":{"on":false}}}}' } },
  ]) {
    const r = decide('PreToolUse', input, ctx);

    const out = r.output?.hookSpecificOutput;
    assert.equal(out?.permissionDecision, 'deny', JSON.stringify(input));
  }
});

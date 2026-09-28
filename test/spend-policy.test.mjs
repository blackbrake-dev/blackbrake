import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { ADAPTERS } from '../src/guard/harnesses.mjs';
import { inventoryDelta } from '../src/load/inventory.mjs';
import { createLoopDetector } from '../src/guard/loops.mjs';
import { baselineFromEpisodes, spendAlert, spendTextTokens, withinTokenBudget } from '../src/guard/spend.mjs';
import { appendSpendEpisode, getSpendBaseline, setSpendBaseline } from '../src/guard/spend-state.mjs';
import { getSession, readLog, setMode } from '../src/guard/state.mjs';

// The hook runs as a real process: its home, guard folder and window stay inside the test folder.
const isolated = (home, extra = {}) => ({ ...process.env, HOME: home, USERPROFILE: home, BLACKBRAKE_HOME: home, BLACKBRAKE_NO_WINDOW: '1', BLACKBRAKE_LANG: 'en', ...extra });

const episodes = (n) => Array.from({ length: n }, (_, i) => ({ cost: i + 1, responses: i % 4 + 1 }));

const assistantMessage = (id, output = 100) => ({ id, role: 'assistant', model: 'claude-sonnet-5', content: [], usage: { input_tokens: 10_000, output_tokens: output } });

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

test('spend-log-is-aggregate-only-and-private', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-spend-state-'));
  const sentinel = 'PRIVATE_PROMPT_SENTINEL';

  appendSpendEpisode({ harness: 'claude', cost: 4.5, responses: 9, label: 'valid', prompt: sentinel, arguments: sentinel }, home);
  setSpendBaseline('claude', { harness: 'claude', n: 30, p50: 1, p90: 3, ready: true, prompt: sentinel }, home);
  const files = fs.readdirSync(path.join(home, 'spend')).map((name) => fs.readFileSync(path.join(home, 'spend', name), 'utf8')).join('\n');

  assert.equal(files.includes(sentinel), false);
  assert.deepEqual(getSpendBaseline('claude', home), { harness: 'claude', n: 30, p50: 1, p90: 3, ready: true });

  if (process.platform !== 'win32') assert.equal(fs.statSync(path.join(home, 'spend', 'baseline.json')).mode & 0o777, 0o600);
});

test('harness-spend-coverage-is-explicit', () => {
  assert.deepEqual(Object.keys(ADAPTERS).sort(), ['claude', 'codex', 'copilot', 'cursor', 'devin', 'gemini', 'windsurf']);
  assert.equal(ADAPTERS.claude.events.Stop, 'Stop');
  assert.equal(ADAPTERS.claude.events.PostToolBatch, 'PostToolBatch');
  assert.equal(ADAPTERS.claude.spendCost, true);
  assert.equal(ADAPTERS.claude.spendAsk, true);

  for (const [name, adapter] of Object.entries(ADAPTERS)) {
    if (name === 'claude') continue;
    assert.equal(adapter.spendCost, false);
    assert.equal(adapter.spendAsk, false);
  }
});

test('loop-mode-observe-warns-and-protect-asks', () => {
  const run = (mode) => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), `blackbrake-loop-${mode}-`));
    setMode(mode, home);
    let result;

    result = spawnSync(process.execPath, ['src/guard/hook.mjs', 'UserPromptSubmit'], {
      cwd: path.resolve('.'), env: isolated(home), input: JSON.stringify({ session_id: 'fixture-session', prompt: 'fixture prompt' }), encoding: 'utf8',
    });
    assert.equal(result.status, 0, result.stderr);

    for (let i = 0; i < 3; i++) {
      result = spawnSync(process.execPath, ['src/guard/hook.mjs', 'PreToolUse'], {
        cwd: path.resolve('.'),
        env: isolated(home),
        input: JSON.stringify({ session_id: 'fixture-session', tool_name: 'Read', tool_input: { file_path: 'fixture.txt' } }),
        encoding: 'utf8',
      });
      assert.equal(result.status, 0, result.stderr);
    }

    return { output: result.stdout ? JSON.parse(result.stdout) : null, log: readLog(home) };
  };

  const observed = run('observe');
  const protectedResult = run('protect');

  assert.equal(observed.log.some((entry) => entry.kind === 'spend-loop' && entry.action === 'warned'), true);
  assert.equal(protectedResult.output.hookSpecificOutput.permissionDecision, 'ask');
  assert.match(protectedResult.output.hookSpecificOutput.permissionDecisionReason, /(?:same call.*3 times|misma llamada 3 veces)/i);
});

test('hook-live-cost-counts-one-response-and-warns', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-live-hook-'));
  const claude = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-claude-'));
  const project = path.join(claude, 'projects', 'fixture');
  const transcript = path.join(project, 'session.jsonl');
  const env = isolated(home, { CLAUDE_CONFIG_DIR: claude });
  const run = (event, input) => spawnSync(process.execPath, ['src/guard/hook.mjs', event], { cwd: path.resolve('.'), env, input: JSON.stringify(input), encoding: 'utf8' });

  fs.mkdirSync(project, { recursive: true });
  fs.writeFileSync(transcript, `${JSON.stringify({ message: { role: 'user', content: 'fixture prompt' } })}\n`);
  setMode('observe', home);
  setSpendBaseline('claude', { n: 30, p50: 0.000001, p90: 0.000002, ready: true }, home);
  let result = run('UserPromptSubmit', { session_id: 'live-session', transcript_path: transcript, prompt: 'fixture prompt' });
  assert.equal(result.status, 0, result.stderr);
  const answer = { requestId: 'fixture-request', message: assistantMessage('fixture-response', 500) };
  fs.appendFileSync(transcript, `${JSON.stringify(answer)}\n${JSON.stringify(answer)}\n`);
  result = run('PreToolUse', { session_id: 'live-session', transcript_path: transcript, tool_name: 'Read', tool_input: { file_path: 'fixture.txt' } });
  assert.equal(result.status, 0, result.stderr);
  assert.match(JSON.parse(result.stdout).systemMessage, /(?:local p90|p90 local)/);
  assert.equal(getSession('live-session', home).spend.open.responses, 1);
});

test('spend-token-overhead-stays-below-one-percent', () => {
  const message = 'fixture warning shown to the user';

  assert.equal(withinTokenBudget(message, 100), false);
  assert.equal(withinTokenBudget(message, 10_000), true);
  assert.ok(spendTextTokens(message) < 10_000 * 0.01);
});

test('inventory-delta-new-and-changed-only', () => {
  const previous = [{ id: 'a', digest: '1' }, { id: 'b', digest: '1' }, { id: 'removed', digest: '1' }];
  const current = [{ id: 'a', digest: '1' }, { id: 'b', digest: '2' }, { id: 'new', digest: '1' }];

  assert.deepEqual(inventoryDelta(previous, current), {
    added: ['new'], changed: ['b'], removed: ['removed'],
  });
});

test('episode-resumes-open-state', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-resume-'));
  const env = isolated(home);
  const run = (event, input) => spawnSync(process.execPath, ['src/guard/hook.mjs', event], { cwd: path.resolve('.'), env, input: JSON.stringify(input), encoding: 'utf8' });

  assert.equal(run('UserPromptSubmit', { session_id: 'resume-session', prompt: 'fixture prompt' }).status, 0);
  const started = getSession('resume-session', home).spend.open.start;
  assert.equal(run('SessionStart', { session_id: 'resume-session' }).status, 0);
  assert.equal(getSession('resume-session', home).spend.open.start, started);
});

test('spend-path-makes-no-network-calls', async () => {
  const original = globalThis.fetch;
  let called = false;
  globalThis.fetch = () => { called = true; throw new Error('network forbidden'); };

  try {
    baselineFromEpisodes(episodes(30), 'claude');
    const detector = createLoopDetector({ secret: Buffer.alloc(32, 3) });
    detector.record('Read', { path: 'fixture' }, 0);
    await Promise.resolve();
    assert.equal(called, false);
  } finally {
    globalThis.fetch = original;
  }
});

test('spend-added-latency-budget', () => {
  const samples = [];

  for (let run = 0; run < 100; run++) {
    const detector = createLoopDetector({ secret: Buffer.alloc(32, run % 255) });
    const start = performance.now();
    detector.record('Read', { path: `fixture-${run}`, nested: { b: 2, a: 1 } }, run);
    samples.push(performance.now() - start);
  }

  samples.sort((a, b) => a - b);
  assert.ok(samples[Math.floor(samples.length * 0.95)] < 20);
});

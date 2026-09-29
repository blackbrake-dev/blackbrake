// F5.5: Devin rewrites one complete JSON document per session. Tokens are measured from one real
// user step to the next; cache is reported separately and no transcript text is persisted.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import { devinRoot, episodesFromDevin, summarizeDevinHistory } from '../src/cost/devin.mjs';

const metrics = (promptTokens, completionTokens = 0, cachedTokens = 0, cacheCreationTokens = 0) => ({
  prompt_tokens: promptTokens,
  completion_tokens: completionTokens,
  cached_tokens: cachedTokens,
  extra: { cache_creation_input_tokens: cacheCreationTokens },
});

const step = (source, id, value = null) => {
  const out = {
    step_id: id,
    source,
    message: `${source} SENTINEL-MESSAGE`,
    timestamp: '2026-09-29T00:00:00.000Z',
    extra: { telemetry: 'SENTINEL-TELEMETRY' },
  };

  if (value) Object.assign(out, { metrics: value, model_name: 'fixture-model', tool_calls: [], observation: 'SENTINEL-OBSERVATION' });

  return out;
};

const document = (id, steps) => ({
  schema_version: 1,
  session_id: id,
  agent: 'fixture-agent',
  steps,
  final_metrics: {
    total_prompt_tokens: steps.reduce((n, s) => n + (s.metrics?.prompt_tokens ?? 0), 0),
    total_completion_tokens: steps.reduce((n, s) => n + (s.metrics?.completion_tokens ?? 0), 0),
    total_cached_tokens: steps.reduce((n, s) => n + (s.metrics?.cached_tokens ?? 0), 0),
    total_steps: steps.length,
  },
});

const session = (id, episodes, size = 100) => {
  const steps = [step('system', `${id}-system`)];

  for (let i = 0; i < episodes; i++) {
    steps.push(step('user', `${id}-user-${i}`));
    steps.push(step('agent', `${id}-agent-${i}`, metrics(size - 10, 10, size - 20, 5)));
  }

  return document(id, steps);
};

const tempHome = (tag) => fs.mkdtempSync(path.join(os.tmpdir(), `blackbrake-devin-${tag}-`));

const envFor = (home) => ({
  ...process.env,
  HOME: home,
  USERPROFILE: home,
  APPDATA: path.join(home, 'AppData', 'Roaming'),
  XDG_CONFIG_HOME: path.join(home, '.config'),
  BLACKBRAKE_HOME: path.join(home, '.bb'),
  BLACKBRAKE_NO_WINDOW: '1',
  BLACKBRAKE_LANG: 'en',
});

const rootFor = (home) => devinRoot(envFor(home), { platform: process.platform, home });

const write = (file, value) => fs.writeFileSync(file, `${JSON.stringify(value)}\n`);

const withBaseline = (home, episodes = 30) => {
  const root = rootFor(home);

  fs.mkdirSync(root, { recursive: true });
  write(path.join(root, 'history.json'), session('history-session', episodes));

  return root;
};

// Runs the real watcher logic in an isolated process. Every write replaces the complete JSON file.
const watch = (home, steps, options = {}) => {
  const url = pathToFileURL(path.resolve('src/cost/devin.mjs')).href;

  const code = `
    import fs from 'node:fs';
    const { createDevinSpend } = await import(${JSON.stringify(url)});
    const plan = JSON.parse(fs.readFileSync(0, 'utf8'));
    const notes = [];
    const spend = createDevinSpend({ home: process.env.BLACKBRAKE_HOME, notifier: (title, body) => notes.push({ title, body }), maxBytes: ${options.maxBytes ?? 32 * 1024 * 1024} });
    const ticks = [];
    for (const item of plan) {
      if (item.write) fs.writeFileSync(item.write, item.text);
      if (item.tick) ticks.push(spend.tick().length);
    }
    process.stdout.write(JSON.stringify({ notes, ticks }));
  `;

  const r = spawnSync(process.execPath, ['--input-type=module', '-e', code], {
    cwd: path.resolve('.'),
    env: envFor(home),
    input: JSON.stringify(steps),
    encoding: 'utf8',
    timeout: 30000,
  });

  assert.equal(r.status, 0, r.stderr);

  return JSON.parse(r.stdout);
};

const encoded = (value) => `${JSON.stringify(value)}\n`;

const logs = (home) => {
  const dir = path.join(home, '.bb', 'log');

  if (!fs.existsSync(dir)) return [];

  return fs.readdirSync(dir).flatMap((file) => fs.readFileSync(path.join(dir, file), 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line)));
};

test('devin-episode-runs-from-user-step-to-next-user-step', () => {
  const { episodes } = episodesFromDevin(document('fixture-session', [
    step('system', 'system-1'),
    step('agent', 'agent-before', metrics(999, 1, 900, 3)),
    step('user', 'user-1'),
    step('agent', 'agent-1', metrics(80, 20, 60, 5)),
    step('system', 'system-2'),
    step('agent', 'agent-2', metrics(40, 10, 30, 2)),
    step('user', 'user-2'),
    step('agent', 'agent-3', metrics(10, 5, 8, 1)),
    // A repeated step id in a rewritten document is counted once.
    step('agent', 'agent-3', metrics(10, 5, 8, 1)),
  ]));

  assert.deepEqual(episodes.map(({ tokens, cached, cacheCreation, closed }) => ({ tokens, cached, cacheCreation, closed })), [
    { tokens: 150, cached: 90, cacheCreation: 7, closed: true },
    { tokens: 15, cached: 8, cacheCreation: 1, closed: false },
  ]);
});

test('devin-history-needs-30-episodes', () => {
  const home = tempHome('n');
  const root = withBaseline(home, 29);
  const under = summarizeDevinHistory({ root });

  assert.equal(under.sessions, 1);
  assert.equal(under.episodes, 29);
  assert.equal(under.baseline.ready, false);
  assert.equal(under.aboveP90, 0);

  write(path.join(root, 'other.json'), session('other-session', 1, 1000));
  const ready = summarizeDevinHistory({ root });

  assert.equal(ready.sessions, 2);
  assert.equal(ready.episodes, 30);
  assert.equal(ready.baseline.ready, true);
  assert.equal(ready.baseline.p90, 100);
  assert.equal(ready.aboveP90, 1);
});

test('devin-rewrite-recalculates-without-double-counting-and-warns-once', () => {
  const home = tempHome('rewrite');
  const root = withBaseline(home);
  const file = path.join(root, 'live.json');
  const low = document('live-session', [step('user', 'live-user'), step('agent', 'live-agent', metrics(40, 10, 30, 2))]);
  const high = document('live-session', [step('user', 'live-user'), step('agent', 'live-agent', metrics(400, 100, 300, 20))]);
  const closed = document('live-session', [...high.steps, step('user', 'next-user'), step('agent', 'next-agent', metrics(5, 5))]);

  const r = watch(home, [
    { write: file, text: encoded(low) }, { tick: true },
    { write: file, text: encoded(high) }, { tick: true },
    { write: file, text: encoded(high) }, { tick: true },
    { write: file, text: encoded(closed) }, { tick: true },
    { write: file, text: encoded(closed) }, { tick: true },
  ]);

  assert.deepEqual(r.ticks, [0, 1, 0, 0, 0]);
  assert.equal(r.notes.length, 1);
  assert.match(r.notes[0].body, /^This Devin episode is at 500 tokens; your p90 is 100\.$/);
  assert.doesNotMatch(JSON.stringify(r.notes), /sav|avoid|%/i);
  assert.equal(JSON.parse(fs.readFileSync(path.join(home, '.bb', 'spend', 'devin.json'), 'utf8')).baseline.n, 31);
});

test('devin-first-view-of-existing-session-never-warns-for-its-past', () => {
  const home = tempHome('existing');
  const root = withBaseline(home);
  const file = path.join(root, 'existing.json');
  const old = document('existing-session', [step('user', 'old-user'), step('agent', 'old-agent', metrics(9000, 999))]);

  write(file, old);
  const grown = document('existing-session', [step('user', 'old-user'), step('agent', 'old-agent', metrics(18000, 1999))]);
  const next = document('existing-session', [...grown.steps, step('user', 'new-user'), step('agent', 'new-agent', metrics(400, 100))]);

  const r = watch(home, [
    { tick: true },
    { write: file, text: encoded(grown) }, { tick: true },
    { write: file, text: encoded(next) }, { tick: true },
  ]);

  assert.deepEqual(r.ticks, [0, 0, 1]);
  assert.equal(r.notes.length, 1);
  assert.match(r.notes[0].body, / 500 tokens/);
});

test('devin-live-does-not-warn-under-30-episodes', () => {
  const home = tempHome('few');
  const root = withBaseline(home, 29);
  const file = path.join(root, 'live.json');
  const r = watch(home, [{ write: file, text: encoded(session('live-session', 1, 90000)) }, { tick: true }]);

  assert.deepEqual(r.ticks, [0]);
  assert.equal(r.notes.length, 0);
});

test('devin-files-over-the-size-limit-are-skipped-and-logged-without-paths', () => {
  const home = tempHome('limit');
  const root = withBaseline(home);
  const file = path.join(root, 'SENTINEL-OVERSIZE.json');
  const huge = { ...session('SENTINEL-SESSION', 1, 90000), padding: 'x'.repeat(70 * 1024) };
  const r = watch(home, [{ write: file, text: encoded(huge) }, { tick: true }, { tick: true }], { maxBytes: 64 * 1024 });

  assert.deepEqual(r.ticks, [0, 0]);
  assert.equal(r.notes.length, 0);
  const limited = logs(home).filter((entry) => entry.kind === 'spend-limit');

  assert.equal(limited.length, 1);
  assert.deepEqual(Object.keys(limited[0]).sort(), ['action', 'bytes', 'ev', 'harness', 'kind', 'maxBytes', 's', 'ts']);
  assert.doesNotMatch(JSON.stringify(limited), /SENTINEL|OVERSIZE|transcripts|AppData/i);
});

test('devin-links-outside-the-transcripts-root-are-ignored', () => {
  const home = tempHome('link');
  const root = withBaseline(home);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-devin-outside-'));
  const planted = path.join(outside, 'planted.json');

  write(planted, session('planted-session', 40, 100000));

  fs.symlinkSync(outside, path.join(root, 'linked-directory'), 'junction');

  try { fs.symlinkSync(planted, path.join(root, 'linked.json'), 'file'); } catch { /* file links need privileges on Windows */ }

  assert.ok(fs.lstatSync(path.join(root, 'linked-directory')).isSymbolicLink());
  assert.equal(summarizeDevinHistory({ root }).episodes, 30);
  assert.deepEqual(watch(home, [{ write: planted, text: encoded(session('planted-session', 50, 200000)) }, { tick: true }]).ticks, [0]);
});

test('devin-root-never-uses-a-remote-config-directory', () => {
  const home = tempHome('unc');
  const expected = devinRoot({}, { platform: 'win32', home });

  assert.equal(devinRoot({ APPDATA: '\\\\attacker.invalid\\share' }, { platform: 'win32', home }), expected);
  assert.equal(devinRoot({ APPDATA: '//attacker.invalid/share' }, { platform: 'win32', home }), expected);
  assert.equal(devinRoot({ APPDATA: 'relative/config' }, { platform: 'win32', home }), expected);
  assert.equal(devinRoot({ APPDATA: path.join(home, 'config') }, { platform: 'win32', home }), path.join(home, 'config', 'devin', 'cli', 'transcripts'));
});

test('devin-spend-state-and-log-hold-only-numbers-and-fingerprints', () => {
  const home = tempHome('privacy');
  const root = withBaseline(home);
  const file = path.join(root, 'SENTINEL-FILE.json');
  const value = document('SENTINEL-SESSION', [step('user', 'SENTINEL-USER'), step('agent', 'SENTINEL-AGENT', metrics(4000, 1000, 3500, 200))]);

  watch(home, [{ write: file, text: encoded(value) }, { tick: true }]);
  const bb = path.join(home, '.bb');
  const files = [];
  const walk = (dir) => { for (const entry of fs.readdirSync(dir, { withFileTypes: true })) (entry.isDirectory() ? walk : (name) => files.push(name))(path.join(dir, entry.name)); };

  walk(bb);
  assert.ok(files.length > 0);

  for (const stored of files) assert.doesNotMatch(fs.readFileSync(stored, 'utf8'), /SENTINEL|fixture|transcripts|AppData/i, path.basename(stored));

  const state = JSON.parse(fs.readFileSync(path.join(bb, 'spend', 'devin.json'), 'utf8'));

  assert.equal(state.baseline.n, 30);
  assert.equal(state.baseline.p90, 100);
  assert.equal(state.maxBytes, 32 * 1024 * 1024);
  const entry = logs(home).find((item) => item.kind === 'spend-tokens' && item.harness === 'devin');

  assert.deepEqual(Object.keys(entry).sort(), ['action', 'cacheCreation', 'cached', 'ev', 'fingerprint', 'harness', 'kind', 'n', 'p90', 's', 'tokens', 'ts']);
  assert.match(entry.fingerprint, /^[0-9a-f]{16}$/);
  assert.equal(entry.tokens, 5000);
  assert.equal(entry.cached, 3500);
});

test('devin-spend-runs-inside-the-background-watcher', () => {
  const home = tempHome('bg');

  withBaseline(home);
  const url = pathToFileURL(path.resolve('src/guard/background.mjs')).href;
  const code = `const { runBackground } = await import(${JSON.stringify(url)}); await runBackground({ home: process.env.BLACKBRAKE_HOME, once: true, notifier: () => {} });`;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', code], { cwd: path.resolve('.'), env: envFor(home), encoding: 'utf8', timeout: 30000 });

  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(fs.readFileSync(path.join(home, '.bb', 'spend', 'devin.json'), 'utf8')).baseline.n, 30);
});

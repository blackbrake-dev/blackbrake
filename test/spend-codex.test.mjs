// F5.4: the tail warning for Codex. Codex writes cumulative token totals per session, not prices, so
// the measure is tokens per episode (real prompt to next real prompt), never dollars.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import { codexRoot, episodesFromRecords, summarizeCodexHistory } from '../src/cost/codex.mjs';

const text = (role, value) => ({ type: 'response_item', payload: { type: 'message', role, content: [{ type: 'input_text', text: value }] } });

const meta = () => ({ type: 'session_meta', payload: { id: 'fixture-session-id' } });

const prompt = (value = 'fixture prompt SENTINEL-PROMPT') => text('user', value);

const toolOut = () => ({ type: 'response_item', payload: { type: 'function_call_output', call_id: 'fixture', output: 'SENTINEL-OUTPUT' } });

const FIXTURE_NOW = Math.floor(Date.now() / 1000);

const PRIMARY_RESET = FIXTURE_NOW + 60;

const SECONDARY_RESET = FIXTURE_NOW + 120;

const NEXT_PRIMARY_RESET = FIXTURE_NOW + 180;

const NEXT_SECONDARY_RESET = FIXTURE_NOW + 240;

const RATE = { primary: { used_percent: 12.5, window_minutes: 300, resets_at: PRIMARY_RESET }, secondary: { used_percent: 3, window_minutes: 10080, resets_at: SECONDARY_RESET } };

const count = (total, cached = 0) => ({
  type: 'event_msg',
  payload: {
    type: 'token_count',
    info: {
      total_token_usage: { input_tokens: total, cached_input_tokens: cached, cache_write_input_tokens: 0, output_tokens: 0, reasoning_output_tokens: 0, total_tokens: total },
      last_token_usage: { input_tokens: 0, cached_input_tokens: 0, cache_write_input_tokens: 0, output_tokens: 0, reasoning_output_tokens: 0, total_tokens: 0 },
      model_context_window: 1000,
    },
    rate_limits: RATE,
  },
});

const quotaCount = (primary, secondary, primaryReset = PRIMARY_RESET, secondaryReset = SECONDARY_RESET) => {
  const record = count(0);

  record.payload.rate_limits = {
    primary: { used_percent: primary, window_minutes: 300, resets_at: primaryReset },
    secondary: { used_percent: secondary, window_minutes: 10080, resets_at: secondaryReset },
  };

  return record;
};

const injected = () => [meta(), text('developer', '<permissions instructions>fixture</permissions instructions>'), text('user', '# AGENTS.md instructions for fixture\n\nfixture'), text('user', '<environment_context>fixture</environment_context>')];

const jsonl = (records) => records.map((r) => JSON.stringify(r)).join('\n') + '\n';

// A session file with `episodes` episodes of `size` tokens each.
const session = (episodes, size = 100) => {
  const out = injected();

  for (let i = 1; i <= episodes; i++) out.push(prompt(), count(i * size - size / 2), toolOut(), count(i * size));

  return out;
};

const tempHome = (tag) => fs.mkdtempSync(path.join(os.tmpdir(), `blackbrake-codex-${tag}-`));

const sessions = (home) => path.join(home, '.codex', 'sessions', '2026', '09', '29');

// Runs the watcher in its own process (temporary HOME, USERPROFILE and BLACKBRAKE_HOME, no window):
// it is built over the files that exist, then each step changes files and ticks.
const watch = (home, steps) => {
  const url = pathToFileURL(path.resolve('src/cost/codex.mjs')).href;

  const code = `
    import fs from 'node:fs';
    import http from 'node:http';
    import https from 'node:https';
    import net from 'node:net';
    let networkCalls = 0;
    const forbidden = () => { networkCalls++; throw new Error('network call'); };
    globalThis.fetch = forbidden;
    http.request = forbidden;
    https.request = forbidden;
    net.connect = forbidden;
    const { createCodexSpend } = await import(${JSON.stringify(url)});
    const plan = JSON.parse(fs.readFileSync(0, 'utf8'));
    const notes = [];
    const spend = createCodexSpend({ home: process.env.BLACKBRAKE_HOME, notifier: (title, body) => notes.push({ title, body }) });
    const ticks = [];
    for (const step of plan) {
      if (step.rename) fs.renameSync(step.rename, step.to);
      if (step.append) fs.appendFileSync(step.append, step.text);
      if (step.write) fs.writeFileSync(step.write, step.text);
      if (step.tick) ticks.push(spend.tick().length);
    }
    process.stdout.write(JSON.stringify({ notes, ticks, networkCalls }));
  `;

  const env = { ...process.env, HOME: home, USERPROFILE: home, BLACKBRAKE_HOME: path.join(home, '.bb'), BLACKBRAKE_NO_WINDOW: '1', BLACKBRAKE_LANG: 'en' };
  delete env.CODEX_HOME;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', code], { env, input: JSON.stringify(steps), encoding: 'utf8' });

  assert.equal(r.status, 0, r.stderr);

  return JSON.parse(r.stdout);
};

// 30 past episodes of 100 tokens: p90 is 100.
const withBaseline = (home, episodes = 30) => {
  fs.mkdirSync(sessions(home), { recursive: true });
  fs.writeFileSync(path.join(sessions(home), 'rollout-history.jsonl'), jsonl(session(episodes)));
};

test('codex-episode-runs-from-real-prompt-to-next-real-prompt', () => {
  const { episodes } = episodesFromRecords([
    ...injected(), prompt(), count(100), toolOut(), count(250),
    text('user', '<subagent_notification>fixture</subagent_notification>'), count(300),
    prompt(), count(400), text('developer', 'fixture developer note'), count(500),
  ]);

  assert.deepEqual(episodes.map((e) => e.tokens), [300, 200]);
});

test('codex-cumulative-total-counts-once-and-cached-apart', () => {
  const { episodes } = episodesFromRecords([prompt(), count(100, 80), count(100, 80), count(100, 80), count(150, 120)]);

  assert.deepEqual(episodes, [{ tokens: 150, cached: 120 }]);
});

test('codex-counter-restart-and-tokens-before-any-prompt', () => {
  // Tokens before the first real prompt belong to no episode; a total that goes down is a counter
  // that started again from zero.
  const { episodes } = episodesFromRecords([count(700), prompt(), count(900), count(40)]);

  assert.deepEqual(episodes.map((e) => e.tokens), [240]);
});

test('codex-history-needs-30-episodes', () => {
  const home = tempHome('n');
  withBaseline(home, 29);
  const under = summarizeCodexHistory({ root: path.join(home, '.codex', 'sessions') });

  assert.equal(under.episodes, 29);
  assert.equal(under.baseline.ready, false);
  assert.equal(under.aboveP90, 0);
  assert.deepEqual(under.rate, { primary: { usedPercent: 12.5, windowMinutes: 300 }, secondary: { usedPercent: 3, windowMinutes: 10080 } });

  fs.writeFileSync(path.join(sessions(home), 'rollout-other.jsonl'), jsonl([...injected(), prompt(), count(1000)]));
  const ready = summarizeCodexHistory({ root: path.join(home, '.codex', 'sessions') });

  assert.equal(ready.sessions, 2);
  assert.equal(ready.episodes, 30);
  assert.equal(ready.baseline.ready, true);
  assert.equal(ready.baseline.p90, 100);
  assert.equal(ready.aboveP90, 1);
});

test('codex-live-warns-once-per-episode-above-p90', () => {
  const home = tempHome('live');
  withBaseline(home);
  const open = path.join(sessions(home), 'rollout-open.jsonl');

  // An episode already running when the watcher starts is never measured from the middle.
  fs.writeFileSync(open, jsonl([...injected(), prompt(), count(1000)]));
  const fresh = path.join(sessions(home), 'rollout-new.jsonl');

  const r = watch(home, [
    { append: open, text: jsonl([count(5000)]) }, { tick: true },
    { append: open, text: jsonl([prompt(), count(5100)]) }, { tick: true },
    { append: open, text: jsonl([count(5100), count(5500)]) }, { tick: true },
    { append: open, text: jsonl([count(6000)]) }, { tick: true },
    // A session that starts while watching is read from its first line.
    { write: fresh, text: jsonl([...injected(), prompt(), count(900)]) }, { tick: true },
  ]);

  assert.deepEqual(r.ticks, [0, 0, 1, 0, 1]);
  assert.equal(r.notes.length, 2);
  assert.match(r.notes[0].body, /^This Codex episode is at 500 tokens; your p90 is 100\.$/);
  assert.doesNotMatch(JSON.stringify(r.notes), /sav|avoid|%/i);
});

test('codex-live-no-warning-under-30-episodes', () => {
  const home = tempHome('few');
  withBaseline(home, 29);
  const file = path.join(sessions(home), 'rollout-live.jsonl');
  const r = watch(home, [{ write: file, text: jsonl([...injected(), prompt(), count(90000)]) }, { tick: true }]);

  assert.deepEqual(r.ticks, [0]);
  assert.equal(r.notes.length, 0);
});

test('codex-live-truncated-or-rotated-file-is-not-counted-again', () => {
  const home = tempHome('rotate');
  withBaseline(home);
  const file = path.join(sessions(home), 'rollout-rot.jsonl');
  fs.writeFileSync(file, jsonl([...injected(), prompt(), count(50)]));

  const r = watch(home, [
    // Rewritten shorter: its old content is read again only to learn the running total.
    { write: file, text: jsonl([prompt(), count(9999)]) }, { tick: true },
    { append: file, text: jsonl([prompt(), count(10099)]) }, { tick: true },
    { append: file, text: jsonl([count(10999)]) }, { tick: true },
  ]);

  assert.deepEqual(r.ticks, [0, 0, 1]);
  assert.match(r.notes[0].body, / 1000 tokens/);
});

test('codex-lines-over-1-mib-are-skipped', () => {
  const home = tempHome('big');
  withBaseline(home);
  const file = path.join(sessions(home), 'rollout-big.jsonl');
  const huge = { type: 'response_item', payload: { type: 'function_call_output', output: 'x'.repeat(1536 * 1024) } };

  const r = watch(home, [
    { write: file, text: jsonl([...injected(), prompt(), count(10)]) + JSON.stringify(huge) + '\n' + jsonl([count(20)]) }, { tick: true }, { tick: true },
    { append: file, text: jsonl([count(400)]) }, { tick: true }, { tick: true },
  ]);

  assert.equal(r.notes.length, 1);
  assert.match(r.notes[0].body, / 400 tokens/);
});

test('codex-links-out-of-the-sessions-root-are-ignored', () => {
  const home = tempHome('link');
  withBaseline(home);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-codex-outside-'));
  fs.writeFileSync(path.join(outside, 'rollout-planted.jsonl'), jsonl(session(40, 100000)));

  try {
    fs.symlinkSync(outside, path.join(sessions(home), 'planted'), 'junction');
    fs.symlinkSync(path.join(outside, 'rollout-planted.jsonl'), path.join(sessions(home), 'rollout-link.jsonl'), 'file');
  } catch { /* file links need privileges on Windows; the junction alone still proves it */ }

  assert.ok(fs.lstatSync(path.join(sessions(home), 'planted')).isSymbolicLink());
  assert.equal(summarizeCodexHistory({ root: path.join(home, '.codex', 'sessions') }).episodes, 30);

  const r = watch(home, [{ append: path.join(outside, 'rollout-planted.jsonl'), text: jsonl([prompt(), count(9e9)]) }, { tick: true }]);

  assert.deepEqual(r.ticks, [0]);
});

test('codex-spend-state-holds-numbers-and-hashes-only', () => {
  const home = tempHome('privacy');
  withBaseline(home);
  const file = path.join(sessions(home), 'rollout-SENTINEL-FILE.jsonl');

  watch(home, [{ write: file, text: jsonl([...injected(), prompt(), toolOut(), count(5000, 4000)]) }, { tick: true }]);

  const bb = path.join(home, '.bb');
  const files = [];
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) (e.isDirectory() ? walk : (f) => files.push(f))(path.join(d, e.name)); };

  walk(bb);
  assert.ok(files.length > 0);

  for (const f of files) {
    const body = fs.readFileSync(f, 'utf8');

    assert.doesNotMatch(body, /SENTINEL|fixture|rollout|\.codex|sessions/i, path.basename(f));
  }

  const state = JSON.parse(fs.readFileSync(path.join(bb, 'spend', 'codex.json'), 'utf8'));

  assert.deepEqual(state, { baseline: { n: 30, p50: 100, p90: 100, q: { 50: 100, 75: 100, 90: 100, 95: 100, 99: 100 }, ready: true }, rate: { primary: { usedPercent: 12.5, windowMinutes: 300 }, secondary: { usedPercent: 3, windowMinutes: 10080 } } });

  const log = fs.readdirSync(path.join(bb, 'log')).flatMap((f) => fs.readFileSync(path.join(bb, 'log', f), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)));
  const entry = log.find((e) => e.kind === 'spend-tokens');

  assert.deepEqual(Object.keys(entry).sort(), ['action', 'cached', 'ev', 'harness', 'kind', 'n', 'p90', 'primaryPercent', 's', 'secondaryPercent', 'tokens', 'ts']);
  assert.equal(entry.tokens, 5000);
  assert.equal(entry.cached, 4000);
});

test('codex-spend-runs-inside-the-background-watcher', () => {
  const home = tempHome('bg');
  withBaseline(home);
  const url = pathToFileURL(path.resolve('src/guard/background.mjs')).href;
  const code = `const { runBackground } = await import(${JSON.stringify(url)}); await runBackground({ home: process.env.BLACKBRAKE_HOME, once: true, notifier: () => {} });`;
  const env = { ...process.env, HOME: home, USERPROFILE: home, BLACKBRAKE_HOME: path.join(home, '.bb'), BLACKBRAKE_NO_WINDOW: '1', BLACKBRAKE_LANG: 'en' };
  delete env.CODEX_HOME;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', code], { env, encoding: 'utf8', timeout: 30000 });

  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(fs.readFileSync(path.join(home, '.bb', 'spend', 'codex.json'), 'utf8')).baseline.n, 30);
});

// A remote CODEX_HOME is never read: listing a UNC share on Windows can send the user's NTLM
// credentials to that host. The default local folder is used instead.
test('codex-root-ignores-remote-codex-home', () => {
  const local = path.join(os.homedir(), '.codex', 'sessions');

  assert.equal(codexRoot({ CODEX_HOME: '\\\\attacker.invalid\\share\\codex' }), local);
  assert.equal(codexRoot({ CODEX_HOME: '//attacker.invalid/share/codex' }), local);
  assert.equal(codexRoot({ CODEX_HOME: 'relative/codex' }), local);
  assert.equal(codexRoot({ CODEX_HOME: path.join(os.tmpdir(), 'codex-home') }), path.join(os.tmpdir(), 'codex-home', 'sessions'));
});

test('codex quota alerts at equality, once per independent window, across files and restart', () => {
  const home = tempHome('quota');
  fs.mkdirSync(sessions(home), { recursive: true });
  const first = path.join(sessions(home), 'rollout-one.jsonl');
  const second = path.join(sessions(home), 'rollout-two.jsonl');

  fs.writeFileSync(first, jsonl([quotaCount(94.9, 97.9)]));

  const run = watch(home, [
    { append: first, text: jsonl([quotaCount(95, 97.9)]) }, { tick: true },
    { write: second, text: jsonl([quotaCount(95, 98)]) }, { tick: true },
    { append: first, text: jsonl([quotaCount(99, 99)]) }, { tick: true },
  ]);

  assert.deepEqual(run.ticks, [1, 1, 0]);
  assert.equal(run.notes.length, 2);
  assert.equal(run.networkCalls, 0);
  assert.match(run.notes[0].body, /5-hour usage reached 95%/);
  assert.match(run.notes[1].body, /weekly usage reached 98%/);
  assert.doesNotMatch(JSON.stringify(run.notes), /bill|sav/i);

  const restart = watch(home, [{ append: second, text: jsonl([quotaCount(100, 100)]) }, { tick: true }]);

  assert.deepEqual(restart.ticks, [0]);
  assert.equal(restart.notes.length, 0);
  assert.equal(restart.networkCalls, 0);

  const state = JSON.parse(fs.readFileSync(path.join(home, '.bb', 'spend', 'codex-quota.json'), 'utf8'));

  assert.equal(state.primary.alertedResetAt, PRIMARY_RESET);
  assert.equal(state.secondary.alertedResetAt, SECONDARY_RESET);
});

test('codex quota new reset can warn again; stale replicated windows cannot', () => {
  const home = tempHome('reset');
  fs.mkdirSync(sessions(home), { recursive: true });
  const file = path.join(sessions(home), 'rollout-reset.jsonl');

  fs.writeFileSync(file, jsonl([quotaCount(94, 97)]));
  assert.deepEqual(watch(home, [{ append: file, text: jsonl([quotaCount(96, 99)]) }, { tick: true }]).ticks, [2]);

  const r = watch(home, [
    { append: file, text: jsonl([quotaCount(95, 98, NEXT_PRIMARY_RESET, NEXT_SECONDARY_RESET)]) }, { tick: true },
    { append: file, text: jsonl([quotaCount(99, 99, PRIMARY_RESET, SECONDARY_RESET)]) }, { tick: true },
  ]);

  assert.deepEqual(r.ticks, [2, 0]);
});

test('codex quota ignores malformed values and wrong windows', () => {
  const home = tempHome('badquota');
  fs.mkdirSync(sessions(home), { recursive: true });

  const file = path.join(sessions(home), 'rollout-bad.jsonl');
  fs.writeFileSync(file, jsonl([quotaCount(20, 20)]));

  const invalid = [
    { used_percent: 99, window_minutes: 301, resets_at: 1000 },
    { used_percent: null, window_minutes: 300, resets_at: 1000 },
    { used_percent: -1, window_minutes: 300, resets_at: 1000 },
    { used_percent: 101, window_minutes: 300, resets_at: 1000 },
    { used_percent: '95', window_minutes: 300, resets_at: 1000 },
    { used_percent: 99, window_minutes: NaN, resets_at: 1000 },
  ];

  const records = invalid.map((primary) => ({ ...count(0), payload: { ...count(0).payload, rate_limits: { primary } } }));
  const r = watch(home, [{ append: file, text: jsonl(records) }, { tick: true }]);

  assert.deepEqual(r.ticks, [0]);
  assert.equal(r.notes.length, 0);
});

test('codex quota without reset identity warns at most once ever, including after restart', () => {
  const home = tempHome('unknownquota');
  fs.mkdirSync(sessions(home), { recursive: true });

  const file = path.join(sessions(home), 'rollout-unknown.jsonl');
  fs.writeFileSync(file, jsonl([quotaCount(94, 0, null, null)]));

  const first = watch(home, [
    { append: file, text: jsonl([quotaCount(95, 0, null, null)]) }, { tick: true },
    { append: file, text: jsonl([quotaCount(20, 0, null, null), quotaCount(99, 0, null, null)]) }, { tick: true },
  ]);

  assert.deepEqual(first.ticks, [1, 0]);
  assert.deepEqual(watch(home, [{ append: file, text: jsonl([quotaCount(100, 0, null, null)]) }, { tick: true }]).ticks, [0]);
});

test('codex quota does not repeat an identity-free alert when the reset identity appears', () => {
  const home = tempHome('unknown-then-known');
  fs.mkdirSync(sessions(home), { recursive: true });

  const file = path.join(sessions(home), 'rollout-identity.jsonl');
  fs.writeFileSync(file, jsonl([quotaCount(94, 0, null, null)]));

  const first = watch(home, [
    { append: file, text: jsonl([quotaCount(95, 0, null, null)]) }, { tick: true },
    { append: file, text: jsonl([quotaCount(95, 0, PRIMARY_RESET, null)]) }, { tick: true },
    { append: file, text: jsonl([quotaCount(95, 0, NEXT_PRIMARY_RESET, null)]) }, { tick: true },
  ]);

  assert.deepEqual(first.ticks, [1, 0, 1]);
  assert.equal(first.notes.length, 2);
});

test('codex quota does not replay startup history or rotated content', () => {
  const home = tempHome('quota-rotate');
  fs.mkdirSync(sessions(home), { recursive: true });

  const file = path.join(sessions(home), 'rollout-rotate.jsonl');
  fs.writeFileSync(file, jsonl([quotaCount(96, 99)]));

  const first = watch(home, [
    { append: file, text: jsonl([quotaCount(96, 99)]) }, { tick: true },
    { write: file, text: jsonl([quotaCount(96, 99)]) }, { tick: true },
    { append: file, text: jsonl([quotaCount(96, 99)]) }, { tick: true },
    { rename: file, to: `${file}.old` }, { write: file, text: jsonl([quotaCount(96, 99)]) }, { tick: true },
    { append: file, text: jsonl([quotaCount(96, 99, NEXT_PRIMARY_RESET, NEXT_SECONDARY_RESET)]) }, { tick: true },
  ]);

  assert.deepEqual(first.ticks, [0, 0, 0, 0, 2]);
});

test('codex quota log and state contain no transcript text or private path', () => {
  const home = tempHome('quota-privacy');
  fs.mkdirSync(sessions(home), { recursive: true });

  const file = path.join(sessions(home), 'rollout-PRIVATE-FILENAME.jsonl');
  fs.writeFileSync(file, jsonl([prompt('PRIVATE-PROMPT-TEXT'), quotaCount(94, 0)]));
  const r = watch(home, [{ append: file, text: jsonl([quotaCount(95, 0)]) }, { tick: true }]);

  assert.deepEqual(r.ticks, [1]);

  const bb = path.join(home, '.bb');
  const files = [path.join(bb, 'spend', 'codex-quota.json'), ...fs.readdirSync(path.join(bb, 'log')).map((name) => path.join(bb, 'log', name))];

  for (const item of files) {
    const body = fs.readFileSync(item, 'utf8');

    assert.doesNotMatch(body, /PRIVATE|PROMPT|rollout|sessions|\.codex/i);
  }
});

test('codex quota rejects an impossible transcript reset without poisoning later windows', () => {
  const home = tempHome('future-transcript');
  fs.mkdirSync(sessions(home), { recursive: true });

  const now = Math.floor(Date.now() / 1000);
  const file = path.join(sessions(home), 'rollout-future.jsonl');
  fs.writeFileSync(file, jsonl([quotaCount(94, 0, now + 300 * 60, null)]));

  const r = watch(home, [
    { append: file, text: jsonl([quotaCount(95, 0, now + 365 * 86400, null)]) }, { tick: true },
    { append: file, text: jsonl([quotaCount(95, 0, now + 300 * 60, null)]) }, { tick: true },
  ]);

  const state = JSON.parse(fs.readFileSync(path.join(home, '.bb', 'spend', 'codex-quota.json'), 'utf8'));

  assert.ok(state.primary.maxResetAt === null || state.primary.maxResetAt <= now + 300 * 60 + 900);
  assert.equal(r.notes.length, 1);
});

test('codex quota ignores impossible persisted reset and warns in a valid window', () => {
  const home = tempHome('future-state');
  fs.mkdirSync(sessions(home), { recursive: true });

  const now = Math.floor(Date.now() / 1000);
  const valid = now + 300 * 60;
  const file = path.join(sessions(home), 'rollout-valid.jsonl');
  const spend = path.join(home, '.bb', 'spend');

  fs.writeFileSync(file, jsonl([quotaCount(94, 0, valid, null)]));
  fs.mkdirSync(spend, { recursive: true });
  fs.writeFileSync(path.join(spend, 'codex-quota.json'), JSON.stringify({ primary: { maxResetAt: now + 365 * 86400, alertedResetAt: now + 365 * 86400 } }));
  const r = watch(home, [{ append: file, text: jsonl([quotaCount(95, 0, valid, null)]) }, { tick: true }]);

  assert.deepEqual(r.ticks, [1]);
});

test('codex quota reset allows bounded clock skew but rejects a larger offset', () => {
  const now = Math.floor(Date.now() / 1000);
  const near = tempHome('reset-near');
  const far = tempHome('reset-far');
  fs.mkdirSync(sessions(near), { recursive: true });
  fs.mkdirSync(sessions(far), { recursive: true });

  const nearFile = path.join(sessions(near), 'rollout-near.jsonl');
  const farFile = path.join(sessions(far), 'rollout-far.jsonl');
  const nearReset = now + 300 * 60 + 14 * 60;
  const farReset = now + 300 * 60 + 16 * 60;

  fs.writeFileSync(nearFile, jsonl([quotaCount(94, 0, nearReset, null)]));
  fs.writeFileSync(farFile, jsonl([quotaCount(94, 0, farReset, null)]));
  assert.deepEqual(watch(near, [{ append: nearFile, text: jsonl([quotaCount(95, 0, nearReset, null)]) }, { tick: true }]).ticks, [1]);
  assert.deepEqual(watch(far, [{ append: farFile, text: jsonl([quotaCount(95, 0, farReset, null)]) }, { tick: true }]).ticks, [1]);

  const nearState = JSON.parse(fs.readFileSync(path.join(near, '.bb', 'spend', 'codex-quota.json'), 'utf8'));
  const farState = JSON.parse(fs.readFileSync(path.join(far, '.bb', 'spend', 'codex-quota.json'), 'utf8'));

  assert.equal(nearState.primary.maxResetAt, nearReset);
  assert.equal(farState.primary.maxResetAt, null);
  assert.equal(farState.primary.unknownAlerted, true);
});

test('codex quota state reader does not stat through a linked spend ancestor', (t) => {
  const home = tempHome('linked-state');
  const outside = tempHome('linked-outside');
  const spend = path.join(home, '.bb', 'spend');

  fs.mkdirSync(path.dirname(spend), { recursive: true });
  fs.writeFileSync(path.join(outside, 'codex-quota.json'), JSON.stringify({ primary: { maxResetAt: 9999999999 } }));

  try { fs.symlinkSync(outside, spend, process.platform === 'win32' ? 'junction' : 'dir'); } catch {
    t.skip('directory links are unavailable on this host');

    return;
  }

  const url = pathToFileURL(path.resolve('src/cost/codex.mjs')).href;

  const code = `
    import fs from 'node:fs';
    const original = fs.lstatSync;
    let reachedState = 0;
    fs.lstatSync = function(file, ...args) {
      if (String(file).endsWith('codex-quota.json')) reachedState++;
      return original.call(this, file, ...args);
    };
    const { createCodexSpend } = await import(${JSON.stringify(url)});
    try { createCodexSpend({ home: process.env.BLACKBRAKE_HOME, root: process.env.CODEX_HOME, notifier: () => {} }); } catch {}
    process.stdout.write(JSON.stringify({ reachedState }));
  `;

  const env = { ...process.env, HOME: home, USERPROFILE: home, CODEX_HOME: path.join(home, '.codex', 'sessions'), BLACKBRAKE_HOME: path.join(home, '.bb'), BLACKBRAKE_NO_WINDOW: '1' };
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', code], { env, encoding: 'utf8' });

  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).reachedState, 0);
});

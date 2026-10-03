// F5.3 cross-review regressions: spend signals never hide a security reason, never answer on an
// event that cannot ask, and never follow a transcript path the hook does not own.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import { summarizeHistory, tailTranscript } from '../src/cost/live.mjs';
import { usageCost } from '../src/cost/prices.mjs';
import { setSpendBaseline } from '../src/guard/spend-state.mjs';
import { getSession, sessionHash, setMode } from '../src/guard/state.mjs';
import { liveWindowRunning, systemProgram } from '../src/guard/window.mjs';

const isolated = (home, extra = {}) => ({ ...process.env, HOME: home, USERPROFILE: home, BLACKBRAKE_HOME: home, BLACKBRAKE_NO_WINDOW: '1', BLACKBRAKE_LANG: 'en', ...extra });

const hook = (env) => (event, input) => {
  const result = spawnSync(process.execPath, ['src/guard/hook.mjs', event], { cwd: path.resolve('.'), env, input: JSON.stringify(input), encoding: 'utf8' });

  assert.equal(result.status, 0, result.stderr);

  return result.stdout ? JSON.parse(result.stdout) : null;
};

test('loop-ask-keeps-the-security-reason', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-review-reason-'));
  const run = hook(isolated(home));
  const read = { session_id: 'review-session', tool_name: 'Read', tool_input: { file_path: path.join(home, '.ssh', 'id_rsa') } };

  setMode('protect', home);
  run('UserPromptSubmit', { session_id: 'review-session', prompt: 'fixture prompt' });
  run('PreToolUse', read);
  run('PreToolUse', read);
  const third = run('PreToolUse', read);

  assert.equal(third.hookSpecificOutput.permissionDecision, 'ask');
  assert.match(third.hookSpecificOutput.permissionDecisionReason, /id_rsa; its contents would be sent/);
  assert.match(third.hookSpecificOutput.permissionDecisionReason, /same call was requested 3 times/);
});

test('cost-ask-waits-for-an-event-that-can-ask', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-review-ask-'));
  const claude = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-review-claude-'));
  const project = path.join(claude, 'projects', 'fixture');
  const transcript = path.join(project, 'session.jsonl');
  const run = hook(isolated(home, { CLAUDE_CONFIG_DIR: claude }));
  const answer = { requestId: 'fixture-request', message: { id: 'fixture-response', role: 'assistant', model: 'claude-sonnet-5', content: [], usage: { input_tokens: 10_000, output_tokens: 500 } } };

  fs.mkdirSync(project, { recursive: true });
  fs.writeFileSync(transcript, '');
  setMode('protect', home);
  setSpendBaseline('claude', { n: 30, p50: 0.000001, p90: 0.000002, ready: true }, home);
  run('UserPromptSubmit', { session_id: 'ask-session', transcript_path: transcript, prompt: 'fixture prompt' });
  fs.appendFileSync(transcript, `${JSON.stringify(answer)}\n`);

  // PostToolUse and Stop cannot ask: the crossing is kept for the next tool call.
  const post = run('PostToolUse', { session_id: 'ask-session', transcript_path: transcript, tool_name: 'Read', tool_input: { file_path: 'fixture.txt' }, tool_response: 'fixture' });
  assert.equal(post?.hookSpecificOutput?.permissionDecision, undefined);
  const stop = run('Stop', { session_id: 'ask-session', transcript_path: transcript });
  assert.equal(stop?.hookSpecificOutput?.permissionDecision, undefined);

  const pre = run('PreToolUse', { session_id: 'ask-session', transcript_path: transcript, tool_name: 'Read', tool_input: { file_path: 'fixture.txt' } });
  assert.equal(pre.hookSpecificOutput.permissionDecision, 'ask');
  assert.match(pre.hookSpecificOutput.permissionDecisionReason, /local p90/);
});

test('tail-never-follows-links-or-remote-paths', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-review-root-'));
  const real = path.join(root, 'real');
  const linked = path.join(root, 'linked');

  fs.mkdirSync(real);
  fs.writeFileSync(path.join(real, 'session.jsonl'), '{"fixture":1}\n');
  // A junction needs no privilege on Windows and is a symlink elsewhere; both count as links.
  fs.symlinkSync(real, linked, process.platform === 'win32' ? 'junction' : 'dir');

  assert.throws(() => tailTranscript(path.join(linked, 'session.jsonl'), { roots: [root] }), /Untrusted/);
  assert.throws(() => tailTranscript('\\\\fixture-host\\share\\session.jsonl', { roots: [root] }), /Untrusted/);
  assert.throws(() => tailTranscript('//fixture-host/share/session.jsonl', { roots: [root] }), /Untrusted/);
  assert.throws(() => tailTranscript(path.join(root, '..', 'elsewhere.jsonl'), { roots: [root] }), /Untrusted/);
  assert.throws(() => tailTranscript(real, { roots: [root] }), /regular file/);
  assert.deepEqual(tailTranscript(path.join(real, 'session.jsonl'), { roots: [root] }).records, [{ fixture: 1 }]);
});

test('tail-skips-a-line-longer-than-one-read', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-review-long-'));
  const file = path.join(root, 'session.jsonl');

  fs.writeFileSync(file, `{"big":"${'x'.repeat(100)}"}\n{"after":1}\n`);
  let state = {};
  const seen = [];

  for (let i = 0; i < 20 && !seen.length; i++) {
    const tailed = tailTranscript(file, { roots: [root], state, maxBytes: 32 });

    state = tailed.state;
    seen.push(...tailed.records);
  }

  assert.deepEqual(seen, [{ after: 1 }]);
});

test('window-query-runs-only-the-system-powershell', () => {
  let asked = null;

  liveWindowRunning({ platform: 'win32', find: (name, options) => { asked = { name, options };

 return null; } });
  assert.equal(asked.name, 'powershell.exe');
  assert.doesNotMatch(systemProgram('powershell.exe', { ...asked.options, env: {}, has: () => true, home: () => 'C:\\Users\\fixture' }), /WindowsApps/);
});

test('security-hook-does-not-load-spend-code-on-a-plain-call', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-review-graph-'));
  const log = path.join(home, 'modules.txt');
  const loader = path.join(home, 'loader.mjs');
  const register = path.join(home, 'register.mjs');

  fs.writeFileSync(loader, `import fs from 'node:fs';\nexport async function resolve(spec, ctx, next) { const r = await next(spec, ctx); fs.appendFileSync(${JSON.stringify(log)}, r.url + '\\n'); return r; }\n`);
  fs.writeFileSync(register, `import { register } from 'node:module';\nregister(${JSON.stringify(pathToFileURL(loader).href)});\n`);

  const result = spawnSync(process.execPath, ['--import', pathToFileURL(register).href, 'src/guard/hook.mjs', 'PreToolUse'], {
    cwd: path.resolve('.'), env: isolated(home), input: JSON.stringify({ session_id: 'graph-session', tool_name: 'Read', tool_input: { file_path: 'fixture.txt' } }), encoding: 'utf8',
  });

  assert.equal(result.status, 0, result.stderr);
  const loaded = fs.readFileSync(log, 'utf8');

  assert.match(loaded, /src\/guard\/policy\.mjs/);
  assert.doesNotMatch(loaded, /src\/cost\/|src\/load\/inventory\.mjs|spend-hook\.mjs/);
});

test('corrupt-spend-state-never-changes-a-security-decision', () => {
  const decide = (corrupt, transcriptPath) => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-review-corrupt-'));
    const claude = path.join(home, 'claude');
    const run = hook(isolated(home, { CLAUDE_CONFIG_DIR: claude }));
    const input = { session_id: 'corrupt-session', transcript_path: transcriptPath?.(claude), tool_name: 'Read', tool_input: { file_path: path.join(home, '.ssh', 'id_rsa') } };

    fs.mkdirSync(path.join(claude, 'projects', 'fixture'), { recursive: true });
    setMode('protect', home);

    if (corrupt) {
      fs.mkdirSync(path.join(home, 'spend', 'loops'), { recursive: true });
      fs.mkdirSync(path.join(home, 'sessions'), { recursive: true });
      fs.writeFileSync(path.join(home, 'spend', 'baseline.json'), '{"claude":');
      fs.writeFileSync(path.join(home, 'spend', 'key'), 'not a key');
      fs.writeFileSync(path.join(home, 'spend', 'loops', `${sessionHash('corrupt-session')}.jsonl`), '{"at":"x"}\n\u0000garbage');
      fs.writeFileSync(path.join(home, 'sessions', `${sessionHash('corrupt-session')}.json`), JSON.stringify({ spend: { open: { cost: 'NaN', responses: -1 }, tail: { offset: -5, identity: 3 }, responses: 'garbage' } }));
    }

    return JSON.parse(JSON.stringify(run('PreToolUse', input)).replaceAll(JSON.stringify(home).slice(1, -1), 'HOME'));
  };

  const clean = decide(false);

  assert.equal(clean.hookSpecificOutput.permissionDecision, 'ask');

  for (const transcriptPath of [undefined, (c) => path.join(c, 'projects'), (c) => path.join(c, 'projects', 'fixture', 'missing.jsonl'), () => '\\\\fixture-host\\share\\s.jsonl', () => 'relative.jsonl']) {
    assert.deepEqual(decide(true, transcriptPath), clean);
    assert.deepEqual(decide(false, transcriptPath), clean);
  }
});

test('history-cost-counts-once-prices-1h-at-2x-and-ignores-injected-turns', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-review-history-'));
  const reply = (id, usage) => ({ id, role: 'assistant', model: 'claude-sonnet-5', content: [], usage });
  const cached = { input_tokens: 0, output_tokens: 0, cache_read_input_tokens: 0, cache_creation_input_tokens: 1000, cache_creation: { ephemeral_5m_input_tokens: 0, ephemeral_1h_input_tokens: 1000 } };
  const plain = { input_tokens: 1000, output_tokens: 0, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 };
  const rows = [];

  // 1h cache writes cost 2x input; 5 min writes 1.25x (sonnet-5 input: $2/MTok).
  assert.equal(usageCost(cached, 'claude-sonnet-5'), 1000 * 2 * 2 / 1e6);
  assert.equal(usageCost({ ...cached, cache_creation: { ephemeral_5m_input_tokens: 1000, ephemeral_1h_input_tokens: 0 } }, 'claude-sonnet-5'), 1000 * 2 * 1.25 / 1e6);

  for (let i = 0; i < 30; i++) {
    const at = (n) => new Date(i * 10_000 + n).toISOString();

    rows.push({ timestamp: at(0), message: { role: 'user', content: `fixture ${i}` } });
    rows.push({ timestamp: at(1), requestId: `req-a-${i}`, message: reply(`a-${i}`, cached) });
    rows.push({ timestamp: at(2), requestId: `req-a-${i}`, message: reply(`a-${i}`, cached) });
    rows.push({ timestamp: at(3), message: { role: 'user', content: [{ type: 'tool_result', content: 'fixture' }] } });
    rows.push({ timestamp: at(4), message: { role: 'user', content: '[Subagent hand-back] fixture' } });
    rows.push({ timestamp: at(5), message: { role: 'user', content: 'Base directory for this skill: fixture' } });
    rows.push({ timestamp: at(6), requestId: `req-b-${i}`, message: reply(`b-${i}`, plain) });
  }

  fs.writeFileSync(path.join(root, 'session.jsonl'), `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`);
  const summary = await summarizeHistory({ root, harness: 'claude' });
  const perEpisode = usageCost(cached, 'claude-sonnet-5') + usageCost(plain, 'claude-sonnet-5');

  assert.equal(summary.episodes, 30);
  assert.ok(Math.abs(summary.baseline.p50 - perEpisode) < 1e-12);
  assert.ok(Math.abs(summary.baseline.p90 - perEpisode) < 1e-12);
});

test('hook-injected-prompt-does-not-split-the-episode', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-review-injected-'));
  const run = hook(isolated(home));

  run('UserPromptSubmit', { session_id: 'injected-session', prompt: 'fixture prompt' });
  const started = getSession('injected-session', home).spend.open.start;

  run('UserPromptSubmit', { session_id: 'injected-session', prompt: '[Subagent hand-back] fixture' });
  assert.equal(getSession('injected-session', home).spend.open.start, started);
  assert.equal(fs.existsSync(path.join(home, 'spend', 'episodes.jsonl')), false);
});

test('first-sight-of-a-long-transcript-starts-at-its-end', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-review-resume-'));
  const claude = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-review-claude-'));
  const project = path.join(claude, 'projects', 'fixture');
  const transcript = path.join(project, 'session.jsonl');
  const run = hook(isolated(home, { CLAUDE_CONFIG_DIR: claude }));
  const old = [];

  // More than one read (1 MiB) of earlier history: none of it belongs to the live episode.
  for (let i = 0; old.join('\n').length < 3 * 1024 * 1024; i++) {
    old.push(JSON.stringify({ requestId: `old-${i}`, message: { id: `old-${i}`, role: 'assistant', model: 'claude-sonnet-5', content: [{ type: 'text', text: 'x'.repeat(2000) }], usage: { input_tokens: 1000, output_tokens: 10 } } }));
  }

  fs.mkdirSync(project, { recursive: true });
  fs.writeFileSync(transcript, `${old.join('\n')}\n`);
  run('SessionStart', { session_id: 'resume-live', transcript_path: transcript });
  run('UserPromptSubmit', { session_id: 'resume-live', transcript_path: transcript, prompt: 'fixture prompt' });

  for (let i = 0; i < 4; i++) run('PreToolUse', { session_id: 'resume-live', transcript_path: transcript, tool_name: 'Read', tool_input: { file_path: `fixture-${i}.txt` } });

  const open = getSession('resume-live', home).spend.open;

  assert.equal(open.responses, 0);
  assert.equal(open.cost, 0);

  // An episode opened before any transcript was seen does not read it from the start either.
  run('UserPromptSubmit', { session_id: 'late-transcript', prompt: 'fixture prompt' });
  run('PreToolUse', { session_id: 'late-transcript', transcript_path: transcript, tool_name: 'Read', tool_input: { file_path: 'fixture.txt' } });
  run('PreToolUse', { session_id: 'late-transcript', transcript_path: transcript, tool_name: 'Read', tool_input: { file_path: 'fixture-2.txt' } });
  assert.equal(getSession('late-transcript', home).spend.open.responses, 0);
});

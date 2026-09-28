// F5.3 cross-review regressions: spend signals never hide a security reason, never answer on an
// event that cannot ask, and never follow a transcript path the hook does not own.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import { tailTranscript } from '../src/cost/live.mjs';
import { setSpendBaseline } from '../src/guard/spend-state.mjs';
import { setMode } from '../src/guard/state.mjs';
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

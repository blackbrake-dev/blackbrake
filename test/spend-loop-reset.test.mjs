import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { getSession, sessionHash, setMode, setSession } from '../src/guard/state.mjs';

const fixture = () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-loop-edit-'));
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-edit-target-')), 'fixture.txt');
  const env = { ...process.env, HOME: home, USERPROFILE: home, BLACKBRAKE_HOME: home, BLACKBRAKE_NO_WINDOW: '1', BLACKBRAKE_LANG: 'en' };

  const run = (event, input) => {
    const result = spawnSync(process.execPath, ['src/guard/hook.mjs', event, '--harness', 'claude'], {
      cwd: path.resolve('.'), env, input: JSON.stringify({ session_id: 'fixture-session', ...input }), encoding: 'utf8',
    });

    assert.equal(result.status, 0, result.stderr);

    return result.stdout ? JSON.parse(result.stdout) : null;
  };

  fs.writeFileSync(file, 'before');
  setMode('protect', home);
  run('UserPromptSubmit', { prompt: 'fixture prompt' });

  return { home, file, run };
};

const repeated = { tool_name: 'Bash', tool_input: { command: 'printf fixture' } };

const warned = (out) => /same call was requested 3 times/.test(out?.hookSpecificOutput?.permissionDecisionReason ?? '');

const edit = (file, tool_use_id = 'fixture-edit') => ({ tool_name: 'Edit', tool_use_id, tool_input: { file_path: file, old_string: 'before', new_string: 'after' } });

test('confirmed Claude edit clears the persisted loop window only after PostToolUse', () => {
  const { home, file, run } = fixture();

  assert.equal(warned(run('PreToolUse', repeated)), false);
  assert.equal(warned(run('PreToolUse', repeated)), false);
  const call = edit(file);

  run('PreToolUse', call);
  assert.equal(getSession('fixture-session', home).spend.pendingEdits.length, 1);
  assert.equal(warned(run('PreToolUse', repeated)), true);
  fs.writeFileSync(file, 'after');
  run('PostToolUse', { ...call, tool_response: { filePath: file, type: 'update' } });
  assert.equal(warned(run('PreToolUse', repeated)), false);
  assert.equal(warned(run('PreToolUse', repeated)), false);
  assert.equal(warned(run('PreToolUse', repeated)), true);
});

test('forged, failed and ambiguous post events do not clear loop calls', () => {
  for (const kind of ['no-pre', 'wrong-id', 'wrong-path', 'rewritten-path', 'wrong-tool', 'error', 'ambiguous', 'failure-event']) {
    const { file, run } = fixture();
    const call = edit(file);

    run('PreToolUse', repeated);
    run('PreToolUse', repeated);

    if (kind !== 'no-pre') run('PreToolUse', call);

    if (kind !== 'no-pre') fs.writeFileSync(file, 'after');

    const post = {
      ...call,
      tool_name: kind === 'wrong-tool' ? 'Write' : call.tool_name,
      tool_input: kind === 'rewritten-path' ? { ...call.tool_input, file_path: path.join(path.dirname(file), 'rewritten.txt') } : call.tool_input,
      tool_use_id: kind === 'wrong-id' ? 'another-edit' : call.tool_use_id,
      tool_response: kind === 'error' ? { filePath: file, type: 'error' }
        : kind === 'ambiguous' ? 'maybe edited'
          : { filePath: kind === 'wrong-path' ? path.join(path.dirname(file), 'elsewhere.txt')
            : kind === 'rewritten-path' ? path.join(path.dirname(file), 'rewritten.txt') : file, type: 'update' },
    };

    run(kind === 'failure-event' ? 'PostToolUseFailure' : 'PostToolUse', post);
    assert.equal(warned(run('PreToolUse', repeated)), true, kind);
  }
});

test('duplicated pending state cannot reset twice from a repeated post event', () => {
  const { home, file, run } = fixture();
  const call = edit(file);

  run('PreToolUse', repeated);
  run('PreToolUse', repeated);
  run('PreToolUse', call);
  const session = getSession('fixture-session', home);

  setSession('fixture-session', { spend: { ...session.spend, pendingEdits: [session.spend.pendingEdits[0], session.spend.pendingEdits[0]] } }, home);
  fs.writeFileSync(file, 'after');
  run('PostToolUse', { ...call, tool_response: { filePath: file, type: 'update' } });
  run('PreToolUse', repeated);
  run('PreToolUse', repeated);
  run('PostToolUse', { ...call, tool_response: { filePath: file, type: 'update' } });
  assert.equal(warned(run('PreToolUse', repeated)), true);
});

test('relative, UNC and device edit paths cannot create pending evidence', () => {
  const { home, run } = fixture();

  for (const file of ['relative.txt', '//host/share/file.txt', '\\\\?\\C:\\file.txt']) {
    run('PreToolUse', edit(file));
    assert.equal(getSession('fixture-session', home).spend.pendingEdits?.length ?? 0, 0, file);
  }
});

test('reads and arbitrary shell commands never clear the window despite a success-shaped result', () => {
  for (const tool_name of ['Read', 'Bash']) {
    const { file, run } = fixture();
    const call = { tool_name, tool_use_id: 'fixture-read', tool_input: tool_name === 'Read' ? { file_path: file } : { command: 'printf different' } };

    run('PreToolUse', repeated);
    run('PreToolUse', repeated);
    run('PreToolUse', call);
    fs.writeFileSync(file, 'after');
    run('PostToolUse', { ...call, tool_response: { filePath: file, type: 'update' } });
    assert.equal(warned(run('PreToolUse', repeated)), true, tool_name);
  }
});

test('an interleaved confirmed edit resets only its active session', () => {
  const { file, run } = fixture();
  const call = edit(file);

  run('UserPromptSubmit', { session_id: 'other-session', prompt: 'other fixture' });
  run('PreToolUse', { ...repeated, session_id: 'other-session' });
  run('PreToolUse', { ...repeated, session_id: 'other-session' });
  run('PreToolUse', repeated);
  run('PreToolUse', repeated);
  run('PreToolUse', call);
  fs.writeFileSync(file, 'after');
  run('PostToolUse', { ...call, tool_response: { filePath: file, type: 'update' } });
  assert.equal(warned(run('PreToolUse', repeated)), false);
  assert.equal(warned(run('PreToolUse', repeated)), false);
  assert.equal(warned(run('PreToolUse', repeated)), true);
  assert.equal(warned(run('PreToolUse', { ...repeated, session_id: 'other-session' })), true);
});

test('two interleaved edits keep their separate pending evidence', () => {
  const { file, run } = fixture();
  const second = path.join(path.dirname(file), 'second.txt');
  const firstCall = edit(file, 'first-edit');
  const secondCall = edit(second, 'second-edit');

  fs.writeFileSync(second, 'before');
  run('PreToolUse', repeated);
  run('PreToolUse', repeated);
  run('PreToolUse', firstCall);
  run('PreToolUse', secondCall);
  run('PostToolUseFailure', { ...secondCall, tool_response: { filePath: second, type: 'error' } });
  fs.writeFileSync(file, 'after');
  run('PostToolUse', { ...firstCall, tool_response: { filePath: file, type: 'update' } });
  assert.equal(warned(run('PreToolUse', repeated)), false);
});

test('blocked edit intent and a later forged success do not clear the window', () => {
  const { home, run } = fixture();
  const blocked = edit(path.join(home, 'protected.txt'));

  run('PreToolUse', repeated);
  run('PreToolUse', repeated);
  const denial = run('PreToolUse', blocked);

  assert.equal(denial.hookSpecificOutput.permissionDecision, 'deny');
  fs.writeFileSync(blocked.tool_input.file_path, 'after');
  run('PostToolUse', { ...blocked, tool_response: { filePath: blocked.tool_input.file_path, type: 'create' } });
  assert.equal(warned(run('PreToolUse', repeated)), true);
});

test('confirmed Write creation clears a window across hook invocations', () => {
  const { file, run } = fixture();
  const target = path.join(path.dirname(file), 'created.txt');
  const write = { tool_name: 'Write', tool_use_id: 'fixture-write', tool_input: { file_path: target, content: 'fixture' } };

  run('PreToolUse', repeated);
  run('PreToolUse', repeated);
  run('PreToolUse', write);
  fs.writeFileSync(target, 'fixture');
  run('PostToolUse', { ...write, tool_response: { filePath: target, type: 'create' } });
  assert.equal(warned(run('PreToolUse', repeated)), false);
  assert.equal(warned(run('PreToolUse', repeated)), false);
  assert.equal(warned(run('PreToolUse', repeated)), true);
});

test('Claude Edit accepts a structured patch result without a type discriminator', () => {
  const { file, run } = fixture();
  const call = edit(file);

  run('PreToolUse', repeated);
  run('PreToolUse', repeated);
  run('PreToolUse', call);
  fs.writeFileSync(file, 'after');
  run('PostToolUse', { ...call, tool_response: { filePath: file, structuredPatch: [{ oldStart: 1, newStart: 1 }] } });
  assert.equal(warned(run('PreToolUse', repeated)), false);
  assert.equal(warned(run('PreToolUse', repeated)), false);
  assert.equal(warned(run('PreToolUse', repeated)), true);
});

test('empty or contradictory edit results do not clear calls', () => {
  for (const tool_response of [
    { structuredPatch: [] },
    { structuredPatch: [], type: 'error' },
    { structuredPatch: [{ oldStart: 1, newStart: 1 }], type: 'error' },
    { type: 'update', success: 0 },
  ]) {
    const { file, run } = fixture();
    const call = edit(file);

    run('PreToolUse', repeated);
    run('PreToolUse', repeated);
    run('PreToolUse', call);
    run('PostToolUse', { ...call, tool_response: { filePath: file, ...tool_response } });
    assert.equal(warned(run('PreToolUse', repeated)), true, JSON.stringify(tool_response));
  }
});

test('the packaged Claude hook registers the events and tools used by the proof', () => {
  const config = JSON.parse(fs.readFileSync(new URL('../plugin/blackbrake/hooks/hooks.json', import.meta.url), 'utf8'));

  assert.match(config.hooks.PreToolUse[0].matcher, /Write\|Edit/);
  assert.equal(config.hooks.PreToolUse[0].hooks[0].args.at(-1), 'PreToolUse');
  assert.equal(config.hooks.PostToolUse[0].hooks[0].args.at(-1), 'PostToolUse');
  assert.equal(config.hooks.PostToolUse[0].matcher, undefined, 'all successful tools reach the hook');
  assert.equal(config.hooks.PostToolUseFailure, undefined, 'failure events are not wired as successes');
});

test('failed pending-state persistence cannot clear the loop window', (t) => {
  const { home, file, run } = fixture();
  const call = edit(file);
  const sessions = path.join(home, 'sessions');
  const moved = path.join(home, 'sessions-original');

  run('PreToolUse', repeated);
  run('PreToolUse', repeated);
  run('PreToolUse', call);
  fs.writeFileSync(file, 'after');
  fs.renameSync(sessions, moved);

  try { fs.symlinkSync(moved, sessions, process.platform === 'win32' ? 'junction' : 'dir'); }
  catch {
    fs.renameSync(moved, sessions);
    t.skip('directory link unavailable on this host');

    return;
  }

  run('PostToolUse', { ...call, tool_response: { filePath: file, type: 'update' } });
  assert.equal(warned(run('PreToolUse', repeated)), true);
});

test('edit evidence persists only an opaque hash and timestamp, never tool text or paths', () => {
  const { home, file, run } = fixture();
  const marker = 'PRIVATE_FIXTURE_CONTENT_SHOULD_NOT_APPEAR';
  const call = { ...edit(file), tool_input: { file_path: file, old_string: 'before', new_string: marker } };

  run('PreToolUse', call);
  const [pending] = getSession('fixture-session', home).spend.pendingEdits;

  assert.match(pending.proof, /^[a-f0-9]{64}$/);
  assert.deepEqual(Object.keys(pending).sort(), ['at', 'proof']);
  const stored = fs.readFileSync(path.join(home, 'sessions', `${sessionHash('fixture-session')}.json`), 'utf8');

  assert.equal(stored.includes(marker), false);
  assert.equal(stored.includes(file), false);
  assert.equal(stored.includes(call.tool_use_id), false);
  const logs = fs.readdirSync(path.join(home, 'log')).map((name) => fs.readFileSync(path.join(home, 'log', name), 'utf8')).join('');

  assert.equal(logs.includes(marker), false);
  assert.equal(logs.includes(file), false);
});

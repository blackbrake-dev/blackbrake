import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { getSession, sessionHash, setMode } from '../src/guard/state.mjs';

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
  assert.ok(getSession('fixture-session', home).spend.pendingEdit);
  assert.equal(warned(run('PreToolUse', repeated)), true);
  fs.writeFileSync(file, 'after');
  run('PostToolUse', { ...call, tool_response: { filePath: file, type: 'update' } });
  assert.equal(warned(run('PreToolUse', repeated)), false);
  assert.equal(warned(run('PreToolUse', repeated)), false);
  assert.equal(warned(run('PreToolUse', repeated)), true);
});

test('forged, failed and ambiguous post events do not clear loop calls', () => {
  for (const kind of ['no-pre', 'unchanged', 'wrong-id', 'wrong-path', 'error', 'ambiguous', 'failure-event']) {
    const { file, run } = fixture();
    const call = edit(file);

    run('PreToolUse', repeated);
    run('PreToolUse', repeated);

    if (kind !== 'no-pre') run('PreToolUse', call);

    if (!['unchanged', 'no-pre'].includes(kind)) fs.writeFileSync(file, 'after');

    const post = {
      ...call,
      tool_use_id: kind === 'wrong-id' ? 'another-edit' : call.tool_use_id,
      tool_response: kind === 'error' ? { filePath: file, type: 'error' }
        : kind === 'ambiguous' ? 'maybe edited'
          : { filePath: kind === 'wrong-path' ? path.join(path.dirname(file), 'elsewhere.txt') : file, type: 'update' },
    };

    run(kind === 'failure-event' ? 'PostToolUseFailure' : 'PostToolUse', post);
    assert.equal(warned(run('PreToolUse', repeated)), true, kind);
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
  run('PostToolUse', { ...call, tool_response: { filePath: file, structuredPatch: [] } });
  assert.equal(warned(run('PreToolUse', repeated)), false);
  assert.equal(warned(run('PreToolUse', repeated)), false);
  assert.equal(warned(run('PreToolUse', repeated)), true);
});

test('edit evidence persists only opaque hashes and metadata, never tool text or paths', () => {
  const { home, file, run } = fixture();
  const marker = 'PRIVATE_FIXTURE_CONTENT_SHOULD_NOT_APPEAR';
  const call = { ...edit(file), tool_input: { file_path: file, old_string: 'before', new_string: marker } };

  run('PreToolUse', call);
  const pending = getSession('fixture-session', home).spend.pendingEdit;

  assert.match(pending.proof, /^[a-f0-9]{64}$/);
  assert.deepEqual(Object.keys(pending).sort(), ['at', 'before', 'proof']);
  const stored = fs.readFileSync(path.join(home, 'sessions', `${sessionHash('fixture-session')}.json`), 'utf8');

  assert.equal(stored.includes(marker), false);
  assert.equal(stored.includes(file), false);
  assert.equal(stored.includes(call.tool_use_id), false);
  const logs = fs.readdirSync(path.join(home, 'log')).map((name) => fs.readFileSync(path.join(home, 'log', name), 'utf8')).join('');

  assert.equal(logs.includes(marker), false);
  assert.equal(logs.includes(file), false);
});

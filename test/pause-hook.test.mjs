// A paused blackbrake (F6.4, guard-design §6x.2): the hooks stay installed; every event gets a valid,
// neutral answer in that agent's own format, nothing is analysed or recorded (at most one "paused"
// line per session), and SessionStart says that nothing is being checked. One exception (review A,
// 2026-10-01): tampering with blackbrake itself is still refused and recorded while paused, so a
// pause cannot be used to rewrite or remove guard. Runs the real hook process, as the agents do.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const HOOK = path.join(ROOT, 'src', 'guard', 'hook.mjs');

// Deleting guard's own folder: tampering, refused in every agent, paused or not.
const TAMPER = 'rm -rf ~/.blackbrake';

// Reading a credentials file: a risky step that is not tampering (refused or asked when active).
const RISKY = 'cat ~/.aws/credentials';

const cases = (command) => [
  ['claude', 'PreToolUse', { session_id: 's1', tool_name: 'Bash', tool_input: { command } }],
  ['codex', 'PreToolUse', { session_id: 's1', tool_name: 'Bash', tool_input: { command } }],
  ['gemini', 'BeforeTool', { session_id: 's1', tool_name: 'run_shell_command', tool_input: { command } }],
  ['cursor', 'beforeShellExecution', { conversation_id: 's1', command }],
  ['copilot', 'PreToolUse', { hook_event_name: 'PreToolUse', session_id: 's1', tool_name: 'Bash', tool_input: { command } }],
  ['windsurf', 'pre_run_command', { trajectory_id: 's1', tool_info: { command_line: command } }],
  ['devin', 'PreToolUse', { session_id: 's1', tool_name: 'exec', tool_input: { command } }],
];

const PAUSED = { at: '2026-10-01T10:00:00.000Z', by: 'cli' };

function freshHome(settings = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-pause-hook-'));
  fs.writeFileSync(path.join(home, 'state.json'), JSON.stringify({ mode: 'protect', settings }));

  return home;
}

function run(home, harness, event, input) {
  const r = spawnSync(process.execPath, [HOOK, event, '--harness', harness], { input: JSON.stringify(input), encoding: 'utf8', env: { ...process.env, BLACKBRAKE_HOME: home, BLACKBRAKE_LANG: 'en', BLACKBRAKE_NO_WINDOW: '1' } });
  let json = null;

  try { json = r.stdout ? JSON.parse(r.stdout) : null; } catch { /* plain text */ }

  return { code: r.status, stdout: r.stdout, stderr: r.stderr, json };
}

const stopped = (r) => r.code === 2 || /"(deny|block|ask)"/.test(r.stdout);

const logLines = (home) => {
  const dir = path.join(home, 'log');

  if (!fs.existsSync(dir)) return [];

  return fs.readdirSync(dir).flatMap((f) => fs.readFileSync(path.join(dir, f), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)));
};

test('control: with blackbrake active, both steps are stopped in all seven agents', () => {
  for (const command of [TAMPER, RISKY]) {
    for (const [harness, event, input] of cases(command)) assert.equal(stopped(run(freshHome(), harness, event, input)), true, `${harness}: ${command}`);
  }
});

test('paused: a risky step that is not tampering gets a valid neutral answer in every agent', () => {
  for (const [harness, event, input] of cases(RISKY)) {
    const r = run(freshHome({ paused: PAUSED }), harness, event, input);
    assert.equal(r.code, 0, `${harness}: exit code`);
    assert.equal(stopped(r), false, `${harness}: not stopped while paused`);
    assert.equal(r.stderr, '', `${harness}: nothing on stderr`);

    if (r.stdout.trim()) assert.ok(r.json, `${harness}: valid JSON`);

    if (harness === 'cursor') assert.deepEqual(r.json, { permission: 'allow' });
  }
});

test('paused: tampering with blackbrake is still refused in every agent, and recorded', () => {
  for (const [harness, event, input] of cases(TAMPER)) {
    const home = freshHome({ paused: PAUSED });
    assert.equal(stopped(run(home, harness, event, input)), true, harness);
    assert.ok(logLines(home).some((e) => e.kind === 'tamper' && e.action === 'denied'), `${harness}: recorded`);
  }
});

test('paused: nothing about a neutral step is recorded; at most one "paused" line per session', () => {
  const home = freshHome({ paused: PAUSED });
  const [, event, input] = cases(RISKY)[0];

  for (let i = 0; i < 3; i++) run(home, 'claude', event, input);
  run(home, 'claude', event, { ...input, session_id: 's2' });
  const lines = logLines(home);
  assert.equal(lines.length, 2, 'one line for each of the two sessions');

  for (const e of lines) {
    assert.equal(e.kind, 'session');
    assert.equal(e.action, 'paused');
    assert.equal(e.rule, undefined);
    assert.equal(e.tool, undefined);
  }

  assert.ok(!JSON.stringify(lines).includes('credentials'), 'no command text');
});

test('paused: SessionStart tells the user what is and is not checked (Claude, Codex, Gemini, Devin)', () => {
  for (const harness of ['claude', 'codex', 'gemini', 'devin']) {
    const r = run(freshHome({ paused: PAUSED }), harness, 'SessionStart', { session_id: 's1' });
    assert.equal(r.code, 0, harness);
    assert.match(r.stdout, /blackbrake is PAUSED: only attempts to switch it off are checked; secrets and spend are not\. Resume it in your terminal with \\?"blackbrake resume\\?"\./, harness);
  }
});

test('an invalid mark is not a pause: the risky step is still stopped', () => {
  for (const paused of ['yes', true, 1, { at: 'not a date' }, { by: 'cli' }, []]) {
    const [harness, event, input] = cases(RISKY)[0];
    assert.equal(stopped(run(freshHome({ paused }), harness, event, input)), true, JSON.stringify(paused));
  }
});

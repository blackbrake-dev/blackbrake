// A paused blackbrake (F6.4, guard-design §6x.2): the hooks stay installed, but every event gets a
// valid, neutral answer in that agent's own format, nothing is analysed or recorded (at most one
// "paused" line per session), and SessionStart says that nothing is being checked. Runs the real
// hook process, as the agents do.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const HOOK = path.join(ROOT, 'src', 'guard', 'hook.mjs');

// Deleting guard's own folder: refused in every agent, in both modes, while guard is active.
const TAMPER = 'rm -rf ~/.blackbrake';

const CASES = [
  ['claude', 'PreToolUse', { session_id: 's1', tool_name: 'Bash', tool_input: { command: TAMPER } }],
  ['codex', 'PreToolUse', { session_id: 's1', tool_name: 'Bash', tool_input: { command: TAMPER } }],
  ['gemini', 'BeforeTool', { session_id: 's1', tool_name: 'run_shell_command', tool_input: { command: TAMPER } }],
  ['cursor', 'beforeShellExecution', { conversation_id: 's1', command: TAMPER }],
  ['copilot', 'PreToolUse', { hook_event_name: 'PreToolUse', session_id: 's1', tool_name: 'Bash', tool_input: { command: TAMPER } }],
  ['windsurf', 'pre_run_command', { trajectory_id: 's1', tool_info: { command_line: TAMPER } }],
  ['devin', 'PreToolUse', { session_id: 's1', tool_name: 'exec', tool_input: { command: TAMPER } }],
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

const denied = (r) => r.code === 2 || /"(deny|block)"/.test(r.stdout);

const logLines = (home) => {
  const dir = path.join(home, 'log');

  if (!fs.existsSync(dir)) return [];

  return fs.readdirSync(dir).flatMap((f) => fs.readFileSync(path.join(dir, f), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)));
};

test('control: with blackbrake active, the same step is refused in all seven agents', () => {
  for (const [harness, event, input] of CASES) {
    const home = freshHome();
    assert.equal(denied(run(home, harness, event, input)), true, harness);
  }
});

test('paused: every agent gets a valid neutral answer, nothing is decided', () => {
  for (const [harness, event, input] of CASES) {
    const home = freshHome({ paused: PAUSED });
    const r = run(home, harness, event, input);
    assert.equal(r.code, 0, `${harness}: exit code`);
    assert.equal(denied(r), false, `${harness}: not refused while paused`);
    assert.equal(r.stderr, '', `${harness}: nothing on stderr`);

    // Whatever is printed is the agent's own protocol (JSON) or nothing.
    if (r.stdout.trim()) assert.ok(r.json, `${harness}: valid JSON`);

    if (harness === 'cursor') assert.deepEqual(r.json, { permission: 'allow' });
  }
});

test('paused: nothing about the step is recorded; at most one "paused" line per session', () => {
  const home = freshHome({ paused: PAUSED });
  const [, event, input] = CASES[0];

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

  assert.ok(!JSON.stringify(lines).includes('blackbrake '), 'no command text');
});

test('paused: SessionStart tells the user that nothing is being checked (Claude, Codex, Gemini, Devin)', () => {
  for (const harness of ['claude', 'codex', 'gemini', 'devin']) {
    const home = freshHome({ paused: PAUSED });
    const r = run(home, harness, 'SessionStart', { session_id: 's1' });
    assert.equal(r.code, 0, harness);
    assert.match(r.stdout, /blackbrake is PAUSED: nothing is being checked\. Resume it in your terminal with \\?"blackbrake resume\\?"\./, harness);
  }
});

test('an invalid mark is not a pause: the step is still refused', () => {
  for (const paused of ['yes', true, 1, { at: 'not a date' }, { by: 'cli' }, []]) {
    const home = freshHome({ paused });
    const [harness, event, input] = CASES[0];
    assert.equal(denied(run(home, harness, event, input)), true, JSON.stringify(paused));
  }
});

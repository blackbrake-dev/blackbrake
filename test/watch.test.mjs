// Live alerts and the alerts window: grading, reading the log as it grows, running agents,
// notifications for high and maximum, fixed commands without a shell, once per session.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { appendLog, setSetting } from '../src/guard/state.mjs';
import { createAlertSink, createTail, eventLine, notificationCommand, runningAgents, severity, watch } from '../src/guard/watch.mjs';
import { maybeOpenWindow, systemProgram, windowCommand } from '../src/guard/window.mjs';
import { createPainter, strip } from '../src/ui/term.mjs';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bb-watch-'));

test('every event gets a level from low to maximum', () => {
  assert.equal(severity({ kind: 'tamper', action: 'denied' }), 'critical');
  assert.equal(severity({ kind: 'secret-in-prompt', action: 'warned' }), 'critical', 'a secret that went out');
  assert.equal(severity({ kind: 'secret-in-prompt', action: 'blocked' }), 'high', 'one guard stopped');
  assert.equal(severity({ kind: 'secret-in-write', action: 'warned' }), 'high');
  assert.equal(severity({ kind: 'sensitive-read', action: 'warned' }), 'medium');
  assert.equal(severity({ kind: 'sensitive-read', action: 'asked' }), 'low');
  assert.equal(severity({ kind: 'session', action: 'started' }), null, 'not an alert');
});

test('the log is read as it grows, and running agents come from recent activity', () => {
  const home = tmp();
  appendLog([{ ev: 'SessionStart', kind: 'session', action: 'started', harness: 'codex' }], 'old', home);
  const tail = createTail(home);
  assert.equal(tail.read().length, 0, 'starts at the end');
  appendLog([{ ev: 'PreToolUse', kind: 'secret-in-output', action: 'warned', harness: 'cursor', rule: 'github-pat' }], 's1', home);
  const fresh = tail.read();
  assert.equal(fresh.length, 1);
  assert.equal(tail.read().length, 0, 'nothing twice');
  const agents = runningAgents(createTail(home).read(true));
  assert.deepEqual(agents.map((a) => a.name).sort(), ['Codex', 'Cursor']);
  const line = strip(eventLine(createPainter(0), fresh[0]));
  assert.match(line, /MAXIMUM +Cursor +secret in tool output · warned · github-pat/);
});

test('high and maximum alerts notify (at most once every 5 s); the rest only show', async () => {
  const out = { text: '', write(s) { this.text += s; } };
  const notices = [];
  let clock = 0;
  const sink = createAlertSink(createPainter(0), { out, notifier: (a, b) => notices.push([a, b]), now: () => clock });
  clock = 10_000;
  sink([{ ts: '2026-01-01T10:00:00Z', kind: 'sensitive-read', action: 'warned', harness: 'gemini' }, { ts: '2026-01-01T10:00:01Z', kind: 'tamper', action: 'denied', harness: 'windsurf' }]);
  assert.deepEqual(notices, [['blackbrake · MAXIMUM', 'Windsurf: attempt to switch guard off']]);
  sink([{ ts: '2026-01-01T10:00:02Z', kind: 'secret-in-output', action: 'warned', harness: 'codex' }]);
  assert.equal(notices.length, 1, 'a burst is one notification');
  clock = 20_000;
  sink([{ ts: '2026-01-01T10:00:12Z', kind: 'secret-in-prompt', action: 'blocked', harness: 'claude' }]);
  assert.equal(notices[1][0], 'blackbrake · HIGH');
  assert.match(out.text, /MEDIUM +Gemini CLI +read of a credential file/);

  // The window itself starts with the header and the last hour.
  const home = tmp();
  const screen = { text: '', write(s) { this.text += s; } };
  await watch(createPainter(0), { home, out: screen, once: true, notifier: () => {} });
  assert.match(screen.text, /LIVE ALERTS/);
});

test('notification and window commands are fixed programs with argument lists (no shell)', () => {
  const sys = (n) => `/sys/${n}`;
  const win = notificationCommand('t"; rm -rf ~', 'b`$(x)`', 'win32', sys);
  assert.equal(win.file, '/sys/powershell.exe');
  assert.ok(!win.args.join(' ').includes('rm -rf'), 'the text travels in environment variables');
  assert.equal(win.env.BB_TITLE, 't"; rm -rf ~');
  assert.deepEqual(notificationCommand('a', 'b', 'darwin', sys).args.slice(-2), ['a', 'b']);
  assert.equal(notificationCommand('a', 'b', 'linux', sys).file, '/sys/notify-send');

  const node = 'C:\\Program Files\\nodejs\\node.exe';
  const cli = 'C:\\Users\\me\\.blackbrake\\app\\src\\guard\\watch-main.mjs';
  assert.deepEqual(windowCommand(node, cli, { platform: 'win32', find: sys }), { file: '/sys/wt.exe', args: ['-w', 'new', 'new-tab', '--title', 'blackbrake', '--tabColor', '#FF5A1F', '--suppressApplicationTitle', '--', node, cli, 'watch'] });
  assert.equal(windowCommand(node, cli, { platform: 'win32', find: (n) => (n === 'conhost.exe' ? sys(n) : null) }).file, '/sys/conhost.exe');
  assert.equal(windowCommand('/usr/bin/node', '/h/x.mjs', { platform: 'darwin', find: sys }).file, '/sys/osascript');
  assert.equal(windowCommand('/usr/bin/node', '/h/x.mjs', { platform: 'linux', find: (n) => (n === 'xterm' ? sys(n) : null) }).file, '/sys/xterm');
  assert.equal(windowCommand('/usr/bin/node', '/h/x;calc.mjs', { platform: 'win32', find: sys }), null, 'Windows Terminal would split on ";"');
});

test('programs come from system folders, never from the agent\'s PATH', () => {
  const seen = [];
  const found = systemProgram('wt.exe', { platform: 'win32', env: { LOCALAPPDATA: 'C:\\Users\\me\\AppData\\Local', SystemRoot: 'C:\\Windows', PATH: 'C:\\repo\\evil' }, has: (f) => { seen.push(f);

 return f.endsWith('wt.exe'); } });
  assert.match(found, /WindowsApps[\\/]wt\.exe$/);
  assert.ok(seen.every((f) => !f.includes('evil')), 'PATH is not consulted');
  assert.equal(systemProgram('xterm', { platform: 'linux', has: (f) => f === '/usr/bin/xterm' }), '/usr/bin/xterm');
});

test('the alerts window opens once per session, never twice at once, and can be turned off', () => {
  const home = tmp();
  const calls = [];
  const spawner = (file, args) => { calls.push([file, args]);

 return { on() {}, unref() {} }; };

  // The terminal to open is given: a CI runner may have none installed.
  const command = (node, cli) => ({ file: '/usr/bin/some-terminal', args: [node, cli, 'watch'] });
  const env = { DISPLAY: ':0' };
  assert.equal(maybeOpenWindow('s1', { home, env, cli: '/h/watch-main.mjs', spawner, command }), true);
  assert.equal(maybeOpenWindow('s1', { home, env, cli: '/h/watch-main.mjs', spawner, command }), false, 'same session');
  assert.equal(maybeOpenWindow('s2', { home, env, cli: '/h/watch-main.mjs', spawner, command }), false, 'another hook right after: the claim is recent');
  assert.equal(calls.length, 1);
  setSetting('window', false, home);
  fs.rmSync(path.join(home, 'window.claim'));
  assert.equal(maybeOpenWindow('s3', { home, env, cli: '/h/watch-main.mjs', spawner, command }), false, 'off');
  assert.equal(maybeOpenWindow('s4', { home: tmp(), env: { CI: '1', DISPLAY: ':0' }, cli: '/h/w.mjs', spawner, command }), true, 'an agent setting CI for its tools does not hide the window');
});

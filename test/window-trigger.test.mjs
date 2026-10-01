// When the alerts window opens (F6.5): decision order, SSH, Cursor background agents, the 10-minute
// cooldown (mtime of window.last) and the session mark. No real window is ever opened: the spawner
// and the terminal command are given.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { getSession, setSession, setSetting } from '../src/guard/state.mjs';
import { maybeOpenWindow, WINDOW_COOLDOWN_MS, windowSkipReason } from '../src/guard/window.mjs';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bb-wt-'));

const NOW = Date.now();

function harness() {
  const calls = [];

  const spawner = (file, args) => { calls.push([file, args]);

 return { on() {}, unref() {} }; };

  const command = () => ({ file: 'terminal', args: [] });

  return { calls, open: (id, home, extra = {}) => maybeOpenWindow(id, { home, env: { DISPLAY: ':0' }, platform: 'linux', cli: '/h/w.mjs', spawner, command, running: () => false, ...extra }) };
}

test('the first matching rule decides, in the order paused, off, display, ssh, background', () => {
  const home = tmp();
  const all = { env: { SSH_TTY: '/dev/pts/1' }, platform: 'darwin', background: true, home };
  assert.equal(windowSkipReason('s', all), 'ssh');
  assert.equal(windowSkipReason('s', { ...all, platform: 'linux' }), 'display', 'linux without a display');
  assert.equal(windowSkipReason('s', { ...all, env: {} }), 'background');
  assert.equal(windowSkipReason('s', { ...all, env: { BLACKBRAKE_NO_WINDOW: '1', SSH_TTY: 'x' } }), 'off');
  setSetting('paused', { at: new Date().toISOString(), by: 'cli' }, home);
  assert.equal(windowSkipReason('s', { ...all, env: { BLACKBRAKE_NO_WINDOW: '1' } }), 'paused');
  setSetting('window', false, home);
  assert.equal(windowSkipReason('s', { home }), 'paused', 'paused beats off');
});

test('a malformed pause mark does not count as paused', () => {
  const home = tmp();

  for (const bad of ['yes', true, { at: 'not a date' }, [], null]) {
    setSetting('paused', bad, home);
    assert.equal(windowSkipReason('s', { home, env: {}, platform: 'win32' }), null, JSON.stringify(bad));
  }
});

test('SSH: darwin and win32 do not open; Linux with a display does', () => {
  const home = tmp();

  for (const v of ['SSH_CONNECTION', 'SSH_CLIENT', 'SSH_TTY']) {
    for (const platform of ['darwin', 'win32']) assert.equal(windowSkipReason('s', { home, platform, env: { [v]: '1' } }), 'ssh', `${platform} ${v}`);
    assert.equal(windowSkipReason('s', { home, platform: 'linux', env: { [v]: '1', DISPLAY: 'localhost:10.0' } }), null, `linux ${v}`);
  }

  assert.equal(windowSkipReason('s', { home, platform: 'win32', env: {} }), null);
});

test('a Cursor background agent opens nothing and does not mark the session', () => {
  const home = tmp();
  const h = harness();
  assert.equal(h.open('s1', home, { background: true }), false);
  assert.equal(h.calls.length, 0);
  assert.equal(getSession('s1', home).windowOpened, undefined);
  assert.equal(h.open('s1', home, { background: false }), true);
});

test('opening writes window.last and the cooldown blocks a different session for 10 minutes', () => {
  const home = tmp();
  const h = harness();
  const last = path.join(home, 'window.last');
  assert.equal(h.open('a', home), true);
  assert.ok(fs.existsSync(last));
  assert.equal(fs.readFileSync(last, 'utf8'), '', 'only the mtime counts');

  fs.rmSync(path.join(home, 'window.claim'), { force: true });
  assert.equal(h.open('b', home), false);
  assert.equal(windowSkipReason('c', { home, env: { DISPLAY: ':0' }, platform: 'linux', now: NOW + 1 }), 'cooldown');

  // Just after the cooldown (judged against the file's own time), a new session opens again.
  const mtime = fs.statSync(last).mtimeMs;
  assert.equal(windowSkipReason('c', { home, env: { DISPLAY: ':0' }, platform: 'linux', now: mtime + WINDOW_COOLDOWN_MS + 1 }), null);
  assert.equal(windowSkipReason('c', { home, env: { DISPLAY: ':0' }, platform: 'linux', now: mtime + WINDOW_COOLDOWN_MS - 1000 }), 'cooldown');
  const old = new Date(Date.now() - WINDOW_COOLDOWN_MS - 5000);
  fs.utimesSync(last, old, old);
  assert.equal(h.open('c', home), true);
  assert.equal(h.calls.length, 2);
});

test('a session held back by the cooldown is marked and never retries', () => {
  const home = tmp();
  const h = harness();
  assert.equal(h.open('a', home), true);
  fs.rmSync(path.join(home, 'window.claim'), { force: true });
  assert.equal(h.open('b', home), false);
  const s = getSession('b', home);
  assert.equal(s.windowSkipped, 'cooldown');
  assert.ok(Number.isFinite(Date.parse(s.windowOpened)));

  // Ten minutes later, the same session does not open a window half-way through.
  const old = new Date(Date.now() - WINDOW_COOLDOWN_MS - 5000);
  fs.utimesSync(path.join(home, 'window.last'), old, old);
  assert.equal(h.open('b', home), false);
  assert.equal(windowSkipReason('b', { home, env: { DISPLAY: ':0' }, platform: 'linux' }), 'session');
  assert.equal(h.calls.length, 1);
});

test('other skips do not mark the session or touch window.last; a window already open does not start the cooldown', () => {
  const home = tmp();
  const h = harness();
  assert.equal(h.open('a', home, { env: {}, platform: 'linux' }), false, 'no display');
  assert.equal(getSession('a', home).windowOpened, undefined);
  assert.equal(h.open('a', home, { running: () => true }), false);
  assert.ok(getSession('a', home).windowOpened);
  assert.equal(fs.existsSync(path.join(home, 'window.last')), false);
  setSession('z', { windowOpened: 'x' }, home);
  assert.equal(windowSkipReason('z', { home, env: { DISPLAY: ':0' }, platform: 'linux' }), 'session');
});

// One live alerts window per user: a window opened by any copy of guard (a checkout, a relocated
// BLACKBRAKE_HOME) is found in the process table, so no hook opens a second one. And blackbrake's
// own tests never open a real window on the developer's desktop.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { liveWindowRunning, maybeOpenWindow } from '../src/guard/window.mjs';

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));

test('every test that starts the hook or the window keeps real windows closed', () => {
  const offenders = fs.readdirSync(TEST_DIR).filter((f) => f.endsWith('.mjs')).filter((f) => {
    const src = fs.readFileSync(path.join(TEST_DIR, f), 'utf8');

    return /['"`][^'"`]*(hook|watch-main)\.mjs['"`]/.test(src) && /spawn(Sync)?\(/.test(src) && !src.includes('BLACKBRAKE_NO_WINDOW');
  });

  assert.deepEqual(offenders, []);
});

test('a live alerts window from any guard copy stops a second one from opening', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-win-'));
  const calls = [];

  const spawner = (...args) => { calls.push(args);

 return { on() {}, unref() {} }; };

  const command = () => ({ file: 'terminal', args: [] });
  const env = { DISPLAY: ':0' };

  try {
    assert.equal(maybeOpenWindow('s1', { home, env, cli: '/h/watch-main.mjs', spawner, command, running: (options) => {
      assert.equal(options.home, home);
      assert.equal(options.platform, process.platform);

      return true;
    } }), false);
    assert.equal(calls.length, 0, 'no terminal is started');
    assert.equal(maybeOpenWindow('s2', { home, env, cli: '/h/watch-main.mjs', spawner, command, running: () => false }), true);
    assert.equal(calls.length, 1);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('the process table tells the alerts window from the background watcher on each system', () => {
  const self = process.pid;
  const linux = (procs) => liveWindowRunning({ home: '/r', platform: 'linux', readdir: () => Object.keys(procs), read: (f) => procs[f.split('/')[2]] });

  assert.equal(linux({ 101: 'blackbrake watch\0\0' }), true, 'Linux: the window after its title rewrite');
  assert.equal(linux({ 102: '/usr/bin/node\0/r/app/src/guard/watch-main.mjs\0watch\0' }), true, 'Linux: before it');
  assert.equal(linux({ 103: 'blackbrake watcher\0', 104: '/usr/bin/node\0/h/watch-main.mjs\0--background\0' }), false, 'Linux: only the background watcher');
  assert.equal(linux({ [self]: 'blackbrake watch\0' }), false, 'this process is not another window');
  assert.equal(linux({ 105: 'vim\0blackbrake watch notes\0' }), false, 'an argument is not a window');

  const mac = (out) => liveWindowRunning({ platform: 'darwin', find: () => '/bin/ps', run: () => ({ stdout: out }) });

  assert.equal(mac('  200 blackbrake watch\n  201 /bin/zsh\n'), true, 'macOS: the window');
  assert.equal(mac(`  202 blackbrake watcher\n  ${self} blackbrake watch\n`), false, 'macOS: watcher and this process only');

  const win = (out) => liveWindowRunning({ home: 'C:/r', platform: 'win32', find: () => 'powershell.exe', run: () => ({ stdout: out }) });

  assert.equal(win('300\t"C:\\node.exe" "C:\\r\\app\\src\\guard\\watch-main.mjs" watch\r\n'), true, 'Windows: the window');
  assert.equal(win('301\t"C:\\node.exe" "C:\\h\\app\\src\\guard\\watch-main.mjs" --background\r\n'), false, 'Windows: the background watcher');
  assert.equal(win(''), false, 'Windows: nothing running');
  assert.equal(liveWindowRunning({ platform: 'win32', find: () => null }), false, 'no process table: the per-folder check still applies');
});

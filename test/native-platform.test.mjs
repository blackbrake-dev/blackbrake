// Native operating-system smoke tests for the background watcher. These deliberately exercise the
// real macOS/Linux process and filesystem branches, but use an isolated home and never touch the
// runner's agent configuration. A hosted runner cannot prove that a human saw a notification or
// that a desktop login launched the item; those checks stay in the manual validation playbook.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { buildRuntime } from '../src/guard/agents.mjs';
import { installAutostart, isWatcherProcess, removeAutostart } from '../src/guard/autostart.mjs';
import { isBackgroundRunning } from '../src/guard/background.mjs';

const POSIX_NATIVE = process.platform === 'darwin' || process.platform === 'linux';

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(check, message, timeoutMs = 15000) {
  const end = Date.now() + timeoutMs;

  while (Date.now() < end) {
    if (check()) return;
    await wait(50);
  }

  assert.fail(message);
}

test('native macOS/Linux: login item starts the installed watcher and removal stops it', { skip: !POSIX_NATIVE, timeout: 30000 }, async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-native-'));
  const home = path.join(root, '.blackbrake');
  const config = path.join(root, '.config');

  const loginItem = process.platform === 'darwin'
    ? path.join(root, 'Library', 'LaunchAgents', 'dev.blackbrake.watch.plist')
    : path.join(config, 'autostart', 'blackbrake-watch.desktop');

  const saved = Object.fromEntries(['HOME', 'USERPROFILE', 'BLACKBRAKE_HOME', 'BLACKBRAKE_NO_WINDOW', 'BLACKBRAKE_LANG', 'XDG_CONFIG_HOME'].map((key) => [key, process.env[key]]));
  let pid = null;

  try {
    Object.assign(process.env, {
      HOME: root,
      USERPROFILE: root,
      BLACKBRAKE_HOME: home,
      BLACKBRAKE_NO_WINDOW: '1',
      BLACKBRAKE_LANG: 'en',
      XDG_CONFIG_HOME: config,
    });
    buildRuntime({ home });
    assert.equal(installAutostart({ home, file: loginItem }), loginItem);
    assert.ok(fs.lstatSync(loginItem).isFile());
    assert.equal(fs.statSync(loginItem).mode & 0o022, 0, 'the login item is not group/other writable');

    if (process.platform === 'darwin') {
      const lint = spawnSync('/usr/bin/plutil', ['-lint', loginItem], { encoding: 'utf8', timeout: 5000 });

      assert.equal(lint.status, 0, lint.stderr || lint.stdout);
    } else {
      const desktop = fs.readFileSync(loginItem, 'utf8');

      assert.match(desktop, /^\[Desktop Entry\]$/m);
      assert.match(desktop, /^Exec="[^"]+" "[^"]+" --background$/m);
    }

    const pidFile = path.join(home, 'watch-bg.pid');

    await waitFor(() => fs.existsSync(pidFile), 'the watcher did not create its pid file');
    pid = Number.parseInt(fs.readFileSync(pidFile, 'utf8'), 10);
    assert.ok(Number.isInteger(pid) && pid > 0);
    assert.equal(isBackgroundRunning(home), true);
    assert.equal(isWatcherProcess(pid), true, 'the native process table identifies blackbrake watcher');
    assert.equal(removeAutostart({ home, file: loginItem }), true);
    await waitFor(() => !isBackgroundRunning(home), 'the watcher did not stop after removing its login item');
    assert.equal(fs.existsSync(loginItem), false);
  } finally {
    if (pid && isWatcherProcess(pid)) {
      try { process.kill(pid, 'SIGTERM'); } catch { /* already stopped */ }
    }

    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }

    fs.rmSync(root, { recursive: true, force: true });
  }
});

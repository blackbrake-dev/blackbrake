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

// watch-main.mjs sets process.title, which on Linux and macOS rewrites the argument area: the
// process table then shows the title, not the script path. Checked on every platform by feeding
// what /proc and ps report.
test('watcher identification survives the process title rewrite on Linux and macOS', () => {
  const linux = (cmdline) => isWatcherProcess(42, { platform: 'linux', read: () => cmdline });
  const mac = (command) => isWatcherProcess(42, { platform: 'darwin', find: () => '/bin/ps', run: () => ({ stdout: `${command}\n` }) });

  assert.equal(linux('blackbrake watcher\0\0\0'), true, 'Linux after the title rewrite');
  assert.equal(linux('/usr/bin/node\0/h/.blackbrake/app/src/guard/watch-main.mjs\0--background\0'), true, 'Linux before it');
  assert.equal(mac('blackbrake watcher'), true, 'macOS after the title rewrite');
  assert.equal(linux('/usr/bin/node\0server.js\0'), false, 'another node process is never taken for the watcher');
  assert.equal(mac('/usr/bin/vim notes.txt'), false, 'another program is never taken for the watcher');
  assert.equal(linux('blackbrake watch\0'), false, 'the alerts window is not the background watcher');
});

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
    await waitFor(() => !isWatcherProcess(pid), 'the watcher process is gone from the process table');
    assert.equal(fs.existsSync(loginItem), false);
  } finally {
    // The pid came from this test's own temporary pid file, written seconds ago by the watcher it
    // started: stop it even when identification is what failed (the first CI run leaked it that
    // way), and wait for it before deleting the folder it could otherwise recreate by logging.
    if (pid) {
      try { process.kill(pid, 'SIGTERM'); } catch { /* already stopped */ }

      const end = Date.now() + 5000;

      while (Date.now() < end && isWatcherProcess(pid)) await wait(50);
    }

    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }

    fs.rmSync(root, { recursive: true, force: true });
  }
});

// OS file formats in a fresh temporary home; process tables and signals are synthetic.
// Desktop login, notifications and real watcher shutdown remain manual N4/N5 gates.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { buildRuntime } from '../src/guard/agents.mjs';
import { installAutostart, isWatcherProcess, removeAutostart } from '../src/guard/autostart.mjs';

const POSIX_NATIVE = process.platform === 'darwin' || process.platform === 'linux';

const removeFixture = (root) => {
  assert.equal(path.dirname(root), path.resolve(os.tmpdir()));
  assert.ok(fs.existsSync(root));
  assert.notEqual(root, os.userInfo().homedir);
  fs.rmSync(root, { recursive: true, force: true });
};

// watch-main.mjs sets process.title, which on Linux and macOS rewrites the argument area: the
// process table then shows the title, not the script path. Checked on every platform by feeding
// what /proc and ps report.
test('watcher identification survives the process title rewrite on Linux and macOS', () => {
  const linux = (cmdline) => isWatcherProcess(42, { home: '/h/.blackbrake', platform: 'linux', read: () => cmdline });
  const mac = (command) => isWatcherProcess(42, { home: '/h/.blackbrake', platform: 'darwin', find: () => '/bin/ps', run: () => ({ stdout: `${command}\n` }) });

  assert.equal(linux('blackbrake watcher\0\0\0'), true, 'Linux after the title rewrite');
  assert.equal(linux('/usr/bin/node\0/h/.blackbrake/app/src/guard/watch-main.mjs\0--background\0'), true, 'Linux before it');
  assert.equal(mac('blackbrake watcher'), true, 'macOS after the title rewrite');
  assert.equal(linux('/usr/bin/node\0server.js\0'), false, 'another node process is never taken for the watcher');
  assert.equal(mac('/usr/bin/vim notes.txt'), false, 'another program is never taken for the watcher');
  assert.equal(linux('blackbrake watch\0'), false, 'the alerts window is not the background watcher');
  assert.equal(linux('vim\0blackbrake watcher notes.txt\0'), false, 'an argument that merely starts with the title is not the watcher');
  assert.equal(mac('/usr/bin/vim blackbrake watcher'), false, 'the title must lead the command line');
});

test('macOS/Linux login item format and permissions on a copy without starting a watcher', { skip: !POSIX_NATIVE }, () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-native-'));
  const home = path.join(root, '.blackbrake');
  const config = path.join(root, '.config');

  const loginItem = process.platform === 'darwin'
    ? path.join(root, 'Library', 'LaunchAgents', 'dev.blackbrake.watch.plist')
    : path.join(config, 'autostart', 'blackbrake-watch.desktop');

  try {
    buildRuntime({ home });
    assert.equal(installAutostart({ home, file: loginItem, start: false }), loginItem);
    assert.ok(fs.lstatSync(loginItem).isFile());
    assert.equal(fs.statSync(loginItem).mode & 0o022, 0, 'the login item is not group/other writable');

    if (process.platform === 'darwin') {
      const lint = spawnSync('/usr/bin/plutil', ['-lint', loginItem], { encoding: 'utf8', timeout: 5000, env: { ...process.env, BLACKBRAKE_NO_WINDOW: '1' } });

      assert.equal(lint.status, 0, lint.stderr || lint.stdout);
    } else {
      const desktop = fs.readFileSync(loginItem, 'utf8');

      assert.match(desktop, /^\[Desktop Entry\]$/m);
      assert.match(desktop, /^Exec="[^"]+" "[^"]+" --background$/m);
    }

    assert.ok(fs.existsSync(path.join(home, 'app', 'src', 'guard', 'watch-main.mjs')));
    assert.equal(fs.existsSync(path.join(home, 'watch-bg.pid')), false, 'no watcher was started');
    assert.equal(removeAutostart({ home, file: loginItem, kill: false }), true);
    assert.equal(fs.existsSync(loginItem), false);

  } finally { removeFixture(root); }
});

// F6.3: uninstall sweeps the process table instead of trusting the pid file. Checked on every
// platform with a fake table, so a planted pid file never makes it signal a foreign process.
test('removeAutostart with sweep stops the watcher without a pid file and ignores a planted one', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-sweep-'));
  const home = path.join(root, '.blackbrake');
  const file = path.join(root, 'blackbrake-watch.desktop');
  const table = new Map([[41, 'blackbrake watcher'], [42, 'node server.js'], [43, 'blackbrake watch']]);
  const signals = [];
  let report = null;

  const sweepOptions = {
    platform: 'linux',
    list: () => [...table].map(([pid, cmd]) => ({ pid, cmd })),
    commandOf: (pid) => table.get(pid) ?? null,
    kill: (pid, sig) => { signals.push(pid); table.delete(pid); assert.ok(sig); },
    sleep: () => {},
  };

  try {
    fs.mkdirSync(home, { recursive: true });
    fs.writeFileSync(file, 'Exec="node" "/h/.blackbrake/app/src/guard/watch-main.mjs" --background\n');
    // A pid file pointing at an unrelated process, and fresh enough to look alive.
    fs.writeFileSync(path.join(home, 'watch-bg.pid'), '42');

    assert.equal(removeAutostart({ home, file, sweep: true, sweepOptions, onSweep: (r) => { report = r; } }), true);
    assert.equal(fs.existsSync(file), false);
    assert.deepEqual(signals, [41], 'only the watcher: not the pid-file process, not the alerts window');
    assert.deepEqual(report.watchers, { found: [41], remaining: [] });
    assert.deepEqual(report.windows, { found: [], remaining: [] });
    assert.equal(report.launchd, 'skipped', 'a custom login item file is not the user\'s real LaunchAgent');

    removeAutostart({ home, file, sweep: true, windows: true, sweepOptions, onSweep: (r) => { report = r; } });
    assert.deepEqual(report.windows, { found: [43], remaining: [] });
    assert.ok(table.has(42), 'the foreign process is still there');
  } finally { removeFixture(root); }
});

test('a test cannot remove its copied login item by attempting to stop real processes', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-sweep-native-'));
  const home = path.join(root, '.blackbrake');
  const loginItem = path.join(root, 'autostart', 'blackbrake-watch.desktop');

  try {
    fs.mkdirSync(path.dirname(loginItem), { recursive: true });
    fs.mkdirSync(home);
    fs.writeFileSync(loginItem, 'Exec="node" "app/src/guard/watch-main.mjs" --background\n');
    fs.writeFileSync(path.join(home, 'watch-bg.pid'), '42');
    assert.throws(() => removeAutostart({ home, file: loginItem }), /refused to stop processes/);
    assert.throws(() => removeAutostart({ home, file: loginItem, sweep: true }), /refused to stop processes/);
    assert.ok(fs.existsSync(loginItem), 'the lock refuses before removing anything');
    assert.equal(removeAutostart({ home, file: loginItem, kill: false }), true);
    assert.equal(fs.existsSync(loginItem), false);
  } finally { removeFixture(root); }
});

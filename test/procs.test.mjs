// The process sweep behind uninstall and pause (src/guard/procs.mjs): classifies the command lines
// of the background watcher and the alerts window (never both), reads the process table of each
// system, and stops only what it re-verified right before. Most tests feed fake process tables;
// the last one starts a real process and stops it.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { test } from 'node:test';
import { bootoutLaunchAgent, classify, commandOf, findWatchers, findWindows, listProcesses, stopBlackbrake, stopKind } from '../src/guard/procs.mjs';

const SCRIPT = '/h/.blackbrake/app/src/guard/watch-main.mjs';

const BS = '\x5c';

const WINNODE = `"C:${BS}Program Files${BS}nodejs${BS}node.exe"`;

const WINSCRIPT = `"C:${BS}Users${BS}a${BS}.blackbrake${BS}app${BS}src${BS}guard${BS}watch-main.mjs"`;

const SYS32 = `C:${BS}Windows${BS}System32${BS}`;

test('classify tells the watcher from the alerts window, and never says both', () => {
  assert.equal(classify('blackbrake watcher'), 'watcher');
  assert.equal(classify(`/usr/bin/node ${SCRIPT} --background`), 'watcher');
  assert.equal(classify(`${WINNODE} ${WINSCRIPT} --background`), 'watcher');
  assert.equal(classify('blackbrake watch'), 'window');
  assert.equal(classify(`/usr/bin/node ${SCRIPT}`), 'window', 'watch-main.mjs without --background is the alerts window');
  assert.equal(classify(`${WINNODE} ${WINSCRIPT}`), 'window');
});

test('classify ignores programs that merely mention the names', () => {
  for (const cmd of ['', 'node server.js', '/usr/bin/vim blackbrake watcher', 'vim blackbrake watch', `vim ${SCRIPT} --background`, 'node /h/other/watch-main.mjs --background', 'blackbrake watcher-extra', 'blackbrake watch-me', 'blackbrake-watcher']) {
    assert.equal(classify(cmd), null, cmd);
  }
});

test('listProcesses reads /proc on Linux, skipping itself and non-process entries', () => {
  const table = { 11: 'blackbrake watcher\0\0', 12: `/usr/bin/node\0${SCRIPT}\0`, 13: 'vim\0notes\0' };

  const read = (f) => {
    const pid = f.split('/')[2];

    if (!(pid in table)) throw new Error('gone');

    return table[pid];
  };

  const list = listProcesses({ platform: 'linux', self: 12, readdir: () => ['11', '12', '13', 'self', 'cpuinfo', '14'], read });

  assert.deepEqual(list, [{ pid: 11, cmd: 'blackbrake watcher' }, { pid: 13, cmd: 'vim notes' }]);
});

test('listProcesses reads ps on macOS', () => {
  const calls = [];

  const run = (file, args) => {
    calls.push([file, args]);

    return { status: 0, stdout: '  1 /sbin/launchd\n  7 blackbrake watcher\n  5 node me.js\n  9 /usr/bin/node /h/.blackbrake/app/src/guard/watch-main.mjs --background\n' };
  };

  const list = listProcesses({ platform: 'darwin', self: 5, find: (n) => `/bin/${n}`, run });

  assert.deepEqual(calls, [['/bin/ps', ['-axo', 'pid=,command=']]]);
  assert.deepEqual(list.map((x) => x.pid), [1, 7, 9]);
  assert.equal(list[1].cmd, 'blackbrake watcher');
});

test('listProcesses asks Windows for node.exe through PowerShell from the system folder', () => {
  const calls = [];

  const run = (file, args) => {
    calls.push([file, args.join(' ')]);

    return { status: 0, stdout: `3	"node.exe" me.js
20	${WINNODE} ${WINSCRIPT} --background
` };
  };

  const list = listProcesses({ platform: 'win32', self: 3, find: (n) => SYS32 + n, run });

  assert.equal(calls[0][0], `${SYS32}powershell.exe`);
  assert.match(calls[0][1], /Win32_Process/);
  assert.deepEqual(list.map((x) => x.pid), [20]);
  assert.equal(classify(list[0].cmd), 'watcher');
});

test('listProcesses answers an empty list when it cannot tell', () => {
  const boom = () => { throw new Error('boom'); };

  assert.deepEqual(listProcesses({ platform: 'darwin', find: () => null }), []);
  assert.deepEqual(listProcesses({ platform: 'darwin', find: () => '/bin/ps', run: boom }), []);
  assert.deepEqual(listProcesses({ platform: 'darwin', find: () => '/bin/ps', run: () => ({ status: 1, stdout: '1 x' }) }), []);
  assert.deepEqual(listProcesses({ platform: 'linux', readdir: boom }), []);
});

test('commandOf reads one process and returns null when it is gone', () => {
  const gone = () => { throw new Error('gone'); };

  const ps = (f, a) => ({ status: 0, stdout: `${a.join(' ')}|x\n` });

  assert.equal(commandOf(7, { platform: 'linux', read: () => 'blackbrake watcher\0\0' }), 'blackbrake watcher');
  assert.equal(commandOf(7, { platform: 'linux', read: gone }), null);
  assert.equal(commandOf(7, { platform: 'darwin', find: () => '/bin/ps', run: ps }), '-p 7 -o command=|x');
  assert.equal(commandOf(-1, { platform: 'linux', read: () => 'x' }), null);
  assert.equal(commandOf('7; rm', { platform: 'linux', read: () => 'x' }), null);
});

// A fake machine: a process table, a kill that obeys (or ignores) SIGTERM, and a clock that only
// moves when asked to wait.
function machine(procs, { stubborn = [] } = {}) {
  const table = new Map(Object.entries(procs).map(([pid, cmd]) => [Number(pid), cmd]));
  const kills = [];
  let slept = 0;

  const kill = (pid, sig) => {
    kills.push([pid, sig]);

    if (!table.has(pid)) throw new Error('ESRCH');

    if (sig === 'SIGKILL' || !stubborn.includes(pid)) table.delete(pid);
  };

  return {
    table,
    kills,
    get slept() { return slept; },
    opts: {
      platform: 'linux',
      list: () => [...table].map(([pid, cmd]) => ({ pid, cmd })),
      commandOf: (pid) => table.get(pid) ?? null,
      kill,
      sleep: (ms) => { slept += ms; },
    },
  };
}

test('findWatchers and findWindows split the table with no overlap', () => {
  const m = machine({ 11: 'blackbrake watcher', 12: 'blackbrake watch', 13: `node ${SCRIPT}`, 14: `node ${SCRIPT} --background`, 15: 'node server.js' });

  assert.deepEqual(findWatchers(m.opts), [11, 14]);
  assert.deepEqual(findWindows(m.opts), [12, 13]);
});

test('stopKind ends every watcher it finds and reports what the second sweep still sees', () => {
  const m = machine({ 11: 'blackbrake watcher', 14: `node ${SCRIPT} --background`, 15: 'node server.js' });
  const r = stopKind('watcher', m.opts);

  assert.deepEqual(r, { found: [11, 14], remaining: [] });
  assert.deepEqual(m.kills, [[11, 'SIGTERM'], [14, 'SIGTERM']]);
  assert.ok(m.table.has(15), 'a process that is not the watcher is left alone');
});

test('stopKind escalates to SIGKILL after the grace period, and the report is what is left', () => {
  const m = machine({ 11: 'blackbrake watcher' }, { stubborn: [11] });
  const r = stopKind('watcher', m.opts);

  assert.deepEqual(m.kills, [[11, 'SIGTERM'], [11, 'SIGKILL']]);
  assert.deepEqual(r, { found: [11], remaining: [] });
  assert.ok(m.slept >= 3000, 'waited the grace period before the hard kill');

  const w = machine({ 12: 'blackbrake watcher' });
  const calls = [];
  const rw = stopKind('watcher', { ...w.opts, platform: 'win32', kill: (pid, sig) => { calls.push([pid, sig]); } });

  assert.deepEqual(rw.remaining, [12], 'what cannot be stopped is reported, not claimed');
  assert.ok(calls.length > 0 && calls.every(([, sig]) => sig === 'SIGTERM'), 'Windows terminates on the first signal: no escalation');
});

test('stopKind re-verifies each pid right before the signal: a reused pid is never killed', () => {
  const m = machine({ 11: 'blackbrake watcher' });
  const r = stopKind('watcher', { ...m.opts, commandOf: () => 'node server.js' });

  assert.deepEqual(m.kills, []);
  assert.deepEqual(r.remaining, [11], 'it still reports it, and says nothing was stopped');
});

test('a foreign node process (a planted pid file, an unrelated server) is never signalled', () => {
  const m = machine({ 99: 'node server.js', 98: 'node /h/other/watch-main.mjs --background', 11: 'blackbrake watcher' });
  const r = stopBlackbrake(m.opts);

  assert.deepEqual(m.kills.map(([pid]) => pid), [11]);
  assert.deepEqual(r.watchers, { found: [11], remaining: [] });
  assert.ok(m.table.has(99) && m.table.has(98));
});

test('stopBlackbrake closes alerts windows only when asked, and never mistakes one for the watcher', () => {
  const a = machine({ 11: 'blackbrake watcher', 12: 'blackbrake watch', 13: `node ${SCRIPT}` });
  const ra = stopBlackbrake({ ...a.opts, windows: false });

  assert.deepEqual(ra.watchers.found, [11]);
  assert.deepEqual(ra.windows, { found: [], remaining: [] });
  assert.deepEqual([...a.table.keys()], [12, 13]);

  const b = machine({ 11: 'blackbrake watcher', 12: 'blackbrake watch', 13: `node ${SCRIPT}` });
  const rb = stopBlackbrake(b.opts);

  assert.deepEqual(rb.windows.found, [12, 13]);
  assert.deepEqual(rb.windows.remaining, []);
  assert.equal(b.table.size, 0);
});

test('never signals itself or pid 0 and 1, whatever the table says', () => {
  const m = machine({ 1: 'blackbrake watcher', 0: 'blackbrake watcher', [process.pid]: 'blackbrake watcher' });
  const r = stopKind('watcher', { ...m.opts, list: () => [...m.table].map(([pid, cmd]) => ({ pid, cmd })) });

  assert.deepEqual(m.kills, []);
  assert.deepEqual(r.found, []);
});

test('bootoutLaunchAgent runs launchctl bootout for the user domain on macOS only', () => {
  const calls = [];

  const run = (file, args) => { calls.push([file, args]);

 return { status: 0, stdout: '', stderr: '' }; };

  const find = (n) => `/bin/${n}`;
  const answer = (status, stderr) => () => ({ status, stderr });

  assert.equal(bootoutLaunchAgent({ platform: 'linux', run, find, uid: 501 }), 'skipped');
  assert.equal(bootoutLaunchAgent({ platform: 'win32', run, find, uid: 501 }), 'skipped');
  assert.equal(calls.length, 0);
  assert.equal(bootoutLaunchAgent({ platform: 'darwin', run, find, uid: 501 }), 'removed');
  assert.deepEqual(calls, [['/bin/launchctl', ['bootout', 'gui/501/dev.blackbrake.watch']]]);
  assert.equal(bootoutLaunchAgent({ platform: 'darwin', run: answer(113, 'Could not find service'), find, uid: 501 }), 'not-loaded');
  assert.equal(bootoutLaunchAgent({ platform: 'darwin', run: answer(3, 'No such process'), find, uid: 501 }), 'not-loaded');
  assert.equal(bootoutLaunchAgent({ platform: 'darwin', run: answer(5, 'Input/output error'), find, uid: 501 }), 'failed');
  assert.equal(bootoutLaunchAgent({ platform: 'darwin', run, find: () => null, uid: 501 }), 'skipped', 'no launchctl in a system folder: nothing to run');
  assert.equal(bootoutLaunchAgent({ platform: 'darwin', run, find, uid: 'x;y' }), 'skipped', 'the user id must be a number');
});

test('a real process that looks like the watcher is found in the real process table and stopped', { timeout: 90000 }, () => {
  const args = ['-e', 'setInterval(function(){},1000)', 'x/src/guard/watch-main.mjs', '--background'];
  const child = spawn(process.execPath, args, { stdio: 'ignore', windowsHide: true, env: { ...process.env, BLACKBRAKE_NO_WINDOW: '1' } });
  // Only this child: a real watcher of the person running the tests must survive the test.
  const only = (list) => list.filter((x) => x.pid === child.pid);

  try {
    const deadline = Date.now() + 20000;
    let seen = [];

    while (Date.now() < deadline && !seen.length) seen = only(listProcesses());

    assert.equal(seen.length, 1, 'the process table lists the child');
    assert.equal(classify(seen[0].cmd), 'watcher', seen[0].cmd);

    // The kill is injected and can only reach this child (src/guard/safety.mjs: tests never stop a real process).
    const kill = (pid, sig) => {
      assert.equal(pid, child.pid, 'only the test\'s own child');
      process.kill(pid, sig);
    };

    const r = stopKind('watcher', { list: () => only(listProcesses()), kill });

    assert.deepEqual(r.found, [child.pid]);
    assert.deepEqual(r.remaining, []);
  } finally {
    try { child.kill('SIGKILL'); } catch { /* already stopped */ }
  }
});

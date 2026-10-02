// The process sweep behind uninstall and pause: finds blackbrake's background watcher and its alerts
// windows in the whole process table (not through a pid file, which only points at one process and
// can be missing, stale or planted), and stops them.
//   - The table is read the way window.mjs reads it: /proc on Linux, `ps` on macOS, a fixed
//     PowerShell query of node.exe on Windows. Programs come from system folders, never from PATH.
//   - A command line is the watcher or the window, never both (the window also runs watch-main.mjs).
//   - Every pid is re-read and re-classified right before it is signalled (a pid can be reused).
//   - The result is what a second sweep still finds, not what was attempted.
// No shell anywhere; pids are numbers; nothing leaves this machine.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { mayStop } from './safety.mjs';
import { systemProgram } from './window.mjs';

export const LAUNCH_AGENT_LABEL = 'dev.blackbrake.watch';

// process.title of the watcher and of the alerts window: on Linux and macOS it rewrites the
// arguments, so the process table then shows the title instead of the script path.
const WATCHER_TITLE = /^blackbrake watcher(?![\w-])/;

const WINDOW_TITLE = /^blackbrake watch(?![\w-])/;

// "node … <something>/src/guard/watch-main.mjs [arguments]": a node program running blackbrake's
// own file. Anything else that merely names the file is not ours.
const NODE_SCRIPT = /(?:^|[\x5c/"\s])node(?:js)?(?:\.exe)?"?\s.*?[\x5c/]src[\x5c/]guard[\x5c/]watch-main\.mjs"?(.*)$/i;

const BACKGROUND = /(?:^|\s)--background(?:\s|$)/;

// 'watcher', 'window' or null for one command line.
export function classify(cmd) {
  const c = String(cmd ?? '').trim();

  if (WATCHER_TITLE.test(c)) return 'watcher';

  if (WINDOW_TITLE.test(c)) return 'window';
  const m = c.match(NODE_SCRIPT);

  if (!m) return null;

  return BACKGROUND.test(m[1]) ? 'watcher' : 'window';
}

const PS_LIST = 'Get-CimInstance Win32_Process -Filter "Name=\'node.exe\'" | ForEach-Object { "$($_.ProcessId)`t$($_.CommandLine)" }';

const lines = (text) => String(text ?? '').replace(/\t/g, ' ').split(/\r?\n/).map((l) => l.match(/^\s*(\d+)\s+(.*)$/)).filter(Boolean).map((m) => ({ pid: Number(m[1]), cmd: m[2].trim() }));

const flat = (s) => String(s).replace(/\0+/g, ' ').trim();

// Every process the system lists, as { pid, cmd }, without this one. On Windows only node.exe
// (everything of ours is node). Unable to tell = an empty list.
export function listProcesses({ platform = process.platform, run = spawnSync, find = (n) => systemProgram(n, { platform }), readdir = fs.readdirSync, read = fs.readFileSync, self = process.pid } = {}) {
  try {
    let all;

    if (platform === 'linux') {
      all = readdir('/proc').filter((d) => /^\d+$/.test(d)).map((d) => {
        try { return { pid: Number(d), cmd: flat(read(`/proc/${d}/cmdline`, 'utf8')) }; } catch { return null; }
      }).filter((x) => x?.cmd);
    } else {
      const ps = find(platform === 'win32' ? 'powershell.exe' : 'ps');

      if (!ps) return [];
      const r = platform === 'win32' ? run(ps, ['-NoProfile', '-NonInteractive', '-Command', PS_LIST], { encoding: 'utf8', windowsHide: true, timeout: 15000 }) : run(ps, ['-axo', 'pid=,command='], { encoding: 'utf8', timeout: 10000, maxBuffer: 8 * 1024 * 1024 });

      if (r.status !== 0) return [];
      all = lines(r.stdout);
    }

    return all.filter((x) => x.pid !== self);
  } catch {
    return [];
  }
}

const validPid = (pid) => Number.isSafeInteger(pid) && pid > 0;

// The command line of one process, or null when it is gone or cannot be read.
export function commandOf(pid, { platform = process.platform, run = spawnSync, find = (n) => systemProgram(n, { platform }), read = fs.readFileSync } = {}) {
  if (!validPid(pid)) return null;

  try {
    if (platform === 'linux') return flat(read(`/proc/${pid}/cmdline`, 'utf8')) || null;
    const ps = find(platform === 'win32' ? 'powershell.exe' : 'ps');

    if (!ps) return null;

    const r = platform === 'win32'
      ? run(ps, ['-NoProfile', '-NonInteractive', '-Command', `(Get-CimInstance Win32_Process -Filter "ProcessId=${pid}").CommandLine`], { encoding: 'utf8', windowsHide: true, timeout: 15000 })
      : run(ps, ['-p', String(pid), '-o', 'command='], { encoding: 'utf8', timeout: 5000 });

    return r.status === 0 ? (String(r.stdout).split(/\r?\n/)[0].trim() || null) : null;
  } catch {
    return null;
  }
}

const sweepOf = (kind, o) => (o.list ?? (() => listProcesses(o)))()
  .filter((x) => validPid(x.pid) && x.pid > 1 && x.pid !== (o.self ?? process.pid) && classify(x.cmd) === kind)
  .map((x) => x.pid);

export const findWatchers = (o = {}) => sweepOf('watcher', o);

export const findWindows = (o = {}) => sweepOf('window', o);

// A synchronous pause (the callers are synchronous CLI code).
const pause = (ms) => { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); };

// Stops every process of one kind: SIGTERM, up to `graceMs` of polling, then (not on Windows,
// where the first signal already terminates) SIGKILL. Returns { found, remaining } with the pids
// seen before and the pids a second sweep still sees.
export function stopKind(kind, o = {}) {
  mayStop({ injected: Boolean(o.kill) });
  const { platform = process.platform, kill = (pid, sig) => process.kill(pid, sig), sleep = pause, graceMs = 3000, stepMs = 250 } = o;
  const read = o.commandOf ?? ((pid) => commandOf(pid, o));
  const found = sweepOf(kind, o);

  const signal = (pids, sig) => {
    for (const pid of pids) {
      // Re-verified at the last moment: the table may be old and the pid may be somebody else's now.
      if (classify(read(pid)) !== kind) continue;

      try { kill(pid, sig); } catch { /* gone already */ }
    }
  };

  signal(found, 'SIGTERM');
  let left = found;

  for (let waited = 0; left.length && waited < graceMs; waited += stepMs) {
    sleep(stepMs);
    left = sweepOf(kind, o);
  }

  if (left.length && platform !== 'win32') {
    signal(left, 'SIGKILL');
    sleep(stepMs);
    left = sweepOf(kind, o);
  }

  return { found, remaining: left };
}

// The watcher first (it opens windows when a harness starts), then, unless told not to, the
// alerts windows. { watchers: { found, remaining }, windows: { found, remaining } }.
export function stopBlackbrake({ windows = true, ...o } = {}) {
  return {
    watchers: stopKind('watcher', o),
    windows: windows ? stopKind('window', o) : { found: [], remaining: [] },
  };
}

// macOS: launchd loaded the login item at login, so it also has to be told to let go of it.
// 'removed', 'not-loaded' (nothing to remove: fine), 'failed' or 'skipped' (not macOS, no launchctl
// in a system folder, no numeric user id). The program is /bin/launchctl, never one from PATH.
export function bootoutLaunchAgent({ platform = process.platform, run = spawnSync, find = (n) => systemProgram(n, { platform }), uid = process.getuid?.() } = {}) {
  if (platform !== 'darwin' || !Number.isSafeInteger(uid) || uid < 0) return 'skipped';
  mayStop({ injected: run !== spawnSync });
  const launchctl = find('launchctl');

  if (!launchctl) return 'skipped';

  try {
    const r = run(launchctl, ['bootout', `gui/${uid}/${LAUNCH_AGENT_LABEL}`], { encoding: 'utf8', timeout: 10000 });

    if (r.status === 0) return 'removed';

    return r.status === 3 || r.status === 113 || /could not find|no such process|not (?:found|loaded)/i.test(`${r.stderr ?? ''}${r.stdout ?? ''}`) ? 'not-loaded' : 'failed';
  } catch {
    return 'failed';
  }
}

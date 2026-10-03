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
import { classify } from './classify.mjs';
import { mayStop } from './safety.mjs';
import { systemProgram } from './window.mjs';

export const LAUNCH_AGENT_LABEL = 'dev.blackbrake.watch';

// 'watcher', 'window' or null for one command line: the one strict rule (src/guard/classify.mjs).
export { classify };

const PS_LIST = 'Get-CimInstance Win32_Process -Filter "Name=\'node.exe\'" | ForEach-Object { "$($_.ProcessId)`t$($_.CommandLine)" }';

const lines = (text) => String(text ?? '').replace(/\t/g, ' ').split(/\r?\n/).map((l) => l.match(/^\s*(\d+)\s+(.*)$/)).filter(Boolean).map((m) => ({ pid: Number(m[1]), cmd: m[2].trim() }));

const flat = (s) => String(s).replace(/\0+/g, ' ').trim();

// Every process the system lists, as { pid, cmd }, without this one. On Windows only node.exe
// (everything of ours is node). Unable to tell = null, never an empty list: "I could not look" must
// not read as "nothing is running" (review C, 2026-10-01: pause and uninstall said "stopped").
export function listProcesses({ platform = process.platform, run = spawnSync, find = (n) => systemProgram(n, { platform }), readdir = fs.readdirSync, read = fs.readFileSync, self = process.pid } = {}) {
  try {
    let all;

    if (platform === 'linux') {
      all = readdir('/proc').filter((d) => /^\d+$/.test(d)).map((d) => {
        try { return { pid: Number(d), cmd: flat(read(`/proc/${d}/cmdline`, 'utf8')) }; } catch { return null; }
      }).filter((x) => x?.cmd);
    } else {
      const ps = find(platform === 'win32' ? 'powershell.exe' : 'ps');

      if (!ps) return null;
      const r = platform === 'win32' ? run(ps, ['-NoProfile', '-NonInteractive', '-Command', PS_LIST], { encoding: 'utf8', windowsHide: true, timeout: 15000 }) : run(ps, ['-axo', 'pid=,command='], { encoding: 'utf8', timeout: 10000, maxBuffer: 8 * 1024 * 1024 });

      if (r.status !== 0) return null;
      all = lines(r.stdout);
    }

    return all.filter((x) => x.pid !== self);
  } catch {
    return null;
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

// What classify needs from the sweep options: guard's folder (V4: the script must be guard's own
// copy under it, or this checkout) and the system (case on Windows). Undefined means the defaults.
const mineOf = (o) => ({ home: o.home, platform: o.platform });

// The pids of one kind, or null when the process table could not be read.
const sweepOf = (kind, o) => {
  const all = (o.list ?? (() => listProcesses(o)))();

  if (!Array.isArray(all)) return null;

  return all.filter((x) => validPid(x.pid) && x.pid > 1 && x.pid !== (o.self ?? process.pid) && classify(x.cmd, mineOf(o)) === kind).map((x) => x.pid);
};

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
      if (classify(read(pid), mineOf(o)) !== kind) continue;

      try { kill(pid, sig); } catch { /* gone already */ }
    }
  };

  // The table could not be read: nothing is signalled and the caller must say "could not check".
  if (found === null) return { found: null, remaining: null };

  signal(found, 'SIGTERM');
  let left = found;

  for (let waited = 0; left?.length && waited < graceMs; waited += stepMs) {
    sleep(stepMs);
    left = sweepOf(kind, o);
  }

  if (left?.length && platform !== 'win32') {
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

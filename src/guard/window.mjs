// Opens a separate terminal window running `blackbrake watch` when an agent session starts, so the
// alerts are in sight while the agent works. At most once per session, never if a watcher already
// runs, and off with `blackbrake window off`. No shell anywhere: each terminal gets an argument list.
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { isWatchRunning } from './watch.mjs';
import { classify } from './classify.mjs';
// A paused blackbrake opens nothing (the mark's tolerant reading is in pause.mjs).
import { isPaused } from './pause.mjs';
import { getSession, getSetting, guardHome, setSession } from './state.mjs';

// Programs are taken from fixed system folders, never from the agent's PATH (a repository can put
// its own "wt.exe" or "xterm" first in it).
// Windows Terminal's wt.exe is an app execution alias: lstat sees it (a link), stat cannot follow it.
// WindowsApps is writable by the user, and so by an agent: there only an alias counts, never a plain
// file someone put there (review C, 2026-10-01: a planted wt.exe was run by blackbrake itself).
const exists = (file) => {
  if (/[\\/]WindowsApps[\\/][^\\/]+\.exe$/i.test(file)) {
    try { return fs.lstatSync(file).isSymbolicLink(); } catch { return false; }
  }

  try { return fs.statSync(file).isFile(); } catch { return false; }
};

export function systemProgram(name, { platform = process.platform, env = process.env, has = exists, home = os.homedir } = {}) {
  const p = platform === 'win32' ? path.win32 : path.posix;
  // Not from LOCALAPPDATA or SystemRoot: the agent's environment could point them at a folder
  // holding its own wt.exe or powershell.exe. The user's AppData comes from the home folder, and
  // Windows from the system drive (SystemRoot only when it is exactly <drive>:\Windows).
  const root = /^[A-Za-z]:\\Windows$/i.test(env.SystemRoot ?? '') ? env.SystemRoot : 'C:\\Windows';
  // WindowsApps is writable by the user (and so by the agent): only Windows Terminal lives there.
  const apps = name.toLowerCase() === 'wt.exe' ? [p.join(home(), 'AppData', 'Local', 'Microsoft', 'WindowsApps')] : [];

  const dirs = platform === 'win32'
    ? [...apps, p.join(root, 'System32'), p.join(root, 'System32', 'WindowsPowerShell', 'v1.0')]
    : ['/usr/bin', '/usr/local/bin', '/bin', '/opt/homebrew/bin'];

  return dirs.filter((d) => p.isAbsolute(d) && !/^[\\/]{2}/.test(d)).map((d) => p.join(d, name)).find((f) => has(f)) ?? null;
}

// The command that opens a new terminal window running `node <cli> watch`, or null if there is none.
export function windowCommand(node, cli, { platform = process.platform, find = (n) => systemProgram(n, { platform }) } = {}) {
  // Windows Terminal splits its own command line on ";", and nothing else here may carry quotes.
  if (/[;"\r\n]/.test(`${node}${cli}`)) return null;

  if (platform === 'win32') {
    const wt = find('wt.exe');

    // The tab in blackbrake's orange, with its name.
    if (wt) return { file: wt, args: ['-w', 'new', 'new-tab', '--title', 'blackbrake', '--tabColor', '#FF5A1F', '--suppressApplicationTitle', '--', node, cli, 'watch'] };
    const conhost = find('conhost.exe');

    return conhost ? { file: conhost, args: [node, cli, 'watch'] } : null;
  }

  if (platform === 'darwin') {
    const osa = find('osascript');

    // Terminal.app runs a shell line, so each part goes through AppleScript's `quoted form of`.
    return osa ? { file: osa, args: ['-e', 'on run argv', '-e', 'tell application "Terminal" to do script (quoted form of item 1 of argv) & " " & (quoted form of item 2 of argv) & " watch"', '-e', 'tell application "Terminal" to activate', '-e', 'end run', node, cli] } : null;
  }

  for (const [term, flag] of [['x-terminal-emulator', '-e'], ['gnome-terminal', '--'], ['konsole', '-e'], ['xfce4-terminal', '-x'], ['kitty', null], ['alacritty', '-e'], ['xterm', '-e']]) {
    const file = find(term);

    if (file) return { file, args: [...(flag ? [flag] : []), node, cli, 'watch'] };
  }

  return null;
}

// The alerts window is a terminal of its own, for the user. It gets only what a terminal needs
// (an allow-list), never the rest of the agent's environment: that would carry NO_COLOR, TERM=dumb
// or CI (no colour, no motion) and, worse, NODE_OPTIONS, NODE_PATH, LD_PRELOAD or DYLD_* that a
// repository's settings could set to run code in the window. guard's folder is passed explicitly.
const TERMINAL_ENV = /^(PATH|Path|SystemRoot|SystemDrive|windir|ComSpec|TEMP|TMP|TMPDIR|USERPROFILE|HOMEDRIVE|HOMEPATH|APPDATA|LOCALAPPDATA|PROGRAMDATA|ProgramFiles|ProgramFiles\(x86\)|PATHEXT|CommonProgramFiles|CommonProgramFiles\(x86\)|PUBLIC|ALLUSERSPROFILE|USERNAME|USERDOMAIN|COMPUTERNAME|NUMBER_OF_PROCESSORS|PROCESSOR_ARCHITECTURE|OS|HOME|USER|LOGNAME|SHELL|LANG|LANGUAGE|LC_[A-Z]+|DISPLAY|WAYLAND_DISPLAY|XAUTHORITY|DBUS_SESSION_BUS_ADDRESS|XDG_RUNTIME_DIR|XDG_CONFIG_HOME|XDG_DATA_HOME|__CF_USER_TEXT_ENCODING|WT_SESSION|WT_PROFILE_ID|COLORTERM|TERM_PROGRAM|ACCESSIBLE|BLACKBRAKE_LANG)$/i;

export function windowEnv(env = process.env, home = null) {
  const out = Object.fromEntries(Object.entries(env).filter(([k]) => TERMINAL_ENV.test(k) && !/^(HOME|XDG_CONFIG_HOME|XDG_DATA_HOME)$/i.test(k)));

  // The folders where a terminal reads its own configuration (which can start programs) come from
  // the account itself, never from the agent's environment (review C, 2026-10-01): a repository's
  // settings could otherwise point HOME or XDG_CONFIG_HOME at a planted terminal config.
  if (process.platform !== 'win32') {
    try { out.HOME = os.userInfo().homedir; } catch { /* the terminal falls back to its default */ }
  }

  if (home) out.BLACKBRAKE_HOME = home;

  return out;
}

// An alerts window is `watch-main.mjs` without --background. It names itself 'blackbrake watch'
// (process.title), which on Linux and macOS replaces the command line the process table shows; the
// background watcher is 'blackbrake watcher'. The title must lead the command line.
// Strict: the process must BE node running watch-main.mjs, not merely mention it (src/guard/classify.mjs;
// review C: a decoy that named the file kept the alerts window from opening).
// Whether another alerts window is already open for this user, whichever guard folder it uses (a
// copy run from a checkout or a relocated BLACKBRAKE_HOME keeps its pid file elsewhere, so the
// per-folder check alone would open a second window). Reads the process table: /proc on Linux, ps
// on macOS, a fixed PowerShell query on Windows. If it cannot tell, it says no and the per-folder
// check still applies.
export function liveWindowRunning({ home = guardHome(), platform = process.platform, run = spawnSync, find = systemProgram, readdir = fs.readdirSync, read = fs.readFileSync } = {}) {
  const WINDOW = (cmd) => classify(cmd, { home, platform }) === 'window';
  const other = (pid) => Number(pid) !== process.pid;

  try {
    if (platform === 'linux') {
      return readdir('/proc').filter((d) => /^\d+$/.test(d) && other(d)).some((pid) => {
        try { return WINDOW(String(read(`/proc/${pid}/cmdline`, 'utf8')).replace(/\0+/g, ' ').trim()); } catch { return false; }
      });
    }

    const lines = (text) => String(text ?? '').split(/\r?\n/).map((l) => l.match(/^\s*(\d+)\s+(.*)$/)).filter(Boolean);

    if (platform === 'darwin') {
      const ps = find('ps', { platform });

      return Boolean(ps) && lines(run(ps, ['-axo', 'pid=,command='], { encoding: 'utf8', timeout: 5000 }).stdout).some(([, pid, cmd]) => other(pid) && WINDOW(cmd.trim()));
    }

    const pwsh = find('powershell.exe', { platform });

    if (!pwsh) return false;
    const r = run(pwsh, ['-NoProfile', '-NonInteractive', '-Command', 'Get-CimInstance Win32_Process -Filter "Name=\'node.exe\'" | ForEach-Object { "$($_.ProcessId)`t$($_.CommandLine)" }'], { encoding: 'utf8', windowsHide: true, timeout: 10000 });

    return lines(String(r.stdout ?? '').replace(/\t/g, ' ')).some(([, pid, cmd]) => other(pid) && WINDOW(cmd));
  } catch {
    return false;
  }
}

// An automatic opening is at most one per 10 minutes for the whole user (mtime of `window.last`):
// a script that starts `claude -p` a hundred times, or a fleet of workers, opens one window.
export const WINDOW_COOLDOWN_MS = 10 * 60e3;

const SSH_VARS = ['SSH_CONNECTION', 'SSH_CLIENT', 'SSH_TTY'];

// Why the window must not open now, or null. The first rule that matches decides:
// paused, off, display, ssh, background, then the session/watcher dedupe and the cooldown.
// Read-only: it writes nothing (maybeOpenWindow marks the session).
export function windowSkipReason(sessionId, { home = guardHome(), env = process.env, platform = process.platform, background = false, now = Date.now() } = {}) {
  if (isPaused(home)) return 'paused';

  // The user's setting decides; an agent that sets CI for its tools does not hide the window.
  // BLACKBRAKE_NO_WINDOW is for blackbrake's own tests (an agent writing it into its settings is
  // refused by guard as tampering).
  if (!getSetting('window', true, home) || env.BLACKBRAKE_NO_WINDOW) return 'off';

  if (platform === 'linux' && !env.DISPLAY && !env.WAYLAND_DISPLAY) return 'display';

  // Over SSH on macOS or Windows the window would open on the remote machine's console, which
  // nobody watches. On Linux the display rule above decides (X11 forwarding shows it to the user).
  if ((platform === 'darwin' || platform === 'win32') && SSH_VARS.some((k) => env[k])) return 'ssh';

  // Cursor's background agents (`is_background_agent: true`) run unattended.
  if (background === true) return 'background';

  if (getSession(sessionId, home).windowOpened) return 'session';

  if (isWatchRunning(home)) return 'watching';

  try {
    if (now - fs.statSync(path.join(home, 'window.last')).mtimeMs < WINDOW_COOLDOWN_MS) return 'cooldown';
  } catch { /* never opened automatically */ }

  return null;
}

// Called from the hook on every event; cheap when there is nothing to do.
export function maybeOpenWindow(sessionId, { home = guardHome(), env = process.env, platform = process.platform, background = false, cli, spawner = spawn, command = windowCommand, running = liveWindowRunning } = {}) {
  const why = windowSkipReason(sessionId, { home, env, platform, background });

  if (why) {
    // The cooldown holds this session back for good: a window must not pop up half-way through a long one.
    if (why === 'cooldown') setSession(sessionId, { windowOpened: new Date().toISOString(), windowSkipped: 'cooldown' }, home);

    return false;
  }

  // Two hooks of the same session can run at once: only the one that creates this file opens.
  const claim = path.join(home, 'window.claim');

  try {
    const st = fs.statSync(claim);

    if (Date.now() - st.mtimeMs < 20e3) return false;
    fs.rmSync(claim, { force: true });
  } catch { /* no recent claim */ }

  try { fs.writeFileSync(claim, String(process.pid), { flag: 'wx', mode: 0o600 }); } catch { return false; }

  // Only now, once per session and after the hook has answered: one process-table read. A window
  // already open serves this session too; the session is marked so it is not asked again.
  if (running({ home, platform })) {
    setSession(sessionId, { windowOpened: new Date().toISOString() }, home);
    fs.rmSync(claim, { force: true });

    return false;
  }

  setSession(sessionId, { windowOpened: new Date().toISOString() }, home);
  const c = command(process.execPath, cli);

  if (!c) return false;

  // Only the mtime counts: an empty file, written when an opening is attempted.
  try { fs.writeFileSync(path.join(home, 'window.last'), '', { mode: 0o600 }); } catch { /* the claim still limits repeats */ }

  try {
    const child = spawner(c.file, c.args, { detached: true, stdio: 'ignore', windowsHide: false, env: windowEnv(env, home) });
    child.on?.('error', () => { /* no terminal to open: the alerts are still in `blackbrake watch` */ });
    child.unref?.();

    return true;
  } catch {
    return false;
  }
}

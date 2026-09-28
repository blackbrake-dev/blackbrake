// Starts the background watcher when the user logs in, so blackbrake keeps running for every AI
// harness without anyone opening it. One small file per system, removed by `blackbrake uninstall`:
//   Windows  Startup folder: blackbrake-watch.vbs (runs node hidden, no console window)
//   macOS    ~/Library/LaunchAgents/dev.blackbrake.watch.plist (argument list, no shell)
//   Linux    ~/.config/autostart/blackbrake-watch.desktop
// The paths inside are checked for characters those formats would reinterpret.
import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { isBackgroundRunning } from './background.mjs';
import { assertNoLinks } from './install.mjs';
import { loginItemFile } from './policy.mjs';
import { guardHome } from './state.mjs';
import { systemProgram } from './window.mjs';

const UNSAFE = /["'`$%\\&<>|\r\n]/;

export function autostartFile(platform = process.platform, env = process.env) {
  return loginItemFile({ platform, home: os.homedir(), appData: env.APPDATA, xdgConfigHome: env.XDG_CONFIG_HOME });
}

const xml = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export function autostartContent(node, script, platform = process.platform) {
  // VBScript doubles its quotes; the others must not see quotes, $, backslashes (Linux) at all.
  if (/["\r\n]/.test(node + script) || (platform !== 'win32' && platform !== 'darwin' && UNSAFE.test(node + script))) return null;

  if (platform === 'win32') return `' blackbrake: background watcher for your AI agents (remove with "blackbrake uninstall")\r\nCreateObject("WScript.Shell").Run """${node}"" ""${script}"" --background", 0, False\r\n`;

  if (platform === 'darwin') {
    return `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>\n<key>Label</key><string>dev.blackbrake.watch</string>\n<key>ProgramArguments</key><array><string>${xml(node)}</string><string>${xml(script)}</string><string>--background</string></array>\n<key>RunAtLoad</key><true/>\n</dict></plist>\n`;
  }

  return `[Desktop Entry]\nType=Application\nName=blackbrake watch\nComment=Background watcher for your AI agents (remove with blackbrake uninstall)\nExec="${node}" "${script}" --background\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n`;
}

export const watchScript = (home = guardHome()) => path.join(home, 'app', 'src', 'guard', 'watch-main.mjs');

export const autostartInstalled = () => fs.existsSync(autostartFile());

// Writes the login item and starts the watcher now (hidden), unless one is already running.
export function installAutostart({ home = guardHome(), start = true, file = autostartFile() } = {}) {
  const content = autostartContent(process.execPath, watchScript(home));

  if (!content) throw new Error(`The paths to node or to blackbrake have characters a login item cannot hold safely: ${process.execPath}`);

  // No link anywhere on the way (the Startup folder included), and the file itself is replaced by
  // a rename, so a planted symlink or hard link is never written through.
  fs.mkdirSync(path.dirname(file), { recursive: true });
  assertNoLinks(file);
  // Windows Script Host reads a script in the system code page unless it is UTF-16 with a byte
  // order mark: that keeps paths like C:\Users\José working.
  const tmp = `${file}.${crypto.randomBytes(6).toString('hex')}.tmp`;

  try {
    fs.writeFileSync(tmp, process.platform === 'win32' ? Buffer.from(`\ufeff${content}`, 'utf16le') : content, { mode: 0o644, flag: 'wx' });
    fs.renameSync(tmp, file);
  } finally {
    fs.rmSync(tmp, { force: true });
  }

  if (start && !isBackgroundRunning(home)) {
    const child = spawn(process.execPath, [watchScript(home), '--background'], { detached: true, stdio: 'ignore', windowsHide: true });
    child.on('error', () => { /* starts at next login */ });
    child.unref();
  }

  return file;
}

// Whether a pid belongs to blackbrake's watcher: its command line names watch-main.mjs (Linux:
// /proc; macOS: ps; Windows: the process image must at least be node.exe).
// watch-main.mjs names itself 'blackbrake watcher' (process.title). On Linux and macOS that rewrites
// the argument area, so /proc and ps show the title instead of the script path: both count. The
// alerts window ('blackbrake watch') does not, nor a program that merely has it as an argument: the
// title leads the whole command line. This decides whether uninstall may kill a pid.
const WATCHER = /watch-main\.mjs|^blackbrake watcher(?![\w-])/;

export function isWatcherProcess(pid, { platform = process.platform, run = spawnSync, read = fs.readFileSync, find = systemProgram } = {}) {
  try {
    if (platform === 'linux') return WATCHER.test(String(read(`/proc/${pid}/cmdline`, 'utf8')).replace(/\0/g, '\n'));
    const ps = find(platform === 'win32' ? 'tasklist.exe' : 'ps', { platform });

    if (!ps) return false;
    const r = platform === 'win32' ? run(ps, ['/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH'], { encoding: 'utf8', windowsHide: true, timeout: 5000 }) : run(ps, ['-p', String(pid), '-o', 'command='], { encoding: 'utf8', timeout: 5000 });

    if (platform !== 'win32') return WATCHER.test(String(r.stdout).trim());

    // Windows: tasklist shows only the image name; the command line comes from PowerShell's
    // Win32_Process (fixed script, pid passed as a number).
    if (!/^"node(\.exe)?"/i.test(String(r.stdout).trim())) return false;
    const pwsh = systemProgram('powershell.exe', { platform });
    const q = pwsh && run(pwsh, ['-NoProfile', '-NonInteractive', '-Command', `(Get-CimInstance Win32_Process -Filter "ProcessId=${Number(pid)}").CommandLine`], { encoding: 'utf8', windowsHide: true, timeout: 10000 });

    return Boolean(q) && String(q.stdout).includes('watch-main.mjs');
  } catch {
    return false;
  }
}

export function removeAutostart({ home = guardHome(), file = autostartFile(), kill = true } = {}) {
  let removed = false;

  try {
    const st = fs.lstatSync(file);

    // Only the file blackbrake wrote: it names blackbrake's watcher.
    const buf = st.isFile() ? fs.readFileSync(file) : Buffer.alloc(0);

    if (buf.toString('utf8').includes('watch-main.mjs') || buf.toString('utf16le').includes('watch-main.mjs')) {
      fs.rmSync(file);
      removed = true;
    }
  } catch { /* not there */ }

  // Stop the running watcher, after checking that the pid really is a node process running
  // blackbrake's watcher (a planted pid file must not make this kill something else).
  try {
    const pid = Number.parseInt(fs.readFileSync(path.join(home, 'watch-bg.pid'), 'utf8'), 10);

    if (kill && Number.isInteger(pid) && pid > 0 && isBackgroundRunning(home) && isWatcherProcess(pid)) process.kill(pid);
  } catch { /* not running */ }

  return removed;
}

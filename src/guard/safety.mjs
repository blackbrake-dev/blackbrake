// The real-installation lock. On 2026-10-01 a review script imported install.mjs and called
// uninstall() while BLACKBRAKE_HOME had come out empty: the person's real ~/.blackbrake (settings,
// alert log, backups, the copies that undo a fix) was deleted. So: only the blackbrake program itself
// (the CLI, the hook, the watcher and the status line, which call declareProgram() first thing) may
// change or delete the real installation, an agent's real configuration or a login item, or stop
// processes. Anything else that imports these modules (a test, a script, an experiment, an agent)
// gets an error instead, and must point everything at a temporary folder.
//
// "Real" is the account's own home folder as the operating system knows it (os.userInfo()), which
// HOME and USERPROFILE cannot redirect: those are exactly what a test changes, or what goes wrong.
import os from 'node:os';
import path from 'node:path';
import { isText } from '../kinds.mjs';

let declared = false;

// Called by the program's entry points (bin/blackbrake.mjs, hook.mjs, watch-main.mjs, statusline.mjs).
export function declareProgram() {
  declared = true;
}

export const isProgram = () => declared;

const fold = (p) => (process.platform === 'win32' ? p.toLowerCase() : p);

const inside = (child, parent) => {
  const rel = path.relative(fold(path.resolve(parent)), fold(path.resolve(child)));

  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
};

// Tests may stand a temporary folder in for the real home (to check this lock itself), never
// anything outside the system's temporary folder.
export function realHome() {
  let home;

  try { home = os.userInfo().homedir; } catch { home = os.homedir(); }

  const wanted = process.env.BLACKBRAKE_REAL_HOME_FOR_TESTS;
  const temp = os.tmpdir();

  if (wanted && path.isAbsolute(wanted) && inside(wanted, temp) && fold(path.resolve(wanted)) !== fold(path.resolve(temp)) && !inside(home, temp)) return path.resolve(wanted);

  return home;
}

// guard's folder, every agent's configuration and the folders that hold login items.
export function realPlaces(home = realHome()) {
  return [
    '.blackbrake', '.claude', '.claude.json', '.codex', '.cursor', '.copilot', '.gemini', '.codeium', '.devin',
    path.join('.config', 'autostart'), path.join('.config', 'devin'), path.join('Library', 'LaunchAgents'),
    path.join('AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
  ].map((p) => path.join(home, p));
}

export const isRealPlace = (target, home = realHome()) => realPlaces(home).some((p) => inside(target, p));

// Throws unless the caller is the blackbrake program or the target is not a real place. An empty or
// relative path is always refused: it is what an unset variable turns into.
export function mayChange(target, { realHome: home = realHome(), declared: program = declared } = {}) {
  const ok = isText(target) && target.trim() !== '' && path.isAbsolute(target);

  if (ok && (program || !isRealPlace(target, home))) return target;

  throw new Error(`blackbrake refused to change ${ok ? target : 'an empty or relative path'}: only the blackbrake program may change its real installation. Point tests and scripts at a temporary folder (BLACKBRAKE_HOME, HOME, USERPROFILE).`);
}

// Stopping processes is the program's job only (tests inject their own `kill`).
export function mayStop({ injected = false } = {}) {
  if (declared || injected) return;

  throw new Error('blackbrake refused to stop processes: only the blackbrake program may. Tests inject `kill` and `list`.');
}

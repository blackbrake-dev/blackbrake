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
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { isText } from '../kinds.mjs';

let declared = false;

// Called by the program's entry points (bin/blackbrake.mjs, hook.mjs, watch-main.mjs, statusline.mjs).
export function declareProgram() {
  declared = true;
}

export const isProgram = () => declared;

const fold = (p, platform = process.platform) => (/^(win32|darwin)$/.test(platform) ? p.toLowerCase() : p);

const inside = (child, parent, platform = process.platform) => {
  const rel = path.relative(fold(path.resolve(parent), platform), fold(path.resolve(child), platform));

  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
};

// Tests may stand a temporary folder in for the real home (to check this lock itself), never
// anything outside the system's temporary folder.
export function realHome() {
  let home;

  try { home = os.userInfo().homedir; } catch {
    throw new Error('blackbrake refused to determine the account home: account lookup failed; HOME cannot replace it.');
  }

  if (!isText(home) || !path.isAbsolute(home) || remote(home)) throw new Error('blackbrake refused an invalid account home.');

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

// Never probe UNC/device paths: even a metadata lookup may contact another machine. On Windows
// streams and trailing dots/spaces can name an ordinary protected file under another spelling.
const remote = (p) => /^[\\/]{2}/.test(p);

const normal = (p, platform) => {
  if (platform !== 'win32') return path.resolve(p);

  return path.resolve(p.replace(/\\/g, '/').split('/').map((part, i) => {
    if (i === 0 && /^[a-z]:$/i.test(part)) return part;

    if (part === '.' || part === '..') return part;

    return part.split(':')[0].replace(/[. ]+$/, '');
  }).join('/'));
};

const missing = (e) => e.code === 'ENOENT' || e.code === 'ENOTDIR';

// Resolve the nearest existing ancestor, retaining the not-yet-created tail. readlink also
// handles a dangling junction/symlink; realpath alone would miss that case. Bound link cycles.
function canonical(target, depth = 0) {
  if (depth > 40 || remote(target)) throw new Error('ambiguous path');
  const p = path.resolve(target);
  let st;

  try { st = fs.lstatSync(p); } catch (e) { if (!missing(e)) throw e; }

  if (st?.isSymbolicLink()) {
    const link = fs.readlinkSync(p);

    if (remote(link)) throw new Error('remote link');

    return canonical(path.resolve(path.dirname(p), link), depth + 1);
  }

  if (st) return fs.realpathSync.native(p);
  const parent = path.dirname(p);

  return parent === p ? p : path.join(canonical(parent, depth + 1), path.basename(p));
}

const stat = (p) => {
  try { return fs.statSync(p, { bigint: true }); } catch (e) { if (!missing(e)) throw e; }

  return null;
};

const sameFile = (a, b) => a && b && a.ino !== 0n && a.dev === b.dev && a.ino === b.ino;

export function isRealPlace(target, home = realHome(), { platform = process.platform } = {}) {
  // Ambiguous or inaccessible paths fail closed, before touching the filesystem for UNC paths.
  if (!isText(target) || !isText(home) || remote(target) || remote(home)) return true;

  try {
    const candidate = canonical(normal(target, platform));
    const actualHome = canonical(normal(home, platform));
    const places = realPlaces(actualHome).map((p) => canonical(normal(p, platform)));

    // A recursive operation on an ancestor would include the protected place too.
    if (places.some((p) => inside(candidate, p, platform) || inside(p, candidate, platform))) return true;

    const protectedStats = places.map(stat).filter(Boolean);
    let ancestor = candidate;

    for (;;) {
      const info = stat(ancestor);

      // A hard link has no unique canonical path. Refuse all multiply-linked files outside the
      // program, and compare dev:ino for directory aliases as well as textual containment.
      if (info && !info.isDirectory() && info.nlink > 1n) return true;

      if (protectedStats.some((p) => sameFile(info, p))) return true;
      const parent = path.dirname(ancestor);

      if (parent === ancestor) break;
      ancestor = parent;
    }

    return false;
  } catch { return true; }
}

// Throws unless the caller is the blackbrake program or the target is not a real place. An empty or
// relative path is always refused: it is what an unset variable turns into.
export function mayChange(target, { realHome: home = realHome(), declared: program = declared, platform = process.platform } = {}) {
  const ok = isText(target) && target.trim() !== '' && path.isAbsolute(target);

  if (ok && (program || !isRealPlace(target, home, { platform }))) return target;

  throw new Error(`blackbrake refused to change ${ok ? target : 'an empty or relative path'}: only the blackbrake program may change its real installation. Point tests and scripts at a temporary folder (BLACKBRAKE_HOME, HOME, USERPROFILE).`);
}

// Stopping processes is the program's job only (tests inject their own `kill`).
export function mayStop({ injected = false } = {}) {
  if (declared || injected) return;

  throw new Error('blackbrake refused to stop processes: only the blackbrake program may. Tests inject `kill` and `list`.');
}

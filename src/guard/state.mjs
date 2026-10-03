// guard's own files, all under ~/.blackbrake (override with BLACKBRAKE_HOME for tests):
//   state.json            { mode: 'observe' | 'protect' }
//   log/YYYY-MM.jsonl     one line per event: time, hashed session id, event, kind, action, rule
//                         id. Never prompts, commands, file contents or secret values.
//   sessions/<hash>.json  per-session flags (when the conversation was last compacted)
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mayChange } from './safety.mjs';

export const MODES = ['observe', 'protect'];

// BLACKBRAKE_HOME only when it is an absolute local path: a relative one would resolve inside each
// agent's working folder (a repository could plant a hook.mjs there), a UNC one on a network share.
export const guardHome = (env = process.env) => {
  const v = env.BLACKBRAKE_HOME;

  return v && path.isAbsolute(v) && !/^[\\/]{2}/.test(v) ? v : path.join(os.homedir(), '.blackbrake');
};

// The folder an installed copy of guard (running inside an agent) uses. The agent's environment
// can set BLACKBRAKE_HOME (a project's settings "env"), so an installed copy honours it only when
// the copy itself lives inside that folder; otherwise it uses ~/.blackbrake. The package itself
// (development, tests) honours it as before.
export function trustedHome(scriptUrl, env = process.env) {
  const own = path.join(os.homedir(), '.blackbrake');
  const wanted = guardHome(env);

  if (path.resolve(wanted) === path.resolve(own)) return own;
  const script = fileURLToPath(scriptUrl);
  let name = null;

  try { name = JSON.parse(fs.readFileSync(path.resolve(path.dirname(script), '..', '..', 'package.json'), 'utf8')).name; } catch { /* no package.json */ }

  if (name !== 'blackbrake-guard') return wanted;

  // The copy must sit exactly where the installer puts it inside that folder (<home>/app/… or
  // <home>/marketplace/blackbrake/app/…). An ancestor (the home folder, a drive root, ~/.claude)
  // contains the script too, but would make guard treat everything under it as its own files.
  const rel = path.relative(path.resolve(wanted), script).replace(/\\/g, '/').toLowerCase();

  return /^(app|marketplace\/blackbrake\/app)\/src\/guard\/[\w-]+\.mjs$/.test(rel) ? wanted : own;
}

const readJson = (f) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; } };

// Writes never go through a link planted in guard's folder: a symlink or a hard link (a second name
// for some other file) in place of state.json, a log or a pid file is removed first (only that name;
// the file it pointed at is untouched). Whole files are written to a fresh temporary name and renamed.
export function writePrivate(file, text, flag = 'w') {
  mayChange(path.resolve(file));
  const parent = path.resolve(path.dirname(file));
  const root = path.parse(parent).root;
  let current = root;

  // Checking from the root prevents even stat/mkdir from traversing a planted parent link.
  for (const part of path.relative(root, parent).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    let st;

    try { st = fs.lstatSync(current); } catch (e) { if (e.code !== 'ENOENT') throw e; }

    // System-owned top-level links such as /var -> /private/var are not agent-controlled.
    if (st?.isSymbolicLink() && !(process.platform !== 'win32' && st.uid === 0 && path.dirname(current) === root)) throw new Error('Refusing a linked state directory');
  }

  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });

  try {
    const st = fs.lstatSync(file);

    if (!st.isFile() || st.nlink > 1) fs.rmSync(file, { force: true });
  } catch { /* not there yet */ }

  if (flag === 'a') {
    fs.writeFileSync(file, text, { encoding: 'utf8', mode: 0o600, flag: 'a' });

    return;
  }

  const tmp = `${file}.${crypto.randomBytes(6).toString('hex')}.tmp`;

  try {
    fs.writeFileSync(tmp, text, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    fs.renameSync(tmp, file);
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

export const sessionHash = (id) => crypto.createHash('sha256').update(String(id ?? '')).digest('hex').slice(0, 12);

// Missing or unreadable state after guard was installed means someone removed it: fail toward
// protect rather than silently dropping to observe. Before installation, observe.
export function getMode(home = guardHome()) {
  const mode = readJson(path.join(home, 'state.json'))?.mode;

  if (MODES.includes(mode)) return mode;

  return ['marketplace', 'app'].some((d) => fs.existsSync(path.join(home, d))) ? 'protect' : 'observe';
}

export const hasMode = (home = guardHome()) => MODES.includes(readJson(path.join(home, 'state.json'))?.mode);

export function setMode(mode, home = guardHome()) {
  if (!MODES.includes(mode)) throw new Error(`Unknown mode "${mode}". Use one of: ${MODES.join(', ')}.`);
  const file = path.join(home, 'state.json');
  const state = readJson(file) ?? {};
  writePrivate(file, `${JSON.stringify({ ...state, mode, changed: new Date().toISOString() }, null, 2)}\n`);
}

// Interface language chosen with `blackbrake lang` (null: follow the system).
export const getSavedLang = (home = guardHome()) => readJson(path.join(home, 'state.json'))?.lang ?? null;

export function setSavedLang(lang, home = guardHome()) {
  const file = path.join(home, 'state.json');
  const state = readJson(file) ?? {};

  if (lang === null) delete state.lang;
  else state.lang = lang;
  writePrivate(file, `${JSON.stringify(state, null, 2)}\n`);
}

// Small user preferences kept next to the mode (for example `window`: open the alerts window).
export const getSetting = (key, fallback, home = guardHome()) => readJson(path.join(home, 'state.json'))?.settings?.[key] ?? fallback;

export function setSetting(key, value, home = guardHome()) {
  const file = path.join(home, 'state.json');
  const state = readJson(file) ?? {};
  writePrivate(file, `${JSON.stringify({ ...state, settings: { ...state.settings, [key]: value } }, null, 2)}\n`);
}

export const logDir = (home = guardHome()) => path.join(home, 'log');

const logFile = (home, d = new Date()) => path.join(home, 'log', `${d.toISOString().slice(0, 7)}.jsonl`);

export function appendLog(entries, sessionId, home = guardHome()) {
  if (!entries.length) return;
  const ts = new Date().toISOString();
  const s = sessionHash(sessionId);
  const lines = entries.map((e) => JSON.stringify({ ts, s, ...e })).join('\n');
  writePrivate(logFile(home), `${lines}\n`, 'a');
}

// Recent log entries (this month and last), newest last.
export function readLog(home = guardHome(), { since = null } = {}) {
  const now = new Date();
  const prev = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 15));
  const out = [];

  for (const f of [logFile(home, prev), logFile(home, now)]) {
    let text;

    try { text = fs.readFileSync(f, 'utf8'); } catch { continue; }

    for (const line of text.split('\n')) {
      if (!line) continue;

      try {
        const e = JSON.parse(line);

        if (!since || e.ts >= since) out.push(e);
      } catch { /* a partial line from a crash is skipped */ }
    }
  }

  return out;
}

const sessionFile = (home, id) => path.join(home, 'sessions', `${sessionHash(id)}.json`);

export const getSession = (id, home = guardHome()) => readJson(sessionFile(home, id)) ?? {};

export function setSession(id, patch, home = guardHome()) {
  writePrivate(sessionFile(home, id), JSON.stringify({ ...getSession(id, home), ...patch }));
}

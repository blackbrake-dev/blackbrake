// Installs guard's hooks into coding agents other than Claude Code (which gets a plugin, see
// install.mjs). What it writes:
//   ~/.blackbrake/app            a copy of this package's code and rules, which the hooks run
//   ~/.blackbrake/backups/…      a copy of each agent config file before it is changed
//   the agent's hook config      only the entries that run ~/.blackbrake/app/src/guard/hook.mjs
// Safety: a config that is not valid JSON, or that is a symbolic link, is left alone; writes are
// atomic; other entries in the file are kept exactly; uninstall removes only guard's entries.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { t } from '../i18n.mjs';
import { autostartInstalled } from './autostart.mjs';
import { roamingDir } from './registry.mjs';
import { appManifest, assertOwnFolder } from './install.mjs';

export { appManifest };

import { getMode, guardHome, hasMode, setMode } from './state.mjs';
import { isRecord } from '../kinds.mjs';

const PKG_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

// Recognises guard's own entries in any agent's config, whatever the quoting or separators.
const OURS = /[\\/]\.blackbrake[\\/]+app[\\/]+src[\\/]+guard[\\/]+hook\.mjs/;

// A hook path that goes through a shell must not carry characters a shell would reinterpret.
const SHELL_UNSAFE = /["'`$%!\r\n]/;

// Deletes ~/.blackbrake/app only when it is really guard's copy (a directory, not a link, holding
// the package.json guard writes); anything else there is left alone and reported.
function removeOwnApp(dest) {
  if (!fs.existsSync(dest)) return;
  const st = fs.lstatSync(dest);
  let name = null;

  try { name = JSON.parse(fs.readFileSync(path.join(dest, 'package.json'), 'utf8')).name; } catch { /* not ours */ }

  if (st.isSymbolicLink() || !st.isDirectory() || name !== 'blackbrake-guard') throw new Error(t('Refusing to replace {dir}: it is not a copy blackbrake made.', { dir: dest }));
  fs.rmSync(dest, { recursive: true, force: true });
}

export const hookScript = (home = guardHome()) => path.join(home, 'app', 'src', 'guard', 'hook.mjs');

export function buildRuntime({ home = guardHome(), pkgRoot = PKG_ROOT } = {}) {
  const guard = assertOwnFolder(home);
  const dest = path.join(guard, 'app');
  // Built complete in a new folder first, then swapped in: hooks already pointing at the copy never
  // see a half-written one if the copy fails.
  const next = path.join(guard, `app.${crypto.randomBytes(4).toString('hex')}.tmp`);

  try {
    fs.cpSync(path.join(pkgRoot, 'src'), path.join(next, 'src'), { recursive: true });
    fs.mkdirSync(path.join(next, 'vendor'), { recursive: true });
    fs.copyFileSync(path.join(pkgRoot, 'vendor', 'gitleaks.rules.json'), path.join(next, 'vendor', 'gitleaks.rules.json'));
    const pkg = JSON.parse(fs.readFileSync(path.join(pkgRoot, 'package.json'), 'utf8'));
    fs.writeFileSync(path.join(next, 'package.json'), `${JSON.stringify({ name: 'blackbrake-guard', version: pkg.version, type: 'module', private: true }, null, 2)}\n`);
    // What the background watcher checks before it runs at login (see watch-main.mjs).
    fs.writeFileSync(path.join(next, 'manifest.json'), `${JSON.stringify(appManifest(next), null, 2)}\n`);
    removeOwnApp(dest);
    fs.renameSync(next, dest);
  } finally {
    fs.rmSync(next, { recursive: true, force: true });
  }

  return dest;
}

// ---------- reading and writing agent config files ----------

function assertNoLinksBelow(file, stop) {
  const top = path.resolve(stop).toLowerCase();

  for (let p = path.dirname(path.resolve(file)); p.toLowerCase().startsWith(top) && p.toLowerCase() !== top; p = path.dirname(p)) {
    let st = null;

    try { st = fs.lstatSync(p); } catch { /* not created yet */ }

    if (st?.isSymbolicLink()) throw new Error(t('{file} is a symbolic link; blackbrake does not write through links. Add the hooks by hand or replace the link with a file.', { file: p }));
  }
}

function readConfig(file) {
  let st = null;

  try { st = fs.lstatSync(file); } catch { return {}; }

  if (st.isSymbolicLink()) throw new Error(t('{file} is a symbolic link; blackbrake does not write through links. Add the hooks by hand or replace the link with a file.', { file }));

  if (!st.isFile()) throw new Error(t('{file} is not a regular file.', { file }));
  const text = fs.readFileSync(file, 'utf8');

  if (!text.trim()) return {};

  try {
    const value = JSON.parse(text);

    if (isRecord(value)) return value;
  } catch { /* reported below */ }

  throw new Error(t('{file} is not valid JSON; blackbrake will not change it. Fix it and run setup again.', { file }));
}

function writeConfig(file, value, { home, id }) {
  // No link between the home folder and the config (a linked ~/.codex would send the write, and a
  // later uninstall, into whatever folder it points at).
  assertNoLinksBelow(file, os.homedir());

  if (fs.existsSync(file)) {
    // Configs can hold tokens: the copy is private to the user, and never overwrites anything.
    const dir = path.join(assertOwnFolder(home), 'backups');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const copy = path.join(dir, `${id}-${new Date().toISOString().replace(/[:.]/g, '-')}-${crypto.randomBytes(3).toString('hex')}${path.extname(file) || '.json'}`);
    fs.writeFileSync(copy, fs.readFileSync(file), { flag: 'wx', mode: 0o600 });
  }

  fs.mkdirSync(path.dirname(file), { recursive: true });
  // Unpredictable name, created exclusively: a planted file or link at that path cannot be followed.
  const tmp = `${file}.${crypto.randomBytes(6).toString('hex')}.blackbrake-tmp`;

  try {
    const mode = fs.existsSync(file) ? fs.statSync(file).mode & 0o777 : 0o600;
    fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode });
    fs.renameSync(tmp, file);
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

const commandOf = (entry) => [entry?.command, entry?.powershell, entry?.bash, entry?.exec, ...(entry?.args ?? [])].filter(Boolean).join(' ');

// Removes guard's handlers from a `{ Event: [ group | handler ] }` map; drops what becomes empty.
function stripOurs(hooks = {}) {
  const out = {};

  for (const [event, list] of Object.entries(hooks)) {
    if (!Array.isArray(list)) {
      out[event] = list;
      continue;
    }

    const kept = list.flatMap((item) => {
      if (Array.isArray(item?.hooks)) {
        const inner = item.hooks.filter((h) => !OURS.test(commandOf(h)));

        return inner.length ? [{ ...item, hooks: inner }] : [];
      }

      return OURS.test(commandOf(item)) ? [] : [item];
    });

    if (kept.length) out[event] = kept;
  }

  return out;
}

const hasOurs = (hooks = {}) => Object.values(hooks).some((list) => Array.isArray(list) && list.some((item) => OURS.test(commandOf(item)) || (item?.hooks ?? []).some((h) => OURS.test(commandOf(h)))));

const quoted = (hook) => {
  if (SHELL_UNSAFE.test(hook)) throw new Error(t('The path {path} has characters a shell would reinterpret; set BLACKBRAKE_HOME to a simpler folder.', { path: hook }));

  return `"${hook}"`;
};

// ---------- one entry per agent ----------

// Local absolute paths only: a network path (\\host\share) would open a connection and send the
// user's NTLM hash on Windows.
const envHome = (name, fallback) => (process.env[name] && path.isAbsolute(process.env[name]) && !/^[\\/]{2}/.test(process.env[name]) ? process.env[name] : fallback);

// Agents whose config is a shared JSON file with a `hooks` map of matcher groups.
function groupAgent({ id, name, dir, file, events, handler, note }) {
  return {
    id,
    name,
    note,
    detect: () => fs.existsSync(dir()),
    configFile: file,
    installed: (strict = false) => {
      try { return hasOurs(readConfig(file()).hooks); } catch (e) { if (strict) throw e;

 return false; }
    },
    install({ home, hook }) {
      const config = readConfig(file());
      const hooks = stripOurs(config.hooks);

      for (const event of events) (hooks[event] ??= []).push({ hooks: [handler(`node ${quoted(hook)} ${event} --harness ${id}`)] });
      writeConfig(file(), { ...config, hooks }, { home, id });
    },
    uninstall({ home }) {
      const config = readConfig(file());

      if (!hasOurs(config.hooks)) return false;
      writeConfig(file(), { ...config, hooks: stripOurs(config.hooks) }, { home, id });

      return true;
    },
  };
}

const codex = groupAgent({
  id: 'codex',
  name: 'Codex',
  dir: () => envHome('CODEX_HOME', path.join(os.homedir(), '.codex')),
  file: () => path.join(envHome('CODEX_HOME', path.join(os.homedir(), '.codex')), 'hooks.json'),
  events: ['SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'PostCompact'],
  handler: (command) => ({ type: 'command', command, timeout: 30 }),
  note: 'Codex runs new hooks only after you trust them: open Codex, type /hooks and trust the blackbrake entries.',
});

const gemini = groupAgent({
  id: 'gemini',
  name: 'Gemini CLI',
  dir: () => path.join(os.homedir(), '.gemini'),
  file: () => path.join(os.homedir(), '.gemini', 'settings.json'),
  events: ['SessionStart', 'BeforeAgent', 'BeforeTool', 'AfterTool', 'PreCompress'],
  handler: (command) => ({ type: 'command', name: 'blackbrake', command, timeout: 30000 }),
});

// Devin CLI: the "hooks" key of its user config (%APPDATA%\devin\config.json on Windows,
// ~/.config/devin/config.json elsewhere), same shape as Codex. The file holds other settings too;
// they are kept exactly.
const devinDir = () => (process.platform === 'win32' ? path.join(roamingDir(), 'devin') : path.join(os.homedir(), '.config', 'devin'));

const devin = groupAgent({
  id: 'devin',
  name: 'Devin CLI',
  dir: devinDir,
  file: () => path.join(devinDir(), 'config.json'),
  events: ['SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'PostCompaction'],
  handler: (command) => ({ type: 'command', command, timeout: 30 }),
  note: 'Devin CLI loads new hooks in new sessions: restart the sessions that are open.',
});

// Cursor and Windsurf: handlers directly under each event, no matcher groups.
function flatAgent({ id, name, dir, file, events, handler, base = {} }) {
  return {
    id,
    name,
    detect: () => fs.existsSync(dir()),
    configFile: file,
    installed: (strict = false) => {
      try { return hasOurs(readConfig(file()).hooks); } catch (e) { if (strict) throw e;

 return false; }
    },
    install({ home, hook }) {
      const config = readConfig(file());
      const hooks = stripOurs(config.hooks);

      for (const event of events) (hooks[event] ??= []).push(handler(hook, event));
      writeConfig(file(), { ...base, ...config, hooks }, { home, id });
    },
    uninstall({ home }) {
      const config = readConfig(file());

      if (!hasOurs(config.hooks)) return false;
      writeConfig(file(), { ...config, hooks: stripOurs(config.hooks) }, { home, id });

      return true;
    },
  };
}

const cursor = flatAgent({
  id: 'cursor',
  name: 'Cursor',
  dir: () => path.join(os.homedir(), '.cursor'),
  file: () => path.join(os.homedir(), '.cursor', 'hooks.json'),
  events: ['sessionStart', 'beforeSubmitPrompt', 'beforeShellExecution', 'beforeReadFile', 'beforeMCPExecution', 'preToolUse', 'postToolUse', 'preCompact'],
  handler: (hook, event) => ({ command: `node ${quoted(hook)} ${event} --harness cursor`, timeout: 30 }),
  base: { version: 1 },
});

const windsurf = flatAgent({
  id: 'windsurf',
  name: 'Windsurf',
  dir: () => path.join(os.homedir(), '.codeium', 'windsurf'),
  file: () => path.join(os.homedir(), '.codeium', 'windsurf', 'hooks.json'),
  events: ['pre_user_prompt', 'pre_read_code', 'pre_write_code', 'pre_run_command', 'pre_mcp_tool_use'],
  // bash -c on macOS/Linux, powershell -Command on Windows: single quotes are literal in both.
  handler: (hook, event) => {
    quoted(hook);

    return { command: `node '${hook.replace(/\\/g, '/')}' ${event} --harness windsurf`, powershell: `& node '${hook}' ${event} --harness windsurf`, show_output: true };
  },
});

// Copilot CLI reads every *.json in ~/.copilot/hooks: guard gets a file of its own, run without a shell.
const copilotDir = () => envHome('COPILOT_HOME', path.join(os.homedir(), '.copilot'));

const copilot = {
  id: 'copilot',
  name: 'GitHub Copilot CLI',
  detect: () => fs.existsSync(copilotDir()),
  configFile: () => path.join(copilotDir(), 'hooks', 'blackbrake.json'),
  installed: (strict = false) => {
    try { return hasOurs(readConfig(copilot.configFile()).hooks); } catch (e) { if (strict) throw e;

 return false; }
  },
  install({ home, hook }) {
    const entry = (event) => [{ type: 'command', exec: 'node', args: [hook, event, '--harness', 'copilot'], timeoutSec: 30 }];
    // Whatever else the user added to this file (other keys, other handlers) is kept.
    const config = readConfig(copilot.configFile());
    const hooks = stripOurs(config.hooks);

    for (const event of ['userPromptSubmitted', 'PreToolUse', 'postToolUse']) hooks[event] = [...(hooks[event] ?? []), ...entry(event)];
    writeConfig(copilot.configFile(), { ...config, version: 1, hooks }, { home, id: 'copilot' });
  },
  // Only guard's entries go; the file is deleted only when nothing else was added to it.
  uninstall({ home }) {
    const file = copilot.configFile();
    const config = readConfig(file);

    if (!hasOurs(config.hooks)) return false;
    const hooks = stripOurs(config.hooks);

    if (Object.keys(hooks).length) writeConfig(file, { ...config, hooks }, { home, id: 'copilot' });
    else fs.rmSync(file, { force: true });

    return true;
  },
};

export const AGENTS = { codex, gemini, cursor, copilot, windsurf, devin };

export const detectedAgents = () => Object.values(AGENTS).filter((a) => a.detect());

export function setupAgents(ids, { log = () => {}, home = guardHome() } = {}) {
  const agents = ids.map((id) => AGENTS[id] ?? (() => { throw new Error(t('Unknown agent "{id}". Known: {list}.', { id, list: Object.keys(AGENTS).join(', ') })); })());
  const runtime = buildRuntime({ home });
  log(t('Copied guard to {dir}', { dir: runtime }));
  const hook = hookScript(home);
  const notes = [];
  const failed = [];

  // One copy for all of them; one agent's broken config does not stop the others.
  for (const a of agents) {
    try {
      a.install({ home, hook });
      log(t('Added guard\'s hooks to {name} ({file})', { name: a.name, file: a.configFile() }));

      if (a.note) notes.push(t(a.note));
    } catch (e) {
      failed.push({ id: a.id, name: a.name, error: e.message });
    }
  }

  if (!hasMode(home)) setMode('observe', home);

  return { mode: getMode(home), notes, failed };
}

export function uninstallAgents(ids, { log = () => {}, home = guardHome() } = {}) {
  const failed = [];

  // One agent's broken config must not leave the others half removed.
  for (const id of ids) {
    const a = AGENTS[id];

    try {
      if (a?.uninstall({ home })) log(t('Removed guard\'s hooks from {name}', { name: a.name }));
    } catch (e) {
      failed.push(`${a?.name ?? id}: ${e.message}`);
    }
  }

  // The shared copy goes only when no agent config can still point at it: one that exists but
  // cannot be read may still hold guard's entries, and hooks to a deleted script can block an agent.
  // The background watcher also runs from the copy.
  const inUse = autostartInstalled() || Object.values(AGENTS).some((a) => {
    if (!fs.existsSync(a.configFile())) return false;

    try { return a.installed(true); } catch { return true; }
  });

  if (!inUse) removeOwnApp(path.join(assertOwnFolder(home), 'app'));

  if (failed.length) throw new Error(t('Could not remove guard from: {list}', { list: failed.join('; ') }));
}


// Installs guard into Claude Code as a plugin from a local marketplace under ~/.blackbrake.
// What it writes: ~/.blackbrake/marketplace (a copy of this package's plugin, code and rules) and
// ~/.blackbrake/state.json. What it runs: `claude plugin marketplace add|update|remove` and
// `claude plugin install|uninstall`. It never edits Claude Code's settings files itself.
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { t } from '../i18n.mjs';
import { clean, isLocalPath } from '../text.mjs';
import { mayChange } from './safety.mjs';
import { getMode, guardHome, hasMode, setMode } from './state.mjs';

const claudeConfigDir = () => process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude');

export const PLUGIN_ID = 'blackbrake@blackbrake';

const MARKETPLACE = 'blackbrake';

// The package root (this file is src/guard/install.mjs).
const PKG_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

const copyDir = (from, to) => fs.cpSync(from, to, { recursive: true, force: true, filter: (src) => !/[\\/](node_modules|\.git)([\\/]|$)/.test(src) });

// sha256 of every file of the copy (src/ and vendor/), relative paths with forward slashes.
export function appManifest(app) {
  const out = {};

  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);

      if (e.isDirectory()) walk(full);
      else if (e.isFile()) out[path.relative(app, full).replace(/\\/g, '/')] = crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex');
    }
  };

  for (const d of ['src', 'vendor']) walk(path.join(app, d));

  return out;
}

// No symbolic link or junction anywhere on the way to a path, from the filesystem root down: a
// link higher up would send writes and recursive deletes somewhere else.
export function assertNoLinks(target) {
  const abs = path.resolve(target);

  for (let p = abs; ; p = path.dirname(p)) {
    let st = null;

    try { st = fs.lstatSync(p); } catch { /* not created yet */ }

    // A link owned by root on macOS or Linux (/var -> /private/var, /tmp on some systems) is part of
    // the system: a process running as the user cannot create or change it.
    if (st?.isSymbolicLink() && !(process.platform !== 'win32' && st.uid === 0)) throw new Error(`Refusing to use ${abs}: ${p} is a symbolic link or junction.`);

    if (p === path.dirname(p)) break;
  }

  return abs;
}

// guard's folder must be a real directory of its own: not a symlink or junction (which would make
// a recursive delete land elsewhere), not the home folder, not a drive or filesystem root.
export function assertOwnFolder(dir) {
  const abs = mayChange(path.resolve(dir));

  // An 8.3 short name (C:\Users\ALUCE~1), a \\?\ prefix or a trailing dot names the home folder
  // without spelling it (review C, 2026-10-01). The same folder on disk (device and file id) is the
  // same folder whatever it is called.
  const id = (p) => {
    try {
      const st = fs.statSync(p, { bigint: true });

      return `${st.dev}:${st.ino}`;
    } catch {
      return null;
    }
  };

  const norm = (p) => path.resolve(p).replace(/^\\\\\?\\/, '').replace(/[. ]+$/, '').toLowerCase();
  const places = [os.homedir(), path.parse(abs).root, path.dirname(os.homedir())];
  const own = id(abs);

  if (places.map(norm).includes(norm(abs)) || (own && places.map(id).includes(own))) throw new Error(`Refusing to use ${abs} as blackbrake's folder.`);

  assertNoLinks(abs);

  return abs;
}

// Whether a folder is the marketplace blackbrake made: a real folder holding its manifest, or what a
// removal interrupted on Windows leaves behind (a file in use): only guard's own two entries, with
// guard's own package in them, or nothing at all. Anything else is not touched.
function ownMarketplace(dest) {
  const readJson = (f) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; } };

  if (fs.lstatSync(dest).isSymbolicLink() || !fs.statSync(dest).isDirectory()) return false;
  const manifest = readJson(path.join(dest, '.claude-plugin', 'marketplace.json'));

  if (manifest) return manifest.name === MARKETPLACE;
  const entries = fs.readdirSync(dest);

  if (entries.some((n) => n !== '.claude-plugin' && n !== 'blackbrake')) return false;
  const files = [];

  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (e.isSymbolicLink()) files.push('link');
      else if (e.isDirectory()) walk(path.join(d, e.name));
      else files.push(e.name);
    }
  };

  walk(dest);

  return !files.includes('link') && (files.length === 0 || readJson(path.join(dest, 'blackbrake', 'app', 'package.json'))?.name === 'blackbrake-guard');
}

// Deletes one of guard's folders. On Windows a file in use (an antivirus scan, the alerts window)
// can refuse a delete for a moment: retry, then say what to do instead of leaving it half gone.
export function removeOwn(dir) {
  mayChange(path.resolve(dir));

  try {
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 6, retryDelay: 250 });
  } catch (e) {
    throw new Error(`Could not delete ${dir} (${e.code ?? 'in use'}): close the blackbrake alerts window and try again.`);
  }
}

// Build ~/.blackbrake/marketplace from the package. Returns its path.
export function buildMarketplace({ home = guardHome(), pkgRoot = PKG_ROOT } = {}) {
  const pkg = JSON.parse(fs.readFileSync(path.join(pkgRoot, 'package.json'), 'utf8'));
  const guard = assertOwnFolder(home);
  const dest = path.join(guard, 'marketplace');

  if (fs.existsSync(dest)) {
    // Replace only a marketplace blackbrake made.
    if (!ownMarketplace(dest)) throw new Error(`Refusing to replace ${dest}: it is not a marketplace blackbrake made.`);
    removeOwn(dest);
  }

  copyDir(path.join(pkgRoot, 'plugin'), dest);
  const app = path.join(dest, 'blackbrake', 'app');
  copyDir(path.join(pkgRoot, 'src'), path.join(app, 'src'));
  fs.mkdirSync(path.join(app, 'vendor'), { recursive: true });
  fs.copyFileSync(path.join(pkgRoot, 'vendor', 'gitleaks.rules.json'), path.join(app, 'vendor', 'gitleaks.rules.json'));
  fs.writeFileSync(path.join(app, 'package.json'), `${JSON.stringify({ name: 'blackbrake-guard', version: pkg.version, type: 'module', private: true }, null, 2)}\n`);
  // The same integrity manifest as the shared copy: the alerts window runs from here too.
  fs.writeFileSync(path.join(app, 'manifest.json'), `${JSON.stringify(appManifest(app), null, 2)}\n`);
  const manifest = path.join(dest, 'blackbrake', '.claude-plugin', 'plugin.json');
  fs.writeFileSync(manifest, `${JSON.stringify({ ...JSON.parse(fs.readFileSync(manifest, 'utf8')), version: pkg.version }, null, 2)}\n`);

  return dest;
}

// On Windows, Claude Code's native installer puts a real claude.exe on PATH; spawning it directly
// needs no shell. Only npm's claude.cmd shim needs cmd.exe.
export function findClaudeExe(env = process.env) {
  if (process.platform !== 'win32') return null;

  for (const dir of String(env.PATH ?? env.Path ?? '').split(';')) {
    const d = dir.replace(/"/g, '');

    if (!d || !isLocalPath(d)) continue;
    const exe = path.join(d, 'claude.exe');

    try { if (fs.statSync(exe).isFile()) return exe; } catch { /* not here */ }
  }

  return null;
}

// Characters cmd.exe reinterprets even inside double quotes (% and ! expand variables) or that
// end a quoted argument. Anything passed through the shell must be free of them.
export const CMD_UNSAFE = /[%!"^&|<>()\r\n]/;

// The command and argument list to start Claude Code with, and whether a shell is needed.
export function claudeCommand(args) {
  if (process.platform !== 'win32') return { file: 'claude', args, shell: false };
  const exe = findClaudeExe();

  if (exe) return { file: exe, args, shell: false };

  if (args.some((a) => CMD_UNSAFE.test(String(a)))) throw new Error('These arguments contain characters cmd.exe would reinterpret; run "claude" directly, or install Claude Code with its native installer.');

  return { file: ['claude', ...args.map((a) => (/^[\w@.:\\/-]+$/.test(a) ? a : `"${a}"`))].join(' '), args: [], shell: true };
}

// Run the Claude Code CLI with fixed arguments and paths we built.
export function runClaude(args, { capture = true } = {}) {
  // Installing or removing plugins and marketplaces changes the real Claude Code configuration.
  if (/^(install|uninstall|enable|disable|add|remove|rm|update)$/.test(args[1] ?? '') || /^(install|uninstall|enable|disable|add|remove|rm|update)$/.test(args[2] ?? '')) mayChange(path.resolve(claudeConfigDir()));
  const c = claudeCommand(args);
  const r = spawnSync(c.file, c.args, { encoding: 'utf8', stdio: capture ? 'pipe' : 'inherit', timeout: 120000, shell: c.shell });
  const out = clean(`${r.stdout ?? ''}${r.stderr ?? ''}`.trim(), 2000);

  return { ok: r.status === 0, out, missing: r.error?.code === 'ENOENT' || (c.shell && r.status !== 0 && /is not recognized|no se reconoce/i.test(out)) };
}

// Installed and enabled, from Claude Code's own files (no process needed).
export function guardInstalled(claudeHome = process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude')) {
  const readJson = (f) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; } };

  const installed = readJson(path.join(claudeHome, 'plugins', 'installed_plugins.json'));
  const settings = readJson(path.join(claudeHome, 'settings.json')) ?? {};
  const present = Boolean(installed?.plugins?.[PLUGIN_ID]);

  return { installed: present, enabled: present && settings.enabledPlugins?.[PLUGIN_ID] !== false };
}

export function setup({ log = () => {} } = {}) {
  // Claude Code runs the hooks with `node` from PATH; without it guard would silently never run.
  if (spawnSync('node', ['--version'], { encoding: 'utf8' }).status !== 0) throw new Error('"node" is not on PATH, so Claude Code could not run guard\'s hooks. Install Node.js 20+ and try again.');
  const dir = buildMarketplace();
  log(t('Copied the guard plugin to {dir}', { dir }));

  let r = runClaude(['plugin', 'marketplace', 'add', dir]);

  if (r.missing) throw new Error('Claude Code ("claude") was not found on PATH.');

  if (!r.ok) {
    // Already registered: refresh it from the new copy instead.
    r = runClaude(['plugin', 'marketplace', 'update', MARKETPLACE]);

    if (!r.ok) throw new Error(`claude plugin marketplace failed: ${r.out}`);
  }

  log(t('Registered the local marketplace with Claude Code'));
  r = runClaude(['plugin', 'install', PLUGIN_ID]);

  if (!r.ok) {
    r = runClaude(['plugin', 'update', PLUGIN_ID]);

    if (!r.ok) throw new Error(`claude plugin install failed: ${r.out}`);
  }

  log(t('Installed {id}', { id: PLUGIN_ID }));

  // First installation starts in observe; a mode the user already chose is kept.
  if (!hasMode()) setMode('observe');

  return { mode: getMode(), statusline: path.join(dir, 'blackbrake', 'app', 'src', 'guard', 'statusline.mjs') };
}

export function uninstall({ keepLog = true, log = () => {} } = {}) {
  // Checked before anything at all is done, Claude Code's plugin removal included (safety.mjs).
  mayChange(path.resolve(guardHome()));
  mayChange(path.resolve(claudeConfigDir()));
  const r1 = runClaude(['plugin', 'uninstall', PLUGIN_ID]);
  log(r1.ok ? t('Uninstalled {id}', { id: PLUGIN_ID }) : t('Plugin was not installed ({why})', { why: r1.out.split('\n')[0] || '-' }));
  const r2 = runClaude(['plugin', 'marketplace', 'remove', MARKETPLACE]);
  log(t(r2.ok ? 'Removed the local marketplace' : 'Local marketplace was not registered'));
  const home = assertOwnFolder(guardHome());
  const market = path.join(home, 'marketplace');

  // A copy that cannot be deleted right now is left for the next setup, which recognises it.
  if (fs.existsSync(market) && !fs.lstatSync(market).isSymbolicLink()) {
    try { removeOwn(market); } catch (e) { log(clean(e.message, 300)); }
  }

  if (!keepLog) {
    // Delete only what guard creates, never a folder with anything else in it.
    const unknown = fs.existsSync(home) ? fs.readdirSync(home).filter((n) => !GUARD_ENTRIES.has(n)) : [];

    if (unknown.length) throw new Error(`Not deleting ${home}: it contains files blackbrake did not create (${unknown.slice(0, 3).join(', ')}).`);

    for (const n of GUARD_ENTRIES) {
      const p = path.join(home, n);

      if (fs.existsSync(p) && !fs.lstatSync(p).isSymbolicLink()) fs.rmSync(p, { recursive: true, force: true });
    }

    // Already gone (a second purge, or removed by hand) is fine: the verification screen follows.
    try { fs.rmdirSync(home); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  }

  log(keepLog ? t('Kept your guard log in {dir}', { dir: path.join(home, 'log') }) : t('Deleted {dir}', { dir: home }));
}

export const GUARD_ENTRIES = new Set(['state.json', 'log', 'sessions', 'marketplace', 'app', 'backups', 'watch.pid', 'watch-bg.pid', 'window.claim', 'window.last', 'fixes', 'reports']);

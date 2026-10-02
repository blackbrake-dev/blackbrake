// "Uninstall blackbrake…" in the main menu, and the one flow `blackbrake uninstall` shares with it
// (the command itself stays a built-in of bin/blackbrake.mjs, which calls runUninstall).
//
//   screen   what will go, what stays, what is left to do by hand (calculated live)
//   choose   Cancel (first, preselected) / uninstall and keep my data / uninstall and delete my data
//   confirm  a typed word, a different one per path: remove|quitar, purge|borrar
//   do       login item + the whole process table swept (src/guard/procs.mjs), hooks, Claude plugin
//   check    what a second look at the machine finds is what is shown, never "what I tried"
//
// Everything that touches the machine goes through `deps`, so the tests never do.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { AGENTS, uninstallAgents } from '../../guard/agents.mjs';
import { autostartFile, autostartInstalled, removeAutostart } from '../../guard/autostart.mjs';
import { confirmTyped, isInteractive } from '../../guard/cli.mjs';
import { requireHuman } from '../../guard/human.mjs';
import { GUARD_ENTRIES, guardInstalled, uninstall as uninstallClaudePlugin } from '../../guard/install.mjs';
import { clearPaused, isPaused } from '../../guard/pause.mjs';
import { findWatchers, findWindows } from '../../guard/procs.mjs';
import { guardHome } from '../../guard/state.mjs';
import { getLang, t } from '../../i18n.mjs';
import { isText } from '../../kinds.mjs';
import { clean } from '../../text.mjs';
import { select } from '../../ui/menu.mjs';
import { columns, screen } from '../../ui/term.mjs';

const WORDS = { keep: ['remove', 'quitar'], purge: ['purge', 'borrar'] };

const defaultPrint = (lines) => console.log(lines.join('\n'));

const claudeDir = () => process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude');

const NAMES = { claude: 'Claude Code' };

const nameOf = (id) => NAMES[id] ?? AGENTS[id]?.name ?? id;

// Whether the statusLine entry in Claude Code's settings runs blackbrake (read only: blackbrake never edits that file).
function statusLineMentionsUs() {
  try {
    const file = path.join(claudeDir(), 'settings.json');

    if (fs.statSync(file).size > 1024 * 1024) return false;
    const command = JSON.parse(fs.readFileSync(file, 'utf8'))?.statusLine?.command;

    return isText(command) && command.toLowerCase().includes('blackbrake');
  } catch {
    return false;
  }
}

export const realDeps = () => ({
  installedIds: () => [...(guardInstalled().installed ? ['claude'] : []), ...Object.values(AGENTS).filter((a) => a.installed()).map((a) => a.id)],
  targets(agent) {
    const ids = agent && agent !== 'all'
      ? agent.split(',').map((s) => s.trim()).filter((id) => id === 'claude' || AGENTS[id])
      : this.installedIds();

    return ids.map((id) => ({ id, name: nameOf(id) }));
  },
  // Other agents that still run guard from the shared folder (a purge would break them).
  foreignAgents: (ids) => Object.values(AGENTS).some((a) => {
    if (ids.includes(a.id) || !fs.existsSync(a.configFile())) return false;

    try { return a.installed(true); } catch { return true; }
  }),
  inspect() {
    const home = guardHome();
    const app = path.join(home, 'app');

    return {
      home,
      loginItem: { path: autostartFile(), present: autostartInstalled() },
      app: { path: app, present: fs.existsSync(app) },
      watchers: findWatchers(),
      windows: findWindows(),
      statusLine: statusLineMentionsUs(),
      blockers: fs.existsSync(home) ? fs.readdirSync(home).filter((n) => !GUARD_ENTRIES.has(n)) : [],
    };
  },
  removeLoginItem: (o) => removeAutostart(o),
  removeHooks: (ids, { log }) => uninstallAgents(ids, { log }),
  removeClaude: (o) => uninstallClaudePlugin(o),
  // A pause left behind would block a later "blackbrake setup" ("run resume first").
  clearPause: () => { if (isPaused()) clearPaused(); },
  select,
});

// ---------- the screen before the word ----------

const list = (items) => items.map((i) => i.name).join(', ');

function planLines(p, { names, hasClaude, info, all }) {
  const bullet = (text) => `    ${p.amber('•')} ${p.cream(text)}`;
  const out = [...screen(p, t('UNINSTALL'), t('remove blackbrake'), columns(), { pose: 'worried', line: t('This removes my protection from your agents.') }), `  ${p.bold(p.cream(t('Will remove')))}`];

  if (names.length) out.push(bullet(t('Guard hooks from: {list}', { list: list(names) })));

  if (hasClaude) out.push(bullet(t('The Claude Code plugin and its marketplace')));

  if (all) {
    if (info.loginItem.present) out.push(bullet(t('The login item: {path}', { path: clean(info.loginItem.path, 200) })));
    out.push(bullet(t(info.watchers === null ? 'Background watcher: could not check (the list of processes could not be read)' : info.watchers.length ? 'Background watcher: running' : 'Background watcher: not running')));

    if (info.windows?.length) out.push(bullet(t('Alerts windows open: {n}', { n: info.windows.length })));
  }

  if (info.app.present) out.push(bullet(t('The shared copy in {dir}', { dir: clean(info.app.path, 200) })));
  out.push('', `  ${p.bold(p.cream(t('Will keep (unless you delete everything)')))}`);
  out.push(bullet(t('Your alert log, settings, configuration backups, the private copies that "fix" made (they undo a fix) and your saved reports, in {dir}', { dir: clean(info.home, 200) })));
  out.push('', `  ${p.bold(p.cream(t('You will have to do yourself')))}`);
  out.push(bullet(t('Remove the package (npm runs no uninstall scripts): npm uninstall -g blackbrake')));

  if (info.statusLine) out.push(bullet(t('Remove the "statusLine" entry from ~/.claude/settings.json: it still runs blackbrake')));

  return [...out, ''];
}

// The questions are the same in the menu and in the command; only where they are asked differs.
async function confirmUninstall(p, { purge, names }, { io, print }) {
  const [word, alias] = WORDS[purge ? 'purge' : 'keep'];

  if (purge) print(['', `  ${p.amber(t('This also deletes your alert log, your settings, the private copies that "fix" made (you will not be able to undo a fix) and your saved reports.'))}`]);
  const question = purge ? t('Remove blackbrake and delete all its data?') : t('Remove blackbrake from {list}?', { list: list(names) || t('every agent') });

  return confirmTyped(p, question, word, getLang() === 'es' ? alias : null, io);
}

// What a purge cannot do, found before a word is asked for.
function checkPurge(ids, info, deps) {
  if (deps.foreignAgents(ids)) throw new Error(t('Other agents still use guard; remove them too (--agent all) before --purge.'));

  if (info.blockers.length) throw new Error(t('Not deleting {dir}: it contains files blackbrake did not create ({list}).', { dir: info.home, list: info.blockers.slice(0, 3).join(', ') }));
}

const nothingChanged = (p, io, print) => {
  const interactive = isInteractive(io);

  print(['', `  ${p.faint(t(interactive ? 'Nothing changed.' : 'Nothing changed: removing guard must be confirmed in an interactive terminal.'))}`, '']);

  return requireHuman({ env: io.env, input: io.input ?? process.stdin, output: io.output ?? process.stdout }).ok ? 0 : 1;
};

const killHint = (pids, platform = process.platform) => (platform === 'win32' ? `taskkill ${pids.map((n) => `/PID ${n}`).join(' ')} /F` : `kill ${pids.join(' ')}`);

// ---------- what the machine looks like afterwards ----------

function finalLines(p, { ids, names, all, purge, before, after, sweep }) {
  const checks = [];
  const good = (text) => checks.push([true, text]);
  const bad = (text) => checks.push([false, text]);

  if (ids.length) {
    const left = ids.filter((id) => after.installed.includes(id));

    if (left.length) bad(t('Still installed in: {list}', { list: left.map(nameOf).join(', ') }));
    else good(t('Removed from: {list}', { list: list(names) }));
  }

  if (all) {
    if (before.loginItem.present || after.loginItem.present) {
      if (after.loginItem.present) bad(t('Login item still there: delete {path} by hand', { path: clean(after.loginItem.path, 200) }));
      else good(t('Login item removed'));
    }

    const w = sweep?.watchers ?? { found: after.watchers, remaining: after.watchers };
    const wi = sweep?.windows ?? { found: [], remaining: after.windows };

    // "Could not check" is never shown as stopped (review C: an unreadable process table said so).
    if (w.remaining === null || w.found === null) bad(t('Background watcher: could not check (the list of processes could not be read)'));
    else if (w.remaining.length) bad(t('Background watcher: still running (pid {pids}): close it by hand ({cmd})', { pids: w.remaining.join(', '), cmd: killHint(w.remaining) }));
    else good(t(w.found.length ? 'Background watcher: stopped' : 'Background watcher: not running'));

    if (wi.remaining === null || wi.found === null) bad(t('Alerts windows: could not check (the list of processes could not be read)'));
    else if (wi.remaining.length) bad(t('Alerts windows: still open (pid {pids}): close them by hand ({cmd})', { pids: wi.remaining.join(', '), cmd: killHint(wi.remaining) }));
    else if (wi.found.length) good(t('Alerts windows: closed ({n})', { n: wi.found.length }));

    if (sweep?.launchd === 'failed') bad(t('launchd would not let go of the login item: run "{cmd}" in your terminal', { cmd: `launchctl bootout gui/${process.getuid?.() ?? '<uid>'}/dev.blackbrake.watch` }));
  }

  if (purge) {
    if (after.dataPresent) bad(t('Your data is still in {dir}: delete it by hand', { dir: clean(after.home, 200) }));
    else good(t('Your data is deleted: {dir}', { dir: clean(after.home, 200) }));
  } else if (all) good(t('Your data is kept in {dir}', { dir: clean(after.home, 200) }));

  const clear = checks.every(([ok]) => ok);

  const head = !all ? [] : [`  ${clear ? p.green('✓') : p.coral('✗')} ${p.bold(p.cream(t(clear ? 'blackbrake is uninstalled. Nothing of mine is running.' : 'Not everything could be removed. This is what is left:')))}`];

  return { clear, lines: ['', ...head, ...checks.map(([ok, text]) => `    ${ok ? p.green('✓') : p.coral('✗')} ${p.cream(text)}`), ...(all ? ['', `  ${p.faint(t('Last step, in your terminal: npm uninstall -g blackbrake'))}`] : []), ''] };
}

// ---------- the flow ----------

const snapshot = (deps) => ({ ...deps.inspect(), installed: deps.installedIds() });

// `blackbrake uninstall [--agent <id,…>] [--purge]` and the menu's second half. Resolves to the exit
// code. `confirmed`: the menu already asked for the word (it never asks twice). `info`: a snapshot
// the caller already took.
export async function runUninstall(opts, p, { confirmed = false, io = {}, deps = realDeps(), print = defaultPrint, info = null } = {}) {
  const targets = deps.targets(opts.agent);
  const ids = targets.map((x) => x.id);
  const all = !opts.agent || opts.agent === 'all';
  const purge = Boolean(opts.purge);

  if (!confirmed) {
    const human = requireHuman({ env: io.env, input: io.input ?? process.stdin, output: io.output ?? process.stdout });

    if (human.ok) {
      info = snapshot(deps);

      // --purge deletes ~/.blackbrake, which other agents' hooks run from: checked before anything is asked or removed.
      if (purge) checkPurge(ids, info, deps);
      print(planLines(p, { names: targets, hasClaude: ids.includes('claude'), info, all }));
    }

    if (!(await confirmUninstall(p, { purge, names: targets }, { io, print }))) return nothingChanged(p, io, print);
  } else {
    info ??= snapshot(deps);

    if (purge) checkPurge(ids, info, deps);
  }

  const log = (m) => print([`  ${p.amber('✓')} ${t(m)}`]);
  let sweep = null;

  // Removing it from everything also stops the background watcher (every one of this user, found
  // in the process table), closes the alerts windows and removes the login item.
  if (all && deps.removeLoginItem({ sweep: true, windows: true, onSweep: (r) => { sweep = r; } })) log(t('Stopped the background watcher and removed its login item'));

  if (all) deps.clearPause?.();
  const hooks = ids.filter((id) => id !== 'claude');

  if (hooks.length) deps.removeHooks(hooks, { log });

  // A purge always goes through here: it is what deletes the folder, even when Claude Code never had guard.
  if (ids.includes('claude') || purge) deps.removeClaude({ keepLog: !purge, log });

  const result = finalLines(p, { ids, names: targets, all, purge, before: info, after: snapshot(deps), sweep });

  print(result.lines);

  return result.clear ? 0 : 1;
}

// The menu row: the screen, the choice (Cancel first), the word, and then the shared flow.
export async function runMenu(ctx, { io = {}, deps = realDeps() } = {}) {
  const { p } = ctx;
  const print = ctx.print ?? defaultPrint;
  const input = io.input ?? process.stdin;
  const output = io.output ?? process.stdout;
  const human = requireHuman({ env: io.env, input, output });

  if (!human.ok) {
    if (human.reason === 'agent') print(['', `  ${p.amber(human.message)}`, `  ${p.faint(human.how)}`]);
    nothingChanged(p, io, print);

    return {};
  }

  const targets = deps.targets('all');
  const ids = targets.map((x) => x.id);
  const info = snapshot(deps);

  print(planLines(p, { names: targets, hasClaude: ids.includes('claude'), info, all: true }));

  const choice = await (deps.select ?? select)(p, [
    { value: 'cancel', label: t('Cancel') },
    { value: 'keep', label: t('Uninstall and keep my data') },
    { value: 'purge', label: t('Uninstall and delete all my blackbrake data') },
  ], { input, output });

  if (choice !== 'keep' && choice !== 'purge') {
    print(['', `  ${p.faint(t('Nothing changed.'))}`, '']);

    return {};
  }

  const purge = choice === 'purge';

  try {
    checkPurge(purge ? ids : [], purge ? info : { blockers: [] }, purge ? deps : { foreignAgents: () => false });
  } catch (e) {
    print(['', `  ${p.amber(clean(e.message, 300))}`, '']);

    return {};
  }

  if (!(await confirmUninstall(p, { purge, names: targets }, { io, print }))) {
    print(['', `  ${p.faint(t('Nothing changed.'))}`, '']);

    return {};
  }

  const code = await runUninstall({ agent: 'all', purge }, p, { confirmed: true, io, deps, print, info });

  if (code) process.exitCode = code;

  return { exit: true };
}

export default {
  id: 'uninstall-menu',
  commands: [],
  menu: [
    {
      slot: 'main',
      order: 50,
      value: 'uninstall',
      label: () => t('Uninstall blackbrake…'),
      hint: () => t('remove it from every agent and stop everything'),
      run: (ctx) => runMenu(ctx),
    },
  ],
};

// "Pause all of blackbrake" / "Resume blackbrake" (guard-design §6x.2): a full, reversible stop that
// uninstalls nothing.
//
//   pause    lowers protection: a person at a terminal types pause|pausar (requireHuman). Then the
//            mark, the login item removed (settings.autostart is kept), the watcher and the alerts
//            windows stopped and checked by sweeping the process table (src/guard/procs.mjs), and a
//            screen with what a second look finds, never "what I tried".
//   resume   raises protection: no word, no terminal needed. The mark goes, the hooks are checked
//            (were any removed or changed during the pause?), the login item and the watcher come
//            back if the user wants them (settings.autostart), and the result is checked again.
//
// Paused, the hooks answer neutrally (src/guard/hook.mjs), the watcher and the window exit, and
// `setup`, `mode`, `window on`, `background on` and `permissions` refuse until resumed.
// Everything that touches the machine goes through `deps`, so the tests never do.
import { autostartInstalled, installAutostart, removeAutostart } from '../../guard/autostart.mjs';
import { agentsIntegrity, confirmTyped, integrity, modeBadge, pausedBadge } from '../../guard/cli.mjs';
import { requireHuman } from '../../guard/human.mjs';
import { clearPaused, pausedHours, pausedMark, setPaused } from '../../guard/pause.mjs';
import { findWatchers, findWindows } from '../../guard/procs.mjs';
import { getMode, getSetting, setSetting } from '../../guard/state.mjs';
import { getLang, t } from '../../i18n.mjs';
import { clean } from '../../text.mjs';
import { realDeps as uninstallDeps } from './uninstall-menu.mjs';

const defaultPrint = (lines) => console.log(lines.join('\n'));

const AGENT_ID = /^[a-z][a-z0-9-]{0,30}$/;

export const realDeps = () => ({
  targets: () => uninstallDeps().targets('all'),
  // Every watcher of this user (process table), the alerts windows and the login item; launchd too.
  stop() {
    let sweep = null;

    removeAutostart({ sweep: true, windows: true, onSweep: (r) => { sweep = r; } });

    return sweep;
  },
  loginItem: () => autostartInstalled(),
  watchers: () => findWatchers(),
  windows: () => findWindows(),
  start: () => installAutostart(),
  autostart: () => getSetting('autostart', true),
  integrity: () => integrity(),
  agentsIntegrity: () => agentsIntegrity(),
  mode: () => getMode(),
  mark: () => pausedMark(),
  // The agents that had guard when it was paused (to say which hooks went missing meanwhile).
  agentsAtPause: () => {
    const ids = getSetting('paused', null)?.agents;

    return Array.isArray(ids) ? ids.filter((id) => AGENT_ID.test(String(id))).slice(0, 20) : [];
  },
  setPaused: (by, agents) => {
    setPaused(by);
    setSetting('paused', { ...pausedMark(), agents });
  },
  clearPaused: () => clearPaused(),
});

const ok = (p, text) => `  ${p.green('✓')} ${p.cream(text)}`;

const bad = (p, text, how = '') => [`  ${p.coral('✗')} ${p.cream(text)}`, ...(how ? [`      ${p.faint(how)}`] : [])];

const killHint = (pids, platform = process.platform) => (platform === 'win32' ? `taskkill ${pids.map((n) => `/PID ${n}`).join(' ')} /F` : `kill ${pids.join(' ')}`);

// The sweeps (src/guard/procs.mjs) give plain pids.
const pidsOf = (list) => list.filter(Number.isSafeInteger);

// ---------- pause ----------

// Resolves to the exit code: 0 paused (or nothing to do), 1 when nothing changed because no person
// confirmed it at a terminal, or when something is still running afterwards.
export async function runPause(p, { by = 'cli', io = {}, deps = realDeps(), print = defaultPrint } = {}) {
  if (deps.mark()) {
    print(['', `  ${p.amber(t('blackbrake is already paused. "blackbrake resume" turns it back on.'))}`, '']);

    return 0;
  }

  const human = requireHuman({ env: io.env, input: io.input ?? process.stdin, output: io.output ?? process.stdout });
  const targets = human.ok ? deps.targets() : [];

  if (human.ok && !targets.length) {
    print(['', `  ${p.faint(t('Nothing to pause: blackbrake is not installed anywhere.'))}`, '']);

    return 0;
  }

  const question = t('Pause all of blackbrake? Nothing will protect your AI agents from leaking secrets or overspending until you resume: the hooks stay installed and only refuse attempts to switch blackbrake off, and the watcher and the alerts window stop.');

  if (!(await confirmTyped(p, question, 'pause', getLang() === 'es' ? 'pausar' : null, io))) {
    print(['', `  ${p.faint(t(human.ok ? 'Nothing changed.' : 'Nothing changed: this must be confirmed in an interactive terminal.'))}`, '']);

    return human.ok ? 0 : 1;
  }

  // The mark first: from here on every hook answers neutrally and anything that starts exits.
  deps.setPaused(by, targets.map((x) => x.id));
  const sweep = deps.stop();
  const watchers = sweep?.watchers?.remaining ?? deps.watchers();
  const windows = sweep?.windows?.remaining ?? deps.windows();
  const loginItem = deps.loginItem();
  const out = ['', `  ${pausedBadge(p)} ${p.bold(p.cream(t('blackbrake is paused')))}`];

  out.push(ok(p, t('Hooks: paused (still installed in: {list})', { list: targets.map((x) => x.name).join(', ') })));
  out.push(...(watchers.length ? bad(p, t('Watcher: still running (pid {pids})', { pids: pidsOf(watchers).join(', ') }), t('Close it by hand: {cmd}', { cmd: killHint(pidsOf(watchers)) })) : [ok(p, t('Watcher: stopped'))]));
  out.push(...(loginItem ? bad(p, t('Login item: still there'), t('Run "blackbrake pause" again, or "blackbrake background off".')) : [ok(p, t('Login item: removed (comes back when you resume)'))]));
  out.push(...(windows.length ? bad(p, t('Alerts window: still open (pid {pids})', { pids: pidsOf(windows).join(', ') }), t('Close it by hand: {cmd}', { cmd: killHint(pidsOf(windows)) })) : [ok(p, t('Alerts window: closed'))]));
  out.push('', `  ${p.amber(t('You are not protected until you run "blackbrake resume".'))}`, '');
  print(out);

  return watchers.length || windows.length || loginItem ? 1 : 0;
}

// ---------- resume ----------

export async function runResume(p, { deps = realDeps(), print = defaultPrint } = {}) {
  if (!deps.mark()) {
    print(['', `  ${p.faint(t('blackbrake is not paused.'))}`, '']);

    return 0;
  }

  const before = deps.agentsAtPause();
  deps.clearPaused();
  const targets = deps.targets();
  const now = targets.map((x) => x.id);
  const out = ['', `  ${p.bold(p.cream(t('blackbrake is running again')))}`];
  let problems = 0;

  if (targets.length) out.push(ok(p, `${t('Hooks: active in {n} harnesses', { n: targets.length })} · ${modeBadge(p, deps.mode())}`));
  else out.push(...bad(p, t('Hooks: not installed in any agent'), t('Run "blackbrake setup".')));

  // Hooks removed while it was paused: said, never put back without the user.
  const gone = before.filter((id) => !now.includes(id));

  if (gone.length) {
    problems++;
    out.push(...bad(p, t('Hooks removed during the pause: {list}', { list: gone.join(', ') }), t('Run "blackbrake setup" to put them back.')));
  }

  // Guard code that changed during the pause (the plugin's and the shared copy the other agents run).
  // Checked before anything is started again; the copy is never rebuilt here (that would hide it).
  const changed = [];

  if (now.includes('claude')) {
    const check = deps.integrity();

    if (check.checked) changed.push(...check.changed);
  }

  if (now.some((id) => id !== 'claude')) changed.push(...deps.agentsIntegrity());

  if (changed.length) {
    problems++;
    out.push(...bad(p, t('Guard code changed since it was installed: {list}', { list: changed.slice(0, 3).map((c) => clean(c, 120)).join(', ') }), t('Run "blackbrake setup" again; if you did not change it, check what did.')));
  }

  const wanted = deps.autostart();

  if (wanted && targets.length) {
    try { deps.start(); } catch (e) {
      problems++;
      out.push(...bad(p, t('Login item: could not be put back'), clean(e.message, 200)));
    }
  }

  if (!wanted) out.push(`  ${p.faint('·')} ${p.faint(t('Watcher: off (your choice; "blackbrake background on" turns it on)'))}`);
  else if (deps.watchers().length) out.push(ok(p, t('Watcher: running')));
  else out.push(...bad(p, t('Watcher: not running yet'), t('It starts at your next login, or now with "blackbrake background on".')));

  print([...out, '']);

  return problems ? 1 : 0;
}

// ---------- the main menu ----------

// Paused for more than a day: Brakey asks when the menu opens (the pause never expires on its own).
export const PAUSE_REMINDER_HOURS = 24;

export const remindToResume = () => pausedHours() > PAUSE_REMINDER_HOURS;

const isPausedState = (state) => Boolean(state?.paused);

export default {
  id: 'pause',
  commands: [
    { name: 'pause', usage: 'blackbrake pause', help: () => t('pause everything; nothing is uninstalled'), run: (ctx) => runPause(ctx.p, { by: 'cli', print: ctx.print }) },
    { name: 'resume', usage: 'blackbrake resume', help: () => t('resume after a pause'), run: (ctx) => runResume(ctx.p, { print: ctx.print }) },
  ],
  menu: [
    {
      slot: 'main',
      order: 35,
      value: 'pause',
      label: (state) => (isPausedState(state) ? t('Resume blackbrake') : t('Pause all of blackbrake')),
      hint: (state) => (isPausedState(state) ? t('nothing is protecting your agents right now') : t('stops watching and protecting until you resume; nothing is uninstalled')),
      tag: (state, p) => (isPausedState(state) ? pausedBadge(p) : ''),
      // Back to the main menu afterwards, which then shows the new state.
      run: async (ctx) => {
        if (isPausedState(ctx.state)) await runResume(ctx.p, { print: ctx.print });
        else await runPause(ctx.p, { by: 'menu', print: ctx.print });
      },
    },
  ],
};

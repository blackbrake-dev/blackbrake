// F6.3: uninstall from the menu and from `blackbrake uninstall`, with one shared flow (runUninstall
// in src/cli/features/uninstall-menu.mjs). Everything that would touch the real machine (agent
// configs, the login item, the process table) is injected; the terminal is a fake one.
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { afterEach, test } from 'node:test';
import uninstallMenu, { runMenu, runUninstall } from '../src/cli/features/uninstall-menu.mjs';
import { findMenuRow } from '../src/cli/registry.mjs';
import { ES } from '../src/i18n-es.mjs';
import { setLang, t } from '../src/i18n.mjs';
import { createPainter } from '../src/ui/term.mjs';

const p = createPainter(0);

afterEach(() => setLang('en'));

// A terminal that answers with what it is given. `typed` is what the person types at the prompt.
function terminal({ typed = '', tty = true, env = {} } = {}) {
  const input = new PassThrough();
  const output = new PassThrough();

  input.isTTY = tty;
  output.isTTY = tty;
  input.setRawMode = () => {};

  output.on('data', () => {});

  if (typed) input.write(`${typed}\n`);

  return { input, output, env };
}

// A fake machine: what is installed, what runs, and a log of every change asked of it.
function fakes({ installed = ['claude', 'codex'], watchers = [4001], windows = [4002], statusLine = false, stubborn = false, foreign = false, blockers = [], loginItem = true } = {}) {
  const calls = [];
  const names = { claude: 'Claude Code', codex: 'Codex', cursor: 'Cursor' };
  const state = { installed: [...installed], loginItem, watchers: [...watchers], windows: [...windows] };

  return {
    calls,
    state,
    deps: {
      targets: (agent) => (agent && agent !== 'all' ? agent.split(',').map((id) => ({ id, name: names[id] ?? id })) : state.installed.map((id) => ({ id, name: names[id] ?? id }))),
      installedIds: () => [...state.installed],
      foreignAgents: () => foreign,
      inspect: () => ({ home: '/h/.blackbrake', loginItem: { path: '/h/autostart/blackbrake-watch.desktop', present: state.loginItem }, app: { path: '/h/.blackbrake/app', present: true }, watchers: [...state.watchers], windows: [...state.windows], statusLine, blockers }),
      removeLoginItem: (o) => {
        calls.push(['loginItem', { sweep: o.sweep, windows: o.windows }]);
        state.loginItem = false;
        const w = stubborn ? { found: state.watchers, remaining: state.watchers } : { found: state.watchers, remaining: [] };

        if (!stubborn) state.watchers = [];
        const wi = { found: state.windows, remaining: [] };

        if (o.windows) state.windows = [];
        o.onSweep?.({ watchers: w, windows: o.windows ? wi : { found: [], remaining: [] }, launchd: 'skipped' });

        return true;
      },
      removeHooks: (ids) => { calls.push(['hooks', ids]); state.installed = state.installed.filter((id) => !ids.includes(id)); },
      removeClaude: (o) => { calls.push(['claude', { keepLog: o.keepLog }]); state.installed = state.installed.filter((id) => id !== 'claude'); },
    },
  };
}

const run = async (opts, machine, io, extra = {}) => {
  const out = [];
  const code = await runUninstall(opts, p, { io, deps: machine.deps, print: (lines) => out.push(...lines), ...extra });

  return { code, out: out.join('\n') };
};

test('without a terminal nothing changes, nothing is asked of the machine, and the exit code is 1', async () => {
  const m = fakes();
  const { code, out } = await run({}, m, terminal({ tty: false, typed: 'remove' }));

  assert.equal(code, 1);
  assert.match(out, /Nothing changed: removing guard must be confirmed in an interactive terminal\./);
  assert.deepEqual(m.calls, []);
});

test('inside an agent (marker in the environment) it refuses even at a terminal', async () => {
  const m = fakes();
  const io = terminal({ typed: 'remove', env: { CLAUDECODE: '1' } });
  const { code } = await run({}, m, io);

  assert.equal(code, 1);
  assert.deepEqual(m.calls, []);
});

test('a wrong word changes nothing and says so (exit 0 at a terminal)', async () => {
  const m = fakes();
  const { code, out } = await run({}, m, terminal({ typed: 'yes' }));

  assert.equal(code, 0);
  assert.match(out, /Nothing changed\./);
  assert.deepEqual(m.calls, []);
});

test('typing remove stops the watcher and the windows first, then removes hooks and the Claude plugin, and keeps the data', async () => {
  const m = fakes();
  const { code, out } = await run({}, m, terminal({ typed: 'remove' }));

  assert.equal(code, 0);
  assert.deepEqual(m.calls, [['loginItem', { sweep: true, windows: true }], ['hooks', ['codex']], ['claude', { keepLog: true }]]);
  assert.match(out, /blackbrake is uninstalled\. Nothing of mine is running\./);
  assert.match(out, /npm uninstall -g blackbrake/);
});

test('Spanish: quitar is the word, and the final screen is in Spanish', async () => {
  setLang('es');
  const m = fakes();
  const { code, out } = await run({}, m, terminal({ typed: 'quitar' }));

  assert.equal(code, 0);
  assert.deepEqual(m.calls.map((c) => c[0]), ['loginItem', 'hooks', 'claude']);
  assert.match(out, /blackbrake está desinstalado\. Nada mío está en marcha\./);
});

test('purge needs its own word: remove is not enough, purge deletes the data even when Claude Code is not installed', async () => {
  const none = fakes({ installed: ['codex'] });
  const wrong = await run({ purge: true }, none, terminal({ typed: 'remove' }));

  assert.equal(wrong.code, 0);
  assert.match(wrong.out, /Nothing changed\./);
  assert.deepEqual(none.calls, []);

  const m = fakes({ installed: ['codex'] });
  const { code } = await run({ purge: true }, m, terminal({ typed: 'purge' }));

  assert.equal(code, 0);
  assert.deepEqual(m.calls, [['loginItem', { sweep: true, windows: true }], ['hooks', ['codex']], ['claude', { keepLog: false }]]);
});

test('Spanish purge word is borrar, and the question says what is deleted', async () => {
  setLang('es');
  const m = fakes();
  const out = [];
  const io = terminal({ typed: 'borrar' });
  const written = [];

  io.output.on('data', (d) => written.push(String(d)));
  const code = await runUninstall({ purge: true }, p, { io, deps: m.deps, print: (l) => out.push(...l) });

  assert.equal(code, 0);
  assert.equal(m.calls.at(-1)[1].keepLog, false);
  assert.match(written.join(''), /borrar/);
  assert.match(out.join('\n'), /Esto borra también tu registro de alertas, tus ajustes, las copias privadas que hizo "fix" \(ya no podrás deshacer un arreglo\) y tus informes guardados\./);
});

test('purge is refused before anything is asked when other agents still use guard or the folder has foreign files', async () => {
  const other = fakes({ foreign: true });

  await assert.rejects(() => run({ purge: true }, other, terminal({ typed: 'purge' })), /Other agents still use guard; remove them too \(--agent all\) before --purge\./);
  assert.deepEqual(other.calls, []);

  const files = fakes({ blockers: ['notes.txt', 'keep.me'] });

  await assert.rejects(() => run({ purge: true }, files, terminal({ typed: 'purge' })), /Not deleting \/h\/\.blackbrake: it contains files blackbrake did not create \(notes\.txt, keep\.me\)\./);
  assert.deepEqual(files.calls, []);
});

test('--agent removes only that agent: no sweep, no login item, and no word for the watcher', async () => {
  const m = fakes();
  const { code, out } = await run({ agent: 'codex' }, m, terminal({ typed: 'remove' }));

  assert.equal(code, 0);
  assert.deepEqual(m.calls, [['hooks', ['codex']]]);
  assert.doesNotMatch(out, /Background watcher/);
});

test('the final screen is what the second sweep found: a watcher that would not stop is reported with how to stop it, exit 1', async () => {
  const m = fakes({ stubborn: true });
  const { code, out } = await run({}, m, terminal({ typed: 'remove' }));

  assert.equal(code, 1);
  assert.match(out, /Background watcher: still running \(pid 4001\): close it by hand/);
  assert.doesNotMatch(out, /Nothing of mine is running/);
  assert.match(out, /npm uninstall -g blackbrake/);
});

test('the screen before the word lists what goes, what stays and what is left to do by hand', async () => {
  const m = fakes({ statusLine: true });
  const { out } = await run({}, m, terminal({ typed: 'no' }));

  assert.match(out, /Claude Code, Codex/);
  assert.match(out, /\/h\/autostart\/blackbrake-watch\.desktop/);
  assert.match(out, /Background watcher: running/);
  assert.match(out, /Alerts windows open: 1/);
  assert.match(out, /Will keep/);
  assert.match(out, /npm uninstall -g blackbrake/);
  assert.match(out, /statusLine/);

  const quiet = fakes({ statusLine: false, watchers: [], windows: [], loginItem: false });
  const second = await run({}, quiet, terminal({ typed: 'no' }));

  assert.match(second.out, /Background watcher: not running/);
  assert.doesNotMatch(second.out, /statusLine/);
});

test('the menu asks Cancel / keep / delete first, then the word once, and ends the session after uninstalling', async () => {
  const picks = [];
  const out = [];
  const m = fakes();

  const ctx = { p, print: (lines) => out.push(...lines) };

  const choose = (answer) => async (_p, items) => { picks.push(items.map((i) => i.value));

 return answer; };

  const cancelled = await runMenu(ctx, { io: terminal({ typed: 'remove' }), deps: { ...m.deps, select: choose('cancel') } });

  assert.equal(cancelled?.exit, undefined);
  assert.deepEqual(m.calls, []);
  assert.deepEqual(picks[0], ['cancel', 'keep', 'purge'], 'Cancel comes first');

  const escaped = await runMenu(ctx, { io: terminal({ typed: 'remove' }), deps: { ...m.deps, select: choose(null) } });

  assert.equal(escaped?.exit, undefined);
  assert.deepEqual(m.calls, []);

  const kept = await runMenu(ctx, { io: terminal({ typed: 'remove' }), deps: { ...m.deps, select: choose('keep') } });

  assert.equal(kept.exit, true);
  assert.deepEqual(m.calls.map((c) => c[0]), ['loginItem', 'hooks', 'claude']);
  assert.equal(m.calls.at(-1)[1].keepLog, true);
});

test('menu: delete-everything asks for purge, and remove does not delete anything', async () => {
  const out = [];
  const ctx = { p, print: (lines) => out.push(...lines) };
  const select = async () => 'purge';

  const wrong = fakes();
  const r1 = await runMenu(ctx, { io: terminal({ typed: 'remove' }), deps: { ...wrong.deps, select } });

  assert.equal(r1?.exit, undefined);
  assert.deepEqual(wrong.calls, []);

  const right = fakes();
  const r2 = await runMenu(ctx, { io: terminal({ typed: 'purge' }), deps: { ...right.deps, select } });

  assert.equal(r2.exit, true);
  assert.equal(right.calls.at(-1)[1].keepLog, false);
});

test('menu: without a terminal or inside an agent it says nothing changed and does not even show the choice', async () => {
  const out = [];
  const ctx = { p, print: (lines) => out.push(...lines) };
  let asked = false;

  const select = async () => { asked = true;

 return 'keep'; };

  const m = fakes();

  assert.equal((await runMenu(ctx, { io: terminal({ tty: false }), deps: { ...m.deps, select } }))?.exit, undefined);
  assert.equal((await runMenu(ctx, { io: terminal({ env: { CLAUDECODE: '1' } }), deps: { ...m.deps, select } }))?.exit, undefined);
  assert.equal(asked, false);
  assert.deepEqual(m.calls, []);
  assert.match(out.join('\n'), /Nothing changed/);
});

test('the registered row keeps its place, text and Spanish', () => {
  const row = findMenuRow('uninstall');

  assert.equal(row.slot, 'main');
  assert.equal(row.label(), t('Uninstall blackbrake…'));
  assert.equal(uninstallMenu.commands.length, 0, 'uninstall stays a built-in command of bin/blackbrake.mjs');
  assert.equal(ES['Uninstall blackbrake…'], 'Desinstalar blackbrake…');
});

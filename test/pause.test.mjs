// F6.4 "Pause all of blackbrake" / "Resume blackbrake" (guard-design §6x.2): the mark and its
// tolerant reading, the pause and resume flows (machine injected, fake terminal), the commands that
// refuse while paused, the watcher and the window exiting, and what an agent cannot do about it.
// The hook's side (seven agents) is test/pause-hook.test.mjs.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import pauseFeature, { runPause, runResume } from '../src/cli/features/pause.mjs';
import { runUninstall } from '../src/cli/features/uninstall-menu.mjs';
import { runBackground } from '../src/guard/background.mjs';
import { clearPaused, isPaused, pausedHours, pausedMark, setPaused } from '../src/guard/pause.mjs';
import { decide } from '../src/guard/policy.mjs';
import { watch } from '../src/guard/watch.mjs';
import { setLang } from '../src/i18n.mjs';
import { loadRules } from '../src/secrets/engine.mjs';
import { createPainter, strip } from '../src/ui/term.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const BIN = path.join(ROOT, 'bin', 'blackbrake.mjs');

const p = createPainter(0);

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bb-pause-'));

afterEach(() => setLang('en'));

const writeState = (home, settings) => {
  fs.mkdirSync(home, { recursive: true });
  fs.writeFileSync(path.join(home, 'state.json'), JSON.stringify({ mode: 'observe', settings }));
};

// A terminal that answers with what it is given. `typed` is what the person types at the prompt.
function terminal({ typed = '', tty = true, env = {} } = {}) {
  const input = new PassThrough();
  const output = new PassThrough();

  input.isTTY = tty;
  output.isTTY = tty;
  output.on('data', () => {});

  if (typed) input.write(`${typed}\n`);

  return { input, output, env };
}

// A fake machine: what is installed and running, and every change asked of it.
function machine({ installed = ['claude', 'codex'], watchers = [4001], windows = [4002], stubborn = false, autostart = true, paused = null, atPause = [], changed = [], appChanged = [], startFails = false } = {}) {
  const calls = [];
  const names = { claude: 'Claude Code', codex: 'Codex', cursor: 'Cursor' };
  const state = { installed: [...installed], watchers: [...watchers], windows: [...windows], loginItem: true, mark: paused, agents: [...atPause] };

  return {
    calls,
    state,
    deps: {
      targets: () => state.installed.map((id) => ({ id, name: names[id] ?? id })),
      stop: () => {
        calls.push('stop');
        state.loginItem = false;
        const left = stubborn ? [...state.watchers] : [];
        const result = { watchers: { found: [...state.watchers], remaining: left }, windows: { found: [...state.windows], remaining: [] }, launchd: 'skipped' };
        state.watchers = left;
        state.windows = [];

        return result;
      },
      loginItem: () => state.loginItem,
      watchers: () => [...state.watchers],
      windows: () => [...state.windows],
      start: () => {
        calls.push('start');

        if (startFails) throw new Error('no node path');
        state.loginItem = true;
        state.watchers = [5001];
      },
      autostart: () => autostart,
      integrity: () => ({ checked: true, changed }),
      agentsIntegrity: () => appChanged,
      mode: () => 'observe',
      mark: () => state.mark,
      agentsAtPause: () => state.agents,
      setPaused: (by, agents) => { calls.push(['setPaused', by, agents]); state.mark = { at: new Date().toISOString(), by }; state.agents = agents; },
      clearPaused: () => { calls.push('clearPaused'); state.mark = null; },
    },
  };
}

const pause = async (m, io, by = 'cli') => {
  const out = [];
  const code = await runPause(p, { by, io, deps: m.deps, print: (lines) => out.push(...lines) });

  return { code, out: strip(out.join('\n')) };
};

const resume = async (m) => {
  const out = [];
  const code = await runResume(p, { deps: m.deps, print: (lines) => out.push(...lines) });

  return { code, out: strip(out.join('\n')) };
};

// ---------- the mark ----------

test('the mark: written and read back; anything malformed is "not paused" (fails towards protection)', () => {
  const home = tmp();
  assert.equal(isPaused(home), false, 'no state.json');
  setPaused('menu', home, new Date('2026-10-01T10:00:00Z'));
  assert.deepEqual(pausedMark(home), { at: '2026-10-01T10:00:00.000Z', by: 'menu' });
  assert.equal(pausedHours(home, Date.parse('2026-10-02T12:00:00Z')), 26);
  clearPaused(home);
  assert.equal(isPaused(home), false);
  assert.equal(pausedHours(home), 0);

  for (const paused of ['yes', true, 1, [], {}, { at: 'tomorrow' }, { at: 12 }, { by: 'cli' }, null]) {
    writeState(home, { paused });
    assert.equal(isPaused(home), false, JSON.stringify(paused));
  }

  fs.writeFileSync(path.join(home, 'state.json'), '{ not json');
  assert.equal(isPaused(home), false, 'invalid JSON');
  writeState(home, { paused: { at: '2026-10-01T10:00:00Z', by: 'someone' } });
  assert.equal(pausedMark(home).by, 'cli', 'an unknown "by" is not repeated back');
});

test('the mark keeps the rest of state.json (mode, other settings)', () => {
  const home = tmp();
  fs.writeFileSync(path.join(home, 'state.json'), JSON.stringify({ mode: 'protect', settings: { window: false, autostart: true } }));
  setPaused('cli', home);
  clearPaused(home);
  const state = JSON.parse(fs.readFileSync(path.join(home, 'state.json'), 'utf8'));
  assert.equal(state.mode, 'protect');
  assert.equal(state.settings.window, false);
  assert.equal(state.settings.autostart, true);
});

// ---------- pause ----------

test('pause without a terminal: nothing changes, nothing is stopped, exit code 1', async () => {
  const m = machine();
  const { code, out } = await pause(m, terminal({ tty: false, typed: 'pause' }));
  assert.equal(code, 1);
  assert.deepEqual(m.calls, []);
  assert.match(out, /Nothing changed/);
});

test('pause inside an AI agent (CLAUDECODE), even with a terminal: refused, exit code 1', async () => {
  const m = machine();
  const { code, out } = await pause(m, terminal({ typed: 'pause', env: { CLAUDECODE: '1' } }));
  assert.equal(code, 1);
  assert.deepEqual(m.calls, []);
  assert.match(out, /Nothing changed/);
});

test('pause: any other answer changes nothing (exit 0 at a terminal)', async () => {
  for (const typed of ['y', 'yes', 'remove', 'pausar', ' ']) {
    const m = machine();
    const { code } = await pause(m, terminal({ typed }));
    assert.equal(code, 0, typed);
    assert.deepEqual(m.calls, [], typed);
  }
});

test('pause: in Spanish "pausar" works as well as "pause"', async () => {
  setLang('es');

  for (const typed of ['pausar', 'PAUSE']) {
    const m = machine();
    const { code } = await pause(m, terminal({ typed }));
    assert.equal(code, 0, typed);
    assert.equal(m.calls[0][0], 'setPaused', typed);
  }
});

test('pause: the mark first, then everything stopped; the screen shows what a second look finds', async () => {
  const m = machine();
  const { code, out } = await pause(m, terminal({ typed: 'pause' }), 'menu');
  assert.equal(code, 0);
  assert.deepEqual(m.calls, [['setPaused', 'menu', ['claude', 'codex']], 'stop']);
  assert.match(out, /Hooks: paused \(still installed in: Claude Code, Codex\)/);
  assert.match(out, /✓ Watcher: stopped/);
  assert.match(out, /✓ Login item: removed \(comes back when you resume\)/);
  assert.match(out, /✓ Alerts window: closed/);
  assert.match(out, /You are not protected until you run "blackbrake resume"\./);
});

test('pause: a watcher that survives is reported with the command to close it, exit 1', async () => {
  const m = machine({ stubborn: true });
  const { code, out } = await pause(m, terminal({ typed: 'pause' }));
  assert.equal(code, 1);
  assert.match(out, /✗ Watcher: still running \(pid 4001\)/);
  assert.match(out, /(taskkill \/PID 4001 \/F|kill 4001)/);
});

test('pause with nothing installed says so and asks nothing', async () => {
  const m = machine({ installed: [] });
  const { code, out } = await pause(m, terminal({ typed: 'pause' }));
  assert.equal(code, 0);
  assert.deepEqual(m.calls, []);
  assert.match(out, /Nothing to pause: blackbrake is not installed anywhere\./);
});

test('pause when already paused: says so, changes nothing', async () => {
  const m = machine({ paused: { at: '2026-10-01T10:00:00.000Z', by: 'cli' } });
  const { code, out } = await pause(m, terminal({ typed: 'pause' }));
  assert.equal(code, 0);
  assert.deepEqual(m.calls, []);
  assert.match(out, /already paused/);
});

// ---------- resume ----------

test('resume: the mark goes, the watcher comes back (autostart on), the result is checked', async () => {
  const m = machine({ paused: { at: '2026-10-01T10:00:00.000Z', by: 'cli' }, atPause: ['claude', 'codex'], watchers: [] });
  const { code, out } = await resume(m);
  assert.equal(code, 0);
  assert.deepEqual(m.calls, ['clearPaused', 'start']);
  assert.match(out, /✓ Hooks: active in 2 harnesses · +OBSERVE/);
  assert.match(out, /✓ Watcher: running/);
});

test('resume with the watcher switched off by the user: it stays off', async () => {
  const m = machine({ paused: { at: '2026-10-01T10:00:00.000Z', by: 'cli' }, atPause: ['claude', 'codex'], watchers: [], autostart: false });
  const { code, out } = await resume(m);
  assert.equal(code, 0);
  assert.deepEqual(m.calls, ['clearPaused']);
  assert.match(out, /Watcher: off \(your choice/);
});

test('resume says which hooks went missing and which guard code changed during the pause (exit 1)', async () => {
  const m = machine({ paused: { at: '2026-10-01T10:00:00.000Z', by: 'cli' }, atPause: ['claude', 'codex', 'cursor'], changed: ['src/guard/policy.mjs'], appChanged: ['src/guard/hook.mjs'] });
  const { code, out } = await resume(m);
  assert.equal(code, 1);
  assert.match(out, /✗ Hooks removed during the pause: cursor/);
  assert.match(out, /✗ Guard code changed since it was installed: src\/guard\/policy\.mjs, src\/guard\/hook\.mjs/);
  assert.equal(m.state.mark, null, 'the pause is lifted anyway: resuming raises protection');
});

test('resume: a login item that cannot be put back is said, exit 1', async () => {
  const m = machine({ paused: { at: '2026-10-01T10:00:00.000Z', by: 'cli' }, atPause: ['codex'], installed: ['codex'], watchers: [], startFails: true });
  const { code, out } = await resume(m);
  assert.equal(code, 1);
  assert.match(out, /✗ Login item: could not be put back/);
  assert.match(out, /✗ Watcher: not running yet/);
});

test('resume when not paused: says so, changes nothing', async () => {
  const m = machine();
  const { code, out } = await resume(m);
  assert.equal(code, 0);
  assert.deepEqual(m.calls, []);
  assert.match(out, /not paused/);
});

test('the main-menu row turns into "Resume blackbrake" with a PAUSED tag', () => {
  const row = pauseFeature.menu[0];
  assert.equal(row.label({}), 'Pause all of blackbrake');
  assert.equal(row.label({ paused: true }), 'Resume blackbrake');
  assert.match(strip(row.tag({ paused: true }, p)), /PAUSED/);
  setLang('es');
  assert.equal(row.label({ paused: true }), 'Reanudar blackbrake');
  assert.match(strip(row.tag({ paused: true }, p)), /PAUSADO/);
});

// ---------- uninstall lifts the pause (W2-7) ----------

test('uninstalling everything lifts the pause, so a later setup is not blocked', async () => {
  const calls = [];

  const deps = {
    targets: () => [{ id: 'codex', name: 'Codex' }],
    installedIds: () => [],
    foreignAgents: () => false,
    inspect: () => ({ home: '/h', loginItem: { path: '/h/x', present: false }, app: { path: '/h/app', present: false }, watchers: [], windows: [], statusLine: false, blockers: [] }),
    removeLoginItem: () => false,
    removeHooks: () => calls.push('hooks'),
    removeClaude: () => calls.push('claude'),
    clearPause: () => calls.push('clearPause'),
  };

  await runUninstall({}, p, { confirmed: true, deps, print: () => {} });
  assert.ok(calls.includes('clearPause'));
  calls.length = 0;
  await runUninstall({ agent: 'codex' }, p, { confirmed: true, deps, print: () => {} });
  assert.ok(!calls.includes('clearPause'), 'removing one agent keeps the pause');
});

// ---------- the watcher and the alerts window ----------

test('paused, the background watcher does not start and leaves no pid file', async () => {
  const home = tmp();
  writeState(home, { paused: { at: '2026-10-01T10:00:00Z', by: 'cli' } });
  assert.equal(await runBackground({ home, once: true, notifier: () => {} }), 'paused');
  assert.equal(fs.existsSync(path.join(home, 'watch-bg.pid')), false);
});

test('paused while open, the alerts window says why and closes itself', async () => {
  const home = tmp();
  writeState(home, {});
  const chunks = [];

  const out = { isTTY: false, columns: 100, write: (s) => chunks.push(s) > 0 };

  const running = watch(p, { home, out, intervalMs: 20, notifier: () => {} });
  setPaused('cli', home);
  await Promise.race([running, new Promise((_, reject) => setTimeout(() => reject(new Error('the window did not close')), 5000))]);
  assert.match(strip(chunks.join('')), /blackbrake is paused: nothing is being watched/);
  assert.equal(fs.existsSync(path.join(home, 'watch.pid')), false, 'its pid file is gone');
});

// ---------- commands that refuse while paused, and what shows the pause ----------

const cli = (args, home) => {
  const env = { ...process.env, HOME: home, USERPROFILE: home, BLACKBRAKE_HOME: path.join(home, '.blackbrake'), CLAUDE_CONFIG_DIR: path.join(home, '.claude'), NO_COLOR: '1', BLACKBRAKE_LANG: 'en', BLACKBRAKE_NO_WINDOW: '1' };
  delete env.CLAUDECODE;

  return spawnSync(process.execPath, [BIN, ...args], { env, encoding: 'utf8', input: '', timeout: 30000 });
};

test('paused: setup, mode, window on, background on and permissions refuse; nothing else changes', () => {
  const home = tmp();
  const bb = path.join(home, '.blackbrake');
  writeState(bb, { paused: { at: '2026-10-01T10:00:00Z', by: 'cli' } });
  const before = fs.readFileSync(path.join(bb, 'state.json'), 'utf8');

  for (const args of [['setup', '--yes'], ['setup', '--agent', 'codex', '--yes'], ['mode', 'protect'], ['window', 'on'], ['background', 'on'], ['permissions']]) {
    const r = cli(args, home);
    assert.equal(r.status, 1, args.join(' '));
    assert.match(r.stdout, /blackbrake is paused; run "blackbrake resume" first\./, args.join(' '));
  }

  assert.equal(fs.readFileSync(path.join(bb, 'state.json'), 'utf8'), before, 'state.json untouched');
  assert.deepEqual(fs.readdirSync(bb), ['state.json'], 'nothing installed');
  assert.equal(fs.existsSync(path.join(home, '.claude')), false);
});

test('paused: status, agents and the status line say PAUSED; resume needs no terminal', () => {
  const home = tmp();
  writeState(path.join(home, '.blackbrake'), { paused: { at: '2026-10-01T10:00:00Z', by: 'cli' } });

  for (const args of [['status'], ['agents'], ['statusline']]) {
    const r = cli(args, home);
    assert.equal(r.status, 0, args.join(' '));
    assert.match(r.stdout, /PAUSED/, args.join(' '));
  }

  cli(['resume'], home);
  assert.equal(isPaused(path.join(home, '.blackbrake')), false);
  assert.doesNotMatch(cli(['statusline'], home).stdout, /PAUSED/);
});

test('pause from a script (no terminal) changes nothing and exits 1', () => {
  const home = tmp();
  writeState(path.join(home, '.blackbrake'), {});
  const r = cli(['pause'], home);
  assert.equal(r.status, 1);
  assert.equal(isPaused(path.join(home, '.blackbrake')), false);
});

// ---------- what an agent cannot do (policy) ----------

test('an agent can neither run pause nor write the mark (W2-3)', () => {
  const home = tmp();
  const ctx = { mode: 'observe', rules: loadRules(), home, guardDir: path.join(home, '.blackbrake'), platform: process.platform };
  const deny = (tool_name, tool_input) => decide('PreToolUse', { tool_name, tool_input }, ctx).output?.hookSpecificOutput?.permissionDecision === 'deny';

  for (const command of ['blackbrake pause', 'npx blackbrake pause', 'blackbrake --lang es pause', 'B=blackbrake; $B pause', 'script -qc "blackbrake pause" /dev/null', 'blackbrake $(echo pau)se', 'echo pausar | blackbrake pause']) {
    assert.equal(deny('Bash', { command }), true, command);
  }

  const state = path.join(home, '.blackbrake', 'state.json');
  assert.equal(deny('Write', { file_path: state, content: JSON.stringify({ settings: { paused: { at: '2026-10-01T10:00:00Z' } } }) }), true, 'Write state.json');
  assert.equal(deny('Bash', { command: `echo {} > ${state}` }), true, 'shell write to state.json');

  // The accepted false positive (W2-3): cmd's pause next to a variable.
  assert.equal(deny('Bash', { command: 'cmd /c "echo %X% & pause"' }), true, 'known false positive');
  // Plain words stay allowed.
  assert.equal(deny('Bash', { command: 'echo pause' }), false);
  assert.equal(deny('Bash', { command: 'docker pause web' }), false);
});

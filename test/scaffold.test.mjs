// The 0.3.x scaffold: one registry where each feature module declares its menu rows, commands,
// help lines and Spanish text; the home screen, the dispatcher and the help read from it.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { commandArgs, commandFor, FEATURES, findMenuRow, helpRows, menuRows } from '../src/cli/registry.mjs';
import { GUARD_ENTRIES } from '../src/guard/install.mjs';
import { decide } from '../src/guard/policy.mjs';
import { ES, FEATURE_TEXTS, mergeFeatureTranslations } from '../src/i18n-es.mjs';
import { setLang, t } from '../src/i18n.mjs';
import { loadRules } from '../src/secrets/engine.mjs';
import { categoryItems, HOME_ITEMS, homeItems } from '../src/ui/home.mjs';
import { createPainter, strip } from '../src/ui/term.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const BIN = path.join(ROOT, 'bin', 'blackbrake.mjs');

const p = createPainter(0);

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bb-scaffold-'));

// Every file under a folder, relative and sorted: the "state" a command could have changed.
const tree = (dir) => fs.readdirSync(dir, { recursive: true }).map(String).sort();

const run = (args, { lang = 'en', home = tmp(), input = '' } = {}) => {
  const env = { ...process.env, HOME: home, USERPROFILE: home, BLACKBRAKE_HOME: path.join(home, '.blackbrake'), CLAUDE_CONFIG_DIR: path.join(home, '.claude'), NO_COLOR: '1', BLACKBRAKE_LANG: lang, BLACKBRAKE_NO_WINDOW: '1' };
  delete env.CLAUDECODE;

  return { home, ...spawnSync(process.execPath, [BIN, ...args], { env, encoding: 'utf8', input, timeout: 30000 }) };
};

test('the registry lists the features with their commands and rows', () => {
  assert.deepEqual(FEATURES.map((f) => f.id), ['pause', 'brakes', 'uninstall-menu', 'report']);
  assert.equal(commandArgs('brakes'), 2, 'brakes takes a brake and a value');
  assert.equal(findMenuRow('brakes').slot, 'protect');
  assert.ok(commandFor('pause') && commandFor('resume') && commandFor('report'));
  assert.equal(commandFor('uninstall'), undefined, 'uninstall stays a built-in command');
  assert.equal(commandFor('nope'), undefined);
  assert.equal(commandArgs('report') >= 2, true, 'report takes a subcommand and a name');
  assert.equal(commandArgs('pause'), 0);
  assert.equal(commandArgs('nope'), 0);
  assert.deepEqual(menuRows('main').map((r) => r.value), ['pause', 'uninstall']);
  assert.ok(menuRows('more').some((r) => r.value === 'report-product') && menuRows('more').some((r) => r.value === 'report-security'));
  assert.equal(findMenuRow('uninstall').slot, 'main');
  assert.equal(findMenuRow('nope'), undefined);
});

test('every command, row and help line has what the dispatcher needs', () => {
  const values = new Set();
  const names = new Set();

  for (const f of FEATURES) {
    for (const c of f.commands ?? []) {
      assert.match(c.name, /^[a-z][a-z-]*$/);
      assert.ok(!names.has(c.name), `duplicate command ${c.name}`);
      names.add(c.name);
      assert.ok(c.run instanceof Function);
      assert.ok(c.help instanceof Function);
      assert.match(c.usage, new RegExp(`^blackbrake ${c.name}`));
    }

    for (const r of f.menu ?? []) {
      assert.ok(!values.has(r.value), `duplicate row ${r.value}`);
      values.add(r.value);
      assert.ok(r.run instanceof Function);
      assert.ok(r.label instanceof Function);
      assert.ok(Number.isInteger(r.order));
    }
  }

  // No row may shadow an action of the built-in menus.
  const builtIn = new Set([...homeItems({}, null, { features: false }).map((i) => i.value), ...['live', 'audit', 'protect', 'more'].flatMap((c) => categoryItems(c, {}, null, { features: false }).map((i) => i.value))]);

  for (const v of values) assert.ok(!builtIn.has(v), `${v} collides with a built-in action`);
});

test('the main menu lists the registered rows, in English and Spanish, and closing is not quitting', () => {
  const state = { installed: true, mode: 'observe', protectedCount: 1, detectedCount: 2 };
  const en = homeItems(state, p);
  assert.deepEqual(en.map((i) => i.value), ['live', 'audit', 'protect', 'pause', 'more', 'uninstall', 'quit']);
  assert.equal(en.find((i) => i.value === 'pause').label, 'Pause all of blackbrake');
  assert.equal(en.find((i) => i.value === 'uninstall').label, 'Uninstall blackbrake…');
  assert.equal(en.at(-1).label, 'Close this menu');
  assert.equal(en.at(-1).hint, 'protection keeps running');

  setLang('es');
  const es = homeItems(state, p);
  setLang('en');
  assert.equal(es.find((i) => i.value === 'pause').label, 'Pausar todo blackbrake');
  assert.equal(es.find((i) => i.value === 'uninstall').label, 'Desinstalar blackbrake…');
  assert.equal(es.at(-1).label, 'Cerrar este menú');
  assert.equal(es.at(-1).hint, 'la protección sigue activa');
});

test('the fixed home rows stay five; the report rows sit in Help and settings, before Back', () => {
  assert.deepEqual(HOME_ITEMS.map((i) => i.value), ['live', 'audit', 'protect', 'more', 'quit']);
  const more = categoryItems('more', {}, null);
  assert.equal(more.at(-1).value, 'back');
  assert.match(more.find((i) => i.value === 'report-product').label, /^Send feedback or report a problem…$/);
  assert.match(more.find((i) => i.value === 'report-security').label, /^Report a security issue…$/);
  assert.ok(more.findIndex((i) => i.value === 'report-product') < more.length - 1);
});

test('help lines come from the registry: usage and text for each command', () => {
  const rows = helpRows();
  assert.deepEqual(rows.map((r) => r.usage), ['blackbrake pause', 'blackbrake resume', 'blackbrake brakes [<brake> <value> | reset]', 'blackbrake report [product|security]']);
  assert.ok(rows.every((r) => r.text.length > 10));

  const en = run(['--help']);
  assert.equal(en.status, 0);
  assert.match(en.stdout, /blackbrake pause\s+\S/);
  assert.match(en.stdout, /blackbrake report \[product\|security\]\s+\S/);
  assert.match(run(['--help'], { lang: 'es' }).stdout, /blackbrake resume\s+\S/);
  assert.match(run(['help']).stdout, /blackbrake pause/, 'the in-menu help screen reads the registry too');
});

test('without a terminal, the feature commands that write say so in English and Spanish and change no state', () => {
  const home = tmp();
  run(['--version'], { home });
  const baseline = tree(home);

  for (const [args, en, es] of [
    [['report'], /Reports are prepared in an interactive terminal/, /Los informes se preparan en un terminal interactivo/],
    [['report', 'send', 'product-20261001T100000Z-0123abcd.md'], /Reports are prepared in an interactive terminal/, /Los informes se preparan en un terminal interactivo/],
    [['report', 'security'], /Reports are prepared in an interactive terminal/, /Los informes se preparan en un terminal interactivo/],
    [['pause'], /Nothing changed: this must be confirmed in an interactive terminal/, /No se ha cambiado nada: hay que confirmarlo en una terminal interactiva/],
  ]) {
    const a = run(args, { home });
    assert.equal(a.status, 1, args.join(' '));
    assert.match(a.stdout + a.stderr, en);
    assert.match(run(args, { home, lang: 'es' }).stdout, es);
  }

  assert.deepEqual(tree(home), baseline, 'no file was created or removed');
});

test('an unknown command is still refused, and built-ins still win over the registry', () => {
  const r = run(['nonsense']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /Unknown command/);
  assert.equal(run(['uninstall'], { input: 'y\n' }).status, 1, 'uninstall is still the built-in command: without a terminal it changes nothing');
});

test('menu rows, run without a terminal, say so and touch no state', async () => {
  const lines = [];
  const ctx = { p, opts: {}, print: (l) => lines.push(...l), state: {} };

  for (const r of FEATURES.flatMap((f) => f.menu ?? [])) {
    const before = lines.length;
    const out = await r.run(ctx);
    assert.ok(lines.length > before, `${r.value} says something`);
    assert.ok(!out?.exit, `${r.value} does not end the menu`);
  }

  assert.ok(lines.every((l) => l === `${l}`));
  assert.match(strip(lines.join('\n')), /Reports are prepared in an interactive terminal/);
});

test('SHELL_TAMPER: the agent cannot run pause, resume or report; GUARD_ENTRIES knows the new files', () => {
  const ctx = { mode: 'protect', rules: loadRules(), home: tmp() };

  for (const command of ['blackbrake pause', 'blackbrake resume', 'blackbrake report send x.md']) {
    const r = decide('PreToolUse', { tool_name: 'Bash', tool_input: { command } }, ctx);
    assert.equal(r.output.hookSpecificOutput.permissionDecision, 'deny', command);
  }

  // Words that only look similar stay allowed.
  const ok = decide('PreToolUse', { tool_name: 'Bash', tool_input: { command: 'echo reports and pauses' } }, ctx);
  assert.notEqual(ok.output?.hookSpecificOutput?.permissionDecision, 'deny');
  assert.ok(GUARD_ENTRIES.has('reports') && GUARD_ENTRIES.has('window.last'));
  assert.ok(GUARD_ENTRIES.has('state.json') && GUARD_ENTRIES.has('fixes'));
});

test('feature translations are merged from the es-*.mjs files', () => {
  assert.equal(ES['Close this menu'], 'Cerrar este menú');
  setLang('es');
  assert.equal(t('protection keeps running'), 'la protección sigue activa');
  setLang('en');

  const demo = { ES: { 'Demo text': 'Texto de demostración', ['__proto__']: 'x', 'Not text': 5 }, ES_PATTERNS: [[/^demo (\d+)$/, 'demostración $1'], ['nope', 'x']] };
  const target = { Existing: 'Existente' };
  const patterns = [];
  mergeFeatureTranslations([demo, {}, { ES: { Existing: 'Otro' } }], target, patterns);
  assert.equal(target['Demo text'], 'Texto de demostración');
  assert.equal(target.Existing, 'Existente', 'an existing key is never overridden');
  assert.ok(!('Not text' in target));
  assert.equal(Object.getPrototypeOf(target), Object.prototype, 'no prototype pollution');
  assert.equal(patterns.length, 1, 'only RegExp patterns are accepted');
});

test('every src/i18n/es-*.mjs file is listed in FEATURE_TEXTS (add the import in src/i18n-es.mjs)', async () => {
  const dir = path.join(ROOT, 'src', 'i18n');
  const files = fs.readdirSync(dir).filter((n) => /^es-[\w-]+\.mjs$/.test(n));
  const source = fs.readFileSync(path.join(ROOT, 'src', 'i18n-es.mjs'), 'utf8');

  assert.ok(files.length >= 4);

  for (const name of files) {
    assert.ok(source.includes(`'./i18n/${name}'`), `${name} is not imported by src/i18n-es.mjs`);
    const mod = await import(pathToFileURL(path.join(dir, name)).href);
    assert.ok(FEATURE_TEXTS.includes(mod), `${name} is not in FEATURE_TEXTS`);

    for (const [en, es] of Object.entries(mod.ES)) assert.equal(ES[en], es, `${name}: "${en}" is not in the Spanish table`);
  }
});

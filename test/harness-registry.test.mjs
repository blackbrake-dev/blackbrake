// Every local AI harness: detection, scanning its files, following its history, noticing its
// processes, the login item for the background watcher, Devin CLI's hooks, the menu.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { autostartContent } from '../src/guard/autostart.mjs';
import { createFollower, processNames, runningHarnesses } from '../src/guard/background.mjs';
import { HARNESSES } from '../src/guard/registry.mjs';
import { scanHarness, skippedAsOwnCredential } from '../src/guard/scan.mjs';
import { loadRules } from '../src/secrets/engine.mjs';
import { categoryItems, homeItems, liveBadge } from '../src/ui/home.mjs';
import { createPainter, strip } from '../src/ui/term.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const HOOK = path.join(ROOT, 'src', 'guard', 'hook.mjs');

const rules = loadRules();

const token = (seed, n) => {
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let x = seed;
  let s = '';

  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) % 2147483648;
    s += a[x % 62];
  }

  return s;
};

const GITHUB = `ghp_${token(11, 36)}`;

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bb-reg-'));

const fake = (dir, extra = {}) => ({ id: 'fake', name: 'Fake Agent', kind: 'watch', dirs: () => [dir], procs: [], ...extra });

test('the registry knows the harnesses the user named, with hooks where they exist', () => {
  const ids = HARNESSES.map((h) => h.id);

  for (const id of ['claude', 'codex', 'devin', 'ollama', 'hermes', 'gemini', 'cursor', 'copilot', 'windsurf']) assert.ok(ids.includes(id), id);
  assert.equal(HARNESSES.find((h) => h.id === 'devin').kind, 'hooks');
  assert.equal(HARNESSES.find((h) => h.id === 'ollama').kind, 'watch');
});

test('scan finds secrets in a harness\'s files, skips its own credential store, never returns values', () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'history'), `>>> deploy with ${GITHUB}\n`);
  fs.writeFileSync(path.join(dir, 'id_ed25519'), `-----BEGIN OPENSSH PRIVATE KEY-----\n${token(3, 200)}\n-----END OPENSSH PRIVATE KEY-----\n`);
  fs.writeFileSync(path.join(dir, 'credentials.toml'), `token = "${`ghp_${token(5, 36)}`}"\n`);
  fs.mkdirSync(path.join(dir, 'models'));
  fs.writeFileSync(path.join(dir, 'models', 'big.txt'), GITHUB);
  const r = scanHarness(fake(dir), rules);
  assert.equal(r.findings.length, 1, 'only the history; not the key, the credential store or models');
  assert.equal(r.findings[0].classification, 'likely-real');
  assert.equal(r.skipped, 2);
  assert.ok(!JSON.stringify(r).includes(GITHUB.slice(4)), 'no value anywhere');
  assert.ok(skippedAsOwnCredential('/h/.devin/credentials.toml'));
  assert.ok(!skippedAsOwnCredential('/h/.ollama/history'));
});

test('the follower reads only what a history file gains after it starts', () => {
  const dir = tmp();
  const file = path.join(dir, 'history');
  fs.writeFileSync(file, `old ${GITHUB}\n`);
  const f = createFollower([fake(dir)]);
  assert.equal(f.read().length, 0, 'what was there before is not new');
  fs.appendFileSync(file, 'new line\n');
  const fresh = f.read();
  assert.equal(fresh.length, 1);
  assert.match(fresh[0].text, /new line\n$/, 'the new text, with a little of what came before (a secret split across writes is seen whole)');
  assert.equal(f.read().length, 0);
});

test('running harnesses come from the process list (fixed system program, parsed safely)', () => {
  const win = processNames({ platform: 'win32', find: () => 'C:\\Windows\\System32\\tasklist.exe', run: () => ({ status: 0, stdout: '"ollama.exe","12","Console","1","10 K"\r\n"claude.exe","13","Console","1","9 K"\r\n"notepad.exe","14","Console","1","1 K"\r\n' }) });
  assert.deepEqual(runningHarnesses(win).sort(), ['claude', 'ollama']);
  const nix = processNames({ platform: 'linux', find: () => '/bin/ps', run: () => ({ status: 0, stdout: '/usr/local/bin/codex\nbash\nhermes\n' }) });
  assert.deepEqual(runningHarnesses(nix).sort(), ['codex', 'hermes']);
  assert.deepEqual(processNames({ platform: 'win32', find: () => null }), [], 'no system program, no guess');
});

test('the login item holds only safe paths, and runs node without a shell', () => {
  const vbs = autostartContent('C:\\Program Files\\nodejs\\node.exe', 'C:\\Users\\me\\.blackbrake\\app\\src\\guard\\watch-main.mjs', 'win32');
  assert.match(vbs, /Run """C:\\Program Files\\nodejs\\node\.exe"" ""C:\\Users\\me.+watch-main\.mjs"" --background", 0, False/);
  assert.equal(autostartContent('C:\\a"b\\node.exe', 'x', 'win32'), null, 'a quote would break out of VBScript');
  assert.match(autostartContent('/usr/bin/node', '/h/w.mjs', 'darwin'), /<string>\/usr\/bin\/node<\/string><string>\/h\/w\.mjs<\/string><string>--background<\/string>/);
  assert.equal(autostartContent('/usr/bin/node', '/h/$(x).mjs', 'linux'), null);
});

test('review: links inside a harness folder are not followed; accents in paths survive the login item', () => {
  const dir = tmp();
  const outside = tmp();
  fs.writeFileSync(path.join(outside, 'history'), `x ${GITHUB}\n`);

  try {
    fs.symlinkSync(outside, path.join(dir, 'linked'), 'junction');
  } catch { return; /* no link rights here */ }

  assert.equal(scanHarness(fake(dir), rules).findings.length, 0, 'the linked folder is outside the harness');
  const vbs = autostartContent('C:\\Program Files\\nodejs\\node.exe', 'C:\\Users\\José\\.blackbrake\\app\\src\\guard\\watch-main.mjs', 'win32');
  assert.match(vbs, /José/);
});

test('review: the background watcher refuses to run when its installed copy was changed', async () => {
  const { appManifest } = await import('../src/guard/agents.mjs');
  const home = tmp();
  const app = path.join(home, 'app');
  fs.cpSync(path.join(ROOT, 'src'), path.join(app, 'src'), { recursive: true });
  fs.mkdirSync(path.join(app, 'vendor'));
  fs.copyFileSync(path.join(ROOT, 'vendor', 'gitleaks.rules.json'), path.join(app, 'vendor', 'gitleaks.rules.json'));
  fs.writeFileSync(path.join(app, 'package.json'), '{"type":"module"}');
  fs.writeFileSync(path.join(app, 'manifest.json'), JSON.stringify(appManifest(app)));
  fs.appendFileSync(path.join(app, 'src', 'guard', 'background.mjs'), '\n// changed\n');
  const r = spawnSync(process.execPath, [path.join(app, 'src', 'guard', 'watch-main.mjs'), '--background'], { encoding: 'utf8', timeout: 20000, env: { ...process.env, BLACKBRAKE_HOME: home, BLACKBRAKE_NO_WINDOW: '1' } });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /background\.mjs/);
  const log = fs.readFileSync(path.join(home, 'log', `${new Date().toISOString().slice(0, 7)}.jsonl`), 'utf8');
  assert.match(log, /"kind":"tamper"/);
});

test('Devin CLI: prompts and tools are checked in its own format', () => {
  const home = tmp();
  fs.writeFileSync(path.join(home, 'state.json'), JSON.stringify({ mode: 'protect' }));

  const run = (event, input) => {
    const r = spawnSync(process.execPath, [HOOK, event, '--harness', 'devin'], { input: JSON.stringify(input), encoding: 'utf8', env: { ...process.env, BLACKBRAKE_HOME: home, BLACKBRAKE_LANG: 'en', BLACKBRAKE_NO_WINDOW: '1' } });

    return r.stdout ? JSON.parse(r.stdout) : null;
  };

  assert.equal(run('UserPromptSubmit', { session_id: 's', prompt: `use ${GITHUB}` }).decision, 'block');
  assert.equal(run('PreToolUse', { session_id: 's', tool_name: 'read', tool_input: { file_path: '/p/.env' } }).decision, 'block');
  assert.equal(run('PreToolUse', { session_id: 's', tool_name: 'exec', tool_input: { command: 'rm -rf ~/.blackbrake' } }).decision, 'block');
  assert.equal(run('PreToolUse', { session_id: 's', tool_name: 'exec', tool_input: { command: 'npm test' } }), null, 'ordinary work passes');
  const out = run('PostToolUse', { session_id: 's', tool_name: 'exec', tool_input: { command: 'env' }, tool_response: { success: true, output: `T=${GITHUB}` } });
  assert.match(out.hookSpecificOutput.additionalContext, /ghp_••••/);
  assert.ok(!JSON.stringify(out).includes(GITHUB));
});

test('permissions checklist: boxes, headings, keys (space, a, enter, q) and no terminal = no change', async () => {
  const { checklist, renderChecklist } = await import('../src/ui/menu.mjs');
  const p = createPainter(0);
  const items = [{ heading: true, label: 'Harnesses' }, { value: 'h:codex', label: 'Codex', on: true, hint: 'writes hooks.json' }, { value: 'observe', label: 'Observe mode', on: true }];
  const lines = renderChecklist(p, items, 1).join('\n');
  assert.match(lines, /❯ ■ Codex +writes hooks\.json/);
  assert.match(lines, /Harnesses/);
  assert.equal(await checklist(p, items, { input: { isTTY: false }, output: { isTTY: false } }), null);

  // A fake terminal: move down, switch observe off, save.
  const { EventEmitter } = await import('node:events');
  const input = Object.assign(new EventEmitter(), { isTTY: true, setRawMode() {}, resume() {}, pause() {} });
  const output = { isTTY: true, write() {} };
  const done = checklist(p, items, { input, output });
  input.emit('keypress', '', { name: 'down' });
  input.emit('keypress', ' ', { name: 'space' });
  input.emit('keypress', '', { name: 'return' });
  assert.deepEqual(await done, { 'h:codex': true, observe: false });
});

test('screens share the brand header; the alerts window opens in blackbrake orange', async () => {
  const { screen } = await import('../src/ui/term.mjs');
  const { windowCommand } = await import('../src/guard/window.mjs');
  const lines = screen(createPainter(0), 'HELP', 'main commands', 80, { pose: 'wink', line: 'hello' });
  assert.match(lines[1], /blackbrake {2} HELP  main commands/, 'Brakey beside the name and the label');
  assert.match(lines[2], /Brakey: hello/, 'and its line about the screen');
  assert.match(lines[4], /━{20,}/);
  const lit = screen(createPainter(3), 'HELP', 'main commands', 80);
  assert.match(lit.join('\n'), /\x1b\[38;2;255;90;31m━/, 'the rule starts in brand orange (then fades)');
  assert.ok(windowCommand('C:\\n\\node.exe', 'C:\\w.mjs', { platform: 'win32', find: (n) => `/sys/${n}` }).args.includes('#FF5A1F'));
});

test('mascot: the logo with eyes; every pose differs; plain fallback; motion only where it helps', async () => {
  const { mascot, mini, motionAllowed, play, POSES, HELLO } = await import('../src/ui/term.mjs');
  const lit = createPainter(3);
  const drawn = POSES.map((pose) => mascot(lit, pose).join('\n'));
  assert.equal(new Set(drawn).size, POSES.length, 'each pose looks different');
  assert.equal(mascot(lit, 'idle').length, 5, 'same footprint as the logo');
  assert.match(mascot(createPainter(0), 'idle')[3], /●.*●/, 'eyes on the band without colour');
  assert.match(strip(mini(lit, 'idle')), /^••$/);
  assert.equal(mini(createPainter(0)), '❯', 'plain terminals keep the arrow');
  assert.equal(motionAllowed({ isTTY: true }, { CI: '1' }), false);
  assert.equal(motionAllowed({ isTTY: true }, { ACCESSIBLE: '1' }), false);
  assert.equal(motionAllowed({ isTTY: false }, {}), false);
  assert.equal(motionAllowed({ isTTY: true }, {}), true);
  const out = { text: '', write(s) { this.text += s; } };
  await play((pose) => [pose], HELLO, { out, motion: false });
  assert.equal(out.text, 'idle\n', 'without motion: one frame, the final pose, no cursor moves');
});

test('Brakey: speaks with its name, reacts to alert levels, reads well on light terminals, steps aside for screen readers', async () => {
  const { say, createPainter: paint, wordmark, withLogo, MASCOT } = await import('../src/ui/term.mjs');
  const { eventLine } = await import('../src/guard/watch.mjs');
  const p = paint(0);
  assert.equal(MASCOT, 'Brakey');
  assert.match(strip(say(p, 'happy', 'All in order.')), /Brakey: All in order\./);
  const lit = paint(3);
  assert.match(strip(eventLine(lit, { ts: '2026-01-01T10:00:00Z', kind: 'tamper', action: 'denied', harness: 'codex' })), /!! +MAXIMUM/, 'alarmed face on maximum alerts');
  assert.match(strip(eventLine(lit, { ts: '2026-01-01T10:00:00Z', kind: 'sensitive-read', action: 'warned', harness: 'codex' })), /·· +MEDIUM/, 'worried face on medium');
  process.env.BLACKBRAKE_THEME = 'light';
  const light = paint(3);
  assert.match(light.cream('x'), /38;2;59;36;21m/, 'light theme: text in dark brown');
  assert.match(wordmark(light).join(''), /38;2;30;18;11m|38;2;42;24;16m/, 'BLACK drawn dark on light terminals');
  delete process.env.BLACKBRAKE_THEME;
  process.env.ACCESSIBLE = '1';
  assert.deepEqual(withLogo(lit, ['Hello']), ['  Hello'], 'screen readers: no drawing');
  delete process.env.ACCESSIBLE;
});

test('each screen starts on a clean terminal; output to a file or a pipe is never cleared', async () => {
  const { clearScreen } = await import('../src/ui/term.mjs');
  const sink = (isTTY) => ({ isTTY, text: '', write(s) { this.text += s; } });
  const tty = sink(true);
  const pipe = sink(false);
  clearScreen(tty);
  clearScreen(pipe);
  assert.equal(tty.text, '\x1b[2J\x1b[3J\x1b[H');
  assert.equal(pipe.text, '');
});

test('menu: numbers pick an option straight away', async () => {
  const { select } = await import('../src/ui/menu.mjs');
  const { EventEmitter } = await import('node:events');
  const input = Object.assign(new EventEmitter(), { isTTY: true, setRawMode() {}, resume() {}, pause() {} });
  const done = select(createPainter(0), [{ value: 'a', label: 'A' }, { value: 'b', label: 'B' }, { value: 'c', label: 'C', disabled: true }], { input, output: { isTTY: true, write() {} } });
  input.emit('keypress', '3', { name: '3' });
  input.emit('keypress', '2', { name: '2' });
  assert.equal(await done, 'b', 'a disabled option cannot be picked by number');
});

test('menu: the live session shows ACTIVE (green, filled) or NOT ACTIVE (grey, hollow); help is there', () => {
  const p = createPainter(3);
  assert.match(liveBadge(p, true), /\x1b\[48;2;91;214;138m/, 'green background');
  assert.match(strip(liveBadge(p, true)), /● ACTIVE/);
  assert.match(strip(liveBadge(p, false)), /○ NOT ACTIVE/);
  const state = { installed: true, running: 2, live: true };
  assert.match(strip(homeItems(state, p).find((i) => i.value === 'live').tag), /ACTIVE/, 'on the main menu');
  assert.match(strip(categoryItems('live', state, p).find((i) => i.value === 'watch').tag), /ACTIVE/, 'and beside the live alerts');
  assert.ok(categoryItems('more', state).some((i) => i.value === 'help'));
  assert.ok(categoryItems('audit', state).some((i) => i.value === 'scan'));
});

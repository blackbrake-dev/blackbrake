// The real-installation lock (src/guard/safety.mjs). On 2026-10-01 a script that imported
// install.mjs and called uninstall() with an empty BLACKBRAKE_HOME deleted the real ~/.blackbrake.
// From now on, code that is not the blackbrake program itself (the CLI, the hook, the watcher, the
// status line) cannot change or delete the real installation or an agent's real configuration.
//
// These tests NEVER act on the real folders: the checks take a stand-in "real home", and the
// integration checks run in a child process whose real home is a temporary folder.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isRealPlace, mayChange, realPlaces } from '../src/guard/safety.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bb-safety-'));

test('the real places: guard\'s folder, every agent\'s config, the login-item folders', () => {
  const real = path.join(path.parse(os.tmpdir()).root, 'Users', 'someone');
  const places = realPlaces(real).map((p) => path.relative(real, p).replace(/\\/g, '/'));

  for (const p of ['.blackbrake', '.claude', '.claude.json', '.codex', '.cursor', '.copilot', '.gemini', '.codeium', '.devin', 'Library/LaunchAgents', '.config/autostart', '.config/devin', 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup']) {
    assert.ok(places.includes(p), p);
  }

  for (const target of ['.blackbrake', '.blackbrake/state.json', '.claude/settings.json', '.cursor/hooks.json', '.BLACKBRAKE/x', 'Library/LaunchAgents/dev.blackbrake.watch.plist']) {
    assert.equal(isRealPlace(path.join(real, target), real), true, target);
  }

  for (const target of ['projects/app/.env', '.blackbrake-old/x', 'Documents', path.join('..', 'other', '.blackbrake')]) {
    assert.equal(isRealPlace(path.join(real, target), real), false, target);
  }
});

test('not the blackbrake program: changing a real place is refused; temporary folders are fine', () => {
  const real = path.join(path.parse(os.tmpdir()).root, 'Users', 'someone');
  assert.throws(() => mayChange(path.join(real, '.blackbrake'), { realHome: real, declared: false }), /refused to change/);
  assert.throws(() => mayChange('', { realHome: real, declared: false }), /refused to change/, 'an empty path is never fine');
  assert.doesNotThrow(() => mayChange(path.join(tmp(), '.blackbrake'), { realHome: real, declared: false }));
  assert.doesNotThrow(() => mayChange(path.join(real, '.blackbrake'), { realHome: real, declared: true }), 'the program itself may');
});

// A child process whose "real home" is a temporary folder (BLACKBRAKE_REAL_HOME_FOR_TESTS is read
// only when that folder is inside the OS temporary folder), with HOME pointing there too and
// BLACKBRAKE_HOME left empty: exactly the 2026-10-01 accident. PATH is empty so no real `claude`
// could ever be started.
function child(code, realHome) {
  const env = { ...process.env, HOME: realHome, USERPROFILE: realHome, BLACKBRAKE_HOME: '', BLACKBRAKE_REAL_HOME_FOR_TESTS: realHome, CLAUDE_CONFIG_DIR: path.join(realHome, '.claude'), PATH: '' };
  delete env.CLAUDECODE;

  return spawnSync(process.execPath, ['--input-type=module', '-e', code], { env, encoding: 'utf8' });
}

const url = (rel) => JSON.stringify(pathToFileURL(path.join(ROOT, rel)).href);

test('the 2026-10-01 accident cannot happen again: uninstall() from a script refuses first, the folder stays', () => {
  const real = tmp();
  const bb = path.join(real, '.blackbrake');
  fs.mkdirSync(path.join(bb, 'log'), { recursive: true });
  fs.writeFileSync(path.join(bb, 'state.json'), '{"mode":"protect"}');
  const r = child(`const { uninstall } = await import(${url('src/guard/install.mjs')}); uninstall({ keepLog: false, log: (m) => console.log(m) });`, real);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /refused to change/);
  assert.equal(r.stdout, '', 'refused before doing anything, even before asking Claude Code to remove its plugin');
  assert.ok(fs.existsSync(path.join(bb, 'state.json')), 'still there');
});

test('from a script, nothing writes the real state, the real agent configs or kills a process', () => {
  const real = tmp();
  fs.mkdirSync(path.join(real, '.cursor'), { recursive: true });
  fs.writeFileSync(path.join(real, '.cursor', 'hooks.json'), '{"version":1,"hooks":{}}');

  for (const code of [
    `const { setMode } = await import(${url('src/guard/state.mjs')}); setMode('observe');`,
    `const { AGENTS } = await import(${url('src/guard/agents.mjs')}); AGENTS.cursor.install({ home: ${JSON.stringify(path.join(real, '.blackbrake'))}, hook: 'x' });`,
    `const { stopKind } = await import(${url('src/guard/procs.mjs')}); stopKind('watcher', { list: () => [] });`,
  ]) {
    const r = child(code, real);
    assert.notEqual(r.status, 0, code);
    assert.match(r.stderr, /refused to change|refused to stop/, code);
  }

  assert.equal(fs.readFileSync(path.join(real, '.cursor', 'hooks.json'), 'utf8'), '{"version":1,"hooks":{}}');
  assert.equal(fs.existsSync(path.join(real, '.blackbrake', 'state.json')), false);
});

test('the blackbrake program itself still works on its own folder (it declares itself)', () => {
  const real = tmp();
  const env = { ...process.env, HOME: real, USERPROFILE: real, BLACKBRAKE_HOME: '', BLACKBRAKE_REAL_HOME_FOR_TESTS: real, CLAUDE_CONFIG_DIR: path.join(real, '.claude'), BLACKBRAKE_NO_WINDOW: '1', NO_COLOR: '1' };
  delete env.CLAUDECODE;
  const r = spawnSync(process.execPath, [path.join(ROOT, 'src', 'guard', 'hook.mjs'), 'PreToolUse', '--harness', 'claude'], { input: JSON.stringify({ session_id: 's', tool_name: 'Bash', tool_input: { command: 'ls' } }), env, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(fs.existsSync(path.join(real, '.blackbrake', 'log')), 'the hook wrote its log in its own folder');
});

test('an override of the real home outside the temporary folder is ignored', () => {
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', `const s = await import(${url('src/guard/safety.mjs')}); console.log(s.realHome());`], { env: { ...process.env, BLACKBRAKE_REAL_HOME_FOR_TESTS: path.join(path.parse(os.tmpdir()).root, 'nowhere') }, encoding: 'utf8' });
  assert.equal(r.stdout.trim(), os.userInfo().homedir);
});

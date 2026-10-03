// F6.6: Cursor's sessionStart (guard-design §6x.6). The input is the shape of a real cursor-agent
// session (test/fixtures/cursor/sessionStart.json, values synthetic). Copilot CLI's sessionStart is
// not wired: there is no real payload yet (no Copilot CLI on the machine where this was written).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { ADAPTERS } from '../src/guard/harnesses.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const HOOK = path.join(ROOT, 'src', 'guard', 'hook.mjs');

const FIXTURE = JSON.parse(fs.readFileSync(path.join(ROOT, 'test', 'fixtures', 'cursor', 'sessionStart.json'), 'utf8'));

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bb-sessionstart-'));

function run(home, input, settings = {}) {
  fs.writeFileSync(path.join(home, 'state.json'), JSON.stringify({ mode: 'protect', settings }));
  // As Cursor sends it on Windows: a byte order mark, then the JSON.
  const body = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(input))]);

  return spawnSync(process.execPath, [HOOK, 'sessionStart', '--harness', 'cursor'], { input: body, encoding: 'utf8', env: { ...process.env, BLACKBRAKE_HOME: home, BLACKBRAKE_LANG: 'en', BLACKBRAKE_NO_WINDOW: '1' } });
}

const logText = (home) => {
  const dir = path.join(home, 'log');

  return fs.existsSync(dir) ? fs.readdirSync(dir).map((f) => fs.readFileSync(path.join(dir, f), 'utf8')).join('') : '';
};

test('Cursor sessionStart: a valid answer, the session is noted, and nothing personal is kept', () => {
  const home = tmp();
  const r = run(home, FIXTURE);
  assert.equal(r.status, 0);
  assert.deepEqual(JSON.parse(r.stdout), {});
  const log = logText(home);
  assert.match(log, /"kind":"session","action":"start"/);
  assert.match(log, /"harness":"cursor"/);

  for (const leak of ['example.invalid', '/work/example', 'example-model', FIXTURE.conversation_id]) assert.ok(!log.includes(leak), leak);
});

test('Cursor sessionStart while paused: still a valid answer', () => {
  const r = run(tmp(), FIXTURE, { paused: { at: '2026-10-01T10:00:00Z', by: 'cli' } });
  assert.equal(r.status, 0);
  assert.deepEqual(JSON.parse(r.stdout), {});
});

test('Cursor sessionStart is normalized to the session id and the background flag only', () => {
  const { event, input } = ADAPTERS.cursor.normalize('SessionStart', FIXTURE, 'sessionStart');
  assert.equal(event, 'SessionStart');
  assert.deepEqual(input, { session_id: FIXTURE.conversation_id, is_background_agent: false });
  assert.equal(ADAPTERS.cursor.normalize('SessionStart', { ...FIXTURE, is_background_agent: true }, 'sessionStart').input.is_background_agent, true);
  assert.equal(ADAPTERS.cursor.normalize('SessionStart', { ...FIXTURE, is_background_agent: 'yes' }, 'sessionStart').input.is_background_agent, false, 'only a real true counts');
});

test('setup subscribes Cursor to sessionStart (and re-running it rewrites the entries, with a backup)', () => {
  const home = tmp();
  const bb = path.join(home, '.blackbrake');

  const code = `const { AGENTS } = await import(${JSON.stringify(pathToFileURL(path.join(ROOT, 'src', 'guard', 'agents.mjs')).href)});
    AGENTS.cursor.install({ home: ${JSON.stringify(bb)}, hook: ${JSON.stringify(path.join(bb, 'app', 'src', 'guard', 'hook.mjs'))} });
    AGENTS.cursor.install({ home: ${JSON.stringify(bb)}, hook: ${JSON.stringify(path.join(bb, 'app', 'src', 'guard', 'hook.mjs'))} });`;

  fs.mkdirSync(path.join(home, '.cursor'));
  fs.writeFileSync(path.join(home, '.cursor', 'hooks.json'), JSON.stringify({ version: 1, hooks: { sessionStart: [{ command: 'mine' }] } }));

  const r = spawnSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8', env: { ...process.env, HOME: home, USERPROFILE: home, BLACKBRAKE_HOME: bb } });
  assert.equal(r.status, 0, r.stderr);
  const hooks = JSON.parse(fs.readFileSync(path.join(home, '.cursor', 'hooks.json'), 'utf8')).hooks;
  assert.equal(hooks.sessionStart.length, 2, 'the user\'s own entry plus one of ours, not two');
  assert.equal(hooks.sessionStart[0].command, 'mine');
  assert.match(hooks.sessionStart[1].command, /hook\.mjs" sessionStart --harness cursor$/);
  assert.ok(fs.readdirSync(path.join(bb, 'backups'), { recursive: true }).length > 0, 'a backup was made');
});

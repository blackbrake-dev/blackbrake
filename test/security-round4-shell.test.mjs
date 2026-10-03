import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const HOOK = fileURLToPath(new URL('../src/guard/hook.mjs', import.meta.url));

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-r4-shell-'));
  const home = path.join(root, '.blackbrake');
  const cwd = path.join(root, 'project');
  fs.mkdirSync(home);
  fs.mkdirSync(cwd);
  fs.writeFileSync(path.join(home, 'state.json'), JSON.stringify({ mode: 'observe' }));
  t.after(() => {
    assert.equal(path.dirname(root), path.resolve(os.tmpdir()));
    assert.equal(fs.existsSync(root), true);
    fs.rmSync(root, { recursive: true, force: true });
  });

  return { root, home, cwd, env: {
    HOME: root, USERPROFILE: root, BLACKBRAKE_HOME: home,
    BLACKBRAKE_NO_WINDOW: '1', BLACKBRAKE_LANG: 'en',
    TEMP: root, TMP: root, PATH: process.env.PATH ?? '', SystemRoot: process.env.SystemRoot ?? '',
    CLAUDE_CONFIG_DIR: path.join(root, '.claude'), CODEX_HOME: path.join(root, '.codex'),
    COPILOT_HOME: path.join(root, '.copilot'), XDG_CONFIG_HOME: path.join(root, '.config'),
    APPDATA: path.join(root, 'AppData', 'Roaming'),
  } };
}

function denied(f, command) {
  const r = spawnSync(process.execPath, [HOOK, 'PreToolUse', '--harness', 'claude'], {
    input: JSON.stringify({ session_id: 's', cwd: f.cwd, tool_name: 'Bash', tool_input: { command } }),
    cwd: f.cwd, env: f.env, encoding: 'utf8', timeout: 15000,
  });

  assert.equal(r.error, undefined);
  const out = JSON.parse(r.stdout || '{}');

  return out.hookSpecificOutput?.permissionDecision === 'deny';
}

test('R4 V2 a previous literal assignment does not excuse later printf -v writes', (t) => {
  const f = fixture(t);
  const command = "d=.ssh; printf -v d '.%s%s' black brake; echo x > ~/$d/state.json";
  assert.equal(denied(f, command), true, command);
});

test('R4 V2 Bash variable names retain their case when determining unresolved gaps', (t) => {
  const f = fixture(t);
  const command = "d=.ssh; D=$(printf '.%s%s' black brake); echo x > ~/$D/state.json";
  assert.equal(denied(f, command), true, command);
});

test('R4 V2 printf variable setters accept attached and quoted flags', (t) => {
  const f = fixture(t);

  for (const setter of ["printf -vd '.%s%s' black brake", "printf '-v' d '.%s%s' black brake"]) {
    const command = `d=.ssh; ${setter}; echo x > ~/$d/state.json`;
    assert.equal(denied(f, command), true, command);
  }
});

test('R4 V2 loop bindings invalidate a previous literal value', (t) => {
  const f = fixture(t);

  for (const loop of ['for', 'select']) {
    const command = `d=.ssh; set -- $(printf '.%s%s' black brake); ${loop} d in "$1"; do echo x > ~/$d/state.json; done`;

    assert.equal(denied(f, command), true, loop);
  }
});

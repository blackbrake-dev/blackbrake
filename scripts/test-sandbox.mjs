#!/usr/bin/env node
// `npm test` runs through here: every test process gets a fresh temporary home, so a test that
// forgets to pass its own `home` still never sees the real ~/.blackbrake, ~/.claude, an agent's
// configuration or the login-item folders (2026-10-01: a script deleted the real ~/.blackbrake).
// The real-installation lock (src/guard/safety.mjs) is the second wall: it refuses real places
// from anything that is not the blackbrake program, whatever HOME says.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-test-home-'));

// Checked before anything runs: the sandbox is a new, empty folder inside the system temporary folder.
if (!path.resolve(sandbox).startsWith(path.resolve(os.tmpdir())) || fs.readdirSync(sandbox).length) {
  console.error(`test-sandbox: refusing ${sandbox}`);
  process.exit(1);
}

const env = {
  ...process.env,
  HOME: sandbox,
  USERPROFILE: sandbox,
  APPDATA: path.join(sandbox, 'AppData', 'Roaming'),
  XDG_CONFIG_HOME: path.join(sandbox, '.config'),
  BLACKBRAKE_HOME: path.join(sandbox, '.blackbrake'),
  CLAUDE_CONFIG_DIR: path.join(sandbox, '.claude'),
  CODEX_HOME: path.join(sandbox, '.codex'),
  COPILOT_HOME: path.join(sandbox, '.copilot'),
  BLACKBRAKE_NO_WINDOW: '1',
};

const r = spawnSync(process.execPath, ['--test', ...process.argv.slice(2)], { env, stdio: 'inherit' });

// Only this run's own sandbox is removed, and only if it is still inside the temporary folder.
try { if (path.dirname(sandbox) === path.resolve(os.tmpdir())) fs.rmSync(sandbox, { recursive: true, force: true }); } catch { /* left for the system to clean */ }

process.exit(r.status ?? 1);

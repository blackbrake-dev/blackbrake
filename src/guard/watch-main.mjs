#!/usr/bin/env node
// What the alerts window runs (`node watch-main.mjs`) and, with --background, the hidden watcher
// started at login. Lives next to the hook so the copy of guard each agent runs has it.
//
// Before loading anything else, the copy is checked against the manifest written when it was
// installed: code that runs at every login must be the code the user installed. If a file changed,
// the watcher does not run; it records a tamper event (seen by `blackbrake status` and `watch`).
// A same-user attacker can rewrite the manifest too: this catches accidents and careless tampering,
// not a determined local attacker (see the README's "What guard cannot promise").
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const app = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

function changedFiles() {
  let manifest;
  let installed = false;

  try { installed = JSON.parse(fs.readFileSync(path.join(app, 'package.json'), 'utf8')).name === 'blackbrake-guard'; } catch { /* the package itself */ }

  // An installed copy without its manifest has been tampered with (deleting it must not switch the
  // check off). Only the package itself (development) runs without one.
  try { manifest = JSON.parse(fs.readFileSync(path.join(app, 'manifest.json'), 'utf8')); } catch { return installed ? ['manifest.json'] : null; }

  const changed = [];

  for (const [rel, sum] of Object.entries(manifest)) {
    let now = null;

    try { now = crypto.createHash('sha256').update(fs.readFileSync(path.join(app, rel))).digest('hex'); } catch { /* missing */ }

    if (now !== sum) changed.push(rel);
  }

  return changed;
}

// Only the installed copy has a manifest; running from the package itself skips the check.
const changed = changedFiles();

if (changed?.length) {
  try {
    const home = path.dirname(app);
    const line = JSON.stringify({ ts: new Date().toISOString(), s: 'watcher', ev: 'Startup', kind: 'tamper', action: 'denied', tool: 'watch-main', rule: changed.slice(0, 3).join(',').slice(0, 120), harness: 'blackbrake' });
    fs.mkdirSync(path.join(home, 'log'), { recursive: true, mode: 0o700 });
    const file = path.join(home, 'log', `${new Date().toISOString().slice(0, 7)}.jsonl`);

    // Not written through a planted link (the rest of the code is not trusted here, so this repeats
    // the rule of state.mjs's writePrivate).
    try {
      const st = fs.lstatSync(file);

      if (!st.isFile() || st.nlink > 1) fs.rmSync(file, { force: true });
    } catch { /* not there yet */ }

    fs.appendFileSync(file, `${line}\n`, { mode: 0o600 });
  } catch { /* nothing else to do */ }

  process.stderr.write(`blackbrake: the installed copy was changed (${changed.slice(0, 3).join(', ')}); not running. Run "blackbrake setup" again.\n`);
  process.exit(1);
}

// This is the blackbrake program (the watcher or the alerts window): it may change its own folder.
(await import('./safety.mjs')).declareProgram();

const { detectLang, setLang } = await import('../i18n.mjs');

const { createPainter } = await import('../ui/term.mjs');

const { getSavedLang, trustedHome } = await import('./state.mjs');

// Same rule as the hook: the login item's environment does not choose guard's folder.
process.env.BLACKBRAKE_HOME = trustedHome(import.meta.url);

setLang(detectLang({ saved: getSavedLang() }));

if (process.argv.includes('--background')) {
  process.title = 'blackbrake watcher';
  const { runBackground } = await import('./background.mjs');
  await runBackground({ cli: fileURLToPath(import.meta.url) });
} else {
  // A window of its own: the brand at the top (logo, name, what it is), then the live alerts.
  process.title = 'blackbrake watch';
  const { watch } = await import('./watch.mjs');
  const { setTitle, withLogo, wordmark } = await import('../ui/term.mjs');
  const { t } = await import('../i18n.mjs');
  const p = createPainter();
  setTitle(`blackbrake · ${t('live alerts')}`);
  process.stdout.write(`\n${withLogo(p, [...wordmark(p), p.cream(t('The black box and the brakes for your AI agents.')), p.faint(t('Local · 0 network connections · you stay in control'))]).join('\n')}\n`);
  await watch(p, { keys: true });
}

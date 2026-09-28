// Terminal side of guard: status, mode, recent events, status line and launching Claude Code.
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { plural, t } from '../i18n.mjs';
import { clean, isLocalPath } from '../text.mjs';
import { select } from '../ui/menu.mjs';
import { columns, padEnd, screen } from '../ui/term.mjs';
import { AGENTS } from './agents.mjs';
import { claudeCommand, guardInstalled, PLUGIN_ID } from './install.mjs';
import { getSpendBaseline } from './spend-state.mjs';
import { getMode, guardHome, readLog, sessionHash } from './state.mjs';

const KIND = {
  'secret-in-prompt': 'secret in your message',
  'secret-in-output': 'secret in tool output',
  'secret-in-write': 'secret written to a file',
  'secret-in-command': 'secret inside a command',
  'sensitive-read': 'read of a credential file',
  'secret-dump': 'command that prints secrets',
  'secret-in-request': 'secret sent in a request',
  'opaque-command': 'command that cannot be checked',
  'destructive-after-compaction': 'destructive command after compaction',
  tamper: 'attempt to switch guard off',
  error: 'guard could not check a step',
  'secret-in-history': 'secret written in an agent\'s history',
  'spend-cost': 'episode above your local cost p90',
  'spend-loop': 'repeated tool call',
  'inventory-delta': 'new or changed agent add-ons',
};

const interesting = (e) => e.kind in KIND;

export const isInteractive = () => Boolean(process.stdin.isTTY && process.stdout.isTTY);

// Ask a yes/no question in the terminal; "No" is preselected. Without a terminal: no.
export async function confirm(p, question) {
  if (!isInteractive()) return false;
  process.stdout.write(`\n  ${p.cream(question)}\n`);

  return (await select(p, [{ value: false, label: t('No') }, { value: true, label: t('Yes') }])) === true;
}

// For lowering protection: the person has to type a word, not just press Enter.
export async function confirmTyped(p, question, word, alias = null) {
  if (!isInteractive()) return false;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise((resolve) => rl.question(`\n  ${p.cream(question)}\n  ${p.faint(t('Type "{w}" to confirm, anything else to cancel:', { w: alias ?? word }))} `, resolve));
  rl.close();

  return [word, alias].includes(answer.trim().toLowerCase());
}

// Compares the guard code Claude Code actually runs (its plugin cache) with this package. A
// difference means it was changed after installation, or blackbrake was updated without setup.
export function integrity(claudeHome = process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude')) {
  let installPath = null;

  try {
    const installed = JSON.parse(fs.readFileSync(path.join(claudeHome, 'plugins', 'installed_plugins.json'), 'utf8')).plugins?.[PLUGIN_ID];
    installPath = (Array.isArray(installed) ? installed[0] : installed)?.installPath ?? null;
  } catch { return { checked: false }; }

  if (!isLocalPath(installPath)) return { checked: false };
  const changed = compareApp(path.join(installPath, 'app'));

  // hooks.json decides which events and tools reach guard at all.
  if (hash(path.join(PKG_ROOT, 'plugin', 'blackbrake', 'hooks', 'hooks.json')) !== hash(path.join(installPath, 'hooks', 'hooks.json'))) changed.push('hooks/hooks.json');

  return { checked: true, changed: changed.map((c) => clean(c.replace(/\\/g, '/'), 120)) };
}

const PKG_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

const hash = (f) => { try { return crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex'); } catch { return null; } };

// Files of an installed copy of guard (src/ and the rules) that differ from this package.
function compareApp(app) {
  if (!fs.existsSync(path.join(app, 'src'))) return [t('the copy of guard is missing: run "blackbrake setup" again')];
  const files = (dir, base = dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(path.join(dir, e.name), base) : e.isFile() ? [path.relative(base, path.join(dir, e.name))] : []));
  const changed = [];

  for (const rel of files(path.join(PKG_ROOT, 'src'))) if (hash(path.join(PKG_ROOT, 'src', rel)) !== hash(path.join(app, 'src', rel))) changed.push(`src/${rel}`);

  if (hash(path.join(PKG_ROOT, 'vendor', 'gitleaks.rules.json')) !== hash(path.join(app, 'vendor', 'gitleaks.rules.json'))) changed.push('vendor/gitleaks.rules.json');

  return changed;
}

// The copy the other agents' hooks run (~/.blackbrake/app).
export const agentsIntegrity = () => compareApp(path.join(guardHome(), 'app')).map((c) => clean(c.replace(/\\/g, '/'), 120));

export function modeBadge(p, mode) {
  return mode === 'protect' ? p.onOrange(p.ink(p.bold(` ${t('PROTECT')} `))) : p.onBrown(p.amber(p.bold(` ${t('OBSERVE')} `)));
}

export function statusLines(p, { days = 7 } = {}) {
  const inst = guardInstalled();
  const mode = getMode();
  const since = new Date(Date.now() - days * 864e5).toISOString();
  const events = readLog(undefined, { since }).filter(interesting);
  const out = screen(p, 'GUARD', t('status of guard in your agents'), columns(), { pose: mode === 'protect' ? 'determined' : 'idle', line: t(mode === 'protect' ? 'Protecting: risky steps are stopped.' : 'Observing: I warn and log, nothing is stopped.') });
  // Hooks that ran in the last day while no installed plugin is registered: loaded another way
  // (claude --plugin-dir, a copied hooks config). It runs, but its code cannot be checked here.
  const dayAgo = new Date(Date.now() - 864e5).toISOString();
  const running = !inst.installed && readLog(undefined, { since: dayAgo }).some((e) => e.ev && e.ev !== 'unknown' && (e.harness ?? 'claude') === 'claude');

  const plugin = inst.installed
    ? (inst.enabled ? p.cream(t('{id} installed and enabled', { id: PLUGIN_ID })) : p.amber(t('{id} installed but disabled', { id: PLUGIN_ID })))
    : running ? p.amber(t('running, but not installed with "blackbrake setup" (e.g. --plugin-dir): its code cannot be verified')) : p.amber(t('not installed · run "blackbrake setup"'));

  out.push(`  ${padEnd(p.faint(t('Plugin')), 14)}${plugin}`);
  out.push(`  ${padEnd(p.faint(t('Mode')), 14)}${modeBadge(p, mode)} ${p.faint(t(mode === 'protect' ? 'stops secrets before they are sent' : 'warns and logs; nothing is stopped'))}`);
  const baseline = getSpendBaseline('claude');

  if (baseline?.ready) out.push(`  ${padEnd(p.faint(t('Spend')), 14)}${p.cream(t('{n} local episodes · median API≈${median} · p90 API≈${p90}', { n: baseline.n, median: baseline.p50.toFixed(2), p90: baseline.p90.toFixed(2) }))}`);
  else out.push(`  ${padEnd(p.faint(t('Spend')), 14)}${p.faint(t('fewer than 30 local Claude Code episodes · no cost threshold'))}`);

  if (inst.installed) {
    const check = integrity();

    if (check.checked && check.changed.length) out.push(`  ${padEnd(p.faint(t('Code')), 14)}${p.coral(`● ${t('{n} file(s) differ from this blackbrake version', { n: check.changed.length })}`)} ${p.faint(`(${check.changed.slice(0, 2).join(', ')}) · ${t('run "blackbrake setup" to reinstall')}`)}`);
    else if (check.checked) out.push(`  ${padEnd(p.faint(t('Code')), 14)}${p.cream(t('matches this blackbrake version'))}`);
  }

  const agents = Object.values(AGENTS).filter((a) => a.installed());

  if (agents.length) {
    const changed = agentsIntegrity();
    out.push(`  ${padEnd(p.faint(t('Other agents')), 14)}${p.cream(agents.map((a) => a.name).join(' · '))}`);
    out.push(`  ${padEnd('', 14)}${changed.length ? p.coral(`● ${t('{n} file(s) differ from this blackbrake version', { n: changed.length })} (${changed.slice(0, 2).join(', ')})`) : p.faint(t('code matches this blackbrake version'))}`);
  }

  if (!events.length) {
    out.push(`  ${padEnd(p.faint(t('Last {n} days', { n: days })), 14)}${p.cream(t('no alerts'))}`);

    return [...out, ''];
  }

  const counts = new Map();

  for (const e of events) counts.set(`${e.kind}|${e.action}`, (counts.get(`${e.kind}|${e.action}`) ?? 0) + 1);
  out.push(`  ${p.faint(t('Last {n} days', { n: days }))}`);

  for (const [key, n] of [...counts].sort((a, b) => b[1] - a[1])) {
    const [kind, action] = key.split('|');
    out.push(`    ${p.orange(String(n).padStart(4))}  ${padEnd(t(KIND[kind]), 40)} ${p.faint(t(clean(action, 12)))}`);
  }

  return [...out, ''];
}

export function logLines(p, { days = 7 } = {}) {
  const since = new Date(Date.now() - days * 864e5).toISOString();
  const events = readLog(undefined, { since }).filter(interesting).slice(-40);
  const out = screen(p, t('LOG'), t('guard events, last {n} days (counts and types only)', { n: days }), columns(), { pose: 'think', line: t('Counts and types only: never what was said.') });

  if (!events.length) return [...out, `  ${p.faint(t('Nothing yet.'))}`, ''];

  // Log lines are data on disk: every field is cleaned before it reaches the terminal.
  for (const e of events) out.push(`  ${p.faint(clean(e.ts, 20).slice(0, 16).replace('T', ' '))}  ${padEnd(t(KIND[e.kind]), 40)} ${p.cream(padEnd(t(clean(e.action, 12)), 10))} ${p.faint([e.tool, e.rule].flatMap((x) => x ? [clean(x, 60)] : []).join(' · '))}`);

  return [...out, ''];
}

// One line for Claude Code's status bar: reads the session JSON Claude Code sends on stdin.
export function statusLineText(p, input) {
  const mode = getMode();
  const s = sessionHash(input?.session_id);
  const alerts = readLog().filter((e) => e.s === s && interesting(e) && e.kind !== 'error').length;

  return `${p.orange('▀▄')} blackbrake ${modeBadge(p, mode)}${alerts ? ` ${p.amber(plural(alerts, 'alert'))}` : ` ${p.faint(t('no alerts'))}`}`;
}

// Start Claude Code in this terminal, with whatever arguments the user passed. No shell unless the
// only Claude Code on PATH is npm's .cmd shim (see claudeCommand).
export function launchClaude(args = []) {
  return new Promise((resolve) => {
    let c;

    try { c = claudeCommand(args); } catch (e) {
      resolve({ ok: false, error: e.message });

      return;
    }

    const child = spawn(c.file, c.args, { stdio: 'inherit', shell: c.shell });

    child.on('error', (e) => resolve({ ok: false, error: e.code === 'ENOENT' ? t('Claude Code ("claude") was not found on PATH.') : e.message }));
    child.on('exit', (code) => resolve({ ok: code === 0, code }));
  });
}

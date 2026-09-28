#!/usr/bin/env node
// blackbrake — local audit of AI coding agent transcripts and setup, and guard for Claude Code.
// No network access, no dependencies. audit only reads; guard writes only to ~/.blackbrake.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCostAnalyzer } from '../src/cost/analyzer.mjs';
import { PRICES_DATE } from '../src/cost/prices.mjs';
import { inventory } from '../src/load/inventory.mjs';
import { runAnalyzers } from '../src/run.mjs';
import { createSecretsAnalyzer } from '../src/secrets/audit.mjs';
import { loadRules } from '../src/secrets/engine.mjs';
import { ADVISORIES_DATE, openAdvisories } from '../src/advisories.mjs';
import { listStores, readTextFile } from '../src/stores.mjs';
import { clean } from '../src/text.mjs';
import { createVersionAnalyzer } from '../src/version.mjs';
import { defaultRoot, listTranscripts } from '../src/transcripts.mjs';
import { buildAdvice } from '../src/advice.mjs';
import { renderAdvice, renderAudit, renderDetails } from '../src/ui/audit-view.mjs';
import { confirm, confirmTyped, isInteractive, launchClaude, logLines, modeBadge, statusLines, statusLineText } from '../src/guard/cli.mjs';
import { guardInstalled, setup, uninstall } from '../src/guard/install.mjs';
import { getMode, getSavedLang, getSetting, hasMode, MODES, readLog, setMode, setSavedLang, setSetting } from '../src/guard/state.mjs';
import { runningAgents, severity, watch } from '../src/guard/watch.mjs';
import { detectLang, getLang, LANGS, plural, setLang, t } from '../src/i18n.mjs';
import { AGENTS, buildRuntime, setupAgents, uninstallAgents } from '../src/guard/agents.mjs';
import { autostartFile, autostartInstalled, installAutostart, removeAutostart } from '../src/guard/autostart.mjs';
import { isBackgroundRunning } from '../src/guard/background.mjs';
import { detected, detectedHarnesses, HARNESSES } from '../src/guard/registry.mjs';
import { harnessFiles, scanHarness } from '../src/guard/scan.mjs';
import { CLASSES } from '../src/secrets/context.mjs';
import { afterAuditItems, category, home, homeItems, privacyScreen } from '../src/ui/home.mjs';
import { checklist, select } from '../src/ui/menu.mjs';
import { agentInstruction, buildPrompt, promptHash, promptUnchanged, prunePrompts, savePrompt } from '../src/fix/prompt.mjs';
import { availableAgents, launchAgent } from '../src/fix/agent.mjs';
import { fixesFromAudit, fixesFromScan } from '../src/fix/plan.mjs';
import { KEEP_DAYS, listScrubs, pruneScrubs, scrub, undoScrub } from '../src/fix/scrub.mjs';
import { applySettings, diffLines, planSettings } from '../src/fix/settings.mjs';
import { goodbyeScene, report, spinner, transition } from '../src/ui/motion.mjs';
import { box, columns, createPainter, HELLO, MASCOT, padEnd, play, say, screen, withLogo } from '../src/ui/term.mjs';

const pkg = JSON.parse(fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../package.json'), 'utf8'));

const HELP_ES = `blackbrake ${pkg.version} — mira qué ha expuesto, qué carga y qué gasta tu agente de IA. En local.

Instálalo una vez y ábrelo desde cualquier carpeta con solo "blackbrake":
  npm install -g blackbrake     (o sin instalar nada: npx blackbrake)

Uso:
  blackbrake                    Pantalla de inicio (en una terminal interactiva)
  blackbrake audit [--details] [--advice] [--all] [--json] [--path <dir>] [--home <dir>]

Guard (blackbrake dentro de tus agentes: Claude Code, Codex, Gemini CLI, Cursor, Copilot CLI, Windsurf):
  blackbrake setup [--yes] [--agent <id,…>]
                                Instala guard en todos los agentes encontrados (o en los indicados)
  blackbrake agents             Qué agentes están protegidos
  blackbrake watch              Alertas en directo de los agentes en marcha (de bajo a máximo)
  blackbrake window [on|off]    Abrir una ventana de alertas al arrancar un agente
  blackbrake claude [args…]     Abre Claude Code con guard activo (los args van a claude)
  blackbrake mode [observe|protect]
                                Muestra o cambia el modo. observe avisa; protect detiene
  blackbrake status             Plugin, modo y alertas de los últimos 7 días
  blackbrake log [--days <n>]   Eventos recientes de guard (recuentos y tipos, nunca contenido)
  blackbrake statusline         Una línea para la barra de estado de Claude Code (lee su JSON por stdin)
  blackbrake fix [--undo]       Arreglar lo que encontraron la auditoría y el escaneo: aquí o con tu agente de IA
                                (--undo deshace una limpieza de los últimos 7 días)
  blackbrake uninstall [--agent <id,…>] [--purge]
                                Quita guard de todos los agentes o de los indicados (--purge borra su registro)
  Pasar a observe y desinstalar exigen tu confirmación en una terminal, así que el agente
  no puede hacerlo por ti.

Idioma:
  blackbrake lang [es|en|auto]  Muestra o fija el idioma (auto: el del sistema)
  --lang <es|en>                Idioma solo para esta ejecución (--json siempre en inglés)

Opciones:
  --details     Informe completo: cada hallazgo, patrón de complemento y episodio caro
  --advice      Precauciones a medida de tus resultados
  --all         Con --details: también los hallazgos clasificados como ejemplos/tests o desarrollo local
  --json        Salida para máquinas (nunca incluye valores secretos)
  --path <dir>  Carpeta de transcripciones (por defecto: ~/.claude/projects)
  --home <dir>  Carpeta personal con .claude/ y .claude.json (por defecto: la tuya)
  -h, --help    Muestra esta ayuda
  -v, --version Muestra la versión

El color sigue a tu terminal; NO_COLOR=1 lo desactiva.
blackbrake no abre conexiones de red. audit solo lee; guard solo escribe en ~/.blackbrake.`;

const HELP = `blackbrake ${pkg.version} — see what your AI coding agent has exposed, loads and spends. Locally.

Install once, then open it from any folder with just "blackbrake":
  npm install -g blackbrake     (or run it without installing: npx blackbrake)

Usage:
  blackbrake                    Home screen (in an interactive terminal)
  blackbrake audit [--details] [--advice] [--all] [--json] [--path <dir>] [--home <dir>]

Guard (blackbrake inside your agents: Claude Code, Codex, Gemini CLI, Cursor, Copilot CLI, Windsurf):
  blackbrake setup [--yes] [--agent <id,…>]
                                Install guard in every agent found (or the ones given)
  blackbrake agents             Which agents are protected
  blackbrake watch              Live alerts from running agents (low to maximum)
  blackbrake window [on|off]    Open an alerts window when an agent starts
  blackbrake claude [args…]     Start Claude Code with guard on (args go to claude)
  blackbrake mode [observe|protect]
                                Show or change the mode. observe warns; protect stops
  blackbrake status             Plugin, mode and alerts of the last 7 days
  blackbrake log [--days <n>]   Recent guard events (counts and types, never content)
  blackbrake statusline         One line for Claude Code's status bar (reads its JSON on stdin)
  blackbrake fix [--undo]       Fix what the audit and the scan found: here, or with your AI agent
                                (--undo reverts a clean-up from the last 7 days)
  blackbrake uninstall [--agent <id,…>] [--purge]
                                Remove guard from every agent or the ones given (--purge also deletes its log)
  Switching to observe and uninstalling need your confirmation in a terminal, so the agent
  cannot do it for you.

Language:
  blackbrake lang [en|es|auto]  Show or set the language (auto: follow the system)
  --lang <en|es>                Language for this run only (--json is always English)

Options:
  --details     Full report: every finding, add-on pattern and costly episode
  --advice      Precautions tailored to your results
  --all         With --details: also findings classified as examples/tests or local-dev
  --json        Machine-readable output (secret values are never included)
  --path <dir>  Transcript folder (default: ~/.claude/projects)
  --home <dir>  Home folder holding .claude/ and .claude.json (default: your home)
  -h, --help    Show this help
  -v, --version Show version

Colour follows your terminal; set NO_COLOR=1 to turn it off.
blackbrake opens no network connections. audit only reads; guard writes only to ~/.blackbrake.`;

function parseArgs(argv) {
  const opts = { command: null, path: null, home: null, json: false, all: false, rest: [], days: 7 };

  // Everything after `claude` belongs to Claude Code.
  if (argv[0] === 'claude') return { ...opts, command: 'claude', rest: argv.slice(1) };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];

    if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '--yes' || a === '-y') opts.yes = true;
    else if (a === '--purge') opts.purge = true;
    else if (a === '--undo') opts.undo = true;
    else if (a === '--days') opts.days = Math.max(1, Math.min(365, Number.parseInt(argv[++i], 10) || 7));
    else if (a === '-v' || a === '--version') opts.version = true;
    else if (a === '--json') opts.json = true;
    else if (a === '--all') opts.all = opts.details = true;
    else if (a === '--details') opts.details = true;
    else if (a === '--advice') opts.advice = true;
    else if (a === '--path') opts.path = argv[++i];
    else if (a === '--home') opts.home = argv[++i];
    else if (a === '--lang') opts.lang = argv[++i];
    else if (a === '--agent') opts.agent = argv[++i];
    else if (!opts.command) opts.command = a;
    else if (['mode', 'lang', 'window', 'background'].includes(opts.command) && !opts.rest.length) opts.rest.push(a);
    else throw new Error(`Unknown argument: ${clean(a, 80)}`);
  }

  return opts;
}

// Reads everything and returns the audit data (JSON-safe, no secret values).
async function collect(opts, p) {
  const home = path.resolve(opts.home ?? os.homedir());
  const root = path.resolve(opts.path ?? (opts.home ? path.join(home, '.claude', 'projects') : defaultRoot()));

  if (!fs.existsSync(root)) {
    console.error(t('No transcripts folder at {root}. Use --path to point to one.', { root: clean(root, 200) }));
    process.exit(1);
  }

  const loading = opts.json ? null : spinner(p, t('Reading your transcripts locally…'));
  const t0 = Date.now();
  const files = listTranscripts(root);
  const bytes = files.reduce((n, f) => n + fs.statSync(f).size, 0);
  const rules = loadRules();
  const inv = inventory({ home });
  const secretsAnalyzer = createSecretsAnalyzer(rules);
  const stores = listStores({ home, projects: inv.projectDirs });

  for (const s of stores) {
    const text = readTextFile(s.file);

    if (text) secretsAnalyzer.onStoreFile({ ...s, text });
  }

  const [secrets, cost, used] = await runAnalyzers({ root, files, analyzers: [secretsAnalyzer, createCostAnalyzer(), createVersionAnalyzer()] });
  const claudeCode = used && { ...used, advisoriesDate: ADVISORIES_DATE, open: openAdvisories(used.version) };

  loading?.stop();

  return { version: pkg.version, root, files: files.length, storeFiles: stores.length, bytes, ms: Date.now() - t0, rules: rules.meta, pricesDate: PRICES_DATE, secrets, load: { ...inv, projectDirs: inv.projectDirs.map((d) => clean(d, 300)) }, spend: cost, claudeCode };
}

const print = (lines) => console.log(lines.join('\n'));

// `blackbrake audit` from a script or a terminal: one report, then exit.
async function audit(opts, p) {
  const data = await collect(opts, p);

  if (opts.json) {
    console.log(JSON.stringify({ ...data, advice: buildAdvice(data) }, null, 2));

    return;
  }

  const advice = buildAdvice(data);
  print(renderAudit(p, data, { adviceCount: advice.length }));

  if (opts.details) print(renderDetails(p, data, { all: opts.all }));

  if (opts.advice) print(renderAdvice(p, advice, { cols: columns() }));
}

// ---------- guard commands ----------

// Every agent blackbrake can protect, with what is known about it here.
const claudePresent = () => fs.existsSync(process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude'));

// Hook agents (guard runs inside) first, then the harnesses watched from outside.
function agentStatus() {
  const claude = { id: 'claude', name: 'Claude Code', kind: 'hooks', detected: claudePresent(), installed: guardInstalled().installed };
  const hooks = [claude, ...Object.values(AGENTS).map((a) => ({ id: a.id, name: a.name, kind: 'hooks', detected: a.detect(), installed: a.installed() }))];
  const watched = autostartInstalled();
  const off = getSetting('watch', {});

  return [...hooks, ...HARNESSES.filter((h) => h.kind === 'watch').map((h) => ({ id: h.id, name: h.name, kind: 'watch', detected: detected(h), installed: watched && detected(h) && off[h.id] !== false }))];
}

const nameOf = (id) => agentStatus().find((a) => a.id === id)?.name ?? id;

// `--agent codex,cursor` or `--agent all`; with no flag, every hook agent found on this machine.
function agentList(value) {
  const found = agentStatus().filter((a) => a.detected && a.kind === 'hooks').map((a) => a.id);

  if (!value || value === 'all') return found;

  return value.split(',').map((s) => s.trim()).filter((id) => found.includes(id) || AGENTS[id] || id === 'claude');
}

// Installs guard in the given agents, each on its own: one failure does not stop the others.
function installIn(ids, p) {
  const log = (m) => print([`  ${p.amber('✓')} ${t(m)}`]);
  const warn = (m) => print([`  ${p.amber('▲')} ${m}`]);
  const others = ids.filter((id) => id !== 'claude');
  let statusline = null;

  if (ids.includes('claude')) {
    try { statusline = setup({ log }).statusline; } catch (e) { warn(`Claude Code: ${clean(e.message, 300)}`); }
  }

  // Always: the shared copy the hooks and the background watcher run from.
  try {
    const r = setupAgents(others, { log: others.length ? log : () => {} });

    for (const n of r.notes) warn(n);

    for (const f of r.failed) warn(`${f.name}: ${clean(f.error, 300)}`);
  } catch (e) {
    warn(clean(e.message, 300));
  }

  // The background watcher, started now and at every login: blackbrake keeps running for every
  // harness, also the ones without hooks.
  if (getSetting('autostart', true)) {
    try { log(t('Background watcher on, also at login ({file})', { file: installAutostart() })); } catch (e) { warn(clean(e.message, 300)); }
  }

  if (!hasMode()) setMode('observe');

  return statusline;
}

async function setupCommand(opts, p) {
  // In a terminal, the first installation is the permissions checklist: everything on by default,
  // and the user switches off what they do not want. Scripts use --yes (all on) or --agent.
  // Saved, it goes on to the main menu.
  if (!opts.yes && !opts.agent && isInteractive()) return (await permissionsCommand(opts, p, { fresh: true, nextStep: 'menu' })) ? interactive(opts, p) : false;
  const ids = agentList(opts.agent);

  if (!ids.length) {
    print(['', `  ${p.amber('▲')} ${p.cream(t('No coding agents found on this machine.'))}`, `  ${p.faint(t('Supported: {list}.', { list: agentStatus().map((a) => a.name).join(', ') }))}`, '']);

    return false;
  }

  const watched = agentStatus().filter((a) => a.kind === 'watch' && a.detected);
  print([
    '',
    `  ${p.cream(t('blackbrake will protect: {list}', { list: ids.map(nameOf).join(', ') }))}`,
    ...(watched.length ? [`  ${p.cream(t('and watch (no hooks to run inside): {list}', { list: watched.map((a) => a.name).join(', ') }))}`] : []),
    `  ${p.faint(t('Claude Code gets a plugin; the others get blackbrake\'s entries in their own hook config, after a backup in ~/.blackbrake/backups. Nothing else in those files changes.'))}`,
    ...(getSetting('autostart', true) ? [`  ${p.faint(t('A hidden background watcher starts now and at every login (one small login item; "blackbrake background off" removes it).'))}`] : []),
    `  ${p.faint(t('guard starts in observe mode: it warns and logs, and stops nothing until you switch to protect.'))}`,
    `  ${p.faint(t('"blackbrake uninstall" removes it from every agent, or from one with --agent.'))}`,
  ]);

  if (!opts.yes && !(await confirm(p, t('Set up guard now?')))) {
    print(['', `  ${p.faint(t(isInteractive() ? 'Nothing changed.' : 'Nothing changed. Run it in a terminal, or add --yes.'))}`, '']);

    return false;
  }

  const statusline = installIn(ids, p);
  print(['', `  ${p.cream(t('guard is on in'))} ${modeBadge(p, getMode())} ${p.cream(t('mode.'))}`]);

  if (getSetting('window', true)) print([`  ${p.faint(t('When an agent starts, a separate window with live alerts opens ("blackbrake window off" to stop it).'))}`]);

  if (statusline) print([`  ${p.faint(t('Optional status bar (only if you have none yet), in ~/.claude/settings.json:'))}`, `  ${JSON.stringify({ statusLine: { type: 'command', command: `node "${statusline}"` } }).slice(1, -1)}`]);
  print(['']);

  return true;
}

// `blackbrake agents`: every harness found, and how blackbrake covers it.
function agentsLines(p, { all = false } = {}) {
  const out = screen(p, t('AGENTS'), t('where blackbrake runs'), columns(), { pose: 'right', line: t('Inside the agents with hooks; from outside for the rest.') });

  for (const a of agentStatus().filter((x) => all || x.detected || x.installed)) {
    const state = a.installed ? p.green(`● ${t(a.kind === 'hooks' ? 'protected inside (hooks)' : 'watched (history and processes)')}`) : a.detected ? p.coral(`○ ${t('not protected')}`) : p.faint(t('not installed here'));
    out.push(`  ${padEnd(p.cream(a.name), 22)}${state}`);
  }

  return [...out, '', `  ${p.faint(t('Add: blackbrake setup [--agent <id>] · Remove: blackbrake uninstall --agent <id> · Scan: blackbrake scan [--agent <id>]'))}`, ''];
}

// `blackbrake scan`: secrets in each harness's own files.
function scanCommand(opts, p) {
  const ids = opts.agent && opts.agent !== 'all' ? opts.agent.split(',').map((s) => s.trim()) : null;
  const list = detectedHarnesses().filter((h) => !ids || ids.includes(h.id));
  const rules = loadRules();
  const title = t('secrets in the files each AI harness keeps (history, sessions, config)');

  if (!list.length) return print([...screen(p, t('SCAN'), title, columns(), { pose: 'think' }), `  ${p.faint(t('No AI harnesses found on this machine.'))}`, '']);

  // Brakey looks around while each harness is read, with a progress bar.
  const loading = spinner(p, t('Scanning {name}…', { name: list[0].name }));

  const results = list.map((h, i) => {
    loading.update(t('Scanning {name}…', { name: h.name }), [i, list.length]);

    return scanHarness(h, rules);
  });

  loading.stop();
  const realOf = (r) => r.findings.filter((f) => f.classification === CLASSES.real).length;
  const totalReal = results.reduce((n, r) => n + realOf(r), 0);

  if (!ids) remember('scan', { real: totalReal, where: results.filter(realOf).sort((a, b) => realOf(b) - realOf(a)).map((r) => r.name).slice(0, 2).join(', ') });
  // The result in Brakey's words and face, then each harness in its own panel.
  const out = screen(p, t('SCAN'), title, columns(), { pose: totalReal ? 'alert' : 'happy', line: `${t(totalReal ? '{n} look real across your AI harnesses' : 'No real secrets in your AI harnesses', { n: plural(totalReal, 'secret') })} · ${t('{n} harnesses read', { n: list.length })}` });

  const rows = [];

  for (const r of results) {
    const real = r.findings.filter((f) => f.classification === CLASSES.real);
    const head = real.length ? p.coral(`● ${t('{n} look real', { n: plural(real.length, 'secret') })}`) : p.green(`✓ ${t('none look real')}`);
    rows.push(`${padEnd(p.cream(r.name), 22)}${head} ${p.faint(`· ${plural(r.files, 'file')}${r.skipped ? ` · ${t('{n} credential files skipped', { n: r.skipped })}` : ''}${r.truncated ? ` · ${t('stopped at the limit')}` : ''}`)}`);

    for (const f of real.slice(0, 5)) rows.push(`  ${p.coral(padEnd(f.shape, 18))} ${padEnd(f.ruleId, 22)} ${p.faint(`${clean(f.files[0], 40)}${f.fileCount > 1 ? ` ${t('+{n} more', { n: f.fileCount - 1 })}` : ''}`)}`);

    if (real.length > 5) rows.push(`  ${p.faint(t('{n} more', { n: real.length - 5 }))}`);
  }

  out.push(...box(p, t('AI harnesses'), rows, { color: totalReal ? 'coral' : 'orangeDk' }));

  print([...out, '', `  ${p.faint(t('Read-only. Values are never shown. Rotate what looks real and delete the copies.'))}`, '']);

  return results;
}

// ---------- fixing what the audit and the scan found ----------

// The files a clean-up may change: Claude Code's transcripts and stores, or one harness's files.
function filesFor(source, opts) {
  if (source !== 'claude') {
    const h = HARNESSES.find((x) => x.id === source);

    return h ? harnessFiles(h) : [];
  }

  const home = path.resolve(opts.home ?? os.homedir());
  const root = path.resolve(opts.path ?? (opts.home ? path.join(home, '.claude', 'projects') : defaultRoot()));

  return [...(fs.existsSync(root) ? listTranscripts(root) : []), ...listStores({ home, projects: inventory({ home }).projectDirs }).map((s) => s.file)];
}

const FIX_MARK = { auto: '⚙', agent: '✦' };

// Every panel offers "Back to the main menu": choosing it unwinds to the main menu from any depth.
const MAIN = '*main';

class ToMainMenu extends Error {}

async function choose(p, items) {
  const hasMain = items.some((i) => i.label === t('Back to the main menu'));
  const choice = await select(p, hasMain ? items : [...items, { value: MAIN, label: t('Back to the main menu') }]);

  if (choice === MAIN || (hasMain && items.find((i) => i.value === choice)?.label === t('Back to the main menu'))) throw new ToMainMenu();

  return choice;
}

// After a screen that only shows something: the user reads it and goes on when ready. Inside a
// deeper panel, "Back" returns one level and "Back to the main menu" leaves.
const backToMenu = (p, label = null) => (label ? choose(p, [{ value: 'back', label }]) : choose(p, []));

// One fix: here (automatic, local), or with the user's own AI agent. Returns true if something ran.
async function runFix(fix, p, opts) {
  const choices = [
    ...(fix.auto ? [{ value: 'auto', label: t(fix.auto.kind === 'scrub' ? 'Remove the copies here, automatically' : 'Change the setting here, automatically'), hint: t(fix.auto.kind === 'scrub' ? 'no AI, no network · private backup for {n} days, can be undone' : 'no AI, no network · you see the change first, backup kept', { n: KEEP_DAYS }) }] : []),
    { value: 'agent', label: t('Ask my AI agent to fix it'), hint: t('a prompt without any secret value; you approve each change') },
    { value: 'back', label: t('Back') },
  ];

  print(['', ...box(p, fix.title, [p.cream(fix.why), '', ...(fix.steps ?? []).slice(0, 6).map((s) => `${p.orange('›')} ${p.faint(clean(s, 300))}`)], { color: fix.level === 'critical' ? 'coral' : 'orangeDk' }), '']);
  const how = await choose(p, choices);

  if (how === 'auto') return fixHere(fix, p, opts);

  if (how === 'agent') return fixWithAgent([fix], p);

  return false;
}

async function fixHere(fix, p, opts) {
  if (fix.auto.kind === 'settings') {
    const plan = planSettings(fix.auto.ids);

    if (!plan) return print(['', `  ${p.green('✓')} ${t('Already set; nothing to change.')}`, '']), false;
    print(['', `  ${p.faint(clean(plan.file, 200))}`, ...diffLines(plan.before, plan.after).map((l) => `    ${l.startsWith('+') ? p.green(l) : p.coral(l)}`), '']);

    if (!(await confirm(p, t('Apply this change?')))) return false;
    applySettings(plan);
    print(['']);
    await report(p, 'good', t('Done.'), t('A copy of the previous file is in ~/.blackbrake/backups.'));

    return true;
  }

  // Clean-up: it changes files that belong to other programs, so a word is typed.
  if (!(await confirmTyped(p, t('Replace every copy of these keys with their masked shape? The originals are kept privately for {n} days.', { n: KEEP_DAYS }), 'remove', getLang() === 'es' ? 'quitar' : null))) return print(['', `  ${p.faint(t('Nothing changed.'))}`, '']), false;
  const loading = spinner(p, t('Removing the copies…'));
  const r = scrub({ files: filesFor(fix.auto.source, opts), keys: new Set(fix.auto.keys), rules: loadRules() });
  loading.stop();
  print(['']);
  await report(p, r.changed.length ? 'good' : 'neutral', r.changed.length ? t('Removed {n} from {files}.', { n: plural(r.replaced, 'copy', 'copies'), files: plural(r.changed.length, 'file') }) : t('No copies found to remove.'));
  const lines = [];

  if (r.busy.length) lines.push(`  ${p.amber('!')} ${t('{n} were being written by a running agent and were left as they were; close it and run this again.', { n: plural(r.busy.length, 'file') })}`);

  if (r.failed.length) lines.push(`  ${p.amber('!')} ${t('{n} could not be changed.', { n: plural(r.failed.length, 'file') })}`);

  if (r.changed.length) lines.push(`  ${p.faint(t('Undo within {n} days: blackbrake fix --undo', { n: KEEP_DAYS }))}`, `  ${p.faint(t('Removing the copies does not make a key safe: rotate it too.'))}`);
  print([...lines, '']);

  return r.changed.length > 0;
}

// The prompt is saved first; the agent opens only with the user's permission, else the file stays.
async function fixWithAgent(fixes, p) {
  const text = buildPrompt(fixes);
  const file = savePrompt(text);
  const agents = availableAgents();
  const shown = clean(file, 200);

  if (!agents.length) return print(['', `  ${t('No AI agent (Claude Code, Codex, Gemini CLI) was found on this machine.')}`, `  ${t('The prompt is saved in:')} ${p.cream(shown)}`, '']), false;
  print(['', `  ${t('The prompt is ready (no secret values; it names only rule types, masked shapes and paths):')}`, `  ${p.cream(shown)}`, '']);
  const agent = agents.length === 1 ? agents[0].id : await choose(p, [...agents.map((a) => ({ value: a.id, label: a.name })), { value: null, label: t('None') }]);
  const chosen = agents.find((a) => a.id === agent);

  if (!chosen || !(await confirm(p, t("Open {name} with this prompt? It will ask you before each change. The prompt (paths, rule types, masked shapes) goes to {name}'s provider, like anything you type there.", { name: chosen.name })))) {
    print(['', `  ${t('Not opened. The prompt is saved in:')} ${p.cream(shown)}`, `  ${p.faint(t('Give it to any agent when you want: "Read and follow the instructions in that file".'))}`, '']);

    return false;
  }

  // The file must still say what was written (nothing swapped it while you were deciding).
  if (!promptUnchanged(file, promptHash(text))) return print(['', `  ${p.coral(t('The prompt file changed after it was written; not opening the agent.'))} ${p.cream(shown)}`, '']), false;
  const r = await launchAgent(chosen, agentInstruction(file));

  if (!r.ok && r.error) print(['', `  ${p.coral(clean(r.error, 300))}`, `  ${t('The prompt is saved in:')} ${p.cream(shown)}`, '']);

  return r.ok;
}

async function fixMenu(fixes, p, opts, { fromMain = false } = {}) {
  for (;;) {
    const open = fixes.filter((f) => !f.done);

    await transition(p);

    if (!open.length) {
      print(['', say(p, 'happy', t('Nothing left to fix from this list.')), '']);
      await backToMenu(p, t('Back'));

      return;
    }

    print([...screen(p, t('FIX'), t('{n} to fix · ⚙ here, automatically · ✦ with your AI agent', { n: open.length }), columns(), { pose: 'determined', line: t('Pick one: I fix it here, or I write a prompt for your agent.') })]);

    const items = [
      ...open.map((f) => ({ value: f.id, label: `${f.auto ? FIX_MARK.auto : ' '} ${FIX_MARK.agent}  ${f.title}`, hint: t(f.level) })),
      ...(open.length > 1 ? [{ value: '*agent', label: t('Ask my AI agent to fix all of them'), hint: t('one prompt with every problem') }] : []),
      // Opened straight from the main menu, going back is going to the main menu.
      ...(fromMain ? [] : [{ value: 'back', label: t('Back') }]),
    ];

    const choice = await choose(p, items);

    if (!choice || choice === 'back') return;

    await transition(p);

    if (choice === '*agent') {
      await fixWithAgent(open, p);
      await backToMenu(p, t('Back'));
      continue;
    }

    const fix = open.find((f) => f.id === choice);

    if (await runFix(fix, p, opts)) fix.done = true;
    await backToMenu(p, t('Back'));
  }
}

// `blackbrake fix`: audit + scan, then the fix menu. `--undo`: put back the files of a clean-up.
async function fixCommand(opts, p) {
  if (!isInteractive()) {
    print(['', `  ${t('Fixing needs an interactive terminal: run "blackbrake fix" yourself.')}`, '']);
    process.exitCode = 1;

    return;
  }

  if (opts.undo) {
    const list = listScrubs();

    if (!list.length) return print(['', `  ${p.faint(t('No clean-up to undo (backups last {n} days).', { n: KEEP_DAYS }))}`, '']);
    const id = await select(p, [...list.map((s) => ({ value: s.id, label: `${s.created.slice(0, 16).replace('T', ' ')} · ${plural(s.files, 'file')}` })), { value: null, label: t('Back') }]);

    if (!id || !(await confirmTyped(p, t('Put the original files back? The keys return to them.'), 'undo', getLang() === 'es' ? 'deshacer' : null))) return;
    const u = undoScrub(id);
    print(['', `  ${p.green('✓')} ${t('Restored {n}.', { n: plural(u.restored, 'file') })}`, ...(u.changed.length ? [`  ${p.amber('!')} ${t('{n} changed after the clean-up and were not overwritten; their originals stay in the backup until it expires.', { n: plural(u.changed.length, 'file') })}`] : []), '']);

    return;
  }

  const data = await collect(opts, p);
  const fixes = [...fixesFromAudit(buildAdvice(data), data), ...fixesFromScan(detectedHarnesses().map((h) => scanHarness(h, loadRules())))];

  try {
    await fixMenu(fixes, p, opts, { fromMain: opts.fromMain });
  } catch (e) {
    // From the command line, the main menu is opened; from the menu, it goes back there.
    if (!(e instanceof ToMainMenu) || opts.fromMain) throw e;
    await interactive(opts, p);
  }
}

// `blackbrake background [on|off]`: the hidden watcher started at login.
async function backgroundCommand(opts, p) {
  const wanted = opts.rest[0];

  if (wanted && !['on', 'off'].includes(wanted)) throw new Error(t('Use "blackbrake background on" or "blackbrake background off".'));

  if (wanted === 'on') {
    setSetting('autostart', true);
    buildRuntime();
    installAutostart();
  } else if (wanted === 'off') {
    // Switching the watcher off lowers protection: a person has to confirm it in a terminal.
    if (!(await confirmTyped(p, t('Stop the background watcher? Harnesses without hooks will no longer be watched.'), 'off', getLang() === 'es' ? 'apagar' : null))) {
      print(['', `  ${p.faint(t(isInteractive() ? 'Nothing changed.' : 'Nothing changed: this must be confirmed in an interactive terminal.'))}`, '']);
      process.exitCode = isInteractive() ? 0 : 1;

      return;
    }

    setSetting('autostart', false);
    removeAutostart();
  }

  const on = autostartInstalled();
  print(['', `  ${p.faint(t('Background watcher'))} ${on ? p.green(`● ${t('enabled')}`) : p.coral(`○ ${t('disabled')}`)} ${p.faint(isBackgroundRunning() ? t('(running now)') : '')}`, '']);
}

// Whether a live session is going on: agents with recent activity, or a harness process running.
function liveState() {
  const agents = runningAgents(readLog());

  return { active: agents.length > 0, agents };
}

// The help screen: the main commands, how to use them and what for.
function helpScreen(p) {
  const row = (cmd, text) => `${padEnd(p.orange(cmd), 34)}${p.cream(t(text))}`;

  return [
    ...screen(p, t('HELP'), t('main commands'), columns(), { pose: 'wink', line: t('Everything in the menu also works as a command.') }),
    ...box(p, t('Commands'), [
    row('blackbrake', 'this menu'),
    row('blackbrake setup', 'protect every AI agent found (one confirmation)'),
    row('blackbrake watch', 'live alerts from running agents, low to maximum'),
    row('blackbrake agents', 'which harnesses are protected or watched'),
    row('blackbrake scan [--agent id]', 'look for secrets in each harness\'s files'),
    row('blackbrake audit', 'full report for Claude Code: secrets, add-ons, spend'),
    row('blackbrake fix [--undo]', 'fix what the audit and the scan found: here, or with your AI agent'),
    row('blackbrake mode protect|observe', 'stop risky steps, or only warn'),
    row('blackbrake status · log', 'mode, code check and recent events'),
    row('blackbrake window on|off', 'alerts window when an agent starts'),
    row('blackbrake background on|off', 'hidden watcher at login'),
    row('blackbrake uninstall [--agent id]', 'remove it from every agent, or one'),
    row('blackbrake lang es|en|auto', 'language'),
    ]),
    '',
    `  ${p.faint(t('Lowering protection and removing blackbrake need you to type a word in a terminal: an agent cannot do it.'))}`,
    `  ${p.faint(t('Everything stays on this machine. blackbrake --help lists every option.'))}`,
    ...(viaNpx() ? [`  ${p.amber(t('Open it from any folder with just "blackbrake": install it once with npm install -g blackbrake'))}`] : []),
    '',
  ];
}

// Run through npx (npm sets npm_command=exec; the package sits in npm's _npx cache): each start
// downloads or checks the package again. Installed globally it opens with just "blackbrake".
function viaNpx() {
  return process.env.npm_command === 'exec' || /[\\/]_npx[\\/]/.test(fileURLToPath(import.meta.url));
}

// ---------- permissions: which harnesses, which mode, what blackbrake may do ----------

const HOOK_PERMISSION = {
  claude: 'installs a plugin with "claude plugin install"',
  codex: 'adds its entries to Codex\'s hooks.json (backup first); Codex asks you to trust them once in /hooks',
};

// The checklist: every harness found, then how blackbrake runs. `fresh` = first installation, all on.
function permissionItems({ fresh = false } = {}) {
  const status = agentStatus().filter((a) => a.detected || a.installed);
  const watchOn = getSetting('watch', {});
  const hookFile = (id) => AGENTS[id]?.configFile?.();
  const items = [{ heading: true, label: t('AI harnesses with hooks: guard runs inside them') }];

  for (const a of status.filter((x) => x.kind === 'hooks')) items.push({ value: `h:${a.id}`, label: a.name, on: fresh || a.installed, hint: t(HOOK_PERMISSION[a.id] ?? 'adds its entries to {file} (backup first)', { file: hookFile(a.id) ?? '' }) });

  const watched = status.filter((x) => x.kind === 'watch');

  if (watched.length) {
    items.push({ heading: true, label: t('AI harnesses without hooks: watched from outside') });

    for (const a of watched) items.push({ value: `w:${a.id}`, label: a.name, on: watchOn[a.id] !== false, hint: t('reads its history as it grows and notices when it runs') });
  }

  items.push(
    { heading: true, label: t('How blackbrake runs') },
    { value: 'observe', label: t('Observe mode (recommended to start)'), on: fresh || getMode() === 'observe', hint: t('warns only; off = protect: stops risky steps') },
    { value: 'background', label: t('Background watcher at login'), on: fresh ? getSetting('autostart', true) : autostartInstalled(), hint: t('a login item that starts it hidden: {file}', { file: autostartFile() }) },
    { value: 'window', label: t('Alerts window when an agent starts'), on: getSetting('window', true), hint: t('opens a terminal window with the live alerts') },
    { value: 'notify', label: t('System notifications'), on: getSetting('notify', true), hint: t('for high and maximum alerts') },
    { value: 'sound', label: t('Sound'), on: getSetting('sound', true), hint: t('the terminal bell on high and maximum alerts') },
  );

  return items;
}

// Applies a checklist result. Anything that lowers protection needs the typed confirmation.
async function applyPermissions(choice, p) {
  const status = agentStatus();
  const on = (key) => choice[key] === true;
  const hookIds = status.filter((a) => a.kind === 'hooks' && (a.detected || a.installed)).map((a) => a.id);
  const add = hookIds.filter((id) => on(`h:${id}`) && !status.find((a) => a.id === id).installed);
  const remove = hookIds.filter((id) => choice[`h:${id}`] === false && status.find((a) => a.id === id).installed);
  const watchMap = Object.fromEntries(status.filter((a) => a.kind === 'watch' && `w:${a.id}` in choice).map((a) => [a.id, on(`w:${a.id}`)]));
  const lowerMode = 'observe' in choice && on('observe') && getMode() === 'protect';
  const stopBackground = choice.background === false && autostartInstalled();
  const unwatch = Object.entries(watchMap).some(([id, v]) => !v && getSetting('watch', {})[id] !== false);
  // Turning off what lets the user see alerts (the window, notifications, the bell) also counts:
  // an agent that silenced them could act unseen.
  const quieter = ['window', 'notify', 'sound'].filter((k) => choice[k] === false && getSetting(k, true));

  if (remove.length || lowerMode || stopBackground || unwatch || quieter.length) {
    const what = [...remove.map(nameOf), ...(lowerMode ? [t('observe mode')] : []), ...(stopBackground ? [t('no background watcher')] : []), ...(unwatch ? [t('fewer watched harnesses')] : []), ...(quieter.length ? [t('fewer alerts shown')] : [])];

    if (!(await confirmTyped(p, t('This lowers protection ({list}). Apply it?', { list: what.join(', ') }), 'confirm', getLang() === 'es' ? 'confirmar' : null))) {
      print(['', `  ${p.faint(t(isInteractive() ? 'Nothing changed.' : 'Nothing changed: this must be confirmed in an interactive terminal.'))}`, '']);

      return false;
    }
  }

  setSetting('watch', { ...getSetting('watch', {}), ...watchMap });

  // A key missing from the choice leaves that setting as it was.
  for (const k of ['window', 'notify', 'sound']) if (k in choice) setSetting(k, on(k));

  if ('background' in choice) setSetting('autostart', on('background'));

  if ('observe' in choice && (!hasMode() || on('observe') !== (getMode() === 'observe'))) setMode(on('observe') ? 'observe' : 'protect');

  const log = (m) => print([`  ${p.amber('✓')} ${t(m)}`]);

  if (remove.length) {
    uninstallAgents(remove.filter((id) => id !== 'claude'), { log });

    if (remove.includes('claude')) uninstall({ keepLog: true, log });
  }

  // installIn also builds the shared copy and, when chosen, the background watcher.
  if (add.length || (on('background') && !autostartInstalled())) installIn(add, p);

  if (stopBackground && removeAutostart()) log(t('Stopped the background watcher and removed its login item'));
  print(['', `  ${p.cream(t('guard is on in'))} ${modeBadge(p, getMode())} ${p.cream(t('mode.'))}`, '']);

  return true;
}

// Where the "continue" button at the top of the checklist leads.
const PROCEED = {
  menu: 'Continue: save and open the main menu',
  next: 'Continue: save and go on',
  back: 'Continue: save and return to the main menu',
};

async function permissionsCommand(opts, p, { fresh = false, nextStep = 'back' } = {}) {
  print(screen(p, t('PERMISSIONS'), t('where blackbrake runs and what it may do'), columns(), { pose: 'determined', line: t('You decide where I run. Lowering protection asks you to type a word.') }));

  // The first time, say plainly that everything starts switched on.
  if (fresh) print([`  ${p.amber('●')} ${p.cream(t('Everything is on by default: guard protects every AI tool found.'))}`, `    ${p.faint(t('Untick (space) what you do not want, then continue.'))}`, '']);
  const choice = await checklist(p, permissionItems({ fresh }), { proceed: { label: t(PROCEED[nextStep]), hint: t('or press enter anywhere') } });

  if (!choice) {
    print(['', `  ${p.faint(t(isInteractive() ? 'Nothing changed.' : 'Nothing changed. Run it in a terminal, or add --yes.'))}`, '']);

    return false;
  }

  return applyPermissions(choice, p);
}

// The home screen's agents panel: pick an agent to add or remove blackbrake.
async function manageAgents(opts, p) {
  for (;;) {
    const list = agentStatus().filter((a) => a.detected || a.installed);
    const missing = list.filter((a) => a.kind === 'hooks' && a.detected && !a.installed);

    const items = [
      ...list.map((a) => ({ value: a.id, label: `${a.installed ? '●' : '○'} ${a.name}`, hint: a.installed ? t(a.kind === 'hooks' ? 'protected inside (hooks)' : 'watched (history and processes)') : t('not protected') })),
      ...(missing.length ? [{ value: '*add', label: t('Protect every agent found ({n})', { n: missing.length }) }] : []),
      { value: '*scan', label: t('Scan every harness for secrets') },
      { value: '*back', label: t('Back to the main menu') },
    ];

    await transition(p);
    print(agentsLines(p).slice(0, 3));
    const pick = await select(p, items);

    if (!pick || pick === '*back') return;

    await transition(p);

    if (pick === '*add') {
      installIn(missing.map((a) => a.id), p);
      await backToMenu(p, t('Back'));
      continue;
    }

    if (pick === '*scan') {
      scanCommand(opts, p);
      await backToMenu(p, t('Back'));
      continue;
    }

    // One harness: scan it, or add / remove blackbrake (hook agents; the watched ones follow the
    // background watcher).
    const a = list.find((x) => x.id === pick);

    const action = await choose(p, [
      { value: 'scan', label: t('Scan {name} for secrets', { name: a.name }) },
      ...(a.kind === 'hooks' ? [{ value: 'toggle', label: t(a.installed ? 'Remove blackbrake from {name}' : 'Protect {name}', { name: a.name }) }] : [{ value: 'bg', label: t(a.installed ? 'Watched by the background watcher' : 'Turn on the background watcher'), disabled: a.installed }]),
      { value: 'back', label: t('Back') },
    ]);

    if (action === 'scan') scanCommand({ ...opts, agent: a.id }, p);
    else if (action === 'toggle' && a.installed) await uninstallCommand({ ...opts, agent: a.id }, p);
    else if (action === 'toggle') installIn([a.id], p);
    else if (action === 'bg') await backgroundCommand({ ...opts, rest: ['on'] }, p);

    if (action && action !== 'back') await backToMenu(p, t('Back'));
  }
}

// `blackbrake window [on|off]`: the separate alerts window when an agent starts.
async function windowCommand(opts, p) {
  const wanted = opts.rest[0];

  if (wanted && !['on', 'off'].includes(wanted)) throw new Error(t('Use "blackbrake window on" or "blackbrake window off".'));

  // Hiding alerts lowers protection like the rest: a person confirms it in a terminal.
  if (wanted === 'off' && getSetting('window', true) && !(await confirmTyped(p, t('Stop opening the alerts window? Alerts will only show if you open them.'), 'off', getLang() === 'es' ? 'apagar' : null))) {
    print(['', `  ${p.faint(t(isInteractive() ? 'Nothing changed.' : 'Nothing changed: this must be confirmed in an interactive terminal.'))}`, '']);
    process.exitCode = isInteractive() ? 0 : 1;

    return;
  }

  if (wanted) setSetting('window', wanted === 'on');
  print(['', `  ${p.faint(t('Alerts window when an agent starts'))} ${p.cream(t(getSetting('window', true) ? 'on' : 'off'))}`, '']);
}

async function modeCommand(opts, p) {
  const current = getMode();
  const wanted = opts.rest[0];

  if (!wanted) {
    print(['', `  ${p.faint(t('guard mode'))} ${modeBadge(p, current)}`, `  ${p.faint(t('Change it with "blackbrake mode protect" or "blackbrake mode observe".'))}`, '']);

    return;
  }

  if (!MODES.includes(wanted)) throw new Error(t('Unknown mode "{m}". Use observe or protect.', { m: wanted }));

  if (wanted === current) {
    print(['', `  ${p.faint(t('Already in'))} ${modeBadge(p, current)}`, '']);

    return;
  }

  // Lowering protection needs a person at a terminal: the agent's shell has none.
  if (wanted === 'observe' && !(await confirmTyped(p, t('Switch guard to observe? Secrets will be reported but no longer stopped.'), 'observe', getLang() === 'es' ? 'observar' : null))) {
    print(['', `  ${p.faint(t(isInteractive() ? 'Mode unchanged.' : 'Mode unchanged: switching to observe must be confirmed in an interactive terminal.'))}`, '']);
    process.exitCode = isInteractive() ? 0 : 1;

    return;
  }

  setMode(wanted);
  print(['', `  ${p.amber('✓')} ${t('guard is now in')} ${modeBadge(p, wanted)} ${p.faint(t(wanted === 'protect' ? 'secrets are stopped before they are sent' : 'warns and logs; nothing is stopped'))}`, '']);
}

async function uninstallCommand(opts, p) {
  // Without --agent: every agent that has it.
  const ids = opts.agent && opts.agent !== 'all' ? agentList(opts.agent) : agentStatus().filter((a) => a.installed).map((a) => a.id);

  const question = opts.purge ? t('Remove guard and delete its log?') : t('Remove blackbrake from {list}?', { list: ids.map(nameOf).join(', ') || t('every agent') });

  if (!(await confirmTyped(p, question, 'remove', getLang() === 'es' ? 'quitar' : null))) {
    print(['', `  ${p.faint(t(isInteractive() ? 'Nothing changed.' : 'Nothing changed: removing guard must be confirmed in an interactive terminal.'))}`, '']);
    process.exitCode = isInteractive() ? 0 : 1;

    return;
  }

  const log = (m) => print([`  ${p.amber('✓')} ${t(m)}`]);

  // --purge deletes ~/.blackbrake, which other agents' hooks run from: all of them must go, checked
  // before anything is removed.
  if (opts.purge && Object.values(AGENTS).some((a) => { if (ids.includes(a.id) || !fs.existsSync(a.configFile())) return false;

 try { return a.installed(true); } catch { return true; } })) throw new Error(t('Other agents still use guard; remove them too (--agent all) before --purge.'));

  // Removing it from everything also stops the background watcher and its login item.
  if ((!opts.agent || opts.agent === 'all') && removeAutostart()) log(t('Stopped the background watcher and removed its login item'));
  uninstallAgents(ids.filter((id) => id !== 'claude'), { log });

  if (ids.includes('claude')) uninstall({ keepLog: !opts.purge, log });
}

async function claudeCommand(opts, p) {
  if (!guardInstalled().installed) {
    print(['', `  ${p.amber('▲')} ${p.cream(t('guard is not set up in Claude Code yet.'))}`]);

    if (!(await setupCommand(opts, p))) return;
  }

  print(['', `  ${p.faint(t('Starting Claude Code with guard in'))} ${modeBadge(p, getMode())}`, '']);
  const r = await launchClaude(opts.rest);

  if (r.error) {
    console.error(`  ${r.error}`);
    process.exitCode = 1;
  }
}

// `blackbrake lang [en|es|auto]`: saved in ~/.blackbrake/state.json, used by the CLI and by guard.
function langCommand(opts, p) {
  const wanted = opts.rest[0];

  if (wanted) {
    if (![...LANGS, 'auto'].includes(wanted)) throw new Error(t('Unknown language "{l}". Use en, es or auto.', { l: wanted }));
    setSavedLang(wanted === 'auto' ? null : wanted);
    setLang(detectLang({ saved: wanted === 'auto' ? null : wanted }));
  }

  const saved = getSavedLang();
  print(['', `  ${p.faint(t('Language'))} ${p.cream(getLang() === 'es' ? 'español' : 'English')} ${p.faint(saved ? t('(chosen with "blackbrake lang")') : t('(from your system; "blackbrake lang es" or "en" to choose)'))}`, '']);
}

function readStdinJson() {
  try {
    const buf = fs.readFileSync(0);

    return buf.length > 1024 * 1024 ? {} : JSON.parse(buf.toString('utf8') || '{}');
  } catch { return {}; }
}

// What the last scan and audit found, for Brakey's tip: counts and a harness name only, never a value.
const remember = (kind, data) => setSetting(`last_${kind}`, { at: new Date().toISOString(), ...data });

// Brakey's one-line tip on the main menu: the most useful next step right now.
function tip(p, state) {
  const days = (at) => (at ? Math.floor((Date.now() - Date.parse(at)) / 864e5) : null);
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Validate untrusted JSON or assert the boundary contract; preserve primitive type checks.
  const safe = (v) => (v && typeof v === 'object' ? { at: typeof v.at === 'string' ? v.at : null, real: Math.max(0, Number.parseInt(v.real, 10) || 0), where: clean(String(v.where ?? ''), 60) } : null);
  const scan = safe(getSetting('last_scan', null));
  const auditRun = safe(getSetting('last_audit', null));
  const maximum = readLog(undefined, { since: new Date(Date.now() - 864e5).toISOString() }).filter((e) => severity(e) === 'critical').length;

  if (!state.installed) return say(p, 'worried', t('I am not protecting any agent yet. Open "Protection and permissions".'));

  if (maximum) return say(p, 'alert', t('{n} maximum alert(s) in the last 24 h. See them in "Live session".', { n: maximum }));

  if (scan?.real) return say(p, 'alert', t('{n} real secret(s) in {where} at the last scan. Rotate them, then delete the copies.', { n: scan.real, where: scan.where }));

  if (auditRun?.real) return say(p, 'alert', t('{n} real secret(s) in Claude Code at the last audit. See the precautions in "Audit".', { n: auditRun.real }));

  if (viaNpx()) return say(p, 'wink', t('Open me from any folder with just "blackbrake": npm install -g blackbrake'));

  if (!scan) return say(p, 'idle', t('Scan your AI harnesses once, from "Audit": it takes a few seconds.'));

  if (days(scan.at) >= 7) return say(p, 'idle', t('I have not scanned your AI harnesses for {n} days.', { n: days(scan.at) }));

  return state.mode === 'observe' ? say(p, 'happy', t('All in order. When you trust me, switch to protect mode.')) : say(p, 'happy', t('All in order. I am watching.'));
}

// First run: Brakey introduces itself, sets up protection with the permissions checklist, and offers
// a first scan. Shown once; an existing installation skips it.
async function welcome(opts, p) {
  setSetting('welcomed', true);

  if (hasMode()) return;
  print(screen(p, t('WELCOME'), t('first steps'), columns(), { pose: 'wave', line: t('Nice to meet you.') }));
  await play((pose) => withLogo(p, [p.cream(t('Hi, I am {name}, the black box of your AI agents.', { name: MASCOT })), p.faint(t('I see what your agents send and read, and I warn you, or stop them, before a secret leaves.')), p.faint(t('Everything stays on this machine.'))], pose), HELLO);
  print(['']);
  const go = await select(p, [{ value: 'setup', label: t('Set up protection now'), hint: t('recommended · you choose each harness') }, { value: 'later', label: t('Look around first') }]);

  if (go !== 'setup' || !(await permissionsCommand(opts, p, { fresh: true, nextStep: 'next' }))) return;
  const next = await select(p, [{ value: 'scan', label: t('Scan my AI harnesses now'), hint: t('secrets already sitting in their history') }, { value: 'later', label: t('Later') }]);

  if (next === 'scan') scanCommand(opts, p);
}

// Home screen loop: guard, audit, then precautions or details, then back to the menu.
async function interactive(opts, p) {
  let again = false;

  if (!getSetting('welcomed', false)) await welcome(opts, p);

  for (;;) {
    try {
      const agents = agentStatus();

      const state = {
        installed: agents.some((a) => a.installed),
        claude: agents[0].installed,
        mode: getMode(),
        protectedCount: agents.filter((a) => a.installed).length,
        detectedCount: agents.filter((a) => a.detected || a.installed).length,
        running: liveState().agents.length,
        live: liveState().active,
        background: isBackgroundRunning(),
        window: getSetting('window', true),
        animations: getSetting('animations', true),
        isAccessible: getSetting('accessible', false),
        light: getSetting('theme', 'dark') === 'light',
      };

      const group = await home(p, pkg.version, {}, again, homeItems(state, p), tip(p, state));
      again = true;

      if (!group) {
        await transition(p);
        await goodbyeScene(p, [p.cream(t('See you soon.')), p.faint(t(isBackgroundRunning() ? 'blackbrake keeps watching in the background.' : 'Run "blackbrake" whenever you want to check on your agents.')), '']);
        print(['']);

        return;
      }

      // The group's screen; "back" returns to the main menu.
      const action = await category(p, group, state);

      if (!action) continue;

      // What the user opens now is all the terminal shows.
      await transition(p);

      if (action === 'privacy') {
        print(privacyScreen(p));
        await backToMenu(p);
        continue;
      }

      // Display settings: saved, and applied from the next screen on.
      if (action === 'animations' || action === 'accessible' || action === 'theme') {
        if (action === 'animations') {
          setSetting('animations', !state.animations);
          process.env.BLACKBRAKE_NO_ANIMATION = state.animations ? '1' : '';
        } else if (action === 'accessible') {
          setSetting('accessible', !state.isAccessible);
          process.env.ACCESSIBLE = state.isAccessible ? '' : '1';
        } else {
          setSetting('theme', state.light ? 'dark' : 'light');
          process.env.BLACKBRAKE_THEME = state.light ? 'dark' : 'light';
          Object.assign(p, createPainter(p.level));
        }

        continue;
      }

      if (action === 'claude') {
        await claudeCommand(opts, p);

        return;
      }

      // Live alerts in this terminal; q or Esc comes back here.
      if (action === 'watch') {
        await watch(p, { keys: true, backHint: t('q or Esc: back to the main menu') });
        continue;
      }

      if (action === 'permissions') {
        await permissionsCommand(opts, p);
        await backToMenu(p);
        continue;
      }

      if (action === 'fix') {
        await fixCommand({ ...opts, fromMain: true }, p);
        continue;
      }

      if (action === 'help') {
        print(helpScreen(p));
        await backToMenu(p);
        continue;
      }

      if (action === 'scan') {
        const results = scanCommand(opts, p) ?? [];
        const fixes = fixesFromScan(results);

        if (!fixes.length) await backToMenu(p);
        else if ((await choose(p, [{ value: 'fix', label: t('Fix what was found ({n})', { n: fixes.length }), hint: t('here, automatically, or with your AI agent') }])) === 'fix') await fixMenu(fixes, p, opts, { fromMain: true });

        continue;
      }

      if (action === 'agents') {
        await manageAgents(opts, p);
        continue;
      }

      if (action === 'window') {
        await windowCommand({ ...opts, rest: [state.window ? 'off' : 'on'] }, p);
        await backToMenu(p);
        continue;
      }

      if (action === 'mode') {
        await modeCommand({ ...opts, rest: [state.mode === 'protect' ? 'observe' : 'protect'] }, p);
        await backToMenu(p);
        continue;
      }

      if (action === 'lang') {
        langCommand({ ...opts, rest: [getLang() === 'es' ? 'en' : 'es'] }, p);
        await backToMenu(p);
        continue;
      }

      if (action === 'guard') {
        if (state.installed) print([...statusLines(p), ...logLines(p)]);
        else await setupCommand(opts, p);
        await backToMenu(p);
        continue;
      }

      if (action !== 'audit') return;
      const data = await collect(opts, p);
      remember('audit', { real: data.secrets.filter((f) => f.classification === CLASSES.real).length });
      const advice = buildAdvice(data);
      const fixes = fixesFromAudit(advice, data);
      print(renderAudit(p, data, { adviceCount: advice.length, interactive: true }));

      for (;;) {
        const next = await select(p, afterAuditItems(advice.length, fixes.filter((f) => !f.done).length));

        if (next === 'advice' || next === 'details') await transition(p);

        if (next === 'fix') await fixMenu(fixes, p, opts);
        else if (next === 'advice') print(renderAdvice(p, advice, { cols: columns() }));
        else if (next === 'details') print(renderDetails(p, data));
        else if (next === 'back') break;
        else return;
      }
    } catch (e) {
      if (!(e instanceof ToMainMenu)) throw e;
    }
  }
}

const help = () => (getLang() === 'es' ? HELP_ES : HELP);

async function main() {
  let opts;

  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (e) {
    console.error(e.message);
    console.error(help());
    process.exit(2);
  }

  // --json is for scripts: always English. Otherwise --lang, then the saved choice, then the system.
  setLang(opts.json ? 'en' : LANGS.includes(opts.lang) ? opts.lang : detectLang({ saved: getSavedLang() }));

  // Display choices from Help and settings, applied before anything is drawn.
  if (getSetting('accessible', false)) process.env.ACCESSIBLE = '1';

  if (!getSetting('animations', true)) process.env.BLACKBRAKE_NO_ANIMATION = '1';

  if (getSetting('theme', 'dark') === 'light') process.env.BLACKBRAKE_THEME = 'light';
  const p = createPainter();

  // Clean-up backups hold the secrets that were removed: gone after their days are up.
  try { pruneScrubs(); prunePrompts(); } catch { /* nothing to prune */ }

  if (opts.version) {
    console.log(pkg.version);

    return;
  }

  if (opts.help) {
    console.log(help());

    return;
  }

  if (!opts.command) {
    // Interactive terminal: home screen. Pipes and scripts get the help text instead.
    if (!process.stdin.isTTY || !process.stdout.isTTY) {
      console.log(help());

      return;
    }

    await interactive(opts, p);

    return;
  }

  const commands = {
    audit: () => audit(opts, p),
    setup: () => setupCommand(opts, p),
    uninstall: () => uninstallCommand(opts, p),
    mode: () => modeCommand(opts, p),
    lang: () => langCommand(opts, p),
    agents: () => print(agentsLines(p, { all: opts.all })),
    watch: () => watch(p, { keys: true }),
    window: () => windowCommand(opts, p),
    fix: () => fixCommand(opts, p),
    scan: () => scanCommand(opts, p),
    background: () => backgroundCommand(opts, p),
    help: () => print(helpScreen(p)),
    permissions: () => permissionsCommand(opts, p),
    claude: () => claudeCommand(opts, p),
    status: () => print(statusLines(p, { days: opts.days })),
    log: () => print(logLines(p, { days: opts.days })),
    statusline: () => console.log(statusLineText(createPainter(3), readStdinJson())),
  };

  if (!commands[opts.command]) {
    console.error(`${t('Unknown command: {c}', { c: clean(opts.command, 80) })}\n\n${help()}`);
    process.exit(2);
  }

  await commands[opts.command]();
}

main().catch((e) => {
  // Errors can carry paths and file names from disk: cleaned before they reach the terminal.
  console.error(clean(process.env.BLACKBRAKE_DEBUG ? (e.stack ?? e.message) : e.message, 2000));
  process.exit(1);
});

// Home screen: what `blackbrake` shows when run with no command in an interactive terminal.
import { menuItems } from '../cli/registry.mjs';
import { getLang, t } from '../i18n.mjs';
import { select } from './menu.mjs';
import { transition } from './motion.mjs';
import { accessible, box, columns, HELLO, LOGO_WIDTH, motionAllowed, play, screen, withLogo, wordmark, WORDMARK_WIDTH } from './term.mjs';

// The big name beside the logo when the terminal is wide enough; the small one otherwise.
export function homeHeader(p, version, cols = columns(), pose = 'idle', glint = null) {
  if (accessible() || cols < LOGO_WIDTH + WORDMARK_WIDTH + 5) {
    return ['', ...withLogo(p, [`${p.bold(p.cream('blackbrake'))}${p.faint(`  v${version}`)}`, p.cream(t('The black box and the brakes for your AI agents.')), p.faint(t('Local · 0 network connections · you stay in control')), ''], pose), ''];
  }

  return [
    '',
    ...withLogo(p, [...wordmark(p, { glint }), `${p.cream(t('The black box and the brakes for your AI agents.'))}${p.faint(`  v${version}`)}`, p.faint(t('Local · 0 network connections · you stay in control'))], pose),
    '',
  ];
}

// While the main menu waits, the name catches the light now and then (a shine runs across the
// letters every few seconds) and Brakey blinks. The header is redrawn in place at the top of the
// screen (cursor saved and restored), only when the whole screen fits, so nothing else moves.
export function headerLife(p, version, { out = process.stdout, motion = motionAllowed(out), lines = 20 } = {}) {
  if (!motion || !out.isTTY || (out.rows ?? 0) < lines + 2) return () => {};

  const cols = columns();
  let tick = 0;

  const draw = (pose, glint) => {
    const rows = homeHeader(p, version, cols, pose, glint);
    out.write(`\x1b7\x1b[H${rows.map((r) => `\x1b[2K${r}`).join('\n')}\x1b8`);
  };

  // One cycle: 70 ticks of 60 ms (4.2 s); the shine crosses in the first 22, a blink near the end.
  const timer = setInterval(() => {
    tick = (tick + 1) % 70;

    if (tick < 22) draw('idle', -6 + tick * 3.4);
    else if (tick === 22) draw('idle', null);
    else if (tick === 58) draw('blink', null);
    else if (tick === 60) draw('idle', null);
  }, 60);

  timer.unref?.();

  return () => {
    clearInterval(timer);
    draw('idle', null);
  };
}

// The menu reflects guard's real state: installed or not, and the current mode.
// The live session's state beside its menu entry: green and filled when agents are running now,
// grey and hollow when nothing is.
export const liveBadge = (p, active) => (active ? p.onGreen(p.ink(p.bold(` ● ${t('ACTIVE')} `))) : p.dim(`○ ${t('NOT ACTIVE')}`));

// The main menu: four groups, each naming what it holds, so the first screen stays short.
export const CATEGORIES = {
  live: { label: 'LIVE', title: 'what your agents are doing now', pose: 'right' },
  audit: { label: 'AUDIT', title: 'look for what is already exposed', pose: 'think' },
  protect: { label: 'PROTECTION', title: 'where blackbrake runs and how firmly', pose: 'determined' },
  more: { label: 'MORE', title: 'help, language and privacy', pose: 'happy' },
};

// Puts the rows that features registered (src/cli/registry.mjs) between the built-in ones, by
// their `order` (the built-in rows count 10, 20, 30…), and keeps the closing row (`tail`) last.
function withFeatureRows(slot, items, tail, state, p) {
  const extra = menuItems(slot, state, p);

  if (!extra.length) return items;

  const merged = [...items.filter((i) => i.value !== tail).map((item, i) => ({ order: (i + 1) * 10, item })), ...extra].sort((a, b) => a.order - b.order);

  return [...merged.map((m) => m.item), ...items.filter((i) => i.value === tail)];
}

// `features: false` leaves out the registered rows (the fixed core of the menu).
export function homeItems(state = {}, p = null, { features = true } = {}) {
  const { installed = false, mode = 'observe', protectedCount = 0, detectedCount = 0, running = 0, live = running > 0 } = state;

  const items = [
    { value: 'live', label: t('Live session'), tag: p ? liveBadge(p, live) : null, rawTag: true, pulse: live, hint: t('live alerts · open Claude Code · recent events') },
    { value: 'audit', label: t('Audit'), hint: t('Claude Code audit · scan every AI harness for secrets') },
    { value: 'protect', label: t('Protection and permissions'), hint: installed ? t('{a} of {b} harnesses · mode {mode} · permissions', { a: protectedCount, b: detectedCount, mode: t(mode) }) : t('set up blackbrake in your AI harnesses') },
    { value: 'more', label: t('Help and settings'), hint: t('commands · language · privacy') },
    { value: 'quit', label: t('Close this menu'), hint: t('protection keeps running') },
  ];

  return features ? withFeatureRows('main', items, 'quit', state, p) : items;
}

// What each group holds.
export function categoryItems(cat, state = {}, p = null, { features = true } = {}) {
  const { installed = false, claude = installed, mode = 'observe', protectedCount = 0, detectedCount = 0, running = 0, live = running > 0, animations = true, isAccessible = false, light = false } = state;
  const protect = mode === 'protect';
  const back = { value: 'back', label: t('Back to the main menu') };

  const items = {
    live: [
      { value: 'watch', label: t('Live alerts from running agents'), tag: p ? liveBadge(p, live) : null, rawTag: true, pulse: live, hint: live ? t('{n} agent(s) running now', { n: running }) : t('opens and waits for alerts'), disabled: !installed },
      { value: 'claude', label: t('Open Claude Code with blackbrake watching'), hint: claude ? t('guard on · {mode}', { mode: t(mode) }) : t('sets up guard first') },
      { value: 'guard', label: t(installed ? 'Guard status and recent alerts' : 'Set up guard in every agent'), hint: t(installed ? 'what guard warned about or stopped' : 'you confirm once; observe mode') },
    ],
    audit: [
      { value: 'audit', label: t('Audit my setup'), hint: t('secrets · add-ons · spend — read-only') },
      { value: 'scan', label: t('Scan my AI harnesses'), hint: t('secrets in the history and config of each one') },
      { value: 'fix', label: t('Fix what was found'), hint: t('here, automatically, or with your AI agent') },
    ],
    protect: [
      { value: 'permissions', label: t('Permissions'), hint: t('which harnesses, observe mode, background watcher, window, notifications') },
      { value: 'agents', label: t('Protected agents: {a} of {b}', { a: protectedCount, b: detectedCount }), hint: t('add, remove or scan each harness') },
      { value: 'mode', label: t(protect ? 'Protection mode: PROTECT' : 'Protection mode: OBSERVE'), hint: t(protect ? 'switch back to observe' : 'switch to protect: stop secrets before they are sent'), disabled: !installed },
    ],
    more: [
      { value: 'help', label: t('Help: commands and what they do'), hint: t('how to use blackbrake from the terminal') },
      { value: 'lang', label: getLang() === 'es' ? 'Idioma: español' : 'Language: English', hint: getLang() === 'es' ? 'switch to English' : 'cambiar a español' },
      { value: 'animations', label: t(animations ? 'Animations: on' : 'Animations: off'), hint: t('Brakey moves only in an interactive terminal') },
      { value: 'accessible', label: t(isAccessible ? 'Screen-reader mode: on' : 'Screen-reader mode: off'), hint: t('plain text, no drawings or motion') },
      { value: 'theme', label: t(light ? 'Theme: light terminal' : 'Theme: dark terminal'), hint: t('switch if the text is hard to read') },
      { value: 'privacy', label: t('What blackbrake never does'), hint: t('privacy guarantees') },
    ],
  };

  const rows = items[cat] ?? [];

  return [...(features ? withFeatureRows(cat, rows, null, state, p) : rows), back];
}

export const HOME_ITEMS = homeItems({}, null, { features: false });

// Leaving: the mascot dozes off; if the background watcher runs, it says so.
export function goodbye(p, { watching = false } = {}) {
  return ['', ...withLogo(p, [p.cream(t('See you soon.')), p.faint(t(watching ? 'blackbrake keeps watching in the background.' : 'Run "blackbrake" whenever you want to check on your agents.'))], 'sleep'), ''];
}

export function privacyScreen(p) {
  const item = (title, text) => [`${p.green('✓')} ${p.cream(t(title))}`, `  ${p.faint(t(text))}`];

  return [
    '',
    ...screen(p, t('NEVER'), t('what blackbrake never does'), columns(), { pose: 'happy', line: t('My promises. A test breaks the build if the code breaks one.') }).slice(1),
    '',
    ...box(p, t('Promises'), [
    ...item('Never opens a network connection', 'There is no network code in the package; a test fails the build if any appears.'),
    ...item('Never writes, changes or deletes your files', 'audit only reads. guard writes only its log in ~/.blackbrake, never content.'),
    ...item('Never lets the agent switch it off', 'Only you, in your own terminal, can change the mode or remove guard.'),
    ...item('Never prints a secret', 'You see the rule that matched, the service prefix (like ghp_) and the length.'),
    ...item('Never runs code from your add-ons', 'Skills, plugins and MCP servers are read as text, not executed.'),
    ...item('No telemetry, no account', 'Nothing about you or your usage leaves this machine.'),
    ]),
    '',
    `  ${p.faint(t('Source and releases with provenance:'))} ${p.orange('github.com/blackbrake-dev/blackbrake')}`,
    '',
  ];
}

// After an audit: what to look at next.
export const afterAuditItems = (adviceCount, fixCount = 0) => [
  { value: 'fix', label: t('Fix what was found ({n})', { n: fixCount }), disabled: !fixCount, hint: t(fixCount ? 'here, automatically, or with your AI agent' : 'nothing to fix') },
  { value: 'advice', label: t('See the precautions for my results ({n})', { n: adviceCount }), disabled: !adviceCount, hint: t(adviceCount ? 'tailored to this audit' : 'nothing to fix') },
  { value: 'details', label: t('See the full details'), hint: t('every finding, add-on and costly episode') },
  { value: 'back', label: t('Back to the main menu') },
  { value: 'quit', label: t('Quit') },
];

// Runs the menu loop. Returns the action to run next ('audit') or null to quit.
// `again` skips the big header when coming back from another screen.
export async function home(p, version, io = {}, again = false, items = HOME_ITEMS, tip = null) {
  const output = io.output ?? process.stdout;
  await transition(p, { out: output, motion: io.motion ?? motionAllowed(output) });

  // The main menu always wears the full name. The first time, Brakey says hello; after that, the
  // header appears as it is.
  if (again) output.write(`${homeHeader(p, version, columns()).join('\n')}\n`);
  else await play((pose) => homeHeader(p, version, columns(), pose), HELLO, { out: output, motion: io.motion ?? motionAllowed(output) });

  // Brakey's tip: the most useful next step.
  if (tip) output.write(`${tip}\n\n`);
  const stop = headerLife(p, version, { out: output, motion: io.motion ?? motionAllowed(output), lines: 8 + (tip ? 2 : 0) + items.length + 2 });
  const choice = await select(p, items, io);
  stop();

  return choice === 'quit' ? null : choice;
}

// A group's own screen: its header, then its options. Returns the chosen action, or null for back.
export async function category(p, cat, state, io = {}) {
  const output = io.output ?? process.stdout;
  const c = CATEGORIES[cat];
  await transition(p, { out: output, motion: io.motion ?? motionAllowed(output) });
  output.write(`${screen(p, t(c.label), t(c.title), columns(), { pose: c.pose ?? 'idle' }).join('\n')}\n`);
  const choice = await select(p, categoryItems(cat, state, p), io);

  return choice === 'back' ? null : choice;
}

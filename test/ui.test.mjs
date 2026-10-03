import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { detectLang, setLang } from '../src/i18n.mjs';
import { CLASSES } from '../src/secrets/context.mjs';
import { buildAdvice } from '../src/advice.mjs';
import { renderAdvice, renderAudit, renderDetails } from '../src/ui/audit-view.mjs';
import { categoryItems, HOME_ITEMS, homeHeader, homeItems, privacyScreen } from '../src/ui/home.mjs';
import { renderMenu, select } from '../src/ui/menu.mjs';
import { colorLevel, createPainter, LOGO_WIDTH, strip, width } from '../src/ui/term.mjs';

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../bin/blackbrake.mjs');

const ESC = '\x1b[';

const data = {
  version: '0.0.0-test', root: '/home/u/.claude/projects', files: 3, bytes: 2048, ms: 1200, rules: { count: 221 }, pricesDate: '2026-09-23',
  secrets: [
    // oxlint-disable-next-line anti-slop/no-shape-in-symbol-names -- fixture of the public finding schema, which names this field "shape".
    { ruleId: 'linear-api-key', shape: 'lin_…(48)', copies: 5, sessions: 1, subagentCopies: 0, origin: 'pasted by you', firstSeen: '2026-09-18T10:00:00Z', where: { user: 1, assistant: 1 }, classification: CLASSES.real },
    // oxlint-disable-next-line anti-slop/no-shape-in-symbol-names -- fixture of the public finding schema, which names this field "shape".
    { ruleId: 'generic-api-key', shape: 'test…(20)', copies: 1, sessions: 1, subagentCopies: 0, origin: 'printed by a command', firstSeen: null, where: {}, classification: CLASSES.example },
  ],
  load: { counts: { skills: 10, agents: 2, commands: 3, pluginsEnabled: 1, duplicates: 0 }, mcp: [], perTurnTokens: { skills: 1200, agents: 300 }, usedSkills: 4, posture: { dangerousModePromptSkipped: true, defaultModeBypass: false }, risks: [{ label: 'sends environment or secrets over the network', owner: 'skill:x', inCode: true }] },
  spend: { episodes: 10, total: 42, topN: 1, topShare: 0.6, p50: 1.2, p90: 9.5, worst: [{ cost: 20, date: '2026-09-17', turns: 30, tools: 80, subagents: 2, hours: 1.5 }], floor: { sessions: 3, medianTokens: 18000, share: 0.2 }, unknownModels: [] },
};

test('colour follows the terminal and NO_COLOR', () => {
  assert.equal(colorLevel({ isTTY: false }, {}), 0, 'pipes get no colour');
  assert.equal(colorLevel({ isTTY: true }, { NO_COLOR: '1' }), 0);
  assert.equal(colorLevel({ isTTY: true }, { COLORTERM: 'truecolor' }), 3);
  assert.equal(colorLevel({ isTTY: true }, {}), 2);
  assert.equal(colorLevel({ isTTY: false }, { FORCE_COLOR: '3' }), 3);
});

test('the audit summary reads the same with and without colour, and stays short', () => {
  const plain = renderAudit(createPainter(0), data, { adviceCount: 4 }).join('\n');
  const color = renderAudit(createPainter(3), data, { adviceCount: 4 }).join('\n');
  assert.ok(!plain.includes(ESC), 'no escape codes without colour');
  assert.ok(color.includes(ESC), 'colour when asked');
  // Same text everywhere except the logo, which uses different glyphs without colour on purpose.
  const noLogo = (s) => s.split('\n').map((l) => l.slice(2 + LOGO_WIDTH)).join('\n');
  assert.equal(noLogo(strip(color)), noLogo(plain), 'colour adds no text');

  for (const s of ['EXPOSURE', 'WHAT YOU LOAD', 'SPEND', 'NEXT', '4 precautions', 'lin_…(48)', 'nothing left this machine']) assert.ok(plain.includes(s), `missing: ${s}`);
  assert.ok(!plain.includes('test…(20)'), 'examples are not listed in the summary');
  assert.ok(plain.split('\n').length <= 24, 'the summary fits one screen');
});

test('details show everything; --all adds the examples', () => {
  const details = renderDetails(createPainter(0), data).join('\n');
  assert.match(details, /Costliest episodes/);
  assert.match(details, /sends environment or secrets over the network/);
  assert.ok(!details.includes('test…(20)'));
  assert.ok(renderDetails(createPainter(0), data, { all: true }).join('\n').includes('test…(20)'));
});

test('precautions are built from the results, most serious first', () => {
  const advice = buildAdvice(data);
  assert.equal(advice[0].level, 'critical');
  assert.match(advice[0].title, /Rotate the 1 key/);
  assert.ok(advice[0].steps.some((s) => s.includes('Linear') && s.includes('lin_…(48)')), 'names where to rotate it');
  assert.ok(advice.some((a) => /pasted/.test(a.why) || /prompts/.test(a.title)), 'pasted by you → keep keys out of prompts');
  assert.ok(advice.some((a) => /bypass-mode warning/.test(a.title)), 'posture → turn the warning back on');
  assert.ok(advice.some((a) => /Review skill:x/.test(a.title)), 'risky add-on → review it');
  assert.ok(!advice.some((a) => /Trim the skills/.test(a.title)), 'too few skills to suggest trimming');

  const clean = buildAdvice({ ...data, secrets: [], load: { ...data.load, risks: [], posture: {} }, spend: { ...data.spend, topShare: 0.2 } });
  assert.equal(clean.length, 0, 'nothing to fix → no precautions');
  assert.match(renderAdvice(createPainter(0), clean).join('\n'), /Nothing to fix/);
  const text = renderAdvice(createPainter(0), advice, { cols: 80 }).join('\n');
  assert.match(text, /CRITICAL/);

  for (const l of text.split('\n')) assert.ok(width(l) <= 80, `precaution line too wide: ${l}`);
  assert.ok(!/\$\d+ (saved|savings)/i.test(text), 'no savings claims');
});

test('menu: pointer on the current item; guard items follow the real state', async () => {
  const p = createPainter(0);
  const lines = renderMenu(p, HOME_ITEMS, 0);
  assert.match(lines[0], /❯ Live session/);
  assert.deepEqual(HOME_ITEMS.map((i) => i.value), ['live', 'audit', 'protect', 'more', 'quit'], 'four groups and quit');
  assert.match(HOME_ITEMS.find((i) => i.value === 'audit').hint, /scan every AI harness/, 'each group names what it holds');
  const off = categoryItems('protect', { installed: false });
  assert.equal(off.find((i) => i.value === 'mode').disabled, true, 'no mode switch before guard is set up');
  const on = categoryItems('protect', { installed: true, mode: 'protect' });
  assert.match(on.find((i) => i.value === 'mode').label, /PROTECT/);
  assert.match(categoryItems('live', { installed: true }).find((i) => i.value === 'guard').label, /status/);
  assert.equal(categoryItems('audit', {}).at(-1).value, 'back', 'every group returns to the main menu');
  assert.equal(await select(p, HOME_ITEMS, { input: { isTTY: false }, output: { isTTY: false } }), null, 'no terminal, no menu');
});

test('home and privacy screens', () => {
  const p = createPainter(0);
  const head = homeHeader(p, '1.2.3', 96).join('\n');
  assert.match(head, /█▀▀▀▄ █ {5}▄▀▀▀▄/, 'the big name (shapes only without colour)');
  const lit = homeHeader(createPainter(3), '1.2.3', 96).join('\n');
  // oxlint-disable-next-line no-control-regex -- the test checks ANSI colour codes
  assert.match(lit, /\x1b\[38;2;255;179;71m/, 'BRAKE lit from above in amber');
  assert.match(lit, /48;2;90;42;20m|38;2;90;42;20m/, 'drop shadow in the brand brown');
  assert.match(head, /v1\.2\.3/);
  assert.match(homeHeader(p, '1.2.3', 70).join('\n'), /blackbrake {2}v1\.2\.3/, 'narrow terminals get the small name');
  assert.match(privacyScreen(p).join('\n'), /Never opens a network connection/);

  for (const l of [...homeHeader(p, '1'), ...privacyScreen(p)]) assert.ok(width(l) <= 96, `line too wide: ${l}`);
});

test('no command in a pipe prints help instead of waiting for keys', () => {
  const out = execFileSync(process.execPath, [BIN], { encoding: 'utf8', input: '', timeout: 5000, env: { ...process.env, BLACKBRAKE_LANG: 'en' } });
  assert.match(out, /Usage:/);
  assert.ok(!out.includes(ESC));
});

test('Spanish: help, home, report and precautions are translated; --json stays English', () => {
  const es = execFileSync(process.execPath, [BIN, '--lang', 'es'], { encoding: 'utf8', input: '', timeout: 5000 });
  assert.match(es, /Uso:/);
  setLang('es');
  const p = createPainter(0);
  const home = [...homeHeader(p, '1'), ...renderMenu(p, homeItems({ installed: true, mode: 'protect' }), 0), ...renderMenu(p, categoryItems('protect', { installed: true, mode: 'protect' }), 0)].join('\n');
  assert.match(home, /La caja negra y los frenos/);
  assert.match(home, /Sesión en directo/);
  assert.match(home, /Modo de protección: PROTEGER/);
  const text = renderAudit(p, data, { adviceCount: 2 }).join('\n');
  assert.match(text, /EXPOSICIÓN/);
  assert.match(text, /parecen reales/);
  const advice = renderAdvice(p, buildAdvice(data), { cols: 80 }).join('\n');
  assert.match(advice, /Rota las 1 clave|Rota las/);
  setLang('en');
  assert.match(renderAudit(p, data, {}).join('\n'), /EXPOSURE/);
});

test('language detection: explicit choice, then saved, then the system', () => {
  assert.equal(detectLang({ env: { BLACKBRAKE_LANG: 'es' } }), 'es');
  assert.equal(detectLang({ env: {}, saved: 'es' }), 'es');
  assert.equal(detectLang({ env: { BLACKBRAKE_LANG: 'en' }, saved: 'es' }), 'en');
  assert.equal(detectLang({ env: { LC_ALL: 'es_ES.UTF-8' } }), 'es');
});

// Brakey's poses and sizes, the panels (header, box, bubble), loading indicators and transitions:
// motion only on an interactive terminal, always ending in text, never touching a file or a pipe.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { goodbyeScene, progressBar, report, spinner, transition } from '../src/ui/motion.mjs';
import { box, bubble, createPainter, mascot, mascotMedium, MEDIUM_WIDTH, POSES, strip, truncate, width } from '../src/ui/term.mjs';

const sink = (isTTY = true) => ({ isTTY, rows: 20, columns: 60, text: '', write(s) { this.text += s; } });

test('Brakey: every pose differs, in both sizes; arms and lid change only what they should', () => {
  const lit = createPainter(3);
  const large = POSES.map((pose) => mascot(lit, pose).join('\n'));
  const medium = POSES.map((pose) => mascotMedium(lit, pose).join('\n'));
  assert.equal(new Set(large).size, POSES.length, 'large poses are distinct');
  assert.equal(new Set(medium).size, POSES.length, 'medium poses are distinct');

  for (const pose of POSES) {
    assert.equal(mascot(lit, pose).length, 5);
    assert.equal(mascotMedium(lit, pose).length, 3);
    assert.ok(mascotMedium(lit, pose).every((r) => width(r) === MEDIUM_WIDTH), `${pose}: fixed width, the layout never shifts`);
  }

  const plain = createPainter(0);
  assert.match(mascot(plain, 'celebrate')[0], /^\\.*\/$/, 'without colour, raised arms are drawn too');
  assert.ok(mascotMedium(plain, 'idle').every((r) => r.length === MEDIUM_WIDTH));
});

test('panels: a box keeps its width, cuts styled rows and wraps plain text; a bubble speaks for Brakey', () => {
  const p = createPainter(3);
  const lines = box(p, 'Title', [p.coral('x'.repeat(200)), `  ${'word '.repeat(40)}`], { width: 40 });
  assert.ok(lines.every((l) => width(l) === 42), 'every row of the panel is the same width');
  assert.match(strip(lines[0]), /╭─ Title ─+╮/);
  assert.match(strip(lines[1]), /…/);
  assert.equal(width(truncate(p.orange('abcdef'), 4)), 4);
  const b = bubble(p, 'All in order.', { pose: 'happy', width: 30 });
  assert.match(strip(b.join('\n')), /◀ All in order\./);
});

test('loading: nothing moves on a pipe; on a terminal it ends with a line of text and the cursor back', async () => {
  const p = createPainter(3);
  const pipe = sink(false);
  const s1 = spinner(p, 'Reading', { out: pipe, motion: false });
  s1.update('Reading more', [3, 10]);
  s1.stop('Done', 'done');
  assert.equal(strip(pipe.text).trim(), '✓ Done', 'without motion only the result line');
  const tty = sink(true);
  const s2 = spinner(p, 'Reading', { out: tty, motion: true, interval: 5 });
  s2.update('Scanning Cursor', [2, 4]);
  await new Promise((r) => setTimeout(r, 20));
  s2.stop();
  assert.match(tty.text, /\x1b\[\?25l/);
  assert.match(tty.text, /\x1b\[\?25h$/, 'the cursor is always given back');
  assert.match(strip(tty.text), /Scanning Cursor/);
  assert.match(strip(progressBar(p, 5, 10, 10)), /^█+▌░+$/);
});

test('the alerts window does not inherit what an agent sets to switch colour or motion off', async () => {
  const { windowEnv } = await import('../src/guard/window.mjs');
  const env = windowEnv({ PATH: '/x', NO_COLOR: '1', TERM: 'dumb', CI: '1', FORCE_COLOR: '0', BLACKBRAKE_NO_ANIMATION: '1', ACCESSIBLE: '1', BLACKBRAKE_HOME: '/evil', NODE_OPTIONS: '--require ./x.js', NODE_PATH: '/r', LD_PRELOAD: '/r/x.so', DYLD_INSERT_LIBRARIES: '/r/x', LANG: 'es_ES.UTF-8' }, '/h/.blackbrake');
  assert.deepEqual(Object.keys(env).sort(), ['ACCESSIBLE', 'BLACKBRAKE_HOME', 'LANG', 'PATH'], 'only what a terminal needs; nothing that switches colour off or loads code');
  assert.equal(env.BLACKBRAKE_HOME, '/h/.blackbrake', "guard's own folder, not the one the agent set");
});

test('main menu: the name shines now and then; the chosen row wears Brakey; the live badge beats', async () => {
  const { wordmark } = await import('../src/ui/term.mjs');
  const { renderMenu } = await import('../src/ui/menu.mjs');
  const { headerLife } = await import('../src/ui/home.mjs');
  const p = createPainter(3);
  assert.notEqual(wordmark(p, { glint: 20 }).join(''), wordmark(p).join(''), 'the shine lightens the letters it crosses');
  assert.equal(wordmark(p, { glint: 500 }).join(''), wordmark(p).join(''), 'and nothing when it is past them');
  const items = [{ value: 'a', label: 'Live session', tag: '● ACTIVE', rawTag: true, pulse: true }, { value: 'b', label: 'Audit' }];
  const rows = renderMenu(p, items, 0, 'idle', 3).map(strip);
  assert.match(rows[0], /▐••▌ 1 {2}Live session/, 'Brakey in its orange box points at the chosen row, with its number');
  assert.match(rows[1], /· {2}2 {2}Audit/);
  assert.match(rows[0], /○ ACTIVE/, 'the badge dot changes with the beat');
  assert.equal(typeof headerLife(p, '1.0.0', { out: sink(false) }), 'function', 'no terminal: nothing starts');
});

test('transitions and scenes: a terminal gets a wipe then a clean screen; a pipe gets nothing', async () => {
  const p = createPainter(3);
  const pipe = sink(false);
  await transition(p, { out: pipe, motion: true });
  assert.equal(pipe.text, '');
  const still = sink(true);
  await transition(p, { out: still, motion: false });
  assert.equal(still.text, '\x1b[2J\x1b[3J\x1b[H', 'without motion: just the clean screen');
  const moving = sink(true);
  await transition(p, { out: moving, motion: true });
  assert.match(moving.text, /▀/, 'the brake-light line sweeps down');
  assert.ok(moving.text.endsWith('\x1b[2J\x1b[3J\x1b[H\x1b[?25h'));
  const out = sink(false);
  await report(p, 'good', 'Removed 3 copies.', null, { out, motion: false });
  assert.match(strip(out.text), /Brakey: Removed 3 copies\./, 'the scene always says what happened');
  const bye = sink(false);
  await goodbyeScene(p, ['See you soon.'], { out: bye, motion: false });
  assert.match(strip(bye.text), /See you soon\. +z Z z/);
});

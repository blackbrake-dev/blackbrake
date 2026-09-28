// Arrow-key menu for the terminal, no dependencies (design after @clack/core's select, MIT; no code
// copied). Returns the chosen value, or null if cancelled or if there is no interactive terminal.
import readline from 'node:readline';
import { t } from '../i18n.mjs';
import { accessible, columns, mini, motionAllowed, padEnd } from './term.mjs';

const HIDE = '\x1b[?25l';

const SHOW = '\x1b[?25h';

// Put the terminal back (cursor, raw mode) if the process exits while a menu or animation is open.
export function restoreOnExit(input = process.stdin, output = process.stdout) {
  const restore = () => {
    try { output.write(SHOW); } catch { /* closed */ }

    try { if (input.isTTY) input.setRawMode(false); } catch { /* closed */ }
  };

  process.once('exit', restore);

  return () => process.off('exit', restore);
}

// The pointer is Brakey in miniature: its face on an orange box with rounded sides (four columns);
// the other rows get a small guide dot in the dark orange. Without colour, the usual arrow.
const pointerFor = (p, on, pose) => {
  if (!p.level || accessible()) return on ? (p.level ? p.orange('❯') : '❯') : ' ';

  return on ? `${p.orange('▐')}${mini(p, pose)}${p.orange('▌')}` : `  ${p.orangeDk('·')} `;
};

// The live badge's dot beats while agents run: ● ◉ ○ ◉.
const PULSE = ['●', '●', '◉', '○', '◉'];

// While a menu waits, Brakey (the pointer) lives a little: it blinks every few seconds, and now and
// then glances to one side and back. Only the pointer moves, and only on a redraw when it changes.
const IDLE_CYCLE = 64;

function poseAt(tick) {
  const k = tick % IDLE_CYCLE;

  if (k === 0 || k === 34) return 'blink';

  if (k >= 20 && k < 24) return 'left';

  if (k >= 48 && k < 52) return 'right';

  if (k === 56) return 'wink';

  return 'idle';
}

// pulse: redraw every few ticks too, for items that beat (the live badge).
function blinker(redraw, motion, pulse = false) {
  if (!motion) return { pose: () => 'idle', beat: () => 0, stop() {} };
  let tick = 1;

  const timer = setInterval(() => {
    const before = poseAt(tick);
    tick++;

    if (poseAt(tick) !== before || (pulse && tick % 3 === 0)) redraw();
  }, 140);

  timer.unref?.();

  return { pose: () => poseAt(tick), beat: () => Math.floor(tick / 3), stop: () => clearInterval(timer) };
}

export function renderMenu(p, items, index, pose = 'idle', beat = 0) {
  const labelWidth = Math.max(...items.map((it) => it.label.length)) + 2;
  const numbered = p.level && !accessible();

  return items.map((it, i) => {
    const on = i === index;
    const pointer = pointerFor(p, on, pose);
    let label = padEnd(it.label, labelWidth);

    if (it.disabled) label = p.faint(label);
    else if (on) label = p.bold(p.hex('#FFF3E4', 'cream')(label));
    else label = p.cream(label);
    // rawTag: the tag is already painted (for example the live session's state); a beating tag
    // swaps its dot in time.
    let tag = it.tag ? `${it.rawTag ? it.tag : p.onBrown(p.amber(` ${it.tag} `))} ` : '';

    if (it.pulse) tag = tag.replace('●', PULSE[beat % PULSE.length]);
    // The chosen row sits on the dark brand band; its hint lights up in amber.
    const num = numbered ? `${p.faint(i < 9 ? String(i + 1) : ' ')} ` : '';
    const lead = p.level ? ' ' : '';
    const body = on && p.level ? p.onBand(` ${label}${tag}`) + ` ${p.amber(it.hint ?? '')}` : `${lead}${label}${tag}${p.faint(it.hint ?? '')}`;

    return `  ${pointer} ${num}${body.trimEnd()}`;
  });
}

// Checkboxes: items [{ value, label, hint, on, locked }]. Space toggles, "a" toggles all, Enter
// confirms, q/Esc cancels. Returns { value: boolean } or null (cancelled or no terminal).
export function renderChecklist(p, items, index, cols = columns(), pose = 'idle') {
  const labelWidth = Math.max(...items.filter((it) => !it.heading && !it.proceed).map((it) => it.label.length)) + 2;
  const room = Math.max(10, cols - labelWidth - 8);
  const fit = (s = '') => (s.length > room ? `${s.slice(0, room - 1)}…` : s);

  return items.map((it, i) => {
    const on = i === index;
    // Ticked boxes glow green on the dark band, empty ones stay a faint outline.
    const box = it.heading ? '' : it.on ? (p.level ? p.onBand(p.green(' ■ ')) : '■') : p.level ? p.dim(' □ ') : '□';
    const pointer = pointerFor(p, on, pose);

    // The way on, at the top: an orange button; Enter or space on it saves and continues.
    if (it.proceed) return `  ${pointer} ${p.level ? p.onOrange(p.ink(p.bold(` ▶ ${it.label} `))) : `▶ ${it.label}`}  ${on ? p.amber(it.hint ?? '') : p.faint(it.hint ?? '')}`;

    // Section headings: the label on the orange band, like the screens' labels.
    if (it.heading) return p.level ? `\n  ${p.onOrange(p.ink(p.bold(` ${it.label} `)))} ${p.orangeDk('─'.repeat(Math.max(4, cols - it.label.length - 10)))}` : `\n  ${it.label}`;
    const label = on ? p.bold(p.hex('#FFF3E4', 'cream')(padEnd(it.label, labelWidth))) : p.cream(padEnd(it.label, labelWidth));

    return `  ${pointer} ${box} ${label}${on ? p.amber(fit(it.hint)) : p.faint(fit(it.hint))}`;
  });
}

// `proceed` ({ label, hint }) puts a "continue" button above the list, selected first: Enter or
// space on it saves, like Enter anywhere.
export function checklist(p, items, { input = process.stdin, output = process.stdout, proceed = null } = {}) {
  if (!input.isTTY || !output.isTTY) return Promise.resolve(null);
  const state = [...(proceed ? [{ proceed: true, ...proceed }] : []), ...items.map((it) => ({ ...it }))];
  const pickable = state.flatMap((it, i) => it.heading || it.locked ? [] : [i]);
  let index = pickable[0];
  let drawn = 0;
  let pose = null;

  const draw = () => {
    const lines = [...renderChecklist(p, state, index, columns(), pose ?? blink.pose()).flatMap((l) => l.split('\n')), '', `    ${p.faint(t('↑↓ move · space on/off · a all · enter save · q cancel'))}`];

    if (drawn) output.write(`\x1b[${drawn}A\x1b[0J`);
    output.write(`${lines.join('\n')}\n`);
    drawn = lines.length;
  };

  const blink = blinker(() => draw(), motionAllowed(output));

  return new Promise((resolve) => {
    readline.emitKeypressEvents(input);
    input.setRawMode(true);
    input.resume();
    output.write(HIDE);

    const release = restoreOnExit(input, output);

    const done = (value) => {
      release();
      blink.stop();
      input.off('keypress', onKey);
      input.setRawMode(false);
      input.pause();
      output.write(SHOW);
      resolve(value);
    };

    function onKey(s, key = {}) {
      try { handle(s, key); } catch { done(null); }
    }

    function handle(_s, key = {}) {
      const pos = pickable.indexOf(index);

      if ((key.ctrl && key.name === 'c') || key.name === 'escape' || key.name === 'q') return done(null);

      if (key.name === 'up' || key.name === 'k') index = pickable[(pos - 1 + pickable.length) % pickable.length];
      else if (key.name === 'down' || key.name === 'j' || key.name === 'tab') index = pickable[(pos + 1) % pickable.length];
      else if (key.name === 'space' && !state[index].proceed) state[index].on = !state[index].on;
      else if (key.name === 'a') {
        const boxes = pickable.filter((i) => !state[i].proceed);
        const all = boxes.every((i) => state[i].on);

        for (const i of boxes) state[i].on = !all;
      } else if (key.name === 'return' || (key.name === 'space' && state[index].proceed)) {
        // The mascot is pleased with the choice.
        pose = 'happy';
        draw();

        return done(Object.fromEntries(state.flatMap((it) => it.heading || it.proceed ? [] : [[it.value, Boolean(it.on)]])));
      }

      draw();
    }

    input.on('keypress', onKey);
    draw();
  });
}

export function select(p, items, { input = process.stdin, output = process.stdout } = {}) {
  if (!input.isTTY || !output.isTTY) return Promise.resolve(null);
  const enabled = items.map((it, i) => (it.disabled ? -1 : i)).filter((i) => i >= 0);

  if (!enabled.length) return Promise.resolve(null);
  let index = enabled[0];
  let drawn = 0;
  let pose = null;

  const draw = () => {
    const lines = [...renderMenu(p, items, index, pose ?? blink.pose(), blink.beat()), '', `    ${p.faint(t('↑↓ move · 1-9 choose · enter select · q back'))}`];

    if (drawn) output.write(`\x1b[${drawn}A\x1b[0J`);
    output.write(`${lines.join('\n')}\n`);
    drawn = lines.length;
  };

  const blink = blinker(() => draw(), motionAllowed(output), items.some((it) => it.pulse));

  return new Promise((resolve) => {
    readline.emitKeypressEvents(input);
    input.setRawMode(true);
    input.resume();
    output.write(HIDE);

    const release = restoreOnExit(input, output);

    const done = (value) => {
      release();
      blink.stop();
      input.off('keypress', onKey);
      input.setRawMode(false);
      input.pause();
      output.write(SHOW);
      resolve(value);
    };

    const move = (step) => {
      const pos = enabled.indexOf(index);
      index = enabled[(pos + step + enabled.length) % enabled.length];
      draw();
    };

    function onKey(s, key = {}) {
      try { handle(s, key); } catch { done(null); }
    }

    function handle(str, key = {}) {
      if (key.ctrl && key.name === 'c') return done(null);

      // 1–9 picks the option in that position straight away.
      if (/^[1-9]$/.test(str ?? '') && items[Number(str) - 1] && !items[Number(str) - 1].disabled) {
        index = Number(str) - 1;
        pose = 'happy';
        draw();

        return done(items[index].value);
      }

      if (key.name === 'up' || key.name === 'k') return move(-1);

      if (key.name === 'down' || key.name === 'j' || key.name === 'tab') return move(1);

      if (key.name === 'return') {
        pose = 'happy';
        draw();

        return done(items[index].value);
      }

      if (key.name === 'escape' || key.name === 'q') return done(null);
    }

    input.on('keypress', onKey);
    draw();
  });
}

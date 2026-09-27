// Motion: loading indicators, screen transitions and Brakey's short scenes. Following Clack, ora and
// cli-spinners: only on an interactive terminal (not CI, not NO_COLOR, not TERM=dumb, not for screen
// readers, not when switched off), frames written in one go, the cursor always restored, and never
// the only signal: every indicator ends in a line of text.
import { t } from '../i18n.mjs';
import { ANIMATIONS, clearScreen, gradientRule, MASCOT, mascotMedium, mini, motionAllowed, padEnd, play, strip } from './term.mjs';

const DOTS = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

// Brakey's eyes while it works: a slow look from side to side.
const LOOK = ['left', 'left', 'idle', 'right', 'right', 'idle'];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// A progress bar that fills in the brand orange, with a lighter head.
export function progressBar(p, done, total, size = 18) {
  const k = total ? Math.max(0, Math.min(1, done / total)) : 0;
  const n = Math.round(k * size);

  return `${p.orange('█'.repeat(Math.max(0, n - 1)))}${n ? p.orangeLt('▌') : ''}${p.faint('░'.repeat(size - n))}`;
}

// A one-line loading indicator: Brakey looking around, braille dots, the message, an optional
// progress bar and the time so far. It keeps moving while the program waits on I/O; a long
// synchronous step can call update() to redraw. Without motion it prints nothing until stop().
export function spinner(p, text, { out = process.stdout, motion = motionAllowed(out), interval = 80 } = {}) {
  let message = text;
  let progress = null;
  let frame = 0;
  const started = Date.now();

  const draw = () => {
    const secs = Math.floor((Date.now() - started) / 1000);
    const bar = progress ? ` ${progressBar(p, progress[0], progress[1])} ${p.faint(`${progress[0]}/${progress[1]}`)}` : '';
    const line = `  ${mini(p, LOOK[Math.floor(frame / 3) % LOOK.length])} ${p.orange(DOTS[frame % DOTS.length])} ${p.cream(message)}${bar}${secs ? p.faint(`  ${secs}s`) : ''}`;
    out.write(`\r\x1b[2K${line}`);
    frame++;
  };

  let timer = null;

  if (motion) {
    out.write('\x1b[?25l');
    draw();
    timer = setInterval(draw, interval);
    timer.unref?.();
  }

  const restore = () => out.write('\x1b[?25h');

  if (motion) process.once('exit', restore);

  return {
    update(next, prog = null) {
      if (next) message = next;

      progress = prog;

      if (motion) draw();
    },
    // Ends with a line that stays: ✓ done, ! warning, or nothing (the caller prints its own result).
    stop(final = null, kind = 'done') {
      if (timer) clearInterval(timer);

      if (motion) {
        out.write('\r\x1b[2K');
        restore();
        process.off('exit', restore);
      }

      if (final) out.write(`  ${kind === 'done' ? p.green('✓') : p.amber('!')} ${p.cream(final)}\n`);
    },
  };
}

// Moving between screens: a thin orange line sweeps down, wiping what was there, then the new
// screen starts on a clean terminal (about 0.15 s). Without motion: just the clean terminal.
export async function transition(p, { out = process.stdout, motion = motionAllowed(out) } = {}) {
  if (!out.isTTY) return;

  if (!motion) {
    clearScreen(out);

    return;
  }

  const rows = Math.max(8, Math.min(out.rows || 24, 60));
  const cols = Math.max(20, Math.min(out.columns || 80, 200));
  const steps = 7;

  out.write('\x1b[?25l');

  try {
    for (let s = 1; s <= steps; s++) {
      const y = Math.round((rows * s) / steps);
      // Wipe everything above the line, draw the line (the brake light) at its new place.
      let frame = '\x1b[H';

      for (let r = 1; r < y; r++) frame += '\x1b[2K\n';

      frame += `\x1b[2K${gradientRule(p, cols - 1, s === steps ? ' ' : '▀')}`;
      out.write(frame);
      await sleep(18);
    }
  } finally {
    clearScreen(out);
    out.write('\x1b[?25h');
  }
}

// A short scene with the medium Brakey and one or two lines beside it; the last pose stays.
export function scene(p, name, lines, opts = {}) {
  const frames = ANIMATIONS[name] ?? [['idle', 0]];

  return play((pose) => mascotMedium(p, pose).map((row, i) => `  ${row}  ${lines[i] ?? ''}`.trimEnd()), frames, opts);
}

// Brakey reports the end of something: celebrating when it went well, alarmed when it found a
// problem, calm otherwise. The text always says what happened.
export function report(p, outcome, text, detail = null, opts = {}) {
  const name = outcome === 'good' ? 'celebrate' : outcome === 'bad' ? 'alarm' : 'think';
  const colour = outcome === 'good' ? p.green : outcome === 'bad' ? p.coral : p.cream;

  return scene(p, name, [`${p.bold(p.orange(MASCOT))}${p.faint(':')} ${colour(text)}`, detail ? p.faint(detail) : '', ''], opts);
}

// Leaving: Brakey dozes off, and the z's float up beside it.
export async function goodbyeScene(p, lines, { out = process.stdout, motion = motionAllowed(out) } = {}) {
  const zs = ['', `${p.faint('z')}`, `${p.faint('z')} ${p.dim('Z')}`, `${p.faint('z')} ${p.dim('Z')} ${p.faint('z')}`];
  const render = (k) => mascotMedium(p, k === 0 ? 'blink' : 'sleep').map((row, i) => `  ${row}  ${padEnd(lines[i] ?? '', Math.max(...lines.map((l) => strip(l).length)) + 2)}${i === 0 ? zs[k] : ''}`.trimEnd());

  await play((pose) => render(Number(pose)), motion ? [['0', 260], ['1', 220], ['2', 220], ['3', 0]] : [['3', 0]], { out, motion });
}

export const loadingText = () => t('Working locally…');

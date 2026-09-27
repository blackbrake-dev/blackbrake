// Terminal look of blackbrake: brand palette, colour support detection, and small layout helpers.
// No dependencies. Colour is off when the output is not a terminal or NO_COLOR is set.
import { t } from '../i18n.mjs';

const PALETTE = {
  orange: ['#FF5A1F', 202],
  orangeLt: ['#FF8A4C', 209],
  orangeDk: ['#C9431A', 166],
  band: ['#2A1810', 234],
  amber: ['#FFB020', 214],
  coral: ['#FF6B5B', 203],
  green: ['#5BD68A', 78],
  cream: ['#FFF3E4', 230],
  brown: ['#5A2A14', 94],
  dim: ['#9A8672', 244],
  ink: ['#120A07', 232],
};

export function colorLevel(stream = process.stdout, env = process.env) {
  if ('NO_COLOR' in env && env.NO_COLOR !== '') return 0;

  if (env.FORCE_COLOR === '0') return 0;
  const forced = env.FORCE_COLOR && env.FORCE_COLOR !== '0';

  if (!forced && !stream.isTTY) return 0;

  if (env.COLORTERM === 'truecolor' || env.COLORTERM === '24bit' || env.WT_SESSION || /^(vscode|iTerm\.app|WezTerm|ghostty)$/.test(env.TERM_PROGRAM || '')) return 3;

  if (env.FORCE_COLOR === '3') return 3;

  return 2;
}

const rgb = (hex) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));

// Light terminals: the light text colours become dark browns so they stay readable on white; the
// brand oranges stay. Chosen in Help and settings (BLACKBRAKE_THEME=light).
const LIGHT = { cream: ['#3B2415', 94], dim: ['#6E5A48', 241], amber: ['#B86E00', 136], green: ['#1E8A4C', 29] };

export const theme = (env = process.env) => (env.BLACKBRAKE_THEME === 'light' ? 'light' : 'dark');

// The mascot's name.
export const MASCOT = 'Brakey';

export function createPainter(level = colorLevel(), mode = theme()) {
  const code = (name, bg) => {
    const [hex, c256] = (mode === 'light' && !bg && LIGHT[name]) || PALETTE[name];

    if (level >= 3) return `\x1b[${bg ? 48 : 38};2;${rgb(hex).join(';')}m`;

    return `\x1b[${bg ? 48 : 38};5;${c256}m`;
  };

  const wrap = (open, close) => (s) => (level ? `${open}${s}${close}` : String(s));
  const p = { level };

  for (const name of Object.keys(PALETTE)) {
    p[name] = level ? wrap(code(name), '\x1b[39m') : (s) => String(s);
    p[`on${name[0].toUpperCase()}${name.slice(1)}`] = level ? wrap(code(name, true), '\x1b[49m') : (s) => String(s);
  }

  // Any brand shade in true colour, or the nearest palette colour on 256-colour terminals.
  p.hex = (hex, fallback) => (level >= 3 ? wrap(`\x1b[38;2;${rgb(hex).join(';')}m`, '\x1b[39m') : p[fallback]);
  p.bold = wrap('\x1b[1m', '\x1b[22m');
  p.faint = wrap('\x1b[2m', '\x1b[22m');

  return p;
}

// Visible width, ignoring ANSI escapes (all our glyphs are single-width).
// oxlint-disable-next-line no-control-regex
const ANSI = /\x1b\[[0-9;?]*[A-Za-z]/g;

export const strip = (s) => String(s).replace(ANSI, '');

export const width = (s) => [...strip(s)].length;

export const padEnd = (s, n) => s + ' '.repeat(Math.max(0, n - width(s)));

export const padStart = (s, n) => ' '.repeat(Math.max(0, n - width(s))) + s;

// Cuts a styled line to n visible characters, keeping its escape codes, ending in "…".
export function truncate(value, n) {
  // A stray escape character that starts no complete sequence is dropped.
  // oxlint-disable-next-line no-control-regex
  const s = String(value).replace(/\x1b(?!\[[0-9;?]*[A-Za-z])/g, '');
  let out = '';
  let seen = 0;

  for (let i = 0; i < s.length;) {
    const m = /^\x1b\[[0-9;?]*[A-Za-z]/.exec(s.slice(i));

    if (m) {
      out += m[0];
      i += m[0].length;
      continue;
    }

    const ch = String.fromCodePoint(s.codePointAt(i));

    if (seen === n - 1) return `${out}…\x1b[0m`;
    out += ch;
    seen++;
    i += ch.length;
  }

  return out;
}

export const columns = (stream = process.stdout) => Math.max(60, Math.min(stream.columns || 80, 96));

// Word-wrap plain text to `max` columns; words longer than a line (paths) are split.
export function wrapText(text, max) {
  const lines = [];
  let line = '';

  for (let word of String(text).split(' ')) {
    while (word.length > max) {
      if (line) { lines.push(line); line = ''; }

      lines.push(word.slice(0, max));
      word = word.slice(max);
    }

    if (!line) line = word;
    else if (line.length + 1 + word.length <= max) line += ` ${word}`;
    else { lines.push(line); line = word; }
  }

  if (line) lines.push(line);

  return lines;
}

// A horizontal bar: filled share in `color`, rest faint.
export function bar(p, share, size = 24, color = 'orange') {
  const n = Math.round(Math.max(0, Math.min(1, share)) * size);

  return p[color]('█'.repeat(n)) + p.faint('░'.repeat(size - n));
}

// Section header: a label on an orange band, then the title.
export const band = (p, label, title) => `${p.onOrange(p.ink(p.bold(` ${label} `)))} ${p.cream(title)}`;

// A rule that fades from the brand orange into the dark band (true colour), or plain dark orange.
const mix = (a, b, k) => `#${[0, 1, 2].map((i) => Math.round(rgb(a)[i] + (rgb(b)[i] - rgb(a)[i]) * k).toString(16).padStart(2, '0')).join('')}`;

export function gradientRule(p, width, char = '━', from = '#FF5A1F', to = '#3A2014') {
  if (p.level < 3) return p.orangeDk(char.repeat(width));
  let out = '';

  for (let i = 0; i < width; i += 4) out += p.hex(mix(from, to, i / Math.max(1, width - 1)), 'orangeDk')(char.repeat(Math.min(4, width - i)));

  return out;
}

// The top of every secondary screen: Brakey (medium) beside the brand, the screen's label on the
// orange band, and a line from Brakey about the screen; then a rule fading from orange to dark.
// Brakey's pose and line follow the screen (worried on problems, happy when all is well…).
export function screen(p, label, title, cols = columns(), { pose = 'idle', line = null } = {}) {
  if (accessible()) return ['', `  blackbrake · ${label} · ${title}`, ''];
  const face = mascotMedium(p, pose);

  const right = [
    `${p.bold(p.cream('blackbrake'))}  ${band(p, label, title)}`,
    line ? `${p.orange(MASCOT)}${p.faint(':')} ${p.cream(line)}` : p.faint(t('local · nothing leaves this machine')),
    '',
  ];

  return ['', ...face.map((row, i) => `  ${row}  ${right[i] ?? ''}`.trimEnd()), `  ${gradientRule(p, Math.max(20, cols - 4))}`, ''];
}

// A panel with a rounded border and its title set into the top edge (as Lip Gloss draws them).
export function box(p, title, lines, { width: size = Math.min(columns() - 4, 92), color = 'orangeDk', titleColor = 'orange' } = {}) {
  // For screen readers: the title and the lines, no border to read out.
  if (accessible()) return [...(title ? [`  ${title}:`] : []), ...lines.map((l) => `  ${l}`)];
  const inner = size - 4;
  const edge = p[color];
  const head = title ? `${edge('╭─ ')}${p.bold(p[titleColor](title))}${edge(` ${'─'.repeat(Math.max(0, inner - width(title) - 1))}╮`)}` : edge(`╭${'─'.repeat(size - 2)}╮`);

  // A styled row that is too long is cut with "…" (its colours kept); plain text wraps, indented.
  const fit = (l) => {
    if (width(l) <= inner) return [l];

    if (l !== strip(l)) return [truncate(l, inner)];
    const indent = /^ */.exec(l)[0];

    return wrapText(l.trim(), inner - indent.length).map((x) => p.cream(indent + x));
  };

  const body = lines.flatMap(fit).map((l) => `${edge('│')} ${padEnd(l, inner)} ${edge('│')}`);

  return [head, ...body, edge(`╰${'─'.repeat(size - 2)}╯`)].map((l) => `  ${l}`);
}

// Brakey saying something longer, in a speech bubble beside the medium mascot (as Houston does).
export function bubble(p, text, { pose = 'idle', width = Math.min(columns() - 18, 72) } = {}) {
  const face = mascotMedium(p, pose);
  const lines = wrapText(text, width - 4);
  const top = p.orangeDk(`╭${'─'.repeat(width - 2)}╮`);
  const bottom = p.orangeDk(`╰${'─'.repeat(width - 2)}╯`);
  const body = lines.map((l, i) => `${i === 0 ? p.orangeDk('◀') : p.orangeDk('│')} ${p.cream(padEnd(l, width - 4))} ${p.orangeDk('│')}`);
  const right = [top, ...body, bottom];
  const n = Math.max(face.length, right.length);

  return Array.from({ length: n }, (_, i) => `  ${face[i] ?? ' '.repeat(MEDIUM_WIDTH)} ${right[i] ?? ''}`.trimEnd());
}

// Each screen starts on a clean terminal (only on a terminal: output sent to a file or another
// program is never cleared). Clears the visible screen and the scrollback, and puts the cursor home.
export function clearScreen(out = process.stdout) {
  if (out.isTTY) out.write('\x1b[2J\x1b[3J\x1b[H');
}

// The terminal window's title (only on a terminal).
export function setTitle(text, out = process.stdout) {
  if (out.isTTY) out.write(`\x1b]0;${String(text).replace(/[\x00-\x1f\x7f]/g, '')}\x07`);
}

// The logo: the flight recorder in pixels (handle, lit lid, product plate, screws, the black band,
// shaded base). Two pixel rows per text row, drawn with half blocks.
const SPRITE = [
  '....gggggggg....',
  '....g......g....',
  '.LLLLLLLLLLLLLL.',
  '.OcOOOCCCCOOOcO.',
  '.OOOOOCCCCOOOOO.',
  '.BBBBBBBBBBBBBB.',
  '.BBBBBBBBBBBBBB.',
  '.OOOOOOOOOOOOOO.',
  '.OcOOOOOOOOOOcO.',
  '.DDDDDDDDDDDDDD.',
];

const PIXEL = { g: 'dim', L: 'orangeLt', Y: 'amber', O: 'orange', c: 'cream', C: 'cream', B: 'band', D: 'orangeDk', E: 'cream', A: 'coral', Z: 'dim', W: 'amber', K: 'ink' };

export const LOGO_WIDTH = SPRITE[0].length;

// ---------- the mascot: the logo itself, with eyes on its black band ----------
// Brakey is the flight recorder looking out through its band like a visor. Poses change the eyes,
// the lid's light and its little arms (one pixel beside the body), never the silhouette.
// Two sizes: the full logo (16×10 pixels, 5 rows) and a medium one for panel headers (10×6, 3 rows).
const MEDIUM = [
  '....gggg....',
  '.LLLLLLLLLL.',
  '.OcOOOOOOcO.',
  '.BBBBBBBBBB.',
  '.BBBBBBBBBB.',
  '.DDDDDDDDDD.',
];

// Per size: where the eyes sit (left pixel of each eye, the band's two pixel rows), how wide an eye
// is, the lid's row, and the pixels of the arms (down, raised) on each side.
const SIZES = {
  large: { grid: SPRITE, eyes: [3, 11], rows: [5, 6], w: 2, lid: 2, side: [0, 15], armDown: [6, 7], armUp: [2, 3], shift: 1 },
  medium: { grid: MEDIUM, eyes: [3, 7], rows: [3, 4], w: 2, lid: 1, side: [0, 11], armDown: [3, 4], armUp: [0, 1], shift: 1 },
};

// Each pose: eye rows used ('both', 'top', 'bottom'), eye colour, horizontal shift, and extras.
const EYES = {
  idle: {},
  blink: { rows: 'bottom' },
  left: { dx: -1 },
  right: { dx: 1 },
  farLeft: { dx: -2 },
  farRight: { dx: 2 },
  happy: { rows: 'top' },
  alert: { ink: 'A', lid: 'Y' },
  alarm: { ink: 'A', lid: 'A' },
  worried: { rows: 'bottom', ink: 'A', tilt: true },
  sleep: { rows: 'bottom', ink: 'Z' },
  wink: { wink: true },
  surprised: { ink: 'W' },
  think: { rows: 'top', dx: 1 },
  determined: { rows: 'bottom', lid: 'Y' },
  wave: { rows: 'top', arms: ['down', 'up'] },
  wave2: { rows: 'top', arms: ['down', 'mid'] },
  celebrate: { rows: 'top', arms: ['up', 'up'], lid: 'Y' },
};

export const POSES = Object.keys(EYES);

function spriteFor(pose, size = 'large') {
  const s = SIZES[size];
  const e = EYES[pose] ?? EYES.idle;
  const grid = s.grid.map((r) => [...r]);
  const rows = e.rows === 'top' ? [s.rows[0]] : e.rows === 'bottom' ? [s.rows[1]] : s.rows;
  const ink = e.ink ?? 'E';
  const width = grid[0].length;

  s.eyes.forEach((x0, i) => {
    const x = Math.min(width - 1 - s.w, Math.max(1, x0 + (e.dx ?? 0)));
    // Winking: the right eye closes.
    const eyeRows = e.wink && i === 1 ? [s.rows[1]] : rows;

    for (const y of eyeRows) for (let k = 0; k < s.w; k++) grid[y][x + k] = ink;

    // Worried: the inner corner of each eye lifts (a slanted look).
    if (e.tilt) grid[s.rows[0]][i === 0 ? x + s.w - 1 : x] = ink;
  });

  if (e.lid) grid[s.lid] = grid[s.lid].map((c) => (c === 'L' ? e.lid : c));

  // Arms: one pixel column beside the body, down along it or raised.
  (e.arms ?? []).forEach((arm, i) => {
    const x = s.side[i];
    const ys = arm === 'up' ? s.armUp : arm === 'mid' ? [s.armUp[1], s.armDown[0]] : s.armDown;

    for (const y of ys) grid[y][x] = 'O';
  });

  return grid;
}

function drawSprite(p, sprite) {
  const rows = [];
  const on = (name) => p[`on${name[0].toUpperCase()}${name.slice(1)}`];

  for (let y = 0; y < sprite.length; y += 2) {
    let row = '';

    for (let x = 0; x < sprite[0].length; x++) {
      const top = PIXEL[sprite[y][x]];
      const bottom = PIXEL[sprite[y + 1][x]];

      if (!top && !bottom) row += ' ';
      else if (!bottom) row += p[top]('▀');
      else if (!top) row += p[bottom]('▄');
      else row += on(bottom)(p[top]('▀'));
    }

    rows.push(row);
  }

  return rows;
}

// Without colour: the line drawing, with the eyes on the band.
const PLAIN_EYES = { idle: '●', blink: '─', happy: '^', alert: '◉', alarm: '◉', worried: '•', sleep: '-', wink: '●', surprised: 'O', think: '^', determined: '▬', wave: '^', wave2: '^', celebrate: '^' };

function plainMascot(pose) {
  const e = PLAIN_EYES[pose] ?? '●';
  const dx = EYES[pose]?.dx ?? 0;
  const shift = Math.max(-1, Math.min(1, dx));
  const band = [...' ╞════════════╡ '];
  band[3 + shift] = e;
  band[12 + shift] = pose === 'wink' ? '─' : e;
  const arms = EYES[pose]?.arms ?? [];
  const top = [...'    ┌──────┐    '];

  if (arms[0] === 'up') top[0] = '\\';

  if (arms[1] === 'up') top[15] = '/';

  return [top.join(''), ' ┌──┴──────┴──┐ ', ' │ •  ▭▭▭▭  • │ ', band.join(''), ' └────────────┘ '];
}

export function mascot(p, pose = 'idle') {
  return p.level ? drawSprite(p, spriteFor(pose, 'large')) : plainMascot(pose);
}

// The medium Brakey (10 columns, 3 rows) for panel headers. Without colour, a small face.
const PLAIN_MEDIUM_EYES = { blink: '- -', happy: '^ ^', alert: '! !', alarm: '! !', worried: '. .', sleep: '- -', wink: 'o -', surprised: 'O O', think: '^ ^', determined: '= =', wave: '^ ^', wave2: '^ ^', celebrate: '^ ^' };

export function mascotMedium(p, pose = 'idle') {
  if (!p.level) return ['  .----.   ', `  [ ${PLAIN_MEDIUM_EYES[pose] ?? 'o o'}]`.padEnd(12), "  '----'    "].map((r) => r.slice(0, 12).padEnd(12));

  return drawSprite(p, spriteFor(pose, 'medium'));
}

export const MEDIUM_WIDTH = MEDIUM[0].length;

// The logo is the mascot at rest.
export const logo = (p) => mascot(p, 'idle');

// The mascot in two columns: a tiny orange box with its eyes, used as the menu pointer and beside
// short messages. Without colour, the usual arrow.
const MINI_EYES = { idle: '••', blink: '--', left: '•·', right: '·•', farLeft: '•·', farRight: '·•', happy: '^^', alert: '!!', alarm: '!!', worried: '··', sleep: 'zz', wink: '•-', surprised: 'oo', think: '˘•', determined: '▪▪', wave: '^^', wave2: '^^', celebrate: '^^' };

// A plain-text screen for screen readers (ACCESSIBLE=1, or chosen in Help and settings): no
// pixel art, no motion, the same words.
export const accessible = (env = process.env) => Boolean(env.ACCESSIBLE);

export function mini(p, pose = 'idle') {
  if (!p.level || accessible()) return '❯';
  const face = MINI_EYES[pose] ?? '••';

  return pose === 'alert' || pose === 'alarm' ? p.onCoral(p.ink(p.bold(face))) : p.onOrange(p.ink(p.bold(face)));
}

// Motion only where it helps: an interactive terminal, not CI, not a dumb or colourless terminal,
// not when the user or a screen reader asked for none.
export function motionAllowed(stream = process.stdout, env = process.env) {
  return Boolean(stream.isTTY) && !env.CI && env.TERM !== 'dumb' && !env.ACCESSIBLE && !env.BLACKBRAKE_NO_ANIMATION && !('NO_COLOR' in env && env.NO_COLOR !== '');
}

// Plays mascot poses in place: `frames` = [[pose, ms], …]; `render(pose)` returns the lines to draw.
// Each frame is written in one go; the cursor is hidden and always restored.
export async function play(render, frames, { out = process.stdout, motion = motionAllowed(out) } = {}) {
  const last = frames.at(-1)?.[0] ?? 'idle';
  let lines = render(motion ? frames[0][0] : last);
  out.write(`${lines.join('\n')}\n`);

  if (!motion) return;
  out.write('\x1b[?25l');
  const restore = () => out.write('\x1b[?25h');
  process.once('exit', restore);

  try {
    for (const [pose, ms] of frames) {
      const next = render(pose);
      out.write(`\x1b[${lines.length}A\x1b[0J${next.join('\n')}\n`);
      lines = next;
      await new Promise((r) => setTimeout(r, ms));
    }
  } finally {
    process.off('exit', restore);
    out.write('\x1b[?25h');
  }
}

// The mascot's hello when blackbrake opens: looks around, blinks, waves, smiles (about 2 s).
export const HELLO = [['idle', 220], ['left', 200], ['right', 200], ['idle', 120], ['blink', 100], ['idle', 120], ['wave', 180], ['wave2', 160], ['wave', 180], ['wave2', 160], ['happy', 300], ['idle', 0]];

// Other moments Brakey acts out (same rules: only with motion, the last pose is what stays).
export const ANIMATIONS = {
  celebrate: [['happy', 140], ['celebrate', 220], ['happy', 140], ['celebrate', 220], ['wink', 260], ['happy', 0]],
  alarm: [['surprised', 180], ['alarm', 160], ['alert', 160], ['alarm', 160], ['alert', 160], ['alarm', 160], ['alert', 0]],
  scan: [['farLeft', 140], ['left', 90], ['idle', 90], ['right', 90], ['farRight', 140], ['right', 90], ['idle', 90], ['left', 90]],
  think: [['think', 300], ['blink', 90], ['think', 300]],
  determined: [['idle', 160], ['determined', 260], ['blink', 90], ['determined', 0]],
};

// The name, in the same pixel style as the logo: 5-pixel letters drawn with half blocks (3 rows).
// "BLACK" in cream and "BRAKE" in orange: the black box and the brakes.
const FONT = {
  B: ['####.', '#...#', '####.', '#...#', '####.'],
  L: ['#....', '#....', '#....', '#....', '#####'],
  A: ['.###.', '#...#', '#####', '#...#', '#...#'],
  C: ['.####', '#....', '#....', '#....', '.####'],
  K: ['#...#', '#..#.', '###..', '#..#.', '#...#'],
  R: ['####.', '#...#', '####.', '#..#.', '#...#'],
  E: ['#####', '#....', '####.', '#....', '#####'],
};

// Lit from above: each pixel row of a letter has its own shade (cream for BLACK, amber to deep
// orange for BRAKE), and a drop shadow in the brand's brown sits one pixel down and to the right,
// so the name stands off the terminal like the logo does. With true colour the gradient is exact;
// on 256 colours the nearest brand colours; without colour, only the letter shapes (no shadow).
const BLACK_ROWS = [['#FFFAF2', 'cream'], ['#FFF3E4', 'cream'], ['#F3E1CA', 'cream'], ['#E6CDB0', 'cream'], ['#D6B794', 'cream']];

// On a light background, BLACK is drawn in dark browns (lit from above the same way).
const BLACK_LIGHT = [['#1E120B', 'ink'], ['#2A1810', 'ink'], ['#3B2415', 'brown'], ['#4A2E1B', 'brown'], ['#5A3820', 'brown']];

const BRAKE_ROWS = [['#FFB347', 'amber'], ['#FF8A4C', 'orangeLt'], ['#FF6A2A', 'orange'], ['#F0521C', 'orange'], ['#C9431A', 'orangeDk']];

const SHADOW = ['#5A2A14', 'brown'];

export const WORDMARK_WIDTH = 10 * 6;

// glint: the column where a passing shine crosses the letters (a diagonal band that lightens each
// pixel it touches, as light running over metal), or null. True colour only.
const shine = (glint, x, y) => {
  if (glint === null || glint === undefined) return 0;
  const d = Math.abs(x + y - glint);

  return d > 2.5 ? 0 : (1 - d / 2.5) * 0.7;
};

export function wordmark(p, { glint = null } = {}) {
  const H = 5;

  const on = (x, y) => {
    if (x < 0 || y < 0 || y >= H) return false;
    const letter = Math.floor(x / 6);

    return letter < 10 && x % 6 < 5 && FONT['BLACKBRAKE'[letter]][y][x % 6] === '#';
  };

  // The colour of one pixel: a letter shade, the shadow, or nothing.
  const pixel = (x, y) => {
    if (on(x, y)) {
      const [hex, name] = (Math.floor(x / 6) < 5 ? (theme() === 'light' ? BLACK_LIGHT : BLACK_ROWS) : BRAKE_ROWS)[y];
      const k = p.level >= 3 ? shine(glint, x, y) : 0;

      return k ? [mix(hex, '#FFFFFF', k), name] : [hex, name];
    }

    return p.level && on(x - 1, y - 1) ? SHADOW : null;
  };

  const fg = ([hex, name]) => (p.level >= 3 ? `\x1b[38;2;${rgb(hex).join(';')}m` : `\x1b[38;5;${PALETTE[name][1]}m`);
  const bg = ([hex, name]) => (p.level >= 3 ? `\x1b[48;2;${rgb(hex).join(';')}m` : `\x1b[48;5;${PALETTE[name][1]}m`);
  const rows = [];

  for (let r = 0; r < 3; r++) {
    let row = '';

    for (let x = 0; x < WORDMARK_WIDTH; x++) {
      const top = pixel(x, r * 2);
      const bottom = pixel(x, r * 2 + 1);

      if (!p.level) row += top && bottom ? '█' : top ? '▀' : bottom ? '▄' : ' ';
      else if (!top && !bottom) row += ' ';
      else if (!bottom) row += `${fg(top)}▀\x1b[39m`;
      else if (!top) row += `${fg(bottom)}▄\x1b[39m`;
      else row += `${fg(top)}${bg(bottom)}▀\x1b[39;49m`;
    }

    rows.push(row.replace(/ +$/, ''));
  }

  return rows;
}

// Brakey says something: the mini mascot in the matching pose, its name, the line.
export const say = (p, pose, text) => `  ${mini(p, pose)} ${p.bold(p.orange(MASCOT))}${p.faint(':')} ${p.cream(text)}`;

// Put the logo on the left and text lines on the right, vertically centred. In accessible mode,
// only the text.
export function withLogo(p, lines, pose = 'idle') {
  if (accessible()) return lines.filter((l) => l !== '').map((l) => `  ${l}`);
  const l = mascot(p, pose);
  const top = Math.max(0, Math.floor((l.length - lines.length) / 2));

  return l.map((row, i) => `  ${row}   ${lines[i - top] ?? ''}`.trimEnd());
}

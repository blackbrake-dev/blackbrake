import fs from 'node:fs';
import { isObject, isText } from './kinds.mjs';

// Text that comes from disk or from the agent (skill names, file paths, MCP server names, tool
// names) is printed to the terminal and shown inside Claude Code. It must not carry control
// characters: an escape sequence in a skill name could redraw the report, and OSC 52 can write the
// clipboard. Removes C0/C1 controls (newlines become spaces), bidirectional overrides, zero-width
// characters and Unicode tag characters, then truncates.
// Also the invisible joiners and selectors review B found still showing (CGJ U+034F, Khmer U+17B4-5,
// Mongolian U+180B-F, U+2065, variation selectors, interlinear annotation U+FFF9-B).
// oxlint-disable-next-line no-control-regex, no-misleading-character-class -- matching control and combining characters one by one is the point
const UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u2028-\u202e\u2060-\u206f\u2800\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufffc]|[\u{13430}-\u{13438}\u{1BCA0}-\u{1BCA3}\u{1D173}-\u{1D17A}\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;

// Every string inside a plain object or array, cleaned (for data about to be shown or exported).
export function cleanDeep(value, max = 500) {
  if (isText(value)) return clean(value, max);

  if (Array.isArray(value)) return value.map((v) => cleanDeep(v, max));

  if (isObject(value)) return Object.fromEntries(Object.entries(value).map(([k, v]) => [clean(k, max), cleanDeep(v, max)]));

  return value;
}

// Local paths only. On Windows a UNC path (\\host\share) or device path (\\.\, \\?\) makes a
// plain file read open a network connection (and send the user's NTLM hash) or block on a device.
export const isLocalPath = (p) => isText(p) && p.length > 0 && !/^[\\/]{2}/.test(p);

// A regular file on a local disk, following a symlink only if it lands on a local regular file
// (dotfile setups symlink settings.json; a planted link to \\host\share or a device is refused).
export function localFileStat(file) {
  const st = fs.lstatSync(file);

  if (st.isFile()) return st;

  if (!st.isSymbolicLink()) return null;
  const real = fs.realpathSync.native(file);

  if (!isLocalPath(real)) return null;
  const target = fs.statSync(real);

  return target.isFile() ? target : null;
}

export const clean = (value, max = 300) => {
  const s = String(value ?? '').replace(/[\n\t]/g, ' ').replace(UNSAFE, '');

  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
};

// The alphabet of a report (guard-design#6x §5.4, rule V4) by code point: space, printable ASCII
// without the markup characters, Latin-1 letters (no × or ÷), ¿ ¡ ª º, and Latin Extended-A. Line
// breaks are the caller's business. `#` and `_` are allowed here and restricted by position in the
// validator. Everything else (controls, bidi, zero width, tags, emoji, Cyrillic or Greek look-alikes,
// lone combining marks) is outside by construction, not by a list of bad characters.
const REPORT_MARKUP = new Set([...'<>[]{}\\`*~|&@^$'].map((c) => c.codePointAt(0)));

export function isSafeReportChar(cp) {
  if (cp === 0x20) return true;

  if (cp > 0x20 && cp < 0x7f) return !REPORT_MARKUP.has(cp);

  if (cp === 0xa1 || cp === 0xaa || cp === 0xba || cp === 0xbf) return true;

  if (cp >= 0xc0 && cp <= 0xff) return cp !== 0xd7 && cp !== 0xf7;

  return cp >= 0x100 && cp <= 0x17f;
}

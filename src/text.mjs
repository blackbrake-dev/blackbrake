import fs from 'node:fs';

// Text that comes from disk or from the agent (skill names, file paths, MCP server names, tool
// names) is printed to the terminal and shown inside Claude Code. It must not carry control
// characters: an escape sequence in a skill name could redraw the report, and OSC 52 can write the
// clipboard. Removes C0/C1 controls (newlines become spaces), bidirectional overrides, zero-width
// characters and Unicode tag characters, then truncates.
// oxlint-disable-next-line no-control-regex -- matching control characters is the point
const UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u00ad\u061c\u115f\u1160\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\u3164\ufeff\uffa0]|[\u{E0000}-\u{E007F}]/gu;

// Every string inside a plain object or array, cleaned (for data about to be shown or exported).
export function cleanDeep(value, max = 500) {
  if (typeof value === 'string') return clean(value, max);

  if (Array.isArray(value)) return value.map((v) => cleanDeep(v, max));

  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [clean(k, max), cleanDeep(v, max)]));

  return value;
}

// Local paths only. On Windows a UNC path (\\host\share) or device path (\\.\, \\?\) makes a
// plain file read open a network connection (and send the user's NTLM hash) or block on a device.
export const isLocalPath = (p) => typeof p === 'string' && p.length > 0 && !/^[\\/]{2}/.test(p);

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

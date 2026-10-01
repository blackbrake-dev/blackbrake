// "Pause all of blackbrake": the mark in state.json (`settings.paused = { at: ISO, by: 'menu' | 'cli' }`).
// Absent means active. Reading is tolerant and fails towards active protection: a mark that is not
// an object with a valid date (invalid JSON, a string, `at` missing or malformed) is not a pause.
// Written like `mode`: through writePrivate, and an agent cannot write it while guard runs (policy
// denies writes to ~/.blackbrake). A process of the same user outside the agents can; that limit is
// the README's "What guard cannot promise".
import { isText } from '../kinds.mjs';
import { getSetting, guardHome, setSetting } from './state.mjs';

const BY = ['menu', 'cli'];

// The mark as { at, by }, or null when blackbrake is not paused.
export function pausedMark(home = guardHome()) {
  const mark = getSetting('paused', null, home);

  if (Object.prototype.toString.call(mark) !== '[object Object]' || !isText(mark.at) || !Number.isFinite(Date.parse(mark.at))) return null;

  return { at: new Date(Date.parse(mark.at)).toISOString(), by: BY.includes(mark.by) ? mark.by : 'cli' };
}

export const isPaused = (home = guardHome()) => pausedMark(home) !== null;

export function setPaused(by = 'cli', home = guardHome(), now = new Date()) {
  setSetting('paused', { at: now.toISOString(), by: BY.includes(by) ? by : 'cli' }, home);
}

export function clearPaused(home = guardHome()) {
  setSetting('paused', null, home);
}

// How long it has been paused, in hours (0 when it is not).
export const pausedHours = (home = guardHome(), now = Date.now()) => {
  const mark = pausedMark(home);

  return mark ? Math.max(0, (now - Date.parse(mark.at)) / 36e5) : 0;
};

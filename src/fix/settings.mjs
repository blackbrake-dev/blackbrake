// Safe changes to Claude Code's user settings (~/.claude/settings.json), each one the setting a
// precaution names. Shown as a before/after before it is applied; the file is copied to
// ~/.blackbrake/backups first and replaced whole (temporary file + rename). An unreadable or invalid
// file is never changed.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { assertNoLinks } from '../guard/install.mjs';
import { guardHome } from '../guard/state.mjs';
import { SYNCED } from './scrub.mjs';
import { isCount, isRecord } from '../kinds.mjs';

export const claudeSettingsFile = (env = process.env) => path.join(env.CLAUDE_CONFIG_DIR && path.isAbsolute(env.CLAUDE_CONFIG_DIR) ? env.CLAUDE_CONFIG_DIR : path.join(os.homedir(), '.claude'), 'settings.json');

const DENY = ['Read(./.env)', 'Read(./.env.*)', 'Read(~/.ssh/**)'];

// Precaution id -> the change, as a pure function of the settings object. null: nothing to do.
export const SETTINGS_FIXES = {
  'bypass-prompt': (s) => ('skipDangerousModePermissionPrompt' in s ? (({ skipDangerousModePermissionPrompt: _removed, ...rest }) => rest)(s) : null),
  'default-mode': (s) => (s.permissions?.defaultMode === 'bypassPermissions' ? { ...s, permissions: { ...s.permissions, defaultMode: 'default' } } : null),
  'deny-reads': (s) => {
    const deny = s.permissions?.deny ?? [];
    const add = DENY.filter((d) => !deny.includes(d));

    return add.length ? { ...s, permissions: { ...s.permissions, deny: [...deny, ...add] } } : null;
  },
  'cleanup-days': (s) => (isCount(s.cleanupPeriodDays) && s.cleanupPeriodDays > 0 && s.cleanupPeriodDays <= 14 ? null : { ...s, cleanupPeriodDays: 14 }),
  'config:enableAllProjectMcpServers': (s) => (s.enableAllProjectMcpServers === true ? { ...s, enableAllProjectMcpServers: false } : null),
};

export const canFixSettings = (id, where = 'user settings') => id in SETTINGS_FIXES && (!id.startsWith('config:') || where === 'user settings');

function readSettings(file) {
  let st = null;

  try { st = fs.lstatSync(file); } catch { return { value: {}, exists: false }; }

  if (!st.isFile()) throw new Error(`${file} is not a regular file; blackbrake does not change it.`);
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));

  if (!isRecord(value)) throw new Error(`${file} is not a JSON object; blackbrake does not change it.`);

  return { value, exists: true };
}

// The change a set of precautions would make: { before, after } as JSON text, or null.
export function planSettings(ids, file = claudeSettingsFile()) {
  const { value } = readSettings(file);
  let next = value;

  for (const id of ids) next = SETTINGS_FIXES[id]?.(next) ?? next;

  return next === value ? null : { file, before: JSON.stringify(value, null, 2), after: JSON.stringify(next, null, 2), value: next };
}

export function applySettings(plan, { home = guardHome() } = {}) {
  const { file, value } = plan;
  assertNoLinks(path.dirname(file));

  // Claude Code writes this file too: if it changed since the change was shown, nothing is applied.
  if (JSON.stringify(readSettings(file).value, null, 2) !== plan.before) throw new Error(`${file} changed since the change was shown; nothing was applied. Run it again.`);

  // settings.json can hold API keys: its backup never goes into a folder that syncs to the cloud.
  if (SYNCED.test(path.resolve(home))) throw new Error(`blackbrake's folder (${home}) is inside a folder that syncs to the cloud; the backup could hold keys. Nothing was changed.`);

  if (fs.existsSync(file)) {
    const dir = path.join(home, 'backups');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(dir, `claude-settings-${new Date().toISOString().replace(/[:.]/g, '-')}-${crypto.randomBytes(3).toString('hex')}.json`), fs.readFileSync(file), { flag: 'wx', mode: 0o600 });
  }

  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${crypto.randomBytes(6).toString('hex')}.tmp`;

  try {
    fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    fs.renameSync(tmp, file);
  } finally {
    fs.rmSync(tmp, { force: true });
  }

  return file;
}

// A short before/after: only the lines that differ.
export function diffLines(before, after) {
  const a = before.split('\n');
  const b = after.split('\n');

  return [...a.filter((l) => !b.includes(l)).map((l) => `- ${l.trim()}`), ...b.filter((l) => !a.includes(l)).map((l) => `+ ${l.trim()}`)];
}
